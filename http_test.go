package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func TestDirectRejectsEveryPrivateDNSAnswerBeforeDial(t *testing.T) {
	for _, answer := range []string{"127.0.0.1", "10.0.0.1", "::1", "::ffff:169.254.169.254"} {
		var calls atomic.Int32
		c := NewDirectClient()
		c.Resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr(answer)}, nil
		})
		c.Dialer = dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			calls.Add(1)
			return nil, fmt.Errorf("unexpected dial")
		})
		if _, _, err := c.Request(context.Background(), "https://checks.example.com", "GET", nil, "", false); err == nil || calls.Load() != 0 {
			t.Fatal(answer, err, calls.Load())
		}
	}
}

func TestPinnedHTTPSPreservesSNIHostAndAuth(t *testing.T) {
	var gotHost, gotSNI, gotAuth string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotSNI, gotAuth = r.Host, r.TLS.ServerName, r.Header.Get("Authorization")
		fmt.Fprint(w, `{"jobs":[]}`)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	c := NewDirectClient()
	c.TLSConfig = &tls.Config{RootCAs: roots}
	var resolveCalls int
	c.Resolver = resolverFunc(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		resolveCalls++
		if host != "example.com" {
			t.Error(host)
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	})
	c.Dialer = dialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "8.8.8.8:443" {
			t.Error(address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})
	response, _, err := c.Request(context.Background(), "https://example.com/api/agent/poll", "POST", map[string]any{}, "secret", false)
	if err != nil || response["jobs"] == nil || resolveCalls != 1 || gotHost != "example.com" || gotSNI != "example.com" || gotAuth != "Bearer secret" {
		t.Fatal(err, resolveCalls, gotHost, gotSNI, gotAuth)
	}
}

func TestBackendRedirectAndBodyLimits(t *testing.T) {
	var leaked atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer other.Close()
	for _, test := range []struct {
		name, body string
		status     int
	}{{"redirect", "", 302}, {"oversize", strings.Repeat(" ", maxResponseBytes) + `{}`, 200}, {"array", `[]`, 200}, {"null", `null`, 200}, {"trailing", `{} {}`, 200}} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", other.URL)
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			if _, _, err := NewDirectClient().Request(context.Background(), server.URL, "POST", struct{}{}, "secret", true); err == nil {
				t.Fatal("accepted malformed response")
			}
		})
	}
	if leaked.Load() != 0 {
		t.Fatal("redirect forwarded token")
	}
}

func TestDirectRequestCancellation(t *testing.T) {
	released := make(chan struct{})
	started := make(chan struct{})
	force := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		close(started)
		select {
		case <-r.Context().Done():
		case <-force:
		}
		close(released)
	}))
	defer server.Close()
	defer close(force)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	returned := make(chan error, 1)
	go func() {
		_, _, err := NewDirectClient().Request(ctx, server.URL, "POST", struct{}{}, "", true)
		returned <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request never started")
	}
	start := time.Now()
	cancel()
	select {
	case err := <-returned:
		if err == nil {
			t.Fatal("cancelled request succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("request ignored cancellation")
	}
	if time.Since(start) > time.Second {
		t.Fatal("slow cancellation")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("request was not cancelled")
	}
}

func TestCycleRealHTTPProtocolAndConcurrency(t *testing.T) {
	jobs := make([]Job, 4)
	for i := range jobs {
		jobs[i] = sampleJob()
		jobs[i].JobID = fmt.Sprint("job-", i)
		jobs[i].TargetID = fmt.Sprint("target-", i)
	}
	var mu sync.Mutex
	var calls []string
	var received []Result
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("x", 32) {
			t.Error("missing token")
		}
		mu.Lock()
		calls = append(calls, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/base/api/agent/poll" {
			var poll map[string]any
			json.NewDecoder(r.Body).Decode(&poll)
			if poll["agent_id"] != "ru-1" || poll["control_ok"] != true || poll["version"] != Version || poll["control_error"] != nil {
				t.Error(poll)
			}
			json.NewEncoder(w).Encode(map[string]any{"jobs": jobs, "poll_after_seconds": 100})
			return
		}
		if r.URL.Path == "/base/api/agent/results" {
			var value struct {
				AgentID string   `json:"agent_id"`
				Results []Result `json:"results"`
			}
			if err := json.NewDecoder(r.Body).Decode(&value); err != nil {
				t.Error(err)
			}
			received = value.Results
			fmt.Fprint(w, `{"accepted":4}`)
			return
		}
		t.Error(r.URL.Path)
	}))
	defer server.Close()
	s := sampleSettings()
	s.ControlPlaneURL = server.URL + "/base/"
	s.AllowInsecureHTTP = true
	a, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	a.HeartbeatFile = t.TempDir() + "/heartbeat"
	var controls atomic.Int32
	a.CheckControls = func(context.Context) bool { controls.Add(1); return true }
	var active, peak atomic.Int32
	gate := make(chan struct{})
	a.Probe = func(ctx context.Context, j Job) Result {
		n := active.Add(1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		if n == 4 {
			close(gate)
		}
		select {
		case <-gate:
		case <-ctx.Done():
		}
		active.Add(-1)
		latency := 1.2
		return Result{JobID: j.JobID, OK: true, LatencyMS: &latency}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	delay, err := a.Cycle(ctx)
	if err != nil || delay != 60*time.Second || peak.Load() != 4 || controls.Load() != 2 {
		t.Fatal(delay, err, peak.Load(), controls.Load())
	}
	if len(received) != 4 || len(calls) != 2 || !Healthy(a.HeartbeatFile, time.Now()) {
		t.Fatal(calls, received)
	}
	for i, r := range received {
		if r.JobID != jobs[i].JobID || !r.OK || r.LatencyMS == nil || r.Error != nil {
			t.Fatal(r)
		}
	}
}

func TestCycleSuppressesOnControlOutage(t *testing.T) {
	for _, initiallyHealthy := range []bool{false, true} {
		t.Run(fmt.Sprint(initiallyHealthy), func(t *testing.T) {
			var polls []map[string]any
			var results atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/agent/results" {
					results.Add(1)
					fmt.Fprint(w, `{}`)
					return
				}
				var poll map[string]any
				json.NewDecoder(r.Body).Decode(&poll)
				polls = append(polls, poll)
				json.NewEncoder(w).Encode(map[string]any{"jobs": []Job{sampleJob()}, "poll_after_seconds": 0})
			}))
			defer server.Close()
			s := sampleSettings()
			s.ControlPlaneURL, s.AllowInsecureHTTP = server.URL, true
			a, _ := New(s)
			a.HeartbeatFile = t.TempDir() + "/heartbeat"
			a.LogReason = func(string) {}
			var checks, probes int
			a.CheckControls = func(context.Context) bool { checks++; return initiallyHealthy && checks == 1 }
			a.Probe = func(_ context.Context, j Job) Result {
				probes++
				reason := "probe_timeout"
				return Result{JobID: j.JobID, Error: &reason}
			}
			delay, err := a.Cycle(context.Background())
			if err != nil || delay != time.Second || results.Load() != 0 {
				t.Fatal(err, delay, results.Load())
			}
			expected := 1
			if initiallyHealthy {
				expected = 2
			}
			if len(polls) != expected || polls[len(polls)-1]["control_ok"] != false || polls[len(polls)-1]["control_error"] != "control_unreachable" {
				t.Fatal(polls)
			}
			if !initiallyHealthy && probes != 0 {
				t.Fatal("outage ran probes")
			}
		})
	}
}

func TestCycleRejectsEntireMalformedBatch(t *testing.T) {
	for _, jobs := range []any{nil, []Job{sampleJob(), sampleJob()}, []Job{sampleJob(), sampleJob(), sampleJob(), sampleJob(), sampleJob()}, []any{map[string]any{"command": "sh"}}} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(map[string]any{"jobs": jobs}) }))
		s := sampleSettings()
		s.ControlPlaneURL, s.AllowInsecureHTTP = server.URL, true
		a, _ := New(s)
		a.HeartbeatFile = t.TempDir() + "/heartbeat"
		a.CheckControls = func(context.Context) bool { return true }
		a.Probe = func(context.Context, Job) Result { t.Error("invalid batch executed"); return Result{} }
		if _, err := a.Cycle(context.Background()); err == nil {
			t.Error("accepted invalid batch")
		}
		server.Close()
	}
}
