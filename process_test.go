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
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The child really binds the generated loopback port and implements CONNECT.
// It receives only a temporary config path, just like the official Xray binary.
func TestXrayHelperProcess(t *testing.T) {
	if os.Getenv("DNS_GUARD_TEST_HELPER") != "true" {
		return
	}
	args := os.Args
	configPath := args[len(args)-1]
	info, err := os.Stat(configPath)
	if err != nil || info.Mode().Perm() != 0600 {
		os.Exit(12)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		os.Exit(13)
	}
	var config struct {
		Inbounds []struct {
			Listen string
			Port   int
		}
		Outbounds []struct {
			Settings struct{ VNext []struct{ Address string } }
		}
	}
	if json.Unmarshal(data, &config) != nil || len(config.Inbounds) != 1 || config.Inbounds[0].Listen != "127.0.0.1" || config.Outbounds[0].Settings.VNext[0].Address != "8.8.8.8" {
		os.Exit(14)
	}
	marker := os.Getenv("DNS_GUARD_TEST_MARKER")
	if marker != "" {
		_ = os.WriteFile(marker, []byte(configPath+"\n"+strconv.Itoa(os.Getpid())), 0600)
	}
	if os.Getenv("DNS_GUARD_TEST_IGNORE_TERM") == "true" {
		signal.Ignore(syscall.SIGTERM)
	}
	if os.Getenv("DNS_GUARD_TEST_START_FAIL") == "true" {
		os.Exit(15)
	}
	listener, err := net.Listen("tcp4", fmt.Sprint("127.0.0.1:", config.Inbounds[0].Port))
	if err != nil {
		os.Exit(16)
	}
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Header.Get("Authorization") != "" {
			w.WriteHeader(500)
			return
		}
		if os.Getenv("DNS_GUARD_TEST_PROXY_HANG") == "true" {
			select {}
		}
		upstream, err := net.Dial("tcp", os.Getenv("DNS_GUARD_TEST_TLS_DESTINATION"))
		if err != nil {
			w.WriteHeader(502)
			return
		}
		client, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go func() { _, _ = io.Copy(upstream, client); upstream.Close() }()
		_, _ = io.Copy(client, upstream)
		client.Close()
	})}
	_ = server.Serve(listener)
	os.Exit(0)
}

func helperBinary(t *testing.T) string {
	t.Helper()
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fake-xray")
	// Shell quoting is only for a known local executable path, never job input.
	quoted := "'" + strings.ReplaceAll(testBinary, "'", "'\\''") + "'"
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec "+quoted+" -test.run=^TestXrayHelperProcess$ -- \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DNS_GUARD_TEST_HELPER", "true")
	return path
}

func assertProcessAndConfigGone(t *testing.T, marker string) {
	t.Helper()
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal("helper never started", err)
	}
	lines := strings.Split(string(data), "\n")
	if _, err := os.Stat(lines[0]); !os.IsNotExist(err) {
		t.Fatal("secret config remains", err)
	}
	if _, err := os.Stat(filepath.Dir(lines[0])); !os.IsNotExist(err) {
		t.Fatal("config directory remains", err)
	}
	pid, _ := strconv.Atoi(lines[1])
	process, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	if err = process.Signal(syscall.Signal(0)); err == nil {
		t.Fatal("Xray child still exists", pid)
	}
}

func TestProbeRealHTTPSViaLoopbackProxyAndCleanup(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Host != "example.com" || r.TLS.ServerName != "example.com" || r.Header.Get("Authorization") != "" {
			t.Error("unexpected tunnel destination or credentials", r.Host, r.TLS.ServerName)
		}
		w.Header().Set("Location", "https://unlisted.invalid/secret")
		w.WriteHeader(302)
	}))
	defer server.Close()
	s := sampleSettings()
	s.XrayBin = helperBinary(t)
	s.ProbeURLs = []string{"https://example.com/probe"}
	marker := filepath.Join(t.TempDir(), "marker")
	t.Setenv("DNS_GUARD_TEST_MARKER", marker)
	t.Setenv("DNS_GUARD_TEST_TLS_DESTINATION", server.Listener.Addr().String())
	a, _ := New(s)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	a.tunnelTLSConfig = &tls.Config{RootCAs: roots}
	result := a.probe(context.Background(), sampleJob())
	if !result.OK || result.Error != nil || result.LatencyMS == nil || requests.Load() != 1 {
		t.Fatal(result, requests.Load())
	}
	assertProcessAndConfigGone(t, marker)
}

func TestProbeTLSVerificationCannotBeSkipped(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted certificate was accepted") }))
	defer server.Close()
	s := sampleSettings()
	s.XrayBin = helperBinary(t)
	s.ProbeURLs = []string{"https://example.com/probe"}
	marker := filepath.Join(t.TempDir(), "marker")
	t.Setenv("DNS_GUARD_TEST_MARKER", marker)
	t.Setenv("DNS_GUARD_TEST_TLS_DESTINATION", server.Listener.Addr().String())
	a, _ := New(s)
	result := a.probe(context.Background(), sampleJob())
	if result.OK || result.Error == nil || *result.Error != "tunnel_unreachable" || result.LatencyMS != nil {
		t.Fatal(result)
	}
	assertProcessAndConfigGone(t, marker)
}

func TestProbeTimeoutKillsUncooperativeChildAndCleansConfig(t *testing.T) {
	s := sampleSettings()
	s.XrayBin = helperBinary(t)
	s.ProbeURLs = []string{"https://example.com/probe"}
	marker := filepath.Join(t.TempDir(), "marker")
	t.Setenv("DNS_GUARD_TEST_MARKER", marker)
	t.Setenv("DNS_GUARD_TEST_IGNORE_TERM", "true")
	t.Setenv("DNS_GUARD_TEST_PROXY_HANG", "true")
	a, _ := New(s)
	job := sampleJob()
	job.TimeoutSeconds = 1
	start := time.Now()
	result := a.probe(context.Background(), job)
	if result.OK || result.Error == nil || *result.Error != "probe_timeout" || time.Since(start) > 5*time.Second {
		t.Fatal(result, time.Since(start))
	}
	assertProcessAndConfigGone(t, marker)
}

func TestProbeEarlyExitAndInvalidInput(t *testing.T) {
	s := sampleSettings()
	s.XrayBin = helperBinary(t)
	marker := filepath.Join(t.TempDir(), "marker")
	t.Setenv("DNS_GUARD_TEST_MARKER", marker)
	t.Setenv("DNS_GUARD_TEST_START_FAIL", "true")
	a, _ := New(s)
	start := time.Now()
	result := a.probe(context.Background(), sampleJob())
	if result.Error == nil || *result.Error != "xray_start_failed" || time.Since(start) > time.Second {
		t.Fatal(result, time.Since(start))
	}
	assertProcessAndConfigGone(t, marker)
	job := sampleJob()
	job.IP = "127.0.0.1"
	if r := a.probe(context.Background(), job); r.Error == nil || *r.Error != "invalid_job" {
		t.Fatal(r)
	}
}

func TestSelfTestExecutesAllTenProfiles(t *testing.T) {
	path := helperBinary(t)
	marker := filepath.Join(t.TempDir(), "marker")
	// A separate simple executable validates the actual command and private mode.
	validator := filepath.Join(t.TempDir(), "validator")
	script := "#!/bin/sh\n[ \"$1\" = run ] && [ \"$2\" = -test ] && [ \"$3\" = -config ] || exit 2\nprintf '.\\n' >> '" + marker + "'\nexit 0\n"
	if os.WriteFile(validator, []byte(script), 0700) != nil {
		t.Fatal("write validator")
	}
	_ = path
	if err := SelfTest(context.Background(), validator); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(marker)
	if strings.Count(string(data), ".") != 10 {
		t.Fatal(string(data))
	}
}

func TestHeartbeatOnlyChecksProgressAndFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heartbeat")
	now := time.Now()
	if Healthy(path, now) {
		t.Fatal("missing heartbeat accepted")
	}
	if err := writeHeartbeat(path, now); err != nil {
		t.Fatal(err)
	}
	if !Healthy(path, now.Add(time.Second)) {
		t.Fatal("fresh heartbeat rejected")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	if Healthy(path, now.Add(181*time.Second)) || Healthy(path, now.Add(-time.Second)) {
		t.Fatal("invalid heartbeat accepted")
	}
	if os.WriteFile(path, []byte("NaN"), 0600) != nil {
		t.Fatal("write")
	}
	if Healthy(path, now) {
		t.Fatal("NaN")
	}
	// Replacing a symlink never overwrites its target.
	target := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(target, []byte("keep"), 0600)
	os.Remove(path)
	os.Symlink(target, path)
	if err := writeHeartbeat(path, now); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(target)
	if string(data) != "keep" {
		t.Fatal("followed symlink")
	}
}

func TestRunRetriesWithoutLeakingErrorDetails(t *testing.T) {
	s := sampleSettings()
	s.ControlPlaneURL = "http://127.0.0.1:1"
	s.AllowInsecureHTTP = true
	a, _ := New(s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.CheckControls = func(context.Context) bool { return true }
	var messages []string
	a.LogReason = func(reason string) { messages = append(messages, reason); cancel() }
	a.Run(ctx)
	if len(messages) != 1 || messages[0] != "poll_cycle_failed" {
		t.Fatal(messages)
	}
}

func TestStopProcessReapsGracefulAndForcedChildren(t *testing.T) {
	for _, ignore := range []bool{false, true} {
		cmd := exec.Command("/bin/sh", "-c", "exec sleep 60")
		if ignore {
			cmd = exec.Command("/bin/sh", "-c", "trap '' TERM; exec sleep 60")
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		time.Sleep(20 * time.Millisecond)
		start := time.Now()
		stopProcess(cmd, done)
		select {
		case <-done:
		default:
			t.Fatal("child not reaped")
		}
		if time.Since(start) > 4*time.Second {
			t.Fatal("cleanup exceeded limit")
		}
	}
}
