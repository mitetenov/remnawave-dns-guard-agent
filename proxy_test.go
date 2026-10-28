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
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSOCKS5URLAndProtocolValidation(t *testing.T) {
	for _, value := range []string{"socks5://proxy.example.com:1080", "socks5h://user:p%40ss%3Aword@proxy.example.com:1080", "socks5://127.0.0.1:1080", "socks5://10.0.0.2:1080", "socks5://[::1]:1080"} {
		if u, err := parseProxyURL(value); err != nil || u.Scheme != "socks5h" {
			t.Errorf("valid URL rejected: %q", value)
		}
	}
	for _, value := range []string{"", "https://proxy.example.com:1080", "socks4://proxy.example.com:1080", "socks5://proxy.example.com", "socks5://proxy.example.com:0", "socks5://proxy.example.com:65536", "socks5://proxy.example.com:1080/", "socks5://proxy.example.com:1080?", "socks5://proxy.example.com:1080#", "socks5://proxy.example.com:1080\n", "socks5://user@proxy.example.com:1080", "socks5://:pass@proxy.example.com:1080", "socks5://user:@proxy.example.com:1080", "socks5://user:%00@proxy.example.com:1080", "socks5://" + strings.Repeat("u", 256) + ":pass@proxy.example.com:1080"} {
		if _, err := parseProxyURL(value); err == nil {
			t.Errorf("unsafe URL accepted: %q", value)
		}
	}
	for _, raw := range []string{`null`, `{}`, `{"url":null,"revision":1}`, `{"url":"","revision":null}`, `{"url":"","revision":-1}`, `{"url":"https://bad:1080","revision":1}`, `{"url":"","revision":1,"command":"sh"}`} {
		if _, err := decodeProxyConfig(json.RawMessage(raw)); err == nil {
			t.Error("accepted malformed config", raw)
		}
	}
}

func TestSOCKS5XrayChainForEverySupportedProfile(t *testing.T) {
	for _, job := range syntheticJobs() {
		job.ProxyURL = "socks5://residential:p%40ss%3Aword@proxy.example.com:1080"
		config, err := XrayConfig(job, 12345)
		if err != nil {
			t.Fatal(err)
		}
		outbounds := config["outbounds"].([]any)
		if len(outbounds) != 2 {
			t.Fatal("unexpected fallback", outbounds)
		}
		target := outbounds[0].(map[string]any)
		if target["protocol"] != "vless" || target["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["address"] != job.IP {
			t.Fatal("lost target IP")
		}
		if target["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["dialerProxy"] != "upstream-socks" {
			t.Fatal("target bypasses SOCKS5")
		}
		proxy := outbounds[1].(map[string]any)
		settings := proxy["settings"].(map[string]any)
		if proxy["protocol"] != "socks" || proxy["tag"] != "upstream-socks" || settings["address"] != "proxy.example.com" || settings["port"] != 1080 || settings["user"] != "residential" || settings["pass"] != "p@ss:word" {
			t.Fatal("lost proxy credentials")
		}
	}
}

// In-process SOCKS5 adapter forwards only the expected domain to a local TLS
// server. It verifies remote DNS, authentication, and HTTPS beyond the handshake.
func fakeSOCKS5(t *testing.T, upstream, password string) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				header := make([]byte, 2)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				methods := make([]byte, int(header[1]))
				if _, err := io.ReadFull(conn, methods); err != nil {
					return
				}
				if password != "" {
					_, _ = conn.Write([]byte{5, 2})
					if _, err := io.ReadFull(conn, header); err != nil {
						return
					}
					user := make([]byte, int(header[1]))
					if _, err := io.ReadFull(conn, user); err != nil {
						return
					}
					if _, err := io.ReadFull(conn, header[:1]); err != nil {
						return
					}
					pass := make([]byte, int(header[0]))
					if _, err := io.ReadFull(conn, pass); err != nil {
						return
					}
					if string(user) != "user" || string(pass) != password {
						_, _ = conn.Write([]byte{1, 1})
						return
					}
					_, _ = conn.Write([]byte{1, 0})
				} else {
					_, _ = conn.Write([]byte{5, 0})
				}
				request := make([]byte, 4)
				if _, err := io.ReadFull(conn, request); err != nil {
					return
				}
				if request[0] != 5 || request[1] != 1 || request[3] != 3 {
					t.Error("SOCKS must receive a domain for remote DNS")
					return
				}
				if _, err := io.ReadFull(conn, header[:1]); err != nil {
					return
				}
				host := make([]byte, int(header[0]))
				if _, err := io.ReadFull(conn, host); err != nil {
					return
				}
				if string(host) != "example.com" {
					t.Error("unexpected SOCKS destination", string(host))
					return
				}
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				remote, err := net.DialTimeout("tcp", upstream, time.Second)
				if err != nil {
					return
				}
				defer remote.Close()
				_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(remote, conn); remote.Close(); close(copied) }()
				_, _ = io.Copy(conn, remote)
				conn.Close()
				<-copied
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done; workers.Wait() })
	credentials := ""
	if password != "" {
		credentials = "user:" + password + "@"
	}
	return "socks5://" + credentials + listener.Addr().String()
}

func TestSOCKS5HealthRequiresAuthenticatedHTTPSAndTrustedTLS(t *testing.T) {
	for _, test := range []struct {
		name                 string
		auth, trust, working bool
		status               int
	}{
		{"anonymous HTTPS", false, true, true, 204}, {"authenticated HTTPS", true, true, true, 200}, {"wrong password", true, true, false, 200}, {"untrusted certificate", false, false, false, 200}, {"HTTP failure", false, true, false, 503}, {"redirect is not proof of egress", false, true, false, 302},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" {
					t.Error("backend token leaked")
				}
				w.WriteHeader(test.status)
			}))
			defer server.Close()
			password := ""
			if test.auth {
				password = "secret"
			}
			proxy := fakeSOCKS5(t, server.Listener.Addr().String(), password)
			if test.name == "wrong password" {
				proxy = strings.Replace(proxy, "secret@", "wrong@", 1)
			}
			a, _ := New(sampleSettings())
			a.Settings.ControlURLs = []string{"https://example.com/check"}
			if test.trust {
				roots := x509.NewCertPool()
				roots.AddCert(server.Certificate())
				a.tunnelTLSConfig = &tls.Config{RootCAs: roots}
			}
			result := a.checkProxy(context.Background(), proxy)
			if result.OK != test.working || test.working && result.LatencyMS == nil {
				t.Fatal(result)
			}
		})
	}
}

func TestSOCKS5CyclePausesAndSuppressesResultsOnProxyOutage(t *testing.T) {
	for _, phase := range []string{"healthy", "before", "after", "stale revision", "mismatched job"} {
		t.Run(phase, func(t *testing.T) {
			proxyURL := "socks5://user:secret@proxy.example.com:1080"
			job := sampleJob()
			job.ProxyURL = proxyURL
			if phase == "mismatched job" {
				job.ProxyURL = ""
			}
			var reports []map[string]any
			results, probes, checks := 0, 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/agent/poll":
					json.NewEncoder(w).Encode(map[string]any{"jobs": []Job{job}, "proxy": ProxyConfig{URL: proxyURL, Revision: 2, TestID: "test-1"}})
				case "/api/agent/proxy-status":
					var report map[string]any
					json.NewDecoder(r.Body).Decode(&report)
					reports = append(reports, report)
					json.NewEncoder(w).Encode(map[string]any{"accepted": phase != "stale revision"})
				case "/api/agent/results":
					results++
					fmt.Fprint(w, `{"accepted":1}`)
				default:
					t.Error(r.URL.Path)
				}
			}))
			defer server.Close()
			s := sampleSettings()
			s.ControlPlaneURL, s.AllowInsecureHTTP = server.URL, true
			a, _ := New(s)
			a.HeartbeatFile = t.TempDir() + "/heartbeat"
			a.LogReason = func(string) {}
			a.CheckControls = func(context.Context) bool { return true }
			a.CheckProxy = func(_ context.Context, value string) ProxyStatus {
				checks++
				if value != proxyURL {
					t.Error("proxy lost")
				}
				return ProxyStatus{OK: phase != "before" && (phase != "after" || checks == 1)}
			}
			a.Probe = func(_ context.Context, j Job) Result {
				probes++
				if j.ProxyURL != proxyURL {
					t.Error("direct fallback")
				}
				return Result{JobID: j.JobID, OK: true}
			}
			_, err := a.Cycle(context.Background())
			if (err != nil) != (phase == "stale revision" || phase == "mismatched job") {
				t.Fatal(err)
			}
			if phase == "healthy" {
				if results != 1 || probes != 1 {
					t.Fatal(results, probes)
				}
			} else if results != 0 {
				t.Fatal("outage results submitted")
			}
			if (phase == "before" || phase == "stale revision" || phase == "mismatched job") && probes != 0 {
				t.Fatal("invalid route probed")
			}
			if len(reports) == 0 || reports[0]["revision"] != float64(2) || reports[0]["test_id"] != "test-1" {
				t.Fatal(reports)
			}
		})
	}
}
