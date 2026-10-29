package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDraftProxyTestCannotBlockOrChangeLiveResults(t *testing.T) {
	for _, mode := range []string{"passed", "failed", "stale", "report failed"} {
		t.Run(mode, func(t *testing.T) {
			routes := RouteSelection{Direct: true, Revision: 2}
			job := sampleJob()
			job.Routes = &routes
			manualStarted, liveSubmitted := make(chan struct{}), make(chan struct{})
			var probeCount, manualCount atomic.Int32
			var live []Result
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/agent/poll":
					json.NewEncoder(w).Encode(map[string]any{"jobs": []Job{job}, "routes": routes, "proxy": ProxyConfig{URL: "socks5://active:pass@192.0.2.1:1080", Revision: 2}, "proxy_test": ProxyTest{ID: "test-1", URL: "socks5://draft:pass@192.0.2.2:1080"}})
				case "/api/agent/proxy-status":
					fmt.Fprint(w, `{"accepted":true}`)
				case "/api/agent/results":
					var value struct {
						Results []Result `json:"results"`
					}
					json.NewDecoder(r.Body).Decode(&value)
					live = value.Results
					close(liveSubmitted)
					fmt.Fprint(w, `{"accepted":1}`)
				case "/api/agent/proxy-test-results":
					var value struct {
						AgentID, TestID string
						OK              bool
					}
					var raw map[string]any
					json.NewDecoder(r.Body).Decode(&raw)
					value.AgentID, _ = raw["agent_id"].(string)
					value.TestID, _ = raw["test_id"].(string)
					value.OK, _ = raw["ok"].(bool)
					if value.AgentID != "ru-1" || value.TestID != "test-1" || value.OK != (mode != "failed") {
						t.Error("incorrect draft report")
					}
					manualCount.Add(1)
					if mode == "report failed" {
						w.WriteHeader(503)
						fmt.Fprint(w, `{}`)
					} else {
						json.NewEncoder(w).Encode(map[string]bool{"accepted": mode != "stale"})
					}
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
			a.CheckProxy = func(ctx context.Context, value string) ProxyStatus {
				if value != "socks5://draft:pass@192.0.2.2:1080" {
					t.Error("manual test changed the live target")
				}
				close(manualStarted)
				select {
				case <-liveSubmitted:
				case <-ctx.Done():
					t.Error("manual test prevented live result submission")
				}
				return ProxyStatus{OK: mode != "failed"}
			}
			a.Probe = func(ctx context.Context, value Job) Result {
				select {
				case <-manualStarted:
				case <-ctx.Done():
				}
				probeCount.Add(1)
				if value.ProxyURL != "" {
					t.Error("draft proxy was used by a live probe")
				}
				return Result{JobID: value.JobID, OK: true}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err := a.Cycle(ctx); err != nil {
				t.Fatal(err)
			}
			if probeCount.Load() != 1 || manualCount.Load() != 1 || len(live) != 1 || !live[0].OK {
				t.Fatal("manual test changed the live outcome")
			}
		})
	}
}

func TestProxyTestDecoderRejectsUnboundedOrInvalidJobs(t *testing.T) {
	for _, raw := range []string{`null`, `{}`, `{"id":"test","url":"http://example.com"}`, `{"id":"test","url":null}`, `{"id":"test","url":"socks5://127.0.0.1:1080","command":"sh"}`} {
		if _, err := decodeProxyTest(json.RawMessage(raw)); err == nil {
			t.Fatal("invalid test accepted", raw)
		}
	}
}
