package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestIndependentRouteCycles(t *testing.T) {
	for _, test := range []struct {
		name                                                                               string
		direct, socks, directControl, proxyBefore, proxyAfter, directSuccess, socksSuccess bool
		directOutcome, socksOutcome                                                        string
		ok                                                                                 bool
		probes                                                                             int
	}{
		{"both succeed", true, true, true, true, true, true, true, "success", "success", true, 2},
		{"direct fails", true, true, true, true, true, false, true, "failure", "success", false, 2},
		{"SOCKS VLESS fails", true, true, true, true, true, true, false, "success", "failure", false, 2},
		{"proxy unavailable before preserves direct success", true, true, true, false, false, true, false, "success", "skipped", true, 1},
		{"proxy unavailable before preserves direct failure", true, true, true, false, false, false, false, "failure", "skipped", false, 1},
		{"proxy fails after preserves direct success", true, true, true, true, false, true, false, "success", "skipped", true, 2},
		{"proxy fails after preserves direct failure", true, true, true, true, false, false, true, "failure", "skipped", false, 2},
		{"proxy only failure", false, true, true, false, false, false, false, "", "skipped", false, 0},
		{"direct control fails but SOCKS works", true, true, false, true, true, false, true, "skipped", "success", true, 1},
		{"SOCKS only with no direct control", false, true, false, true, true, false, true, "", "success", true, 1},
		{"direct only does not use stored proxy", true, false, true, false, false, true, false, "success", "", true, 1},
		{"both off", false, false, true, false, false, false, false, "", "", false, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			routes := RouteSelection{test.direct, test.socks, 3}
			job := sampleJob()
			job.Routes = &routes
			proxy := ProxyConfig{URL: "socks5://user:pass@proxy.example.com:1080", Revision: 3}
			if test.socks {
				job.ProxyURL = proxy.URL
			}
			var received []Result
			var mu sync.Mutex
			probes, checks := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/agent/poll":
					jobs := []Job{}
					if test.direct || test.socks {
						jobs = append(jobs, job)
					}
					json.NewEncoder(w).Encode(map[string]any{"jobs": jobs, "proxy": proxy, "routes": routes})
				case "/api/agent/proxy-status":
					json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
				case "/api/agent/results":
					var payload struct {
						Results []Result `json:"results"`
					}
					json.NewDecoder(r.Body).Decode(&payload)
					received = payload.Results
					json.NewEncoder(w).Encode(map[string]int{"accepted": len(received)})
				default:
					t.Error(r.URL.Path)
				}
			}))
			defer server.Close()
			s := sampleSettings()
			s.ControlPlaneURL, s.AllowInsecureHTTP = server.URL, true
			a, _ := New(s)
			a.HeartbeatFile = t.TempDir() + "/heartbeat"
			a.CheckControls = func(context.Context) bool { return test.directControl }
			a.CheckProxy = func(context.Context, string) ProxyStatus {
				checks++
				return ProxyStatus{OK: checks == 1 && test.proxyBefore || checks > 1 && test.proxyAfter}
			}
			a.Probe = func(_ context.Context, value Job) Result {
				mu.Lock()
				probes++
				mu.Unlock()
				ok := test.directSuccess
				if value.ProxyURL != "" {
					ok = test.socksSuccess
				}
				result := Result{JobID: value.JobID, OK: ok}
				if !ok {
					reason := "tunnel_unreachable"
					result.Error = &reason
				}
				return result
			}
			if _, err := a.Cycle(context.Background()); err != nil {
				t.Fatal(err)
			}
			if probes != test.probes {
				t.Fatal("unexpected probe count", probes)
			}
			if !test.direct && !test.socks {
				if len(received) != 0 || checks != 0 {
					t.Fatal("paused agent sent traffic")
				}
				return
			}
			if len(received) != 1 || received[0].OK != test.ok || received[0].Routes == nil {
				t.Fatalf("unexpected aggregate: %+v", received)
			}
			got := received[0].Routes
			direct, socks := "", ""
			if got.Direct != nil {
				direct = got.Direct.Outcome
			}
			if got.SOCKS5 != nil {
				socks = got.SOCKS5.Outcome
			}
			if direct != test.directOutcome || socks != test.socksOutcome {
				t.Fatalf("direct=%s socks=%s", direct, socks)
			}
			if !test.socks && checks != 0 {
				t.Fatal("disabled SOCKS route sent traffic")
			}
		})
	}
}

func TestRouteSelectionValidation(t *testing.T) {
	for _, raw := range []string{`null`, `{}`, `{"direct":true,"socks5":null,"revision":0}`, `{"direct":true,"socks5":false,"revision":-1}`, `{"direct":true,"socks5":false,"revision":1,"command":"sh"}`} {
		if _, err := decodeRoutes(json.RawMessage(raw)); err == nil {
			t.Fatal(raw)
		}
	}
	job := sampleJob()
	job.Routes = &RouteSelection{Direct: true, SOCKS5: true, Revision: 1}
	if job.Validate() == nil {
		t.Fatal("SOCKS route accepted without proxy")
	}
}
