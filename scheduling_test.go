package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestBothRoutesShareBoundedWorkers(t *testing.T) {
	a, err := New(sampleSettings())
	if err != nil {
		t.Fatal(err)
	}
	jobs := make([]Job, MaxJobs)
	for i := range jobs {
		jobs[i] = sampleJob()
		jobs[i].ProxyURL = "socks5://proxy.example.com:1080"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	entered := make(chan bool, MaxJobs*2)
	release := make(chan struct{})
	var active, peak atomic.Int32
	a.Probe = func(ctx context.Context, job Job) Result {
		n := active.Add(1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		entered <- job.ProxyURL != ""
		select {
		case <-release:
		case <-ctx.Done():
		}
		active.Add(-1)
		return Result{JobID: job.JobID, OK: true}
	}
	done := make(chan []RouteResults, 1)
	go func() { done <- a.probeRoutes(ctx, jobs, RouteSelection{Direct: true, SOCKS5: true}, true, true) }()
	direct, socks := false, false
	for range MaxJobs {
		select {
		case viaProxy := <-entered:
			direct = direct || !viaProxy
			socks = socks || viaProxy
		case <-ctx.Done():
			t.Fatal("workers did not fill their capacity")
		}
	}
	if !direct || !socks {
		t.Fatal("one route blocked the other route's queue")
	}
	close(release)
	select {
	case results := <-done:
		if peak.Load() != MaxJobs || len(results) != MaxJobs {
			t.Fatal("unexpected concurrency", peak.Load(), len(results))
		}
		for _, result := range results {
			if result.Direct == nil || result.SOCKS5 == nil || result.Direct.Outcome != "success" || result.SOCKS5.Outcome != "success" {
				t.Fatal("lost route evidence", result)
			}
		}
	case <-ctx.Done():
		t.Fatal("workers did not complete")
	}
}

func TestImmediateRefillHintRetainsIdleBackoff(t *testing.T) {
	for _, routed := range []bool{false, true} {
		for _, withJobs := range []bool{false, true} {
			routes := RouteSelection{Direct: true}
			job := sampleJob()
			job.Routes = &routes
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/agent/poll" {
					json.NewEncoder(w).Encode(map[string]any{"accepted": true})
					return
				}
				jobs := []Job{}
				if withJobs {
					jobs = append(jobs, job)
				}
				response := map[string]any{"jobs": jobs, "poll_after_seconds": 0}
				if routed {
					response["routes"], response["proxy"] = routes, ProxyConfig{}
				}
				json.NewEncoder(w).Encode(response)
			}))
			settings := sampleSettings()
			settings.ControlPlaneURL, settings.AllowInsecureHTTP = server.URL, true
			a, _ := New(settings)
			a.HeartbeatFile = t.TempDir() + "/heartbeat"
			a.CheckControls = func(context.Context) bool { return true }
			a.Probe = func(_ context.Context, job Job) Result { return Result{JobID: job.JobID, OK: true} }
			delay, err := a.Cycle(context.Background())
			server.Close()
			if err != nil || withJobs && delay != 0 || !withJobs && delay < time.Second {
				t.Fatalf("routed=%v jobs=%v delay=%v error=%v", routed, withJobs, delay, err)
			}
		}
	}
}
