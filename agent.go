package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

type Result struct {
	Routes    *RouteResults `json:"routes,omitempty"`
	JobID     string        `json:"job_id"`
	OK        bool          `json:"ok"`
	LatencyMS *float64      `json:"latency_ms"`
	Error     *string       `json:"error"`
}

type Agent struct {
	Settings      Settings
	Client        *DirectClient
	HeartbeatFile string
	// Dependency hooks support isolated protocol tests without weakening runtime
	// URL policy or introducing operator-controlled verification bypasses.
	CheckControls   func(context.Context) bool
	Probe           func(context.Context, Job) Result
	CheckProxy      func(context.Context, string) ProxyStatus
	LogReason       func(string)
	tunnelTLSConfig *tls.Config
}

func New(settings Settings) (*Agent, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	a := &Agent{Settings: settings, Client: NewDirectClient(), HeartbeatFile: HeartbeatPath, LogReason: func(reason string) { log.Print(reason) }}
	a.CheckControls, a.Probe = a.controlHealth, a.probe
	a.CheckProxy = a.checkProxy
	return a, nil
}

func (a *Agent) Cycle(ctx context.Context) (time.Duration, error) {
	healthy := a.CheckControls(ctx)
	poll := map[string]any{"agent_id": a.Settings.AgentID, "version": Version, "control_ok": healthy, "control_error": nil}
	if !healthy {
		poll["control_error"] = "control_unreachable"
	}
	response, err := a.api(ctx, "/api/agent/poll", poll)
	if err != nil {
		return 0, err
	}
	if err := writeHeartbeat(a.HeartbeatFile, time.Now()); err != nil {
		return 0, errors.New("heartbeat_failed")
	}
	delay := 10
	if value, ok := response["poll_after_seconds"]; ok {
		var parsed int
		if json.Unmarshal(value, &parsed) == nil && string(value) != "null" {
			delay = max(1, min(60, parsed))
		}
	}
	if _, exists := response["routes"]; exists {
		return a.routedCycle(ctx, response, healthy, delay)
	}
	var proxy *ProxyConfig
	if raw, ok := response["proxy"]; ok {
		config, err := decodeProxyConfig(raw)
		if err != nil {
			return 0, err
		}
		proxy = &config
		status := ProxyStatus{OK: true}
		if config.URL != "" {
			status = a.CheckProxy(ctx, config.URL)
		}
		if err := a.reportProxy(ctx, config, status); err != nil {
			return 0, err
		}
		if !status.OK {
			a.LogReason("proxy_unavailable_probing_paused")
			return time.Duration(delay) * time.Second, nil
		}
	}
	if !healthy {
		return time.Duration(delay) * time.Second, nil
	}
	jobs, err := DecodeJobs(response["jobs"])
	if err != nil {
		return 0, err
	}
	for _, job := range jobs {
		if proxy != nil && job.ProxyURL != proxy.URL {
			return 0, ErrBackendProtocol
		}
	}
	if len(jobs) == 0 {
		return time.Duration(delay) * time.Second, nil
	}
	results := make([]Result, len(jobs))
	done := make(chan int, len(jobs))
	for i, job := range jobs {
		go func(i int, job Job) { results[i] = a.Probe(ctx, job); done <- i }(i, job)
	}
	for range jobs {
		<-done
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	proxyOK := true
	if proxy != nil && proxy.URL != "" {
		status := a.CheckProxy(ctx, proxy.URL)
		if err := a.reportProxy(ctx, *proxy, status); err != nil {
			return 0, err
		}
		proxyOK = status.OK
	}
	if !proxyOK {
		a.LogReason("proxy_unavailable_results_suppressed")
	} else if a.CheckControls(ctx) {
		_, err = a.api(ctx, "/api/agent/results", map[string]any{"agent_id": a.Settings.AgentID, "results": results})
	} else {
		poll["control_ok"], poll["control_error"] = false, "control_unreachable"
		_, err = a.api(ctx, "/api/agent/poll", poll)
		a.LogReason("control_unreachable_results_suppressed")
	}
	return time.Duration(delay) * time.Second, err
}

func (a *Agent) Run(ctx context.Context) {
	for ctx.Err() == nil {
		delay, err := a.Cycle(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.LogReason("poll_cycle_failed")
			delay = 10 * time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func writeHeartbeat(path string, now time.Time) error {
	// A fresh private inode prevents following an existing symlink in writable /tmp.
	f, err := os.CreateTemp(filepath.Dir(path), ".dns-guard-heartbeat-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.WriteString(strconv.FormatFloat(float64(now.UnixNano())/1e9, 'f', 6, 64)); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func Healthy(path string, now time.Time) bool {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 100 {
		return false
	}
	seconds, err := strconv.ParseFloat(string(data), 64)
	age := float64(now.UnixNano())/1e9 - seconds
	return err == nil && !math.IsNaN(age) && !math.IsInf(age, 0) && age >= 0 && age <= 180
}

func portString(port int) string { return strconv.Itoa(port) }

func configFile(job Job, port int) (string, func(), error) {
	config, err := XrayConfig(job, port)
	if err != nil {
		return "", func() {}, err
	}
	directory, err := os.MkdirTemp("", "dns-guard-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	path := filepath.Join(directory, "config.json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	err = json.NewEncoder(f).Encode(config)
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

// stopProcess always reaps the child. WaitDelay closes any inherited pipes;
// SIGKILL is followed by a bounded wait after the graceful SIGTERM allowance.
func stopProcess(cmd *exec.Cmd, done <-chan struct{}) {
	select {
	case <-done:
		return
	default:
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-timer.C:
	}
	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func (a *Agent) probe(parent context.Context, job Job) Result {
	started := time.Now()
	failure := func(reason string) Result { return Result{JobID: job.JobID, Error: &reason} }
	if err := job.Validate(); err != nil {
		return failure("invalid_job")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return failure("xray_start_failed")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	path, cleanup, err := configFile(job, port)
	if err != nil {
		return failure("xray_start_failed")
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(parent, time.Duration(job.TimeoutSeconds)*time.Second)
	defer cancel()
	cmd := exec.Command(a.Settings.XrayBin, "run", "-config", path)
	// Nil stdout/stderr are connected to the null device by os/exec.
	cmd.WaitDelay = 2 * time.Second
	if err = cmd.Start(); err != nil {
		return failure("xray_start_failed")
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	defer stopProcess(cmd, done)
	ready := false
	for i := 0; i < 40; i++ {
		select {
		case <-done:
			return failure("xray_start_failed")
		default:
		}
		if ctx.Err() != nil {
			return failure("probe_timeout")
		}
		dialCtx, dialCancel := context.WithTimeout(ctx, 50*time.Millisecond)
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort("127.0.0.1", portString(port)))
		dialCancel()
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			return failure("probe_timeout")
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !ready {
		return failure("xray_start_failed")
	}
	if a.tunnelRequests(ctx, port) {
		ms := math.Round(float64(time.Since(started).Microseconds())/100) / 10
		return Result{JobID: job.JobID, OK: true, LatencyMS: &ms}
	}
	if ctx.Err() != nil {
		return failure("probe_timeout")
	}
	return failure("tunnel_unreachable")
}
