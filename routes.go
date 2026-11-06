package agent

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

type RouteSelection struct {
	Direct   bool  `json:"direct"`
	SOCKS5   bool  `json:"socks5"`
	Revision int64 `json:"revision"`
}
type RouteResult struct {
	Outcome   string   `json:"outcome"`
	LatencyMS *float64 `json:"latency_ms,omitempty"`
	Error     string   `json:"error,omitempty"`
}
type RouteResults struct {
	Direct *RouteResult `json:"direct,omitempty"`
	SOCKS5 *RouteResult `json:"socks5,omitempty"`
}

func decodeRoutes(raw json.RawMessage) (RouteSelection, error) {
	var value RouteSelection
	var fields map[string]json.RawMessage
	if strictJSON(raw, &value) != nil || json.Unmarshal(raw, &fields) != nil || fields == nil || value.Revision < 0 {
		return value, ErrBackendProtocol
	}
	for _, key := range []string{"direct", "socks5", "revision"} {
		if fields[key] == nil || string(fields[key]) == "null" {
			return value, ErrBackendProtocol
		}
	}
	return value, nil
}

func skippedRoute(reason string) *RouteResult { return &RouteResult{Outcome: "skipped", Error: reason} }
func routeResult(result Result) *RouteResult {
	if result.OK {
		return &RouteResult{Outcome: "success", LatencyMS: result.LatencyMS}
	}
	reason := "probe_failed"
	if result.Error != nil {
		reason = *result.Error
	}
	if oneOf(reason, "xray_start_failed", "xray_config_invalid", "invalid_job", "control_unhealthy", "control_unreachable", "proxy_unavailable") {
		return skippedRoute(reason)
	}
	return &RouteResult{Outcome: "failure", Error: reason}
}

func aggregateRouteResults(id string, routes *RouteResults) Result {
	result := Result{JobID: id, Routes: routes}
	for _, value := range []*RouteResult{routes.Direct, routes.SOCKS5} {
		if value == nil || value.Outcome == "skipped" {
			continue
		}
		if value.Outcome == "failure" {
			reason := value.Error
			result.OK = false
			result.Error = &reason
			result.LatencyMS = nil
			return result
		}
		result.OK = true
		if value.LatencyMS != nil && (result.LatencyMS == nil || *value.LatencyMS > *result.LatencyMS) {
			result.LatencyMS = value.LatencyMS
		}
	}
	if !result.OK {
		reason := "no_valid_routes"
		result.Error = &reason
	}
	return result
}

// Both routes share one bounded queue. A slow direct probe cannot prevent
// idle workers from starting SOCKS5 probes; at most MaxJobs Xray processes run.
func (a *Agent) probeRoutes(ctx context.Context, jobs []Job, routes RouteSelection, controlOK, proxyOK bool) []RouteResults {
	results := make([]RouteResults, len(jobs))
	tasks := make(chan func(), len(jobs)*2)
	for i, job := range jobs {
		job.Routes = nil
		if routes.Direct {
			if controlOK {
				direct := job
				direct.ProxyURL = ""
				tasks <- func() { results[i].Direct = routeResult(a.Probe(ctx, direct)) }
			} else {
				results[i].Direct = skippedRoute("control_unhealthy")
			}
		}
		if routes.SOCKS5 {
			if proxyOK {
				tasks <- func() { results[i].SOCKS5 = routeResult(a.Probe(ctx, job)) }
			} else {
				results[i].SOCKS5 = skippedRoute("proxy_unavailable")
			}
		}
	}
	close(tasks)
	var workers sync.WaitGroup
	for range min(MaxJobs, len(tasks)) {
		workers.Go(func() {
			for task := range tasks {
				if ctx.Err() != nil {
					return
				}
				task()
			}
		})
	}
	workers.Wait()
	return results
}

func (a *Agent) routedCycle(ctx context.Context, response map[string]json.RawMessage, controlOK bool, delay int) (time.Duration, error) {
	duration := time.Duration(delay) * time.Second
	routes, err := decodeRoutes(response["routes"])
	if err != nil {
		return 0, err
	}
	proxy, err := decodeProxyConfig(response["proxy"])
	if err != nil || proxy.Revision != routes.Revision || routes.SOCKS5 && proxy.URL == "" {
		return 0, ErrBackendProtocol
	}
	jobs, err := DecodeJobs(response["jobs"])
	if err != nil {
		return 0, err
	}
	for _, job := range jobs {
		expectedProxy := ""
		if routes.SOCKS5 {
			expectedProxy = proxy.URL
		}
		if job.Routes == nil || *job.Routes != routes || job.ProxyURL != expectedProxy {
			return 0, ErrBackendProtocol
		}
	}
	status := ProxyStatus{ControlOK: &controlOK}
	if proxy.URL != "" && (routes.SOCKS5 || proxy.TestID != "") {
		status = a.CheckProxy(ctx, proxy.URL)
		status.Checked = true
		status.ControlOK = &controlOK
	}
	if err := a.reportProxy(ctx, proxy, status); err != nil {
		return 0, err
	}
	if len(jobs) == 0 {
		return time.Duration(max(1, delay)) * time.Second, nil
	}
	if !routes.Direct && !routes.SOCKS5 {
		return 0, ErrBackendProtocol
	}
	results := a.probeRoutes(ctx, jobs, routes, controlOK, status.OK)
	if routes.SOCKS5 {
		if status.OK {
			status = a.CheckProxy(ctx, proxy.URL)
			status.Checked = true
			if !status.OK {
				for i := range results {
					results[i].SOCKS5 = skippedRoute("proxy_unavailable")
				}
			}
		}
	}
	if routes.Direct && controlOK {
		controlOK = a.CheckControls(ctx)
		if !controlOK {
			for i := range results {
				results[i].Direct = skippedRoute("control_unhealthy")
			}
		}
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	status.ControlOK = &controlOK
	if err := a.reportProxy(ctx, proxy, status); err != nil {
		return 0, err
	}
	combined := make([]Result, len(jobs))
	for i, job := range jobs {
		combined[i] = aggregateRouteResults(job.JobID, &results[i])
	}
	_, err = a.api(ctx, "/api/agent/results", map[string]any{"agent_id": a.Settings.AgentID, "results": combined})
	return duration, err
}
