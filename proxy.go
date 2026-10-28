package agent

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ProxyConfig struct {
	URL      string `json:"url"`
	Revision int64  `json:"revision"`
	TestID   string `json:"test_id,omitempty"`
}

type ProxyStatus struct {
	Checked   bool     `json:"-"`
	ControlOK *bool    `json:"-"`
	OK        bool     `json:"ok"`
	LatencyMS *float64 `json:"latency_ms"`
	ExitIP    string   `json:"exit_ip"`
}

func decodeProxyConfig(raw json.RawMessage) (ProxyConfig, error) {
	var config ProxyConfig
	var fields map[string]json.RawMessage
	if strictJSON(raw, &config) != nil || json.Unmarshal(raw, &fields) != nil || fields == nil || fields["url"] == nil || fields["revision"] == nil || config.Revision < 0 || !bounded(config.TestID, 100) {
		return config, ErrBackendProtocol
	}
	for _, value := range fields {
		if string(value) == "null" {
			return config, ErrBackendProtocol
		}
	}
	if config.URL != "" {
		if _, err := parseProxyURL(config.URL); err != nil {
			return config, ErrBackendProtocol
		}
	}
	return config, nil
}

func parseProxyURL(value string) (*url.URL, error) {
	if len(value) > 2048 {
		return nil, ErrInvalidSettings
	}
	u, err := url.Parse(value)
	if err != nil {
		return nil, ErrInvalidSettings
	}
	port, err := strconv.Atoi(u.Port())
	ip, ipErr := netip.ParseAddr(u.Hostname())
	validEndpointHost := hostname(u.Hostname(), false)
	if ipErr == nil {
		validEndpointHost = ip.IsGlobalUnicast() || ip.IsLoopback()
	}
	if err != nil || port < 1 || port > 65535 || !oneOf(u.Scheme, "socks5", "socks5h") || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || strings.ContainsAny(value, "\r\n\t#?") || !validEndpointHost {
		return nil, ErrInvalidSettings
	}
	if u.User != nil {
		pass, ok := u.User.Password()
		if !ok || len(u.User.Username()) < 1 || len(u.User.Username()) > 255 || len(pass) < 1 || len(pass) > 255 || strings.ContainsAny(u.User.Username()+pass, "\x00\r\n") {
			return nil, ErrInvalidSettings
		}
	}
	u.Scheme = "socks5h"
	return u, nil
}

// An independent HTTPS check prevents a failed proxy from being counted as
// every VLESS target being blocked. Destination DNS is resolved by SOCKS5.
func (a *Agent) checkProxy(ctx context.Context, value string) ProxyStatus {
	started := time.Now()
	u, err := parseProxyURL(value)
	if err != nil {
		return ProxyStatus{}
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true, TLSClientConfig: a.tunnelTLSConfig, TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 4 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: noRedirect, Timeout: 5 * time.Second}
	results := make(chan ProxyStatus, len(a.Settings.ControlURLs))
	for _, endpoint := range a.Settings.ControlURLs {
		go func(endpoint string) {
			status := ProxyStatus{}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
			if err == nil {
				response, err := client.Do(request)
				if err == nil {
					body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
					response.Body.Close()
					status.OK = readErr == nil && response.StatusCode >= 200 && response.StatusCode < 300
					if status.OK {
						ms := math.Round(float64(time.Since(started).Microseconds())/100) / 10
						status.LatencyMS = &ms
						if request.URL.Hostname() == "www.cloudflare.com" && request.URL.Path == "/cdn-cgi/trace" {
							for _, line := range strings.Split(string(body), "\n") {
								if strings.HasPrefix(line, "ip=") {
									ip, err := netip.ParseAddr(strings.TrimPrefix(line, "ip="))
									if err == nil && PublicAddress(ip) {
										status.ExitIP = ip.String()
									}
								}
							}
						}
					}
				}
			}
			results <- status
		}(endpoint)
	}
	status := ProxyStatus{}
	for range a.Settings.ControlURLs {
		result := <-results
		if result.OK && (!status.OK || result.ExitIP != "") {
			status = result
		}
	}
	return status
}

func (a *Agent) reportProxy(ctx context.Context, config ProxyConfig, status ProxyStatus) error {
	payload := map[string]any{"agent_id": a.Settings.AgentID, "revision": config.Revision, "test_id": config.TestID, "ok": status.OK, "latency_ms": status.LatencyMS, "exit_ip": status.ExitIP}
	if status.ControlOK != nil {
		payload["checked"], payload["control_ok"] = status.Checked, *status.ControlOK
	}
	response, err := a.api(ctx, "/api/agent/proxy-status", payload)
	if err != nil {
		return err
	}
	var accepted bool
	if json.Unmarshal(response["accepted"], &accepted) != nil || !accepted {
		return ErrBackendProtocol
	}
	return nil
}
