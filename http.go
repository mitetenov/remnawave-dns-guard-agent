package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"sync/atomic"
	"time"
)

const maxResponseBytes = 256 * 1024

type AddressResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}
type ContextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// DirectClient pins each connection to one validated DNS answer; the original
// request URL still supplies TLS SNI, certificate hostname, and HTTP Host.
type DirectClient struct {
	Resolver  AddressResolver
	Dialer    ContextDialer
	TLSConfig *tls.Config
	// LogFailure may be called concurrently by the parallel control requests.
	LogFailure func(RequestFailure)
}

func NewDirectClient() *DirectClient {
	return &DirectClient{Resolver: net.DefaultResolver, Dialer: &net.Dialer{Timeout: 5 * time.Second}, LogFailure: logRequestFailure}
}

func (c *DirectClient) transport(allowPrivate bool) *http.Transport {
	return &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: c.TLSConfig, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, &requestPhaseError{"tcp", err}
			}
			var addresses []netip.Addr
			if literal, err := netip.ParseAddr(host); err == nil {
				addresses = []netip.Addr{literal}
			} else {
				addresses, err = c.Resolver.LookupNetIP(ctx, "ip", host)
				if err != nil {
					return nil, &requestPhaseError{"dns", err}
				}
			}
			if len(addresses) == 0 {
				return nil, &requestPhaseError{"dns", errNoAddresses}
			}
			for _, ip := range addresses {
				if !ip.IsValid() || (!allowPrivate && !PublicAddress(ip)) {
					return nil, &requestPhaseError{"address_policy", errBlockedAddress}
				}
			}
			var lastError error
			for _, ip := range addresses {
				conn, err := c.Dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				lastError = err
				if ctx.Err() != nil {
					break
				}
			}
			return nil, &requestPhaseError{"tcp", lastError}
		}}
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func (c *DirectClient) Request(ctx context.Context, rawURL, method string, payload any, token string, allowPrivate bool) (result map[string]json.RawMessage, healthy bool, err error) {
	started := time.Now()
	diagnostic := RequestFailure{Event: "request_failed", Kind: "control", Method: method, URL: diagnosticURL(rawURL), Phase: "request", Reason: "invalid_request"}
	if payload != nil {
		diagnostic.Kind = "backend"
	}
	defer func() {
		if c.LogFailure != nil && (err != nil || !healthy) {
			diagnostic.Time = time.Now().UTC().Format(time.RFC3339Nano)
			diagnostic.DurationMS = time.Since(started).Milliseconds()
			c.LogFailure(diagnostic)
		}
	}()
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, false, ErrBackendProtocol
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, false, ErrInvalidSettings
	}
	req.Header.Set("User-Agent", "DNSGuard-Agent/"+Version)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	transport := c.transport(allowPrivate)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: noRedirect, Timeout: 5 * time.Second}
	var phase atomic.Value
	phase.Store("request")
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { phase.Store("dns") },
		ConnectStart:      func(string, string) { phase.Store("tcp") },
		TLSHandshakeStart: func() { phase.Store("tls") },
		GotConn:           func(httptrace.GotConnInfo) { phase.Store("http") },
	}))
	response, requestErr := client.Do(req)
	if requestErr != nil {
		diagnostic.Phase = phase.Load().(string)
		diagnostic.Reason = failureReason(requestErr)
		var phaseError *requestPhaseError
		if errors.As(requestErr, &phaseError) {
			diagnostic.Phase = phaseError.phase
		}
		return nil, false, errors.New("backend_unreachable")
	}
	defer response.Body.Close()
	diagnostic.HTTPStatus = response.StatusCode
	diagnostic.Phase, diagnostic.Reason = "http", "status"
	if payload == nil {
		return nil, response.StatusCode >= 200 && response.StatusCode < 400, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, false, errors.New("backend_unreachable")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		diagnostic.Phase, diagnostic.Reason = "response", failureReason(err)
		return nil, false, ErrBackendProtocol
	}
	if len(data) > maxResponseBytes {
		diagnostic.Phase, diagnostic.Reason = "response", "too_large"
		return nil, false, ErrBackendProtocol
	}
	if err := strictJSON(data, &result); err != nil || result == nil {
		diagnostic.Phase, diagnostic.Reason = "response", "invalid_json"
		return nil, false, ErrBackendProtocol
	}
	return result, true, nil
}

func (a *Agent) controlHealth(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	results := make(chan bool, len(a.Settings.ControlURLs))
	for _, value := range a.Settings.ControlURLs {
		go func(value string) {
			_, healthy, err := a.Client.Request(ctx, value, "GET", nil, "", false)
			results <- healthy && err == nil
		}(value)
	}
	healthy := false
	for range a.Settings.ControlURLs {
		healthy = <-results || healthy
	}
	return healthy
}

func (a *Agent) api(ctx context.Context, path string, body any) (map[string]json.RawMessage, error) {
	u, err := ParseURL(a.Settings.ControlPlaneURL, a.Settings.AllowInsecureHTTP, true)
	if err != nil {
		return nil, err
	}
	u.Path = trimSlash(u.Path) + path
	u.RawPath = ""
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	result, _, err := a.Client.Request(ctx, u.String(), "POST", body, a.Settings.Token, a.Settings.AllowInsecureHTTP)
	return result, err
}

func trimSlash(path string) string {
	for len(path) > 0 && path[len(path)-1] == '/' {
		path = path[:len(path)-1]
	}
	return path
}

func (a *Agent) tunnelRequests(ctx context.Context, port int) bool {
	proxyURL := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", portString(port))}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true, TLSClientConfig: a.tunnelTLSConfig, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: noRedirect, Timeout: 5 * time.Second}
	perURL := 8 * time.Second / time.Duration(len(a.Settings.ProbeURLs))
	for _, value := range a.Settings.ProbeURLs {
		requestCtx, cancel := context.WithTimeout(ctx, perURL)
		req, err := http.NewRequestWithContext(requestCtx, "GET", value, nil)
		if err == nil {
			response, err := client.Do(req)
			if err == nil {
				response.Body.Close()
				if response.StatusCode >= 200 && response.StatusCode < 400 {
					cancel()
					return true
				}
			}
		}
		cancel()
		if ctx.Err() != nil {
			return false
		}
	}
	return false
}
