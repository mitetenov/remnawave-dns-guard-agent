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
	"net/netip"
	"net/url"
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
}

func NewDirectClient() *DirectClient {
	return &DirectClient{Resolver: net.DefaultResolver, Dialer: &net.Dialer{Timeout: 5 * time.Second}}
}

func (c *DirectClient) transport(allowPrivate bool) *http.Transport {
	return &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: c.TLSConfig, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, errors.New("connection_failed")
			}
			var addresses []netip.Addr
			if literal, err := netip.ParseAddr(host); err == nil {
				addresses = []netip.Addr{literal}
			} else {
				addresses, err = c.Resolver.LookupNetIP(ctx, "ip", host)
				if err != nil {
					return nil, errors.New("control_unreachable")
				}
			}
			if len(addresses) == 0 {
				return nil, errors.New("control_unreachable")
			}
			for _, ip := range addresses {
				if !ip.IsValid() || (!allowPrivate && !PublicAddress(ip)) {
					return nil, errors.New("control_unreachable")
				}
			}
			for _, ip := range addresses {
				conn, err := c.Dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				if ctx.Err() != nil {
					break
				}
			}
			return nil, errors.New("connection_failed")
		}}
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func (c *DirectClient) Request(ctx context.Context, rawURL, method string, payload any, token string, allowPrivate bool) (map[string]json.RawMessage, bool, error) {
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
	response, err := client.Do(req)
	if err != nil {
		return nil, false, errors.New("backend_unreachable")
	}
	defer response.Body.Close()
	if payload == nil {
		return nil, response.StatusCode >= 200 && response.StatusCode < 400, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, false, errors.New("backend_unreachable")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(data) > maxResponseBytes {
		return nil, false, ErrBackendProtocol
	}
	var result map[string]json.RawMessage
	if err := strictJSON(data, &result); err != nil || result == nil {
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
