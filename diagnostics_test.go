package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func assertFailure(t *testing.T, got RequestFailure, kind, phase, reason string) {
	t.Helper()
	if got.Event != "request_failed" || got.Kind != kind || got.Phase != phase || got.Reason != reason || got.DurationMS < 0 {
		t.Fatalf("unexpected failure: %+v", got)
	}
	if _, err := time.Parse(time.RFC3339Nano, got.Time); err != nil {
		t.Fatal("missing diagnostic timestamp", got.Time)
	}
	data, err := json.Marshal(got)
	if err != nil || strings.Contains(string(data), "secret") {
		t.Fatalf("diagnostic exposed a secret: %s (%v)", data, err)
	}
}

func TestRequestFailureHTTPAndProtocolDiagnostics(t *testing.T) {
	for _, test := range []struct {
		name, body, kind, phase, reason string
		status                          int
		payload                         any
	}{
		{"control_status", "response-secret", "control", "http", "status", 503, nil},
		{"backend_status", "response-secret", "backend", "http", "status", 401, map[string]string{"value": "payload-secret"}},
		{"backend_protocol", "response-secret", "backend", "response", "invalid_json", 200, struct{}{}},
		{"backend_oversize", strings.Repeat("x", maxResponseBytes+1), "backend", "response", "too_large", 200, struct{}{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Error", "header-secret")
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			client := NewDirectClient()
			var failures []RequestFailure
			client.LogFailure = func(f RequestFailure) { failures = append(failures, f) }
			_, healthy, err := client.Request(context.Background(), server.URL+"/check?token=query-secret#fragment-secret", "GET", test.payload, "bearer-secret", true)
			if healthy || len(failures) != 1 || test.payload != nil && err == nil {
				t.Fatal(healthy, err, failures)
			}
			got := failures[0]
			assertFailure(t, got, test.kind, test.phase, test.reason)
			if got.HTTPStatus != test.status || got.URL != server.URL+"/check" || got.Method != "GET" {
				t.Fatal(got)
			}
		})
	}
}

func TestRequestFailurePreservesDNSCause(t *testing.T) {
	for _, test := range []struct {
		name, reason string
		cause        error
	}{
		{"not_found", "not_found", &net.DNSError{Err: "resolver-secret", Name: "name-secret", IsNotFound: true}},
		{"timeout", "timeout", &net.DNSError{Err: "resolver-secret", IsTimeout: true}},
		{"temporary", "temporary_error", &net.DNSError{Err: "resolver-secret", IsTemporary: true}},
		{"empty", "no_addresses", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := NewDirectClient()
			client.Resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
				return nil, test.cause
			})
			var failures []RequestFailure
			client.LogFailure = func(f RequestFailure) { failures = append(failures, f) }
			_, healthy, err := client.Request(context.Background(), "https://control.example/check?token=query-secret", "GET", nil, "", false)
			if err == nil || err.Error() != "backend_unreachable" || healthy || len(failures) != 1 {
				t.Fatal(healthy, err, failures)
			}
			assertFailure(t, failures[0], "control", "dns", test.reason)
		})
	}
}

func TestRequestFailureTLSFixtureVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("untrusted TLS connection reached HTTP handler")
	}))
	defer server.Close()
	client := NewDirectClient()
	var failures []RequestFailure
	client.LogFailure = func(f RequestFailure) { failures = append(failures, f) }
	_, _, err := client.Request(context.Background(), server.URL, "GET", nil, "", true)
	if err == nil || len(failures) != 1 {
		t.Fatal(err, failures)
	}
	assertFailure(t, failures[0], "control", "tls", "certificate_untrusted")
}

func TestRequestFailureHTTPFixtureHeaderTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	client := NewDirectClient()
	var failures []RequestFailure
	client.LogFailure = func(f RequestFailure) { failures = append(failures, f) }
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, _, err := client.Request(ctx, server.URL, "GET", nil, "", true)
	if err == nil || len(failures) != 1 {
		t.Fatal(err, failures)
	}
	assertFailure(t, failures[0], "control", "http", "timeout")
}

func TestControlFailureLoggedEvenWhenOtherControlSucceeds(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/failed" {
			w.WriteHeader(503)
		}
	}))
	defer server.Close()
	settings := sampleSettings()
	settings.ControlURLs = []string{"https://example.com/healthy", "https://example.com/failed?token=query-secret"}
	agent, err := New(settings)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	agent.Client.TLSConfig = &tls.Config{RootCAs: roots}
	agent.Client.Resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	})
	agent.Client.Dialer = dialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})
	var mu sync.Mutex
	var failures []RequestFailure
	agent.Client.LogFailure = func(f RequestFailure) {
		mu.Lock()
		defer mu.Unlock()
		failures = append(failures, f)
	}
	if !agent.controlHealth(context.Background()) {
		t.Fatal("one successful control must keep the agent healthy")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(failures) != 1 || failures[0].URL != "https://example.com/failed" {
		t.Fatal(failures)
	}
	assertFailure(t, failures[0], "control", "http", "status")
}

func TestDiagnosticURLRemovesCredentialsAndParameters(t *testing.T) {
	got := diagnosticURL("https://user-secret:password-secret@example.com/check?token=query-secret#fragment-secret")
	if got != "https://example.com/check" {
		t.Fatal(got)
	}
}
