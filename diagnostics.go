package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/url"
	"syscall"
)

// RequestFailure contains only safe diagnostic fields, never headers, bodies,
// credentials, query strings, or the underlying error's untrusted text.
type RequestFailure struct {
	Event      string `json:"event"`
	Time       string `json:"time"`
	Kind       string `json:"kind"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	DurationMS int64  `json:"duration_ms"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Phase      string `json:"phase"`
	Reason     string `json:"reason"`
}

func logRequestFailure(failure RequestFailure) {
	data, _ := json.Marshal(failure)
	log.Print(string(data))
}

func diagnosticURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "invalid_url"
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path, RawPath: u.RawPath}).String()
}

// Keep transport causes until the local diagnostic is recorded. Request still
// returns the existing enumerated errors to its callers and the backend.
type requestPhaseError struct {
	phase string
	err   error
}

func (e *requestPhaseError) Error() string { return e.phase + "_failed" }
func (e *requestPhaseError) Unwrap() error { return e.err }

var errNoAddresses = errors.New("no_addresses")
var errBlockedAddress = errors.New("blocked_address")

func failureReason(err error) string {
	var phase *requestPhaseError
	if errors.As(err, &phase) {
		err = phase.err
	}
	var dns *net.DNSError
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &dns) && dns.IsNotFound:
		return "not_found"
	case errors.Is(err, errNoAddresses):
		return "no_addresses"
	case errors.Is(err, errBlockedAddress):
		return "blocked_address"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection_refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection_reset"
	case errors.Is(err, syscall.ENETUNREACH):
		return "network_unreachable"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "host_unreachable"
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return "unexpected_eof"
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return "timeout"
	}
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var certificate x509.CertificateInvalidError
	var verification *tls.CertificateVerificationError
	switch {
	case errors.As(err, &authority):
		return "certificate_untrusted"
	case errors.As(err, &hostname):
		return "certificate_hostname"
	case errors.As(err, &certificate), errors.As(err, &verification):
		return "certificate_invalid"
	case dns != nil && dns.IsTemporary:
		return "temporary_error"
	default:
		return "request_error"
	}
}
