package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestValidatedAddressFallbackAndCancellation(t *testing.T) {
	c := NewDirectClient()
	firstCanceled := make(chan struct{})
	winner, peer := net.Pipe()
	defer peer.Close()
	c.Dialer = dialerFunc(func(ctx context.Context, _, address string) (net.Conn, error) {
		if address == "1.1.1.1:443" {
			return winner, nil
		}
		if address != "[2606:4700::1111]:443" {
			t.Errorf("did not alternate address families: %s", address)
		}
		<-ctx.Done()
		close(firstCanceled)
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	conn, err := c.dialAddresses(ctx, []netip.Addr{netip.MustParseAddr("2606:4700::1111"), netip.MustParseAddr("2606:4700::1001"), netip.MustParseAddr("1.1.1.1")}, "443")
	if err != nil || conn != winner {
		t.Fatal("working IPv4 was not reached before deadline", err)
	}
	conn.Close()
	select {
	case <-firstCanceled:
	case <-time.After(time.Second):
		t.Fatal("losing attempt was not canceled")
	}
}

func TestLateLosingConnectionIsClosed(t *testing.T) {
	c := NewDirectClient()
	late, latePeer := net.Pipe()
	defer latePeer.Close()
	winner, winnerPeer := net.Pipe()
	defer winnerPeer.Close()
	release := make(chan struct{})
	c.Dialer = dialerFunc(func(_ context.Context, _, address string) (net.Conn, error) {
		if address == "1.1.1.1:443" {
			return winner, nil
		}
		<-release
		return late, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := c.dialAddresses(ctx, []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}, "443")
	close(release)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	latePeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := latePeer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("late losing connection leaked", err)
	}
}

func TestControlHealthReturnsAfterFirstSuccess(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	a, _ := New(sampleSettings())
	a.Settings.ControlURLs = []string{"https://example.com", "https://slow.example.com"}
	a.Client.TLSConfig = &tls.Config{RootCAs: roots}
	a.Client.Resolver = resolverFunc(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		ip := "1.1.1.1"
		if host == "slow.example.com" {
			ip = "8.8.8.8"
		}
		return []netip.Addr{netip.MustParseAddr(ip)}, nil
	})
	a.Client.Dialer = dialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "8.8.8.8:443" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if !a.controlHealth(ctx) || ctx.Err() != nil {
		t.Fatal("a slow control delayed an already successful health check", ctx.Err())
	}
}
