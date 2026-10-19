package agent

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestALPNWireAndGeneratedTLSSettings(t *testing.T) {
	data, err := os.ReadFile("testdata/profile-alpn.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Profile Profile }
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	job := sampleJob()
	job.Profile = fixture.Profile
	wire, _ := json.Marshal([]Job{job})
	jobs, err := DecodeJobs(wire)
	if err != nil {
		t.Fatal(err)
	}
	for _, protocols := range [][]string{{"h2", "http/1.1"}, {"http/1.1"}, {"h3"}} {
		jobs[0].Profile.ALPN = protocols
		config, err := XrayConfig(jobs[0], 12345)
		if err != nil {
			t.Fatal(err)
		}
		out := config["outbounds"].([]any)
		if len(out) != 1 {
			t.Fatal("unexpected fallback")
		}
		outbound := out[0].(map[string]any)
		destination := outbound["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
		stream := outbound["streamSettings"].(map[string]any)
		tls := stream["tlsSettings"].(map[string]any)
		got, _ := json.Marshal(tls["alpn"])
		want, _ := json.Marshal(protocols)
		if !bytes.Equal(got, want) || tls["allowInsecure"] != false || tls["serverName"] != fixture.Profile.ServerName || tls["fingerprint"] != "firefox" || destination["address"] != job.IP {
			t.Fatal("ALPN, TLS verification or destination changed")
		}
		extra := stream["xhttpSettings"].(map[string]any)["extra"]
		got, _ = json.Marshal(extra)
		want, _ = json.Marshal(fixture.Profile.XHTTPExtra)
		if !bytes.Equal(got, want) {
			t.Fatal("ALPN lost XHTTP extra")
		}
	}
	// Explicit null and wrong JSON shapes fail before any probe can start.
	for _, value := range []string{`null`, `"h2"`, `[null]`, `["h2\r\nX:1"]`} {
		bad := bytes.Replace(wire, []byte(`"alpn":["h2","http/1.1"]`), []byte(`"alpn":`+value), 1)
		if bytes.Equal(wire, bad) {
			t.Fatal("bad fixture replacement")
		}
		if _, err := DecodeJobs(bad); err == nil {
			t.Fatal("bad ALPN decoded")
		}
	}
	// Missing ALPN retains the legacy config shape.
	job.Profile.ALPN = nil
	config, err := XrayConfig(job, 12345)
	if err != nil {
		t.Fatal(err)
	}
	tls := config["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)
	if _, ok := tls["alpn"]; ok {
		t.Fatal("default ALPN overridden")
	}
}

func TestALPNValidation(t *testing.T) {
	data, err := os.ReadFile("testdata/profile-alpn.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases struct{ Valid, Invalid []json.RawMessage }
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, raw := range cases.Valid {
		var protocols []string
		if err := json.Unmarshal(raw, &protocols); err != nil || !validALPN(protocols, "tls") {
			t.Errorf("valid ALPN rejected: %s", raw)
		}
	}
	for _, raw := range cases.Invalid {
		// Null is rejected by the strict HTTP/job decoder before slice validation.
		if string(raw) == "null" {
			continue
		}
		var protocols []string
		if err := json.Unmarshal(raw, &protocols); err == nil && validALPN(protocols, "tls") {
			t.Errorf("invalid ALPN accepted: %s", raw)
		}
	}
	if validALPN([]string{"h2"}, "reality") || validALPN(make([]string, 17), "tls") || validALPN([]string{strings.Repeat("a", 256)}, "tls") {
		t.Error("context/length validation failed")
	}
	if !validALPN(nil, "reality") {
		t.Error("legacy profile rejected")
	}
}
