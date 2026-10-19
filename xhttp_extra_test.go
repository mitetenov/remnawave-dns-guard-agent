package agent

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestXHTTPExtraWireAndConfig(t *testing.T) {
	for _, security := range []string{"tls", "reality"} {
		job := SyntheticJobs()[2]
		job.Profile.Security = security
		job.Profile.Host = "edge.example.com"
		job.Profile.Path = "/probe"
		job.Profile.XHTTPExtra = json.RawMessage(`{"xPaddingBytes":"100-1000","noGRPCHeader":true,"headers":{"X-Token":"a+b%20c"},"xmux":{"maxConcurrency":"16-32"},"host":"ignored.example.com","path":"/ignored","mode":"ignored"}`)
		wire, err := json.Marshal([]Job{job})
		if err != nil {
			t.Fatal(err)
		}
		jobs, err := DecodeJobs(wire)
		if err != nil {
			t.Fatal(err)
		}
		config, err := XrayConfig(jobs[0], 12345)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Outbounds []struct {
				Settings struct {
					Vnext []struct {
						Address string
						Port    int
					}
				}
				StreamSettings struct {
					Network       string
					XHTTPSettings struct {
						Path, Host, Mode string
						Extra            json.RawMessage
					}
					TLSSettings struct {
						AllowInsecure bool
						ServerName    string
					}
				}
			}
		}
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		out := decoded.Outbounds
		if len(out) != 1 || out[0].Settings.Vnext[0].Address != job.IP || out[0].Settings.Vnext[0].Port != job.Profile.Port {
			t.Fatal("destination changed")
		}
		settings := out[0].StreamSettings.XHTTPSettings
		if settings.Path != "/probe" || settings.Host != "edge.example.com" || settings.Mode != job.Profile.XHTTPMode || !bytes.Equal(settings.Extra, job.Profile.XHTTPExtra) {
			t.Fatal("extra lost, flattened or replaced outer fields")
		}
		if security == "tls" && (out[0].StreamSettings.TLSSettings.AllowInsecure || out[0].StreamSettings.TLSSettings.ServerName != job.Profile.ServerName) {
			t.Fatal("TLS changed")
		}
	}
	// Invalid extra must fail at the job boundary, before Xray or network access.
	job := SyntheticJobs()[2]
	job.Profile.XHTTPExtra = json.RawMessage(`{"downloadSettings":{"address":"127.0.0.1"}}`)
	wire, _ := json.Marshal([]Job{job})
	if _, err := DecodeJobs(wire); err == nil {
		t.Fatal("unsafe extra accepted")
	}
}

func TestXHTTPExtraSchema(t *testing.T) {
	data, err := os.ReadFile("testdata/xhttp-extra.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases struct{ Valid, Invalid []json.RawMessage }
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, value := range cases.Valid {
		if !validXHTTPExtra(value, "xhttp", "stream-up") {
			t.Errorf("rejected valid extra: %s", value)
		}
		if validXHTTPExtra(value, "tcp", "auto") {
			t.Error("TCP extra accepted")
		}
	}
	for _, value := range cases.Invalid {
		if validXHTTPExtra(value, "xhttp", "stream-up") {
			t.Errorf("accepted invalid extra: %s", value)
		}
	}
	if validXHTTPExtra(json.RawMessage(`{"headers":{"X-Pad":"`+strings.Repeat("x", 16384)+`"}}`), "xhttp", "auto") {
		t.Error("oversized extra")
	}
	if validXHTTPExtra(json.RawMessage(`{"headers":{"X-Pad":"`+strings.Repeat("<", 3000)+`"}}`), "xhttp", "auto") {
		t.Error("HTML escaping exceeds wire size")
	}
	if !validXHTTPExtra(nil, "tcp", "auto") {
		t.Error("legacy profile rejected")
	}
	if !validXHTTPExtra(json.RawMessage(`{"uplinkHTTPMethod":"GET","uplinkDataPlacement":"cookie"}`), "xhttp", "packet-up") {
		t.Error("packet-up fields rejected")
	}
}
