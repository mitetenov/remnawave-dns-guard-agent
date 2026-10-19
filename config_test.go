package agent

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func sampleJob() Job { return SyntheticJobs()[1] }
func sampleSettings() Settings {
	s := DefaultSettings()
	s.ControlPlaneURL, s.Token = "https://guard.example.com", strings.Repeat("x", 32)
	return s
}

func TestTenProfilesAndExactOutbound(t *testing.T) {
	jobs := SyntheticJobs()
	if len(jobs) != 10 {
		t.Fatalf("profiles=%d", len(jobs))
	}
	for _, job := range jobs {
		t.Run(job.Profile.Transport+"/"+job.Profile.Security+"/"+job.Profile.XHTTPMode, func(t *testing.T) {
			config, err := XrayConfig(job, 12345)
			if err != nil {
				t.Fatal(err)
			}
			outbounds := config["outbounds"].([]any)
			if len(outbounds) != 1 {
				t.Fatal("unexpected direct fallback")
			}
			outbound := outbounds[0].(map[string]any)
			destination := outbound["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
			if destination["address"] != job.IP || destination["port"] != 443 {
				t.Fatal(destination)
			}
			stream := outbound["streamSettings"].(map[string]any)
			if job.Profile.Security == "reality" {
				reality := stream["realitySettings"].(map[string]any)
				if reality["password"] != job.Profile.PublicKey || reality["serverName"] != "example.com" || reality["privateKey"] != nil || reality["publicKey"] != nil {
					t.Fatal(reality)
				}
			} else if stream["tlsSettings"].(map[string]any)["allowInsecure"] != false {
				t.Fatal("TLS verification disabled")
			}
			inbound := config["inbounds"].([]any)[0].(map[string]any)
			if inbound["listen"] != "127.0.0.1" || inbound["protocol"] != "http" {
				t.Fatal(inbound)
			}
		})
	}
}

func TestNonPublicDestinations(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "224.0.0.1", "240.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "::1", "fc00::1", "fe80::1", "2001:db8::1", "::ffff:127.0.0.1"} {
		t.Run(value, func(t *testing.T) {
			if PublicAddress(netip.MustParseAddr(value)) {
				t.Fatal("accepted non-public address")
			}
			j := sampleJob()
			j.IP = value
			if j.Validate() == nil {
				t.Fatal("accepted target")
			}
		})
	}
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "192.0.0.9", "2606:4700:4700::1111"} {
		if !PublicAddress(netip.MustParseAddr(value)) {
			t.Fatal(value)
		}
	}
}

func TestLegacyIPv4ClassificationParity(t *testing.T) {
	// Match Python 3.12's is_global classification used by the wire contract,
	// including the two global anycast exceptions in 192.0.0.0/24.
	for _, test := range []struct {
		address string
		public  bool
	}{
		{"8.8.8.8", true}, {"1.1.1.1", true}, {"192.0.0.8", false},
		{"192.0.0.9", true}, {"192.0.0.10", true}, {"192.0.0.11", false},
		{"192.0.0.172", false}, {"192.88.99.1", true}, {"192.88.99.2", true},
		{"10.0.0.1", false}, {"127.0.0.1", false}, {"100.64.0.1", false},
		{"192.0.2.1", false}, {"198.51.100.1", false}, {"224.0.0.1", false},
	} {
		t.Run(test.address, func(t *testing.T) {
			if got := PublicAddress(netip.MustParseAddr(test.address)); got != test.public {
				t.Fatalf("PublicAddress=%v, want %v", got, test.public)
			}
			job := sampleJob()
			job.IP = test.address
			if err := job.Validate(); (err == nil) != test.public {
				t.Fatalf("job validation=%v, public=%v", err, test.public)
			}
		})
	}
}

func TestUnicodeCharacterBoundsMatchLegacyAgent(t *testing.T) {
	job := sampleJob()
	job.Profile.Transport, job.Profile.Flow = "xhttp", ""
	for _, test := range []struct {
		path  string
		valid bool
	}{
		{"/" + strings.Repeat("я", 1500), true},
		{"/" + strings.Repeat("界", 2047), true},
		{"/" + strings.Repeat("😀", 2047), true},
		{"/" + strings.Repeat("я", 2048), false},
		{"/" + strings.Repeat("я", 1500) + "\n", false},
	} {
		job.Profile.Path = test.path
		data, _ := json.Marshal([]Job{job})
		jobs, err := DecodeJobs(data)
		if (err == nil) != test.valid {
			t.Fatalf("path len bytes=%d valid=%v: %v", len(test.path), test.valid, err)
		}
		if test.valid {
			config, err := XrayConfig(jobs[0], 12345)
			if err != nil {
				t.Fatal(err)
			}
			settings := config["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["xhttpSettings"].(map[string]any)
			if settings["path"] != test.path {
				t.Fatal("Unicode path changed")
			}
		}
	}
	// Token minimum is also specified in characters rather than UTF-8 bytes.
	s := sampleSettings()
	s.Token = strings.Repeat("я", 16)
	if s.Validate() == nil {
		t.Fatal("16 Unicode characters accepted as a 32-character token")
	}
	s.Token = strings.Repeat("я", 32)
	if err := s.Validate(); err != nil {
		t.Fatal("32-character token rejected", err)
	}
}

func TestStrictJobProtocolAndDefaults(t *testing.T) {
	j := sampleJob()
	data, _ := json.Marshal([]Job{j})
	for _, replace := range [][2]string{{`"port":443`, `"port":true`}, {`"port":443`, `"port":0`}, {`"timeout_seconds":15`, `"timeout_seconds":31`}, {`"transport":"tcp"`, `"transport":"ws"`}, {`"security":"reality"`, `"security":"none"`}, {`"short_id":"aabb"`, `"short_id":"abc"`}, {`"fingerprint":"chrome"`, `"fingerprint":"unknown"`}, {`"path":"/"`, `"path":"//host"`}, {`"server_name":"example.com"`, `"server_name":"evil\r\nHeader:x"`}, {`"transport":"tcp"`, `"transport":"xhttp"`}, {`"public_key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"`, `"public_key":"bad"`}, {`"port":443`, `"raw_config":{},"port":443`}, {`"job_id":"synthetic"`, `"command":"/bin/sh","job_id":"synthetic"`}} {
		modified := strings.Replace(string(data), replace[0], replace[1], 1)
		if modified == string(data) {
			t.Fatal("test replacement failed", replace)
		}
		if _, err := DecodeJobs([]byte(modified)); err == nil {
			t.Fatal("accepted invalid payload", modified)
		}
	}
	if _, err := DecodeJobs(append(data, []byte(` {}`)...)); err == nil {
		t.Fatal("trailing data")
	}
	for _, value := range []string{`null`, `{}`, `[{}]`, `[null]`, ""} {
		if _, err := DecodeJobs([]byte(value)); err == nil {
			t.Fatal("accepted", value)
		}
	}
	for _, jobs := range [][]Job{{j, j}, {j, j, j, j, j}} {
		data, _ := json.Marshal(jobs)
		if _, err := DecodeJobs(data); err == nil {
			t.Fatal("duplicate or overlimit jobs")
		}
	}
	// Optional profile fields have the same defaults as the previous worker.
	data = []byte(`[{"job_id":"one","target_id":"target","ip":"8.8.8.8","timeout_seconds":10,"profile":{"port":443,"uuid":"550e8400-e29b-41d4-a716-446655440000","transport":"tcp","security":"tls","server_name":"example.com"}}]`)
	jobs, err := DecodeJobs(data)
	if err != nil {
		t.Fatal(err)
	}
	if jobs[0].Profile.Fingerprint != "chrome" || jobs[0].Profile.Path != "/" || jobs[0].Profile.XHTTPMode != "auto" {
		t.Fatal(jobs[0])
	}
}

func TestSettingsURLAllowlist(t *testing.T) {
	for _, value := range []string{"http://example.com", "https://user:secret@example.com", "https://example.com/#x", "https://example.com:0", "https://example.com:65536", "https://example.com\n", "https://example.com:", "https://[::1]", "https://a..com"} {
		if _, err := ParseURL(value, false, false); err == nil {
			t.Fatal("accepted", value)
		}
	}
	if _, err := ParseURL("https://example.com/path?x=y", false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseURL("https://example.com/path?x=y", false, true); err == nil {
		t.Fatal("backend query")
	}
	s := sampleSettings()
	if s.Validate() != nil {
		t.Fatal("valid defaults")
	}
	s.ControlPlaneURL, s.AllowInsecureHTTP = "http://localhost:8080/base", true
	if s.Validate() != nil {
		t.Fatal("development backend")
	}
	s.ControlURLs = []string{"http://localhost:8080"}
	if s.Validate() == nil {
		t.Fatal("dev switch weakened controls")
	}
	s = sampleSettings()
	s.Token = strings.Repeat("x", 31)
	if s.Validate() == nil {
		t.Fatal("short token")
	}
	s = sampleSettings()
	s.Token += "\n"
	if s.Validate() == nil {
		t.Fatal("header injection")
	}
	s = sampleSettings()
	s.AgentID = "bad:id"
	if s.Validate() == nil {
		t.Fatal("bad ID")
	}
	s = sampleSettings()
	s.XrayBin = "xray"
	if s.Validate() == nil {
		t.Fatal("relative executable")
	}
	s = sampleSettings()
	s.ProbeURLs = nil
	if s.Validate() == nil {
		t.Fatal("empty allowlist")
	}
	s = sampleSettings()
	s.ControlURLs = []string{"https://a.com", "https://a.com", "https://a.com", "https://a.com", "https://a.com"}
	if s.Validate() == nil {
		t.Fatal("unbounded allowlist")
	}
}
