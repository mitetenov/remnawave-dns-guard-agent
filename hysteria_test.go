package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

func hysteriaJob() Job {
	j := sampleJob()
	j.Profile = Profile{Protocol: "hysteria2", Port: 8443, Transport: "udp", Security: "tls", ServerName: "edge.example.com", Password: "user:p@ss:word", Obfs: "salamander", ObfsPassword: "obfuscation-secret", PinSHA256: strings.Repeat("ab", 32)}
	return j
}

func TestHysteriaWireAndExactOutbound(t *testing.T) {
	for _, proxy := range []string{"", "socks5://login:password@127.0.0.1:1080"} {
		job := hysteriaJob()
		job.ProxyURL = proxy
		job.Profile.Congestion = "bbr"
		raw, _ := json.Marshal([]Job{job})
		jobs, err := DecodeJobs(raw)
		if err != nil {
			t.Fatal(err)
		}
		config, err := XrayConfig(jobs[0], 12345)
		if err != nil {
			t.Fatal(err)
		}
		outbounds := config["outbounds"].([]any)
		target := outbounds[0].(map[string]any)
		settings := target["settings"].(map[string]any)
		if target["protocol"] != "hysteria" || settings["version"] != 2 || settings["address"] != job.IP || settings["port"] != job.Profile.Port || settings["vnext"] != nil {
			t.Fatal("incorrect Hysteria destination", settings)
		}
		stream := target["streamSettings"].(map[string]any)
		tls := stream["tlsSettings"].(map[string]any)
		if stream["network"] != "hysteria" || tls["serverName"] != job.Profile.ServerName || tls["allowInsecure"] != false || tls["pinnedPeerCertSha256"] != job.Profile.PinSHA256 || tls["fingerprint"] != nil || stream["hysteriaSettings"].(map[string]any)["auth"] != job.Profile.Password {
			t.Fatal("incorrect Hysteria TLS/authentication settings")
		}
		finalmask := stream["finalmask"].(map[string]any)
		quic := finalmask["quicParams"].(map[string]any)
		if quic["congestion"] != "bbr" {
			t.Fatal("QUIC congestion setting was lost")
		}
		mask := finalmask["udp"].([]any)[0].(map[string]any)
		if mask["type"] != "salamander" || mask["settings"].(map[string]any)["password"] != job.Profile.ObfsPassword {
			t.Fatal("obfuscation password was lost")
		}
		if proxy == "" && len(outbounds) != 1 || proxy != "" && (len(outbounds) != 2 || stream["sockopt"].(map[string]any)["dialerProxy"] != "upstream-socks") {
			t.Fatal("incorrect route or unexpected direct fallback")
		}
	}
}

func TestHysteriaRejectsInvalidProfiles(t *testing.T) {
	for name, mutate := range map[string]func(*Job){
		"unknown protocol":      func(j *Job) { j.Profile.Protocol = "hy2" },
		"TCP":                   func(j *Job) { j.Profile.Transport = "tcp" },
		"REALITY":               func(j *Job) { j.Profile.Security = "reality" },
		"invalid SNI":           func(j *Job) { j.Profile.ServerName = "example.com/path" },
		"password control":      func(j *Job) { j.Profile.Password = "secret\r\nheader" },
		"oversized password":    func(j *Job) { j.Profile.Password = strings.Repeat("x", 2049) },
		"unknown obfs":          func(j *Job) { j.Profile.Obfs = "unknown" },
		"missing obfs password": func(j *Job) { j.Profile.ObfsPassword = "" },
		"orphan obfs password":  func(j *Job) { j.Profile.Obfs = "" },
		"invalid pin":           func(j *Job) { j.Profile.PinSHA256 = strings.Repeat("z", 64) },
		"invalid congestion":    func(j *Job) { j.Profile.Congestion = "force-brutal" },
		"wrong ALPN":            func(j *Job) { j.Profile.ALPN = []string{"h2"} },
		"VLESS UUID":            func(j *Job) { j.Profile.UUID = sampleJob().Profile.UUID },
		"XHTTP extra":           func(j *Job) { j.Profile.XHTTPExtra = json.RawMessage(`{}`) },
		"private target":        func(j *Job) { j.IP = "127.0.0.1" },
	} {
		t.Run(name, func(t *testing.T) {
			job := hysteriaJob()
			mutate(&job)
			if job.Validate() == nil {
				t.Fatal("invalid profile accepted")
			}
		})
	}
	job := hysteriaJob()
	job.Profile.Password, job.Profile.Obfs, job.Profile.ObfsPassword, job.Profile.PinSHA256 = "", "", "", ""
	if job.Validate() != nil {
		t.Fatal("optional authentication/obfuscation/pin rejected")
	}
	config, _ := XrayConfig(job, 12345)
	if config["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["finalmask"] != nil {
		t.Fatal("obfuscation enabled by default")
	}
}
