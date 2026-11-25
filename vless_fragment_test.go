package agent

import (
	"encoding/json"
	"maps"
	"testing"
)

func TestVLESSFragmentJobConfig(t *testing.T) {
	job := sampleJob()
	job.Profile.Fingerprint = "firefox"
	want := map[string]string{"packets": "tlshello", "length": "10-20", "delay": "0"}
	job.Profile.VLESSFragment = want
	data, err := json.Marshal([]Job{job})
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := DecodeJobs(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, proxy := range []string{"", "socks5://8.8.4.4:1080"} {
		job = jobs[0]
		job.ProxyURL = proxy
		config, err := XrayConfig(job, 12345)
		if err != nil {
			t.Fatal(err)
		}
		target := config["outbounds"].([]any)[0].(map[string]any)
		stream := target["streamSettings"].(map[string]any)
		mask := stream["finalmask"].(map[string]any)["tcp"].([]any)[0].(map[string]any)
		if mask["type"] != "fragment" || !maps.Equal(mask["settings"].(map[string]string), want) {
			t.Fatalf("unexpected TCP mask: %v", mask)
		}
		_, usesProxy := stream["sockopt"]
		if usesProxy != (proxy != "") {
			t.Fatalf("unexpected SOCKS5 route: %v", stream)
		}
		destination := target["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
		if destination["address"] != job.IP || destination["port"] != job.Profile.Port {
			t.Fatalf("fragmentation changed destination: %v", destination)
		}
	}

	job.Profile.Transport, job.Profile.Flow = "xhttp", ""
	if _, err := XrayConfig(job, 12345); err != ErrInvalidJob {
		t.Fatalf("XHTTP accepted VLESS fragment: %v", err)
	}
	job = jobs[0]
	job.Profile.VLESSFragment = map[string]string{"packets": "tlshello", "length": "0", "delay": "0"}
	if _, err := XrayConfig(job, 12345); err != ErrInvalidJob {
		t.Fatalf("zero-length fragment accepted: %v", err)
	}
	job.Profile.VLESSFragment = nil
	config, err := XrayConfig(job, 12345)
	if err != nil {
		t.Fatal(err)
	}
	stream := config["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	if _, exists := stream["finalmask"]; exists {
		t.Fatal("unconfigured fragmentation changed the legacy config")
	}
}
