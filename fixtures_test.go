package agent

import "encoding/json"

// Synthetic profiles are fixtures for pure config and schema tests only.
func syntheticJobs() []Job {
	var jobs []Job
	for _, transport := range []string{"tcp", "xhttp"} {
		for _, security := range []string{"tls", "reality"} {
			modes := []string{"auto"}
			if transport == "xhttp" {
				modes = []string{"auto", "packet-up", "stream-up", "stream-one"}
			}
			for _, mode := range modes {
				flow := ""
				if transport == "tcp" {
					flow = "xtls-rprx-vision"
				}
				var extra json.RawMessage
				var alpn []string
				if security == "tls" {
					alpn = []string{"h2", "http/1.1"}
				}
				if transport == "xhttp" {
					extra = json.RawMessage(`{"xPaddingBytes":"100-1000","xPaddingObfsMode":true,"xPaddingMethod":"tokenish","xPaddingPlacement":"queryInHeader","noGRPCHeader":true,"scMaxEachPostBytes":1000000,"scMinPostsIntervalMs":"10-30","scMaxBufferedPosts":30,"scStreamUpServerSecs":"20-80","headers":{"User-Agent":"DNSGuard/ConfigFixture"},"xmux":{"maxConcurrency":"16-32","cMaxReuseTimes":0,"hMaxRequestTimes":"600-900","hMaxReusableSecs":"1800-3000","hKeepAlivePeriod":30}}`)
				}
				jobs = append(jobs, Job{JobID: "synthetic", TargetID: "synthetic", IP: "8.8.8.8", TimeoutSeconds: 15, Profile: Profile{Port: 443, UUID: "550e8400-e29b-41d4-a716-446655440000", Transport: transport, Security: security, ServerName: "example.com", PublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA", ShortID: "aabb", Flow: flow, Fingerprint: "chrome", Path: "/", XHTTPMode: mode, XHTTPExtra: extra, ALPN: alpn}})
				if transport == "xhttp" && security == "tls" && mode == "packet-up" {
					p := &jobs[len(jobs)-1].Profile
					p.Fingerprint, p.ServerName, p.Host, p.Path, p.ShortID = "firefox", "edge.example.com", "edge.example.com", "/probe/", ""
					p.XHTTPExtra = json.RawMessage(`{"xPaddingKey":"_dc","uplinkDataKey":"data","xPaddingHeader":"X-Cache","xPaddingMethod":"tokenish","uplinkHTTPMethod":"GET","xPaddingObfsMode":true,"xPaddingPlacement":"queryInHeader","scMaxEachPostBytes":32768,"uplinkDataPlacement":"header","scMinPostsIntervalMs":10,"serverMaxHeaderBytes":3932160}`)
				}
			}
		}
	}
	return jobs
}
