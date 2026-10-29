package agent

import (
	"context"
	"encoding/json"
)

type ProxyTest struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

func decodeProxyTest(raw json.RawMessage) (ProxyTest, error) {
	var test ProxyTest
	if strictJSON(raw, &test) != nil || !bounded(test.ID, 100) || test.ID == "" || test.URL == "" {
		return test, ErrBackendProtocol
	}
	if _, err := parseProxyURL(test.URL); err != nil {
		return test, ErrBackendProtocol
	}
	return test, nil
}

func (a *Agent) runProxyTest(ctx context.Context, raw json.RawMessage) error {
	test, err := decodeProxyTest(raw)
	if err != nil {
		return err
	}
	status := a.CheckProxy(ctx, test.URL)
	response, err := a.api(ctx, "/api/agent/proxy-test-results", map[string]any{"agent_id": a.Settings.AgentID, "test_id": test.ID, "ok": status.OK, "latency_ms": status.LatencyMS, "exit_ip": status.ExitIP})
	if err != nil {
		return err
	}
	var accepted bool
	if json.Unmarshal(response["accepted"], &accepted) != nil {
		return ErrBackendProtocol
	}
	// A changed/expired request can be rejected without affecting live probes.
	return nil
}
