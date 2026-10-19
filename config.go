// Package agent implements the outbound-only DNS Guard RU worker protocol.
package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const Version = "1.2.0"
const MaxJobs = 4
const HeartbeatPath = "/tmp/dns-guard-agent-heartbeat"

var ErrInvalidJob = errors.New("invalid_job")
var ErrInvalidSettings = errors.New("invalid_settings")
var ErrBackendProtocol = errors.New("backend_protocol_error")
var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$`)
var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
var agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$`)
var hexPattern = regexp.MustCompile(`^[a-fA-F0-9]*$`)
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type Profile struct {
	Port        int             `json:"port"`
	UUID        string          `json:"uuid"`
	Transport   string          `json:"transport"`
	Security    string          `json:"security"`
	ServerName  string          `json:"server_name"`
	PublicKey   string          `json:"public_key"`
	ShortID     string          `json:"short_id"`
	Flow        string          `json:"flow"`
	Fingerprint string          `json:"fingerprint"`
	Path        string          `json:"path"`
	Host        string          `json:"host"`
	XHTTPMode   string          `json:"xhttp_mode"`
	XHTTPExtra  json.RawMessage `json:"xhttp_extra,omitempty"`
	ALPN        []string        `json:"alpn,omitempty"`
}

func (p *Profile) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return ErrInvalidJob
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrInvalidJob
		}
	}
	type plain Profile
	v := plain{Fingerprint: "chrome", Path: "/", XHTTPMode: "auto"}
	if err := strictJSON(data, &v); err != nil {
		return ErrInvalidJob
	}
	*p = Profile(v)
	return nil
}

type Job struct {
	JobID          string  `json:"job_id"`
	TargetID       string  `json:"target_id"`
	IP             string  `json:"ip"`
	Profile        Profile `json:"profile"`
	TimeoutSeconds int     `json:"timeout_seconds"`
}

func strictJSON(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func hostname(value string, empty bool) bool {
	if value == "" {
		return empty
	}
	if len(value) > 253 || !hostnamePattern.MatchString(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

func bounded(value string, limit int) bool {
	if utf8.RuneCountInString(value) > limit {
		return false
	}
	for _, c := range value {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

// These special-use networks are never valid probe targets or direct control
// destinations. Every DNS answer is checked before any connection is attempted.
var nonPublic = func() []netip.Prefix {
	values := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/96", "64:ff9b:1::/48", "100::/64", "2001:db8::/32", "2001::/23", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10", "ff00::/8"}
	result := make([]netip.Prefix, len(values))
	for i, value := range values {
		result[i] = netip.MustParsePrefix(value)
	}
	return result
}()

func PublicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() {
		return false
	}
	// The globally reachable anycast exceptions in the otherwise reserved /24.
	if ip.String() == "192.0.0.9" || ip.String() == "192.0.0.10" {
		return true
	}
	for _, prefix := range nonPublic {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func (j *Job) Validate() error {
	p := &j.Profile
	if !validALPN(p.ALPN, p.Security) {
		return ErrInvalidJob
	}
	if !validXHTTPExtra(p.XHTTPExtra, p.Transport, p.XHTTPMode) {
		return ErrInvalidJob
	}
	ip, err := netip.ParseAddr(j.IP)
	if err != nil || !ip.Is4() || !PublicAddress(ip) || !identifierPattern.MatchString(j.JobID) || !identifierPattern.MatchString(j.TargetID) || j.TimeoutSeconds < 1 || j.TimeoutSeconds > 30 {
		return ErrInvalidJob
	}
	if p.Port < 1 || p.Port > 65535 || !uuidPattern.MatchString(p.UUID) || !oneOf(p.Transport, "tcp", "xhttp") || !oneOf(p.Security, "tls", "reality") {
		return ErrInvalidJob
	}
	uuid := strings.ToLower(strings.ReplaceAll(p.UUID, "-", ""))
	p.UUID = uuid[:8] + "-" + uuid[8:12] + "-" + uuid[12:16] + "-" + uuid[16:20] + "-" + uuid[20:]
	if !hostname(p.ServerName, false) || !hostname(p.Host, true) || !oneOf(p.Fingerprint, "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized") || !oneOf(p.XHTTPMode, "auto", "packet-up", "stream-up", "stream-one") {
		return ErrInvalidJob
	}
	if !oneOf(p.Flow, "", "xtls-rprx-vision") || (p.Transport == "xhttp" && p.Flow != "") || !bounded(p.Path, 2048) || !strings.HasPrefix(p.Path, "/") || strings.HasPrefix(p.Path, "//") || len(p.ShortID) > 16 || len(p.ShortID)%2 != 0 || !hexPattern.MatchString(p.ShortID) || !bounded(p.PublicKey, 43) {
		return ErrInvalidJob
	}
	if p.Security == "reality" {
		decoded, err := base64.RawURLEncoding.DecodeString(p.PublicKey)
		if err != nil || len(decoded) != 32 || !keyPattern.MatchString(p.PublicKey) {
			return ErrInvalidJob
		}
	}
	return nil
}

func DecodeJobs(raw json.RawMessage) ([]Job, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, ErrBackendProtocol
	}
	var jobs []Job
	if err := strictJSON(raw, &jobs); err != nil || len(jobs) > MaxJobs {
		return nil, ErrBackendProtocol
	}
	ids, targets := map[string]bool{}, map[string]bool{}
	for i := range jobs {
		if err := jobs[i].Validate(); err != nil {
			return nil, err
		}
		if ids[jobs[i].JobID] || targets[jobs[i].TargetID] {
			return nil, ErrBackendProtocol
		}
		ids[jobs[i].JobID], targets[jobs[i].TargetID] = true, true
	}
	return jobs, nil
}

type Settings struct {
	ControlPlaneURL   string
	Token             string
	AgentID           string
	XrayBin           string
	ControlURLs       []string
	ProbeURLs         []string
	AllowInsecureHTTP bool
}

func DefaultSettings() Settings {
	return Settings{AgentID: "ru-1", XrayBin: "/usr/local/bin/xray", ControlURLs: []string{"https://ya.ru", "https://www.cloudflare.com/cdn-cgi/trace"}, ProbeURLs: []string{"https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"}}
}

func ParseURL(value string, allowHTTP, base bool) (*url.URL, error) {
	if !bounded(value, 2048) {
		return nil, ErrInvalidSettings
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "https" && !(allowHTTP && u.Scheme == "http")) || u.User != nil || u.Fragment != "" || !hostname(u.Hostname(), false) || u.Opaque != "" || (base && u.RawQuery != "") {
		return nil, ErrInvalidSettings
	}
	if u.Port() != "" {
		var port int
		if _, err := fmt.Sscanf(u.Port(), "%d", &port); err != nil || port < 1 || port > 65535 {
			return nil, ErrInvalidSettings
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, ErrInvalidSettings
	}
	return u, nil
}

func (s Settings) Validate() error {
	if _, err := ParseURL(s.ControlPlaneURL, s.AllowInsecureHTTP, true); err != nil {
		return err
	}
	if utf8.RuneCountInString(s.Token) < 32 || !bounded(s.Token, 8192) || strings.IndexFunc(s.Token, unicode.IsSpace) >= 0 || !agentIDPattern.MatchString(s.AgentID) || !filepath.IsAbs(s.XrayBin) {
		return ErrInvalidSettings
	}
	for _, urls := range [][]string{s.ControlURLs, s.ProbeURLs} {
		if len(urls) < 1 || len(urls) > 4 {
			return ErrInvalidSettings
		}
		for _, value := range urls {
			if _, err := ParseURL(value, false, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func SettingsFromEnv() (Settings, error) {
	s := DefaultSettings()
	s.ControlPlaneURL, s.Token = os.Getenv("CONTROL_PLANE_URL"), os.Getenv("AGENT_TOKEN")
	for name, target := range map[string]*string{"AGENT_ID": &s.AgentID, "XRAY_BIN": &s.XrayBin} {
		if value, ok := os.LookupEnv(name); ok {
			*target = value
		}
	}
	for name, target := range map[string]*[]string{"CONTROL_URLS": &s.ControlURLs, "PROBE_URLS": &s.ProbeURLs} {
		if value, ok := os.LookupEnv(name); ok {
			*target = strings.Split(value, ",")
			for i := range *target {
				(*target)[i] = strings.TrimSpace((*target)[i])
			}
		}
	}
	s.AllowInsecureHTTP = strings.EqualFold(os.Getenv("ALLOW_INSECURE_HTTP"), "true")
	return s, s.Validate()
}

func XrayConfig(job Job, port int) (map[string]any, error) {
	if err := job.Validate(); err != nil || port < 1024 || port > 65535 {
		return nil, ErrInvalidJob
	}
	p := job.Profile
	network := "raw"
	if p.Transport == "xhttp" {
		network = "xhttp"
	}
	stream := map[string]any{"network": network, "security": p.Security}
	if p.Security == "reality" {
		stream["realitySettings"] = map[string]any{"show": false, "serverName": p.ServerName, "fingerprint": p.Fingerprint, "password": p.PublicKey, "shortId": p.ShortID}
	} else {
		settings := map[string]any{"serverName": p.ServerName, "allowInsecure": false, "fingerprint": p.Fingerprint}
		if len(p.ALPN) > 0 {
			settings["alpn"] = p.ALPN
		}
		stream["tlsSettings"] = settings
	}
	if p.Transport == "xhttp" {
		settings := map[string]any{"path": p.Path, "host": p.Host, "mode": p.XHTTPMode}
		if len(p.XHTTPExtra) != 0 {
			settings["extra"] = p.XHTTPExtra
		}
		stream["xhttpSettings"] = settings
	}
	user := map[string]any{"id": p.UUID, "encryption": "none"}
	if p.Flow != "" {
		user["flow"] = p.Flow
	}
	return map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"tag": "probe-http", "listen": "127.0.0.1", "port": port, "protocol": "http", "settings": map[string]any{"allowTransparent": false}}}, "outbounds": []any{map[string]any{"tag": "target", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": job.IP, "port": p.Port, "users": []any{user}}}}, "streamSettings": stream}}}, nil
}
