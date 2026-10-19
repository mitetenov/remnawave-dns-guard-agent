// XHTTP extra follows Xray v26.3.27 SplitHTTPConfig. Keep this validator
// identical in the backend and agent: extra is transported as JSON, never merged
// into the surrounding outbound or stream settings.
package agent

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

const maxXHTTPExtraBytes = 16 * 1024

var extraRangePattern = regexp.MustCompile(`^(-?[0-9]+)(?:-(-?[0-9]+))?$`)
var extraHeaderPattern = regexp.MustCompile("^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+$")

func extraObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	err := json.Unmarshal(raw, &object)
	return object, err == nil && object != nil
}

func extraNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

func extraInteger(raw json.RawMessage, bits int) (int64, bool) {
	n, err := strconv.ParseInt(string(raw), 10, bits)
	// JSON numbers must also round-trip losslessly through the browser.
	return n, err == nil && n >= -9007199254740991 && n <= 9007199254740991
}

func extraRange(raw json.RawMessage) (int64, int64, bool) {
	if extraNull(raw) {
		return 0, 0, true
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		n, ok := extraInteger(raw, 32)
		return n, n, ok
	}
	if s == "" {
		return 0, 0, true
	}
	match := extraRangePattern.FindStringSubmatch(s)
	if match == nil {
		return 0, 0, false
	}
	lo, err := strconv.ParseInt(match[1], 10, 32)
	if err != nil {
		return 0, 0, false
	}
	hi := lo
	if match[2] != "" {
		hi, err = strconv.ParseInt(match[2], 10, 32)
		if err != nil {
			return 0, 0, false
		}
	}
	if lo > hi {
		lo, hi = hi, lo
	}
	return lo, hi, true
}

func extraText(raw json.RawMessage) (string, bool) {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return "", false
		}
	}
	return s, true
}

func validXHTTPExtra(raw json.RawMessage, transport, mode string) bool {
	if len(raw) == 0 {
		return true
	}
	if transport != "xhttp" || len(raw) > maxXHTTPExtraBytes {
		return false
	}
	fields, ok := extraObject(raw)
	if !ok {
		return false
	}
	// The API/storage encoder escapes HTML. Bound that representation too so a
	// profile accepted on save cannot grow beyond the agent's wire limit.
	wire, err := json.Marshal(fields)
	if err != nil || len(wire) > maxXHTTPExtraBytes {
		return false
	}
	for key, value := range fields {
		// A second stream can dial a different destination and bypass the pool IP.
		if key == "downloadSettings" {
			if !extraNull(value) {
				return false
			}
			continue
		}
		switch key {
		case "host", "path", "mode", "xPaddingKey", "xPaddingHeader", "xPaddingPlacement",
			"xPaddingMethod", "uplinkHTTPMethod", "sessionPlacement", "sessionKey",
			"seqPlacement", "seqKey", "uplinkDataPlacement", "uplinkDataKey":
			text, ok := extraText(value)
			if !ok {
				return false
			}
			switch key {
			case "xPaddingPlacement":
				if !oneOf(text, "", "cookie", "header", "query", "queryInHeader") {
					return false
				}
			case "xPaddingMethod":
				if !oneOf(text, "", "repeat-x", "tokenish") {
					return false
				}
			case "sessionPlacement", "seqPlacement":
				if !oneOf(text, "", "path", "cookie", "header", "query") {
					return false
				}
			case "uplinkDataPlacement":
				if !oneOf(text, "", "auto", "body", "header", "cookie") ||
					oneOf(text, "header", "cookie") && mode != "packet-up" {
					return false
				}
			case "uplinkHTTPMethod":
				if strings.EqualFold(text, "GET") && mode != "packet-up" {
					return false
				}
			}
		case "xPaddingBytes", "uplinkChunkSize", "scMaxEachPostBytes", "scMinPostsIntervalMs", "scStreamUpServerSecs":
			lo, hi, ok := extraRange(value)
			if !ok || key == "xPaddingBytes" && (lo != 0 || hi != 0) && (lo <= 0 || hi <= 0) {
				return false
			}
		case "scMaxBufferedPosts", "serverMaxHeaderBytes":
			if extraNull(value) {
				continue
			}
			bits := 64
			if key == "serverMaxHeaderBytes" {
				bits = 32
			}
			n, ok := extraInteger(value, bits)
			if !ok || key == "serverMaxHeaderBytes" && n < 0 {
				return false
			}
		case "xPaddingObfsMode", "noGRPCHeader", "noSSEHeader":
			var flag bool
			if json.Unmarshal(value, &flag) != nil {
				return false
			}
		case "headers":
			if extraNull(value) {
				continue
			}
			headers, ok := extraObject(value)
			if !ok {
				return false
			}
			for name, value := range headers {
				if !extraHeaderPattern.MatchString(name) || strings.EqualFold(name, "host") {
					return false
				}
				if _, ok := extraText(value); !ok {
					return false
				}
			}
		case "xmux":
			if extraNull(value) {
				continue
			}
			xmux, ok := extraObject(value)
			if !ok {
				return false
			}
			var concurrency, connections int64
			for key, value := range xmux {
				if key == "hKeepAlivePeriod" {
					if !extraNull(value) {
						if _, ok := extraInteger(value, 64); !ok {
							return false
						}
					}
				} else {
					if !oneOf(key, "maxConcurrency", "maxConnections", "cMaxReuseTimes", "hMaxRequestTimes", "hMaxReusableSecs") {
						return false
					}
					_, hi, ok := extraRange(value)
					if !ok {
						return false
					}
					if key == "maxConcurrency" {
						concurrency = hi
					}
					if key == "maxConnections" {
						connections = hi
					}
				}
			}
			if concurrency > 0 && connections > 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
