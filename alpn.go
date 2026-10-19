package agent

import "strings"

// ALPN identifiers are kept in preference order. Empty lists use Xray defaults.
// fromMitm needs an inbound TLS session, which an outbound-only probe lacks.
func validALPN(protocols []string, security string) bool {
	if len(protocols) > 16 || len(protocols) > 0 && security != "tls" {
		return false
	}
	for _, protocol := range protocols {
		if len(protocol) < 1 || len(protocol) > 255 || strings.EqualFold(protocol, "fromMitm") {
			return false
		}
		for _, c := range protocol {
			if c < 33 || c > 126 || c == ',' {
				return false
			}
		}
	}
	return true
}
