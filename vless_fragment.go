package agent

import (
	"strconv"
	"strings"
)

// Keep the VLESS fragmentation settings valid on both the backend and agent.
func validVLESSFragment(settings map[string]string, protocol, transport string) bool {
	return settings == nil ||
		(oneOf(protocol, "", "vless") && transport == "tcp" &&
			len(settings) == 3 && settings["packets"] == "tlshello" &&
			validFragmentRange(settings["length"], 1) && validFragmentRange(settings["delay"], 0))
}

func validFragmentRange(value string, minimum uint64) bool {
	left, right, hasRange := strings.Cut(value, "-")
	low, err := strconv.ParseUint(left, 10, 31)
	if err != nil || len(left) > 10 || low < minimum {
		return false
	}
	if !hasRange {
		return true
	}
	high, err := strconv.ParseUint(right, 10, 31)
	return err == nil && len(right) <= 10 && low <= high
}
