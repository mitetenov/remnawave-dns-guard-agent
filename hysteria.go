package agent

import "strconv"

func validHysteriaProfile(p Profile) bool {
	return p.Transport == "udp" && p.Security == "tls" && hostname(p.ServerName, false) &&
		bounded(p.Password, 2048) && bounded(p.ObfsPassword, 2048) &&
		oneOf(p.Obfs, "", "salamander") && (p.Obfs == "salamander") == (p.ObfsPassword != "") &&
		(p.PinSHA256 == "" || len(p.PinSHA256) == 64 && hexPattern.MatchString(p.PinSHA256)) &&
		oneOf(p.Congestion, "", "bbr", "reno", "brutal") &&
		(len(p.ALPN) == 0 || len(p.ALPN) == 1 && p.ALPN[0] == "h3") &&
		p.UUID == "" && p.PublicKey == "" && p.ShortID == "" && p.Flow == "" && p.Host == "" &&
		oneOf(p.Fingerprint, "", "chrome") && oneOf(p.Path, "", "/") && oneOf(p.XHTTPMode, "", "auto")
}

func hysteriaConfig(job Job, port int) map[string]any {
	p := job.Profile
	tls := map[string]any{"serverName": p.ServerName, "allowInsecure": false, "alpn": []string{"h3"}}
	if p.PinSHA256 != "" {
		tls["pinnedPeerCertSha256"] = p.PinSHA256
	}
	stream := map[string]any{"network": "hysteria", "security": "tls", "tlsSettings": tls,
		"hysteriaSettings": map[string]any{"version": 2, "auth": p.Password}}
	if p.Obfs == "salamander" || p.Congestion != "" {
		finalmask := map[string]any{}
		if p.Obfs == "salamander" {
			finalmask["udp"] = []any{map[string]any{"type": "salamander", "settings": map[string]any{"password": p.ObfsPassword}}}
		}
		if p.Congestion != "" {
			finalmask["quicParams"] = map[string]any{"congestion": p.Congestion}
		}
		stream["finalmask"] = finalmask
	}
	outbounds := []any{map[string]any{"tag": "target", "protocol": "hysteria",
		"settings": map[string]any{"version": 2, "address": job.IP, "port": p.Port}, "streamSettings": stream}}
	if job.ProxyURL != "" {
		u, _ := parseProxyURL(job.ProxyURL)
		proxyPort, _ := strconv.Atoi(u.Port())
		settings := map[string]any{"address": u.Hostname(), "port": proxyPort}
		if u.User != nil {
			pass, _ := u.User.Password()
			settings["user"], settings["pass"] = u.User.Username(), pass
		}
		stream["sockopt"] = map[string]any{"dialerProxy": "upstream-socks"}
		outbounds = append(outbounds, map[string]any{"tag": "upstream-socks", "protocol": "socks", "settings": settings})
	}
	return map[string]any{"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{map[string]any{"tag": "probe-http", "listen": "127.0.0.1", "port": port, "protocol": "http", "settings": map[string]any{"allowTransparent": false}}}, "outbounds": outbounds}
}
