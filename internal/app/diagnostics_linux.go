package app

import (
	"os"
	"strings"
)

func forwardingChecks() []Check {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	check := Check{Name: "IPv4 forwarding", OK: err == nil && strings.TrimSpace(string(data)) == "1", Detail: "Linux net.ipv4.ip_forward must be enabled"}
	if err != nil {
		check.Detail = err.Error()
	}
	return []Check{check}
}
