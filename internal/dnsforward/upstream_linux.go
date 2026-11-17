package dnsforward

import (
	"context"
	"os/exec"
	"strings"

	"github.com/miekg/dns"
)

func Discover(ctx context.Context, listenIP string) ([]string, error) {
	// Prefer link-specific DHCP DNS. Global resolv.conf can be replaced by
	// Tailscale or systemd's stub resolver and hide the physical network DNS.
	if iface, err := interfaceForIP(listenIP); err == nil {
		if b, err := exec.CommandContext(ctx, "resolvectl", "dns", iface.Name).Output(); err == nil {
			if _, values, ok := strings.Cut(string(b), ":"); ok {
				if out, err := filterUpstreams(withInterfaceZone(strings.Fields(values), iface), listenIP); err == nil {
					return out, nil
				}
			}
		}
		if b, err := exec.CommandContext(ctx, "nmcli", "--escape", "no", "-g", "IP4.DNS,IP6.DNS", "device", "show", iface.Name).Output(); err == nil {
			if out, err := filterUpstreams(withInterfaceZone(strings.Fields(string(b)), iface), listenIP); err == nil {
				return out, nil
			}
		}
	}
	for _, path := range []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"} {
		if c, err := dns.ClientConfigFromFile(path); err == nil {
			if out, err := filterUpstreams(c.Servers, listenIP); err == nil {
				return out, nil
			}
		}
	}
	return filterUpstreams(nil, listenIP)
}
