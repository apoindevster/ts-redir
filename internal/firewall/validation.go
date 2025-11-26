package firewall

import (
	"errors"
	"fmt"
	"net"
	"runtime"
)

func validateRule(rule RedirectRule) error {
	if rule.MatchIP == nil {
		if rule.MatchInterface == "" {
			return errors.New("match IP must be provided when no ingress interface is specified")
		}
	} else {
		if err := ensureIPv4(rule.MatchIP, "match IP"); err != nil {
			return err
		}
	}
	if err := ensureIPv4(rule.TargetIP, "target IP"); err != nil {
		return err
	}
	if rule.MatchPort == 0 {
		return errors.New("match port must be non-zero")
	}
	if rule.TargetPort == 0 {
		return errors.New("target port must be non-zero")
	}
	if rule.Protocol != ProtocolTCP && rule.Protocol != ProtocolUDP {
		return fmt.Errorf("unsupported protocol %q", rule.Protocol)
	}
	if runtime.GOOS != "windows" && len(rule.MatchInterface) > 15 {
		return errors.New("match interface must be 15 characters or fewer")
	}
	return nil
}

func ensureIPv4(ip net.IP, label string) error {
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("%s must be a valid IPv4 address", label)
	}
	return nil
}
