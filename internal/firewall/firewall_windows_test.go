//go:build windows

package firewall

import (
	"net"
	"strings"
	"testing"
)

func TestWindowsRejectsNonTCPBeforeNetsh(t *testing.T) {
	m := &netshManager{}
	for _, protocol := range []Protocol{ProtocolUDP, ProtocolBoth, "icmp", ""} {
		t.Run(string(protocol), func(t *testing.T) {
			rule := RedirectRule{Protocol: protocol, MatchIP: net.ParseIP("192.0.2.10"), MatchPort: 8080, TargetIP: net.ParseIP("100.64.0.2"), TargetPort: 80}
			if err := m.AddRedirectRule(rule); err == nil || !strings.Contains(err.Error(), "only supports TCP") {
				t.Fatalf("AddRedirectRule: %v", err)
			}
			if _, err := m.RuleExists(rule); err == nil || !strings.Contains(err.Error(), "only supports TCP") {
				t.Fatalf("RuleExists: %v", err)
			}
		})
	}
	if got := SupportedProtocols(); len(got) != 1 || got[0] != ProtocolTCP {
		t.Fatalf("Windows protocol choices: %v", got)
	}
}

func TestWindowsStillAcceptsTCP(t *testing.T) {
	rule := RedirectRule{Protocol: ProtocolTCP, MatchIP: net.ParseIP("192.0.2.10"), MatchPort: 8080, TargetIP: net.ParseIP("100.64.0.2"), TargetPort: 80}
	if err := validateRule(rule); err != nil {
		t.Fatal(err)
	}
	if _, err := (&netshManager{}).normalizeRule(rule); err != nil {
		t.Fatal(err)
	}
}
