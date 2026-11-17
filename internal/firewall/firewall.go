package firewall

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
)

// Protocol represents the L4 protocol supported by redirect rules.
type Protocol string

const (
	// ProtocolTCP matches TCP traffic.
	ProtocolTCP Protocol = "tcp"
	// ProtocolUDP matches UDP traffic.
	ProtocolUDP Protocol = "udp"
	// ProtocolBoth creates separate TCP and UDP redirect rules.
	ProtocolBoth Protocol = "both"
)

// Label returns the protocol name used in the interfaces.
func (p Protocol) Label() string {
	if p == ProtocolBoth {
		return "Both (TCP + UDP)"
	}
	return strings.ToUpper(string(p))
}

// SupportedProtocols returns the protocol choices supported by this host.
func SupportedProtocols() []Protocol {
	if runtime.GOOS == "windows" {
		return []Protocol{ProtocolTCP}
	}
	return []Protocol{ProtocolTCP, ProtocolUDP, ProtocolBoth}
}

// ValidateProtocol rejects unsupported choices before any firewall operations.
func ValidateProtocol(protocol Protocol) error {
	if runtime.GOOS == "windows" && protocol != ProtocolTCP {
		return errors.New("Windows portproxy only supports TCP; UDP and TCP + UDP are not supported")
	}
	switch protocol {
	case ProtocolTCP, ProtocolUDP, ProtocolBoth:
		return nil
	default:
		return fmt.Errorf("unsupported protocol %q", protocol)
	}
}

func expandRule(rule RedirectRule) []RedirectRule {
	if rule.Protocol != ProtocolBoth {
		return []RedirectRule{rule}
	}
	tcp, udp := rule, rule
	tcp.Protocol = ProtocolTCP
	udp.Protocol = ProtocolUDP
	return []RedirectRule{tcp, udp}
}

// RedirectRule describes a single redirect from a public IP/port to a tailnet peer.
type RedirectRule struct {
	Handle         uint64
	Description    string
	Protocol       Protocol
	MatchIP        net.IP
	MatchInterface string
	MatchPort      uint16
	TargetIP       net.IP
	TargetPort     uint16
	TailscalePeer  string
}

// Manager encapsulates platform-specific firewall control plane functionality.
type Manager interface {
	ListRedirectRules() ([]RedirectRule, error)
	// RuleExists reports whether any requested protocol already has a matching rule.
	RuleExists(RedirectRule) (bool, error)
	AddRedirectRule(RedirectRule) error
	DeleteRedirectRule(handle uint64) error
	Close() error
}

// ErrDuplicateRule indicates a rule already exists with the same parameters.
var ErrDuplicateRule = errors.New("redirect rule already exists")

// NewManager returns the platform-specific firewall manager implementation.
func NewManager() (Manager, error) {
	return newManager()
}

func ruleKey(rule RedirectRule) string {
	ip := ipToString(rule.MatchIP)
	target := ipToString(rule.TargetIP)
	return strings.Join([]string{
		strings.ToLower(string(rule.Protocol)),
		strings.ToLower(rule.MatchInterface),
		ip,
		fmt.Sprintf("%d", rule.MatchPort),
		target,
		fmt.Sprintf("%d", rule.TargetPort),
		strings.ToLower(rule.TailscalePeer),
	}, "|")
}

func ipToString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
