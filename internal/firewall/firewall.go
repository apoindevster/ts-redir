package firewall

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// Protocol represents the L4 protocol supported by redirect rules.
type Protocol string

const (
	// ProtocolTCP matches TCP traffic.
	ProtocolTCP Protocol = "tcp"
	// ProtocolUDP matches UDP traffic.
	ProtocolUDP Protocol = "udp"
)

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
