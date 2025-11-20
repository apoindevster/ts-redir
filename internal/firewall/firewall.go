package firewall

import "net"

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
	Handle        uint64
	Description   string
	Protocol      Protocol
	MatchIP       net.IP
	MatchPort     uint16
	TargetIP      net.IP
	TargetPort    uint16
	TailscalePeer string
}

// Manager encapsulates platform-specific firewall control plane functionality.
type Manager interface {
	ListRedirectRules() ([]RedirectRule, error)
	AddRedirectRule(RedirectRule) error
	DeleteRedirectRule(handle uint64) error
	Close() error
}

// NewManager returns the platform-specific firewall manager implementation.
func NewManager() (Manager, error) {
	return newManager()
}
