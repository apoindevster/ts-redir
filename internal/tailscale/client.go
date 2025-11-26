package tailscale

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
)

// Peer represents a single Tailscale node.
type Peer struct {
	ID         string
	Name       string
	HostName   string
	IPs        []net.IP
	Online     bool
	DNSName    string
	OS         string
	IsExitNode bool
	Self       bool
}

type statusResponse struct {
	DNSSuffix string                `json:"MagicDNSSuffix"`
	Self      selfStatus            `json:"Self"`
	Peer      map[string]peerStatus `json:"Peer"`
}

type selfStatus struct {
	ID           string   `json:"ID"`
	HostName     string   `json:"HostName"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Online       bool     `json:"Online"`
	DNSName      string   `json:"DNSName"`
	OS           string   `json:"OS"`
	IsExitNode   bool     `json:"ExitNodeOption"`
}

type peerStatus struct {
	ID           string   `json:"ID"`
	HostName     string   `json:"HostName"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Online       bool     `json:"Online"`
	DNSName      string   `json:"DNSName"`
	OS           string   `json:"OS"`
	IsExitNode   bool     `json:"ExitNodeOption"`
}

var dnsSuffix string

// ListPeers returns the current set of peers reported by the local Tailscale daemon.
func ListPeers(ctx context.Context) ([]Peer, error) {
	output, err := fetchStatus(ctx)
	if err != nil {
		return nil, err
	}

	var status statusResponse
	if err := json.Unmarshal(output, &status); err != nil {
		return nil, fmt.Errorf("parse tailscale status: %w", err)
	}

	dnsSuffix = status.DNSSuffix

	var peers []Peer
	if status.Self.ID != "" {
		peers = append(peers, peerFromSelf(status.Self))
	}
	for id, p := range status.Peer {
		peer := peerFromStatus(id, p)
		peers = append(peers, peer)
	}

	sort.Slice(peers, func(i, j int) bool {
		if peers[i].Self != peers[j].Self {
			return peers[i].Self
		}
		return strings.ToLower(peers[i].Name) < strings.ToLower(peers[j].Name)
	})

	return peers, nil
}

// RawStatus returns the full JSON payload from `tailscale status --json` so callers can
// expose more peer/self details without needing to mirror all fields here.
func RawStatus(ctx context.Context) (json.RawMessage, error) {
	output, err := fetchStatus(ctx)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := json.Unmarshal(output, &raw); err != nil {
		return nil, fmt.Errorf("parse tailscale status: %w", err)
	}
	return raw, nil
}

func fetchStatus(ctx context.Context) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "tailscale", "status", "--json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("tailscale status: %w", err)
	}
	return output, nil
}

func peerFromSelf(s selfStatus) Peer {
	name := strings.TrimSuffix(s.DNSName, ".")
	name = strings.TrimSuffix(name, dnsSuffix)
	name = strings.TrimSuffix(name, ".")
	return Peer{
		ID:         s.ID,
		Name:       name,
		HostName:   s.HostName,
		IPs:        parseIPs(s.TailscaleIPs),
		Online:     s.Online,
		DNSName:    s.DNSName,
		OS:         s.OS,
		IsExitNode: s.IsExitNode,
		Self:       true,
	}
}

func peerFromStatus(id string, s peerStatus) Peer {
	hostname := s.HostName
	if hostname == "" {
		hostname = id
	}

	name := strings.TrimSuffix(s.DNSName, ".")
	name = strings.TrimSuffix(name, dnsSuffix)
	name = strings.TrimSuffix(name, ".")

	return Peer{
		ID:         firstNonEmpty(s.ID, id),
		Name:       name,
		HostName:   hostname,
		IPs:        parseIPs(s.TailscaleIPs),
		Online:     s.Online,
		DNSName:    s.DNSName,
		OS:         s.OS,
		IsExitNode: s.IsExitNode,
	}
}

func parseIPs(values []string) []net.IP {
	ips := make([]net.IP, 0, len(values))
	for _, v := range values {
		if ip := net.ParseIP(v); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
