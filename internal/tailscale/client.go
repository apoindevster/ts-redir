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
	ID     string
	Name   string
	IPs    []net.IP
	Online bool
	Self   bool
}

type statusResponse struct {
	Self selfStatus            `json:"Self"`
	Peer map[string]peerStatus `json:"Peer"`
}

type selfStatus struct {
	ID           string   `json:"ID"`
	HostName     string   `json:"HostName"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Online       bool     `json:"Online"`
}

type peerStatus struct {
	ID           string   `json:"ID"`
	HostName     string   `json:"HostName"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Online       bool     `json:"Online"`
}

// ListPeers returns the current set of peers reported by the local Tailscale daemon.
func ListPeers(ctx context.Context) ([]Peer, error) {
	cmd := exec.CommandContext(ctx, "tailscale", "status", "--json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("tailscale status: %w", err)
	}

	var status statusResponse
	if err := json.Unmarshal(output, &status); err != nil {
		return nil, fmt.Errorf("parse tailscale status: %w", err)
	}

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

func peerFromSelf(s selfStatus) Peer {
	return Peer{
		ID:     s.ID,
		Name:   s.HostName + " (self)",
		IPs:    parseIPs(s.TailscaleIPs),
		Online: s.Online,
		Self:   true,
	}
}

func peerFromStatus(id string, s peerStatus) Peer {
	name := s.HostName
	if name == "" {
		name = id
	}
	return Peer{
		ID:     firstNonEmpty(s.ID, id),
		Name:   name,
		IPs:    parseIPs(s.TailscaleIPs),
		Online: s.Online,
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
