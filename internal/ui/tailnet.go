package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/apoindevster/ts-redir/internal/tailscale"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
)

type tailnetItem struct{ peer tailscale.Peer }

func peerName(p tailscale.Peer) string {
	for _, s := range []string{p.Name, p.HostName, p.ID} {
		if s != "" {
			return clean(s)
		}
	}
	return "Unnamed peer"
}
func (p tailnetItem) Title() string {
	flags := []string{}
	if p.peer.Online {
		flags = append(flags, "online")
	} else {
		flags = append(flags, "offline")
	}
	if p.peer.Self {
		flags = append(flags, "this machine")
	}
	if p.peer.IsExitNode {
		flags = append(flags, "exit node available")
	}
	return peerName(p.peer) + " · " + strings.Join(flags, ", ")
}
func (p tailnetItem) Description() string {
	return clean(p.peer.OS) + " · " + peerAddresses(p.peer) + " · " + clean(p.peer.DNSName)
}
func (p tailnetItem) FilterValue() string { return peerName(p.peer) }
func peerAddresses(p tailscale.Peer) string {
	ips := []string{}
	for _, ip := range p.IPs {
		ips = append(ips, ip.String())
	}
	return strings.Join(ips, ", ")
}
func peerDetails(p tailscale.Peer) string {
	return fmt.Sprintf("%s\n\nHostname: %s\nDNS name: %s\nAddresses: %s\nOS: %s\nOnline: %t\nThis machine: %t\nExit node available: %t\nID: %s", peerName(p), clean(p.HostName), clean(p.DNSName), peerAddresses(p), clean(p.OS), p.Online, p.Self, p.IsExitNode, clean(p.ID))
}
func tailnetItems(peers []tailscale.Peer) []list.Item {
	items := make([]list.Item, 0, len(peers))
	for _, p := range peers {
		items = append(items, tailnetItem{peer: p})
	}
	return items
}

type rawStatusMsg struct {
	text string
	err  error
}

func (m *Model) loadRawStatus() tea.Cmd {
	if m.rawLoading {
		return nil
	}
	m.rawLoading = true
	ctx := m.ctx
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		raw, err := tailscale.RawStatus(ctx)
		if err != nil {
			return rawStatusMsg{err: err}
		}
		var buf bytes.Buffer
		if err = json.Indent(&buf, raw, "", "  "); err != nil {
			return rawStatusMsg{err: err}
		}
		return rawStatusMsg{text: buf.String()}
	}
}
