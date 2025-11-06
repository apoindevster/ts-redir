package ui

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/apoindevster/ts-redir/internal/nft"
	"github.com/apoindevster/ts-redir/internal/tailscale"
)

type addRuleModel struct {
	step int

	matchIPInput    textinput.Model
	matchPortInput  textinput.Model
	targetPortInput textinput.Model

	protocolIndex int

	peers    []tailscale.Peer
	peerList list.Model
	peerIP   net.IP
	peerName string

	matchIP    net.IP
	matchPort  uint16
	targetPort uint16

	width  int
	height int

	completed bool
	canceled  bool

	errMsg string
}

var protocolOptions = []nft.Protocol{nft.ProtocolTCP, nft.ProtocolUDP}

func newAddRuleModel(peers []tailscale.Peer) addRuleModel {
	matchIP := textinput.New()
	matchIP.Placeholder = "Destination IP to match (e.g. 192.168.1.10)"
	matchIP.Prompt = "> "
	matchIP.CharLimit = 64
	matchIP.Width = len(matchIP.Placeholder)

	matchPort := textinput.New()
	matchPort.Placeholder = "Destination port to match (1-65535)"
	matchPort.Prompt = "> "
	matchPort.CharLimit = 5
	matchPort.Width = len(matchPort.Placeholder)

	targetPort := textinput.New()
	targetPort.Placeholder = "Destination port on peer (1-65535)"
	targetPort.Prompt = "> "
	targetPort.CharLimit = 5
	targetPort.Width = len(targetPort.Placeholder)

	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = false
	l := list.New(peerItems(peers), delegate, 50, 7)
	l.Title = "Select destination peer"
	l.SetShowHelp(false)
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)

	return addRuleModel{
		matchIPInput:    matchIP,
		matchPortInput:  matchPort,
		targetPortInput: targetPort,
		peers:           peers,
		peerList:        l,
	}
}

func (a *addRuleModel) SetSize(width, height int) {
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	a.width = width
	a.height = height

	listWidth := width - 6
	if listWidth < 30 {
		listWidth = 30
	}
	listHeight := height - 10
	if listHeight < 5 {
		listHeight = 5
	}
	a.peerList.SetSize(listWidth, listHeight)
}

func (a *addRuleModel) Init() tea.Cmd {
	return a.matchIPInput.Focus()
}

func (a *addRuleModel) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			a.canceled = true
			return nil
		}
	}

	switch a.step {
	case 0:
		return a.updateMatchIP(msg)
	case 1:
		return a.updateMatchPort(msg)
	case 2:
		return a.updateProtocol(msg)
	case 3:
		return a.updatePeerSelection(msg)
	case 4:
		return a.updateTargetPort(msg)
	default:
		return nil
	}
}

func (a *addRuleModel) updateMatchIP(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	a.matchIPInput, cmd = a.matchIPInput.Update(msg)

	if key, ok := msg.(tea.KeyMsg); ok && key.Type == tea.KeyEnter {
		ip := net.ParseIP(strings.TrimSpace(a.matchIPInput.Value()))
		if ip == nil || ip.To4() == nil {
			a.errMsg = "enter a valid IPv4 address"
			return cmd
		}
		a.matchIP = ip.To4()
		a.step = 1
		a.errMsg = ""
		return a.matchPortInput.Focus()
	}

	return cmd
}

func (a *addRuleModel) updateMatchPort(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	a.matchPortInput, cmd = a.matchPortInput.Update(msg)

	if key, ok := msg.(tea.KeyMsg); ok && key.Type == tea.KeyEnter {
		port, err := parsePort(a.matchPortInput.Value())
		if err != nil {
			a.errMsg = err.Error()
			return cmd
		}
		a.matchPort = port
		a.step = 2
		a.errMsg = ""
		return nil
	}

	return cmd
}

func (a *addRuleModel) updateProtocol(msg tea.Msg) tea.Cmd {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "left", "up", "shift+tab":
			a.protocolIndex = (a.protocolIndex + len(protocolOptions) - 1) % len(protocolOptions)
		case "right", "down", "tab":
			a.protocolIndex = (a.protocolIndex + 1) % len(protocolOptions)
		case "enter":
			a.step = 3
			a.errMsg = ""
			return a.resetPeerList()
		}
	}
	return nil
}

func (a *addRuleModel) updatePeerSelection(msg tea.Msg) tea.Cmd {
	if len(a.peerList.Items()) == 0 {
		if key, ok := msg.(tea.KeyMsg); ok && key.Type == tea.KeyEnter {
			a.errMsg = "no peers available; refresh tailscale status"
		}
		return nil
	}

	var cmd tea.Cmd
	a.peerList, cmd = a.peerList.Update(msg)

	if key, ok := msg.(tea.KeyMsg); ok && key.Type == tea.KeyEnter {
		item, ok := a.peerList.SelectedItem().(peerItem)
		if !ok || item.ip == nil {
			a.errMsg = "selected peer has no IPv4 address"
			return tea.Batch(cmd)
		}
		a.peerIP = item.ip
		a.peerName = item.name
		a.step = 4
		a.errMsg = ""
		return tea.Batch(cmd, a.targetPortInput.Focus())
	}

	return cmd
}

func (a *addRuleModel) updateTargetPort(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	a.targetPortInput, cmd = a.targetPortInput.Update(msg)

	if key, ok := msg.(tea.KeyMsg); ok && key.Type == tea.KeyEnter {
		port, err := parsePort(a.targetPortInput.Value())
		if err != nil {
			a.errMsg = err.Error()
			return cmd
		}
		a.targetPort = port
		a.completed = true
		a.errMsg = ""
	}

	return cmd
}

func (a *addRuleModel) Completed() bool {
	return a.completed
}

func (a *addRuleModel) Result() nft.RedirectRule {
	description := fmt.Sprintf("→ %s", a.peerName)
	return nft.RedirectRule{
		Description:   description,
		Protocol:      protocolOptions[a.protocolIndex],
		MatchIP:       a.matchIP,
		MatchPort:     a.matchPort,
		TargetIP:      a.peerIP,
		TargetPort:    a.targetPort,
		TailscalePeer: a.peerName,
	}
}

func (a *addRuleModel) Canceled() bool {
	return a.canceled
}

func (a *addRuleModel) SetPeers(peers []tailscale.Peer) {
	a.peers = peers
	a.peerList.SetItems(peerItems(peers))
	a.SetSize(a.width, a.height)
}

func (a addRuleModel) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Add Redirect Rule"))
	b.WriteString("\n\n")

	switch a.step {
	case 0:
		b.WriteString("Match destination IPv4 address:\n")
		b.WriteString(a.matchIPInput.View())
	case 1:
		b.WriteString("Match destination port:\n")
		b.WriteString(a.matchPortInput.View())
	case 2:
		b.WriteString("Select protocol (Tab/Arrow keys to toggle):\n")
		for i, p := range protocolOptions {
			choice := strings.ToUpper(string(p))
			if i == a.protocolIndex {
				choice = statusStyle.Render(choice)
			}
			b.WriteString(choice)
			if i != len(protocolOptions)-1 {
				b.WriteString("  ")
			}
		}
	case 3:
		b.WriteString("Select destination Tailscale peer:\n")
		b.WriteString(a.peerList.View())
	case 4:
		b.WriteString("Destination port on selected peer:\n")
		b.WriteString(a.targetPortInput.View())
	}

	if a.errMsg != "" {
		b.WriteString("\n")
		b.WriteString(errorStyle.Render(a.errMsg))
	}

	b.WriteString("\n\n")
	b.WriteString(helpStyle.Render("enter continue • esc cancel"))
	return b.String()
}

func (a addRuleModel) FullView(status string) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("ts-redir — tailscale redirect manager"))
	b.WriteString("\n\n")
	b.WriteString(a.View())
	if status != "" {
		b.WriteString("\n\n")
		b.WriteString(statusStyle.Render(status))
	}
	return b.String()
}

func parsePort(value string) (uint16, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("port is required")
	}
	p, err := strconv.Atoi(value)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("port must be between 1 and 65535")
	}
	return uint16(p), nil
}

func (a *addRuleModel) resetPeerList() tea.Cmd {
	a.peerList.SetItems(peerItems(a.peers))
	if len(a.peerList.Items()) > 0 {
		a.peerList.Select(0)
	}
	return nil
}

type peerItem struct {
	name string
	ip   net.IP
}

func (p peerItem) Title() string {
	return fmt.Sprintf("%s", p.name)
}

func (p peerItem) Description() string {
	return p.ip.String()
}

func (p peerItem) FilterValue() string {
	return fmt.Sprintf("%s %s", p.name, p.ip)
}

func peerItems(peers []tailscale.Peer) []list.Item {
	items := []list.Item{}
	for _, peer := range peers {
		ip := primaryIPv4(peer.IPs)
		if ip == nil {
			continue
		}
		name := peer.Name
		if name == "" {
			name = peer.ID
		}
		if !peer.Online {
			name = fmt.Sprintf("%s (offline)", name)
		}
		items = append(items, peerItem{name: name, ip: ip})
	}
	return items
}

func primaryIPv4(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.To4()
		}
	}
	return nil
}
