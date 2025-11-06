package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/apoindevster/ts-redir/internal/nft"
	"github.com/apoindevster/ts-redir/internal/tailscale"
)

type mode int

const (
	modeInitializing mode = iota
	modeList
	modeAdding
	modeConfirmDelete
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true)
	statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	errorStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	helpStyle   = lipgloss.NewStyle().Faint(true)
)

// Model is the root Bubble Tea model for ts-redir.
type Model struct {
	manager *nft.Manager
	list    list.Model

	rules []nft.RedirectRule
	peers []tailscale.Peer

	statusMessage string

	mode          mode
	addForm       *addRuleModel
	pendingDelete *nft.RedirectRule

	width  int
	height int
	ready  bool
}

// NewModel constructs a new root model.
func NewModel() Model {
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true

	l := list.New([]list.Item{}, delegate, 0, 0)
	l.Title = "Redirect Rules"
	l.SetShowHelp(false)
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)

	return Model{
		list: l,
		mode: modeInitializing,
	}
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return tea.Batch(initManagerCmd(), schedulePeerRefresh())
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetSize(m.width, m.height-5) // -5 because of the title.
		if m.addForm != nil {
			m.addForm.SetSize(m.width, m.height)
		}
		return m, nil

	case tea.KeyMsg:
		if m.mode == modeAdding && m.addForm != nil {
			if msg.String() == "ctrl+c" {
				if m.manager != nil {
					_ = m.manager.Close()
				}
				return m, tea.Quit
			}
			cmd := m.addForm.Update(msg)
			if m.addForm.Completed() {
				rule := m.addForm.Result()
				m.addForm = nil
				m.mode = modeList
				return m, tea.Batch(cmd, addRuleCmd(m.manager, rule))
			}
			if m.addForm.Canceled() {
				m.addForm = nil
				m.mode = modeList
				m.statusMessage = "rule creation cancelled"
			}
			return m, cmd
		}
		return m.handleKeyMsg(msg)

	case tea.QuitMsg:
		if m.manager != nil {
			_ = m.manager.Close()
			m.manager = nil
		}
		return m, nil

	case initResultMsg:
		if msg.err != nil {
			m.statusMessage = fmt.Sprintf("init error: %v", msg.err)
			m.mode = modeList
			m.ready = true
			return m, loadPeersCmd()
		}
		m.manager = msg.manager
		m.ready = true
		m.mode = modeList
		return m, tea.Batch(loadRulesCmd(m.manager), loadPeersCmd())

	case rulesLoadedMsg:
		m.rules = msg.rules
		m.list.SetItems(rulesToItems(msg.rules))
		if len(msg.rules) == 0 {
			m.list.Title = "No redirect rules configured"
		} else {
			m.list.Title = "Redirect Rules"
		}
		return m, nil

	case peersLoadedMsg:
		m.peers = msg.peers
		if m.addForm != nil {
			m.addForm.SetPeers(msg.peers)
		}
		return m, nil

	case peersRefreshMsg:
		return m, tea.Batch(loadPeersCmd(), schedulePeerRefresh())

	case opResultMsg:
		if msg.err != nil {
			m.statusMessage = fmt.Sprintf("error: %v", msg.err)
			return m, nil
		}
		m.statusMessage = msg.message
		return m, loadRulesCmd(m.manager)

	default:
		return m, nil
	}
}

func (m *Model) handleKeyMsg(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if !m.ready && m.mode != modeInitializing {
		return m, nil
	}

	switch msg.String() {
	case "ctrl+c", "q":
		if m.manager != nil {
			_ = m.manager.Close()
		}
		return m, tea.Quit
	}

	switch m.mode {
	case modeList:
		return m.handleListKey(msg)
	case modeConfirmDelete:
		return m.handleConfirmKey(msg)
	default:
		return m, nil
	}
}

func (m *Model) handleListKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "a":
		if m.manager == nil {
			m.statusMessage = "nft manager unavailable"
			return m, nil
		}
		form := newAddRuleModel(m.peers)
		form.SetSize(m.width, m.height)
		m.addForm = &form
		m.mode = modeAdding
		return m, form.Init()

	case "d":
		if len(m.list.Items()) == 0 {
			return m, nil
		}
		selected := m.currentRule()
		if selected == nil {
			return m, nil
		}
		m.pendingDelete = selected
		m.mode = modeConfirmDelete
		return m, nil

	case "r":
		if m.manager == nil {
			m.statusMessage = "nft manager unavailable"
			return m, nil
		}
		return m, loadRulesCmd(m.manager)
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m *Model) handleConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "enter":
		if m.pendingDelete != nil && m.manager != nil {
			handle := m.pendingDelete.Handle
			m.pendingDelete = nil
			m.mode = modeList
			return m, deleteRuleCmd(m.manager, handle)
		}
	case "n", "esc":
		m.pendingDelete = nil
		m.mode = modeList
		return m, nil
	}
	return m, nil
}

func (m *Model) currentRule() *nft.RedirectRule {
	item, ok := m.list.SelectedItem().(ruleItem)
	if !ok {
		return nil
	}
	for _, r := range m.rules {
		if r.Handle == item.rule.Handle {
			return &r
		}
	}
	return nil
}

// View renders the TUI.
func (m Model) View() string {
	if !m.ready && m.mode == modeInitializing {
		return "initialising nftables connection..."
	}

	if m.mode == modeAdding && m.addForm != nil {
		return m.addForm.FullView(m.statusMessage)
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render("ts-redir — tailscale redirect manager"))
	b.WriteString("\n\n")
	b.WriteString(m.list.View())
	b.WriteString("\n\n")
	b.WriteString(helpStyle.Render("a add • d delete • r refresh • q quit"))
	if m.statusMessage != "" {
		b.WriteString("\n")
		b.WriteString(statusStyle.Render(m.statusMessage))
	}

	switch m.mode {
	case modeAdding:
		if m.addForm != nil {
			b.WriteString("\n\n")
			b.WriteString(m.addForm.View())
		}
	case modeConfirmDelete:
		if m.pendingDelete != nil {
			msg := fmt.Sprintf("Delete rule %s:%d → %s:%d ? (y/N)",
				m.pendingDelete.MatchIP, m.pendingDelete.MatchPort,
				m.pendingDelete.TargetIP, m.pendingDelete.TargetPort,
			)
			b.WriteString("\n\n")
			b.WriteString(errorStyle.Render(msg))
		}
	}

	return b.String()
}

type initResultMsg struct {
	manager *nft.Manager
	err     error
}

type rulesLoadedMsg struct {
	rules []nft.RedirectRule
}

type peersLoadedMsg struct {
	peers []tailscale.Peer
}

type peersRefreshMsg struct {
}

type opResultMsg struct {
	message string
	err     error
}

func initManagerCmd() tea.Cmd {
	return func() tea.Msg {
		manager, err := nft.NewManager()
		return initResultMsg{manager: manager, err: err}
	}
}

func loadRulesCmd(manager *nft.Manager) tea.Cmd {
	return func() tea.Msg {
		if manager == nil {
			return opResultMsg{err: fmt.Errorf("manager unavailable")}
		}
		rules, err := manager.ListRedirectRules()
		if err != nil {
			return opResultMsg{err: err}
		}
		return rulesLoadedMsg{rules: rules}
	}
}

func loadPeersCmd() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		peers, err := tailscale.ListPeers(ctx)
		if err != nil {
			return opResultMsg{err: err}
		}
		return peersLoadedMsg{peers: peers}
	}
}

func schedulePeerRefresh() tea.Cmd {
	return tea.Tick(30*time.Second, func(time.Time) tea.Msg {
		return peersRefreshMsg{}
	})
}

func addRuleCmd(manager *nft.Manager, rule nft.RedirectRule) tea.Cmd {
	return func() tea.Msg {
		if manager == nil {
			return opResultMsg{err: fmt.Errorf("manager unavailable")}
		}
		if err := manager.AddRedirectRule(rule); err != nil {
			return opResultMsg{err: err}
		}
		return opResultMsg{message: "rule added"}
	}
}

func deleteRuleCmd(manager *nft.Manager, handle uint64) tea.Cmd {
	return func() tea.Msg {
		if manager == nil {
			return opResultMsg{err: fmt.Errorf("manager unavailable")}
		}
		if err := manager.DeleteRedirectRule(handle); err != nil {
			return opResultMsg{err: err}
		}
		return opResultMsg{message: "rule deleted"}
	}
}

func rulesToItems(rules []nft.RedirectRule) []list.Item {
	items := make([]list.Item, 0, len(rules))
	for _, r := range rules {
		items = append(items, ruleItem{rule: r})
	}
	return items
}

type ruleItem struct {
	rule nft.RedirectRule
}

func (i ruleItem) Title() string {
	return fmt.Sprintf("%s:%d → %s:%d (%s)",
		i.rule.MatchIP.String(),
		i.rule.MatchPort,
		i.rule.TargetIP.String(),
		i.rule.TargetPort,
		strings.ToUpper(string(i.rule.Protocol)),
	)
}

func (i ruleItem) Description() string {
	var parts []string
	if i.rule.Description != "" {
		parts = append(parts, i.rule.Description)
	}
	if i.rule.TailscalePeer != "" {
		parts = append(parts, fmt.Sprintf("peer: %s", i.rule.TailscalePeer))
	}
	parts = append(parts, fmt.Sprintf("handle: %d", i.rule.Handle))
	return strings.Join(parts, " • ")
}

func (i ruleItem) FilterValue() string {
	return fmt.Sprintf("%s %d %s %d %s %d",
		i.rule.MatchIP.String(),
		i.rule.MatchPort,
		i.rule.TargetIP.String(),
		i.rule.TargetPort,
		i.rule.Description,
		i.rule.Handle,
	)
}
