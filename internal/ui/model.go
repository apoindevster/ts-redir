package ui

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/apoindevster/ts-redir/internal/app"
	"github.com/apoindevster/ts-redir/internal/firewall"
	"github.com/apoindevster/ts-redir/internal/state"
	"github.com/apoindevster/ts-redir/internal/tailscale"
)

type mode int

const (
	modeInitializing mode = iota
	modeList
	modeAdding
	modeConfirmDelete
	modeEditingDNS
	modeAddingHostname
	modeConfirmHostnameDelete
	modeDetails
	modeHelp
	modeRawStatus
)

type page int

const (
	pageRules page = iota
	pageDNS
	pageHostnames
	pageChecks
	pageTailnet
)

var pageNames = []string{"Redirects", "Local DNS", "Hostnames", "Checks", "Tailnet"}

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#00796b", Dark: "#67f5df"})
	statusStyle = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#00796b", Dark: "#67f5df"})
	errorStyle  = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#a43f00", Dark: "#ffad70"})
	helpStyle   = lipgloss.NewStyle().Faint(true)
)

// Model is the root Bubble Tea model. Commands perform I/O outside the event loop.
type Model struct {
	manager                             firewall.Manager
	application                         *app.App
	iface                               string
	ownsManager                         bool
	ctx                                 context.Context
	cancel                              context.CancelFunc
	list, hosts, peerList               list.Model
	details                             viewport.Model
	rules                               []firewall.RedirectRule
	peers                               []tailscale.Peer
	config                              state.Config
	status                              app.Status
	addresses                           []app.LANAddress
	addressError, peerError, rulesError string
	statusMessage                       string
	statusError                         bool
	mode                                mode
	page                                page
	addForm                             *addRuleModel
	dnsForm                             *dnsForm
	hostnameForm                        *hostnameForm
	pendingDelete                       *firewall.RedirectRule
	pendingHostname                     string
	detailText                          string
	width, height                       int
	ready, busy, refreshing             bool
	quitAfterSave                       bool
	refreshID                           uint64
	checking                            bool
	checkCancel                         context.CancelFunc
	checkID                             uint64
	checks                              []app.Check
	checkedAt                           time.Time
	rawStatus                           string
	rawLoading, peersLoading            bool
}

func newList(title string) list.Model {
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = delegate.Styles.SelectedTitle.Foreground(lipgloss.AdaptiveColor{Light: "#00796b", Dark: "#67f5df"})
	l := list.New(nil, delegate, 80, 12)
	l.Title = title
	l.SetShowHelp(false)
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	// Only the root handles quitting: q is ordinary text in forms.
	l.DisableQuitKeybindings()
	return l
}

func NewModel() Model {
	ctx, cancel := context.WithCancel(context.Background())
	return Model{list: newList("Redirect Rules"), hosts: newList("Service hostnames"), peerList: newList("Tailnet peers"), details: viewport.New(80, 12), mode: modeInitializing, width: 80, height: 24, ctx: ctx, cancel: cancel}
}

// NewModelWithManager retains support for a caller supplying only forwarding.
func NewModelWithManager(manager firewall.Manager) Model {
	m := NewModel()
	m.manager = manager
	return m
}

// NewModelWithApplication exposes the same persistent services as the web UI.
func NewModelWithApplication(application *app.App, iface string) Model {
	m := NewModelWithManager(application.Manager)
	m.application, m.iface = application, iface
	return m
}

func (m Model) Init() tea.Cmd {
	if m.manager != nil {
		return func() tea.Msg { return initResultMsg{manager: m.manager} }
	}
	return func() tea.Msg {
		manager, err := firewall.NewManager()
		return initResultMsg{manager: manager, err: err, owned: true}
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := m.update(msg)
	next.resize()
	return next, cmd
}

func (m Model) update(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tea.QuitMsg:
		m.shutdown()
		return m, nil
	case initResultMsg:
		m.ready, m.mode = true, modeList
		if msg.err != nil {
			m.setError(msg.err)
			return m, nil
		}
		m.manager, m.ownsManager = msg.manager, msg.owned
		return m, tea.Batch(m.refresh(), m.refreshPeers(), scheduleRefresh())
	case snapshotMsg:
		if msg.id != m.refreshID {
			return m, nil
		}
		m.refreshing = false
		m.rulesError = ""
		if msg.err != nil {
			m.rulesError = msg.err.Error()
			m.setError(msg.err)
		} else {
			m.rules = msg.rules
			selected := m.currentRule()
			m.list.SetItems(rulesToItems(msg.rules))
			if selected != nil {
				selectRule(&m.list, selected.Handle)
			}
		}
		if m.application != nil {
			m.config, m.status = msg.config, msg.status
			m.addresses, m.addressError = msg.addresses, msg.addressError
			oldName := m.selectedHostname()
			m.hosts.SetItems(hostnameItems(m.config))
			for i, h := range m.config.Hostnames {
				if h.Name == oldName {
					m.hosts.Select(i)
				}
			}
		}
		return m, nil
	case peersLoadedMsg:
		m.peersLoading = false
		if msg.err != nil {
			m.peerError = msg.err.Error()
			return m, nil
		}
		m.peers, m.peerError = msg.peers, ""
		selectedID := ""
		if item, ok := m.peerList.SelectedItem().(tailnetItem); ok {
			selectedID = item.peer.ID
		}
		m.peerList.SetItems(tailnetItems(msg.peers))
		for i, p := range msg.peers {
			if p.ID == selectedID {
				m.peerList.Select(i)
			}
		}
		if m.addForm != nil {
			m.addForm.SetPeers(msg.peers)
		}
		return m, nil
	case refreshMsg:
		return m, tea.Batch(m.refresh(), m.refreshPeers(), scheduleRefresh())
	case opResultMsg:
		m.busy = false
		if m.quitAfterSave {
			m.shutdown()
			return m, tea.Quit
		}
		if msg.err != nil {
			m.setError(msg.err)
			return m, nil
		}
		m.statusMessage, m.statusError = msg.message, false
		m.mode = modeList
		m.addForm, m.dnsForm, m.hostnameForm = nil, nil, nil
		m.pendingDelete, m.pendingHostname = nil, ""
		// Diagnostics describe the configuration at the time they ran.
		m.checks, m.checkedAt = nil, time.Time{}
		return m, m.refresh()
	case checksMsg:
		if !m.checking || msg.id != m.checkID {
			return m, nil
		}
		m.checking = false
		m.checkCancel = nil
		m.checks, m.checkedAt = msg.checks, time.Now()
		return m, nil
	case rawStatusMsg:
		m.rawLoading = false
		if msg.err != nil {
			m.rawStatus = "Could not load Tailscale status: " + msg.err.Error()
		} else {
			m.rawStatus = msg.text
		}
		return m, nil
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			if m.busy {
				m.quitAfterSave = true
				m.statusMessage = "Finishing the current save before quitting…"
				return m, nil
			}
			m.shutdown()
			return m, tea.Quit
		}
		if m.width < 40 || m.height < 16 {
			return m, nil
		}
		if m.busy {
			return m, nil
		}
		if m.mode == modeAdding && m.addForm != nil {
			cmd := m.addForm.Update(msg)
			if m.addForm.Canceled() {
				m.addForm = nil
				m.mode = modeList
				m.clearStatus()
				return m, nil
			}
			if m.addForm.Completed() {
				rule := m.addForm.Result()
				m.addForm.completed = false
				return m, m.mutate("Redirect added", func() error { return m.manager.AddRedirectRule(rule) })
			}
			return m, cmd
		}
		if m.mode == modeEditingDNS && m.dnsForm != nil {
			cmd, done, canceled := m.dnsForm.Update(msg)
			if canceled {
				m.dnsForm = nil
				m.mode = modeList
				m.clearStatus()
				return m, nil
			}
			if done {
				settings := m.dnsForm.settings
				return m, m.mutate("DNS settings saved", func() error { return m.application.ConfigureDNS(settings) })
			}
			return m, cmd
		}
		if m.mode == modeAddingHostname && m.hostnameForm != nil {
			cmd, done, canceled := m.hostnameForm.Update(msg)
			if canceled {
				m.hostnameForm = nil
				m.mode = modeList
				m.clearStatus()
				return m, nil
			}
			if done {
				name, handle := m.hostnameForm.name(), m.hostnameForm.handle()
				return m, m.mutate("Hostname added", func() error { return m.application.Manager.AddHostname(name, handle) })
			}
			return m, cmd
		}
		return m.handleKey(msg)
	}
	// Text input cursor/blink messages must reach the active form too.
	if m.mode == modeAdding && m.addForm != nil {
		return m, m.addForm.Update(msg)
	}
	if m.mode == modeAddingHostname && m.hostnameForm != nil {
		cmd, _, _ := m.hostnameForm.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) clearStatus()       { m.statusMessage, m.statusError = "", false }
func (m *Model) setError(err error) { m.statusMessage, m.statusError = "Error: "+err.Error(), true }
func (m *Model) shutdown() {
	m.cancel()
	if m.checkCancel != nil {
		m.checkCancel()
	}
	if m.ownsManager && m.manager != nil {
		_ = m.manager.Close()
		m.ownsManager = false
	}
}

func (m *Model) mutate(message string, operation func() error) tea.Cmd {
	if m.checking {
		m.setError(fmt.Errorf("wait for setup checks or cancel them on the Checks view"))
		return nil
	}
	m.busy = true
	m.refreshID++ // Discard snapshots started before this write.
	m.refreshing = false
	m.statusMessage, m.statusError = "Saving…", false
	return func() tea.Msg { return opResultMsg{message: message, err: operation()} }
}

func (m Model) handleKey(msg tea.KeyMsg) (Model, tea.Cmd) {
	key := msg.String()
	if key == "q" {
		m.shutdown()
		return m, tea.Quit
	}
	if !m.ready {
		return m, nil
	}
	readOnly := m.mode == modeHelp || m.mode == modeDetails || m.mode == modeRawStatus ||
		(m.mode == modeList && (m.page == pageDNS || m.page == pageChecks))
	if readOnly && (key == "home" || key == "end") {
		if key == "home" {
			m.details.GotoTop()
		} else {
			m.details.GotoBottom()
		}
		return m, nil
	}
	if m.mode == modeConfirmDelete || m.mode == modeConfirmHostnameDelete {
		switch key {
		case "esc", "n":
			m.mode, m.pendingDelete, m.pendingHostname = modeList, nil, ""
		case "y":
			if m.pendingDelete != nil {
				handle := m.pendingDelete.Handle
				return m, m.mutate("Redirect deleted", func() error { return m.manager.DeleteRedirectRule(handle) })
			}
			name := m.pendingHostname
			return m, m.mutate("Hostname removed; redirect kept", func() error { return m.application.Manager.DeleteHostname(name) })
		}
		return m, nil
	}
	if m.mode == modeHelp || m.mode == modeDetails || m.mode == modeRawStatus {
		if key == "esc" {
			m.mode = modeList
			m.details.GotoTop()
			return m, nil
		}
		if m.mode == modeRawStatus && key == "r" {
			return m, m.loadRawStatus()
		}
		var cmd tea.Cmd
		m.details, cmd = m.details.Update(msg)
		return m, cmd
	}
	switch key {
	case "tab", "shift+tab", "1", "2", "3", "4", "5":
		switch key {
		case "tab":
			m.page = (m.page + 1) % 5
		case "shift+tab":
			m.page = (m.page + 4) % 5
		default:
			m.page = page(key[0] - '1')
		}
		m.clearStatus()
		m.details.GotoTop()
		return m, m.refresh()
	case "?":
		m.mode = modeHelp
		m.details.GotoTop()
		return m, nil
	case "r":
		if m.page == pageChecks {
			return m, m.runChecks()
		}
		return m, tea.Batch(m.refresh(), m.refreshPeers())
	}
	if m.page == pageDNS || m.page == pageHostnames || m.page == pageChecks {
		if m.application == nil {
			m.setError(fmt.Errorf("DNS management requires persistent application mode"))
			return m, nil
		}
	}
	switch m.page {
	case pageRules:
		switch key {
		case "a":
			if m.manager == nil {
				m.setError(fmt.Errorf("firewall manager unavailable"))
				return m, nil
			}
			form := newAddRuleModel(m.peers)
			m.addForm, m.mode = &form, modeAdding
			m.clearStatus()
			return m, form.Init()
		case "d":
			if r := m.currentRule(); r != nil {
				m.pendingDelete, m.mode = r, modeConfirmDelete
			}
			return m, nil
		case "enter":
			if r := m.currentRule(); r != nil {
				m.detailText, m.mode = ruleDetails(*r, m.config), modeDetails
				m.details.GotoTop()
			}
			return m, nil
		}
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	case pageDNS:
		if key == "e" {
			if m.refreshing {
				m.statusMessage = "Loading current settings…"
				return m, nil
			}
			form := newDNSForm(m.config.DNS, m.addresses)
			m.dnsForm, m.mode = &form, modeEditingDNS
			m.clearStatus()
			return m, nil
		}
	case pageHostnames:
		switch key {
		case "a":
			if m.refreshing {
				m.statusMessage = "Loading current redirects…"
				return m, nil
			}
			if m.rulesError != "" {
				m.setError(fmt.Errorf("refresh redirects before adding a hostname: %s", m.rulesError))
				return m, nil
			}
			form := newHostnameForm(m.rules)
			m.hostnameForm, m.mode = &form, modeAddingHostname
			m.clearStatus()
			return m, form.Init()
		case "d":
			if name := m.selectedHostname(); name != "" {
				m.pendingHostname, m.mode = name, modeConfirmHostnameDelete
			}
			return m, nil
		case "enter":
			if h, ok := m.hosts.SelectedItem().(hostnameItem); ok {
				m.detailText, m.mode = h.details(), modeDetails
				m.details.GotoTop()
			}
			return m, nil
		}
		var cmd tea.Cmd
		m.hosts, cmd = m.hosts.Update(msg)
		return m, cmd
	case pageChecks:
		if key == "enter" {
			return m, m.runChecks()
		}
		if key == "c" && m.checking {
			m.checkCancel()
			m.checking = false
			m.checkCancel = nil
			m.statusMessage = "Checks canceled"
			return m, nil
		}
	case pageTailnet:
		if key == "s" {
			m.mode = modeRawStatus
			m.details.GotoTop()
			return m, m.loadRawStatus()
		}
		if key == "enter" {
			if item, ok := m.peerList.SelectedItem().(tailnetItem); ok {
				m.detailText, m.mode = peerDetails(item.peer), modeDetails
				m.details.GotoTop()
			}
			return m, nil
		}
		var cmd tea.Cmd
		m.peerList, cmd = m.peerList.Update(msg)
		return m, cmd
	}
	var cmd tea.Cmd
	m.details, cmd = m.details.Update(msg)
	return m, cmd
}

func (m Model) currentRule() *firewall.RedirectRule {
	item, ok := m.list.SelectedItem().(ruleItem)
	if !ok {
		return nil
	}
	r := item.rule
	return &r
}
func selectRule(l *list.Model, handle uint64) {
	for i, item := range l.Items() {
		if r, ok := item.(ruleItem); ok && r.rule.Handle == handle {
			l.Select(i)
			return
		}
	}
}
func (m Model) selectedHostname() string {
	if item, ok := m.hosts.SelectedItem().(hostnameItem); ok {
		return item.hostname.Name
	}
	return ""
}

func (m *Model) refresh() tea.Cmd {
	if m.busy || m.refreshing || m.manager == nil {
		return nil
	}
	m.refreshing = true
	m.refreshID++
	id, manager, application, iface := m.refreshID, m.manager, m.application, m.iface
	return func() tea.Msg {
		out := snapshotMsg{id: id}
		out.rules, out.err = manager.ListRedirectRules()
		if application != nil {
			out.config, out.status = application.Store.Snapshot(), application.Status()
			var err error
			out.addresses, err = app.LANAddresses(iface)
			if err != nil {
				out.addressError = err.Error()
			}
		}
		return out
	}
}
func (m *Model) refreshPeers() tea.Cmd {
	if m.peersLoading {
		return nil
	}
	m.peersLoading = true
	ctx := m.ctx
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		peers, err := tailscale.ListPeers(ctx)
		return peersLoadedMsg{peers: peers, err: err}
	}
}
func scheduleRefresh() tea.Cmd {
	return tea.Tick(30*time.Second, func(time.Time) tea.Msg { return refreshMsg{} })
}

type initResultMsg struct {
	manager firewall.Manager
	err     error
	owned   bool
}
type snapshotMsg struct {
	id           uint64
	rules        []firewall.RedirectRule
	config       state.Config
	status       app.Status
	addresses    []app.LANAddress
	addressError string
	err          error
}
type peersLoadedMsg struct {
	peers []tailscale.Peer
	err   error
}
type refreshMsg struct{}
type opResultMsg struct {
	message string
	err     error
}

func (m Model) frame() (header, footer string, bodyHeight int) {
	width := max(1, m.width)
	header = titleStyle.Render("ts-redir · "+pageNames[m.page]) + "\n" + wrap("1 Redirects  2 DNS  3 Hostnames  4 Checks  5 Tailnet", width)
	help := "tab switch view • ? help • q quit"
	switch m.mode {
	case modeAdding:
		help = "enter continue/save • ctrl+b back • esc cancel"
	case modeEditingDNS, modeAddingHostname:
		help = "enter continue/save • backspace back • esc cancel"
	case modeConfirmDelete, modeConfirmHostnameDelete:
		help = "y confirm • n/esc cancel"
	case modeHelp, modeDetails, modeRawStatus:
		help = "↑/↓ scroll • pgup/pgdown • esc back • q quit"
	default:
		switch m.page {
		case pageRules:
			help = "a add • d delete • enter details • r refresh\n" + help
		case pageDNS:
			help = "e edit • r refresh • ↑/↓ scroll\n" + help
		case pageHostnames:
			help = "a add • d remove • enter details • r refresh\n" + help
		case pageChecks:
			help = "enter/r run checks • c cancel • ↑/↓ scroll\n" + help
		case pageTailnet:
			help = "enter details • s full status • r refresh\n" + help
		}
	}
	if m.busy {
		help = "Saving… • ctrl+c quit"
	}
	footer = helpStyle.Render(wrap(help, width))
	if m.statusMessage != "" {
		style := statusStyle
		if m.statusError {
			style = errorStyle
		}
		// Keep navigation visible even when a backend returns a long error.
		notice := wrap(clean(m.statusMessage), width)
		lines := strings.Split(notice, "\n")
		if len(lines) > 3 {
			notice = strings.Join(lines[:2], "\n") + "\n" + ansi.Truncate(lines[2], max(1, width-1), "") + "…"
		}
		footer += "\n" + style.Render(notice)
	}
	return header, footer, max(1, m.height-lipgloss.Height(header)-lipgloss.Height(footer)-2)
}

func (m *Model) resize() {
	_, _, height := m.frame()
	width := max(1, m.width)
	m.list.SetSize(width, height)
	m.hosts.SetSize(width, height)
	m.peerList.SetSize(width, height)
	m.details.Width, m.details.Height = width, height
	if m.addForm != nil {
		m.addForm.SetSize(width, height)
	}
	if m.dnsForm != nil {
		m.dnsForm.SetSize(width, height)
	}
	if m.hostnameForm != nil {
		m.hostnameForm.SetSize(width, height)
	}
	m.details.SetContent(wrap(m.detailContent(), width))
}

func (m Model) View() string {
	if m.width < 40 || m.height < 16 {
		return wrap("Enlarge terminal to at least 40 columns × 16 rows. Ctrl+C quits.", max(1, m.width))
	}
	if !m.ready {
		return "Initializing forwarding manager…"
	}
	header, footer, height := m.frame()
	var body string
	switch m.mode {
	case modeAdding:
		body = m.addForm.View()
	case modeEditingDNS:
		body = m.dnsForm.View()
	case modeAddingHostname:
		body = m.hostnameForm.View()
	case modeConfirmDelete:
		if m.pendingDelete != nil {
			body = "Delete this redirect?\n\n" + ruleDetails(*m.pendingDelete, m.config) + "\n\nPress y to delete. Enter does not confirm."
		}
	case modeConfirmHostnameDelete:
		body = "Remove hostname " + clean(m.pendingHostname) + "?\n\nThe shared redirect will remain.\n\nPress y to remove. Enter does not confirm."
	case modeDetails, modeHelp, modeRawStatus:
		body = m.details.View()
	default:
		switch m.page {
		case pageRules:
			if len(m.rules) == 0 {
				body = "No redirects configured.\n\nPress a to forward a local port to a tailnet peer."
			} else {
				body = m.list.View()
			}
			if m.rulesError != "" {
				body = "Could not refresh redirects: " + clean(m.rulesError) + "\n\nPress r to retry."
			}
		case pageHostnames:
			if len(m.config.Hostnames) == 0 {
				body = "No service hostnames configured.\n\nCreate a TCP redirect on a specific private LAN IPv4 address, then press a to associate a hostname."
			} else {
				body = m.hosts.View()
			}
		case pageTailnet:
			if m.peerError != "" {
				body = "Could not load peers: " + clean(m.peerError) + "\n\nPress r to retry."
			} else if len(m.peers) == 0 {
				body = "No tailnet peers available. Press r to refresh."
			} else {
				body = m.peerList.View()
			}
		default:
			body = m.details.View()
		}
	}
	body = wrap(body, max(1, m.width))
	// Bound rendering even when resized mid-form or when a backend error is long.
	lines := strings.Split(body, "\n")
	if len(lines) > height {
		lines = lines[:height]
	}
	for len(lines) < height {
		lines = append(lines, "")
	}
	return header + "\n\n" + strings.Join(lines, "\n") + "\n" + footer
}

func wrap(text string, width int) string {
	return ansi.Hardwrap(ansi.Wordwrap(text, max(1, width), ""), max(1, width), true)
}
func clean(text string) string {
	text = ansi.Strip(text)
	return strings.Map(func(r rune) rune {
		if r < 32 || (r >= 0x7f && r <= 0x9f) {
			return ' '
		}
		return r
	}, text)
}
func rulesToItems(rules []firewall.RedirectRule) []list.Item {
	items := make([]list.Item, 0, len(rules))
	for _, r := range rules {
		items = append(items, ruleItem{rule: r})
	}
	return items
}

type ruleItem struct {
	rule firewall.RedirectRule
}

func (i ruleItem) Title() string {
	source := ipOrInterface(i.rule.MatchIP, i.rule.MatchInterface)
	return fmt.Sprintf("%s:%d → %s:%d (%s)",
		source,
		i.rule.MatchPort,
		i.rule.TargetIP.String(),
		i.rule.TargetPort,
		strings.ToUpper(string(i.rule.Protocol)),
	)
}

func (i ruleItem) Description() string {
	var parts []string
	if i.rule.Description != "" {
		parts = append(parts, clean(i.rule.Description))
	}
	if i.rule.TailscalePeer != "" {
		parts = append(parts, fmt.Sprintf("peer: %s", clean(i.rule.TailscalePeer)))
	}
	return strings.Join(parts, " • ")
}

func (i ruleItem) FilterValue() string {
	source := ipOrInterface(i.rule.MatchIP, i.rule.MatchInterface)
	return fmt.Sprintf("%s %d %s %d %s %d",
		source,
		i.rule.MatchPort,
		i.rule.TargetIP.String(),
		i.rule.TargetPort,
		i.rule.Description,
		i.rule.Handle,
	)
}

func ipOrInterface(ip net.IP, iface string) string {
	if ip != nil && ip.String() != "" {
		return ip.String()
	}
	if iface != "" {
		return clean(iface)
	}
	return "any"
}
