package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/apoindevster/ts-redir/internal/app"
	"github.com/apoindevster/ts-redir/internal/firewall"
	"github.com/apoindevster/ts-redir/internal/state"
)

type dnsForm struct {
	settings  state.DNS
	step      int
	addresses list.Model
	err       string
}

type addressItem struct {
	ip, iface   string
	unavailable bool
}

func (a addressItem) Title() string {
	if a.ip == "" {
		return "No address selected"
	}
	return a.ip
}
func (a addressItem) Description() string {
	if a.unavailable {
		return "Saved address is not currently available"
	}
	return clean(a.iface)
}
func (a addressItem) FilterValue() string { return a.ip }

func newDNSForm(settings state.DNS, addresses []app.LANAddress) dnsForm {
	items := []list.Item{addressItem{iface: "DNS must be disabled to leave this empty"}}
	selected := 0
	for _, addr := range addresses {
		items = append(items, addressItem{ip: addr.IP, iface: addr.Interface})
		if addr.IP == settings.ListenIP {
			selected = len(items) - 1
		}
	}
	if settings.ListenIP != "" && selected == 0 {
		items = append(items, addressItem{ip: settings.ListenIP, unavailable: true})
		selected = len(items) - 1
	}
	l := newList("LAN address for DNS")
	l.SetItems(items)
	l.Select(selected)
	return dnsForm{settings: settings, addresses: l}
}
func (f *dnsForm) SetSize(width, height int) { f.addresses.SetSize(max(1, width), max(1, height-5)) }
func (f *dnsForm) Update(msg tea.Msg) (tea.Cmd, bool, bool) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			return nil, false, true
		case "backspace":
			if f.step > 0 {
				f.step--
				f.err = ""
			}
			return nil, false, false
		}
		if f.step == 0 {
			switch key.String() {
			case " ", "left", "right", "up", "down", "tab":
				f.settings.Enabled = !f.settings.Enabled
			case "enter":
				f.step = 1
			}
			return nil, false, false
		}
		if key.String() == "enter" {
			item, ok := f.addresses.SelectedItem().(addressItem)
			if !ok || (f.settings.Enabled && (item.ip == "" || item.unavailable)) {
				f.err = "Select an available LAN IPv4 address to enable DNS."
				return nil, false, false
			}
			f.settings.ListenIP = item.ip
			f.err = ""
			return nil, true, false
		}
	}
	if f.step == 1 {
		var cmd tea.Cmd
		f.addresses, cmd = f.addresses.Update(msg)
		return cmd, false, false
	}
	return nil, false, false
}
func (f dnsForm) View() string {
	if f.step == 0 {
		setting := "Disabled"
		if f.settings.Enabled {
			setting = "Enabled"
		}
		return titleStyle.Render("Edit Local DNS") + "\n\nDNS forwarding: " + statusStyle.Render(setting) + "\n\nSpace/arrow keys toggle • enter choose address\n\nDNS serves UDP and TCP port 53, including on Windows."
	}
	out := f.addresses.View() + "\nEnter saves • backspace returns to enable/disable"
	if f.err != "" {
		out += "\n" + errorStyle.Render(f.err)
	}
	return out
}

type hostnameForm struct {
	input textinput.Model
	rules list.Model
	step  int
	err   string
	width int
}

func newHostnameForm(rules []firewall.RedirectRule) hostnameForm {
	input := textinput.New()
	input.Prompt = "> "
	input.Placeholder = "photos.example.com"
	input.CharLimit = 254
	l := newList("Select TCP redirect")
	eligible := []list.Item{}
	for _, r := range rules {
		if r.Protocol == firewall.ProtocolTCP && r.MatchIP.To4() != nil && r.MatchIP.IsPrivate() {
			eligible = append(eligible, hostnameRuleItem{ruleItem{rule: r}})
		}
	}
	l.SetItems(eligible)
	return hostnameForm{input: input, rules: l, width: 80}
}
func (f *hostnameForm) Init() tea.Cmd { return f.input.Focus() }
func (f *hostnameForm) SetSize(width, height int) {
	f.width = max(1, width)
	f.input.Width = max(1, width-4)
	f.rules.SetSize(max(1, width), max(1, height-5))
}
func (f *hostnameForm) Update(msg tea.Msg) (tea.Cmd, bool, bool) {
	if key, ok := msg.(tea.KeyMsg); ok {
		if key.String() == "esc" {
			return nil, false, true
		}
		if f.step == 1 && key.String() == "backspace" {
			f.step = 0
			f.err = ""
			return f.input.Focus(), false, false
		}
		if key.String() == "enter" {
			if len(f.rules.Items()) == 0 {
				f.err = "Add a TCP redirect with a specific private LAN IPv4 address first."
				return nil, false, false
			}
			if f.step == 0 {
				name, err := state.NormalizeHostname(f.input.Value())
				if err != nil {
					f.err = err.Error()
					return nil, false, false
				}
				f.input.SetValue(name)
				f.input.Blur()
				f.step, f.err = 1, ""
				return nil, false, false
			}
			if _, ok := f.rules.SelectedItem().(hostnameRuleItem); ok {
				return nil, true, false
			}
		}
	}
	var cmd tea.Cmd
	if f.step == 0 {
		f.input, cmd = f.input.Update(msg)
	} else {
		f.rules, cmd = f.rules.Update(msg)
	}
	return cmd, false, false
}
func (f hostnameForm) name() string { return f.input.Value() }
func (f hostnameForm) handle() uint64 {
	if item, ok := f.rules.SelectedItem().(hostnameRuleItem); ok {
		return item.rule.Handle
	}
	return 0
}
func (f hostnameForm) View() string {
	if len(f.rules.Items()) == 0 {
		return "No eligible TCP redirects.\n\nPress Esc, switch to Redirects (1), and add a TCP redirect on a specific private LAN IPv4 address. Use local port 443 for HTTPS or 80 for HTTP. Interface-only redirects cannot be used for hostname answers."
	}
	out := titleStyle.Render("Add service hostname") + "\n\n"
	if f.step == 0 {
		out += "Hostname (no URL, port or wildcard):\n" + f.input.View() + "\n\nEnter selects a redirect. Several names can share one redirect."
	} else {
		// Keep both redirect endpoints visible even for a maximum-length name.
		// Backspace returns to the horizontally scrollable input for inspection.
		out = ansi.Truncate("Hostname: "+clean(f.name()), f.width, "…") + "\n" + f.rules.View() + "\nEnter adds mapping • backspace edits hostname"
	}
	if f.err != "" {
		out += "\n" + errorStyle.Render(f.err)
	}
	return out
}

type hostnameItem struct {
	hostname state.Hostname
	rule     firewall.RedirectRule
	found    bool
}

// Put the two endpoints on separate lines so the choice is legible in a narrow terminal.
type hostnameRuleItem struct{ ruleItem }

func (r hostnameRuleItem) Title() string {
	return fmt.Sprintf("%s:%d (TCP)", r.rule.MatchIP, r.rule.MatchPort)
}
func (r hostnameRuleItem) Description() string {
	return fmt.Sprintf("→ %s:%d · %s", r.rule.TargetIP, r.rule.TargetPort, clean(r.rule.Description))
}

func (h hostnameItem) Title() string { return clean(h.hostname.Name) }
func (h hostnameItem) Description() string {
	if !h.found {
		return "Saved redirect is missing"
	}
	return ruleItem{rule: h.rule}.Title()
}
func (h hostnameItem) FilterValue() string { return h.hostname.Name }
func (h hostnameItem) details() string {
	if !h.found {
		return h.Title() + "\n\nSaved redirect is missing. Remove this mapping and add it again."
	}
	return h.Title() + "\n\n" + ruleDetails(h.rule, state.Config{}) + "\n\nDNS answers this exact name with " + h.rule.MatchIP.String() + ".\nRemoving the hostname keeps its redirect."
}
func hostnameItems(c state.Config) []list.Item {
	items := make([]list.Item, 0, len(c.Hostnames))
	for _, h := range c.Hostnames {
		r, ok := c.Rule(h.RuleID)
		items = append(items, hostnameItem{hostname: h, rule: r, found: ok})
	}
	return items
}

func ruleDetails(r firewall.RedirectRule, c state.Config) string {
	out := fmt.Sprintf("Protocol: %s\nIngress address: %s\nIngress interface: %s\nLocal port: %d\nDestination: %s:%d\nPeer: %s\nDescription: %s",
		r.Protocol.Label(), ipOrInterface(r.MatchIP, ""), clean(r.MatchInterface), r.MatchPort, r.TargetIP, r.TargetPort, clean(r.TailscalePeer), clean(r.Description))
	names := []string{}
	for _, h := range c.Hostnames {
		if h.RuleID == state.RuleID(r) {
			names = append(names, h.Name)
		}
	}
	if len(names) > 0 {
		out += "\nHostnames: " + strings.Join(names, ", ") + "\nRemove these hostname mappings before deleting this redirect."
	}
	return out
}

func (m Model) detailContent() string {
	switch m.mode {
	case modeHelp:
		return tuiHelp
	case modeDetails:
		return m.detailText
	case modeRawStatus:
		if m.rawLoading {
			return "Loading full Tailscale status…"
		}
		return "Full Tailscale status (r refresh)\n\n" + m.rawStatus
	}
	if m.application == nil && (m.page == pageDNS || m.page == pageChecks) {
		return "DNS management requires persistent application mode."
	}
	switch m.page {
	case pageDNS:
		return m.dnsSummary()
	case pageChecks:
		if m.checking {
			return "Running setup checks…\n\nChecking DNS, upstream resolution, saved redirects, and destination connectivity. This can take up to 12 seconds. Press c to cancel; other views remain available."
		}
		if m.checkedAt.IsZero() {
			return "Setup checks have not run for the current configuration.\n\nPress Enter to inspect DNS, upstreams, saved/live redirects and destination connectivity, including TLS with the original hostname for local port 443.\n\nAlso test from a separate LAN client to verify its DNS settings and complete forwarding path."
		}
		out := "Setup checks · " + m.checkedAt.Format("15:04:05") + "\n\n"
		for _, check := range m.checks {
			label := "PASS"
			if !check.OK {
				label = "FAIL"
			}
			out += label + "  " + clean(check.Name) + "\n" + clean(check.Detail) + "\n\n"
		}
		return out + "Test from a separate LAN client as well. These checks cannot verify client DHCP, browser DNS or the complete LAN path."
	}
	return ""
}
func (m Model) dnsSummary() string {
	setting := "Disabled"
	if m.config.DNS.Enabled {
		setting = "Enabled — unavailable"
		if m.status.DNS.Running {
			setting = "Enabled — running"
		}
	}
	address := m.config.DNS.ListenIP
	if address == "" {
		address = "Not selected"
	} else {
		address += ":53 (UDP + TCP)"
	}
	upstreams := strings.Join(m.status.DNS.Upstreams, ", ")
	if upstreams == "" {
		upstreams = "None discovered"
	}
	out := fmt.Sprintf("Local DNS: %s\nListener: %s\nNetwork upstreams: %s\nSaved redirects: %d\nService hostnames: %d\nConfig: %s", setting, address, clean(upstreams), m.status.SavedRules, len(m.config.Hostnames), clean(m.status.ConfigPath))
	if m.status.DNS.Error != "" {
		out += "\n\nDNS error: " + clean(m.status.DNS.Error)
	}
	if m.status.RestoreError != "" {
		out += "\nRestore error: " + clean(m.status.RestoreError)
	}
	if m.addressError != "" {
		out += "\nLAN address discovery error: " + clean(m.addressError)
	}
	if len(m.addresses) == 0 {
		out += "\nNo available private LAN IPv4 addresses. Connect a LAN adapter and press r."
	}
	return out + "\n\nPress e to change listener settings. Use Hostnames (3) to map service domains to an existing TCP redirect.\n\nClients must use this LAN IP as DNS (DHCP or per-device settings). Keep this machine's network upstream DNS independent of ts-redir to avoid a forwarding loop. Public secondary DNS and custom browser DNS can bypass these overrides.\n\nExiting the TUI stops DNS. See ? for background service setup and HTTPS guidance."
}

type checksMsg struct {
	checks []app.Check
	id     uint64
}

func (m *Model) runChecks() tea.Cmd {
	if m.application == nil || m.checking || m.busy {
		return nil
	}
	ctx, cancel := context.WithTimeout(m.ctx, 12*time.Second)
	m.checking, m.checkCancel = true, cancel
	m.checkID++
	id, application := m.checkID, m.application
	m.clearStatus()
	m.details.GotoTop()
	return func() tea.Msg { defer cancel(); return checksMsg{checks: application.Diagnose(ctx), id: id} }
}

const tuiHelp = `Terminal controls

Tab / Shift+Tab or 1–5 switch views. Arrow keys select list entries. Enter shows their full details; Esc returns. Read-only views scroll with arrows, Page Up/Down, Home and End. q quits outside forms; Ctrl+C quits anywhere.

Redirects: a adds, d deletes, r refreshes. Ctrl+B returns to the previous step while adding a rule. Linux offers TCP, UDP and Both. Both creates independent TCP and UDP rules. Windows netsh portproxy supports TCP only. DNS itself supports UDP and TCP on either platform.

Local DNS: e edits enable/disable and the LAN listener address. Space toggles; Enter continues and then saves. Backspace returns to the previous step. Esc discards changes. Save failures preserve your input.

Hostnames: a adds an exact hostname and associates it with an existing TCP redirect on a private LAN IPv4 address. Several names can share a redirect. d removes a mapping, leaving the redirect in place. Remove all linked hostnames before deleting a redirect.

Checks: Enter or r runs setup checks; c cancels. They check DNS, network upstreams, saved/live redirects and destination connectivity. For local port 443 they check TLS with the original hostname. Test from a separate LAN client too.

Tailnet: inspect online/offline, self, OS, DNS name, addresses and exit-node capability. s shows full Tailscale status; r refreshes. The destination picker only lists peers with IPv4 addresses.

Client and HTTPS setup

Reserve a stable LAN IP. Clients must use ts-redir as DNS via DHCP or device settings; this app does not configure clients or routers. Keep the ts-redir host and router's upstream DNS independent of this listener. Public secondary resolvers, custom DNS-over-HTTPS, VPN DNS and caches can bypass overrides.

Forward local TCP 443 to your HTTPS reverse proxy, and TCP 80 for HTTP if needed. DNS names do not select ports. The original hostname and SNI reach the reverse proxy, whose certificate must cover those names. Multiple services on one local IP/port need one reverse proxy routing by hostname. Direct IP URLs do not carry this identity. HTTP/3 needs TCP fallback for this setup.

Exact names answer with IPv4 and a 30-second TTL. Other record types for those names return no data, preventing IPv6 and HTTPS/SVCB address hints from bypassing the redirect. Wildcards are unsupported; use punycode for international names. Other names use network upstream DNS; there is no public fallback.

Allow LAN UDP/TCP 53 and the redirected ports through the host firewall. Linux also needs IPv4 forwarding and appropriate forward-chain policy.

Persistence and background service

Changes are saved immediately to the config shown in Local DNS. Saved rules are restored on startup and every 30 seconds. Use the same --config path across terminal, web and service modes. Only one instance can own a config file; stop the service before starting the TUI.

Exiting the TUI stops DNS, but leaves OS forwarding rules. To run after reboot, install the built executable in a permanent location, then run with root/Administrator privileges:

ts-redir --service install
ts-redir --service start

Include custom --config, --ts-interface and --port options when installing. Stop the foreground instance before starting the service. Use --service status, stop, restart or uninstall as needed. --daemon runs the service components in the foreground for a supervisor. --web opens the web UI instead of the TUI.`
