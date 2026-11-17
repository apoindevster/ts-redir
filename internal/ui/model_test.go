package ui

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apoindevster/ts-redir/internal/app"
	"github.com/apoindevster/ts-redir/internal/firewall"
	"github.com/apoindevster/ts-redir/internal/state"
	"github.com/apoindevster/ts-redir/internal/tailscale"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

type tuiBackend struct {
	rules []firewall.RedirectRule
	next  uint64
	fail  bool
}

func (b *tuiBackend) ListRedirectRules() ([]firewall.RedirectRule, error) {
	return append([]firewall.RedirectRule(nil), b.rules...), nil
}
func (b *tuiBackend) RuleExists(r firewall.RedirectRule) (bool, error) {
	for _, old := range b.rules {
		if state.RuleID(old) == state.RuleID(r) {
			return true, nil
		}
	}
	return false, nil
}
func (b *tuiBackend) AddRedirectRule(r firewall.RedirectRule) error {
	if b.fail {
		return errors.New("firewall unavailable")
	}
	b.next++
	r.Handle = b.next
	b.rules = append(b.rules, r)
	return nil
}
func (b *tuiBackend) DeleteRedirectRule(handle uint64) error {
	for i, r := range b.rules {
		if r.Handle == handle {
			b.rules = append(b.rules[:i], b.rules[i+1:]...)
			return nil
		}
	}
	return errors.New("missing redirect")
}
func (b *tuiBackend) Close() error { return nil }
func tuiRule() firewall.RedirectRule {
	return firewall.RedirectRule{Protocol: firewall.ProtocolTCP, MatchIP: net.ParseIP("192.168.1.20"), MatchPort: 443, TargetIP: net.ParseIP("100.64.0.2"), TargetPort: 443, Description: "Shared HTTPS", TailscalePeer: "reverse-proxy"}
}
func testModel(t *testing.T) (Model, *app.App, *tuiBackend) {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	backend := &tuiBackend{next: 18446744073709551000}
	application := app.New(store, backend)
	m := NewModelWithApplication(application, "tailscale0")
	m.ready, m.mode = true, modeList
	t.Cleanup(func() { m.cancel(); application.Close() })
	settle(t, &m, m.refresh())
	return m, application, backend
}
func updateModel(m *Model, msg tea.Msg) tea.Cmd {
	next, cmd := m.Update(msg)
	*m = next.(Model)
	return cmd
}
func key(m *Model, s string) tea.Cmd {
	types := map[string]tea.KeyType{"enter": tea.KeyEnter, "esc": tea.KeyEsc, "tab": tea.KeyTab, "shift+tab": tea.KeyShiftTab, "down": tea.KeyDown, "up": tea.KeyUp, "backspace": tea.KeyBackspace, "ctrl+c": tea.KeyCtrlC, "pgdown": tea.KeyPgDown}
	if typ, ok := types[s]; ok {
		return updateModel(m, tea.KeyMsg{Type: typ})
	}
	return updateModel(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)})
}
func settle(t *testing.T, m *Model, cmd tea.Cmd) {
	t.Helper()
	for i := 0; cmd != nil; i++ {
		if i > 10 {
			t.Fatal("unexpected command loop")
		}
		msg := cmd()
		if _, ok := msg.(tea.BatchMsg); ok {
			t.Fatal("unexpected batch in synchronous workflow")
		}
		cmd = updateModel(m, msg)
	}
}
func pageKey(t *testing.T, m *Model, s string) { t.Helper(); settle(t, m, key(m, s)) }
func addMapping(t *testing.T, m *Model, name string) {
	t.Helper()
	pageKey(t, m, "3")
	key(m, "a")
	key(m, name)
	key(m, "enter")
	cmd := key(m, "enter")
	if !m.busy || cmd == nil {
		t.Fatalf("mapping was not submitted: %s", m.View())
	}
	if extra := key(m, "enter"); extra != nil {
		t.Fatal("duplicate in-flight submit")
	}
	settle(t, m, cmd)
}

func TestHostnameWorkflowPreservesSharedRulesAndLargeHandles(t *testing.T) {
	m, a, b := testModel(t)
	if err := a.Manager.AddRedirectRule(tuiRule()); err != nil {
		t.Fatal(err)
	}
	addMapping(t, &m, "Photos.Example.COM.")
	if m.statusError || len(a.Store.Snapshot().Hostnames) != 1 || a.Store.Snapshot().Hostnames[0].Name != "photos.example.com" {
		t.Fatal(m.statusMessage)
	}
	if b.rules[0].Handle != 18446744073709551001 {
		t.Fatal("handle lost precision")
	}
	addMapping(t, &m, "photos.example.com")
	if !m.statusError || m.mode != modeAddingHostname || m.hostnameForm.name() != "photos.example.com" || m.hostnameForm.handle() != b.rules[0].Handle {
		t.Fatal("failed add discarded input")
	}
	key(&m, "esc")
	pageKey(t, &m, "1")
	key(&m, "d")
	if cmd := key(&m, "enter"); cmd != nil {
		t.Fatal("Enter confirmed a destructive action")
	}
	settle(t, &m, key(&m, "y"))
	if !m.statusError || len(b.rules) != 1 || m.mode != modeConfirmDelete {
		t.Fatal("referenced redirect was deleted")
	}
	key(&m, "esc")
	pageKey(t, &m, "3")
	key(&m, "d")
	settle(t, &m, key(&m, "y"))
	if len(a.Store.Snapshot().Hostnames) != 0 || len(b.rules) != 1 {
		t.Fatal("hostname removal deleted shared redirect")
	}
	pageKey(t, &m, "1")
	key(&m, "d")
	settle(t, &m, key(&m, "y"))
	if len(b.rules) != 0 || len(a.Store.Snapshot().Rules) != 0 {
		t.Fatal("redirect deletion did not persist")
	}
}

func TestDNSWorkflowSaveFailureAndUnavailableAddress(t *testing.T) {
	m, a, _ := testModel(t)
	pageKey(t, &m, "2")
	m.addresses = []app.LANAddress{{IP: "192.168.1.20", Interface: "Ethernet"}}
	key(&m, "e")
	key(&m, "enter")
	key(&m, "down")
	settle(t, &m, key(&m, "enter"))
	if m.statusError || a.Store.Snapshot().DNS.ListenIP != "192.168.1.20" || a.Status().DNS.Running {
		t.Fatal("disabled DNS settings not saved")
	}
	// A saved unavailable address can be retained while disabling DNS, but cannot
	// be enabled accidentally. No real listener or firewall is touched by tests.
	m.addresses = nil
	key(&m, "e")
	key(&m, " ")
	key(&m, "enter")
	if cmd := key(&m, "enter"); cmd != nil || m.dnsForm.err == "" {
		t.Fatal("enabled missing LAN address")
	}
	key(&m, "backspace")
	key(&m, " ")
	key(&m, "enter")
	settle(t, &m, key(&m, "enter"))
	if m.statusError {
		t.Fatal(m.statusMessage)
	}
	// Simulate an address disappearing between discovery and save. Loopback is
	// always rejected by the real application before it can bind port 53.
	m.addresses = []app.LANAddress{{IP: "127.0.0.1", Interface: "gone"}}
	key(&m, "e")
	key(&m, " ")
	key(&m, "enter")
	key(&m, "up")
	settle(t, &m, key(&m, "enter"))
	if !m.statusError || m.mode != modeEditingDNS || !m.dnsForm.settings.Enabled || m.dnsForm.settings.ListenIP != "127.0.0.1" {
		t.Fatal("DNS failure lost form state")
	}
	if a.Store.Snapshot().DNS.Enabled {
		t.Fatal("failed save persisted")
	}
	key(&m, "esc")
	if m.mode != modeList {
		t.Fatal("could not cancel after failure")
	}
}

func TestHostnameValidationAndEligibleRedirects(t *testing.T) {
	tcp := tuiRule()
	udp := tcp
	udp.Protocol = firewall.ProtocolUDP
	wildcard := tcp
	wildcard.MatchIP = net.IPv4zero
	iface := tcp
	iface.MatchIP = nil
	iface.MatchInterface = "eth0"
	public := tcp
	public.MatchIP = net.ParseIP("203.0.113.1")
	f := newHostnameForm([]firewall.RedirectRule{udp, wildcard, iface, public, tcp})
	if len(f.rules.Items()) != 1 {
		t.Fatal("offered invalid redirect for DNS")
	}
	f.input.SetValue("https://photos.example.com")
	if _, done, _ := f.Update(tea.KeyMsg{Type: tea.KeyEnter}); done || f.step != 0 || f.err == "" {
		t.Fatal("accepted a URL")
	}
	f.input.SetValue("Photos.Example.COM.")
	f.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if f.name() != "photos.example.com" || f.step != 1 {
		t.Fatal("hostname not normalized")
	}
	f.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	if f.step != 0 || f.input.Value() != "photos.example.com" {
		t.Fatal("back did not preserve input")
	}
}

func TestRedirectFailurePreservesForm(t *testing.T) {
	m, _, b := testModel(t)
	key(&m, "a")
	key(&m, "q") // q is text while editing, not quit.
	if m.addForm.descriptionInput.Value() != "q" {
		t.Fatal("q did not reach text input")
	}
	key(&m, "enter")
	key(&m, "enter")
	key(&m, "192.168.1.20")
	key(&m, "enter")
	key(&m, "443")
	key(&m, "enter")
	key(&m, "enter")
	updateModel(&m, peersLoadedMsg{peers: []tailscale.Peer{{ID: "proxy", Name: "proxy", Online: true, IPs: []net.IP{net.ParseIP("100.64.0.2")}}}})
	key(&m, "enter")
	key(&m, "443")
	b.fail = true
	settle(t, &m, key(&m, "enter"))
	if !m.statusError || m.mode != modeAdding || m.addForm.targetPortInput.Value() != "443" || m.addForm.description != "q" {
		t.Fatal("failed rule discarded input")
	}
	b.fail = false
	settle(t, &m, key(&m, "enter"))
	if m.statusError || len(b.rules) != 1 || m.mode != modeList {
		t.Fatal("retry failed", m.statusMessage)
	}
}

func TestChecksCancellationAndStaleRefresh(t *testing.T) {
	m, _, _ := testModel(t)
	pageKey(t, &m, "4")
	first := key(&m, "enter")
	if first == nil || !m.checking {
		t.Fatal("checks did not start asynchronously")
	}
	if key(&m, "enter") != nil {
		t.Fatal("duplicate checks launched")
	}
	key(&m, "c")
	second := key(&m, "enter")
	old := first()
	updateModel(&m, old)
	if !m.checking {
		t.Fatal("canceled results replaced newer run")
	}
	settle(t, &m, second)
	if m.checking || len(m.checks) < 3 || m.checkedAt.IsZero() {
		t.Fatal("check results missing")
	}
	stale := m.refresh()()
	mutation := m.mutate("Saved", func() error { return nil })
	updateModel(&m, stale)
	if !m.busy {
		t.Fatal("old refresh interrupted mutation")
	}
	settle(t, &m, mutation)
	if !m.checkedAt.IsZero() || len(m.checks) != 0 {
		t.Fatal("configuration change kept stale diagnostics")
	}
	key(&m, "ctrl+c")
	if m.ctx.Err() == nil {
		t.Fatal("quit did not cancel pending work")
	}
}

func TestPeerDetailsAndSelectionSurviveRefresh(t *testing.T) {
	a := tailscale.Peer{ID: "a", Name: "alpha", Online: true, Self: true, OS: "linux", DNSName: "alpha.example.ts.net.", IPs: []net.IP{net.ParseIP("100.64.0.1")}}
	b := tailscale.Peer{ID: "b", HostName: "beta", IsExitNode: true, OS: "windows", IPs: []net.IP{net.ParseIP("100.64.0.2")}}
	f := newAddRuleModel([]tailscale.Peer{a, b})
	f.peerList.Select(1)
	f.SetPeers([]tailscale.Peer{b, a})
	selected := f.peerList.SelectedItem().(peerItem)
	if selected.name != "beta" || !strings.Contains(selected.Title(), "offline") || !strings.Contains(selected.Description(), "windows") {
		t.Fatal("selection/metadata lost")
	}
	f.step = 5
	f.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if f.Result().TailscalePeer != "beta" {
		t.Fatal("display status leaked into saved peer label")
	}
	for _, text := range []string{"this machine", "online"} {
		if !strings.Contains((tailnetItem{peer: a}).Title(), text) {
			t.Fatal(text)
		}
	}
	if !strings.Contains(peerDetails(a), a.DNSName) {
		t.Fatal("full DNS name missing")
	}
}

// These captures are terminal cells, not browser pixels. Set TS_REDIR_TUI_CAPTURES
// to retain plain-text renders for manual inspection without launching a firewall.
func TestTerminalLayouts(t *testing.T) {
	for _, size := range [][2]int{{100, 30}, {80, 24}, {40, 16}, {32, 12}} {
		t.Run(fmt.Sprintf("%dx%d", size[0], size[1]), func(t *testing.T) {
			m, a, _ := testModel(t)
			if err := a.Manager.AddRedirectRule(tuiRule()); err != nil {
				t.Fatal(err)
			}
			settle(t, &m, m.refresh())
			addMapping(t, &m, "photos.example.com")
			m.status.DNS.Error = "An upstream server could not be reached; connect the LAN adapter and refresh."
			m.status.RestoreError = "An existing rule conflicts with a saved redirect."
			updateModel(&m, peersLoadedMsg{peers: []tailscale.Peer{{ID: "proxy", Name: "reverse-proxy", Online: true, OS: "linux", IPs: []net.IP{net.ParseIP("100.64.0.2")}}}})
			updateModel(&m, tea.WindowSizeMsg{Width: size[0], Height: size[1]})
			capture := func(name string) {
				m.clearStatus()
				t.Helper()
				m.resize()
				view := m.View()
				if lipgloss.Height(view) > size[1] {
					t.Fatalf("%s exceeds height: %d\n%s", name, lipgloss.Height(view), view)
				}
				for _, line := range strings.Split(view, "\n") {
					if ansi.StringWidth(line) > size[0] {
						t.Fatalf("%s exceeds width: %q", name, line)
					}
				}
				if dir := os.Getenv("TS_REDIR_TUI_CAPTURES"); dir != "" {
					if err := os.MkdirAll(dir, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%s-%dx%d.txt", name, size[0], size[1])), []byte(ansi.Strip(view)), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, p := range []page{pageRules, pageDNS, pageHostnames, pageChecks, pageTailnet} {
				m.page = p
				capture(pageNames[p])
			}
			m.mode = modeHelp
			capture("help")
			updateModel(&m, tea.KeyMsg{Type: tea.KeyPgDown})
			if size[0] >= 40 && size[1] >= 16 && m.details.YOffset == 0 {
				t.Fatal("help cannot scroll")
			}
			m.mode = modeList
			m.page = pageDNS
			f := newDNSForm(state.DNS{Enabled: true, ListenIP: "192.168.1.20"}, []app.LANAddress{{IP: "192.168.1.20", Interface: "enp1s0"}})
			m.dnsForm, m.mode = &f, modeEditingDNS
			capture("dns-enable")
			m.dnsForm.step = 1
			capture("dns-address")
			m.page = pageHostnames
			h := newHostnameForm(m.rules)
			h.input.SetValue("photos.example.com")
			m.hostnameForm, m.mode = &h, modeAddingHostname
			capture("hostname-name")
			h.step = 1
			capture("hostname-rule")
			m.page = pageRules
			r := newAddRuleModel(m.peers)
			m.addForm, m.mode = &r, modeAdding
			for step := 0; step <= 6; step++ {
				r.step = step
				capture(fmt.Sprintf("redirect-step-%d", step))
			}
			m.mode = modeConfirmDelete
			m.pendingDelete = &m.rules[0]
			capture("confirm-rule")
			m.page = pageHostnames
			m.mode = modeConfirmHostnameDelete
			m.pendingHostname = "photos.example.com"
			capture("confirm-hostname")
			m.mode = modeList
			m.page = pageChecks
			m.checkedAt = time.Now()
			m.checks = []app.Check{{Name: "DNS listener", Detail: "Disabled"}, {Name: "Saved redirects", OK: true, Detail: "1 saved redirect"}}
			capture("checks-result")
		})
	}
}

func TestSmallTerminalDoesNotAcceptHiddenActions(t *testing.T) {
	m, a, _ := testModel(t)
	if err := a.Manager.AddRedirectRule(tuiRule()); err != nil {
		t.Fatal(err)
	}
	settle(t, &m, m.refresh())
	key(&m, "d")
	updateModel(&m, tea.WindowSizeMsg{Width: 32, Height: 12})
	if cmd := key(&m, "y"); cmd != nil || m.busy {
		t.Fatal("accepted hidden delete confirmation")
	}
	if !strings.Contains(m.View(), "Enlarge terminal") {
		t.Fatal("missing resize guidance")
	}
}

func TestQuitWaitsForMutation(t *testing.T) {
	m, _, _ := testModel(t)
	cmd := m.mutate("Saved", func() error { return nil })
	if key(&m, "ctrl+c") != nil || !m.quitAfterSave || m.ctx.Err() != nil {
		t.Fatal("quit interrupted save")
	}
	quit := updateModel(&m, cmd())
	if quit == nil || m.ctx.Err() == nil {
		t.Fatal("save did not finish shutdown")
	}
	if _, ok := quit().(tea.QuitMsg); !ok {
		t.Fatal("did not quit after saving")
	}
}

func TestRefreshDoesNotOverwriteActiveDNSForm(t *testing.T) {
	m, _, _ := testModel(t)
	pageKey(t, &m, "2")
	key(&m, "e")
	key(&m, " ")
	settle(t, &m, m.refresh())
	if !m.dnsForm.settings.Enabled {
		t.Fatal("refresh overwrote unsaved input")
	}
}

func TestLongHostnameKeepsRedirectChoiceVisible(t *testing.T) {
	m, a, _ := testModel(t)
	if err := a.Manager.AddRedirectRule(tuiRule()); err != nil {
		t.Fatal(err)
	}
	pageKey(t, &m, "3")
	updateModel(&m, tea.WindowSizeMsg{Width: 40, Height: 16})
	key(&m, "a")
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	key(&m, name)
	key(&m, "enter")
	view := ansi.Strip(m.View())
	for _, endpoint := range []string{"192.168.1.20:443", "100.64.0.2:443"} {
		if !strings.Contains(view, endpoint) {
			t.Fatalf("selected endpoint %s is hidden:\n%s", endpoint, view)
		}
	}
	if m.hostnameForm.name() != name || m.hostnameForm.step != 1 {
		t.Fatal("display truncation altered hostname")
	}
	if dir := os.Getenv("TS_REDIR_TUI_CAPTURES"); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "hostname-long-40x16.txt"), []byte(view), 0600); err != nil {
			t.Fatal(err)
		}
	}
	settle(t, &m, key(&m, "enter"))
	if m.statusError || a.Store.Snapshot().Hostnames[0].Name != name {
		t.Fatal("long hostname was not saved intact")
	}
}

func TestReadOnlyViewsSupportHomeAndEnd(t *testing.T) {
	m, _, _ := testModel(t)
	updateModel(&m, tea.WindowSizeMsg{Width: 40, Height: 16})
	for _, mode := range []mode{modeHelp, modeDetails, modeRawStatus, modeList} {
		m.mode, m.page = mode, pageDNS
		m.detailText = strings.Repeat("Long detail\n", 80)
		m.rawStatus = m.detailText
		m.resize()
		updateModel(&m, tea.KeyMsg{Type: tea.KeyEnd})
		if !m.details.AtBottom() || m.details.YOffset == 0 {
			t.Fatalf("mode %d: End did not scroll", mode)
		}
		updateModel(&m, tea.KeyMsg{Type: tea.KeyHome})
		if m.details.YOffset != 0 {
			t.Fatalf("mode %d: Home did not return to top", mode)
		}
	}
}
