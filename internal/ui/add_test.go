package ui

import (
	"runtime"
	"strings"
	"testing"

	"github.com/apoindevster/ts-redir/internal/firewall"
	tea "github.com/charmbracelet/bubbletea"
)

func TestProtocolSelection(t *testing.T) {
	m := newAddRuleModel(nil)
	m.step = 4
	want := []firewall.Protocol{firewall.ProtocolTCP, firewall.ProtocolUDP, firewall.ProtocolBoth}
	if runtime.GOOS == "windows" {
		want = []firewall.Protocol{firewall.ProtocolTCP}
	}
	for _, protocol := range want {
		if got := m.Result().Protocol; got != protocol {
			t.Fatalf("selected %s; want %s", got, protocol)
		}
		if !strings.Contains(m.View(), protocol.Label()) {
			t.Fatalf("missing label for %s", protocol)
		}
		m.Update(tea.KeyMsg{Type: tea.KeyTab})
	}
	if m.Result().Protocol != firewall.ProtocolTCP {
		t.Fatal("selection did not wrap to TCP")
	}
	m.Update(tea.KeyMsg{Type: tea.KeyLeft})
	if m.Result().Protocol != want[len(want)-1] {
		t.Fatal("reverse navigation did not wrap")
	}
	if runtime.GOOS == "windows" && (strings.Contains(m.View(), "UDP") || !strings.Contains(m.View(), "TCP only")) {
		t.Fatal("Windows exposes unsupported protocols")
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.step != 5 {
		t.Fatal("protocol selection did not advance to peers")
	}
}
