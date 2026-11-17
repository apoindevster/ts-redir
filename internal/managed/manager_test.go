package managed

import (
	"errors"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/apoindevster/ts-redir/internal/firewall"
	"github.com/apoindevster/ts-redir/internal/state"
)

type memoryFirewall struct {
	rules []firewall.RedirectRule
	next  uint64
	fail  bool
}

func (b *memoryFirewall) ListRedirectRules() ([]firewall.RedirectRule, error) {
	return append([]firewall.RedirectRule{}, b.rules...), nil
}
func (b *memoryFirewall) RuleExists(r firewall.RedirectRule) (bool, error) {
	for _, old := range b.rules {
		if state.RuleID(old) == state.RuleID(r) {
			return true, nil
		}
	}
	return false, nil
}
func (b *memoryFirewall) AddRedirectRule(r firewall.RedirectRule) error {
	if b.fail {
		return errors.New("backend failure")
	}
	for _, part := range expand(r) {
		b.next++
		part.Handle = b.next
		b.rules = append(b.rules, part)
	}
	return nil
}
func (b *memoryFirewall) DeleteRedirectRule(handle uint64) error {
	if b.fail {
		return errors.New("backend failure")
	}
	for i, r := range b.rules {
		if r.Handle == handle {
			b.rules = append(b.rules[:i], b.rules[i+1:]...)
			return nil
		}
	}
	return errors.New("missing rule")
}
func (b *memoryFirewall) Close() error { return nil }
func testRule() firewall.RedirectRule {
	return firewall.RedirectRule{Protocol: firewall.ProtocolTCP, MatchIP: net.ParseIP("192.168.1.20"), MatchPort: 443, TargetIP: net.ParseIP("100.64.0.2"), TargetPort: 443}
}
func newTestManager(t *testing.T) (*Manager, *memoryFirewall, *state.Store) {
	t.Helper()
	s, err := state.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	b := &memoryFirewall{}
	return New(b, s), b, s
}

func TestRestoreSharedHostnamesAndDeletion(t *testing.T) {
	m, b, s := newTestManager(t)
	if err := m.AddRedirectRule(testRule()); err != nil {
		t.Fatal(err)
	}
	handle := b.rules[0].Handle
	for _, name := range []string{"photos.example.com", "files.example.com"} {
		if err := m.AddHostname(name, handle); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.Snapshot().Rules) != 1 {
		t.Fatal("hostnames duplicated forwarding rule")
	}
	b.rules = nil
	if err := m.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if len(b.rules) != 1 || b.rules[0].Handle == handle {
		t.Fatal("rule not restored with new handle")
	}
	if err := m.Reconcile(); err != nil || len(b.rules) != 1 {
		t.Fatal("restore is not idempotent")
	}
	if err := m.DeleteRedirectRule(b.rules[0].Handle); err == nil {
		t.Fatal("deleted referenced rule")
	}
	for _, name := range []string{"photos.example.com", "files.example.com"} {
		if err := m.DeleteHostname(name); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.DeleteRedirectRule(b.rules[0].Handle); err != nil {
		t.Fatal(err)
	}
	if len(s.Snapshot().Rules) != 0 || len(b.rules) != 0 {
		t.Fatal("deletion did not persist")
	}
}

func TestBackendFailureRollsBackIntent(t *testing.T) {
	m, b, s := newTestManager(t)
	b.fail = true
	if err := m.AddRedirectRule(testRule()); err == nil {
		t.Fatal("failure ignored")
	}
	if len(s.Snapshot().Rules) != 0 {
		t.Fatal("failed add persisted")
	}
	b.fail = false
	if err := m.AddRedirectRule(testRule()); err != nil {
		t.Fatal(err)
	}
	b.fail = true
	if err := m.DeleteRedirectRule(b.rules[0].Handle); err == nil {
		t.Fatal("failure ignored")
	}
	if len(s.Snapshot().Rules) != 1 {
		t.Fatal("failed deletion lost intent")
	}
}

func TestListenerConflictsDoNotOverwriteExistingRules(t *testing.T) {
	m, b, s := newTestManager(t)
	existing := testRule()
	existing.TargetIP = net.ParseIP("100.64.0.8")
	b.AddRedirectRule(existing)
	if err := m.AddRedirectRule(testRule()); !errors.Is(err, firewall.ErrDuplicateRule) {
		t.Fatal(err)
	}
	if len(s.Snapshot().Rules) != 0 {
		t.Fatal("conflict saved")
	}
	if err := s.Update(func(c *state.Config) error { c.Rules = []firewall.RedirectRule{testRule()}; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := m.Reconcile(); err == nil {
		t.Fatal("restore ignored collision")
	}
	if len(b.rules) != 1 || !b.rules[0].TargetIP.Equal(existing.TargetIP) {
		t.Fatal("existing rule overwritten")
	}
}

func TestBothIsPersistedAsIndependentlyDeletableRules(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows intentionally TCP only")
	}
	m, b, s := newTestManager(t)
	r := testRule()
	r.Protocol = firewall.ProtocolBoth
	if err := m.AddRedirectRule(r); err != nil {
		t.Fatal(err)
	}
	if len(s.Snapshot().Rules) != 2 {
		t.Fatal("both not expanded")
	}
	if err := m.DeleteRedirectRule(b.rules[1].Handle); err != nil {
		t.Fatal(err)
	}
	b.rules = nil
	if err := m.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if len(b.rules) != 1 || b.rules[0].Protocol != firewall.ProtocolTCP {
		t.Fatal("deleted UDP rule resurrected")
	}
}
