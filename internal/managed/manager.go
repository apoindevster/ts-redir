// Package managed adds durable ownership and restart reconciliation to firewall rules.
package managed

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/apoindevster/ts-redir/internal/firewall"
	"github.com/apoindevster/ts-redir/internal/state"
)

type Manager struct {
	mu      sync.Mutex
	backend firewall.Manager
	store   *state.Store
}

func New(backend firewall.Manager, store *state.Store) *Manager {
	return &Manager{backend: backend, store: store}
}
func (m *Manager) Close() error { return nil } // Runtime owns the backend and store.

func normalize(r firewall.RedirectRule) (firewall.RedirectRule, error) {
	r.Handle = 0
	if runtime.GOOS == "windows" {
		if r.MatchIP == nil {
			iface, err := net.InterfaceByName(r.MatchInterface)
			if err != nil {
				return r, err
			}
			addrs, err := iface.Addrs()
			if err != nil {
				return r, err
			}
			for _, a := range addrs {
				if ip, _, err := net.ParseCIDR(a.String()); err == nil && ip.To4() != nil {
					r.MatchIP = ip.To4()
					break
				}
			}
		}
		r.MatchInterface = ""
	}
	return r, firewall.ValidateRule(r)
}

func expand(r firewall.RedirectRule) []firewall.RedirectRule {
	if r.Protocol != firewall.ProtocolBoth {
		return []firewall.RedirectRule{r}
	}
	tcp, udp := r, r
	tcp.Protocol = firewall.ProtocolTCP
	udp.Protocol = firewall.ProtocolUDP
	return []firewall.RedirectRule{tcp, udp}
}

func overlaps(a, b firewall.RedirectRule) bool {
	return a.Protocol == b.Protocol && a.MatchPort == b.MatchPort &&
		(a.MatchIP == nil || b.MatchIP == nil || a.MatchIP.IsUnspecified() || b.MatchIP.IsUnspecified() || a.MatchIP.Equal(b.MatchIP)) &&
		(a.MatchInterface == "" || b.MatchInterface == "" || a.MatchInterface == b.MatchInterface)
}

func (m *Manager) ListRedirectRules() ([]firewall.RedirectRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rules, err := m.backend.ListRedirectRules()
	c := m.store.Snapshot()
	for i, r := range rules {
		if saved, ok := c.Rule(state.RuleID(r)); ok {
			rules[i].Description = saved.Description
			rules[i].TailscalePeer = saved.TailscalePeer
		}
	}
	return rules, err
}

func (m *Manager) RuleExists(r firewall.RedirectRule) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := normalize(r)
	if err != nil {
		return false, err
	}
	return m.backend.RuleExists(r)
}

func (m *Manager) AddRedirectRule(r firewall.RedirectRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := normalize(r)
	if err != nil {
		return err
	}
	live, err := m.backend.ListRedirectRules()
	if err != nil {
		return err
	}
	before := m.store.Snapshot()
	for _, part := range expand(r) {
		if before.DNS.Enabled && part.MatchPort == 53 && (part.MatchIP == nil || part.MatchIP.IsUnspecified() || part.MatchIP.Equal(net.ParseIP(before.DNS.ListenIP))) {
			return errors.New("port 53 is reserved by the DNS forwarder")
		}
		for _, old := range live {
			if overlaps(part, old) {
				return fmt.Errorf("%w: listener overlaps an existing redirect", firewall.ErrDuplicateRule)
			}
		}
		for _, old := range before.Rules {
			if overlaps(part, old) {
				return fmt.Errorf("%w: listener is already saved", firewall.ErrDuplicateRule)
			}
		}
	}
	// Write intent first; if the process stops after this write, startup restores it.
	if err := m.store.Update(func(c *state.Config) error { c.Rules = append(c.Rules, expand(r)...); return nil }); err != nil {
		return err
	}
	if err := m.backend.AddRedirectRule(r); err != nil {
		rollback := m.store.Update(func(c *state.Config) error { c.Rules = before.Rules; return nil })
		return errors.Join(err, rollback)
	}
	return nil
}

func (m *Manager) DeleteRedirectRule(handle uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	live, err := m.backend.ListRedirectRules()
	if err != nil {
		return err
	}
	var rule firewall.RedirectRule
	found := false
	for _, r := range live {
		if r.Handle == handle {
			rule = r
			found = true
			break
		}
	}
	if !found {
		return errors.New("redirect no longer exists; refresh the list")
	}
	id := state.RuleID(rule)
	before := m.store.Snapshot()
	for _, h := range before.Hostnames {
		if h.RuleID == id {
			return fmt.Errorf("remove hostname %s before deleting its redirect", h.Name)
		}
	}
	if err := m.store.Update(func(c *state.Config) error {
		kept := c.Rules[:0]
		for _, r := range c.Rules {
			if state.RuleID(r) != id {
				kept = append(kept, r)
			}
		}
		c.Rules = kept
		return nil
	}); err != nil {
		return err
	}
	if err := m.backend.DeleteRedirectRule(handle); err != nil {
		return errors.Join(err, m.store.Update(func(c *state.Config) error { c.Rules = before.Rules; return nil }))
	}
	return nil
}

// Reconcile restores only rules explicitly saved by this application. Existing
// portproxy entries are never silently adopted or replaced.
func (m *Manager) Reconcile() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	live, err := m.backend.ListRedirectRules()
	if err != nil {
		return err
	}
	var problems []error
	for _, saved := range m.store.Snapshot().Rules {
		r, err := normalize(saved)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		found, conflict := false, false
		for _, old := range live {
			if state.RuleID(old) == state.RuleID(r) {
				found = true
				break
			}
			if overlaps(old, r) {
				conflict = true
			}
		}
		if found {
			continue
		}
		if conflict {
			problems = append(problems, fmt.Errorf("saved listener %s:%d conflicts with an existing rule", r.MatchIP, r.MatchPort))
			continue
		}
		if err := m.backend.AddRedirectRule(r); err != nil {
			problems = append(problems, err)
		} else {
			live = append(live, r)
		}
	}
	return errors.Join(problems...)
}

func (m *Manager) AddHostname(name string, handle uint64) error {
	name, err := state.NormalizeHostname(name)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	live, err := m.backend.ListRedirectRules()
	if err != nil {
		return err
	}
	var rule firewall.RedirectRule
	found := false
	for _, r := range live {
		if r.Handle == handle {
			rule = r
			found = true
			break
		}
	}
	if !found {
		return errors.New("choose an existing redirect")
	}
	if rule.Protocol != firewall.ProtocolTCP || rule.MatchIP.To4() == nil || !rule.MatchIP.IsPrivate() {
		return errors.New("hostname mappings require a TCP redirect with a specific LAN IPv4 address")
	}
	rule.Handle = 0
	return m.store.Update(func(c *state.Config) error {
		for _, h := range c.Hostnames {
			if h.Name == name {
				return errors.New("hostname already configured; remove it before changing its destination")
			}
		}
		id := state.RuleID(rule)
		if _, ok := c.Rule(id); !ok {
			c.Rules = append(c.Rules, rule)
		}
		c.Hostnames = append(c.Hostnames, state.Hostname{Name: name, RuleID: id})
		return nil
	})
}

func (m *Manager) DeleteHostname(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.Update(func(c *state.Config) error {
		for i, h := range c.Hostnames {
			if h.Name == name {
				c.Hostnames = append(c.Hostnames[:i], c.Hostnames[i+1:]...)
				return nil
			}
		}
		return errors.New("hostname not found")
	})
}
