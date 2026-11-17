// Package state owns the durable configuration shared by the DNS and firewall services.
package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/apoindevster/ts-redir/internal/firewall"
)

type DNS struct {
	Enabled  bool   `json:"enabled"`
	ListenIP string `json:"listen_ip"`
}

type Hostname struct {
	Name   string `json:"name"`
	RuleID string `json:"rule_id"`
}

type Config struct {
	Version   int                     `json:"version"`
	DNS       DNS                     `json:"dns"`
	Rules     []firewall.RedirectRule `json:"rules"`
	Hostnames []Hostname              `json:"hostnames"`
}

type Store struct {
	mu     sync.RWMutex
	path   string
	config Config
	lock   *os.File
}

func DefaultPath() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "ts-redir", "config.json")
	}
	return "/etc/ts-redir/config.json"
}

func Open(path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		return nil, err
	}
	lock, err := lockFile(abs + ".lock")
	if err != nil {
		return nil, fmt.Errorf("configuration already in use or inaccessible: %w", err)
	}
	s := &Store{path: abs, lock: lock, config: Config{Version: 1}}
	data, err := os.ReadFile(abs)
	if err == nil {
		err = json.Unmarshal(data, &s.config)
		if err == nil {
			err = s.config.validate()
		}
	} else if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	return s, nil
}

func (s *Store) Path() string { return s.path }
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}

func clone(c Config) Config {
	// net.IP is a slice too; callers must never share mutable state.
	b, _ := json.Marshal(c)
	var out Config
	_ = json.Unmarshal(b, &out)
	return out
}

func (s *Store) Snapshot() Config { s.mu.RLock(); defer s.mu.RUnlock(); return clone(s.config) }

// Answers avoids serializing the entire configuration for every DNS query.
func (s *Store) Answers() map[string]net.IP {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.Answers()
}

func (s *Store) Update(change func(*Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return errors.New("configuration store is closed")
	}
	c := clone(s.config)
	if err := change(&c); err != nil {
		return err
	}
	if err := c.validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".ts-redir-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(data, '\n')); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), s.path)
	}
	if err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	s.config = c
	return nil
}

// RuleID is independent of OS-assigned handles, descriptions and peer labels.
func RuleID(r firewall.RedirectRule) string {
	key := fmt.Sprintf("%s|%s|%s|%d|%s|%d", r.Protocol, r.MatchInterface, r.MatchIP, r.MatchPort, r.TargetIP, r.TargetPort)
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:12])
}

func (c Config) Rule(id string) (firewall.RedirectRule, bool) {
	for _, r := range c.Rules {
		if RuleID(r) == id {
			return r, true
		}
	}
	return firewall.RedirectRule{}, false
}

func (c Config) Answers() map[string]net.IP {
	out := make(map[string]net.IP)
	rules := make(map[string]firewall.RedirectRule, len(c.Rules))
	for _, r := range c.Rules {
		rules[RuleID(r)] = r
	}
	for _, h := range c.Hostnames {
		if r, ok := rules[h.RuleID]; ok && r.MatchIP.To4() != nil {
			out[h.Name+"."] = append(net.IP(nil), r.MatchIP.To4()...)
		}
	}
	return out
}

// Validate durable intent without requiring interfaces to be available at boot.
func (c Config) validate() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported configuration version %d", c.Version)
	}
	if c.DNS.Enabled || c.DNS.ListenIP != "" {
		ip := net.ParseIP(c.DNS.ListenIP)
		if ip.To4() == nil || !ip.IsPrivate() {
			return errors.New("DNS requires a private LAN IPv4 address")
		}
	}
	seenRules := map[string]bool{}
	for _, r := range c.Rules {
		if err := firewall.ValidateRule(r); err != nil {
			return fmt.Errorf("invalid saved redirect: %w", err)
		}
		if r.Protocol == firewall.ProtocolBoth || seenRules[RuleID(r)] {
			return errors.New("saved redirects must be unique individual TCP or UDP rules")
		}
		seenRules[RuleID(r)] = true
		if c.DNS.Enabled && r.MatchPort == 53 && (r.MatchIP == nil || r.MatchIP.IsUnspecified() || r.MatchIP.Equal(net.ParseIP(c.DNS.ListenIP))) {
			return errors.New("saved port 53 redirect conflicts with the DNS listener")
		}
	}
	if len(c.Hostnames) > 256 {
		return errors.New("maximum of 256 hostnames reached")
	}
	seenNames := map[string]bool{}
	for _, h := range c.Hostnames {
		name, err := NormalizeHostname(h.Name)
		if err != nil || name != h.Name || seenNames[name] {
			return fmt.Errorf("invalid or duplicate saved hostname %q", h.Name)
		}
		seenNames[name] = true
		r, ok := c.Rule(h.RuleID)
		if !ok || r.Protocol != firewall.ProtocolTCP || r.MatchIP.To4() == nil || !r.MatchIP.IsPrivate() {
			return fmt.Errorf("hostname %s requires a saved TCP redirect on a private LAN IPv4 address", name)
		}
	}
	return nil
}

func NormalizeHostname(name string) (string, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if len(name) > 253 || !strings.Contains(name, ".") || net.ParseIP(name) != nil || strings.ContainsAny(name, ":/*") {
		return "", errors.New("enter a full DNS hostname, without a URL, port or wildcard")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS hostname")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", errors.New("use ASCII DNS names (punycode for international names)")
			}
		}
	}
	return name, nil
}
