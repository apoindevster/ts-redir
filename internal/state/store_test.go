package state

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/apoindevster/ts-redir/internal/firewall"
)

func TestDurabilityAndExclusiveOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := Open(path); err == nil {
		second.Close()
		t.Fatal("two instances acquired the same configuration")
	}
	rule := firewall.RedirectRule{Protocol: firewall.ProtocolTCP, MatchIP: net.ParseIP("192.168.1.2"), MatchPort: 443, TargetIP: net.ParseIP("100.64.0.2"), TargetPort: 443}
	if err := s.Update(func(c *Config) error {
		c.Rules = []firewall.RedirectRule{rule}
		c.Hostnames = []Hostname{{"photos.example.com", RuleID(rule)}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	snapshot := s.Snapshot()
	snapshot.Rules[0].MatchIP[0] ^= 255
	if !s.Snapshot().Rules[0].MatchIP.Equal(rule.MatchIP) {
		t.Fatal("snapshot aliases stored IP")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if !restored.Snapshot().Answers()["photos.example.com."].Equal(rule.MatchIP) {
		t.Fatal("mapping lost on restart")
	}
}

func TestFailedSaveDoesNotChangeMemory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(c *Config) error { c.DNS = DNS{Enabled: true, ListenIP: "192.168.1.2"}; return nil }); err == nil {
		t.Fatal("expected disk error")
	}
	if s.Snapshot().DNS.Enabled {
		t.Fatal("failed update changed live configuration")
	}
}

func TestInvalidConfigIsNotOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	for _, data := range []string{"broken", `{"version":99}`, `{"version":1,"hostnames":[{"name":"photos.example.com","rule_id":"missing"}]}`, `{"version":1,"dns":{"enabled":true,"listen_ip":"0.0.0.0"}}`} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if s, err := Open(path); err == nil {
			s.Close()
			t.Fatal("invalid config accepted")
		}
		got, _ := os.ReadFile(path)
		if string(got) != data {
			t.Fatal("invalid config overwritten")
		}
	}
}

func TestHostnameValidation(t *testing.T) {
	name, err := NormalizeHostname(" Photos.Example.COM. ")
	if err != nil || name != "photos.example.com" {
		t.Fatalf("%s %v", name, err)
	}
	for _, bad := range []string{"", "localhost", "https://example.com", "a.example.com:443", "*.example.com", "a..example.com", "-a.example.com", "127.0.0.1", "a/b.example.com", "a_1.example.com"} {
		if _, err := NormalizeHostname(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
