package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/apoindevster/ts-redir/internal/firewall"
)

type testManager struct {
	added  []firewall.RedirectRule
	rules  []firewall.RedirectRule
	exists bool
	addErr error
	checks int
}

func (m *testManager) ListRedirectRules() ([]firewall.RedirectRule, error) { return m.rules, nil }
func (m *testManager) RuleExists(firewall.RedirectRule) (bool, error) {
	m.checks++
	return m.exists, nil
}
func (m *testManager) AddRedirectRule(rule firewall.RedirectRule) error {
	m.added = append(m.added, rule)
	return m.addErr
}
func (m *testManager) DeleteRedirectRule(uint64) error { return nil }
func (m *testManager) Close() error                    { return nil }

func TestIndexOffersOnlySupportedProtocols(t *testing.T) {
	s, err := NewServer(&testManager{}, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleIndex(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("index: %s", w.Body.String())
	}
	for _, protocol := range []string{"tcp", "udp", "both"} {
		present := strings.Contains(w.Body.String(), `value="`+protocol+`"`)
		want := runtime.GOOS != "windows" || protocol == "tcp"
		if present != want {
			t.Fatalf("option %s: present=%v, want %v", protocol, present, want)
		}
	}
	if runtime.GOOS == "windows" && !strings.Contains(w.Body.String(), "Windows supports TCP only.") {
		t.Fatal("missing Windows explanation")
	}
}

func TestCreateRuleProtocolValidation(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp", "both", "icmp", "", " BOTH "} {
		t.Run(protocol, func(t *testing.T) {
			mgr := &testManager{}
			s, err := NewServer(mgr, "", 0)
			if err != nil {
				t.Fatal(err)
			}
			body := fmt.Sprintf(`{"protocol":%q,"match_ip":"192.0.2.10","match_port":8080,"target_ip":"100.64.0.2","target_port":80}`, protocol)
			w := httptest.NewRecorder()
			s.handleRules(w, httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(body)))
			normalized := strings.ToLower(strings.TrimSpace(protocol))
			allowed := normalized == "tcp" || (runtime.GOOS != "windows" && (normalized == "udp" || normalized == "both"))
			if !allowed {
				if w.Code != http.StatusBadRequest || mgr.checks != 0 || len(mgr.added) != 0 {
					t.Fatalf("unsupported protocol reached firewall: status=%d, checks=%d, adds=%d", w.Code, mgr.checks, len(mgr.added))
				}
				return
			}
			if w.Code != http.StatusCreated || len(mgr.added) != 1 || string(mgr.added[0].Protocol) != normalized {
				t.Fatalf("unexpected create result: status=%d, adds=%+v, body=%s", w.Code, mgr.added, w.Body.String())
			}
			if w.Header().Get("Content-Type") != "application/json" {
				t.Fatal("created response is not JSON")
			}
		})
	}
}

func TestBothReturnsSeparateRules(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows rejects combined requests")
	}
	mgr := &testManager{rules: []firewall.RedirectRule{
		{Handle: 1, Protocol: firewall.ProtocolTCP, TargetIP: net.ParseIP("100.64.0.2")},
		{Handle: 2, Protocol: firewall.ProtocolUDP, TargetIP: net.ParseIP("100.64.0.2")},
	}}
	s, err := NewServer(mgr, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleRules(w, httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(`{"protocol":"both","match_ip":"192.0.2.10","match_port":8080,"target_ip":"100.64.0.2","target_port":80}`)))
	var rules []apiRule
	if err := json.Unmarshal(w.Body.Bytes(), &rules); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusCreated || len(rules) != 2 || rules[0].Protocol != "tcp" || rules[1].Protocol != "udp" {
		t.Fatalf("unexpected response: %s", w.Body.String())
	}
}

func TestDuplicateReturnsConflict(t *testing.T) {
	for _, preexisting := range []bool{true, false} {
		mgr := &testManager{exists: preexisting, addErr: firewall.ErrDuplicateRule}
		s, err := NewServer(mgr, "", 0)
		if err != nil {
			t.Fatal(err)
		}
		protocol := "both"
		if runtime.GOOS == "windows" {
			protocol = "tcp"
		}
		w := httptest.NewRecorder()
		body := fmt.Sprintf(`{"protocol":%q,"match_ip":"192.0.2.10","match_port":8080,"target_ip":"100.64.0.2","target_port":80}`, protocol)
		s.handleRules(w, httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(body)))
		if w.Code != http.StatusConflict {
			t.Fatalf("duplicate status: %d", w.Code)
		}
		if preexisting && len(mgr.added) != 0 {
			t.Fatal("known duplicate reached creation")
		}
	}
}
