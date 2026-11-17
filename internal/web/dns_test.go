package web

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apoindevster/ts-redir/internal/app"
	"github.com/apoindevster/ts-redir/internal/dnsforward"
	"github.com/apoindevster/ts-redir/internal/firewall"
	"github.com/apoindevster/ts-redir/internal/state"
)

type dnsTestBackend struct {
	mu    sync.Mutex
	rules []firewall.RedirectRule
	next  uint64
}

func (b *dnsTestBackend) ListRedirectRules() ([]firewall.RedirectRule, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]firewall.RedirectRule{}, b.rules...), nil
}
func (b *dnsTestBackend) RuleExists(r firewall.RedirectRule) (bool, error) {
	rules, _ := b.ListRedirectRules()
	for _, old := range rules {
		if state.RuleID(old) == state.RuleID(r) {
			return true, nil
		}
	}
	return false, nil
}
func (b *dnsTestBackend) AddRedirectRule(r firewall.RedirectRule) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next++
	r.Handle = b.next
	b.rules = append(b.rules, r)
	return nil
}
func (b *dnsTestBackend) DeleteRedirectRule(handle uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, r := range b.rules {
		if r.Handle == handle {
			b.rules = append(b.rules[:i], b.rules[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("missing redirect")
}
func (b *dnsTestBackend) Close() error { return nil }

func dnsTestServer(t *testing.T) (*Server, *app.App, *dnsTestBackend) {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	backend := &dnsTestBackend{next: 18446744073709551000}
	application := app.New(store, backend)
	t.Cleanup(func() { application.Close() })
	server, err := NewServer(application.Manager, "tailscale0", 0)
	if err != nil {
		t.Fatal(err)
	}
	server.SetApplication(application)
	return server, application, backend
}
func apiRequest(s *Server, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
	return w
}
func addDNSRedirect(t *testing.T, s *Server) apiRule {
	t.Helper()
	w := apiRequest(s, "POST", "/api/rules", `{"protocol":"tcp","match_ip":"192.168.1.20","match_port":443,"target_ip":"100.64.0.2","target_port":443,"description":"Shared HTTPS","tailscale_peer":"reverse-proxy"}`)
	var rules []apiRule
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &rules) != nil || len(rules) != 1 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	return rules[0]
}

func TestHostnameAPIPreservesLargeHandlesAndSharedRedirect(t *testing.T) {
	s, application, _ := dnsTestServer(t)
	rule := addDNSRedirect(t, s)
	if rule.HandleID != "18446744073709551001" {
		t.Fatalf("handle lost precision: %q", rule.HandleID)
	}
	for _, name := range []string{"Photos.Example.COM.", "files.example.com"} {
		w := apiRequest(s, "POST", "/api/hostnames", fmt.Sprintf(`{"hostname":%q,"rule_handle":%q}`, name, rule.HandleID))
		if w.Code != http.StatusCreated || w.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("hostname: %d %s", w.Code, w.Body)
		}
	}
	if len(application.Store.Snapshot().Rules) != 1 {
		t.Fatal("shared hostname created extra redirect")
	}
	w := apiRequest(s, "GET", "/api/dns", "")
	if !strings.Contains(w.Body.String(), `"name":"photos.example.com"`) || !strings.Contains(w.Body.String(), `"address":"192.168.1.20"`) {
		t.Fatal(w.Body.String())
	}
	for _, body := range []string{
		`{"hostname":"https://invalid.example","rule_handle":"18446744073709551001"}`,
		`{"hostname":"photos.example.com","rule_handle":"18446744073709551001"}`,
		`{"hostname":"new.example.com","rule_handle":"3"}`,
		`{"hostname":"new.example.com","rule_handle":18446744073709551001}`,
	} {
		if w := apiRequest(s, "POST", "/api/hostnames", body); w.Code != http.StatusBadRequest {
			t.Fatalf("accepted %s", body)
		}
	}
	if w := apiRequest(s, "DELETE", "/api/rules/"+rule.HandleID, ""); w.Code != http.StatusBadRequest {
		t.Fatal("removed referenced rule")
	}
	for _, name := range []string{"photos.example.com", "files.example.com"} {
		if w := apiRequest(s, "DELETE", "/api/hostnames/"+name, ""); w.Code != http.StatusNoContent {
			t.Fatal(w.Body.String())
		}
	}
	if len(application.Store.Snapshot().Rules) != 1 {
		t.Fatal("removing names removed the shared rule")
	}
	if w := apiRequest(s, "DELETE", "/api/rules/"+rule.HandleID, ""); w.Code != http.StatusNoContent {
		t.Fatal(w.Body.String())
	}
	if len(application.Store.Snapshot().Rules) != 0 {
		t.Fatal("deleted redirect still saved")
	}
}

func TestDNSAPIValidationLeavesConfigurationUnchanged(t *testing.T) {
	s, application, _ := dnsTestServer(t)
	for _, address := range []string{"0.0.0.0", "127.0.0.1", "::1", "203.0.113.1", "not-an-ip"} {
		w := apiRequest(s, "PUT", "/api/dns", fmt.Sprintf(`{"enabled":true,"listen_ip":%q}`, address))
		if w.Code != http.StatusBadRequest || application.Store.Snapshot().DNS.Enabled {
			t.Fatalf("accepted %q: %s", address, w.Body)
		}
	}
	if w := apiRequest(s, "PUT", "/api/dns", `{"enabled":false,"listen_ip":"192.168.1.20"}`); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	if application.Status().DNS.Running {
		t.Fatal("disabled setting started a listener")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest("POST", "/api/diagnostics", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, req)
	var checks []app.Check
	if json.Unmarshal(w.Body.Bytes(), &checks) != nil || len(checks) < 3 || checks[0].OK {
		t.Fatalf("invalid diagnostics: %s", w.Body)
	}
}

func TestApplicationRestartRestoresHostnameTarget(t *testing.T) {
	s, application, backend := dnsTestServer(t)
	rule := addDNSRedirect(t, s)
	w := apiRequest(s, "POST", "/api/hostnames", fmt.Sprintf(`{"hostname":"photos.example.com","rule_handle":%q}`, rule.HandleID))
	if w.Code != http.StatusCreated {
		t.Fatal(w.Body.String())
	}
	path := application.Store.Path()
	application.Close()
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	restored := app.New(store, &dnsTestBackend{})
	defer restored.Close()
	restored.Start()
	live, err := restored.Manager.ListRedirectRules()
	if err != nil || len(live) != 1 || live[0].Handle == backend.rules[0].Handle {
		t.Fatalf("not restored: %+v %v", live, err)
	}
	if !store.Snapshot().Answers()["photos.example.com."].Equal(net.ParseIP("192.168.1.20")) {
		t.Fatal("mapping lost after restart")
	}
	if err := restored.Manager.DeleteRedirectRule(live[0].Handle); err == nil {
		t.Fatal("new OS handle bypassed mapping protection")
	}
}

func TestDNSListenerCannotTakeOverPort53Redirect(t *testing.T) {
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil || ip.To4() == nil || !ip.IsPrivate() {
				continue
			}
			for _, matchIP := range []net.IP{ip, net.IPv4zero, nil} {
				t.Run(fmt.Sprint(matchIP), func(t *testing.T) {
					s, application, backend := dnsTestServer(t)
					backend.AddRedirectRule(firewall.RedirectRule{Protocol: firewall.ProtocolTCP, MatchIP: matchIP, MatchInterface: iface.Name, MatchPort: 53, TargetIP: net.ParseIP("100.64.0.2"), TargetPort: 53})
					w := apiRequest(s, "PUT", "/api/dns", fmt.Sprintf(`{"enabled":true,"listen_ip":%q}`, ip.String()))
					if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "conflicts") || application.Store.Snapshot().DNS.Enabled {
						t.Fatalf("conflict accepted: %s", w.Body)
					}
					// The same conflict can appear after settings were saved, before reboot.
					// Startup must reject it before binding any real DNS sockets.
					if err := application.Store.Update(func(c *state.Config) error { c.DNS = state.DNS{Enabled: true, ListenIP: ip.String()}; return nil }); err != nil {
						t.Fatal(err)
					}
					application.Start()
					status := application.Status()
					if status.DNS.Running || !strings.Contains(status.DNS.Error, "conflicts") {
						t.Fatalf("startup ignored conflict: %+v", status)
					}
				})
			}
			return
		}
	}
	t.Skip("no private LAN address available")
}

func TestHTTPSDiagnosticsUseHostnameAndRejectUntrustedCertificate(t *testing.T) {
	_, application, _ := dnsTestServer(t)
	names := make(chan string, 1)
	destination := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	destination.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		names <- hello.ServerName
		return nil, nil
	}}
	destination.StartTLS()
	defer destination.Close()
	ip, port, _ := net.SplitHostPort(destination.Listener.Addr().String())
	targetPort, _ := strconv.Atoi(port)
	rule := firewall.RedirectRule{Protocol: firewall.ProtocolTCP, MatchIP: net.ParseIP("192.168.1.20"), MatchPort: 443, TargetIP: net.ParseIP(ip), TargetPort: uint16(targetPort)}
	if err := application.Manager.AddRedirectRule(rule); err != nil {
		t.Fatal(err)
	}
	live, _ := application.Manager.ListRedirectRules()
	if err := application.Manager.AddHostname("photos.example.com", live[0].Handle); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	checks := application.Diagnose(ctx)
	select {
	case name := <-names:
		if name != "photos.example.com" {
			t.Fatalf("incorrect TLS SNI %q", name)
		}
	default:
		t.Fatal("did not send TLS SNI to destination")
	}
	for _, check := range checks {
		if check.Name == "photos.example.com HTTPS destination" {
			if check.OK || !strings.Contains(check.Detail, "certificate") {
				t.Fatalf("certificate validation bypassed: %+v", check)
			}
			return
		}
	}
	t.Fatal("missing TLS diagnostic")
}

func TestUnavailableLANAtStartupKeepsManagementAndRestorationAvailable(t *testing.T) {
	s, application, backend := dnsTestServer(t)
	rule := addDNSRedirect(t, s)
	unavailable := "192.168.255.254"
	if dnsforward.ValidateListenIP(unavailable) == nil {
		t.Skip("test address is assigned to this machine")
	}
	if err := application.Store.Update(func(c *state.Config) error { c.DNS = state.DNS{Enabled: true, ListenIP: unavailable}; return nil }); err != nil {
		t.Fatal(err)
	}
	backend.DeleteRedirectRule(rule.Handle)
	application.Start()
	status := application.Status()
	if status.DNS.Running || status.DNS.Error == "" || status.RestoreError != "" {
		t.Fatalf("unexpected boot status: %+v", status)
	}
	if live, _ := application.Manager.ListRedirectRules(); len(live) != 1 {
		t.Fatal("DNS failure prevented rule restoration")
	}
	if w := apiRequest(s, "GET", "/api/dns", ""); w.Code != http.StatusOK {
		t.Fatal("management inaccessible after DNS failure")
	}
}
