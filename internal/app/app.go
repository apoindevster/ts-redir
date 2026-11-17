package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/apoindevster/ts-redir/internal/dnsforward"
	"github.com/apoindevster/ts-redir/internal/firewall"
	"github.com/apoindevster/ts-redir/internal/managed"
	"github.com/apoindevster/ts-redir/internal/state"
	"github.com/miekg/dns"
)

type App struct {
	mu           sync.Mutex
	Store        *state.Store
	Manager      *managed.Manager
	backend      firewall.Manager
	dns          *dnsforward.Server
	dnsError     string
	restoreError string
}

type Status struct {
	ConfigPath   string            `json:"config_path"`
	DNS          dnsforward.Status `json:"dns"`
	RestoreError string            `json:"restore_error,omitempty"`
	SavedRules   int               `json:"saved_rules"`
}

func Open(path string) (*App, error) {
	store, err := state.Open(path)
	if err != nil {
		return nil, err
	}
	backend, err := firewall.NewManager()
	if err != nil {
		store.Close()
		return nil, err
	}
	a := New(store, backend)
	return a, nil
}

func New(store *state.Store, backend firewall.Manager) *App {
	return &App{Store: store, backend: backend, Manager: managed.New(backend, store)}
}

func (a *App) Start() {
	a.Reconcile()
	a.mu.Lock()
	defer a.mu.Unlock()
	settings := a.Store.Snapshot().DNS
	if settings.Enabled {
		if err := a.startDNS(settings); err != nil {
			a.dnsError = err.Error()
		}
	}
}

func (a *App) newDNS() *dnsforward.Server {
	return dnsforward.New(a.Store.Answers)
}

func (a *App) startDNS(settings state.DNS) error {
	if err := a.validateDNSListener(settings.ListenIP); err != nil {
		return err
	}
	server := a.newDNS()
	if err := server.Start(net.JoinHostPort(settings.ListenIP, "53")); err != nil {
		return err
	}
	a.dns = server
	a.dnsError = ""
	return nil
}

// Kernel redirects can intercept DNS before it reaches our sockets, so a
// successful bind alone does not establish that this listener can serve clients.
func (a *App) validateDNSListener(listenIP string) error {
	if err := dnsforward.ValidateListenIP(listenIP); err != nil {
		return err
	}
	live, err := a.Manager.ListRedirectRules()
	if err != nil {
		return err
	}
	for _, r := range live {
		if r.MatchPort == 53 && (r.MatchIP == nil || r.MatchIP.IsUnspecified() || r.MatchIP.Equal(net.ParseIP(listenIP))) {
			return errors.New("a port 53 redirect conflicts with this DNS listener")
		}
	}
	return nil
}

func (a *App) ConfigureDNS(settings state.DNS) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if settings.Enabled {
		if err := a.validateDNSListener(settings.ListenIP); err != nil {
			return err
		}
	}
	var candidate *dnsforward.Server
	if a.dns != nil && !a.dns.Status().Running {
		a.dns.Close()
		a.dns = nil
	}
	if settings.Enabled && (a.dns == nil || a.dns.Status().Address != net.JoinHostPort(settings.ListenIP, "53")) {
		candidate = a.newDNS()
		if err := candidate.Start(net.JoinHostPort(settings.ListenIP, "53")); err != nil {
			return err
		}
	}
	if err := a.Store.Update(func(c *state.Config) error { c.DNS = settings; return nil }); err != nil {
		if candidate != nil {
			candidate.Close()
		}
		return err
	}
	if candidate != nil || !settings.Enabled {
		if a.dns != nil {
			a.dns.Close()
		}
		a.dns = candidate
	}
	a.dnsError = ""
	return nil
}

func (a *App) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.Store.Snapshot()
	st := Status{ConfigPath: a.Store.Path(), SavedRules: len(c.Rules), RestoreError: a.restoreError}
	if a.dns != nil {
		st.DNS = a.dns.Status()
	}
	if a.dnsError != "" {
		st.DNS.Error = a.dnsError
	}
	return st
}

func (a *App) Reconcile() {
	err := a.Manager.Reconcile()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.restoreError = ""
	if err != nil {
		a.restoreError = err.Error()
	}
}

// Run retries rules and a failed DNS bind after boot while DHCP/Tailscale are
// still starting. A changing LAN address is shown as an error, never guessed.
func (a *App) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.Reconcile()
			a.mu.Lock()
			settings := a.Store.Snapshot().DNS
			if a.dns != nil && (!a.dns.Status().Running || dnsforward.ValidateListenIP(settings.ListenIP) != nil) {
				a.dns.Close()
				a.dns = nil
			}
			if settings.Enabled && a.dns == nil {
				if err := a.startDNS(settings); err != nil {
					a.dnsError = err.Error()
				}
			}
			a.mu.Unlock()
		}
	}
}

func (a *App) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dns != nil {
		a.dns.Close()
		a.dns = nil
	}
	return errors.Join(a.backend.Close(), a.Store.Close())
}

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Diagnose verifies the actual DNS listener and destination TLS identity. It
// cannot prove that a different device is using this network's DNS settings.
func (a *App) Diagnose(ctx context.Context) []Check {
	st := a.Status()
	c := a.Store.Snapshot()
	listenerDetail := st.DNS.Address
	if !c.DNS.Enabled {
		listenerDetail = "DNS forwarding is disabled"
	} else if listenerDetail == "" {
		listenerDetail = st.DNS.Error
	}
	checks := []Check{{Name: "DNS listener", OK: st.DNS.Running, Detail: listenerDetail}, {Name: "Network DNS", OK: len(st.DNS.Upstreams) > 0 && st.DNS.Error == "", Detail: fmt.Sprint(st.DNS.Upstreams)}}
	if st.DNS.Error != "" {
		checks[1].Detail = st.DNS.Error
	}
	restoreDetail := fmt.Sprintf("%d saved redirects", st.SavedRules)
	if st.RestoreError != "" {
		restoreDetail = st.RestoreError
	}
	checks = append(checks, Check{Name: "Saved redirects", OK: st.RestoreError == "", Detail: restoreDetail})
	checks = append(checks, forwardingChecks()...)
	live, liveErr := a.Manager.ListRedirectRules()
	if liveErr != nil {
		checks = append(checks, Check{Name: "Forwarding rules", Detail: liveErr.Error()})
	}
	if c.DNS.Enabled {
		err := dnsforward.ValidateListenIP(c.DNS.ListenIP)
		check := Check{Name: "LAN address", OK: err == nil, Detail: c.DNS.ListenIP}
		if err != nil {
			check.Detail = err.Error()
		}
		checks = append(checks, check)
	}
	if st.DNS.Running {
		q := new(dns.Msg)
		q.SetQuestion(".", dns.TypeNS)
		out, _, err := (&dns.Client{Timeout: 2 * time.Second}).ExchangeContext(ctx, q, st.DNS.Address)
		check := Check{Name: "Upstream DNS query", OK: err == nil && out != nil && out.Rcode == dns.RcodeSuccess, Detail: "Forwarded root nameserver lookup"}
		if err != nil {
			check.Detail = err.Error()
		}
		checks = append(checks, check)
	}
	for _, h := range c.Hostnames {
		r, ok := c.Rule(h.RuleID)
		if !ok {
			checks = append(checks, Check{Name: h.Name, Detail: "Saved redirect is missing"})
			continue
		}
		if ctx.Err() != nil {
			checks = append(checks, Check{Name: h.Name, Detail: "Check timed out; run checks again"})
			continue
		}
		active := false
		for _, rule := range live {
			if state.RuleID(rule) == h.RuleID {
				active = true
				break
			}
		}
		checks = append(checks, Check{Name: h.Name + " redirect", OK: active, Detail: net.JoinHostPort(r.MatchIP.String(), strconv.Itoa(int(r.MatchPort)))})
		if st.DNS.Running {
			q := new(dns.Msg)
			q.SetQuestion(dns.Fqdn(h.Name), dns.TypeA)
			out, _, err := (&dns.Client{Timeout: time.Second}).ExchangeContext(ctx, q, st.DNS.Address)
			correct := false
			if err == nil && out != nil {
				for _, rr := range out.Answer {
					if answer, ok := rr.(*dns.A); ok && answer.A.Equal(r.MatchIP) {
						correct = true
					}
				}
			}
			checks = append(checks, Check{Name: h.Name + " DNS", OK: correct, Detail: "Expected " + r.MatchIP.String()})
		}
		checkCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		address := net.JoinHostPort(r.TargetIP.String(), strconv.Itoa(int(r.TargetPort)))
		var conn net.Conn
		var err error
		label := " TCP destination"
		if r.MatchPort == 443 {
			label = " HTTPS destination"
			conn, err = (&tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{ServerName: h.Name, MinVersion: tls.VersionTLS12}}).DialContext(checkCtx, "tcp", address)
		} else {
			conn, err = (&net.Dialer{}).DialContext(checkCtx, "tcp", address)
		}
		cancel()
		check := Check{Name: h.Name + label, OK: err == nil, Detail: address}
		if err != nil {
			check.Detail = err.Error()
		} else {
			conn.Close()
		}
		checks = append(checks, check)
	}
	return checks
}
