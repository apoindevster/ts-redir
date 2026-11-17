package web

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/apoindevster/ts-redir/internal/app"
	"github.com/apoindevster/ts-redir/internal/state"
)

func (s *Server) handleLANAddresses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	type address struct {
		IP        string `json:"ip"`
		Interface string `json:"interface"`
	}
	addresses := []address{}
	ifaces, err := net.Interfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, iface := range ifaces {
		if iface.Name == s.ifaceName || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err == nil && ip.To4() != nil && ip.IsPrivate() {
				addresses = append(addresses, address{ip.String(), iface.Name})
			}
		}
	}
	writeJSON(w, addresses)
}

func (s *Server) SetApplication(application *app.App) { s.app = application }

func (s *Server) handleDNS(w http.ResponseWriter, r *http.Request) {
	if s.app == nil {
		http.Error(w, "DNS management requires persistent application mode", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		c := s.app.Store.Snapshot()
		type mapping struct {
			Name        string `json:"name"`
			RuleID      string `json:"rule_id"`
			Address     string `json:"address"`
			Port        uint16 `json:"port"`
			Destination string `json:"destination"`
		}
		records := []mapping{}
		for _, h := range c.Hostnames {
			rule, _ := c.Rule(h.RuleID)
			records = append(records, mapping{h.Name, h.RuleID, rule.MatchIP.String(), rule.MatchPort, net.JoinHostPort(rule.TargetIP.String(), strconv.Itoa(int(rule.TargetPort)))})
		}
		writeJSON(w, map[string]any{"settings": c.DNS, "hostnames": records, "status": s.app.Status()})
	case http.MethodPut:
		var settings state.DNS
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&settings); err != nil {
			http.Error(w, "invalid DNS settings", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.app.ConfigureDNS(settings); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, s.app.Status())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleHostnames(w http.ResponseWriter, r *http.Request) {
	if s.app == nil {
		http.Error(w, "DNS management unavailable", http.StatusServiceUnavailable)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.Method {
	case http.MethodPost:
		if r.URL.Path != "/api/hostnames" {
			http.NotFound(w, r)
			return
		}
		var payload struct {
			Hostname   string `json:"hostname"`
			RuleHandle string `json:"rule_handle"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&payload); err != nil {
			http.Error(w, "invalid hostname mapping", http.StatusBadRequest)
			return
		}
		if len(s.app.Store.Snapshot().Hostnames) >= 256 {
			http.Error(w, "maximum of 256 hostnames reached", http.StatusBadRequest)
			return
		}
		handle, err := strconv.ParseUint(payload.RuleHandle, 10, 64)
		if err != nil {
			http.Error(w, "rule_handle must be a decimal string from handle_id", http.StatusBadRequest)
			return
		}
		if err := s.app.Manager.AddHostname(payload.Hostname, handle); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]string{"status": "created"})
	case http.MethodDelete:
		name := strings.TrimPrefix(r.URL.Path, "/api/hostnames/")
		if err := s.app.Manager.DeleteHostname(name); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.app == nil {
		http.Error(w, "DNS management unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	writeJSON(w, s.app.Diagnose(ctx))
}
