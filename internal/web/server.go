package web

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apoindevster/ts-redir/internal/firewall"
	"github.com/apoindevster/ts-redir/internal/tailscale"
)

//go:embed templates/index.html
var indexHTML string

type Server struct {
	mgr       firewall.Manager
	ifaceName string
	port      int
	server    *http.Server
	mu        sync.Mutex
	indexTmpl *template.Template
}

func NewServer(mgr firewall.Manager, iface string, port int) (*Server, error) {
	tmpl, err := template.New("index").Parse(indexHTML)
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}

	s := &Server{
		mgr:       mgr,
		ifaceName: iface,
		port:      port,
		indexTmpl: tmpl,
	}
	return s, nil
}

func (s *Server) Run() error {
	addr, err := s.bindAddr()
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/rules/", s.handleRuleByID)
	mux.HandleFunc("/api/peers", s.handlePeers)
	mux.HandleFunc("/api/interfaces", s.handleInterfaces)
	mux.HandleFunc("/api/status", s.handleStatus)

	s.server = &http.Server{
		Addr:    addr,
		Handler: withLogging(mux),
	}

	if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

func (s *Server) bindAddr() (string, error) {
	iface, err := net.InterfaceByName(s.ifaceName)
	if err != nil {
		return "", fmt.Errorf("locate interface %q: %w", s.ifaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("list addresses: %w", err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return net.JoinHostPort(ipnet.IP.String(), strconv.Itoa(s.port)), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address found on interface %q", s.ifaceName)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if err := s.indexTmpl.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listRules(w, r)
	case http.MethodPost:
		s.createRule(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRuleByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 3 {
		http.NotFound(w, r)
		return
	}
	handle, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		http.Error(w, "invalid handle", http.StatusBadRequest)
		return
	}

	if err := s.mgr.DeleteRedirectRule(handle); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.mgr.ListRedirectRules()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, toAPIRules(rules))
}

func (s *Server) createRule(w http.ResponseWriter, r *http.Request) {
	var payload rulePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	rule, err := payload.toRule()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if exists, err := s.mgr.RuleExists(rule); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if exists {
		http.Error(w, "duplicate rule exists", http.StatusConflict)
		return
	}

	if err := s.mgr.AddRedirectRule(rule); err != nil {
		if errors.Is(err, firewall.ErrDuplicateRule) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Return the newly created rule (with an unknown handle until reloaded).
	w.WriteHeader(http.StatusCreated)
	all, err := s.mgr.ListRedirectRules()
	if err != nil {
		writeJSON(w, map[string]string{"status": "created"})
		return
	}
	writeJSON(w, toAPIRules(all))
}

func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	peers, err := tailscale.ListPeers(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, peers)
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	names := availableInterfaces(s.ifaceName)
	writeJSON(w, names)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	raw, err := tailscale.RawStatus(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(raw); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type rulePayload struct {
	Description    string `json:"description"`
	Protocol       string `json:"protocol"`
	MatchInterface string `json:"match_interface"`
	MatchIP        string `json:"match_ip"`
	MatchPort      uint16 `json:"match_port"`
	TargetIP       string `json:"target_ip"`
	TargetPort     uint16 `json:"target_port"`
	TailscalePeer  string `json:"tailscale_peer"`
}

func (p rulePayload) toRule() (firewall.RedirectRule, error) {
	description := strings.TrimSpace(p.Description)
	var matchIP net.IP
	if strings.TrimSpace(p.MatchIP) != "" {
		matchIP = net.ParseIP(p.MatchIP)
		if matchIP == nil {
			return firewall.RedirectRule{}, errors.New("invalid match IP")
		}
	}
	targetIP := net.ParseIP(p.TargetIP)
	if targetIP == nil {
		return firewall.RedirectRule{}, errors.New("invalid target IP")
	}
	rule := firewall.RedirectRule{
		Description:    description,
		Protocol:       firewall.Protocol(strings.ToLower(p.Protocol)),
		MatchInterface: strings.TrimSpace(p.MatchInterface),
		MatchIP:        matchIP,
		MatchPort:      p.MatchPort,
		TargetIP:       targetIP,
		TargetPort:     p.TargetPort,
		TailscalePeer:  p.TailscalePeer,
	}
	return rule, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

type apiRule struct {
	Handle         uint64 `json:"handle"`
	Description    string `json:"description"`
	Protocol       string `json:"protocol"`
	MatchInterface string `json:"match_interface,omitempty"`
	MatchIP        string `json:"match_ip,omitempty"`
	MatchPort      uint16 `json:"match_port"`
	TargetIP       string `json:"target_ip"`
	TargetPort     uint16 `json:"target_port"`
	TailscalePeer  string `json:"tailscale_peer"`
}

func toAPIRules(rules []firewall.RedirectRule) []apiRule {
	out := make([]apiRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, apiRule{
			Handle:         r.Handle,
			Description:    r.Description,
			Protocol:       strings.ToLower(string(r.Protocol)),
			MatchInterface: r.MatchInterface,
			MatchIP:        ipToString(r.MatchIP),
			MatchPort:      r.MatchPort,
			TargetIP:       ipToString(r.TargetIP),
			TargetPort:     r.TargetPort,
			TailscalePeer:  r.TailscalePeer,
		})
	}
	return out
}

func ipToString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func availableInterfaces(exclude string) []string {
	seen := map[string]struct{}{}
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Name == exclude {
				continue
			}
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			seen[iface.Name] = struct{}{}
		}
	}

	if len(seen) == 0 {
		if fallback, err := parseProcNetDev(); err == nil {
			for _, name := range fallback {
				if name == "" || name == "lo" || name == exclude {
					continue
				}
				seen[name] = struct{}{}
			}
		}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func parseProcNetDev() ([]string, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var names []string
	scanner := bufio.NewScanner(f)
	for line := 0; scanner.Scan(); line++ {
		if line < 2 {
			continue
		}
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		if name != "" {
			names = append(names, name)
		}
	}
	return names, scanner.Err()
}
