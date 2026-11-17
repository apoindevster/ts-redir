// Package dnsforward serves exact local hostname overrides and forwards other
// questions to DNS servers learned from the host's LAN configuration.
package dnsforward

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Status struct {
	Running   bool     `json:"running"`
	Address   string   `json:"address"`
	Upstreams []string `json:"upstreams"`
	Error     string   `json:"error,omitempty"`
}

type Server struct {
	mu       sync.RWMutex
	status   Status
	answers  func() map[string]net.IP
	discover func(context.Context, string) ([]string, error)
	tcp, udp *dns.Server
	cancel   context.CancelFunc
	workers  sync.WaitGroup
	slots    chan struct{}
}

func New(answers func() map[string]net.IP) *Server {
	return &Server{answers: answers, discover: Discover, slots: make(chan struct{}, 128)}
}

func (s *Server) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := s.status
	st.Upstreams = append([]string{}, st.Upstreams...)
	return st
}

// Start binds both transports before accepting queries. The caller serializes
// lifecycle changes; query handling and status reads are concurrency-safe.
func (s *Server) Start(address string) error {
	tcp, err := net.Listen("tcp4", address)
	if err != nil {
		return fmt.Errorf("DNS TCP listener: %w", err)
	}
	// Port zero is useful for integration tests; both transports share its port.
	address = tcp.Addr().String()
	udp, err := net.ListenPacket("udp4", address)
	if err != nil {
		tcp.Close()
		return fmt.Errorf("DNS UDP listener: %w", err)
	}
	s.tcp = &dns.Server{Listener: tcp, Handler: s, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second}
	s.udp = &dns.Server{PacketConn: udp, Handler: s, UDPSize: 1232, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.mu.Lock()
	s.status = Status{Running: true, Address: address, Upstreams: []string{}}
	s.mu.Unlock()
	for _, server := range []*dns.Server{s.tcp, s.udp} {
		ready := make(chan struct{})
		stopped := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		s.workers.Add(1)
		go func(server *dns.Server) {
			defer s.workers.Done()
			defer close(stopped)
			if err := server.ActivateAndServe(); err != nil && ctx.Err() == nil {
				s.mu.Lock()
				s.status.Running = false
				s.status.Error = err.Error()
				s.mu.Unlock()
			}
		}(server)
		select {
		case <-ready:
		case <-stopped:
			err := fmt.Errorf("DNS listener stopped during startup: %s", s.Status().Error)
			s.Close()
			tcp.Close()
			udp.Close()
			return err
		}
	}
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		s.Refresh(ctx)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.Refresh(ctx)
			}
		}
	}()
	return nil
}

func (s *Server) Refresh(ctx context.Context) {
	st := s.Status()
	host, _, _ := net.SplitHostPort(st.Address)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	upstreams, err := s.discover(ctx, host)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Drop stale upstreams if the LAN changes or discovery fails. Never fall back
	// to a hardcoded public resolver or to this forwarder itself.
	s.status.Upstreams = upstreams
	if s.status.Running {
		s.status.Error = ""
		if err != nil {
			s.status.Error = err.Error()
		}
	}
}

func (s *Server) Close() {
	if s.cancel == nil {
		return
	}
	s.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_ = s.tcp.ShutdownContext(ctx)
	_ = s.udp.ShutdownContext(ctx)
	s.workers.Wait()
	s.mu.Lock()
	s.status.Running = false
	s.mu.Unlock()
	s.cancel = nil
}

func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	response := new(dns.Msg)
	response.SetReply(req)
	response.RecursionAvailable = true
	if req.Opcode != dns.OpcodeQuery || len(req.Question) != 1 {
		response.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(response)
		return
	}
	q := req.Question[0]
	if q.Qclass != dns.ClassINET {
		response.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(response)
		return
	}
	if ip, ok := s.answers()[strings.ToLower(dns.Fqdn(q.Name))]; ok {
		// Exact overrides are IPv4-only. NODATA for AAAA, HTTPS/SVCB and all
		// other types prevents public aliases/address hints bypassing this gateway.
		response.Authoritative = true
		if q.Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: ip.To4()}}
		}
		_ = w.WriteMsg(response)
		return
	}
	if !req.RecursionDesired {
		response.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(response)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		response.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(response)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	network := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		network = "tcp"
	}
	for _, upstream := range s.Status().Upstreams {
		client := &dns.Client{Net: network, Timeout: 1500 * time.Millisecond}
		out, _, err := client.ExchangeContext(ctx, req, upstream)
		if err == nil && out.Truncated && network == "udp" {
			client.Net = "tcp"
			out, _, err = client.ExchangeContext(ctx, req, upstream)
		}
		if err != nil || out.Rcode == dns.RcodeServerFailure || out.Rcode == dns.RcodeRefused {
			continue
		}
		// Respect the client's advertised UDP payload instead of emitting a large
		// response after retrying a truncated upstream reply over TCP.
		if network == "udp" {
			size := uint16(512)
			if opt := req.IsEdns0(); opt != nil {
				size = opt.UDPSize()
				if size < 512 {
					size = 512
				}
				if size > 1232 {
					size = 1232
				}
			}
			out.Truncate(int(size))
		}
		_ = w.WriteMsg(out)
		return
	}
	response.Rcode = dns.RcodeServerFailure
	_ = w.WriteMsg(response)
}

func ValidateListenIP(address string) error {
	ip := net.ParseIP(address)
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsLoopback() || !ip.IsPrivate() {
		return errors.New("choose a private LAN IPv4 address assigned to this machine")
	}
	_, err := interfaceForIP(address)
	return err
}

func interfaceForIP(address string) (*net.Interface, error) {
	ip := net.ParseIP(address)
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			addr, _, err := net.ParseCIDR(a.String())
			if err == nil && addr.Equal(ip) {
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf("LAN address %s is not assigned to this machine", address)
}

func filterUpstreams(servers []string, listenIP string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, server := range servers {
		ip := net.ParseIP(strings.Split(server, "%")[0])
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.ParseIP(listenIP)) || ip.Equal(net.ParseIP("100.100.100.100")) || ip.Equal(net.ParseIP("fd7a:115c:a1e0::53")) {
			continue
		}
		address := net.JoinHostPort(server, "53")
		if !seen[address] {
			out = append(out, address)
			seen[address] = true
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no network upstream DNS found; the LAN resolver must not point back to ts-redir")
	}
	return out, nil
}

// Link-local IPv6 resolvers require the selected interface as their scope.
func withInterfaceZone(servers []string, iface *net.Interface) []string {
	out := append([]string{}, servers...)
	for i, server := range out {
		if ip := net.ParseIP(server); ip != nil && ip.To4() == nil && ip.IsLinkLocalUnicast() {
			out[i] = server + "%" + strconv.Itoa(iface.Index)
		}
	}
	return out
}
