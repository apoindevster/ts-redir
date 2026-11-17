package dnsforward

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func upstream(t *testing.T, handler dns.Handler) string {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range []*dns.Server{{Listener: tcp, Handler: handler}, {PacketConn: udp, Handler: handler}} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go server.ActivateAndServe()
		<-ready
		t.Cleanup(func() { server.Shutdown() })
	}
	return tcp.Addr().String()
}

func forwarder(t *testing.T, addresses []string) *Server {
	t.Helper()
	s := New(func() map[string]net.IP { return map[string]net.IP{"photos.example.com.": net.ParseIP("192.168.1.20")} })
	s.discover = func(context.Context, string) ([]string, error) { return addresses, nil }
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	s.Refresh(context.Background())
	t.Cleanup(s.Close)
	return s
}

func query(t *testing.T, network, address, name string, qtype uint16) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	out, _, err := (&dns.Client{Net: network, Timeout: 2 * time.Second}).Exchange(q, address)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestExactOverridesAndForwardingBothTransports(t *testing.T) {
	var calls atomic.Int32
	addr := upstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		calls.Add(1)
		out := new(dns.Msg)
		out.SetReply(r)
		out.RecursionAvailable = true
		if r.Question[0].Name == "missing.example." {
			out.Rcode = dns.RcodeNameError
		} else {
			out.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600}, A: net.ParseIP("192.0.2.50")}}
		}
		w.WriteMsg(out)
	}))
	s := forwarder(t, []string{addr})
	for _, network := range []string{"udp", "tcp"} {
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB, dns.TypeANY, dns.TypeTXT} {
			before := calls.Load()
			out := query(t, network, s.Status().Address, "PHOTOS.example.com.", qtype)
			if out.Rcode != dns.RcodeSuccess || !out.Authoritative || out.AuthenticatedData {
				t.Fatalf("bad local answer: %v", out)
			}
			if qtype == dns.TypeA {
				if len(out.Answer) != 1 || !out.Answer[0].(*dns.A).A.Equal(net.ParseIP("192.168.1.20")) {
					t.Fatal(out)
				}
			} else if len(out.Answer) != 0 {
				t.Fatal("non-A override leaked upstream records")
			}
			if calls.Load() != before {
				t.Fatal("override queried upstream")
			}
		}
		out := query(t, network, s.Status().Address, "other.example.com.", dns.TypeA)
		if out.Answer[0].(*dns.A).A.String() != "192.0.2.50" {
			t.Fatal(out)
		}
		if query(t, network, s.Status().Address, "missing.example.", dns.TypeA).Rcode != dns.RcodeNameError {
			t.Fatal("NXDOMAIN not preserved")
		}
	}
}

func TestUpstreamTCPRetryAndFailover(t *testing.T) {
	var tcpCalls atomic.Int32
	good := upstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		out := new(dns.Msg)
		out.SetReply(req)
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			out.Truncated = true
		} else {
			tcpCalls.Add(1)
			out.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.6")}}
		}
		w.WriteMsg(out)
	}))
	bad := upstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		out := new(dns.Msg)
		out.SetRcode(req, dns.RcodeServerFailure)
		w.WriteMsg(out)
	}))
	s := forwarder(t, []string{bad, good})
	out := query(t, "udp", s.Status().Address, "other.example.", dns.TypeA)
	if out.Truncated || len(out.Answer) != 1 || tcpCalls.Load() != 1 {
		t.Fatalf("retry failed: %v", out)
	}
}

func TestNoUpstreamsStillServesLocalNames(t *testing.T) {
	s := forwarder(t, nil)
	if query(t, "tcp", s.Status().Address, "photos.example.com.", dns.TypeA).Rcode != dns.RcodeSuccess {
		t.Fatal("local lookup needs upstream")
	}
	if query(t, "udp", s.Status().Address, "other.example.com.", dns.TypeA).Rcode != dns.RcodeServerFailure {
		t.Fatal("expected SERVFAIL")
	}
}

func TestListenerCollisionAndShutdown(t *testing.T) {
	s := forwarder(t, nil)
	address := s.Status().Address
	other := New(func() map[string]net.IP { return nil })
	if err := other.Start(address); err == nil {
		other.Close()
		t.Fatal("accepted duplicate listener")
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 20; n++ {
				s.Status()
			}
		}()
	}
	wg.Wait()
	s.Close()
	tcp, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	tcp.Close()
	udp, err := net.ListenPacket("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	udp.Close()
}

func TestNetworkUpstreamFiltering(t *testing.T) {
	addresses, err := filterUpstreams([]string{"192.168.1.20", "100.100.100.100", "fd7a:115c:a1e0::53", "0.0.0.0", "192.168.1.1", "192.168.1.1", "fe80::1%eth0", "invalid"}, "192.168.1.20")
	if err != nil || strings.Join(addresses, ",") != "192.168.1.1:53,[fe80::1%eth0]:53" {
		t.Fatalf("%v %v", addresses, err)
	}
	if _, err := filterUpstreams([]string{"192.168.1.20"}, "192.168.1.20"); err == nil {
		t.Fatal("self-forwarding accepted")
	}
}

func TestUDPCollisionReleasesTCPListener(t *testing.T) {
	occupied, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	s := New(func() map[string]net.IP { return nil })
	if err := s.Start(occupied.LocalAddr().String()); err == nil {
		s.Close()
		t.Fatal("expected UDP conflict")
	}
	tcp, err := net.Listen("tcp4", occupied.LocalAddr().String())
	if err != nil {
		t.Fatalf("failed start leaked TCP listener: %v", err)
	}
	tcp.Close()
}

func TestLinkLocalResolverScope(t *testing.T) {
	got := withInterfaceZone([]string{"fe80::1", "fe80::2%eth0", "2001:db8::1", "192.168.1.1"}, &net.Interface{Index: 12})
	if strings.Join(got, ",") != "fe80::1%12,fe80::2%eth0,2001:db8::1,192.168.1.1" {
		t.Fatal(got)
	}
}
