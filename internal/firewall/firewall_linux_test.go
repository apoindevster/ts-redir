//go:build linux

package firewall

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Exercise the real nftables serialization and decoding without touching the
// host firewall. Record complete transactions and emulate rule dumps/deletions.
type testNFT struct {
	rules      []netlink.Message
	batches    int
	nextHandle uint64
	fail       error
}

func newTestNFTManager(t *testing.T) (*nftManager, *testNFT) {
	t.Helper()
	fake := &testNFT{}
	table := &nftables.Table{Name: tableName, Family: tableFamily}
	m := &nftManager{
		table:            table,
		preroutingChain:  &nftables.Chain{Name: preroutingChainName, Table: table},
		postroutingChain: &nftables.Chain{Name: postroutingChainName, Table: table},
		outputChain:      &nftables.Chain{Name: outputChainName, Table: table},
	}
	m.conn = &nftables.Conn{TestDial: func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, io.EOF
		}
		if req[0].Header.Type == netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_GETRULE) {
			chain := string(nftAttribute(t, req[0], unix.NFTA_RULE_CHAIN))
			var reply []netlink.Message
			for _, rule := range fake.rules {
				if string(nftAttribute(t, rule, unix.NFTA_RULE_CHAIN)) == chain {
					reply = append(reply, rule)
				}
			}
			if len(reply) == 0 {
				return nil, io.EOF
			}
			return reply, nil
		}
		if req[0].Header.Type != unix.NFNL_MSG_BATCH_BEGIN || req[len(req)-1].Header.Type != unix.NFNL_MSG_BATCH_END {
			t.Fatal("firewall writes must be sent in one complete nftables transaction")
		}
		fake.batches++
		if fake.fail != nil {
			return nil, fake.fail
		}
		for _, msg := range req[1 : len(req)-1] {
			switch msg.Header.Type {
			case netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWRULE):
				fake.nextHandle++
				handle := make([]byte, 8)
				binary.BigEndian.PutUint64(handle, fake.nextHandle)
				attrs, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_RULE_HANDLE, Data: handle}})
				if err != nil {
					t.Fatal(err)
				}
				fake.rules = append(fake.rules, netlink.Message{
					Header: netlink.Header{Type: msg.Header.Type},
					Data:   append(append([]byte(nil), msg.Data...), attrs...),
				})
			case netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_DELRULE):
				handle := string(nftAttribute(t, msg, unix.NFTA_RULE_HANDLE))
				for i, rule := range fake.rules {
					if string(nftAttribute(t, rule, unix.NFTA_RULE_HANDLE)) == handle {
						fake.rules = append(fake.rules[:i], fake.rules[i+1:]...)
						break
					}
				}
			default:
				t.Fatalf("unexpected nftables operation: %v", msg.Header.Type)
			}
		}
		return nil, io.EOF
	}}
	return m, fake
}

func nftAttribute(t *testing.T, msg netlink.Message, kind uint16) []byte {
	t.Helper()
	attrs, err := netlink.UnmarshalAttributes(msg.Data[4:])
	if err != nil {
		t.Fatal(err)
	}
	for _, attr := range attrs {
		if attr.Type == kind {
			return attr.Data
		}
	}
	t.Fatalf("missing nftables attribute %d", kind)
	return nil
}

func testRedirect(protocol Protocol) RedirectRule {
	return RedirectRule{Protocol: protocol, MatchInterface: "eth0", MatchIP: net.ParseIP("192.0.2.10"), MatchPort: 8080, TargetIP: net.ParseIP("100.64.0.2"), TargetPort: 80, Description: "example", TailscalePeer: "peer"}
}

func TestRedirectProtocolsAndDeletion(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolTCP, ProtocolUDP, ProtocolBoth} {
		for _, interfaceOnly := range []bool{false, true} {
			name := string(protocol)
			if interfaceOnly {
				name += "/interface-only"
			}
			t.Run(name, func(t *testing.T) {
				m, fake := newTestNFTManager(t)
				rule := testRedirect(protocol)
				stages := 3
				if interfaceOnly {
					rule.MatchIP = nil
					stages = 2
				}
				if err := m.AddRedirectRule(rule); err != nil {
					t.Fatal(err)
				}
				wantProtocols := []Protocol{protocol}
				if protocol == ProtocolBoth {
					wantProtocols = []Protocol{ProtocolTCP, ProtocolUDP}
				}
				if fake.batches != 1 || len(fake.rules) != stages*len(wantProtocols) {
					t.Fatalf("got %d transactions and %d kernel rules; want one transaction and %d rules", fake.batches, len(fake.rules), stages*len(wantProtocols))
				}
				listed, err := m.ListRedirectRules()
				if err != nil {
					t.Fatal(err)
				}
				if len(listed) != len(wantProtocols) {
					t.Fatalf("got %d visible rules", len(listed))
				}
				for i, listedRule := range listed {
					want := rule
					want.Protocol = wantProtocols[i]
					if ruleKey(listedRule) != ruleKey(want) || listedRule.Description != rule.Description {
						t.Fatalf("rule did not round-trip: %+v", listedRule)
					}
				}
				for _, chain := range []*nftables.Chain{m.preroutingChain, m.postroutingChain, m.outputChain} {
					kernelRules, err := m.conn.GetRules(m.table, chain)
					if err != nil {
						t.Fatal(err)
					}
					for i, kernelRule := range kernelRules {
						wantProtocol := byte(6)
						if wantProtocols[i] == ProtocolUDP {
							wantProtocol = 17
						}
						matched := false
						for j, e := range kernelRule.Exprs {
							if p, ok := e.(*expr.Payload); ok && p.Base == expr.PayloadBaseNetworkHeader && p.Offset == 9 && p.Len == 1 {
								cmp, ok := kernelRule.Exprs[j+1].(*expr.Cmp)
								matched = ok && cmp.Op == expr.CmpOpEq && len(cmp.Data) == 1 && cmp.Data[0] == wantProtocol
								break
							}
						}
						if !matched {
							t.Fatalf("%s rule does not match protocol %d", chain.Name, wantProtocol)
						}
						last := kernelRule.Exprs[len(kernelRule.Exprs)-1]
						if chain == m.postroutingChain {
							if _, ok := last.(*expr.Masq); !ok {
								t.Fatal("missing return-path masquerade")
							}
						} else if nat, ok := last.(*expr.NAT); !ok || nat.Type != expr.NATTypeDestNAT {
							t.Fatal("missing destination NAT")
						}
					}
				}
				for i, listedRule := range listed {
					if err := m.DeleteRedirectRule(listedRule.Handle); err != nil {
						t.Fatal(err)
					}
					if len(fake.rules) != (len(listed)-i-1)*stages {
						t.Fatal("deletion removed the wrong protocol's companion rules")
					}
				}
			})
		}
	}
}

func TestBothRejectsEitherDuplicateBeforeWriting(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolTCP, ProtocolUDP} {
		t.Run(string(protocol), func(t *testing.T) {
			m, fake := newTestNFTManager(t)
			if err := m.AddRedirectRule(testRedirect(protocol)); err != nil {
				t.Fatal(err)
			}
			if exists, err := m.RuleExists(testRedirect(ProtocolBoth)); err != nil || !exists {
				t.Fatalf("duplicate check: exists=%v, err=%v", exists, err)
			}
			if err := m.AddRedirectRule(testRedirect(ProtocolBoth)); !errors.Is(err, ErrDuplicateRule) {
				t.Fatalf("got %v; want duplicate error", err)
			}
			if fake.batches != 1 || len(fake.rules) != 3 {
				t.Fatal("duplicate request changed firewall state")
			}
		})
	}
}

func TestBothFailedTransactionDoesNotLeakIntoNextRequest(t *testing.T) {
	m, fake := newTestNFTManager(t)
	fake.fail = unix.EPERM
	if err := m.AddRedirectRule(testRedirect(ProtocolBoth)); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("got %v; want permission error", err)
	}
	fake.fail = nil
	if err := m.AddRedirectRule(testRedirect(ProtocolUDP)); err != nil {
		t.Fatal(err)
	}
	rules, err := m.ListRedirectRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Protocol != ProtocolUDP || len(fake.rules) != 3 {
		t.Fatal("failed batch leaked into a later request")
	}
}

func TestConcurrentBothRequestsCreateOnePair(t *testing.T) {
	m, fake := newTestNFTManager(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.AddRedirectRule(testRedirect(ProtocolBoth)); err != nil && !errors.Is(err, ErrDuplicateRule) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if fake.batches != 1 || len(fake.rules) != 6 {
		t.Fatalf("got %d batches and %d rules", fake.batches, len(fake.rules))
	}
}

func TestInvalidProtocolDoesNotTouchNFTables(t *testing.T) {
	m, fake := newTestNFTManager(t)
	if err := m.AddRedirectRule(testRedirect("icmp")); err == nil || !strings.Contains(err.Error(), "unsupported protocol") {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.batches != 0 {
		t.Fatal("invalid protocol changed firewall state")
	}
}
