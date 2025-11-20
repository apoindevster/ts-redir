//go:build linux

package firewall

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	tableName            = "ts_redir"
	preroutingChainName  = "prerouting"
	postroutingChainName = "postrouting"
	outputChainName      = "output"
	userDataPrefix       = "ts-redir:"
	tableFamily          = nftables.TableFamilyIPv4
	stagePrerouting      = "prerouting"
	stagePostrouting     = "postrouting"
	stageOutput          = "output"
)

// ErrPermissionDenied indicates the caller lacks CAP_NET_ADMIN privileges.
var ErrPermissionDenied = errors.New("nftables requires CAP_NET_ADMIN (try running with sudo)")

type ruleMetadata struct {
	Description    string   `json:"description"`
	Protocol       Protocol `json:"protocol"`
	MatchIP        string   `json:"match_ip"`
	MatchInterface string   `json:"match_interface,omitempty"`
	MatchPort      uint16   `json:"match_port"`
	TargetIP       string   `json:"target_ip"`
	TargetPort     uint16   `json:"target_port"`
	TailscalePeer  string   `json:"tailscale_peer"`
	Stage          string   `json:"stage,omitempty"`
}

type nftManager struct {
	conn             *nftables.Conn
	table            *nftables.Table
	preroutingChain  *nftables.Chain
	postroutingChain *nftables.Chain
	outputChain      *nftables.Chain
}

func newManager() (Manager, error) {
	conn := &nftables.Conn{}
	m := &nftManager{conn: conn}
	if err := m.ensureBaseObjects(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *nftManager) Close() error { return nil }

func (m *nftManager) ensureBaseObjects() error {
	if err := m.ensureTable(); err != nil {
		return err
	}
	if err := m.ensureChains(); err != nil {
		return err
	}
	return nil
}

func (m *nftManager) ensureTable() error {
	tables, err := m.conn.ListTables()
	if err != nil {
		return wrapNFTError("list tables", err)
	}
	for _, t := range tables {
		if t.Name == tableName && t.Family == tableFamily {
			m.table = t
			return nil
		}
	}
	table := &nftables.Table{
		Family: tableFamily,
		Name:   tableName,
	}
	m.conn.AddTable(table)
	if err := m.conn.Flush(); err != nil {
		return wrapNFTError("flush after table add", err)
	}
	m.table = table
	return nil
}

func (m *nftManager) ensureChains() error {
	chains, err := m.conn.ListChains()
	if err != nil {
		return wrapNFTError("list chains", err)
	}
	if m.table == nil {
		return errors.New("table not initialised")
	}

	m.preroutingChain = findChain(chains, preroutingChainName, tableName)
	m.postroutingChain = findChain(chains, postroutingChainName, tableName)
	m.outputChain = findChain(chains, outputChainName, tableName)

	var toCreate []*nftables.Chain
	policyAccept := nftables.ChainPolicyAccept
	if m.preroutingChain == nil {
		toCreate = append(toCreate, &nftables.Chain{
			Name:     preroutingChainName,
			Table:    m.table,
			Type:     nftables.ChainTypeNAT,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: nftables.ChainPriorityNATDest,
			Policy:   &policyAccept,
		})
	}
	if m.postroutingChain == nil {
		toCreate = append(toCreate, &nftables.Chain{
			Name:     postroutingChainName,
			Table:    m.table,
			Type:     nftables.ChainTypeNAT,
			Hooknum:  nftables.ChainHookPostrouting,
			Priority: nftables.ChainPriorityNATSource,
			Policy:   &policyAccept,
		})
	}
	if m.outputChain == nil {
		toCreate = append(toCreate, &nftables.Chain{
			Name:     outputChainName,
			Table:    m.table,
			Type:     nftables.ChainTypeNAT,
			Hooknum:  nftables.ChainHookOutput,
			Priority: nftables.ChainPriorityNATDest,
			Policy:   &policyAccept,
		})
	}

	for _, chain := range toCreate {
		m.conn.AddChain(chain)
	}
	if len(toCreate) > 0 {
		if err := m.conn.Flush(); err != nil {
			return wrapNFTError("flush after chain add", err)
		}
		chains, err = m.conn.ListChains()
		if err != nil {
			return wrapNFTError("list chains", err)
		}
		m.preroutingChain = findChain(chains, preroutingChainName, tableName)
		m.postroutingChain = findChain(chains, postroutingChainName, tableName)
		m.outputChain = findChain(chains, outputChainName, tableName)
	}

	if m.preroutingChain == nil || m.postroutingChain == nil || m.outputChain == nil {
		return errors.New("failed to initialise ts-redir nftables chains")
	}
	return nil
}

func (m *nftManager) ListRedirectRules() ([]RedirectRule, error) {
	if m.table == nil || m.preroutingChain == nil {
		return nil, errors.New("manager not initialised")
	}
	rules, err := m.conn.GetRules(m.table, m.preroutingChain)
	if err != nil {
		return nil, fmt.Errorf("get rules: %w", err)
	}
	out := make([]RedirectRule, 0, len(rules))
	for _, r := range rules {
		if len(r.UserData) == 0 {
			continue
		}
		rawMeta := trimUserDataPrefix(r.UserData)
		if len(rawMeta) == 0 {
			continue
		}
		meta := ruleMetadata{}
		if err := json.Unmarshal(rawMeta, &meta); err != nil {
			continue
		}
		if meta.Stage != "" && meta.Stage != stagePrerouting {
			continue
		}
		redirect, err := redirectFromMetadata(r.Handle, meta)
		if err != nil {
			continue
		}
		out = append(out, redirect)
	}
	return out, nil
}

func (m *nftManager) AddRedirectRule(rule RedirectRule) error {
	if err := validateRule(rule); err != nil {
		return err
	}
	if m.table == nil || m.preroutingChain == nil || m.postroutingChain == nil || m.outputChain == nil {
		return errors.New("manager not initialised")
	}

	protoNum, err := protoToNumber(rule.Protocol)
	if err != nil {
		return err
	}

	redirectMetadata := buildMetadata(rule, stagePrerouting)
	masqMetadata := buildMetadata(rule, stagePostrouting)
	outputMetadata := buildMetadata(rule, stageOutput)

	redirectUserData, err := marshalMetadata(redirectMetadata)
	if err != nil {
		return fmt.Errorf("marshal redirect metadata: %w", err)
	}
	masqUserData, err := marshalMetadata(masqMetadata)
	if err != nil {
		return fmt.Errorf("marshal masquerade metadata: %w", err)
	}
	outputUserData, err := marshalMetadata(outputMetadata)
	if err != nil {
		return fmt.Errorf("marshal output metadata: %w", err)
	}

	preroutingExprs := append(
		matchInterfaceExprs(rule.MatchInterface, expr.MetaKeyIIFNAME),
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			Base:          expr.PayloadBaseNetworkHeader,
			Offset:        9,
			Len:           1,
			DestRegister:  1,
		},
		&expr.Cmp{
			Register: 1,
			Op:       expr.CmpOpEq,
			Data:     []byte{protoNum},
		},
	)
	if rule.MatchIP != nil {
		preroutingExprs = append(preroutingExprs,
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        16,
				Len:           4,
				DestRegister:  1,
			},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     rule.MatchIP.To4(),
			},
		)
	}
	preroutingExprs = append(preroutingExprs,
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			Base:          expr.PayloadBaseTransportHeader,
			Offset:        2,
			Len:           2,
			DestRegister:  1,
		},
		&expr.Cmp{
			Register: 1,
			Op:       expr.CmpOpEq,
			Data:     uint16ToBytes(rule.MatchPort),
		},
		&expr.Immediate{
			Register: 1,
			Data:     rule.TargetIP.To4(),
		},
		&expr.Immediate{
			Register: 2,
			Data:     uint16ToBytes(rule.TargetPort),
		},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      uint32(unix.NFPROTO_IPV4),
			RegAddrMin:  1,
			RegAddrMax:  1,
			RegProtoMin: 2,
			RegProtoMax: 2,
		},
	)

	preroutingRule := &nftables.Rule{
		Table:    m.table,
		Chain:    m.preroutingChain,
		UserData: redirectUserData,
		Exprs:    preroutingExprs,
	}

	postroutingRule := &nftables.Rule{
		Table:    m.table,
		Chain:    m.postroutingChain,
		UserData: masqUserData,
		Exprs: []expr.Any{
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        9,
				Len:           1,
				DestRegister:  1,
			},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     []byte{protoNum},
			},
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        16,
				Len:           4,
				DestRegister:  1,
			},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     rule.TargetIP.To4(),
			},
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Base:          expr.PayloadBaseTransportHeader,
				Offset:        2,
				Len:           2,
				DestRegister:  1,
			},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     uint16ToBytes(rule.TargetPort),
			},
			&expr.Masq{},
		},
	}

	m.conn.AddRule(preroutingRule)
	m.conn.AddRule(postroutingRule)
	if rule.MatchIP != nil {
		outputExprs := []expr.Any{
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        9,
				Len:           1,
				DestRegister:  1,
			},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     []byte{protoNum},
			},
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        16,
				Len:           4,
				DestRegister:  1,
			},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     rule.MatchIP.To4(),
			},
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Base:          expr.PayloadBaseTransportHeader,
				Offset:        2,
				Len:           2,
				DestRegister:  1,
			},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     uint16ToBytes(rule.MatchPort),
			},
			&expr.Immediate{
				Register: 1,
				Data:     rule.TargetIP.To4(),
			},
			&expr.Immediate{
				Register: 2,
				Data:     uint16ToBytes(rule.TargetPort),
			},
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      uint32(unix.NFPROTO_IPV4),
				RegAddrMin:  1,
				RegAddrMax:  1,
				RegProtoMin: 2,
				RegProtoMax: 2,
			},
		}

		outputRule := &nftables.Rule{
			Table:    m.table,
			Chain:    m.outputChain,
			UserData: outputUserData,
			Exprs:    outputExprs,
		}
		m.conn.AddRule(outputRule)
	}
	if err := m.conn.Flush(); err != nil {
		return wrapNFTError("flush after rule add", err)
	}
	return nil
}

func (m *nftManager) DeleteRedirectRule(handle uint64) error {
	if m.table == nil || m.preroutingChain == nil || m.postroutingChain == nil || m.outputChain == nil {
		return errors.New("manager not initialised")
	}
	rules, err := m.conn.GetRules(m.table, m.preroutingChain)
	if err != nil {
		return wrapNFTError("get rules", err)
	}
	for _, r := range rules {
		if r.Handle != handle {
			continue
		}
		rawMeta := trimUserDataPrefix(r.UserData)
		if len(rawMeta) == 0 {
			return fmt.Errorf("redirect rule metadata missing for handle %d", handle)
		}
		meta := ruleMetadata{}
		if err := json.Unmarshal(rawMeta, &meta); err != nil {
			return fmt.Errorf("decode metadata: %w", err)
		}
		redirect, err := redirectFromMetadata(r.Handle, meta)
		if err != nil {
			return err
		}
		if err := m.conn.DelRule(r); err != nil {
			return wrapNFTError("delete rule", err)
		}
		if err := m.deleteRuleByStage(m.postroutingChain, stagePostrouting, redirect); err != nil {
			return err
		}
		if err := m.deleteRuleByStage(m.outputChain, stageOutput, redirect); err != nil {
			return err
		}
		if err := m.conn.Flush(); err != nil {
			return wrapNFTError("flush after delete", err)
		}
		return nil
	}
	return fmt.Errorf("rule with handle %d not found", handle)
}

func trimUserDataPrefix(data []byte) []byte {
	if len(data) < len(userDataPrefix) {
		return nil
	}
	if !bytes.HasPrefix(data, []byte(userDataPrefix)) {
		return nil
	}
	trimmed := data[len(userDataPrefix):]
	return bytes.TrimRight(trimmed, "\x00")
}

func buildMetadata(rule RedirectRule, stage string) ruleMetadata {
	matchIP := ""
	if rule.MatchIP != nil {
		matchIP = rule.MatchIP.String()
	}
	meta := ruleMetadata{
		Description:    rule.Description,
		Protocol:       rule.Protocol,
		MatchIP:        matchIP,
		MatchInterface: rule.MatchInterface,
		MatchPort:      rule.MatchPort,
		TargetIP:       rule.TargetIP.String(),
		TargetPort:     rule.TargetPort,
		TailscalePeer:  rule.TailscalePeer,
	}
	if stage != "" {
		meta.Stage = stage
	}
	return meta
}

func marshalMetadata(meta ruleMetadata) ([]byte, error) {
	raw, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	return append([]byte(userDataPrefix), raw...), nil
}

func redirectFromMetadata(handle uint64, meta ruleMetadata) (RedirectRule, error) {
	var matchIP net.IP
	if meta.MatchIP != "" {
		matchIP = net.ParseIP(meta.MatchIP)
		if matchIP == nil {
			return RedirectRule{}, errors.New("invalid match IP in metadata")
		}
	}
	targetIP := net.ParseIP(meta.TargetIP)
	if targetIP == nil {
		return RedirectRule{}, errors.New("invalid target IP in metadata")
	}
	return RedirectRule{
		Handle:         handle,
		Description:    meta.Description,
		Protocol:       meta.Protocol,
		MatchIP:        matchIP,
		MatchInterface: meta.MatchInterface,
		MatchPort:      meta.MatchPort,
		TargetIP:       targetIP,
		TargetPort:     meta.TargetPort,
		TailscalePeer:  meta.TailscalePeer,
	}, nil
}

func metadataMatches(meta ruleMetadata, rule RedirectRule, expectedStage string) bool {
	if expectedStage != "" {
		if meta.Stage != "" && meta.Stage != expectedStage {
			return false
		}
	}
	if meta.MatchIP != ipToString(rule.MatchIP) {
		return false
	}
	if meta.MatchInterface != rule.MatchInterface {
		return false
	}
	if meta.TargetIP != ipToString(rule.TargetIP) {
		return false
	}
	if meta.MatchPort != rule.MatchPort || meta.TargetPort != rule.TargetPort {
		return false
	}
	if meta.Protocol != rule.Protocol {
		return false
	}
	return true
}

func (m *nftManager) deleteRuleByStage(chain *nftables.Chain, expectedStage string, rule RedirectRule) error {
	if chain == nil {
		return nil
	}
	stageRules, err := m.conn.GetRules(m.table, chain)
	if err != nil {
		return wrapNFTError(fmt.Sprintf("get %s rules", expectedStage), err)
	}
	for _, r := range stageRules {
		rawMeta := trimUserDataPrefix(r.UserData)
		if len(rawMeta) == 0 {
			continue
		}
		meta := ruleMetadata{}
		if err := json.Unmarshal(rawMeta, &meta); err != nil {
			continue
		}
		if !metadataMatches(meta, rule, expectedStage) {
			continue
		}
		if err := m.conn.DelRule(r); err != nil {
			return wrapNFTError(fmt.Sprintf("delete %s rule", expectedStage), err)
		}
		return nil
	}
	return nil
}

func matchInterfaceExprs(iface string, key expr.MetaKey) []expr.Any {
	if iface == "" {
		return nil
	}
	return []expr.Any{
		&expr.Meta{
			Key:      key,
			Register: 1,
		},
		&expr.Cmp{
			Register: 1,
			Op:       expr.CmpOpEq,
			Data:     ifaceBytes(iface),
		},
	}
}

func ifaceBytes(name string) []byte {
	buf := make([]byte, 16)
	copy(buf, []byte(name))
	return buf
}

func protoToNumber(proto Protocol) (byte, error) {
	switch proto {
	case ProtocolTCP:
		return 6, nil
	case ProtocolUDP:
		return 17, nil
	default:
		return 0, fmt.Errorf("unknown protocol %q", proto)
	}
}

func uint16ToBytes(v uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, v)
	return buf
}

func ipToString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func wrapNFTError(action string, err error) error {
	if err == nil {
		return nil
	}
	if isPermissionError(err) {
		return fmt.Errorf("%s: %w", action, ErrPermissionDenied)
	}
	return fmt.Errorf("%s: %w", action, err)
}

func isPermissionError(err error) bool {
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		return true
	}
	var opErr *netlink.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, unix.EPERM) || errors.Is(opErr.Err, unix.EACCES) {
			return true
		}
	}
	return false
}

func findChain(chains []*nftables.Chain, name, table string) *nftables.Chain {
	for _, c := range chains {
		if c == nil {
			continue
		}
		if c.Name == name && c.Table != nil && c.Table.Name == table {
			return c
		}
	}
	return nil
}
