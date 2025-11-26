//go:build windows

package firewall

import (
	"bufio"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// ErrPermissionDenied indicates the caller lacks Administrator privileges.
var ErrPermissionDenied = errors.New("netsh interface portproxy requires administrator privileges")

type netshManager struct{}

func newManager() (Manager, error) { return &netshManager{}, nil }

func (m *netshManager) Close() error { return nil }

func (m *netshManager) ListRedirectRules() ([]RedirectRule, error) {
	output, err := exec.Command("netsh", "interface", "portproxy", "dump").CombinedOutput()
	if err != nil {
		return nil, wrapNetshError("list rules", err, output)
	}
	return parsePortProxyDump(string(output)), nil
}

func (m *netshManager) RuleExists(rule RedirectRule) (bool, error) {
	normalized, err := m.normalizeRule(rule)
	if err != nil {
		return false, err
	}
	current, err := m.ListRedirectRules()
	if err != nil {
		return false, err
	}
	key := ruleKey(normalized)
	for _, r := range current {
		if ruleKey(r) == key {
			return true, nil
		}
	}
	return false, nil
}

func (m *netshManager) AddRedirectRule(rule RedirectRule) error {
	if err := validateRule(rule); err != nil {
		return err
	}
	normalized, err := m.normalizeRule(rule)
	if err != nil {
		return err
	}
	if exists, err := m.RuleExists(rule); err != nil {
		return err
	} else if exists {
		return ErrDuplicateRule
	}

	args := []string{
		"interface", "portproxy", "add", "v4tov4",
		fmt.Sprintf("listenaddress=%s", normalized.MatchIP.String()),
		fmt.Sprintf("listenport=%d", normalized.MatchPort),
		fmt.Sprintf("connectaddress=%s", normalized.TargetIP.String()),
		fmt.Sprintf("connectport=%d", normalized.TargetPort),
		fmt.Sprintf("protocol=%s", strings.ToLower(string(normalized.Protocol))),
	}
	return runNetsh(args, "add rule")
}

func (m *netshManager) DeleteRedirectRule(handle uint64) error {
	rules, err := m.ListRedirectRules()
	if err != nil {
		return err
	}
	var target *RedirectRule
	for i, r := range rules {
		if r.Handle == handle {
			target = &rules[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("rule with handle %d not found", handle)
	}

	args := []string{
		"interface", "portproxy", "delete", "v4tov4",
		fmt.Sprintf("listenaddress=%s", target.MatchIP.String()),
		fmt.Sprintf("listenport=%d", target.MatchPort),
		fmt.Sprintf("protocol=%s", strings.ToLower(string(target.Protocol))),
	}
	return runNetsh(args, "delete rule")
}

func (m *netshManager) normalizeRule(rule RedirectRule) (RedirectRule, error) {
	normalized := rule
	normalized.Description = ""
	normalized.TailscalePeer = ""
	normalized.MatchInterface = ""

	listenIP := rule.MatchIP
	if listenIP == nil {
		ip, err := interfaceIPv4(rule.MatchInterface)
		if err != nil {
			return RedirectRule{}, err
		}
		listenIP = ip
	}
	if listenIP == nil || listenIP.To4() == nil {
		return RedirectRule{}, errors.New("listen address must be a valid IPv4 address")
	}
	if rule.TargetIP == nil || rule.TargetIP.To4() == nil {
		return RedirectRule{}, errors.New("target IP must be a valid IPv4 address")
	}
	normalized.MatchIP = listenIP.To4()
	normalized.TargetIP = rule.TargetIP.To4()
	return normalized, nil
}

func parsePortProxyDump(output string) []RedirectRule {
	scanner := bufio.NewScanner(strings.NewReader(output))
	var rules []RedirectRule
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(line), "add ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.ToLower(fields[1]) != "v4tov4" {
			continue
		}
		params := parseKeyValueFields(fields[2:])
		rule, ok := ruleFromParams(params)
		if !ok {
			continue
		}
		rules = append(rules, rule)
	}
	return rules
}

func parseKeyValueFields(fields []string) map[string]string {
	values := make(map[string]string)
	for _, f := range fields {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		values[key] = strings.TrimSpace(parts[1])
	}
	return values
}

func ruleFromParams(params map[string]string) (RedirectRule, bool) {
	listenAddr := params["listenaddress"]
	connectAddr := params["connectaddress"]
	if listenAddr == "" || connectAddr == "" {
		return RedirectRule{}, false
	}
	listenIP := net.ParseIP(listenAddr)
	targetIP := net.ParseIP(connectAddr)
	if listenIP == nil || targetIP == nil {
		return RedirectRule{}, false
	}

	listenPort, err := strconv.ParseUint(params["listenport"], 10, 16)
	if err != nil {
		return RedirectRule{}, false
	}
	targetPort, err := strconv.ParseUint(params["connectport"], 10, 16)
	if err != nil {
		return RedirectRule{}, false
	}

	proto := protocolFromString(params["protocol"])
	rule := RedirectRule{
		Protocol:   proto,
		MatchIP:    listenIP.To4(),
		MatchPort:  uint16(listenPort),
		TargetIP:   targetIP.To4(),
		TargetPort: uint16(targetPort),
	}
	rule.Handle = computeHandle(rule)
	return rule, true
}

func protocolFromString(value string) Protocol {
	switch strings.ToLower(value) {
	case "udp":
		return ProtocolUDP
	default:
		return ProtocolTCP
	}
}

func computeHandle(rule RedirectRule) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(ruleKey(rule)))
	return h.Sum64()
}

func interfaceIPv4(name string) (net.IP, error) {
	if name == "" {
		return nil, errors.New("match interface must be provided when no listen address is specified")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %q: %w", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("list addresses for %q: %w", name, err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if v4 := ipnet.IP.To4(); v4 != nil {
				return v4, nil
			}
		}
	}
	return nil, fmt.Errorf("interface %q has no IPv4 address", name)
}

func runNetsh(args []string, action string) error {
	output, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return wrapNetshError(action, err, output)
	}
	return nil
}

func wrapNetshError(action string, err error, output []byte) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(string(output))
	if strings.Contains(msg, "access is denied") || strings.Contains(msg, "requires elevation") {
		return fmt.Errorf("%s: %w", action, ErrPermissionDenied)
	}
	return fmt.Errorf("%s: %w", action, err)
}
