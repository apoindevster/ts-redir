//go:build windows

package firewall

import (
	"bufio"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// ErrPermissionDenied indicates the caller lacks Administrator privileges.
var ErrPermissionDenied = errors.New("netsh interface portproxy requires administrator privileges")

type netshManager struct{}

func newManager() (Manager, error) { return &netshManager{}, nil }

func (m *netshManager) Close() error { return nil }

func (m *netshManager) ListRedirectRules() ([]RedirectRule, error) {
	output, err := exec.Command("netsh", "interface", "portproxy", "show", "all").CombinedOutput()
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
	re := regexp.MustCompile(`^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$`)
	headerSkipped := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "---") {
			headerSkipped = true
			continue
		}

		// Only continue if we are passed the header
		if !headerSkipped {
			continue
		}

		// If we don't find a match, continue
		if match := re.FindStringSubmatch(line); match == nil {
			fmt.Println("Failed to match the output needed")
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			fmt.Println("Not enough fields")
			continue
		}
		params := parseRedirectRuleFromOutput(fields)
		rule, ok := ruleFromParams(params)
		if !ok {
			continue
		}
		rules = append(rules, rule)
	}
	return rules
}

func parseRedirectRuleFromOutput(fields []string) map[string]string {
	values := make(map[string]string)
	for i, f := range fields {
		switch i {
		case 0:
			values["listenaddress"] = strings.TrimSpace(f)
			break
		case 1:
			values["listenport"] = strings.TrimSpace(f)
			break
		case 2:
			values["connectaddress"] = strings.TrimSpace(f)
			break
		case 3:
			values["connectport"] = strings.TrimSpace(f)
			break
		}
	}
	return values
}

func ruleFromParams(params map[string]string) (RedirectRule, bool) {
	var listenIP net.IP = nil
	listenAddr := params["listenaddress"]

	if listenAddr != "" {
		listenIP = net.ParseIP(listenAddr)
	}

	connectAddr := params["connectaddress"]
	if connectAddr == "" {
		return RedirectRule{}, false
	}

	targetIP := net.ParseIP(connectAddr)

	if targetIP == nil {
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
		MatchIP:    listenIP,
		MatchPort:  uint16(listenPort),
		TargetIP:   targetIP,
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
	// Reduced precision because browser side loses some precision in the number.
	// Should have no collisions at 32 bits for this project
	h := fnv.New32a()
	_, _ = h.Write([]byte(windowsRuleKey(rule)))
	out := h.Sum32()
	return uint64(out)
}

func windowsRuleKey(rule RedirectRule) string {
	ip := ipToString(rule.MatchIP)
	target := ipToString(rule.TargetIP)
	return strings.Join([]string{
		ip,
		fmt.Sprintf("%d", rule.MatchPort),
		target,
		fmt.Sprintf("%d", rule.TargetPort),
	}, "|")
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
