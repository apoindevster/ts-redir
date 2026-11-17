package dnsforward

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

func Discover(ctx context.Context, listenIP string) ([]string, error) {
	iface, err := interfaceForIP(listenIP)
	if err != nil {
		return nil, err
	}
	// Interface index is an integer obtained from the OS, never shell input.
	script := fmt.Sprintf("$ErrorActionPreference='Stop'; $v=@(Get-DnsClientServerAddress -InterfaceIndex %d | ForEach-Object { $_.ServerAddresses }); ConvertTo-Json -InputObject $v -Compress", iface.Index)
	data, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return nil, fmt.Errorf("read LAN DNS servers: %w", err)
	}
	var servers []string
	if err := json.Unmarshal(data, &servers); err != nil {
		return nil, err
	}
	return filterUpstreams(withInterfaceZone(servers, iface), listenIP)
}
