package app

import "net"

// LANAddress is an assigned private IPv4 address suitable for the DNS listener.
type LANAddress struct {
	IP        string `json:"ip"`
	Interface string `json:"interface"`
}

// LANAddresses is shared by both management interfaces.
func LANAddresses(excludeInterface string) ([]LANAddress, error) {
	addresses := []LANAddress{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Name == excludeInterface || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err == nil && ip.To4() != nil && ip.IsPrivate() {
				addresses = append(addresses, LANAddress{IP: ip.String(), Interface: iface.Name})
			}
		}
	}
	return addresses, nil
}
