package utils

import (
	"net"
	"strings"
	"wired/modules/logger"
)

func GetListeners() []net.IP {
	listeners := []net.IP{}

	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Println("Failed to get network interfaces:", err)
		return listeners
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			logger.Println("Failed to get addresses for interface:", iface.Name, err)
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() {
				continue
			}

			if ipNet.IP.IsGlobalUnicast() {
				listeners = append(listeners, ipNet.IP)
			}
		}
	}

	return listeners
}

func IsIPv4(ip net.IP) bool {
	return strings.Count(ip.String(), ":") < 2
}

func IsIPv6(ip net.IP) bool {
	return strings.Count(ip.String(), ":") >= 2
}
