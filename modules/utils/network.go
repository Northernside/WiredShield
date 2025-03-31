package utils

import (
	"net"
	"wired/modules/logger"
)

func GetListeners() []net.IP {
	listeners := []net.IP{}

	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Log("failed to get network interfaces:", err)
		return listeners
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			logger.Log("failed to get addresses for interface:", iface.Name, err)
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() {
				continue
			}

			listeners = append(listeners, ipNet.IP)
		}
	}

	return listeners
}
