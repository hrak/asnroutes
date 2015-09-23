// Network utility functions. These are borrowed from docker/libnetwork.
package netutils

import (
	"net"
)

// NetworkOverlaps detects overlap between one IPNet and another
func NetworkOverlaps(netX *net.IPNet, netY *net.IPNet) bool {
	// Check if both netX and netY are ipv4 or ipv6
	if (netX.IP.To4() != nil && netY.IP.To4() != nil) ||
		(netX.IP.To4() == nil && netY.IP.To4() == nil) {
		if firstIP, _ := NetworkRange(netX); netY.Contains(firstIP) {
			return true
		}
		if firstIP, _ := NetworkRange(netY); netX.Contains(firstIP) {
			return true
		}
	}
	return false
}

// NetworkRange calculates the first and last IP addresses in an IPNet
func NetworkRange(network *net.IPNet) (net.IP, net.IP) {
	var netIP net.IP
	if network.IP.To4() != nil {
		netIP = network.IP.To4()
	} else if network.IP.To16() != nil {
		netIP = network.IP.To16()
	} else {
		return nil, nil
	}

	lastIP := make([]byte, len(netIP), len(netIP))
	for i := 0; i < len(netIP); i++ {
		lastIP[i] = netIP[i] | ^network.Mask[i]
	}
	return netIP.Mask(network.Mask), net.IP(lastIP)
}
