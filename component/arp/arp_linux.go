package arp

import (
	"fmt"
	"net"

	"github.com/sagernet/netlink"
)

func neighMAC(n netlink.Neigh) string {
	return n.HardwareAddr.String()
}

func neighIP(n netlink.Neigh) net.IP {
	return n.IP
}

func GetARPTable() (map[string]string, error) {
	entries := make(map[string]string)

	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	for _, link := range links {
		attr := link.Attrs()
		neighs, err := netlink.NeighList(attr.Index, 0)
		if err != nil {
			fmt.Println(err)
			continue
		}
		for _, neigh := range neighs {
			ip := neighIP(neigh)
			mac := neighMAC(neigh)

			if IsReserved(ip) {
				continue
			}

			if ip.IsGlobalUnicast() {
				entries[ip.String()] = mac
			}
		}
	}
	return entries, nil
}
