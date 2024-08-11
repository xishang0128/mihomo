package arp

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/log"
)

var (
	table          map[string]string
	failedIPs      map[string]int
	mu             sync.RWMutex
	failedIPsMutex sync.RWMutex
	lastFetch      time.Time
)

type ARPEntry struct {
	IP  net.IP
	MAC net.HardwareAddr
}

const refreshInterval = 5 * time.Minute

func init() {
	table = make(map[string]string)
	failedIPs = make(map[string]int)
}

func IsReserved(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[3] == 0 || ip4[3] == 255
	}
	return false
}

func refreshARPTable() {
	newTable, err := GetARPTable()
	if err != nil {
		log.Warnln("Failed to refresh ARP table")
		return
	}

	mu.Lock()
	defer mu.Unlock()

	table = newTable
	lastFetch = time.Now()
}

func IPToMac(ip netip.Addr) string {
	if ok, _ := iface.IsLocalIp(ip); ok {
		return ""
	}

	mu.RLock()
	if time.Since(lastFetch) > refreshInterval {
		mu.RUnlock()
		refreshARPTable()
		mu.RLock()
	}
	defer mu.RUnlock()

	if mac, ok := table[ip.String()]; ok {
		return mac
	}

	if ip.IsPrivate() {
		failedIPsMutex.RLock()
		failCount, exists := failedIPs[ip.String()]
		failedIPsMutex.RUnlock()
		if exists && failCount >= 10 {
			return ""
		}

		mu.RUnlock()
		refreshARPTable()
		mu.RLock()

		if mac, ok := table[ip.String()]; ok {
			return mac
		} else {
			failedIPs[ip.String()]++
		}
	}

	return ""
}
