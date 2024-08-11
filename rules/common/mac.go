package common

import (
	"fmt"
	"regexp"
	"runtime"
	"strings"

	"github.com/metacubex/mihomo/component/arp"
	C "github.com/metacubex/mihomo/constant"
)

type Mac struct {
	*Base
	mac     string
	adapter string
}

func (m *Mac) RuleType() C.RuleType {
	return C.Mac
}

func (m *Mac) Match(metadata *C.Metadata) (bool, string) {
	if runtime.GOOS == "windows" || runtime.GOOS == "linux" {
		if arp.IPToMac(metadata.SrcIP) == m.mac {
			return true, m.adapter
		}
	}
	return false, m.adapter
}

func (m *Mac) Adapter() string {
	return m.adapter
}

func (m *Mac) Payload() string {
	return m.mac
}

func NewMAC(mac string, adapter string) (*Mac, error) {
	mac = regexp.MustCompile(`[^a-fA-F0-9]`).ReplaceAllString(mac, "")
	if len(mac) != 12 {
		return nil, fmt.Errorf("invalid MAC address length")
	}
	formattedMAC := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		mac[0:2], mac[2:4], mac[4:6], mac[6:8], mac[8:10], mac[10:12])
	return &Mac{
		Base:    &Base{},
		mac:     strings.ToLower(formattedMAC),
		adapter: adapter,
	}, nil
}
