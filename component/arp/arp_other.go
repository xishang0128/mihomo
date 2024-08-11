//go:build !linux && !windows

package arp

func GetARPTable() (map[string]string, error) {
	return nil, nil
}
