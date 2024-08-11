//go:build windows
// +build windows

package arp

const anySize = 1 << 16

type MIBIpNetTable2 []MIBIpNetRow2

type rawMIBIpNetTable2 struct {
	numEntries uint32
	padding    uint32
	table      [anySize]rawMIBIpNetRow2
}

func (r *rawMIBIpNetTable2) parse() MIBIpNetTable2 {
	t := make([]MIBIpNetRow2, r.numEntries)
	for i := 0; i < int(r.numEntries); i++ {
		t[i] = r.table[i].Parse()
	}
	return t
}
