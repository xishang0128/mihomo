//go:build windows
// +build windows

package arp

import (
	"encoding/binary"
	"net"
	"time"
)

const MIBIpNetRow2Size = 88
const SockAddrSize = 28

type SockAddrIn struct {
	sinFamily uint16
	sinPort   uint16
	sinAddr   net.IP
	sinZero   []byte
}

func NewSockAddrIn(buffer []byte) SockAddrIn {
	addr := SockAddrIn{
		sinFamily: binary.LittleEndian.Uint16(buffer[:2]),
		sinPort:   binary.LittleEndian.Uint16(buffer[2:4]),
		sinAddr:   net.IP(make([]byte, 4)).To4(),
		sinZero:   make([]byte, 8),
	}
	copy(addr.sinAddr, buffer[4:8])
	copy(addr.sinZero, buffer[8:16])
	return addr
}

func (s SockAddrIn) Family() uint16 {
	return s.sinFamily
}

func (s SockAddrIn) Addr() net.IP {
	return s.sinAddr.To4()
}

type SockAddrIn6 struct {
	sin6Family   uint16
	sin6Port     uint16
	sin6FlowInfo uint32
	sin6Addr     net.IP
	sin6ScopeId  uint32
}

func NewSockAddrIn6(buffer []byte) SockAddrIn6 {
	addr := SockAddrIn6{
		sin6Family:   binary.LittleEndian.Uint16(buffer[:2]),
		sin6Port:     binary.LittleEndian.Uint16(buffer[2:4]),
		sin6FlowInfo: binary.LittleEndian.Uint32(buffer[4:8]),
		sin6Addr:     net.IP(make([]byte, 16)).To16(),
		sin6ScopeId:  binary.LittleEndian.Uint32(buffer[24:28]),
	}
	copy(addr.sin6Addr, buffer[8:24])
	return addr
}

func (s SockAddrIn6) Family() uint16 {
	return s.sin6Family
}

func (s SockAddrIn6) Addr() net.IP {
	return s.sin6Addr.To16()
}

type SockAddr interface {
	Family() uint16
	Addr() net.IP
}

func parseSockAddr(buffer []byte) SockAddr {
	sockType := binary.LittleEndian.Uint16(buffer[:2])
	switch sockType {
	case 2: // IPv4
		return NewSockAddrIn(buffer[:SockAddrSize])
	case 23: // IPv6
		return NewSockAddrIn6(buffer[:SockAddrSize])
	default:
		return nil
	}
}

func parsePhysicalAddress(buffer []byte, physicalAddressLength uint32) net.HardwareAddr {
	pa := make(net.HardwareAddr, physicalAddressLength)
	copy(pa, buffer[:physicalAddressLength])
	return pa
}

type MIBIpNetRow2 struct {
	address               SockAddr
	interfaceIndex        uint32
	interfaceLuid         uint64
	physicalAddress       net.HardwareAddr
	physicalAddressLength uint32
	flags                 uint32
	reachabilityTime      time.Duration
}

func (r MIBIpNetRow2) MAC() net.HardwareAddr {
	mac := make(net.HardwareAddr, r.physicalAddressLength)
	copy(mac, r.physicalAddress)
	return mac
}

func (r MIBIpNetRow2) IP() net.IP {
	length := len(r.address.Addr())
	ip := make(net.IP, length)
	copy(ip, r.address.Addr())
	return ip
}

func (r MIBIpNetRow2) ToARPEntry() ARPEntry {
	return ARPEntry{
		MAC: r.MAC(),
		IP:  r.IP(),
	}
}

type rawMIBIpNetRow2 struct {
	address               [28]byte
	interfaceIndex        uint32
	interfaceLuid         uint64
	physicalAddress       [32]byte
	physicalAddressLength uint32
	flags                 uint32
	reachabilityTime      uint32
}

func (r rawMIBIpNetRow2) Parse() MIBIpNetRow2 {
	return MIBIpNetRow2{
		address:               parseSockAddr(r.address[:]),
		interfaceIndex:        r.interfaceIndex,
		interfaceLuid:         r.interfaceLuid,
		physicalAddress:       parsePhysicalAddress(r.physicalAddress[:], r.physicalAddressLength),
		physicalAddressLength: r.physicalAddressLength,
		flags:                 r.flags,
		reachabilityTime:      time.Duration(r.reachabilityTime * uint32(time.Millisecond)),
	}
}
