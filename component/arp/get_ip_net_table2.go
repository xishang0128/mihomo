//go:build windows
// +build windows

package arp

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var iphlpapi *windows.DLL

func init() {
	iphlpapi = windows.MustLoadDLL("Iphlpapi.dll")
}

func GetIpNetTable2() (MIBIpNetTable2, error) {
	proc, err := iphlpapi.FindProc("GetIpNetTable2")
	if err != nil {
		return nil, err
	}

	free, err := iphlpapi.FindProc("FreeMibTable")
	if err != nil {
		return nil, err
	}

	var data *rawMIBIpNetTable2
	errno, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&data)))
	defer free.Call(uintptr(unsafe.Pointer(data)))

	switch syscall.Errno(errno) {
	case windows.ERROR_SUCCESS:
		err = nil
	case windows.ERROR_NOT_ENOUGH_MEMORY:
		err = fmt.Errorf("insufficient memory resources are available to complete the operation")
	case windows.ERROR_INVALID_PARAMETER:
		err = fmt.Errorf("an invalid parameter was passed to the function")
	case windows.ERROR_NOT_FOUND:
		err = fmt.Errorf("no neighbor IP address entries as specified in the Family parameter were found")
	case windows.ERROR_NOT_SUPPORTED:
		err = fmt.Errorf("the IPv4 or IPv6 transports are not configured on the local computer")
	default:
		err = windows.GetLastError()
	}

	table := data.parse()
	return table, err
}
