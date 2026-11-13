//go:build windows

package main

import (
	"runtime"
	"syscall"
	"unsafe"
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// physicalMemoryMB 取物理内存总量（MB）；失败返回 0
func physicalMemoryMB() int {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	proc := kernel32.NewProc("GlobalMemoryStatusEx")
	if r, _, _ := proc.Call(uintptr(unsafe.Pointer(&m))); r == 0 {
		return 0
	}
	return int(m.TotalPhys / (1024 * 1024))
}

func cpuCount() int { return runtime.NumCPU() }

// isElevated 用 TokenElevation 判断当前进程是否已提权
func isElevated() bool {
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	openProcessToken := advapi32.NewProc("OpenProcessToken")
	getTokenInformation := advapi32.NewProc("GetTokenInformation")

	const tokenQuery = 0x0008
	const tokenElevation = 20

	hProc, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}
	var token syscall.Handle
	if r, _, _ := openProcessToken.Call(uintptr(hProc), tokenQuery, uintptr(unsafe.Pointer(&token))); r == 0 {
		return false
	}
	defer syscall.CloseHandle(token)

	var elevated uint32
	var retLen uint32
	if r, _, _ := getTokenInformation.Call(
		uintptr(token), tokenElevation,
		uintptr(unsafe.Pointer(&elevated)),
		unsafe.Sizeof(elevated),
		uintptr(unsafe.Pointer(&retLen)),
	); r == 0 {
		return false
	}
	return elevated != 0
}
