//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleMode     = kernel32.NewProc("SetConsoleMode")
	procGetConsoleMode     = kernel32.NewProc("GetConsoleMode")
	procSetConsoleOutputCP = kernel32.NewProc("SetConsoleOutputCP")
	procSetConsoleCP       = kernel32.NewProc("SetConsoleCP")
)

const enableVirtualTerminalProcessing = 0x0004

// initConsole 在 Windows 控制台开启 ANSI 转义处理 + UTF-8 代码页（65001），
// 否则中文与进度条会乱码。失败时静默降级（重定向到文件/管道时正常）。
func initConsole() {
	procSetConsoleOutputCP.Call(65001)
	procSetConsoleCP.Call(65001)

	h, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err != nil || h == 0 || h == syscall.InvalidHandle {
		return
	}
	var mode uint32
	if r, _, _ := procGetConsoleMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode))); r == 0 {
		return
	}
	procSetConsoleMode.Call(uintptr(h), uintptr(mode|enableVirtualTerminalProcessing))

	if hi, err := syscall.GetStdHandle(syscall.STD_ERROR_HANDLE); err == nil && hi != 0 {
		var m2 uint32
		if r, _, _ := procGetConsoleMode.Call(uintptr(hi), uintptr(unsafe.Pointer(&m2))); r != 0 {
			procSetConsoleMode.Call(uintptr(hi), uintptr(m2|enableVirtualTerminalProcessing))
		}
	}
}

// consoleWidth 取控制台宽度（取不到就用 80）
func consoleWidth() int {
	h, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err != nil || h == 0 {
		return 80
	}
	var info struct {
		Size              [2]int16
		CursorPosition    [2]int16
		Attributes        uint16
		Window            [4]int16
		MaximumWindowSize [2]int16
	}
	proc := kernel32.NewProc("GetConsoleScreenBufferInfo")
	if r, _, _ := proc.Call(uintptr(h), uintptr(unsafe.Pointer(&info))); r == 0 {
		return 80
	}
	w := int(info.Window[2]-info.Window[0]) + 1
	if w < 60 {
		return 80
	}
	return w
}
