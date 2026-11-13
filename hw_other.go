//go:build !windows

package main

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

func cpuCount() int { return runtime.NumCPU() }

// physicalMemoryMB 读 /proc/meminfo（Linux / WSL）
func physicalMemoryMB() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 {
			if kb, err := strconv.Atoi(f[1]); err == nil {
				return kb / 1024
			}
		}
	}
	return 0
}

// isElevated Linux 下等价于 euid == 0（masscan 需要 CAP_NET_RAW）
func isElevated() bool { return os.Geteuid() == 0 }
