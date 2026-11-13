package main

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const defaultPorts = "443,8443,2053,2083,2087,2096"

var portRe = regexp.MustCompile(`^\d{1,5}$`)

// parsePorts 支持 "443" / "443,8443" / "1-1000" / 混合，去重排序。
func parsePorts(s string) ([]uint16, error) {
	seen := map[uint16]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			ab := strings.SplitN(part, "-", 2)
			a, err1 := strconv.Atoi(strings.TrimSpace(ab[0]))
			b, err2 := strconv.Atoi(strings.TrimSpace(ab[1]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("端口段无效: %q", part)
			}
			if a < 1 || b > 65535 || a > b {
				return nil, fmt.Errorf("端口段越界: %q", part)
			}
			for p := a; p <= b; p++ {
				seen[uint16(p)] = true
			}
			continue
		}
		if !portRe.MatchString(part) {
			return nil, fmt.Errorf("端口无效: %q", part)
		}
		p, _ := strconv.Atoi(part)
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("端口越界: %q", part)
		}
		seen[uint16(p)] = true
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("端口列表为空")
	}
	out := make([]uint16, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func portsString(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	return strings.Join(parts, ",")
}

func defaultPortsFromFile() string {
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "ports.txt")
		if data, err := os.ReadFile(p); err == nil {
			var out []string
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				out = append(out, line)
			}
			if len(out) > 0 {
				return strings.Join(out, ",")
			}
		}
	}
	return defaultPorts
}

// ---------- 前置检查：只确认 masscan 与提权状态，不再探测抓包驱动 ----------

func preflight(cfg *config) (string, error) {
	bin, err := resolveMasscan(cfg.masscanPath)
	if err != nil {
		return "", err
	}
	if cfg.noPreflight {
		return bin, nil
	}
	if !isElevated() {
		return "", fmt.Errorf("当前进程不是管理员：masscan 在 Windows 上需要提权才能打开发包设备。\n" +
			"     右键 Windows Terminal / PowerShell → “以管理员身份运行”，再执行本命令\n" +
			"     （若你的 masscan 已由服务/计划任务以高权限拉起，可加 -no-preflight 跳过此检查）")
	}
	return bin, nil
}

func resolveMasscan(explicit string) (string, error) {
	candidates := []string{}
	if explicit != "" {
		candidates = append(candidates, explicit)
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "masscan.exe"),
			filepath.Join(dir, "masscan", "masscan.exe"),
		)
	}
	candidates = append(candidates, "masscan.exe", "masscan")

	for _, c := range candidates {
		if strings.ContainsAny(c, `\/`) || strings.HasSuffix(strings.ToLower(c), ".exe") {
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				return c, nil
			}
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("未找到 masscan.exe：\n" +
		"     把它放到 asnip.exe 同目录（或同目录的 masscan\\ 子目录），或在 PATH 中，\n" +
		"     或用 -masscan D:\\tools\\masscan.exe 指定绝对路径")
}

// ---------- masscan 扫描（CIDR 直接 -iL，无 prips 展开）----------

var masscanPctRe = regexp.MustCompile(`([\d.]+)%\s*done`)

func masscanScan(ctx context.Context, entries []prefixEntry, ports []uint16, cfg *config, dir string) ([]string, error) {
	bin, err := preflight(cfg)
	if err != nil {
		return nil, err
	}

	scanEntries := entries
	if cfg.limit > 0 {
		total := totalAddrs(entries)
		if total > cfg.limit {
			scanEntries = trimPrefixes(entries, cfg.limit)
			info("-limit %s：前缀裁剪为 %s 段 / %s 个地址",
				humanInt(cfg.limit), humanInt(int64(len(scanEntries))), humanInt(totalAddrs(scanEntries)))
		}
	}
	cidrFile := filepath.Join(dir, "cidrs_scan.txt")
	if err := writeCIDRFile(cidrFile, scanEntries); err != nil {
		return nil, err
	}

	rawFile := filepath.Join(dir, "masscan_raw.txt")
	_ = os.Remove(rawFile)

	args := []string{
		"-iL", cidrFile,
		"-p", portsString(ports),
		"--rate", strconv.Itoa(cfg.rate),
		"-oL", rawFile,
		"--wait", "5",
	}
	args = append(args, cfg.masscanExtra...)
	info("masscan: %s %s", bin, strings.Join(args, " "))

	cmd := exec.CommandContext(ctx, bin, args...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	prog := newProgress("masscan", 100)
	doneScan := make(chan struct{})
	var tail []string
	var tailMu sync.Mutex
	var lastPct float64

	go func() {
		defer close(doneScan)
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 0, 64*1024), 256*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			tailMu.Lock()
			tail = append(tail, line)
			if len(tail) > 20 {
				tail = tail[len(tail)-20:]
			}
			tailMu.Unlock()

			for _, m := range masscanPctRe.FindAllStringSubmatch(line, 1) {
				if v, err := strconv.ParseFloat(m[1], 64); err == nil {
					if v-lastPct >= 0.5 || v >= 100 {
						lastPct = v
						prog.setPct(v)
					}
				}
			}
		}
	}()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动 masscan 失败: %w", err)
	}
	werr := cmd.Wait()
	<-doneScan
	prog.finish("masscan 完成")

	if werr != nil {
		tailMu.Lock()
		lines := strings.Join(tail, "\n     ")
		tailMu.Unlock()
		hint := ""
		low := strings.ToLower(lines)
		switch {
		case strings.Contains(low, "npcap") || strings.Contains(low, "wpcap") || strings.Contains(low, "winpcap"):
			hint = "\n     → masscan 打不开发包设备：按其输出处理驱动问题（本工具不做预检）"
		case strings.Contains(low, "could not determine default interface") || strings.Contains(low, "adapter"):
			hint = "\n     → 多网卡/虚拟网卡环境下需指定出口，例如：-masscan-args \"--adapter-ip 192.168.1.10 --router-mac aa:bb:cc:dd:ee:ff\""
		case strings.Contains(low, "permission") || strings.Contains(low, "access is denied"):
			hint = "\n     → 需要管理员权限运行"
		case strings.Contains(low, "no such file") || strings.Contains(low, "cannot open"):
			hint = "\n     → 检查 CIDR 文件与 -oL 输出路径是否可写"
		}
		return nil, fmt.Errorf("masscan 退出异常（%v）:\n     %s%s", werr, lines, hint)
	}

	open, err := parseMasscanOutput(rawFile)
	if err != nil {
		return nil, err
	}
	ok("masscan 开放端口 %s 个", humanInt(int64(len(open))))
	if err := writeLines(filepath.Join(dir, "open.txt"), open); err != nil {
		return nil, err
	}
	return open, nil
}

func writeCIDRFile(path string, entries []prefixEntry) error {
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.Prefix.String())
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// trimPrefixes 把前缀列表裁剪到不超过 budget 个地址：
// 放不下的前缀二分拆开，深度优先取前段，保证结果确定且地址数可控。
func trimPrefixes(entries []prefixEntry, budget int64) []prefixEntry {
	type item struct {
		p   netip.Prefix
		asn string
	}
	queue := make([]item, 0, len(entries))
	for _, e := range entries {
		queue = append(queue, item{e.Prefix, e.ASN})
	}

	var out []prefixEntry
	for len(queue) > 0 && budget > 0 {
		it := queue[0]
		queue = queue[1:]

		n := ipCount(it.p)
		if n <= budget {
			out = append(out, prefixEntry{Prefix: it.p, ASN: it.asn})
			budget -= n
			continue
		}
		if it.p.Bits() >= 32 {
			break
		}
		lo, hi := splitPrefix(it.p)
		queue = append([]item{{lo, it.asn}, {hi, it.asn}}, queue...)
	}
	return out
}

func splitPrefix(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	lo := netip.PrefixFrom(p.Addr(), p.Bits()+1).Masked()
	b := lo.Addr().As4()
	idx := p.Bits() / 8
	bit := uint(7 - (p.Bits() % 8))
	b[idx] ^= 1 << bit
	hi := netip.PrefixFrom(netip.AddrFrom4(b), p.Bits()+1).Masked()
	return lo, hi
}

func parseMasscanOutput(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("读不到 masscan 输出: %w", err)
	}
	defer f.Close()

	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[0] != "open" {
			continue
		}
		// 格式: open <proto> <port> <ip> <timestamp>
		port, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		ip, err := netip.ParseAddr(fields[3])
		if err != nil {
			continue
		}
		t := netip.AddrPortFrom(ip, uint16(port)).String()
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sortTargets(out)
	return out, sc.Err()
}

// ---------- 通用 ----------

func sortTargets(list []string) {
	sort.Slice(list, func(i, j int) bool {
		ai, api, ok1 := splitTarget(list[i])
		aj, apj, ok2 := splitTarget(list[j])
		if ok1 && ok2 {
			if ai != aj {
				return ai.Less(aj)
			}
			return api < apj
		}
		return list[i] < list[j]
	})
}

func splitTarget(t string) (netip.Addr, uint16, bool) {
	ap, err := netip.ParseAddrPort(t)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	return ap.Addr(), ap.Port(), true
}

func writeLines(path string, lines []string) error {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

func readOpen(dir string) ([]string, error) {
	open, err := readLines(filepath.Join(dir, "open.txt"))
	if err != nil {
		return nil, fmt.Errorf("缺少 open.txt（先跑 scan 阶段）")
	}
	return open, nil
}
