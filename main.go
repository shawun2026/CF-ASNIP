package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const version = "2.3.0"

type config struct {
	asns    []string
	ports   []uint16
	portsRaw string

	masscanPath  string
	masscanExtra []string
	rate         int
	limit        int64
	maxIPs       int64
	force        bool
	noPreflight  bool

	cfConc    int
	cfTimeout time.Duration
	sni       string
	host      string

	api        string
	batch      int
	vconc      int
	apiTimeout time.Duration

	dir    string
	stages map[string]bool
	serve    bool
	bind     string
	httpPort int
	serveWait time.Duration
	all      bool

	autoTune bool
	tuneNote string
}

var validStages = []string{"asn", "scan", "cfscan", "verify", "out"}

func usage() {
	fmt.Printf(`%s — ASN → CIDR → 端口扫描 → CF 粗筛 → API 精筛 → CSV

%s
  asnip 209242
  asnip 209242,3214 -p 443,8443
  asnip 209242 -rate 10000
  asnip 209242 -masscan /usr/local/bin/masscan
  asnip -rundir runs/20261113_150000_AS209242 -stages verify,out
  asnip doctor                       # 环境自检
  asnip version

%s
  -p            端口，支持 443 / 443,8443 / 1000-2000（默认读 ports.txt）
  -masscan      masscan 可执行文件路径（默认 exe 同目录 / PATH）
  -masscan-args 追加给 masscan 的原始参数，如 "--adapter-ip 1.2.3.4 --router-mac aa:bb:.."
  -rate         masscan 速率（pps），默认按 CPU 核数自动
  -limit        只扫前 N 个地址（裁剪前缀，冒烟测试用，0=不限）
  -max-ips      地址数守卫阈值，默认 2000000
  -force        忽略 max-ips 守卫
  -no-preflight 跳过 masscan 路径与管理员检查（自定义封装时用）

  -cf-conc      粗筛并发，默认按硬件自动
  -cf-timeout   粗筛单目标超时，默认 2500ms
  -sni          粗筛 TLS SNI，默认 cloudflare.com
  -host         粗筛 HTTP Host，默认 www.cloudflare.com

  -api          精筛接口，默认 https://proxyip.wasmer.app/
  -batch        单次批量条数，默认 50（实测 200 可用）
  -vconc        精筛并发批次，默认按硬件自动
  -api-timeout  单批请求超时，默认 60s

  -rundir       指定工作目录（复用上一次中间产物）
  -stages       只跑指定阶段，如 verify,out（默认 asn,scan,cfscan,verify,out）
  -serve        结束后起临时下载服务，默认 true（-serve=false 关闭）
  -bind         下载服务绑定地址，默认本机局域网 IP
  -http-port    下载服务端口，默认 8899（占用则自动 +1 尝试）
  -serve-wait   服务最长存活时间，0=交互等回车/非交互 30s
  -auto-tune    按本机 CPU 自动匹配速率与并发，默认 true
  -all          CSV 里连无效行一起输出

%s
  扫描只走 masscan 一条路径：必须能定位到 masscan（Linux/WSL 直接 apt install masscan）。
    · masscan 放 PATH，或与 asnip 同目录，或 -masscan <路径>；普通用户运行时需 sudo
    · masscan 自身所需的抓包驱动由其运行环境决定，本工具不做预检；
      它若报驱动/网卡相关错误，会连同 stderr 原文一起回显（见下方 hint）
`, bold("asnip v"+version), bold("用法"), bold("参数"), bold("前置条件"))
}

func parseArgs(argv []string) (*config, error) {
	cfg := &config{
		rate:       10000,
		maxIPs:     2_000_000,
		cfConc:     300,
		cfTimeout:  2500 * time.Millisecond,
		sni:        "cloudflare.com",
		host:       "www.cloudflare.com",
		api:        "https://proxyip.wasmer.app/",
		batch:      50,
		vconc:      4,
		apiTimeout: 60 * time.Second,
		serve:      true,
		httpPort:   8899,
		stages:     map[string]bool{"asn": true, "scan": true, "cfscan": true, "verify": true, "out": true},
	}

	fs := flag.NewFlagSet("asnip", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = usage

	var stagesRaw, masscanArgsRaw string
	fs.StringVar(&cfg.portsRaw, "p", "", "扫描端口")
	fs.StringVar(&cfg.masscanPath, "masscan", "", "masscan.exe 路径")
	fs.StringVar(&masscanArgsRaw, "masscan-args", "", "追加给 masscan 的原始参数")
	fs.IntVar(&cfg.rate, "rate", cfg.rate, "masscan 速率 pps")
	fs.Int64Var(&cfg.limit, "limit", 0, "只扫前 N 个地址")
	fs.Int64Var(&cfg.maxIPs, "max-ips", cfg.maxIPs, "地址数守卫")
	fs.BoolVar(&cfg.force, "force", false, "忽略 max-ips 守卫")
	fs.BoolVar(&cfg.noPreflight, "no-preflight", false, "跳过 masscan 路径与管理员检查")

	fs.IntVar(&cfg.cfConc, "cf-conc", cfg.cfConc, "粗筛并发")
	fs.DurationVar(&cfg.cfTimeout, "cf-timeout", cfg.cfTimeout, "粗筛超时")
	fs.StringVar(&cfg.sni, "sni", cfg.sni, "TLS SNI")
	fs.StringVar(&cfg.host, "host", cfg.host, "HTTP Host")

	fs.StringVar(&cfg.api, "api", cfg.api, "精筛接口")
	fs.IntVar(&cfg.batch, "batch", cfg.batch, "批量条数")
	fs.IntVar(&cfg.vconc, "vconc", cfg.vconc, "精筛并发")
	fs.DurationVar(&cfg.apiTimeout, "api-timeout", cfg.apiTimeout, "单批超时")

	fs.StringVar(&cfg.dir, "rundir", "", "工作目录")
	fs.StringVar(&stagesRaw, "stages", "", "只跑指定阶段")
	fs.BoolVar(&cfg.serve, "serve", cfg.serve, "临时下载服务")
	fs.StringVar(&cfg.bind, "bind", "", "下载服务绑定地址")
	fs.IntVar(&cfg.httpPort, "http-port", cfg.httpPort, "下载服务端口")
	fs.DurationVar(&cfg.serveWait, "serve-wait", 0, "下载服务最长存活时间（0=交互时等回车；非交互默认 30s）")
	fs.BoolVar(&cfg.all, "all", false, "CSV 包含无效行")
	fs.BoolVar(&cfg.autoTune, "auto-tune", true, "按本机 CPU/内存自动匹配扫描参数")

	// Go 的 flag 遇到第一个位置参数就停止解析，而用户习惯写 `asnip 209242 -p 443`。
	// 这里先把「-flag value」整体前移，位置参数后置，两种写法都支持。
	if err := fs.Parse(reorderArgs(argv)); err != nil {
		return nil, err
	}

	cfg.asns = normalizeASNs(fs.Args())

	if strings.TrimSpace(cfg.portsRaw) == "" {
		cfg.portsRaw = defaultPortsFromFile()
	}
	ports, err := parsePorts(cfg.portsRaw)
	if err != nil {
		return nil, err
	}
	cfg.ports = ports

	if raw := strings.TrimSpace(masscanArgsRaw); raw != "" {
		cfg.masscanExtra = strings.Fields(raw)
	}

	if cfg.rate < 0 {
		return nil, fmt.Errorf("-rate 不能为负")
	}
	if cfg.batch < 1 || cfg.batch > 200 {
		return nil, fmt.Errorf("-batch 需在 1~200 之间（接口实测上限 200）")
	}
	if cfg.vconc < 1 {
		return nil, fmt.Errorf("-vconc 必须 ≥ 1")
	}

	if strings.TrimSpace(stagesRaw) != "" {
		cfg.stages = map[string]bool{}
		for _, s := range strings.Split(stagesRaw, ",") {
			s = strings.ToLower(strings.TrimSpace(s))
			if s == "" {
				continue
			}
			known := false
			for _, v := range validStages {
				if s == v {
					known = true
					break
				}
			}
			if !known {
				return nil, fmt.Errorf("未知阶段 %q（可用: %s）", s, strings.Join(validStages, ","))
			}
			cfg.stages[s] = true
		}
		if len(cfg.stages) == 0 {
			return nil, fmt.Errorf("-stages 为空")
		}
	}

	// 硬件自适应：只覆盖「用户没显式指定」的那几项
	if cfg.autoTune {
		explicit := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
		applyAutoTune(cfg, explicit)
	}
	return cfg, nil
}

// applyAutoTune 按本机 CPU 核数给默认值。masscan 走 raw socket，
// 吞吐主要受网卡与抓包驱动限制，经验上 ≈ 1k pps / 核，封顶 50k。
func applyAutoTune(cfg *config, explicit map[string]bool) {
	cores := cpuCount()
	if cores < 1 {
		cores = 1
	}
	ram := physicalMemoryMB()

	rate := cores * 1000
	if rate < 2000 {
		rate = 2000
	}
	if rate > 50000 {
		rate = 50000
	}

	cfConc := cores * 100
	if cfConc < 200 {
		cfConc = 200
	}
	if cfConc > 1000 {
		cfConc = 1000
	}

	vconc := cores * 2
	if vconc < 4 {
		vconc = 4
	}
	if vconc > 16 {
		vconc = 16
	}

	var auto []string
	if !explicit["rate"] {
		cfg.rate = rate
		auto = append(auto, "masscan 速率")
	}
	if !explicit["cf-conc"] {
		cfg.cfConc = cfConc
		auto = append(auto, "粗筛并发")
	}
	if !explicit["vconc"] {
		cfg.vconc = vconc
		auto = append(auto, "精筛并发")
	}

	hw := fmt.Sprintf("%d 核", cores)
	if ram > 0 {
		hw += fmt.Sprintf(" / %d MB", ram)
	}
	cfg.tuneNote = fmt.Sprintf("硬件 %s → masscan %d pps、粗筛并发 %d、精筛并发 %d",
		hw, cfg.rate, cfg.cfConc, cfg.vconc)
	if len(auto) > 0 {
		cfg.tuneNote += fmt.Sprintf("（自动: %s）", strings.Join(auto, "、"))
	} else {
		cfg.tuneNote += "（参数全部手指定）"
	}
}

// reorderArgs 把 flag 与其取值前移、位置参数后置，支持
// `asnip 209242 -p 443` 与 `asnip -p 443 209242` 两种写法。
func reorderArgs(argv []string) []string {
	boolFlags := map[string]bool{
		"force": true, "all": true, "serve": true, "h": true, "help": true,
	}
	var flags, positional []string
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") || boolFlags[name] {
			flags = append(flags, a)
			continue
		}
		flags = append(flags, a)
		if i+1 < len(argv) && !isKnownFlag(argv[i+1]) {
			flags = append(flags, argv[i+1])
			i++
		}
	}
	return append(flags, positional...)
}

func isKnownFlag(tok string) bool {
	if !strings.HasPrefix(tok, "-") || tok == "-" {
		return false
	}
	// 只把「像 flag 的 token」当作新 flag；"-1" 这类负数取值仍视为值
	body := strings.TrimLeft(tok, "-")
	if body == "" {
		return true
	}
	return body[0] < '0' || body[0] > '9'
}

func normalizeASNs(in []string) []string {	var out []string
	seen := map[string]bool{}
	for _, raw := range in {
		for _, part := range strings.Split(strings.ReplaceAll(raw, "，", ","), ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			part = strings.TrimPrefix(strings.TrimPrefix(part, "AS"), "as")
			part = strings.TrimPrefix(part, "As")
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			onlyDigits := true
			for _, r := range part {
				if r < '0' || r > '9' {
					onlyDigits = false
					break
				}
			}
			if !onlyDigits || seen[part] {
				continue
			}
			seen[part] = true
			out = append(out, part)
		}
	}
	return out
}

func banner() {
	const width = 52
	line := strings.Repeat("═", width+2)
	fmt.Println()
	fmt.Println(cyan("  ╔" + line + "╗"))
	fmt.Println(cyan("  ║ ") + padRight("asnip v"+version+"   ASN -> CIDR -> 扫描 -> CF 精筛", width) + cyan(" ║"))
	fmt.Println(cyan("  ╚" + line + "╝"))
}

// padRight 按显示宽度补空格（CJK 字符按 2 列计）
func padRight(s string, width int) string {
	w := 0
	for _, r := range s {
		if r > 0x2E80 {
			w += 2
		} else {
			w++
		}
	}
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

func main() {
	initConsole()

	// 子命令：doctor / version（放在 flag 解析之前，避免被当成 ASN）
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "doctor":
			runDoctor()
			return
		case "version", "-v", "--version":
			fmt.Printf("asnip v%s\n", version)
			return
		}
	}

	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "  %s %v\n", red("✗"), err)
		fmt.Fprintf(os.Stderr, "  %s\n", dim("asnip -h 查看用法"))
		os.Exit(2)
	}

	if len(cfg.asns) == 0 && cfg.stages["asn"] {
		if !isTTY(os.Stdin) {
			usage()
			os.Exit(2)
		}
		fmt.Printf("  输入 ASN 编号（多个用逗号分隔，如 209242,3214）: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		cfg.asns = normalizeASNs(strings.Fields(strings.ReplaceAll(line, "，", ",")))
		if len(cfg.asns) == 0 {
			fmt.Fprintf(os.Stderr, "  %s 没拿到有效 ASN\n", red("✗"))
			os.Exit(2)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Printf("\n  %s\n", yellow("已中断（中间产物已落盘，可用 -rundir 续跑）"))
			return
		}
		fmt.Fprintf(os.Stderr, "\n  %s %v\n", red("✗ 失败:"), err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *config) error {
	banner()

	if cfg.dir == "" {
		tag := "manual"
		if len(cfg.asns) > 0 {
			tag = "AS" + strings.Join(cfg.asns, "_AS")
		}
		cfg.dir = filepath.Join("runs", time.Now().Format("20060102_150405")+"_"+tag)
	}
	if err := os.MkdirAll(cfg.dir, 0o755); err != nil {
		return err
	}
	abs, _ := filepath.Abs(cfg.dir)
	info("ASN: %s", strings.Join(prefixed(cfg.asns), " "))
	info("工作目录: %s", abs)
	if cfg.stages["scan"] {
		info("端口: %s（%d 个）", portsString(cfg.ports), len(cfg.ports))
	}
	if cfg.tuneNote != "" {
		info("%s", cfg.tuneNote)
	}

	var (
		entries []prefixEntry
		open    []string
		hits    []cfHit
		rows    []verified
		err     error
	)

	// 依赖判定：只有「后面还有阶段要用」的中间产物才需要加载，
	// 这样 -stages verify,out 不会因为缺 open.txt 直接失败。
	needPrefixes := cfg.stages["asn"] || cfg.stages["scan"] || cfg.stages["out"]
	needOpen := cfg.stages["cfscan"]
	needHits := cfg.stages["verify"]

	// ── 1/5 ASN → CIDR ──
	if cfg.stages["asn"] {
		title("[1/5] ASN → CIDR（RIPE Stat announced-prefixes）")
		entries, err = fetchASNPrefixes(cfg.asns)
		if err != nil {
			return err
		}
		total := totalAddrs(entries)
		probes := total * int64(len(cfg.ports))
		info("%s 个前缀 / %s 个地址 / %s 个探测点", humanInt(int64(len(entries))), humanInt(total), humanInt(probes))
		if cfg.rate > 0 && probes > 0 {
			secs := float64(probes) / float64(cfg.rate)
			if secs < 90 {
				info("按 -rate %d pps 估算，masscan 约需 %.0f 秒（不含收尾 --wait）", cfg.rate, secs)
			} else {
				info("按 -rate %d pps 估算，masscan 约需 %.1f 分钟（不含收尾 --wait）", cfg.rate, secs/60)
			}
		}
		if total > cfg.maxIPs && !cfg.force {
			return fmt.Errorf("地址数 %s 超过守卫阈值 %s：确认要扫就加 -force，或用 -max-ips 调高",
				humanInt(total), humanInt(cfg.maxIPs))
		}
		cidrPath, err := writeCIDRs(cfg.dir, entries)
		if err != nil {
			return err
		}
		ok("CIDR 已写入 %s（masscan 直接 -iL 即可，不再需要 prips 展开）", filepath.Base(cidrPath))
	} else if needPrefixes {
		entries, err = readPrefixes(cfg.dir)
		if err != nil {
			return err
		}
		info("复用 prefixes.json：%s 个前缀 / %s 个地址", humanInt(int64(len(entries))), humanInt(totalAddrs(entries)))
	}

	// 复用旧目录时 cfg.asns 是空的，从 prefixes.json 反推，保证文件名/展示正确
	if len(cfg.asns) == 0 && len(entries) > 0 {
		seen := map[string]bool{}
		for _, e := range entries {
			if e.ASN != "" && !seen[e.ASN] {
				seen[e.ASN] = true
				cfg.asns = append(cfg.asns, e.ASN)
			}
		}
		sort.Strings(cfg.asns)
		if len(cfg.asns) > 0 {
			info("源 ASN（取自 prefixes.json）: %s", strings.Join(prefixed(cfg.asns), " "))
		}
	}

	// ── 2/5 端口扫描（masscan）──
	if cfg.stages["scan"] {
		title("[2/5] 端口扫描（masscan，CIDR 直接 -iL）")
		open, err = masscanScan(ctx, entries, cfg.ports, cfg, cfg.dir)
		if err != nil {
			return err
		}
		ok("开放 %s 个 ip:port → %s", humanInt(int64(len(open))), "open.txt")
	} else if needOpen {
		open, err = readOpen(cfg.dir)
		if err != nil {
			return err
		}
		info("复用 open.txt：%s 个目标", humanInt(int64(len(open))))
	}

	// ── 3/5 粗筛 ──
	if cfg.stages["cfscan"] {
		title("[3/5] cf-scanner 粗筛（TLS 握手 + CF 指纹）")
		hits, err = cfScan(ctx, open, cfg, cfg.dir)
		if err != nil {
			return err
		}
		ok("CF 候选 %s 个 → %s", humanInt(int64(len(hits))), "cf_hits.jsonl")
	} else if needHits {
		hits, err = readCFHits(filepath.Join(cfg.dir, "cf_hits.jsonl"))
		if err != nil {
			return err
		}
		info("复用 cf_hits.jsonl：%s 个候选", humanInt(int64(len(hits))))
	}

	// ── 4/5 精筛 ──
	if cfg.stages["verify"] {
		title("[4/5] API 精筛（" + cfg.api + "）")
		rows, err = verifyHits(ctx, hits, cfg, cfg.dir)
		if err != nil {
			return err
		}
	} else if cfg.stages["out"] {
		rows, err = readVerified(filepath.Join(cfg.dir, "verified.jsonl"))
		if err != nil {
			return err
		}
		info("复用 verified.jsonl：%s 条记录", humanInt(int64(len(rows))))
	}
	if len(rows) > 0 {
		summarizeVerified(rows)
	}

	// ── 5/5 输出 ──
	if cfg.stages["out"] {
		title("[5/5] 输出 CSV")
		path, valid, err := writeCSV(cfg.dir, rows, entries, cfg)
		if err != nil {
			return err
		}
		if valid == 0 {
			warn("本轮 0 个有效节点（明细见 verified.jsonl，加 -all 可把无效行也写进 CSV）")
		}
		ok("有效节点 %s 条 → %s", humanInt(int64(valid)), filepath.Base(path))
		if cfg.serve {
			if err := serveCSV(path, cfg); err != nil {
				warn("下载服务启动失败: %v", err)
			}
		}
		fmt.Printf("\n  %s\n\n", green("完成"))
	}
	return nil
}

// runDoctor 打印运行环境自检，装完先跑这个能省掉大半排错
func runDoctor() {
	exe, _ := os.Executable()
	masscan := "MISSING"
	if p, err := resolveMasscan(""); err == nil {
		masscan = p
	}
	cwd, _ := os.Getwd()

	ws := "no"
	if isWSL() {
		ws = "yes"
	}
	elev := "no（masscan 需要 root/提权）"
	if isElevated() {
		elev = "yes"
	}
	ram := physicalMemoryMB()
	ramStr := "未知"
	if ram > 0 {
		ramStr = fmt.Sprintf("%d MB", ram)
	}

	fmt.Printf("\n  asnip v%s 运行环境\n\n", version)
	fmt.Printf("  os          : %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  wsl         : %s\n", ws)
	fmt.Printf("  cpu / mem   : %d 核 / %s\n", cpuCount(), ramStr)
	fmt.Printf("  user        : uid=%d 提权=%s\n", os.Getuid(), elev)
	fmt.Printf("  masscan     : %s\n", masscan)
	fmt.Printf("  asnip 可执行 : %s\n", exe)
	fmt.Printf("  当前目录     : %s\n", cwd)
	fmt.Printf("  默认端口     : %s\n", defaultPortsFromFile())
	fmt.Println()
	if masscan == "MISSING" {
		warn("没找到 masscan：放到 PATH，或用 -masscan <路径>")
	}
	if !isElevated() {
		info("提示：非 root 运行时请用 sudo（安装脚本注册的 asnip 命令已自动 sudo）")
	}
}

func prefixed(asns []string) []string {	out := make([]string, len(asns))
	for i, a := range asns {
		out[i] = "AS" + a
	}
	return out
}
