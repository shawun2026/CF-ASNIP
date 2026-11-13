package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var csvHeader = []string{
	"IP", "端口", "TLS", "边缘机房", "源ASN", "数据中心", "国家", "地区", "城市",
	"响应时间(ms)", "ASN", "组织", "双栈", "出口IP", "出口类型", "CF官方IP", "状态",
}

// writeCSV 生成最终 CSV：按「有效优先 + 响应时间升序」排序，可选包含失败行。
func writeCSV(dir string, rows []verified, entries []prefixEntry, cfg *config) (string, int, error) {
	out := make([]verified, 0, len(rows))
	for _, r := range rows {
		if r.SourceASN == "" {
			if ip, _, ok := splitTarget(r.Target); ok {
				r.SourceASN = lookupASN(entries, ip)
			}
		}
		if !r.Valid && !cfg.all {
			continue
		}
		out = append(out, r)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Valid != out[j].Valid {
			return out[i].Valid
		}
		if out[i].Valid && out[i].RTTms != out[j].RTTms {
			return out[i].RTTms < out[j].RTTms
		}
		return out[i].Target < out[j].Target
	})

	validCount := 0
	for _, r := range out {
		if r.Valid {
			validCount++
		}
	}

	ts := time.Now().Format("20060102_150405")
	tag := "manual"
	if len(cfg.asns) > 0 {
		tag = "AS" + strings.Join(cfg.asns, "_AS")
	}
	name := fmt.Sprintf("output_%s_%s.csv", tag, ts)
	path := filepath.Join(dir, name)

	f, err := os.Create(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	// UTF-8 BOM：Windows 版 Excel 直接双击打开不乱码
	if _, err := f.WriteString("\xef\xbb\xbf"); err != nil {
		return "", 0, err
	}

	w := csv.NewWriter(f)
	if err := w.Write(csvHeader); err != nil {
		return "", 0, err
	}
	for _, r := range out {
		status := "有效"
		if !r.Valid {
			status = "无效"
			if r.Fail != "" {
				status = "无效: " + r.Fail
			}
		}
		row := []string{
			r.IP,
			strconv.Itoa(int(r.Port)),
			dash(r.TLS),
			dash(r.EdgeColo),
			asnOrDash(r.SourceASN),
			dash(r.Colo),
			dash(r.Country),
			dash(r.Region),
			dash(r.City),
			strconv.Itoa(r.RTTms),
			asnOrDash(r.ASN),
			dash(r.Org),
			boolStr(r.Dual),
			dash(r.ExitIP),
			dash(r.ExitType),
			boolStr(r.CFOfficial),
			status,
		}
		if err := w.Write(row); err != nil {
			return "", 0, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return "", 0, err
	}
	return path, validCount, nil
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func asnOrDash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	if !strings.HasPrefix(s, "AS") {
		return "AS" + s
	}
	return s
}

func boolStr(b bool) string {
	if b {
		return "是"
	}
	return "否"
}

// ---------- 临时下载服务：只暴露「一个 CSV 文件」，不再共享整个项目目录 ----------

func serveCSV(csvPath string, cfg *config) error {
	dir := filepath.Join(filepath.Dir(csvPath), "http")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	name := filepath.Base(csvPath)
	dst := filepath.Join(dir, name)
	data, err := os.ReadFile(csvPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return err
	}

	bind := cfg.bind
	if bind == "" {
		if isWSL() {
			// WSL2 里 lanIP 是虚拟网卡地址（172.x），Windows 侧反而访问不到；
			// 绑 0.0.0.0 才能同时被 localhost 转发与 portproxy 命中。
			bind = "0.0.0.0"
		} else {
			bind = lanIP()
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if path := strings.TrimPrefix(r.URL.Path, "/"); path != name {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Disposition", "attachment; filename="+name)
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		http.ServeFile(w, r, dst)
	})

	var ln net.Listener
	port := cfg.httpPort
	for i := 0; i < 12; i++ {
		ln, err = net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(port)))
		if err == nil {
			break
		}
		port++
	}
	if err != nil {
		return fmt.Errorf("监听失败（%s 起 12 个端口都被占用）: %w", cfg.bind, err)
	}

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	urlPath := fmt.Sprintf("http://%s:%d/%s", bind, port, name)
	fmt.Println()
	fmt.Println("  " + green("📥 下载链接（临时，仅此一个文件）:"))
	if isWSL() {
		// WSL 下 bind 是 0.0.0.0，给真正能点开的地址
		fmt.Printf("     %s\n", bold(fmt.Sprintf("http://localhost:%d/%s", port, name)))
		fmt.Printf("     %s\n", dim(fmt.Sprintf("http://127.0.0.1:%d/%s（Windows 浏览器可直接打开）", port, name)))
		fmt.Println()
		fmt.Printf("  %s\n", dim("局域网其它设备要访问，在 Windows 管理员 PowerShell 里转发一次："))
		fmt.Printf("  %s\n", dim(fmt.Sprintf(`netsh interface portproxy add v4tov4 listenport=%d listenaddress=0.0.0.0 connectport=%d connectaddress=127.0.0.1`, port, port)))
	} else {
		fmt.Printf("     %s\n", bold(urlPath))
		if host := lanIP(); host != bind {
			fmt.Printf("     %s\n", fmt.Sprintf("http://%s:%d/%s", host, port, name))
		}
		if bind != "127.0.0.1" {
			fmt.Printf("     %s\n", dim(fmt.Sprintf("http://127.0.0.1:%d/%s", port, name)))
		}
		fmt.Println()
		fmt.Printf("  %s\n", dim("若局域网其它设备打不开，用管理员 PowerShell 放行一次："))
		fmt.Printf("  %s\n", dim(fmt.Sprintf(`netsh advfirewall firewall add rule name="asnip" dir=in action=allow protocol=TCP localport=%d`, port)))
	}
	fmt.Println()

	wait := cfg.serveWait
	tty := isTTY(os.Stdin)
	if tty {
		fmt.Printf("  %s", dim("按回车关闭下载服务…"))
		enterCh := make(chan struct{})
		go func() {
			var b [1]byte
			_, _ = os.Stdin.Read(b[:])
			close(enterCh)
		}()
		if wait > 0 {
			select {
			case <-enterCh:
			case <-time.After(wait):
			}
		} else {
			<-enterCh
		}
	} else {
		if wait <= 0 {
			wait = 30 * time.Second
		}
		fmt.Printf("  %s\n", dim(fmt.Sprintf("非交互模式：服务保持 %s 后自动关闭", wait)))
		time.Sleep(wait)
	}
	return nil
}

// isWSL 判断是否运行在 WSL 里（决定绑定地址与链接展示方式）
func isWSL() bool {
	if os.Getenv("WSL_DISTRO_NAME") != "" {
		return true
	}
	if data, err := os.ReadFile("/proc/version"); err == nil {
		s := strings.ToLower(string(data))
		if strings.Contains(s, "microsoft") || strings.Contains(s, "wsl") {
			return true
		}
	}
	return false
}

// lanIP 取本机对外网卡地址（UDP connect 不发包，仅用于选路）
func lanIP() string {
	if c, err := net.Dial("udp", "8.8.8.8:80"); err == nil {
		defer c.Close()
		if ua, ok := c.LocalAddr().(*net.UDPAddr); ok && ua.IP != nil && !ua.IP.IsLoopback() {
			return ua.IP.String()
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if v4 := ipnet.IP.To4(); v4 != nil {
					return v4.String()
				}
			}
		}
	}
	return "127.0.0.1"
}
