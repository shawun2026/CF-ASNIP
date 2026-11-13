package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// cfHit 粗筛命中结果。colo 来自 CF-Ray 尾部的三字码（如 ...-NRT），
// 这是本地实测得到的边缘机房，不依赖任何第三方。
type cfHit struct {
	Target      string   `json:"target"`
	Status      int      `json:"status"`
	Server      string   `json:"server"`
	CFRay       string   `json:"cf_ray"`
	Colo        string   `json:"colo"`
	TLS         string   `json:"tls"`
	HandshakeMS int      `json:"handshake_ms"`
	Signals     []string `json:"signals"`
}

// probeCF 对单个 ip:port 做 TLS 握手 + HTTP/1.1 探测，按 CF 指纹判定。
func probeCF(ctx context.Context, target string, cfg *config) (*cfHit, error) {
	dialer := net.Dialer{Timeout: cfg.cfTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(cfg.cfTimeout)); err != nil {
		return nil, err
	}

	t0 := time.Now()
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         cfg.sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	handshakeMS := int(time.Since(t0).Milliseconds())

	req := "GET / HTTP/1.1\r\n" +
		"Host: " + cfg.host + "\r\n" +
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36\r\n" +
		"Accept: */*\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := io.WriteString(tlsConn, req); err != nil {
		return nil, err
	}

	br := bufio.NewReaderSize(tlsConn, 8192)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	h := resp.Header
	server := h.Get("Server")
	cfray := h.Get("CF-Ray")

	var signals []string
	if strings.EqualFold(server, "cloudflare") {
		signals = append(signals, "server")
	}
	if cfray != "" {
		signals = append(signals, "cf-ray")
	}
	if h.Get("CF-Cache-Status") != "" {
		signals = append(signals, "cf-cache-status")
	}
	if strings.Contains(strings.ToLower(h.Get("Set-Cookie")), "__cf_bm") {
		signals = append(signals, "__cf_bm")
	}
	if len(signals) == 0 {
		return nil, fmt.Errorf("非 CF 指纹 (status=%d server=%q)", resp.StatusCode, server)
	}

	return &cfHit{
		Target:      target,
		Status:      resp.StatusCode,
		Server:      server,
		CFRay:       cfray,
		Colo:        coloFromCFRay(cfray),
		TLS:         tls.VersionName(tlsConn.ConnectionState().Version),
		HandshakeMS: handshakeMS,
		Signals:     signals,
	}, nil
}

// coloFromCFRay 从 "a59beb2bca71d79b-NRT" 取 "NRT"
func coloFromCFRay(ray string) string {
	i := strings.LastIndex(ray, "-")
	if i < 0 || i == len(ray)-1 {
		return ""
	}
	colo := strings.ToUpper(strings.TrimSpace(ray[i+1:]))
	if len(colo) != 3 {
		return ""
	}
	for _, r := range colo {
		if r < 'A' || r > 'Z' {
			return ""
		}
	}
	return colo
}

// cfScan 粗筛：并发探测、断点续跑（按已写 JSONL 里的 target 去重）、实时落盘。
func cfScan(ctx context.Context, targets []string, cfg *config, dir string) ([]cfHit, error) {
	hitsFile := filepath.Join(dir, "cf_hits.jsonl")

	existing, err := readCFHits(hitsFile)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	done := make(map[string]bool, len(existing))
	for _, h := range existing {
		done[h.Target] = true
	}
	if len(done) > 0 {
		info("断点续跑：已有 %s 条命中记录，跳过", humanInt(int64(len(done))))
	}

	var todo []string
	for _, t := range targets {
		if !done[t] {
			todo = append(todo, t)
		}
	}
	if cfg.limit > 0 && int64(len(todo)) > cfg.limit {
		todo = todo[:cfg.limit]
	}

	var mu sync.Mutex
	f, err := os.OpenFile(hitsFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	prog := newProgress("粗筛", int64(len(todo)))
	jobs := make(chan string, cfg.cfConc*2)
	var wg sync.WaitGroup
	newHits := make([]cfHit, 0, 256)

	for i := 0; i < cfg.cfConc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				if ctx.Err() != nil {
					return
				}
				hit, err := probeCF(ctx, target, cfg)
				if err == nil && hit != nil {
					line, _ := json.Marshal(hit)
					mu.Lock()
					f.Write(append(line, '\n'))
					newHits = append(newHits, *hit)
					mu.Unlock()
				}
				prog.add(1)
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, t := range todo {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
	prog.finish(fmt.Sprintf("CF 候选 %s 个", humanInt(int64(len(existing)+len(newHits)))))

	all := append(existing, newHits...)
	if len(all) == 0 {
		return nil, fmt.Errorf("粗筛后没有任何 CF 候选（检查端口是否为 TLS 端口，或目标 ASN 是否承载 CF）")
	}
	return all, nil
}

func readCFHits(path string) ([]cfHit, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []cfHit
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var h cfHit
		if err := json.Unmarshal([]byte(line), &h); err != nil {
			continue
		}
		out = append(out, h)
	}
	return out, sc.Err()
}
