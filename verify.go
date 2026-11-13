package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// apiItem 对应 https://proxyip.wasmer.app/?ip=... 的单条返回（字段名保持中文原样）
type apiItem struct {
	Target     string `json:"目标"`
	Valid      bool   `json:"有效ProxyIP"`
	Fail       string `json:"失败原因"`
	IP         string `json:"ip"`
	Port       int    `json:"端口"`
	ExitIP     string `json:"出口ip"`
	ExitType   string `json:"出口类型"`
	ExitV4     string `json:"出口IPv4"`
	ExitV6     string `json:"出口IPv6"`
	Dual       bool   `json:"双栈"`
	Colo       string `json:"数据中心"`
	Country    string `json:"国家"`
	Region     string `json:"地区"`
	City       string `json:"城市"`
	RTT        string `json:"响应时间"`
	ExitCountry string `json:"出口国家"`
	ExitRegion  string `json:"出口地区"`
	ExitCity    string `json:"出口城市"`
	ASN        string `json:"ASN"`
	Org        string `json:"组织"`
	SameFamily bool   `json:"出口地址与目标是否同族一致"`
	CFOfficial bool   `json:"是否为Cloudflare官方IP"`
}

// verified 是最终 CSV 的一行（粗筛结果 + API 精筛结果 + 源 ASN）
type verified struct {
	Target     string `json:"target"`
	Valid      bool   `json:"valid"`
	Fail       string `json:"fail,omitempty"`
	IP         string `json:"ip"`
	Port       uint16 `json:"port"`
	TLS        string `json:"tls"`
	EdgeColo   string `json:"edge_colo"`
	Colo       string `json:"colo"`
	Country    string `json:"country"`
	Region     string `json:"region"`
	City       string `json:"city"`
	RTTms      int    `json:"rtt_ms"`
	ASN        string `json:"asn"`
	Org        string `json:"org"`
	ExitIP     string `json:"exit_ip"`
	ExitType   string `json:"exit_type"`
	Dual       bool   `json:"dual_stack"`
	CFOfficial bool   `json:"cf_official"`
	SourceASN  string `json:"source_asn"`
	Handshake  int    `json:"handshake_ms"`
}

var rttRe = regexp.MustCompile(`(\d+)`)

func parseRTT(s string) int {
	if m := rttRe.FindStringSubmatch(s); m != nil {
		if v, err := strconv.Atoi(m[1]); err == nil {
			return v
		}
	}
	return 0
}

func newAPIRequestURL(base string, targets []string) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	q := "ip=" + strings.Join(targets, ",") // 逗号在 query 中合法，保持与官方示例一致
	return strings.TrimRight(base, "/") + sep + q
}

// queryBatch 一次批量请求；失败重试 3 次，429/503 读 Retry-After。
func queryBatch(ctx context.Context, cfg *config, targets []string) (map[string]apiItem, error) {
	raw := newAPIRequestURL(cfg.api, targets)
	if _, err := url.Parse(raw); err != nil {
		return nil, fmt.Errorf("API 地址无效: %w", err)
	}

	client := &http.Client{Timeout: cfg.apiTimeout}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			wait := time.Duration(attempt) * 900 * time.Millisecond
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		req, err := http.NewRequestWithContext(ctx, "GET", raw, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "asnip/2.0")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		ra := resp.Header.Get("Retry-After")
		resp.Body.Close()

		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			if secs, e := strconv.Atoi(strings.TrimSpace(ra)); e == nil && secs > 0 && secs <= 30 {
				select {
				case <-time.After(time.Duration(secs) * time.Second):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			lastErr = fmt.Errorf("HTTP %d（限流）", resp.StatusCode)
			continue
		}
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		if err != nil {
			lastErr = err
			continue
		}

		items, err := decodeItems(body)
		if err != nil {
			lastErr = err
			continue
		}
		out := make(map[string]apiItem, len(items))
		for _, it := range items {
			out[strings.TrimSpace(it.Target)] = it
		}
		return out, nil
	}
	return nil, lastErr
}

// decodeItems 兼容「数组」与「单个对象」两种返回。
func decodeItems(body []byte) ([]apiItem, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, fmt.Errorf("空响应")
	}
	switch trimmed[0] {
	case '[':
		var arr []apiItem
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			return nil, fmt.Errorf("解析数组失败: %w", err)
		}
		return arr, nil
	case '{':
		var one apiItem
		if err := json.Unmarshal([]byte(trimmed), &one); err != nil {
			return nil, fmt.Errorf("解析对象失败: %w", err)
		}
		return []apiItem{one}, nil
	default:
		return nil, fmt.Errorf("非 JSON 响应: %.120s", trimmed)
	}
}

// verifyChunk 递归执行：整块失败就二分，把「API 抖动」和「个别目标卡住」区分开。
func verifyChunk(ctx context.Context, cfg *config, chunk []string) []verified {
	if len(chunk) == 0 {
		return nil
	}
	items, err := queryBatch(ctx, cfg, chunk)
	if err != nil {
		if len(chunk) == 1 {
			return []verified{{Target: chunk[0], Valid: false, Fail: "API 请求失败: " + err.Error()}}
		}
		mid := len(chunk) / 2
		out := verifyChunk(ctx, cfg, chunk[:mid])
		time.Sleep(200 * time.Millisecond)
		return append(out, verifyChunk(ctx, cfg, chunk[mid:])...)
	}

	out := make([]verified, 0, len(chunk))
	for _, t := range chunk {
		it, ok := items[t]
		if !ok {
			out = append(out, verified{Target: t, Valid: false, Fail: "API 未返回该项"})
			continue
		}
		ip, port, _ := splitTarget(t)
		row := verified{
			Target:     t,
			Valid:      it.Valid,
			Fail:       it.Fail,
			IP:         ip.String(),
			Port:       port,
			Colo:       it.Colo,
			Country:    it.Country,
			Region:     it.Region,
			City:       it.City,
			RTTms:      parseRTT(it.RTT),
			ASN:        it.ASN,
			Org:        it.Org,
			ExitIP:     it.ExitIP,
			ExitType:   it.ExitType,
			Dual:       it.Dual,
			CFOfficial: it.CFOfficial,
		}
		if row.ASN != "" && !strings.HasPrefix(row.ASN, "AS") {
			row.ASN = "AS" + row.ASN
		}
		out = append(out, row)
	}
	return out
}

// verifyHits 精筛主流程：分片 + 并发 + 断点续跑 + JSONL 落盘。
func verifyHits(ctx context.Context, hits []cfHit, cfg *config, dir string) ([]verified, error) {
	rowsFile := filepath.Join(dir, "verified.jsonl")

	existing, err := readVerified(rowsFile)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	done := make(map[string]bool, len(existing))
	for _, r := range existing {
		done[r.Target] = true
	}
	if len(done) > 0 {
		info("断点续跑：已有 %s 条精筛记录，跳过", humanInt(int64(len(done))))
	}

	var todo []string
	for _, h := range hits {
		if !done[h.Target] {
			todo = append(todo, h.Target)
		}
	}

	var chunks [][]string
	for i := 0; i < len(todo); i += cfg.batch {
		end := i + cfg.batch
		if end > len(todo) {
			end = len(todo)
		}
		chunks = append(chunks, todo[i:end])
	}
	info("待精筛 %s 个目标，分 %s 批（批大小 %d，并发 %d）",
		humanInt(int64(len(todo))), humanInt(int64(len(chunks))), cfg.batch, cfg.vconc)

	f, err := os.OpenFile(rowsFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	prog := newProgress("精筛", int64(len(todo)))
	chunkCh := make(chan []string, cfg.vconc)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < cfg.vconc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for chunk := range chunkCh {
				if ctx.Err() != nil {
					return
				}
				rows := verifyChunk(ctx, cfg, chunk)
				mu.Lock()
				for _, r := range rows {
					line, _ := json.Marshal(r)
					f.Write(append(line, '\n'))
				}
				mu.Unlock()
				prog.add(int64(len(chunk)))
			}
		}()
	}
	for _, c := range chunks {
		select {
		case chunkCh <- c:
		case <-ctx.Done():
			break
		}
	}
	close(chunkCh)
	wg.Wait()

	prog.finish("精筛完成")

	all, err := readVerified(rowsFile)
	if err != nil {
		return nil, err
	}

	// 回填粗筛信息（TLS/边缘机房），并按 target 去重
	hitMap := make(map[string]cfHit, len(hits))
	for _, h := range hits {
		hitMap[h.Target] = h
	}
	merged := make(map[string]verified, len(all))
	for _, r := range all {
		if h, ok := hitMap[r.Target]; ok {
			r.TLS = h.TLS
			r.EdgeColo = h.Colo
			r.Handshake = h.HandshakeMS
		}
		merged[r.Target] = r
	}
	out := make([]verified, 0, len(merged))
	for _, r := range merged {
		out = append(out, r)
	}
	return out, nil
}

// summarizeVerified 打印有效/无效统计与最常见失败原因。
// 接口语义上「CF 官方 anycast IP」几乎都返回 `远端返回失败结果`，
// 直接把原因摆出来，免得用户对着 0 条结果猜。
func summarizeVerified(rows []verified) {
	valid, invalid := 0, 0
	reasons := map[string]int{}
	for _, r := range rows {
		if r.Valid {
			valid++
			continue
		}
		invalid++
		reason := strings.TrimSpace(r.Fail)
		if reason == "" {
			reason = "未知"
		}
		reasons[reason]++
	}
	info("精筛结果: 有效 %s / 无效 %s", humanInt(int64(valid)), humanInt(int64(invalid)))

	type kv struct {
		k string
		n int
	}
	var top []kv
	for k, n := range reasons {
		top = append(top, kv{k, n})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].n > top[j].n })
	for i, r := range top {
		if i >= 3 {
			break
		}
		info("  失败原因 top%d: %s × %s", i+1, r.k, humanInt(int64(r.n)))
	}
	if invalid > 0 && valid == 0 {
		warn("接口判定「有效」= 该 ip:port 能当 ProxyIP 用；CF 官方 anycast IP 通常被判无效，属接口语义而非筛选 bug")
	}
}

func readVerified(path string) ([]verified, error) {	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []verified
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r verified
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, sc.Err()
}
