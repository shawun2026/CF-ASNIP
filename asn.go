package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// prefixEntry 保留「前缀 → 源 ASN」的归属，供最终 CSV 输出「源ASN」列。
type prefixEntry struct {
	Prefix netip.Prefix `json:"prefix"`
	ASN    string       `json:"asn"`
}

type ripeResp struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
	Status string `json:"status"`
}

func ripeClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

// fetchASNPrefixes 逐个 ASN 查询 RIPE Stat，只保留 IPv4，并做合并压缩。
func fetchASNPrefixes(asns []string) ([]prefixEntry, error) {
	var all []prefixEntry
	seen := map[string]bool{}
	client := ripeClient()

	for _, asn := range asns {
		raw, err := fetchOneASN(client, asn)
		if err != nil {
			bad("AS%s 查询失败: %v", asn, err)
			continue
		}
		merged := mergePrefixes(raw)
		addrs := int64(0)
		for _, p := range merged {
			addrs += ipCount(p)
		}
		ok("AS%s → %s 段 → 合并 %s 段 / %s 个地址", asn,
			humanInt(int64(len(raw))), humanInt(int64(len(merged))), humanInt(addrs))

		for _, p := range merged {
			key := p.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			all = append(all, prefixEntry{Prefix: p, ASN: asn})
		}
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("没有取到任何 IPv4 前缀")
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].Prefix.Addr().Less(all[j].Prefix.Addr())
	})
	return all, nil
}

func fetchOneASN(client *http.Client, asn string) ([]netip.Prefix, error) {
	url := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s", asn)
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 800 * time.Millisecond)
		}
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "asnip/2.0 (+https://stat.ripe.net)")
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		var r ripeResp
		if err := json.Unmarshal(body, &r); err != nil {
			lastErr = fmt.Errorf("解析 JSON 失败: %w", err)
			continue
		}
		var out []netip.Prefix
		for _, item := range r.Data.Prefixes {
			if strings.Contains(item.Prefix, ":") { // 跳过 IPv6
				continue
			}
			p, err := netip.ParsePrefix(item.Prefix)
			if err != nil || !p.Addr().Is4() {
				continue
			}
			out = append(out, p.Masked())
		}
		return out, nil
	}
	return nil, lastErr
}

// mergePrefixes 归一化 → 去被包含 → 兄弟前缀逐级合并（不改地址集合）。
func mergePrefixes(in []netip.Prefix) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].Addr() == in[j].Addr() {
			return in[i].Bits() < in[j].Bits()
		}
		return in[i].Addr().Less(in[j].Addr())
	})

	var kept []netip.Prefix
	for _, p := range in {
		p = p.Masked()
		if !p.Addr().Is4() {
			continue
		}
		contained := false
		for i := len(kept) - 1; i >= 0; i-- {
			if kept[i].Bits() <= p.Bits() && kept[i].Contains(p.Addr()) {
				contained = true
				break
			}
		}
		if !contained {
			kept = append(kept, p)
		}
	}

	set := make(map[netip.Prefix]struct{}, len(kept))
	for _, p := range kept {
		set[p] = struct{}{}
	}
	collapseSiblings(set)

	out := make([]netip.Prefix, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Addr().Less(out[j].Addr())
	})
	return out
}

// collapseSiblings 把 a.b.c.0/24 + a.b.c.1/24 合并成 a.b.c.0/23，逐级向上。
func collapseSiblings(set map[netip.Prefix]struct{}) {
	for {
		merged := false
		for p := range set {
			if p.Bits() == 0 {
				continue
			}
			b := p.Addr().As4()
			idx := (p.Bits() - 1) / 8
			bit := uint(7 - ((p.Bits() - 1) % 8))
			b[idx] ^= 1 << bit
			sib := netip.PrefixFrom(netip.AddrFrom4(b), p.Bits()).Masked()
			if _, has := set[sib]; !has {
				continue
			}
			parent := netip.PrefixFrom(p.Addr(), p.Bits()-1).Masked()
			delete(set, p)
			delete(set, sib)
			set[parent] = struct{}{}
			merged = true
			break
		}
		if !merged {
			return
		}
	}
}

func ipCount(p netip.Prefix) int64 {
	if !p.IsValid() {
		return 0
	}
	bits := p.Bits()
	if bits < 0 || bits > 32 {
		return 0
	}
	return int64(1) << uint(32-bits)
}

func totalAddrs(entries []prefixEntry) int64 {
	var n int64
	for _, e := range entries {
		n += ipCount(e.Prefix)
	}
	return n
}

// lookupASN 找出包含该 IP 的源前缀（前缀数量在千级、命中在千级，线性足够）。
func lookupASN(entries []prefixEntry, ip netip.Addr) string {
	for _, e := range entries {
		if e.Prefix.Contains(ip) {
			return e.ASN
		}
	}
	return ""
}

func writeCIDRs(dir string, entries []prefixEntry) (string, error) {
	path := filepath.Join(dir, "cidrs.txt")
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.Prefix.String())
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	// 归属表，供 out 阶段回填「源ASN」
	pj := filepath.Join(dir, "prefixes.json")
	data, _ := json.MarshalIndent(entries, "", "  ")
	if err := os.WriteFile(pj, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func readPrefixes(dir string) ([]prefixEntry, error) {
	data, err := os.ReadFile(filepath.Join(dir, "prefixes.json"))
	if err != nil {
		return nil, fmt.Errorf("缺少 %s（先跑 asn 阶段）", filepath.Join(dir, "prefixes.json"))
	}
	var entries []prefixEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}
