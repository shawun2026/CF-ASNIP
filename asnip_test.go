package main

import (
	"net/netip"
	"testing"
)

func TestParsePorts(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"443", "443", false},
		{"443,8443", "443,8443", false},
		{"8443-8445", "8443,8444,8445", false},
		{" 443 , 2053 ", "443,2053", false},
		{"443,443", "443", false},
		{"", "", true},
		{"abc", "", true},
		{"70000", "", true},
		{"100-50", "", true},
	}
	for _, c := range cases {
		got, err := parsePorts(c.in)
		if c.wantErr {
			if err == nil {
				t.Fatalf("parsePorts(%q) 期望报错，实际 %v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parsePorts(%q) 报错: %v", c.in, err)
		}
		if s := portsString(got); s != c.want {
			t.Fatalf("parsePorts(%q) = %q，期望 %q", c.in, s, c.want)
		}
	}
}

func TestMergePrefixes(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("104.16.0.0/24"),
		netip.MustParsePrefix("104.16.1.0/24"),
		netip.MustParsePrefix("104.16.2.0/24"), // 落单，无法合并
		netip.MustParsePrefix("104.17.0.0/24"),
		netip.MustParsePrefix("104.17.0.128/25"), // 被 /24 包含
	}
	got := mergePrefixes(in)
	if len(got) != 3 {
		t.Fatalf("合并结果 %d 段，期望 3 段: %v", len(got), got)
	}
	if got[0].String() != "104.16.0.0/23" {
		t.Fatalf("首段 = %s，期望 104.16.0.0/23", got[0])
	}
	var total int64
	for _, p := range got {
		total += ipCount(p)
	}
	if total != 256*2+256+256 {
		t.Fatalf("地址总数 = %d，期望 %d", total, 256*2+256+256)
	}
}

func TestColoFromCFRay(t *testing.T) {
	cases := map[string]string{
		"a59beb2bca71d79b-NRT": "NRT",
		"a59beb2bca71d79b-LAX": "LAX",
		"":                     "",
		"nosuffix":             "",
		"x-ab":                 "", // CF 机房码固定 3 位
		"x-1234":               "",
	}
	for in, want := range cases {
		if got := coloFromCFRay(in); got != want {
			t.Fatalf("coloFromCFRay(%q) = %q，期望 %q", in, got, want)
		}
	}
}

func TestParseRTT(t *testing.T) {
	cases := map[string]int{"223ms": 223, "1.2s": 1, "": 0, "abc": 0}
	for in, want := range cases {
		if got := parseRTT(in); got != want {
			t.Fatalf("parseRTT(%q) = %d，期望 %d", in, got, want)
		}
	}
}

func TestDecodeItems(t *testing.T) {
	arr := `[{"目标":"1.1.1.1:443","有效ProxyIP":true,"数据中心":"NRT","响应时间":"220ms"}]`
	items, err := decodeItems([]byte(arr))
	if err != nil || len(items) != 1 {
		t.Fatalf("数组解析失败: %v %v", items, err)
	}
	if !items[0].Valid || items[0].Colo != "NRT" || items[0].Target != "1.1.1.1:443" {
		t.Fatalf("字段映射错误: %+v", items[0])
	}

	one := `{"目标":"2.2.2.2:443","有效ProxyIP":false,"失败原因":"远端返回失败结果"}`
	items, err = decodeItems([]byte(one))
	if err != nil || len(items) != 1 || items[0].Fail == "" {
		t.Fatalf("单对象解析失败: %+v %v", items, err)
	}

	if _, err := decodeItems([]byte("<html>")); err == nil {
		t.Fatal("非 JSON 应报错")
	}
}

func TestNormalizeASNs(t *testing.T) {
	got := normalizeASNs([]string{"AS209242", "as3214,209242", " 906 "})
	want := []string{"209242", "3214", "906"}
	if len(got) != len(want) {
		t.Fatalf("得到 %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("得到 %v，期望 %v", got, want)
		}
	}
}

func TestSplitPrefix(t *testing.T) {
	lo, hi := splitPrefix(netip.MustParsePrefix("104.16.0.0/24"))
	if lo.String() != "104.16.0.0/25" || hi.String() != "104.16.0.128/25" {
		t.Fatalf("split /24 = %s / %s", lo, hi)
	}
	lo, hi = splitPrefix(netip.MustParsePrefix("10.0.0.0/23"))
	if lo.String() != "10.0.0.0/24" || hi.String() != "10.0.1.0/24" {
		t.Fatalf("split /23 = %s / %s", lo, hi)
	}
}

func TestTrimPrefixes(t *testing.T) {
	entries := []prefixEntry{{Prefix: netip.MustParsePrefix("104.16.0.0/24"), ASN: "13335"}}

	got := trimPrefixes(entries, 8)
	if n := totalAddrs(got); n != 8 {
		t.Fatalf("trim 到 8 个地址，实际 %d（%v）", n, got)
	}
	for _, e := range got {
		if e.ASN != "13335" {
			t.Fatalf("ASN 归属丢失: %v", e)
		}
	}

	got = trimPrefixes(entries, 100000)
	if n := totalAddrs(got); n != 256 {
		t.Fatalf("预算够时应原样保留 256，实际 %d", n)
	}
	if len(got) != 1 {
		t.Fatalf("预算够时不应拆分，实际 %d 段", len(got))
	}
}

func TestReorderArgs(t *testing.T) {	got := reorderArgs([]string{"209242", "-p", "443,8443", "-serve=false", "3214", "-force"})
	want := []string{"-p", "443,8443", "-serve=false", "-force", "209242", "3214"}
	if len(got) != len(want) {
		t.Fatalf("得到 %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("得到 %v，期望 %v", got, want)
		}
	}
}
