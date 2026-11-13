// masscan 假体：仅用于在没有 Npcap 的机器上验证 asnip 的 masscan 集成逻辑
// （参数传递、stderr 进度解析、-oL 解析、open.txt 产出）。
//
//	go build -o testdata\masscan_stub.exe ./testdata/masscan_stub
//
// 它会把输入 CIDR 文件的第一个前缀的首 2 个地址当作"开放端口"写进 -oL。
package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

func main() {
	in := flag.String("iL", "", "input list")
	out := flag.String("oL", "", "output list")
	ports := flag.String("p", "443", "ports")
	rate := flag.String("rate", "1000", "rate")
	wait := flag.String("wait", "5", "wait")
	flag.Parse()
	_ = wait

	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: masscan_stub -iL cidrs.txt -oL out.txt -p 443 --rate 1000")
		os.Exit(2)
	}

	data, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: cannot open %s: %v\n", *in, err)
		os.Exit(1)
	}

	port := strings.Split(*ports, ",")[0]
	var lines []string
	for _, raw := range strings.Split(string(data), "\n") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			continue
		}
		addr := p.Masked().Addr()
		for i := 0; i < 2 && p.Contains(addr); i++ {
			lines = append(lines, fmt.Sprintf("open tcp %s %s 1700000000", port, addr.String()))
			addr = addr.Next()
		}
		break
	}

	fmt.Fprintf(os.Stderr, "rate: %s.00-kpps, 0.00%% done, found=0\n", *rate)
	fmt.Fprintf(os.Stderr, "rate: %s.00-kpps, 100.00%% done, found=%d\n", *rate, len(lines))

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: cannot create %s: %v\n", *out, err)
		os.Exit(1)
	}
	defer f.Close()
	for _, l := range lines {
		fmt.Fprintln(f, l)
	}
	fmt.Printf("stub: wrote %d open lines to %s\n", len(lines), *out)
}
