package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// ANSI 颜色（非 TTY 自动关闭；Windows 下由 initConsole 打开 VT 处理与 UTF-8 代码页）
var useColor = true

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func init() {
	if !isTTY(os.Stdout) {
		useColor = false
	}
}

func paint(code, s string) string {
	if !useColor {
		return s
	}
	return code + s + "\x1b[0m"
}

func cyan(s string) string   { return paint("\x1b[36m", s) }
func green(s string) string  { return paint("\x1b[32m", s) }
func red(s string) string    { return paint("\x1b[31m", s) }
func yellow(s string) string { return paint("\x1b[33m", s) }
func dim(s string) string    { return paint("\x1b[2m", s) }
func bold(s string) string   { return paint("\x1b[1m", s) }

// ok/info/warn/err 统一输出格式
func ok(format string, a ...any)   { fmt.Printf("  %s "+format+"\n", append([]any{green("✓")}, a...)...) }
func info(format string, a ...any) { fmt.Printf("  %s "+format+"\n", append([]any{cyan("·")}, a...)...) }
func warn(format string, a ...any) { fmt.Printf("  %s "+format+"\n", append([]any{yellow("!")}, a...)...) }
func bad(format string, a ...any)  { fmt.Printf("  %s "+format+"\n", append([]any{red("✗")}, a...)...) }

func title(s string) {
	fmt.Printf("\n%s %s\n", cyan("▌"), bold(s))
}

// progress 单行进度条：TTY 下 \r 覆盖；重定向到文件/管道时改成每 5 秒一行
type progress struct {
	label     string
	total     int64
	done      int64
	start     time.Time
	mu        sync.Mutex
	last      time.Time
	lastPlain time.Time
	plain     bool
	extra     string
}

func newProgress(label string, total int64) *progress {
	p := &progress{label: label, total: total, start: time.Now(), plain: !isTTY(os.Stderr)}
	if !p.plain {
		p.render(true)
	}
	return p
}

func (p *progress) add(n int64) {
	p.mu.Lock()
	p.done += n
	p.mu.Unlock()
	p.render(false)
}

func (p *progress) setExtra(s string) {
	p.mu.Lock()
	p.extra = s
	p.mu.Unlock()
}

// setPct 用于外部已经算出百分比进度（如 masscan 的 "x% done"）
func (p *progress) setPct(pct float64) {
	p.mu.Lock()
	p.total = 100
	p.done = int64(pct)
	p.mu.Unlock()
	p.render(true)
}

func (p *progress) render(force bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !force && time.Since(p.last) < 120*time.Millisecond {
		return
	}
	p.last = time.Now()

	const width = 26
	var pct float64
	if p.total > 0 {
		pct = float64(p.done) / float64(p.total) * 100
		if pct > 100 {
			pct = 100
		}
	}
	elapsed := time.Since(p.start).Seconds()
	rate := 0.0
	if elapsed > 0 {
		rate = float64(p.done) / elapsed
	}
	eta := ""
	if rate > 0 && p.total > p.done {
		rem := float64(p.total-p.done) / rate
		if rem > 90 {
			eta = fmt.Sprintf(" ETA %.0fm", rem/60)
		} else {
			eta = fmt.Sprintf(" ETA %.0fs", rem)
		}
	}

	if p.plain {
		if !force && time.Since(p.lastPlain) < 5*time.Second {
			return
		}
		p.lastPlain = time.Now()
		fmt.Fprintf(os.Stderr, "  %-8s %5.1f%% | %s/s%s %s\n", p.label, pct, humanRate(rate), eta, p.extra)
		return
	}

	filled := int(float64(width) * pct / 100)
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	line := fmt.Sprintf("\r  [%s] %5.1f%% | %s/s%s %s\x1b[K",
		bar, pct, humanRate(rate), eta, p.extra)
	fmt.Fprint(os.Stderr, line)
}

func (p *progress) finish(summary string) {
	p.mu.Lock()
	p.done = p.total
	plain := p.plain
	p.mu.Unlock()
	if plain {
		fmt.Fprintf(os.Stderr, "  %-8s 100.0%% | %s\n", p.label, summary)
		return
	}
	fmt.Fprintf(os.Stderr, "\r  [%s] 100.0%% | %s\x1b[K\n", strings.Repeat("█", 26), summary)
}

func humanRate(r float64) string {
	switch {
	case r >= 1e6:
		return fmt.Sprintf("%.1fM", r/1e6)
	case r >= 1e3:
		return fmt.Sprintf("%.1fk", r/1e3)
	default:
		return fmt.Sprintf("%.0f", r)
	}
}

func humanInt(n int64) string {
	s := fmt.Sprintf("%d", n)
	var out []byte
	for i, ch := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, ch)
	}
	return string(out)
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
