#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# asnip 一键安装 / 更新 / 卸载（Linux / WSL2 Ubuntu）
#
#   项目目录内：   bash install.sh
#   一键（远程）： curl -fsSL <RAW_URL>/install.sh | ASNIP_REPO=<git地址> bash
#   指定源码目录： ASNIP_SRC=/path/to/asnip bash install.sh
#   子命令：       install | update | uninstall | doctor
# ─────────────────────────────────────────────────────────────
set -euo pipefail

VERSION="2.3.0"
DEFAULT_REPO="https://github.com/shawun2026/CF-ASNIP.git"
APP="asnip"
INSTALL_DIR="${ASNIP_HOME:-$HOME/$APP}"
GO_MIN_MAJOR=1
GO_MIN_MINOR=22
GO_VERSION="1.22.12"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'
BOLD='\033[1m'; NC='\033[0m'

info() { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
err()  { printf "${RED}[x]${NC} %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }

logo() {
    printf "${CYAN}${BOLD}"
    echo "   ╔══════════════════════════════════════╗"
    echo "   ║        asnip  ${VERSION}                  ║"
    echo "   ║   ASN → CIDR → masscan → CF 节点     ║"
    echo "   ╚══════════════════════════════════════╝"
    printf "${NC}"
}

SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi

is_wsl() {
    [ -n "${WSL_DISTRO_NAME:-}" ] && return 0
    grep -qi "microsoft\|wsl" /proc/version 2>/dev/null
}

# ── Go ──
go_ok() {
    command -v go >/dev/null 2>&1 || return 1
    local v maj min
    v=$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')
    maj=${v%%.*}
    min=$(echo "$v" | cut -d. -f2)
    [[ "$maj" =~ ^[0-9]+$ && "$min" =~ ^[0-9]+$ ]] || return 1
    [ "$maj" -gt "$GO_MIN_MAJOR" ] || { [ "$maj" -eq "$GO_MIN_MAJOR" ] && [ "$min" -ge "$GO_MIN_MINOR" ]; }
}

ensure_go() {
    # 可能上一轮已装到 ~/.local/go 或 /usr/local/go，但当前 shell 的 PATH 里没有
    for cand in "$HOME/.local/go/bin" "/usr/local/go/bin"; do
        if [ -x "$cand/go" ]; then export PATH="$cand:$PATH"; fi
    done
    if go_ok; then
        info "Go $(go version | awk '{print $3}') 已就绪"
        return 0
    fi
    warn "未检测到 Go ≥ ${GO_MIN_MAJOR}.${GO_MIN_MINOR}，开始安装 Go ${GO_VERSION} ..."

    local goarch
    case "$(uname -m)" in
        x86_64|amd64) goarch=amd64 ;;
        aarch64|arm64) goarch=arm64 ;;
        *) die "不支持的架构：$(uname -m)" ;;
    esac

    local tmp; tmp=$(mktemp -d)
    local ok=""
    for url in \
        "https://golang.google.cn/dl/go${GO_VERSION}.linux-${goarch}.tar.gz" \
        "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz" \
        "https://mirrors.aliyun.com/golang/go${GO_VERSION}.linux-${goarch}.tar.gz"; do
        info "下载 $url"
        if curl -fsSL --connect-timeout 10 --retry 2 "$url" -o "$tmp/go.tgz"; then ok=1; break; fi
        warn "  该源不可用，换下一个"
    done
    [ -n "$ok" ] || die "Go 下载失败：请手动安装 Go ≥${GO_MIN_MAJOR}.${GO_MIN_MINOR} 后重试"

    local prefix="$HOME/.local"
    if [ "$(id -u)" -eq 0 ]; then prefix="/usr/local"; fi
    mkdir -p "$prefix"
    rm -rf "$prefix/go"
    tar -C "$prefix" -xzf "$tmp/go.tgz"
    rm -rf "$tmp"
    export PATH="$prefix/go/bin:$PATH"
    for rc in "$HOME/.profile" "$HOME/.bashrc"; do
        [ -f "$rc" ] || continue
        grep -q "$prefix/go/bin" "$rc" 2>/dev/null || echo "export PATH=\"$prefix/go/bin:\$PATH\"" >> "$rc"
    done
    go_ok || die "Go 安装后仍不可用，请检查 $prefix/go/bin 是否在 PATH"
    info "Go $($prefix/go/bin/go version | awk '{print $3}') 安装完成（$prefix/go）"
}

# ── masscan ──
ensure_masscan() {
    if command -v masscan >/dev/null 2>&1; then
        info "masscan 已就绪：$(command -v masscan)"
        return 0
    fi
    warn "未检测到 masscan，尝试用包管理器安装 ..."
    if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get update -qq || true
        $SUDO apt-get install -y -qq masscan || warn "apt 安装 masscan 失败"
    elif command -v dnf >/dev/null 2>&1; then
        $SUDO dnf install -y -q masscan || warn "dnf 安装 masscan 失败"
    elif command -v yum >/dev/null 2>&1; then
        $SUDO yum install -y -q masscan || warn "yum 安装 masscan 失败"
    else
        warn "未识别包管理器"
    fi
    command -v masscan >/dev/null 2>&1 || die "masscan 未安装成功：请手动安装（apt install masscan）后重试"
    info "masscan 安装完成：$(command -v masscan)"
}

# ── 源码定位 ──
resolve_src() {
    local self="${BASH_SOURCE[0]:-}"
    if [ -n "$self" ] && [ -f "$self" ]; then
        local d; d=$(cd "$(dirname "$self")" && pwd)
        if [ -f "$d/go.mod" ] && [ -f "$d/main.go" ]; then
            SRC="$d"; return 0
        fi
    fi
    if [ -n "${ASNIP_SRC:-}" ] && [ -f "${ASNIP_SRC}/go.mod" ]; then
        SRC="$ASNIP_SRC"; return 0
    fi
    local repo="${ASNIP_REPO:-$DEFAULT_REPO}"
    if [ -n "$repo" ]; then
        local tmp; tmp=$(mktemp -d)
        info "克隆 $repo"
        if command -v git >/dev/null 2>&1; then
            git clone --depth 1 "$repo" "$tmp/src" >/dev/null 2>&1 || die "git clone 失败：$repo"
        else
            local url="${repo%.git}"
            curl -fsSL "$url/archive/refs/heads/main.tar.gz" -o "$tmp/src.tgz" || die "下载源码失败：$url"
            mkdir -p "$tmp/src" && tar -xzf "$tmp/src.tgz" -C "$tmp/src" --strip-components=1
        fi
        SRC="$tmp/src"; return 0
    fi
    die "找不到源码目录。三种方式任选：
     1) 在项目目录里执行： bash install.sh
     2) ASNIP_SRC=/path/to/asnip bash install.sh
     3) ASNIP_REPO=https://github.com/shawun2026/CF-ASNIP.git bash install.sh"
}

build() {
    [ -n "${SRC:-}" ] || resolve_src
    info "编译 asnip（$(go version | awk '{print $3}')）..."
    mkdir -p "$INSTALL_DIR"
    ( cd "$SRC" && go build -trimpath -ldflags "-s -w" -o "$INSTALL_DIR/$APP" . )
    cp -f "$SRC/ports.txt" "$INSTALL_DIR/" 2>/dev/null || true
    cp -f "$SRC/README.md" "$INSTALL_DIR/" 2>/dev/null || true
    cp -f "$SRC/install.sh" "$INSTALL_DIR/" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/$APP"
    info "二进制：$INSTALL_DIR/$APP（$(du -h "$INSTALL_DIR/$APP" | cut -f1)）"
}

# ── 注册命令（非 root 时自动 sudo 提权跑 masscan）──
install_wrapper() {
    local tmp; tmp=$(mktemp)
    cat > "$tmp" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
DIR="${ASNIP_HOME:-$HOME/asnip}"
BIN="$DIR/asnip"
[ -x "$BIN" ] || { echo "asnip 未安装或不可执行：$BIN" >&2; exit 1; }
# 只读子命令不需要提权，避免每次都弹密码
case "${1:-}" in
    version|-v|--version|doctor|-h|--help|help) exec "$BIN" "$@" ;;
esac
if [ "$(id -u)" -eq 0 ]; then
    exec "$BIN" "$@"
fi
exec sudo -E "$BIN" "$@"
EOS
    chmod +x "$tmp"

    local target="/usr/local/bin/$APP"
    if [ "$(id -u)" -eq 0 ]; then
        mv "$tmp" "$target"
    elif [ -w /usr/local/bin ]; then
        mv "$tmp" "$target"
    elif $SUDO -n true 2>/dev/null && $SUDO mv "$tmp" "$target" 2>/dev/null; then
        :
    else
        target="$HOME/.local/bin/$APP"
        mkdir -p "$(dirname "$target")"
        mv "$tmp" "$target"
        grep -q '.local/bin' "$HOME/.bashrc" 2>/dev/null || echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    fi
    chmod +x "$target"
    WRAPPER="$target"
    info "命令已注册：$target"
}

do_install() {
    logo
    info "系统：$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -s)"
    if is_wsl; then info "环境：WSL2（$(grep -o 'microsoft.*' /proc/version 2>/dev/null | head -c 40)）"; fi
    info "安装目录：$INSTALL_DIR"

    resolve_src
    info "源码：$SRC"

    ensure_go
    ensure_masscan
    build
    install_wrapper

    echo ""
    printf "${GREEN}${BOLD}✅ 安装完成${NC}\n\n"
    cat <<EOS
  快速开始（masscan 需要 root，wrapper 已自动 sudo）：
    $APP 209242
    $APP 209242,3214 -p 443,8443
    $APP doctor                    # 检查 go / masscan / 权限
    $APP -rundir runs/<dir> -stages verify,out

  长扫描建议放 screen 里（SSH/终端断开不中断）：
    screen -S scan                 # 进去正常跑 asnip
    # Ctrl+A 然后按 D 脱离；screen -r scan 恢复

  产物默认在运行目录下的 runs/ 里，结尾会起一个临时下载服务。
EOS
    echo ""
}

do_update() {
    [ -d "$INSTALL_DIR" ] || die "还没安装，先执行 bash install.sh"
    if [ -d "$INSTALL_DIR/.git" ]; then
        info "更新源码 ..."
        ( cd "$INSTALL_DIR" && git pull --ff-only )
        SRC="$INSTALL_DIR"
    else
        resolve_src
    fi
    ensure_go
    build
    install_wrapper
    printf "${GREEN}✅ 已更新到 %s 最新构建${NC}\n" "$VERSION"
}

do_uninstall() {
    local target="/usr/local/bin/$APP"
    if [ -f "$target" ]; then $SUDO rm -f "$target" && info "已删除 $target"; fi
    if [ -f "$HOME/.local/bin/$APP" ]; then rm -f "$HOME/.local/bin/$APP" && info "已删除 ~/.local/bin/$APP"; fi
    if [ -d "$INSTALL_DIR" ]; then rm -rf "$INSTALL_DIR" && info "已删除 $INSTALL_DIR"; fi
    printf "${GREEN}✅ 卸载完成${NC}\n"
}

do_doctor() {
    logo
    echo "  os        : $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -s) / $(uname -m)"
    echo "  wsl       : $(is_wsl && echo yes || echo no)"
    echo "  kernel    : $(uname -r)"
    echo "  user      : $(id -un) (uid=$(id -u))"
    echo "  go        : $(command -v go >/dev/null 2>&1 && go version | awk '{print $3}' || echo MISSING)"
    echo "  masscan   : $(command -v masscan >/dev/null 2>&1 && command -v masscan || echo MISSING)"
    echo "  asnip bin : $([ -x "$INSTALL_DIR/$APP" ] && echo "$INSTALL_DIR/$APP" || echo MISSING)"
    echo "  wrapper   : $(command -v "$APP" 2>/dev/null || echo MISSING)"
    echo "  sudo      : $([ "$(id -u)" -eq 0 ] && echo root || ($SUDO -n true 2>/dev/null && echo passwordless || echo needs-password))"
    echo ""
}

main() {
    case "${1:-install}" in
        install)   do_install ;;
        update)    do_update ;;
        uninstall) do_uninstall ;;
        doctor)    do_doctor ;;
        *)         die "未知子命令：$1（可用：install / update / uninstall / doctor）" ;;
    esac
}

main "${1:-install}"
