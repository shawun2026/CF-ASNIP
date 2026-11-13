#!/usr/bin/env bash
# asnip 一键卸载（与 install.sh uninstall 等价）
#   bash uninstall.sh
set -uo pipefail

APP="asnip"
HOME_DIR="${ASNIP_HOME:-$HOME/$APP}"
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
info() { printf "${GREEN}[+]${NC} %s\n" "$*"; }

for f in "/usr/local/bin/$APP" "$HOME/.local/bin/$APP"; do
    if [ -f "$f" ]; then
        if [ -w "$(dirname "$f")" ]; then rm -f "$f"; else sudo rm -f "$f"; fi
        info "已删除命令 $f"
    fi
done

for d in "$HOME_DIR" "$HOME/.asnip"; do
    if [ -d "$d" ]; then
        rm -rf "$d"
        info "已删除目录 $d"
    fi
done

printf "${GREEN}✅ 卸载完成${NC}\n"
