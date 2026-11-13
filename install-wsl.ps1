# Windows 侧一键装到 WSL2（对应 README「Windows（WSL2）」安装方式）
#
#   管理员 PowerShell:
#     powershell -ExecutionPolicy Bypass -File .\install-wsl.ps1
#
# 流程：
#   1. 检查 wsl.exe / 目标发行版
#   2. 缺发行版就执行 wsl --install -d Ubuntu（装完需重启，脚本会退出提示）
#   3. 把当前目录映射成 /mnt/<盘符>/...，在发行版里执行 install.sh
param(
    [string]$Distro = "Ubuntu",
    [string]$SourcePath = $PSScriptRoot
)

$ErrorActionPreference = "Stop"
function Info($m) { Write-Host "[+] $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    Die "未找到 wsl.exe。请先以管理员身份运行： wsl --install   然后重启电脑"
}

# 发行版是否可用（直接试跑，避免解析 UTF-16 的 wsl -l 输出）
$null = & wsl.exe -d $Distro -- true 2>$null
if ($LASTEXITCODE -ne 0) {
    Warn "发行版 $Distro 不可用，开始安装（需要管理员权限，装完必须重启）"
    & wsl.exe --install -d $Distro
    if ($LASTEXITCODE -ne 0) { Die "wsl --install 失败，请手动执行：wsl --install -d $Distro" }
    Write-Host ""
    Write-Host "✅ WSL2 + $Distro 已开始安装，重启电脑后重新运行本脚本即可。" -ForegroundColor Green
    exit 0
}

# Windows 路径 → WSL 路径
if (-not (Test-Path -LiteralPath (Join-Path $SourcePath "install.sh"))) {
    Die "在 $SourcePath 下找不到 install.sh：请把本脚本放在 asnip 项目目录里运行"
}
$full  = (Resolve-Path -LiteralPath $SourcePath).Path
$drive = $full.Substring(0, 1).ToLower()
$rest  = $full.Substring(2) -replace '\\', '/'
$wslPath = "/mnt/$drive$rest"

Info "发行版: $Distro"
Info "源码目录: $wslPath"
Info "开始安装（首次会下载 Go 工具链，约 70MB）..."
Write-Host ""

& wsl.exe -d $Distro -- bash "$wslPath/install.sh" install
if ($LASTEXITCODE -ne 0) { Die "安装脚本返回 $LASTEXITCODE" }

Write-Host ""
Write-Host "✅ 完成。以后在任意终端直接运行：" -ForegroundColor Green
Write-Host "   wsl -d $Distro -- bash -lc ""asnip 209242""" -ForegroundColor White
Write-Host "或先进入发行版再跑：" -ForegroundColor Gray
Write-Host "   wsl -d $Distro" -ForegroundColor White
Write-Host "   asnip 209242      # 若提示找不到命令，先 source ~/.bashrc" -ForegroundColor White
