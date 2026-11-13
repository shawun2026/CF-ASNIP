# 构建 asnip.exe（Windows 原生，无 CGO、无外部依赖）
# 用法: powershell -ExecutionPolicy Bypass -File .\build.ps1
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host "[!] 未找到 go，请先安装 Go >= 1.22: https://go.dev/dl/" -ForegroundColor Red
    exit 1
}

$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"

Write-Host "[+] go vet" -ForegroundColor Cyan
go vet ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[+] go test" -ForegroundColor Cyan
go test ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[+] build" -ForegroundColor Cyan
go build -trimpath -ldflags "-s -w" -o asnip.exe .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$size = (Get-Item .\asnip.exe).Length / 1MB
Write-Host ("[✓] asnip.exe 构建完成  {0:N2} MB" -f $size) -ForegroundColor Green
Write-Host "    试跑: .\asnip.exe 209242 -stages asn"
