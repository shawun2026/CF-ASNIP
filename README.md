# CF-ASNIP

**从 ASN 编号出发，自动筛出可用的 Cloudflare 反代节点。**

[![release](https://img.shields.io/github/v/release/shawun2026/CF-ASNIP?label=release)](https://github.com/shawun2026/CF-ASNIP/releases)
[![license](https://img.shields.io/github/license/shawun2026/CF-ASNIP)](LICENSE)
![platform](https://img.shields.io/badge/platform-WSL2%20%7C%20Linux%20%7C%20Windows-2ea44f)

```
ASN → CIDR → masscan → CF 指纹粗筛 → proxyip 精筛 → CSV
```

按 ASN 拉取该 ASN 广播的 IPv4 前缀，把 CIDR **直接交给 masscan**（不再 prips 展开成百万行 IP），
做 Cloudflare 反代节点指纹识别，再调用 `https://proxyip.wasmer.app` 做二次精筛，
最后输出带 BOM 的 CSV 并起一个**只暴露这一个文件**的临时下载服务。

安装方式沿用 ASNIPtest 的 **Windows（WSL2）** 流程：`wsl --install` → 进 Ubuntu → 一条 `install.sh` 装完。
扫描器只有一条路径：**masscan**（内置 connect 扫描已移除，也不再预检抓包驱动）。

---

## 1. 安装

### Windows（WSL2，推荐）

**第一步：装 WSL2**（PowerShell 管理员模式，装完重启）

```powershell
wsl --install
```

重启后开始菜单会多一个「Ubuntu」。打开它（或任意终端里 `wsl -d Ubuntu`）即可继续。

**第二步：装 asnip**（二选一）

方式 A：一条命令（在 Ubuntu / 任意 Linux 里）

```bash
curl -fsSL https://raw.githubusercontent.com/shawun2026/CF-ASNIP/main/install.sh | bash
```

方式 B：Windows 侧一键（自动进 WSL 执行安装脚本，适合源码已在本地）

```powershell
git clone https://github.com/shawun2026/CF-ASNIP.git D:\tools\CF-ASNIP
cd D:\tools\CF-ASNIP
powershell -ExecutionPolicy Bypass -File .\install-wsl.ps1
```

方式 C：进 Ubuntu 手动跑本地源码

```bash
cd /mnt/d/tools/CF-ASNIP
bash install.sh
```

安装脚本做的事：

| 步骤 | 说明 |
|---|---|
| 定位源码 | 当前目录有 `go.mod`+`main.go` 就用它；否则读 `ASNIP_SRC` / `ASNIP_REPO` |
| Go | 已有的 ≥1.22 直接用；没有就下 `golang.google.cn`（备用 `go.dev`、阿里云镜像）装到 `~/.local/go`，不动系统目录 |
| masscan | 已装则跳过；没有就 `apt-get install masscan`（Ubuntu 26.04 实测 `/usr/bin/masscan` 就有） |
| 编译 | `go build -trimpath -ldflags "-s -w"` → `~/asnip/asnip` |
| 注册命令 | 优先 `/usr/local/bin/asnip`，无权限则 `~/.local/bin/asnip`；wrapper 自动 `sudo`（masscan 需要 root） |

**第三步：跑**

```powershell
wsl -d Ubuntu -- bash -lc "asnip 209242"
```

或进 Ubuntu 里直接 `asnip 209242`（若提示找不到命令，先 `source ~/.bashrc`）。

### Linux

```bash
curl -fsSL https://raw.githubusercontent.com/shawun2026/CF-ASNIP/main/install.sh | bash
# 或本地源码
bash install.sh
ASNIP_SRC=/path/to/CF-ASNIP bash install.sh
```

### Windows 原生 exe（可选，需要自备 masscan.exe）

```powershell
git clone https://github.com/shawun2026/CF-ASNIP.git
cd CF-ASNIP
powershell -ExecutionPolicy Bypass -File .\build.ps1     # 产出 asnip.exe
.\asnip.exe 209242                                        # 管理员终端里跑
```

也可以直接下 Release 里的 `asnip-windows-amd64.exe`。

> 官方 masscan 仓库没有 Windows 预编译二进制，需自行用 MSVC 构建或使用可信来源的构建。

### 后台跑长任务

扫描动辄几十分钟，终端/SSH 断开会杀进程，用 `screen`：

```bash
apt install -y screen
screen -S scan          # 进去正常跑 asnip 209242
# Ctrl+A 然后按 D 脱离；screen -r scan 恢复；screen -ls 列出会话
```

### 卸载 / 自检

```bash
asnip doctor            # 环境自检：os / wsl / cpu / 提权 / masscan / 可执行路径
bash install.sh update  # 重新编译（源码或 git 仓库）
bash install.sh uninstall
```

---

## 2. 前置条件

| 依赖 | 说明 |
|---|---|
| **masscan** | 放 PATH（Linux/WSL 直接 `apt install masscan`），或与 `asnip` 同目录，或 `-masscan <路径>` |
| **root / 提权** | masscan 打开发包设备需要权限。安装脚本注册的 `asnip` 命令已自动 `sudo`；直接跑二进制则用 `sudo` |
| 抓包驱动 | **不预检**。masscan 运行时若缺驱动/选错网卡，本工具会把它的 stderr 尾部原样抛出并附一句分类提示 |

启动扫描前只确认两件事，任一不满足就给出可执行的修复指引：

```
✗ 失败: 未找到 masscan.exe：
     把它放到 asnip.exe 同目录（或同目录的 masscan\ 子目录），或在 PATH 中，
     或用 -masscan D:\tools\masscan.exe 指定绝对路径
```

```
✗ 失败: 当前进程不是管理员：masscan 在 Windows 上需要提权才能打开发包设备。
     右键 Windows Terminal / PowerShell → “以管理员身份运行”，再执行本命令
     （若你的 masscan 已由服务/计划任务以高权限拉起，可加 -no-preflight 跳过此检查）
```

### 运行产物

产物都在 `runs/<时间戳>_AS<ASN>/`：

| 文件 | 内容 |
|---|---|
| `cidrs.txt` | RIPE 拉取并合并压缩后的 IPv4 前缀 |
| `prefixes.json` | 前缀 → 源 ASN 归属表（回填 CSV 的「源ASN」列） |
| `cidrs_scan.txt` | 实际喂给 masscan 的前缀清单（`-limit` 裁剪 / 去重后的结果） |
| `masscan_raw.txt` | masscan `-oL` 原始输出 |
| `open.txt` | 解析出的 `ip:port` 开放端口清单 |
| `cf_hits.jsonl` | 粗筛命中（TLS 版本、握手 ms、`cf-ray` 推出的边缘机房） |
| `verified.jsonl` | 精筛全量明细（含失败原因） |
| `output_AS*.csv` | 最终结果（UTF-8 BOM，Excel 双击不乱码） |
| `http/` | 仅含本次 CSV 的下载目录（WSL 下自动绑 0.0.0.0 并给 localhost 链接） |

---

## 3. 五个步骤

```
[1/5] ASN → CIDR     RIPE Stat announced-prefixes，只取 IPv4
                     + 归一化/去包含/兄弟前缀逐级合并（不改地址集合）
[2/5] 端口扫描       masscan -iL cidrs_scan.txt -p ... --rate N -oL ...
                     CIDR 直传，无 prips、无中间 IP 列表
[3/5] CF 粗筛        TLS 握手（SNI=cloudflare.com）+ HTTP/1.1 探测
                     指纹：server: cloudflare / cf-ray / cf-cache-status / __cf_bm
                     边缘机房直接读 cf-ray 尾部（如 ...-NRT → NRT）
[4/5] API 精筛       https://proxyip.wasmer.app/?ip=a:443,b:443,c:443
                     批量（默认 50，实测 200 可用）+ 并发 + 失败二分重试
[5/5] 输出           CSV（有效优先、响应时间升序）+ 临时下载服务
```

### 3.1 masscan 参数与常见场景

程序实际执行的命令（日志里会原样打印）：

```
masscan -iL runs\<run>\cidrs_scan.txt -p 443,8443,2053,2083,2087,2096 \
        --rate 16000 -oL runs\<run>\masscan_raw.txt --wait 5
```

`-masscan-args` 会把内容原样追加到末尾，用来处理这些情况：

| 场景 | 追加参数 |
|---|---|
| 多网卡/VPN，masscan 选错出口 | `--adapter-ip 192.168.1.10` |
| 需要指定网关 MAC（跨网段） | `--router-mac aa:bb:cc:dd:ee:ff` |
| 排除某些网段 | `--excludefile exclude.txt` |
| 固定源端口（过 ACL） | `--source-port 40000` |
| 只打印开放端口 | `--open-only` |

> `-masscan-args` 按空格切分，值里不要带空格；路径含空格时请改用相对路径或不含空格的目录。

### 3.2 关于 API 精筛的语义

`proxyip.wasmer.app` 校验的是「这个 `ip:port` 能不能当 ProxyIP 用」（内部经它自己的边缘回连并读取出口 IP），
**不是**「这是不是 Cloudflare 的 IP」。实测：

| 候选 | 结果 |
|---|---|
| `45.192.200.148:443`（第三方反代节点） | `有效ProxyIP: true`，`数据中心 NRT`，出口 IPv6 |
| `104.16.132.229:443`、`162.159.192.1:443`（CF 官方 anycast） | `有效ProxyIP: false`，`失败原因: 远端返回失败结果` |

所以：**官方 CF anycast IP 在精筛阶段通常会被判无效，这是接口语义，不是 bug**。
CSV 保留 `失败原因` 与 `CF官方IP` 两列，`-all` 可把无效行一并导出核对；结束时还会打印失败原因直方图。

### 3.3 硬件自适应默认值

启动时读 CPU 核数（+ 物理内存，仅用于展示），**只覆盖你没显式指定的项**：

| 参数 | 公式 | 16 核实测 |
|---|---|---|
| `-rate` | `clamp(核数 × 1000, 2000, 50000)` pps | 16000 pps |
| `-cf-conc` | `clamp(核数 × 100, 200, 1000)` | 1000 |
| `-vconc` | `clamp(核数 × 2, 4, 16)` | 16 |

```powershell
.\asnip.exe 209242                # 全自动
.\asnip.exe 209242 -rate 30000    # 只改速率，其余自动
.\asnip.exe 209242 -auto-tune=false
```

启动日志：

```
· 硬件 16 核 / 16070 MB → masscan 16000 pps、粗筛并发 1000、精筛并发 16（自动: masscan 速率、粗筛并发、精筛并发）
```

> 抓包驱动的实际吞吐取决于网卡，通常 2 万~4 万 pps 就到顶；`-rate` 设太高只会丢包漏报，不会更快。

---

## 4. 参数

```
asnip [ASN...] [-flags]          # ASN 与参数顺序任意：209242 -p 443 或 -p 443 209242
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `-p` | `ports.txt` | 端口，支持 `443` / `443,8443` / `1000-2000` |
| `-masscan` | 自动查找 | masscan.exe 路径（同目录 → 同目录 `masscan\` → PATH） |
| `-masscan-args` | 空 | 追加给 masscan 的原始参数（见 3.1） |
| `-rate` | 按硬件 | masscan pps |
| `-limit` | `0` | 只扫前 N 个地址（二分裁剪前缀实现）；小范围冒烟测试用 |
| `-max-ips` | `2000000` | 地址数守卫，超了要求 `-force` |
| `-force` | `false` | 忽略 `-max-ips` |
| `-no-preflight` | `false` | 跳过 masscan 路径与管理员检查 |
| `-cf-conc` | 按硬件 | 粗筛并发 |
| `-cf-timeout` | `2500ms` | 粗筛单目标超时 |
| `-sni` / `-host` | `cloudflare.com` / `www.cloudflare.com` | 粗筛探测用的 SNI / Host |
| `-api` | `https://proxyip.wasmer.app/` | 精筛接口 |
| `-batch` | `50` | 单次批量条数（上限 200） |
| `-vconc` | 按硬件 | 精筛并发批次数 |
| `-api-timeout` | `60s` | 单批请求超时 |
| `-rundir` | 自动 | 复用某个工作目录 |
| `-stages` | 全部 | 只跑指定阶段，如 `verify,out` |
| `-serve` | `true` | 结束后起下载服务（`-serve=false` 关闭） |
| `-bind` | 自动 | 下载服务绑定地址（WSL 下自动用 `0.0.0.0`，其余环境用局域网 IP） |
| `-http-port` | `8899` | 占用时自动 +1 重试（最多 12 次） |
| `-serve-wait` | `0` | 服务最长存活；`0` = 交互等回车、非交互 30s |
| `-auto-tune` | `true` | 按 CPU 自动匹配 `rate/cf-conc/vconc` |
| `-all` | `false` | CSV 连无效行一起输出 |

### 断点续跑

中间产物都是 append-only JSONL，启动时按 `target` 去重跳过：

```powershell
# masscan 中断后继续（已完成的粗筛/精筛不会再跑）
.\asnip.exe -rundir runs\20261113_151200_AS209242 -stages cfscan,verify,out
# 只重做精筛和输出
.\asnip.exe -rundir runs\20261113_151200_AS209242 -stages verify,out
```

---

## 5. CSV 列

| 列 | 来源 | 说明 |
|---|---|---|
| IP / 端口 | masscan `-oL` | 实测开放 |
| TLS | 本地 TLS 握手 | 真实版本，如 `TLS 1.3` |
| 边缘机房 | 本地 `cf-ray` 尾部 | 如 `NRT`，本地实测，不依赖第三方 |
| 源ASN | RIPE 前缀归属表 | 该 IP 来自哪个 ASN 的段（如 `AS209242`） |
| 数据中心 / 国家 / 地区 / 城市 | 精筛接口 | 接口判定 |
| 响应时间(ms) | 精筛接口 | 由 `223ms` 解析为数字 |
| ASN / 组织 | 精筛接口 | 出口侧 ASN（如 `AS401615`） |
| 双栈 / 出口IP / 出口类型 | 精筛接口 | 例如 IPv6 出口 |
| CF官方IP | 精筛接口 | `是否为Cloudflare官方IP` |
| 状态 | — | `有效` 或 `无效: <失败原因>` |

排序：有效在前 → 响应时间升序 → 地址。

---

## 6. 相对此前版本的改动

| 变更 | 说明 |
|---|---|
| **移除内置 connect 扫描** | 扫描只剩 masscan 一条路径，不再有 `-scanner/-conc/-timeout` |
| **移除 Npcap 预检** | 不再检查 `wpcap.dll`、不再拦截启动；抓包驱动问题交给 masscan 自己报，本工具只做 stderr 分类提示 |
| **前置检查只留两项** | masscan 定位 + 管理员提权；`-no-preflight` 可整体跳过 |
| **新增 `-masscan-args`** | 原样透传 `--adapter-ip` / `--router-mac` / `--excludefile` 等 |
| **`-limit` 语义改为裁剪前缀** | 二分拆分前缀取前 N 个地址，masscan 侧无需额外支持 |
| **自适配改为 masscan 口径** | `rate = clamp(核数×1000, 2000, 50000)`，不再有并发参数 |
| masscan 失败诊断 | 保留 stderr 尾部 20 行，按驱动/网卡/权限/路径四类给出提示 |
| 仍然保留的改进 | CIDR 直传、cf-ray 取机房、精筛批量+二分重试、单文件下载服务、断点续跑、参数重排 |

---

## 7. 常见问题

**`masscan` 报 “FAIL: could not determine default interface”**
多网卡/VPN 环境选不准出口。加 `-masscan-args "--adapter-ip <本机出口IP>"`，跨网段再加 `--router-mac <网关MAC>`。

**`masscan` 报驱动 / 打不开设备相关错误**
本工具不做预检，错误来自 masscan 自身。按它的 stderr 原文处理（通常是抓包驱动缺失或未提权）；
这类失败会带 `→ masscan 打不开发包设备` 的提示，与网卡/权限/路径错误区分开。

**实测速率远低于 `-rate`**
瓶颈在网卡/抓包驱动，不是 CPU。把 `-rate` 降到实测值附近（2 万上下），否则 masscan 会丢包漏报开放端口。

**中文乱码 / 进度条错位**
用 Windows Terminal 或 PowerShell 7；程序启动会 `SetConsoleOutputCP(65001)` 并开启 VT 处理，
重定向到文件时进度条自动降级为每 5 秒一行。

**下载链接打不开**

WSL2：程序会把链接打成 `http://localhost:端口/...`，Windows 浏览器直接打开即可；局域网其它设备才需要 `netsh interface portproxy`（程序会把命令打印出来）。

Windows 原生 exe：防火墙默认拦入站，按提示执行一次（管理员）：
```powershell
netsh advfirewall firewall add rule name="asnip" dir=in action=allow protocol=TCP localport=8899
```

**只想扫自己的网段**
把 `prefixes.json` 换成自己的段即可复用 3/4/5 阶段：
```json
[{"prefix":"203.0.113.0/24","asn":"64496"}]
```

---

## 8. 目录结构

```
asnip/
├─ main.go            CLI、参数重排、阶段编排、硬件自适应
├─ asn.go             RIPE Stat 拉取 + 前缀合并 + 归属表
├─ scan.go            masscan 调用、前置检查、-limit 前缀裁剪、-oL 解析
├─ cfscan.go          TLS/HTTP 指纹、cf-ray 机房提取、断点续跑
├─ verify.go          wasmer API 批量/重试/二分降级、JSONL、失败原因统计
├─ output.go          CSV（BOM/排序）+ 单文件临时 HTTP 服务
├─ console.go         颜色、进度条（TTY/重定向两种模式）
├─ console_windows.go SetConsoleOutputCP / VT 模式
├─ hw_windows.go      CPU 核数 / 物理内存 / 提权判断
├─ asnip_test.go      单元测试
├─ install.sh         Linux / WSL2 安装脚本（Go + masscan + 编译 + 注册命令）
├─ install-wsl.ps1    Windows 侧一键装进 WSL2
├─ uninstall.sh       卸载脚本
├─ ports.txt          默认端口
└─ testdata/          masscan 假体（无 masscan 环境时验证集成逻辑，不参与构建）
```

> 使用边界：只对自己有权测试的 ASN/网段执行扫描。`-rate` 越低越不容易惊动对端 IDS。
