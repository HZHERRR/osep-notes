::: warning 仅限授权使用
本笔记仅用于 OSEP 官方实验 / 考试环境，或已获得书面授权的测试。禁止对未授权系统使用。
:::

# 00 · 环境与基础设施（所有模块共用）

> 本文不属于任何单一场景，而是 56 个场景共用的攻击机准备、载荷矩阵、监听/回传规范和决策流程。
> 每个模块文档里的"准备（攻击机侧）"都默认你已经按本文把基础设施搭好。

---

## 1. 环境假设

| 角色 | 系统 | 说明 |
|---|---|---|
| 攻击机 | Kali Linux（考试官方镜像） | 全部监听、编译、投递、隧道操作在此进行 |
| 入口目标 | Windows 10/11 + Office | 存在 Defender、可能启用 AppLocker / CLM / AMSI |
| 域环境 | AD DS（可能含子域、ADCS、MSSQL、IIS） | 域管、委派、证书、SQL 服务账户等 |
| Linux 目标 | 加域或独立 | ELF 执行、共享库、sudo、SSH 复用、Kerberos 票据 |
| 网络限制 | 分段 + 代理 + 可能只放行少量出网路径 | 决定你用直连、代理、DNS 还是域前置 |

**核心原则**：cheat sheet 里的技术"老但能打通考试环境"。考试环境不是现代 EDR 战场，别为了追新把链路搞复杂——**越简单越稳，失败一次的时间成本极高**。

---

## 2. 攻击机目录与命名规范

```bash
mkdir -p ~/osep/{payloads/{win/{x86,x64},linux,web},listeners,logs,loot,tools}
cd ~/osep
```

| 目录 | 放什么 |
|---|---|
| `payloads/win/x86`、`payloads/win/x64` | 按位数分开的 Windows 载荷（**不要混放**） |
| `payloads/linux` | ELF、共享库、编码后的 loader |
| `payloads/web` | ASPX/JSP/PHP shell、上传文件 |
| `listeners` | 监听脚本、监听命令备忘 |
| `logs` | 每个入口一个日志文件，用于确认回连与排错 |
| `loot` | 哈希、票据、凭据、截图 |
| `tools` | 编译产物与第三方工具（只放可信来源） |

**统一占位符**（全项目一致，不得自创）：

| 占位符 | 含义 |
|---|---|
| `LHOST` | 攻击机可达 IP |
| `LPORT` | 监听端口 |
| `TARGET` | 目标 IP/主机名 |
| `DOMAIN` | AD 域名 |
| `USER` / `PASS` / `NTHASH` | 凭据 |
| `PAYLOAD` | 载荷文件名 |
| `URL` | 我方 HTTP(S) 地址 |

---

## 3. 端口与基础设施规划

固定一套端口，避免考试中记混：

| 端口 | 用途 |
|---|---|
| 80 | HTTP 投递（python3 -m http.server / nginx） |
| 443 | HTTPS 投递（自签证书，记录指纹） |
| 445 | SMB 投递（impacket-smbserver / Responder 关闭时） |
| 8080 | 备用 HTTP / SOCKS 前置 |
| 4444 | 通用反向 shell 监听 |
| 4445 | 备用监听（第二个会话） |
| 11601 | Ligolo-ng 代理端 |
| 5985 | WinRM（目标侧） |

```bash
# HTTP 投递 + 请求日志（确认目标是否真的下载了）
cd ~/osep/payloads && python3 -m http.server 80 2>&1 | tee ~/osep/logs/http-80.log

# HTTPS 投递
openssl req -newkey rsa:2048 -nodes -keyout ~/osep/tools/key.pem \
  -x509 -days 365 -out ~/osep/tools/cert.pem -subj "/CN=LHOST"
# 记下指纹，目标侧如需信任证书时使用
openssl x509 -in ~/osep/tools/cert.pem -noout -fingerprint -sha256

# SMB 投递（无需认证的临时共享）
impacket-smbserver share ~/osep/payloads -smb2support

# 带 readline 的监听（强烈建议，考试里少按坏键盘）
rlwrap -cAr nc -lvnp 4444 | tee ~/osep/logs/shell-4444.log
```

**回连验证三件套**（每个入口都要做）：

1. 目标是否访问了投递地址 → 看 HTTP/SMB 日志
2. 载荷是否真的执行 → 无害回调（`curl`/`nslookup`/写文件）先验证
3. 会话是否稳定 → 立即 `whoami /priv`、`systeminfo`、确认位数与用户

---

## 4. 载荷矩阵（按入口类型选形态）

| 入口 | 首选形态 | 依赖出网 | 备注 |
|---|---|---|---|
| Word 宏 | VBA 内嵌 Runner / PowerShell stager | 视场景 | 位数未知时先探测 |
| HTA | HTA + PowerShell / 内嵌 C# | 视场景 | AppLocker 下优先非 EXE |
| JScript | DotNetToJScript + C# 第二阶段 | 视场景 | WSH 宿主，AMSI 处理要单独做 |
| 邮件 ZIP | Proxy DLL + 旁加载宿主 | 否 | 保持宿主正常运行 |
| 邮件/网站 | InstallUtil / Workflow / XSL | 否 | 受信任宿主，绕 AppLocker |
| Web（ASPX） | 精简 ASPX + 托管加载 | 是 | 服务账户，注意 AV 查杀 |
| Web（命令注入） | 短命令 + 下载器备选 | 是 | 注意长度限制 |
| Linux | 自定义 ELF / 共享库 | 视场景 | 保持业务输出与生命周期 |

**位数规则**：任何 Windows 载荷在生成前先确定目标位数。探测方法见 [01-word-vba-office](/zh/modules/01-word-vba-office) 场景 1；不确定时 **两套都准备**，用分支逻辑选择。

**staged vs stageless**：所有阶段必须走**同一条已验证可达的通信路径**。第一阶段通了、第二阶段不通，90% 是地址/端口/协议不一致或代理上下文不同（见 [09-c2-egress-channels](/zh/modules/09-c2-egress-channels)）。

---

## 5. 被拦时的排查顺序（通用决策树）

```
载荷没反应
├─ 投递日志里没有请求 → 投递被拦/用户没打开 → 换投递方式（HTTP→SMB→邮件附件）
├─ 有请求但没执行     → 载荷被静态查杀 → 编码/加密/换宿主形态（模块 M05）
├─ 执行了但立即退出   → 位数不匹配 / 依赖缺失 / 导出函数不匹配（M01、M04）
├─ 执行了但被终止     → 行为检测 → 换进程内/跨进程实现（M05 场景 19）
├─ 第一阶段通了、第二阶段没有 → 通信路径/代理上下文不一致（M09）
└─ 会话建立了但很快断 → 宿主生命周期问题 → 迁移/常驻（M01 场景 5）
```

**排查纪律**：一次只改一个变量；每改一次都记录"改了什么、结果如何"。考试评分看的是过程，不是运气。

---

## 6. 编译环境准备（Kali 侧）

```bash
# Windows 交叉编译（x64 / x86）
sudo apt install -y mingw-w64
x86_64-w64-mingw32-gcc -o payload-x64.exe payload.c -lws2_32 -s -O2
i686-w64-mingw32-gcc   -o payload-x86.exe payload.c -lws2_32 -s -O2

# 共享库 / Proxy DLL
x86_64-w64-mingw32-gcc -shared -o proxy.dll proxy.c proxy.def -s
x86_64-w64-mingw32-g++ -shared -o proxy.dll proxy.cpp proxy.def -s

# Linux 侧
gcc -o loader loader.c -O2
gcc -shared -fPIC -o libpayload.so libpayload.c -O2
```

.NET 程序集用目标机上已有的 `csc.exe` 编译（考试环境里比装 Mono 稳），或在本机用 `mcs`/`dotnet` 预编译后只投递程序集。

---


## 8. 关联文档

| 文档 | 内容 |
|---|---|
| [01-word-vba-office](/zh/modules/01-word-vba-office) | Word/VBA 入口、位数探测、Runner |
| [02-hta](/zh/modules/02-hta) | HTA 入口与 AppLocker/CLM/AMSI 组合 |
| [05-applocker-clm-amsi](/zh/modules/05-applocker-clm-amsi) | 免杀与受信任宿主 |
| [09-c2-egress-channels](/zh/modules/09-c2-egress-channels) | 出网通道：代理、DNS、域前置、分阶段 |
| [99-pre-exam-checklist](/zh/modules/99-pre-exam-checklist) | 考前逐项检查清单 |
