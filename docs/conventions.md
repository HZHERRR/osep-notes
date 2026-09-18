::: warning 仅供授权实验与备考学习
本文是个人备考教材。源码只用于 OSEP 官方实验/考试环境，或你拥有书面授权的目标。禁止对未授权系统使用。
:::

# 产出规范（所有模块必须遵守）

> 本目录是为 OSEP 考试（OffSec Experienced Penetration Tester）实验/考试环境准备的**授权测试**资料。
> 所有脚本只允许在 OSEP 实验网、考试靶场或你拥有书面授权的目标上使用。
> 技术路线以 `reference/osep-cheatsheet.md`（emmanuelsolis OSEP Cheatsheet）为准：**用老而稳的技术打通考试环境**，不追求新式 EDR 对抗。

## 1. 目录结构

```
osep-prep/
├── README.md                     # 索引（最后由总装生成）
├── CONVENTIONS.md                # 本文件
├── scenarios.md                  # 56 个场景清单 + 模块映射
├── reference/
│   └── osep-cheatsheet.md        # cheat sheet 全文（本地参考副本）
├── docs/
│   ├── 01-word-vba-office.md
│   ├── 02-hta.md
│   ├── 03-jscript-dotnettojscript.md
│   ├── 04-dll-sideloading.md
│   ├── 05-applocker-clm-amsi.md
│   ├── 06-uac-windows-privesc.md
│   ├── 07-credentials-lsass.md
│   ├── 08-pivoting-tunneling.md
│   ├── 09-c2-egress-channels.md
│   ├── 10-web-entry-webshell.md
│   ├── 11-mssql.md
│   ├── 12-ad-attacks.md
│   ├── 13-linux.md
│   ├── 14-kiosk-jea-jit.md
│   ├── 15-winrm-lateral.md
│   └── 16-ics-calendar.md
└── scripts/
    ├── vba/  powershell/  csharp/  hta/  jscript/  aspx/
    ├── c/    linux/       python/  infra/  sql/
```

## 2. 文档（docs/*.md）必须包含的结构

每个模块文档开头：

```markdown
# 模块 Mxx：<主题>

> 覆盖场景：<场景编号列表>
> cheat sheet 依据：<章节名>  |  教材依据：<第 N 章 / 节>
> 前置依赖：<需要哪些基础设施 / 工具 / 环境>
```

然后**每个场景一节**，标题格式固定：

```markdown
## 场景 N：<场景标题>

**场景回顾**：一句话复述该场景的失败点/限制。

**前提与假设**：目标环境假设、我方已有条件、需要预先准备的东西。

**准备（攻击机侧）**：
1. ... 命令 + 期望输出

**执行步骤**：
1. ...（编号步骤，每步给完整可复制命令；关键处说明"为什么"）

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `scripts/...` | ... | ... |

**验证**：如何确认成功（回连、文件落地、命令输出、票据等）。

**失败分支与备选**：至少 2 条，覆盖该场景可能出现的不同限制（例如"如果 X 被拦 → 换 Y"）。

**考试注意 / OPSEC**：容易丢分或踩坑的点（如 payload 位数、路径、编码、日志、时间窗）。
```

结尾必须有 `## 模块速查表`（一页命令清单）和 `## 关联脚本清单`。

## 3. 脚本规范

### 3.1 统一占位符（不得自创）

| 占位符 | 含义 |
|---|---|
| `LHOST` | 攻击机（Kali）可达 IP |
| `LPORT` | 监听端口 |
| `TARGET` | 目标 IP / 主机名 |
| `DOMAIN` | AD 域名（如 `oscp.exam`） |
| `USER` / `PASS` / `NTHASH` | 凭据 |
| `PAYLOAD` | 载荷文件名 |
| `URL` | 我方 HTTP(S) 地址 |

脚本内**必须**在文件头注释里说明如何替换这些占位符。

### 3.2 脚本头注释模板

```text
# 用途：<一句话>
# 场景：<对应场景编号>
# 依赖：<工具/运行库/编译方式>
# 使用：<最小可运行命令示例>
# 占位符：LHOST=... LPORT=...
# 测试状态：<已在本机做语法校验 / 未在 Windows 实测，需在实验环境验证>
```

### 3.3 脚本质量要求

- **可直接跑**：不要伪代码；参数化后能执行。
- **不留真实 IP/域名/密钥**：一律占位符。
- **保持最小可用**：单文件、少依赖；考试环境里越简单越稳。
- **位数/架构明确**：x86 与 x64 版本分别标注（`-x86` / `-x64` 后缀或注释）。
- **失败要有反馈**：脚本失败时打印可读错误，而不是静默退出。
- **能自检就自检**：Python 用 `python3 -m py_compile`，Bash 用 `bash -n`，PHP/JSP/ASPX 至少保证语法正确。
- 不要写入任何"自动传播/自毁/清除痕迹"功能。

### 3.4 命名

- 脚本文件名**统一以模块前缀开头**，避免多模块并行写作时冲突：`m06-fodhelper-uac.ps1`、`m13-xor-encoder.py`。
- 同一模块内多个同类脚本再加序号：`m01-shellcode-runner-vba-x64.vba`、`m01-shellcode-runner-vba-x86.vba`。
- 语言后缀固定：`.vba`（VBA 宏源码）、`.ps1`、`.cs`、`.hta`、`.js`、`.aspx`、`.c`、`.cpp`、`.py`、`.sh`、`.sql`、`.ics`、`.xsl`
- 基础设施配置：`scripts/infra/` 下，后缀按实际（`.conf`、`.md`、`.sh`）

## 4. 引用要求

- 每个技术点在文档里标注 cheat sheet 章节名（便于回查 `reference/osep-cheatsheet.md`）。
- 涉及教材章节的场景，保留用户原文里的"教材第 N 章 / §x.y"依据。
- 命令里出现的工具名要写清获取方式（Kali 自带 / 需编译 / 需从目标侧复制），但**不要写具体下载链接到未知来源**。

## 5. 交付自检（子代理完成前必须跑一遍）

```bash
ls -l <本模块要求的每个文件>            # 文件必须存在且非空
python3 -m py_compile <每个 .py>        # 若有 Python
bash -n <每个 .sh>                      # 若有 Bash
grep -n "TODO\|待补充\|xxx" <产出文件>   # 不应残留占位文字
```
