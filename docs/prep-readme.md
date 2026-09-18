::: warning 仅供授权实验与备考学习
本文是个人备考教材。源码只用于 OSEP 官方实验/考试环境，或你拥有书面授权的目标。禁止对未授权系统使用。
:::

# OSEP 考试备考资料包

> 依据用户整理的 **56 个 OSEP 考试场景**（`/Users/barok/Desktop/xxx`）编写，技术路线对齐
> [emmanuelsolis OSEP Cheatsheet](https://www.emmanuelsolis.com/osep.html)（本地副本：`reference/osep-cheatsheet.md`）。
>
> ⚠️ **仅限授权测试**：OSEP 实验环境、考试靶场，或你持有书面授权的目标。请勿用于任何未授权系统。

---

## 这套资料解决什么问题

你列出的 56 个场景，本质上都是**同一条链路在不同限制下的变形**：入口 → 执行 → 通信 → 提权 → 横向。
本资料把每个场景拆成"为什么失败 / 需要提前准备什么 / 怎么一步步做 / 怎么验证 / 失败后换什么"，并给出**可以直接改 IP 就用的脚本**。

核心思路（对齐 cheat sheet）：**老技术 + 提前准备 + 组合验证**。考试环境不是现代 EDR 战场，稳定的老方法比花哨的新方法更能拿分。

---

## 目录结构

```
osep-prep/
├── README.md                      ← 本文件
├── CONVENTIONS.md                 ← 产出规范（文档结构、脚本头注释、占位符）
├── scenarios.md                   ← 56 个场景原文 + 模块映射
├── docs/                          ← 20 篇文档（16 模块 + 4 篇跨模块）
│   ├── 00-environment-and-infra.md   攻击机环境、端口规划、载荷矩阵、排查决策树
│   ├── 01…16-*.md                    场景 1–56 的详细流程（56/56 全覆盖）
│   ├── 97-exam-day-lookup.md         考场快速定位表（现象 → 场景 → 文档）
│   ├── 98-exam-note-template.md      考试记录与报告模板
│   └── 99-pre-exam-checklist.md      考前逐项检查清单
├── scripts/                       ← 80 个脚本（按语言分组）
│   ├── vba/ powershell/ csharp/ hta/ jscript/ aspx/
│   ├── c/ linux/ python/ sql/ infra/
│   └── INDEX.md                      脚本索引（自动生成）
├── reference/
│   └── osep-cheatsheet.md         ← cheat sheet 全文本地副本（便于离线查阅）
└── tools/
    ├── verify.py                  ← 自检脚本（结构/覆盖/语法/交叉引用/索引）
    ├── SUBAGENT_BRIEF.md          ← 产出规格（供后续扩展模块复用）
    └── scenario-matrix.md         ← 场景 → 模块文档 对照表（自动生成）
```

**交付统计**：文档 20 篇 / 约 4,500 行；脚本 80 个 / 约 7,800 行；56 个场景 100% 覆盖；
文档→脚本交叉引用 89 处、0 处缺失；Python / Bash / JavaScript / C 均已通过语法校验。

---

## 怎么用

**考前准备（按顺序）**

1. 读 [`docs/00-environment-and-infra.md`](/modules/00-environment-and-infra)，把攻击机目录、端口、投递服务、编译环境搭好。
2. 打开 [`docs/99-pre-exam-checklist.md`](/modules/99-pre-exam-checklist)，**逐项生成并验证**准备物，打勾。
3. 针对自己薄弱的模块，读对应 `docs/0X-*.md` 并用 `scripts/` 下的脚本实操一遍。

**考试中**

1. 拿到入口先判断属于哪个场景 → 打开对应模块文档的"场景 N"小节。
2. 按"准备（攻击机侧）→ 执行步骤 → 验证"照做；卡住就查"失败分支与备选"。
3. 每一步命令与输出记进笔记（报告要复现）。

**自检**

```bash
cd /Users/barok/Desktop/osep-prep
python3 tools/verify.py --index     # 检查文档/脚本完整性并重建索引
```

---

## 模块与场景对照

| 模块 | 主题 | 场景 | 文档 |
|---|---|---|---|
| M01 | Word/VBA 宏入口与载荷形态 | 1–5 | [`docs/01-word-vba-office.md`](/modules/01-word-vba-office) |
| M02 | HTA 入口与 AppLocker/CLM/AMSI 组合 | 6–8 | [`docs/02-hta.md`](/modules/02-hta) |
| M03 | JScript / WSH 与 DotNetToJScript | 9–10 | [`docs/03-jscript-dotnettojscript.md`](/modules/03-jscript-dotnettojscript) |
| M04 | DLL 旁加载与 Proxy DLL | 11–12 | [`docs/04-dll-sideloading.md`](/modules/04-dll-sideloading) |
| M05 | AppLocker/CLM/AMSI 绕过与受信任宿主 | 18–24 | [`docs/05-applocker-clm-amsi.md`](/modules/05-applocker-clm-amsi) |
| M06 | Windows 本地提权：UAC/令牌/服务 | 25–27 | [`docs/06-uac-windows-privesc.md`](/modules/06-uac-windows-privesc) |
| M07 | 凭据获取：LSASS/LSA/SAM 与替代来源 | 46 | [`docs/07-credentials-lsass.md`](/modules/07-credentials-lsass) |
| M08 | 隧道与端口转发 | 34–35 | [`docs/08-pivoting-tunneling.md`](/modules/08-pivoting-tunneling) |
| M09 | C2 出网通道：代理/分阶段/DNS/域前置 | 17, 28–33 | [`docs/09-c2-egress-channels.md`](/modules/09-c2-egress-channels) |
| M10 | Web 入口：ASPX 与注入后的下载/执行 | 14–16 | [`docs/10-web-entry-webshell.md`](/modules/10-web-entry-webshell) |
| M11 | MSSQL：认证、中继、Linked Server | 44–45 | [`docs/11-mssql.md`](/modules/11-mssql) |
| M12 | AD 攻击：Kerberos/委派/LAPS/ADCS | 47, 49–55 | [`docs/12-ad-attacks.md`](/modules/12-ad-attacks) |
| M13 | Linux：ELF 免杀、共享库、提权、横向 | 36–40, 48 | [`docs/13-linux.md`](/modules/13-linux) |
| M14 | Kiosk 突破、JEA 与 JIT 临时权限 | 41–43 | [`docs/14-kiosk-jea-jit.md`](/modules/14-kiosk-jea-jit) |
| M15 | 仅 WinRM 可达时的横向移动 | 56 | [`docs/15-winrm-lateral.md`](/modules/15-winrm-lateral) |
| M16 | ICS 日历邀请触发认证 | 13 | [`docs/16-ics-calendar.md`](/modules/16-ics-calendar) |

---

## 脚本使用约定

所有脚本统一使用占位符，**运行前替换**：

| 占位符 | 含义 |
|---|---|
| `LHOST` / `LPORT` | 攻击机 IP / 监听端口 |
| `TARGET` | 目标 IP 或主机名 |
| `DOMAIN` | AD 域名 |
| `USER` / `PASS` / `NTHASH` | 凭据 |
| `PAYLOAD` / `URL` | 载荷文件名 / 我方投递地址 |

每个脚本头部都有「用途 / 场景 / 依赖 / 使用 / 占位符 / 测试状态」注释块，先看头注释再跑。

**测试状态说明**：Windows 侧脚本（VBA/PowerShell/C#/HTA/ASPX）在 macOS 上无法实测，只能保证语法与逻辑正确；
Linux 侧脚本（`.py`/`.sh`/`.c`）已做语法校验或本机编译验证。首次使用请在实验环境先跑无害版本。

---

## 参考

- OSEP Cheatsheet（Emmanuel Solis）：<https://www.emmanuelsolis.com/osep.html>
- 本地副本：`reference/osep-cheatsheet.md`
- 场景原文：`scenarios.md`
