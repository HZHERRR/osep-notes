::: warning 仅供授权实验与备考学习
本文是个人备考教材。源码只用于 OSEP 官方实验/考试环境，或你拥有书面授权的目标。禁止对未授权系统使用。
:::

# OSEP 考试场景清单（56 个）与模块映射

> 来源：`/Users/barok/Desktop/xxx`（用户整理的 OSEP 场景表）。
> 每个场景对应一个模块文档，文档内含逐步流程与该场景需要的脚本。

| # | 场景摘要 | 模块 | 模块文档 |
|---|---|---|---|
| 1 | 网站接受 Word 文件，并自动打开；目标有杀毒软件 | M01 | [`docs/01-word-vba-office.md`](/modules/01-word-vba-office) |
| 2 | Word 会自动打开，但 Office 启动 PowerShell 被阻止 | M01 | [`docs/01-word-vba-office.md`](/modules/01-word-vba-office) |
| 3 | Word 可以启动 PowerShell，但第二阶段脚本被扫描拦截 | M01 | [`docs/01-word-vba-office.md`](/modules/01-word-vba-office) |
| 4 | Word 入口可用，但 PowerShell 动态编译产生的文件被删除 | M01 | [`docs/01-word-vba-office.md`](/modules/01-word-vba-office) |
| 5 | Word payload 成功上线，但文档关闭后会话消失 | M01 | [`docs/01-word-vba-office.md`](/modules/01-word-vba-office) |
| 6 | 邮件入口存在，但没有可用的 Office 宏入口 | M02 | [`docs/02-hta.md`](/modules/02-hta) |
| 7 | HTA 可以触发，但目标同时有 AppLocker、CLM 和 AMSI | M02 | [`docs/02-hta.md`](/modules/02-hta) |
| 8 | HTA 下载和执行放在一起失败，分开后能够工作 | M02 | [`docs/02-hta.md`](/modules/02-hta) |
| 9 | 邮件附件中的 JScript 会运行，但普通 EXE 受到限制 | M03 | [`docs/03-jscript-dotnettojscript.md`](/modules/03-jscript-dotnettojscript) |
| 10 | JScript 能执行简单内容，但复杂脚本被扫描拦截 | M03 | [`docs/03-jscript-dotnettojscript.md`](/modules/03-jscript-dotnettojscript) |
| 11 | 用户会打开 ZIP 中的程序，但宏和脚本入口不可用 | M04 | [`docs/04-dll-sideloading.md`](/modules/04-dll-sideloading) |
| 12 | DLL 已被加载，但程序立即闪退 | M04 | [`docs/04-dll-sideloading.md`](/modules/04-dll-sideloading) |
| 13 | 目标接受日历邀请，但没有宏执行机会 | M16 | [`docs/16-ics-calendar.md`](/modules/16-ics-calendar) |
| 14 | 网站允许上传 ASPX，后台是 IIS，目标安装了杀毒软件 | M10 | [`docs/10-web-entry-webshell.md`](/modules/10-web-entry-webshell) |
| 15 | 经典 ASP 网站存在 SQL 注入，可以执行系统命令，但下载器被拦 | M10 | [`docs/10-web-entry-webshell.md`](/modules/10-web-entry-webshell) |
| 16 | Web 命令注入只接受很短的命令 | M10 | [`docs/10-web-entry-webshell.md`](/modules/10-web-entry-webshell) |
| 17 | 目标没有稳定出网能力，下载式第二阶段无法取得 | M09 | [`docs/09-c2-egress-channels.md`](/modules/09-c2-egress-channels) |
| 18 | 自定义 EXE 一落地就被删除 | M05 | [`docs/05-applocker-clm-amsi.md`](/modules/05-applocker-clm-amsi) |
| 19 | EXE 能保存、能启动，但开始执行内容时被终止 | M05 | [`docs/05-applocker-clm-amsi.md`](/modules/05-applocker-clm-amsi) |
| 20 | 你需要使用托管工具，但其 EXE 文件不能落地运行 | M05 | [`docs/05-applocker-clm-amsi.md`](/modules/05-applocker-clm-amsi) |
| 21 | 普通 EXE 被 AppLocker 拒绝，但特定目录存在允许规则 | M05 | [`docs/05-applocker-clm-amsi.md`](/modules/05-applocker-clm-amsi) |
| 22 | EXE 规则严格，但 DLL 规则和宿主允许条件不同 | M05 | [`docs/05-applocker-clm-amsi.md`](/modules/05-applocker-clm-amsi) |
| 23 | InstallUtil 不可用，但教材中的其他受信任执行宿主可用 | M05 | [`docs/05-applocker-clm-amsi.md`](/modules/05-applocker-clm-amsi) |
| 24 | 普通脚本入口受限，但 XSL 处理路线可用 | M05 | [`docs/05-applocker-clm-amsi.md`](/modules/05-applocker-clm-amsi) |
| 25 | 当前已经是本地管理员，但会话没有提升 | M06 | [`docs/06-uac-windows-privesc.md`](/modules/06-uac-windows-privesc) |
| 26 | ASPX 或 SQL 会话是服务账户，并具备模拟权限 | M06 | [`docs/06-uac-windows-privesc.md`](/modules/06-uac-windows-privesc) |
| 27 | 自动服务提权工具失败，但你仍能修改某个高权限服务 | M06 | [`docs/06-uac-windows-privesc.md`](/modules/06-uac-windows-privesc) |
| 28 | 普通用户能通过浏览器联网，自定义 payload 无法直接回连 | M09 | [`docs/09-c2-egress-channels.md`](/modules/09-c2-egress-channels) |
| 29 | 用户权限会话能回连，提升为 SYSTEM 后却失联 | M09 | [`docs/09-c2-egress-channels.md`](/modules/09-c2-egress-channels) |
| 30 | 第一阶段回连成功，第二阶段始终没有出现 | M09 | [`docs/09-c2-egress-channels.md`](/modules/09-c2-egress-channels) |
| 31 | 目标只允许 HTTPS，但 HTTPS 检查影响通信 | M09 | [`docs/09-c2-egress-channels.md`](/modules/09-c2-egress-channels) |
| 32 | 普通 HTTP(S) 通信不通，但课程实验允许 DNS 通道 | M09 | [`docs/09-c2-egress-channels.md`](/modules/09-c2-egress-channels) |
| 33 | 目标限制访问目的域名，且实验基础设施支持域前置 | M09 | [`docs/09-c2-egress-channels.md`](/modules/09-c2-egress-channels) |
| 34 | 内部网站只接受来自指定网段的访问 | M08 | [`docs/08-pivoting-tunneling.md`](/modules/08-pivoting-tunneling) |
| 35 | 代理能连接内网目标，但目标主动认证到不了你的监听端 | M08 | [`docs/08-pivoting-tunneling.md`](/modules/08-pivoting-tunneling) |
| 36 | Linux 上传站会执行 ELF，但程序还要通过业务检查 | M13 | [`docs/13-linux.md`](/modules/13-linux) |
| 37 | Linux 目标也有杀毒软件，常见 ELF 被检测 | M13 | [`docs/13-linux.md`](/modules/13-linux) |
| 38 | Linux 程序从可控位置加载共享库 | M13 | [`docs/13-linux.md`](/modules/13-linux) |
| 39 | sudo 只允许一个编辑器或解释器 | M13 | [`docs/13-linux.md`](/modules/13-linux) |
| 40 | 你能覆盖制品，但不能直接登录下载制品的机器 | M13 | [`docs/13-linux.md`](/modules/13-linux) |
| 41 | 只有受限 Kiosk 桌面，没有终端 | M14 | [`docs/14-kiosk-jea-jit.md`](/modules/14-kiosk-jea-jit) |
| 42 | JEA 会话只暴露少量命令，其中包含权限过宽的文件复制 | M14 | [`docs/14-kiosk-jea-jit.md`](/modules/14-kiosk-jea-jit) |
| 43 | JIT 临时管理员权限获批，但有效时间很短 | M14 | [`docs/14-kiosk-jea-jit.md`](/modules/14-kiosk-jea-jit) |
| 44 | SQL 账户能登录，但不能运行系统命令 | M11 | [`docs/11-mssql.md`](/modules/11-mssql) |
| 45 | Linked Server 能查询，但远程执行失败 | M11 | [`docs/11-mssql.md`](/modules/11-mssql) |
| 46 | 凭据工具被拦，且 LSASS 本身受到保护 | M07 | [`docs/07-credentials-lsass.md`](/modules/07-credentials-lsass) |
| 47 | Linux 上已有域票据，但你需要访问 Windows 服务 | M12 | [`docs/12-ad-attacks.md`](/modules/12-ad-attacks) |
| 48 | 没有 SSH 密码，但存在已认证的复用连接 | M13 | [`docs/13-linux.md`](/modules/13-linux) |
| 49 | 没有本地提权路径，但当前域用户能读取 LAPS | M12 | [`docs/12-ad-attacks.md`](/modules/12-ad-attacks) |
| 50 | 控制了非约束委派机器，但还没有域级身份 | M12 | [`docs/12-ad-attacks.md`](/modules/12-ad-attacks) |
| 51 | 对计算机对象有相关写权限，但不能直接管理目标主机 | M12 | [`docs/12-ad-attacks.md`](/modules/12-ad-attacks) |
| 52 | 控制了服务账户，存在约束委派，但只能访问指定服务 | M12 | [`docs/12-ad-attacks.md`](/modules/12-ad-attacks) |
| 53 | 掌握了子域高权限，最终目标在林根 | M12 | [`docs/12-ad-attacks.md`](/modules/12-ad-attacks) |
| 54 | 低权限域用户可以申请错误配置的证书模板 | M12 | [`docs/12-ad-attacks.md`](/modules/12-ad-attacks) |
| 55 | 没有可用的 ESC1 模板，但 CA 存在可中继的 HTTP 注册入口 | M12 | [`docs/12-ad-attacks.md`](/modules/12-ad-attacks) |
| 56 | 凭据有效，但目标只开放 WinRM | M15 | [`docs/15-winrm-lateral.md`](/modules/15-winrm-lateral) |

## 模块总览

| 模块 | 主题 | cheat sheet 对应章节 | 场景 |
|---|---|---|---|
| M01 | Word/VBA 宏入口与载荷形态 | Microsoft Word / Payloads(C#、PowerShell) | 1, 2, 3, 4, 5 |
| M02 | HTA 入口与 CLM/AppLocker 组合 | HTA / Payloads | 6, 7, 8 |
| M03 | JScript / WSH 与 DotNetToJScript | JScript | 9, 10 |
| M04 | DLL 旁加载与 Proxy DLL | Payloads(DLL) / Upgrading Shells(DLL) | 11, 12 |
| M05 | AppLocker/CLM/AMSI 绕过与受信任宿主 | Defense Evasion / Utilities | 18, 19, 20, 21, 22, 23, 24 |
| M06 | Windows 本地提权：UAC/令牌/服务 | Privilege Escalation / Defense Evasion(UAC) | 25, 26, 27 |
| M07 | 凭据获取：LSASS/LSA/SAM 与替代来源 | Credentials | 46 |
| M08 | 隧道与端口转发 | Tunneling / Metasploit | 34, 35 |
| M09 | C2 出网通道：代理/分阶段/DNS/域前置 | Initial & Further Access / Utilities | 17, 28, 29, 30, 31, 32, 33 |
| M10 | Web 入口：ASPX 与注入后的下载/执行 | Payloads(WebShells) | 14, 15, 16 |
| M11 | MSSQL：认证、中继、Linked Server | MSSQL | 44, 45 |
| M12 | AD 攻击：Kerberos/委派/LAPS/ADCS | AD Enumeration / AD Attacking | 47, 49, 50, 51, 52, 53, 54, 55 |
| M13 | Linux：ELF 免杀、共享库、提权、横向 | Linux | 36, 37, 38, 39, 40, 48 |
| M14 | Kiosk 突破、JEA 与 JIT 临时权限 | Linux/Windows 杂项（教材 16、23 章） | 41, 42, 43 |
| M15 | 仅 WinRM 可达时的横向移动 | Credentials / Lateral | 56 |
| M16 | ICS 日历邀请触发认证 | Initial Access（教材第5章） | 13 |

## 场景原文（逐条）

### 场景 1：网站接受 Word 文件，并自动打开；目标有杀毒软件

- 归属模块：`M01` → [`docs/01-word-vba-office.md`](/modules/01-word-vba-office)

你发现一个招聘网站，可以上传 .docm。后台用户会打开文档，宏能够触发。目标安装了 Defender，但你不知道 Office 的位数，直接使用公开宏样例可能被查杀。
可提前准备： 无害回调宏、可靠的宿主位数识别宏、分别匹配 x86/x64 的 VBA Runner、教材中的编码／加密内容版本。
依据：C1；教材第4、11章。你提供的 cheat sheet 的 Microsoft Word 部分 也按回调、架构和 Runner 区分准备内容。

### 场景 2：Word 会自动打开，但 Office 启动 PowerShell 被阻止

- 归属模块：`M01` → [`docs/01-word-vba-office.md`](/modules/01-word-vba-office)

同样是 Word 上传入口。简单宏可以运行，但宏一启动 PowerShell 就失败；目标可能限制 Office 创建子进程，或对该进程链进行检测。
可提前准备： 直接在 VBA 宿主中运行的版本；与依赖 PowerShell 子进程的宏分别保留。
依据：教材第4、11章。是否能使用直接 VBA 路线，仍取决于目标对宏内行为的限制。

### 场景 3：Word 可以启动 PowerShell，但第二阶段脚本被扫描拦截

- 归属模块：`M01` → [`docs/01-word-vba-office.md`](/modules/01-word-vba-office)

上传文档后，你能确认 PowerShell 已启动，但下载或解释第二阶段时出现脚本内容被阻止的信息。
可提前准备： 短宏第一阶段、PowerShell 第二阶段、与实际 PowerShell 宿主匹配的 AMSI 实验版本。
依据：教材第9、12章。

### 场景 4：Word 入口可用，但 PowerShell 动态编译产生的文件被删除

- 归属模块：`M01` → [`docs/01-word-vba-office.md`](/modules/01-word-vba-office)

宏和 PowerShell 都能启动，语言模式也没有受到限制；但依赖 Add-Type 的 Runner 失败，动态编译产生的临时文件被检测。
可提前准备： 教材中的反射 PowerShell Runner，以及预编译的 C# 版本。
依据：教材第8、9章。

### 场景 5：Word payload 成功上线，但文档关闭后会话消失

- 归属模块：`M01` → [`docs/01-word-vba-office.md`](/modules/01-word-vba-office)

上传文档后得到会话，但后台用户很快关闭 Word，会话随之终止。目标进程中有同用户的长期运行程序。
可提前准备： 能脱离初始文档生命周期的执行版本，以及按用户、位数和权限区分的迁移方案。
依据：C1；教材第10章。

### 场景 6：邮件入口存在，但没有可用的 Office 宏入口

- 归属模块：`M02` → [`docs/02-hta.md`](/modules/02-hta)

目标会处理邮件中的链接或 HTA 文件，但没有安装 Office。目标同时存在 AppLocker，直接启动你上传的 EXE 被拒绝。
可提前准备： HTA 第一阶段、InstallUtil 兼容程序集，以及对应的 x86/x64 构建版本。
依据：C4；教材第13章。

### 场景 7：HTA 可以触发，但目标同时有 AppLocker、CLM 和 AMSI

- 归属模块：`M02` → [`docs/02-hta.md`](/modules/02-hta)

你能让 HTA 执行，但普通 EXE 被应用控制限制；PowerShell 中反射和动态编译不可用；后续脚本还会被 AMSI 扫描。
可提前准备： C4 中的 HTA、InstallUtil、自定义 Runspace、进程内 AMSI 处理、第二阶段 Runner 组合。
依据：C4。这是需要完整组合验证的场景，单独验证某一组件不够。

### 场景 8：HTA 下载和执行放在一起失败，分开后能够工作

- 归属模块：`M02` → [`docs/02-hta.md`](/modules/02-hta)

目标确实打开了 HTA，也访问了下载地址，但最终没有执行结果。你的材料中出现过“分开可以，放一起没反应”。
可提前准备： 下载与执行分开的两个阶段，以及带完成确认的单文件版本。
依据：C4。将其作为时序和生命周期场景，不预先认定失败一定由杀软造成。

### 场景 9：邮件附件中的 JScript 会运行，但普通 EXE 受到限制

- 归属模块：`M03` → [`docs/03-jscript-dotnettojscript.md`](/modules/03-jscript-dotnettojscript)

目标保留 Windows Script Host 和兼容的 .NET 环境。用户会打开脚本附件，但直接启动独立 EXE 的路线不可靠。
可提前准备： JScript 第一阶段、教材中的 DotNetToJscript 路线、由其加载的 C# 第二阶段。
依据：教材第7、9章。

### 场景 10：JScript 能执行简单内容，但复杂脚本被扫描拦截

- 归属模块：`M03` → [`docs/03-jscript-dotnettojscript.md`](/modules/03-jscript-dotnettojscript)

相同入口中，简单脚本可以执行，加入 .NET 桥接或后续执行内容后被拦截；PowerShell 中验证过的方法不能直接套用。
可提前准备： JScript／WSH 宿主对应的 AMSI 实验版本，以及分离第二阶段的脚本结构。
依据：教材 §12.6。

### 场景 11：用户会打开 ZIP 中的程序，但宏和脚本入口不可用

- 归属模块：`M04` → [`docs/04-dll-sideloading.md`](/modules/04-dll-sideloading)

邮件或网站允许投递 ZIP。目标用户会解压并运行里面的程序；其中某个允许启动的签名程序，会加载同目录下的 DLL。
可提前准备： 已验证具体程序版本的 DLL 旁加载包、对应架构的 DLL、保持宿主正常运行的 Proxy DLL。
依据：教材第6章。

### 场景 12：DLL 已被加载，但程序立即闪退

- 归属模块：`M04` → [`docs/04-dll-sideloading.md`](/modules/04-dll-sideloading)

你已经找到可用的旁加载宿主，目标也执行了程序，但自定义 DLL 导致宿主退出，无法保持后续执行。
可提前准备： 导出函数和调用约定匹配的 Proxy DLL；将宿主兼容性作为单独的准备场景。
依据：教材 §6.1–6.2。

### 场景 13：目标接受日历邀请，但没有宏执行机会

- 归属模块：`M16` → [`docs/16-ics-calendar.md`](/modules/16-ics-calendar)

你知道收件人的地址，目标会处理会议邀请。实验中的日历客户端可能访问邀请引用的外部资源，并发起认证。
可提前准备： 教材中的 ICS 邀请文件，以及对应的认证接收和后续处理命令笔记。
依据：教材第5章。触发条件与客户端版本、配置有关，不能把“收到邀请”直接视为会认证。

### 场景 14：网站允许上传 ASPX，后台是 IIS，目标安装了杀毒软件

- 归属模块：`M10` → [`docs/10-web-entry-webshell.md`](/modules/10-web-entry-webshell)

上传后的 ASPX 会被服务器解析。简单命令执行可用，但公开 Web Shell 或上传的 EXE 被查杀；当前身份是应用池账户。
可提前准备： 精简的 ASPX 执行入口、兼容的托管加载版本、可独立替换的第二阶段。
依据：C6；教材第8、9、24章。

### 场景 15：经典 ASP 网站存在 SQL 注入，可以执行系统命令，但下载器被拦

- 归属模块：`M10` → [`docs/10-web-entry-webshell.md`](/modules/10-web-entry-webshell)

你已经通过数据库获得命令执行。使用一种系统下载工具失败，换另一种却可以下载同一个文件。
可提前准备： curl、PowerShell、BITS 等不同下载方式的命令模板，以及已经验证的 EXE／脚本第二阶段。
依据：C2。这里准备的是传输备选路线，不是重新准备 SQL 注入工具。

### 场景 16：Web 命令注入只接受很短的命令

- 归属模块：`M10` → [`docs/10-web-entry-webshell.md`](/modules/10-web-entry-webshell)

内部页面提供 ping 等功能，存在命令注入，但参数长度有限，复杂引号和多层命令容易被截断。
可提前准备： 短第一阶段、下载与执行分离的版本、适合目标解释器的编码参数版本。
依据：C6 的内部 Web 入口；你的复习笔记中的客户端分阶段执行内容。

### 场景 17：目标没有稳定出网能力，下载式第二阶段无法取得

- 归属模块：`M09` → [`docs/09-c2-egress-channels.md`](/modules/09-c2-egress-channels)

入口已经能执行代码，但目标无法访问你的文件服务器，或者只允许访问少数地址。依赖临时下载的宏、脚本和加载器都失败。
可提前准备： 内嵌第二阶段的 VBA／C#／JScript 版本，与需要下载的版本分别保留。
依据：教材第4、7、9、14章。

### 场景 18：自定义 EXE 一落地就被删除

- 归属模块：`M05` → [`docs/05-applocker-clm-amsi.md`](/modules/05-applocker-clm-amsi)

目标允许上传文件，但你准备的 Runner 在启动之前就被隔离；简单无害程序可以保存和执行。
可提前准备： 教材中的静态特征定位方法、执行内容编码／加密版本、自定义 C# Runner。
依据：教材第11章。需要分别测试执行内容与加载器自身的检测情况。

### 场景 19：EXE 能保存、能启动，但开始执行内容时被终止

- 归属模块：`M05` → [`docs/05-applocker-clm-amsi.md`](/modules/05-applocker-clm-amsi)

文件落地没有问题，运行初期也正常；进入后续执行或通信阶段后进程被终止。
可提前准备： 教材中的行为差异实验版本，以及进程内执行、跨进程执行等不同实现的对照样本。
依据：教材第10、11章。把它作为运行阶段检测场景，不继续只改静态编码。

### 场景 20：你需要使用托管工具，但其 EXE 文件不能落地运行

- 归属模块：`M05` → [`docs/05-applocker-clm-amsi.md`](/modules/05-applocker-clm-amsi)

已经有一个可执行托管逻辑的宿主。某个 .NET 工具直接落地运行被限制，但它的程序集格式适合在现有宿主中加载。
可提前准备： 托管程序集加载器，以及该工具的入口、参数、依赖和输出适配版本。
依据：教材第8、9章。原生 EXE 不能直接当作托管程序集使用。

### 场景 21：普通 EXE 被 AppLocker 拒绝，但特定目录存在允许规则

- 归属模块：`M05` → [`docs/05-applocker-clm-amsi.md`](/modules/05-applocker-clm-amsi)

你有普通用户会话，上传的程序在当前目录不能运行。目标的有效策略允许某些路径，其中可能存在当前用户可写的位置。
可提前准备： 已验证的允许路径执行方案，以及有效规则与目录权限的查询命令。
依据：C1；教材 §13.2。

### 场景 22：EXE 规则严格，但 DLL 规则和宿主允许条件不同

- 归属模块：`M05` → [`docs/05-applocker-clm-amsi.md`](/modules/05-applocker-clm-amsi)

普通自定义程序不能直接启动，但一个已允许的应用能加载外部 DLL，且对应 DLL 加载没有被有效规则阻止。
可提前准备： 指定宿主使用的 DLL payload，而不是只准备 EXE。
依据：教材 §13.2；第6章。

### 场景 23：InstallUtil 不可用，但教材中的其他受信任执行宿主可用

- 归属模块：`M05` → [`docs/05-applocker-clm-amsi.md`](/modules/05-applocker-clm-amsi)

你之前准备的 InstallUtil 路线被策略阻止，目标却保留了教材中的 Workflow 编译宿主及其所需环境。
可提前准备： Workflow Compiler 对应的输入文件和程序集版本。
依据：教材 §13.4。

### 场景 24：普通脚本入口受限，但 XSL 处理路线可用

- 归属模块：`M05` → [`docs/05-applocker-clm-amsi.md`](/modules/05-applocker-clm-amsi)

目标的常规脚本执行受到限制，但对应组件仍能处理带脚本逻辑的 XSL，并且有效策略允许调用它。
可提前准备： 教材中的 XSL 执行文件和对应调用模板。
依据：教材 §13.5。

### 场景 25：当前已经是本地管理员，但会话没有提升

- 归属模块：`M06` → [`docs/06-uac-windows-privesc.md`](/modules/06-uac-windows-privesc)

你获得的是管理员账户的普通令牌；高权限操作被拒绝，但不是因为账户本身没有管理员身份。
可提前准备： 教材 Fodhelper UAC 场景的 payload 与命令模板，记录适用的系统和 UAC 配置。
依据：教材 §12.5。

### 场景 26：ASPX 或 SQL 会话是服务账户，并具备模拟权限

- 归属模块：`M06` → [`docs/06-uac-windows-privesc.md`](/modules/06-uac-windows-privesc)

你取得 IIS／SQL 服务身份，能够执行代码，但还没有 SYSTEM；账户具有可用的 SeImpersonatePrivilege，目标也满足相应机制的其他条件。
可提前准备： 与实验系统兼容的令牌模拟提权工具，以及它需要调用的 EXE／命令型 payload。
依据：C6；教材第17、24章。

### 场景 27：自动服务提权工具失败，但你仍能修改某个高权限服务

- 归属模块：`M06` → [`docs/06-uac-windows-privesc.md`](/modules/06-uac-windows-privesc)

服务配置或可执行路径的权限存在问题。自动工具没有成功，但你已确认自己拥有相关修改权限，并有可用的启动或触发条件。
可提前准备： 服务型 payload、普通命令型 payload，以及保存和恢复原配置的命令笔记。
依据：C6 jump03。你的 writeup 在这里有过程缺口，适合单独补练。

### 场景 28：普通用户能通过浏览器联网，自定义 payload 无法直接回连

- 归属模块：`M09` → [`docs/09-c2-egress-channels.md`](/modules/09-c2-egress-channels)

目标只允许通过企业代理访问外部网络。浏览器工作正常，直接 TCP 或忽略代理的 HTTP 客户端失败。
可提前准备： 使用系统代理的 HTTP(S) payload／下载器，以及支持代理认证的版本。
依据：教材客户端通信和第14章。

### 场景 29：用户权限会话能回连，提升为 SYSTEM 后却失联

- 归属模块：`M09` → [`docs/09-c2-egress-channels.md`](/modules/09-c2-egress-channels)

同一台机器、同一个地址，提升前能够通信，提升后失败。两种身份使用的代理设置和认证上下文不同。
可提前准备： 用户上下文与 SYSTEM 上下文分别验证过的通信版本。
依据：教材中的 SYSTEM Proxy 场景。

### 场景 30：第一阶段回连成功，第二阶段始终没有出现

- 归属模块：`M09` → [`docs/09-c2-egress-channels.md`](/modules/09-c2-egress-channels)

入口成功联系了监听端，但后续阶段使用另一地址、端口或协议，而该路径不被目标允许。
可提前准备： staged 与 stageless 两种形态，以及所有阶段都使用已验证通信路径的配置。
依据：C1、C2；教材第14章。

### 场景 31：目标只允许 HTTPS，但 HTTPS 检查影响通信

- 归属模块：`M09` → [`docs/09-c2-egress-channels.md`](/modules/09-c2-egress-channels)

目标能访问普通 HTTPS 网站，你的 payload 却在 TLS 握手或请求阶段失败。环境可能存在代理检查、证书信任或应用层过滤。
可提前准备： 可配置证书、请求头和 User-Agent 的 HTTPS 通信方案。
依据：教材 §14.2–14.5。

### 场景 32：普通 HTTP(S) 通信不通，但课程实验允许 DNS 通道

- 归属模块：`M09` → [`docs/09-c2-egress-channels.md`](/modules/09-c2-egress-channels)

你已经能在目标上执行程序，但直接连接和常规代理路线均不可用；目标仍可使用满足实验条件的 DNS 通信。
可提前准备： 教材中的 DNS 通道客户端及服务端配置。
依据：教材 §14.7。

### 场景 33：目标限制访问目的域名，且实验基础设施支持域前置

- 归属模块：`M09` → [`docs/09-c2-egress-channels.md`](/modules/09-c2-egress-channels)

目标只允许访问特定前端地址，直接访问你的后端不通；你搭建的课程环境支持教材中的前端与后端分离方式。
可提前准备： 对应基础设施上的域前置通信配置。
依据：教材 §14.6。该场景依赖具体服务支持。

### 场景 34：内部网站只接受来自指定网段的访问

- 归属模块：`M08` → [`docs/08-pivoting-tunneling.md`](/modules/08-pivoting-tunneling)

你从 Kali 访问内部网站被拒绝，但已经控制的一台 DEV 网主机可以访问。网站后面还有上传或命令执行入口。
可提前准备： 从指定跳板访问的端口转发模板，以及适配该跳板回连路径的后续 payload。
依据：C6 的 web06:8081 场景。

### 场景 35：代理能连接内网目标，但目标主动认证到不了你的监听端

- 归属模块：`M08` → [`docs/08-pivoting-tunneling.md`](/modules/08-pivoting-tunneling)

你可以经 SOCKS 访问 SQL 或域服务，但触发目标主动连接时没有任何认证到达。正向访问与目标回连走的是两条不同路径。
可提前准备： 在目标可达位置接收连接的监听／转发配置，以及与其一致的地址参数模板。
依据：C4 的 SQL 认证与中继场景。

### 场景 36：Linux 上传站会执行 ELF，但程序还要通过业务检查

- 归属模块：`M13` → [`docs/13-linux.md`](/modules/13-linux)

网站要求上传程序并自动运行。普通反向连接程序可能破坏检查流程，或者随父进程退出。
可提前准备： 与目标架构和运行库匹配、能保持预期输出与生命周期的 ELF payload。
依据：C3。

### 场景 37：Linux 目标也有杀毒软件，常见 ELF 被检测

- 归属模块：`M13` → [`docs/13-linux.md`](/modules/13-linux)

上传入口没有问题，但直接生成的 Linux 程序被检测；Windows 的 C# 和 PowerShell 准备在这里用不上。
可提前准备： 教材 Linux AV 实验中的自定义 ELF／加载版本。
依据：教材 §15.2。

### 场景 38：Linux 程序从可控位置加载共享库

- 归属模块：`M13` → [`docs/13-linux.md`](/modules/13-linux)

你不能直接执行高权限命令，但目标程序会从你能够影响的位置寻找共享库，或实验环境允许对应预加载设置。
可提前准备： 分别适配 LD_LIBRARY_PATH 与 LD_PRELOAD 场景的共享库 payload。
依据：教材 §15.3。

### 场景 39：sudo 只允许一个编辑器或解释器

- 归属模块：`M13` → [`docs/13-linux.md`](/modules/13-linux)

当前 Linux 用户不能直接获得 root Shell，但 sudo 允许运行某个具体程序，例如材料中的 vim、find 或 lua，并存在相应可用能力。
可提前准备： 针对这几个具体程序及参数限制的命令笔记。
依据：C3、C5、C6。

### 场景 40：你能覆盖制品，但不能直接登录下载制品的机器

- 归属模块：`M13` → [`docs/13-linux.md`](/modules/13-linux)

已经取得制品库权限。另一台主机会周期性下载并执行指定路径下的程序，你没有它的密码或直接执行入口。
可提前准备： 符合下游架构、文件名和业务行为的替换制品，以及打包模板。
依据：C3 的 Artifactory 场景。

### 场景 41：只有受限 Kiosk 桌面，没有终端

- 归属模块：`M14` → [`docs/14-kiosk-jea-jit.md`](/modules/14-kiosk-jea-jit)

目标只显示浏览器或指定应用，但仍有文件对话框、配置文件或其他已安装应用可访问。
可提前准备： 教材对应应用的 Kiosk 突破操作笔记，以及取得执行机会后可直接使用的 payload。
依据：教材第16章。

### 场景 42：JEA 会话只暴露少量命令，其中包含权限过宽的文件复制

- 归属模块：`M14` → [`docs/14-kiosk-jea-jit.md`](/modules/14-kiosk-jea-jit)

你可以连接指定 PowerShell 端点，但不能运行普通程序。允许的文件复制操作却能以高于连接用户的权限写入其他位置。
可提前准备： 教材具体服务使用的 DLL payload，以及对应 JEA 文件操作模板。
依据：教材 §23.2；需要同时存在可用的服务加载和触发条件。

### 场景 43：JIT 临时管理员权限获批，但有效时间很短

- 归属模块：`M14` → [`docs/14-kiosk-jea-jit.md`](/modules/14-kiosk-jea-jit)

你能通过目标的授权流程取得临时组成员身份；审批处理、新票据和当前令牌之间存在时间差。
可提前准备： 授权状态查询、认证状态更新，以及在授权窗口内使用的既定命令笔记。
依据：教材 §23.3。

### 场景 44：SQL 账户能登录，但不能运行系统命令

- 归属模块：`M11` → [`docs/11-mssql.md`](/modules/11-mssql)

你只有低权限数据库登录，无法直接使用预期的命令执行功能；但该 SQL 身份具备材料中可用的对外认证触发条件，另一目标满足中继条件。
可提前准备： SQL 认证触发和对应中继命令模板，以及获得执行权限后使用的 payload。
依据：C4。

### 场景 45：Linked Server 能查询，但远程执行失败

- 归属模块：`M11` → [`docs/11-mssql.md`](/modules/11-mssql)

你已经能访问一个 SQL 实例，发现它连接另一个实例。远端映射账户、RPC 配置和实际权限与当前实例不同。
可提前准备： 单跳／多跳 Linked Server 的查询和执行模板，适合 SQL 命令长度及转义要求的短 payload。
依据：C2、C6。

### 场景 46：凭据工具被拦，且 LSASS 本身受到保护

- 归属模块：`M07` → [`docs/07-credentials-lsass.md`](/modules/07-credentials-lsass)

你已经取得较高本地权限，但 LSASS 访问失败。材料中同类场景仍能从 LSA Secrets、SAM 或应用配置中取得另一种有用身份。
可提前准备： 按不同凭据来源分类的命令笔记，以及工具可用的加载形态。
依据：C4。这个场景的准备重点是已有替代凭据来源，而不是假定一定能绕过 LSASS 保护。

### 场景 47：Linux 上已有域票据，但你需要访问 Windows 服务

- 归属模块：`M12` → [`docs/12-ad-attacks.md`](/modules/12-ad-attacks)

你控制了一台加域 Linux，存在可访问且有效的 credential cache 或 keytab；下一跳是 Windows 域中的服务。
可提前准备： 票据格式转换、Kerberos 认证、代理与域名配置模板。
依据：C5；教材 §19.3。

### 场景 48：没有 SSH 密码，但存在已认证的复用连接

- 归属模块：`M13` → [`docs/13-linux.md`](/modules/13-linux)

你控制了 Linux 上的某个用户环境，发现仍有效且可访问的 ControlMaster 套接字；或者存在可用的 SSH Agent 转发。
可提前准备： 两种场景分别对应的连接复用命令笔记，以及到达下一跳后的 Linux payload。
依据：C3；教材 §19.1。

### 场景 49：没有本地提权路径，但当前域用户能读取 LAPS

- 归属模块：`M12` → [`docs/12-ad-attacks.md`](/modules/12-ad-attacks)

初始会话只是普通域用户。当前机器没有明显本地提权点，但目录权限允许读取另一台机器的本地管理员密码。
可提前准备： 与目标 LAPS 实现匹配的查询方式，以及取得该身份后的远程执行模板。
依据：C1。

### 场景 50：控制了非约束委派机器，但还没有域级身份

- 归属模块：`M12` → [`docs/12-ad-attacks.md`](/modules/12-ad-attacks)

你已经控制一台配置非约束委派的主机。下一步取决于是否有符合条件的域身份向它认证，以及是否能取得对应票据。
可提前准备： 材料中的认证触发、票据处理和后续认证命令模板。
依据：C1；教材第21、23章。

### 场景 51：对计算机对象有相关写权限，但不能直接管理目标主机

- 归属模块：`M12` → [`docs/12-ad-attacks.md`](/modules/12-ad-attacks)

图谱和实际 ACL 显示，你能影响某台计算机的相关属性；同时具备 RBCD 所需的可控服务身份等前提。
可提前准备： RBCD 配置、服务票据和目标服务访问的参数化命令笔记。
依据：C5；教材第21、23章。

### 场景 52：控制了服务账户，存在约束委派，但只能访问指定服务

- 归属模块：`M12` → [`docs/12-ad-attacks.md`](/modules/12-ad-attacks)

你掌握一个服务账户的有效身份材料，它配置了约束委派。可用目标由委派配置和 SPN 决定，而不是任意机器。
可提前准备： 对应协议转换条件、目标 SPN 和票据使用方式的不同命令模板。
依据：教材第21、23章。

### 场景 53：掌握了子域高权限，最终目标在林根

- 归属模块：`M12` → [`docs/12-ad-attacks.md`](/modules/12-ad-attacks)

当前已控制子域，但目标资产属于根域。需要根据实际信任关系和权限条件判断能否继续。
可提前准备： 教材中的林内信任、Extra SID 和跨域认证命令笔记。
依据：C5；教材第21章。

### 场景 54：低权限域用户可以申请错误配置的证书模板

- 归属模块：`M12` → [`docs/12-ad-attacks.md`](/modules/12-ad-attacks)

目标部署了 ADCS。某个已发布模板满足教材 ESC1 的相关条件，当前用户拥有申请权限。
可提前准备： 模板枚举、证书申请、格式转换和证书认证的命令笔记。
依据：教材 §22.2.1。

### 场景 55：没有可用的 ESC1 模板，但 CA 存在可中继的 HTTP 注册入口

- 归属模块：`M12` → [`docs/12-ad-attacks.md`](/modules/12-ad-attacks)

目标提供 ADCS Web Enrollment；对应认证方式、保护配置和模板权限满足教材 ESC8 场景。
可提前准备： 该端点的中继配置，以及获得证书后的认证模板。
依据：教材 §22.2.2。

### 场景 56：凭据有效，但目标只开放 WinRM

- 归属模块：`M15` → [`docs/15-winrm-lateral.md`](/modules/15-winrm-lateral)

你已经取得正确身份，但 SMB 不通，原先准备的 SMB／服务式执行方法全部失败；目标仅提供 WinRM 管理入口。
可提前准备： WinRM 的密码、哈希或 Kerberos 认证模板，以及该会话内可用的后续 payload。
依据：C5 的 proxy01 场景。

