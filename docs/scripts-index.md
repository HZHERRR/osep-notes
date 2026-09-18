::: warning 私人教材 · 仅供授权实验与备考学习
本文是个人备考教材，仓库不公开。源码只用于 OSEP 官方实验/考试环境或你拥有书面授权的目标。禁止转发到公开网络、禁止对未授权系统使用。
:::

# 脚本索引

共 80 个脚本文件，按语言分组。由 `tools/verify.py --index` 生成。

## aspx

| 文件 | 大小 | 用途 |
|---|---|---|
| `scripts/aspx/m10-jsp-shell.jsp` | 1651B | 精简 JSP 命令执行入口（Tomcat/Jetty 等环境下的备选，非 IIS 场景） |
| `scripts/aspx/m10-managed-loader.aspx` | 3231B | ASPX 托管加载器——在 w3wp 进程内加载 .NET 程序集（不落地 EXE，绕文件查杀） |
| `scripts/aspx/m10-minimal-exec.aspx` | 1793B | 精简 ASPX 命令执行入口（去 UI、去公开 Web Shell 特征，降低被查杀概率） |
| `scripts/aspx/m10-php-shell.php` | 1358B | 精简 PHP 命令执行入口（LAMP/nginx+php-fpm 环境备选） |

## c

| 文件 | 大小 | 用途 |
|---|---|---|
| `scripts/c/m04-proxy-dll-cpp.cpp` | 5047B | DLL 旁加载 Proxy 的 C++ 写法示例。重点说明三件事： |
| `scripts/c/m04-proxy-dll-newadmin.c` | 6547B | DLL 旁加载的"实弹"Proxy —— 转发保持宿主正常的同时执行载荷， |
| `scripts/c/m04-proxy-dll-sideload.c` | 3404B | DLL 旁加载的"纯转发 / 无载荷对照"Proxy。编译出的 DLL 与宿主原 |
| `scripts/c/m06-service-binary-payload.c` | 3971B | Windows 服务二进制劫持用的 payload——服务以 SYSTEM 启动时执行，默认反向 shell（cmd 直 |
| `scripts/c/m13-shared-library-ldlibrarypath.c` | 2249B | LD_LIBRARY_PATH 场景的共享库 payload——命名与导出函数必须匹配目标程序的依赖 |
| `scripts/c/m13-shared-library-ldpreload.c` | 1833B | LD_PRELOAD 场景的共享库 payload——在被预加载的程序启动时执行载荷，同时保留原程序行为 |
| `scripts/c/m13-simple-loader.c` | 5130B | Linux 内存加载器——解码 XOR 编码的 ELF/shellcode 并在内存中执行，保持业务输出与生命周期 |

## csharp

| 文件 | 大小 | 用途 |
|---|---|---|
| `scripts/csharp/m01-shellcode-runner-x64.cs` | 2935B | 自定义 x64 shellcode Runner（预编译使用，避免 Add-Type 动态编译落地临时文件） |
| `scripts/csharp/m02-clm-bypass-dotnettojscript.cs` | 1990B | DotNetToJScript 路线的 C# 载荷骨架（CLM 绕过版）——JScript 只做加载，重活在托管侧 |
| `scripts/csharp/m02-clm-bypass-runspace.cs` | 3973B | InstallUtil 兼容 runner——由 InstallUtil.exe /U 触发 Uninstall()，在 |
| `scripts/csharp/m03-dotnettojscript-payload.cs` | 4163B | C# 第二阶段载荷——[ComVisible] 类，构造时把 shellcode 注入指定进程。 |
| `scripts/csharp/m05-installutil-runner.cs` | 4697B | InstallUtil 兼容托管 Runner——一个可被 InstallUtil.exe 调用的 .NET 安装器类， |
| `scripts/csharp/m05-workflow-compiler-runner.cs` | 2587B | Workflow Compiler 受信任宿主——被 Microsoft.Workflow.Compiler.exe 加 |
| `scripts/csharp/m14-jea-service-dll.cs` | 3262B | JEA 场景配套的服务 DLL 载荷——被已注册服务从可写位置加载执行 |

## hta

| 文件 | 大小 | 用途 |
|---|---|---|
| `scripts/hta/m02-hta-callback.hta` | 2063B | 最小 HTA 回调——确认 mshta 承载的 JScript 能执行且能出网（无害，不落地任何 payload） |
| `scripts/hta/m02-hta-download-exec-split.hta` | 3998B | 下载与执行分离的两阶段 HTA：阶段一落盘并检查文件存在，阶段二才执行；每阶段带 HTTP 回显 |
| `scripts/hta/m02-hta-embedded-clm-bypass.hta` | 6320B | 单文件完整组合链 HTA：mshta→(写 C# 源码)→csc 现编译→InstallUtil /U→自定义 Runs |
| `scripts/hta/m02-hta-powershell-stager.hta` | 2579B | HTA→PowerShell 拉取并执行第二阶段（shell.ps1），场景 6 主入口；场景 8 中作为"合并形态"对 |

## infra

| 文件 | 大小 | 用途 |
|---|---|---|
| `scripts/infra/m00-build-payloads.sh` | 5490B | 在 Kali 攻击机上一次性生成 OSEP 考试常用的标准载荷矩阵（x86/x64 分离），并建好目录结构 |
| `scripts/infra/m00-listener.sh` | 2322B | 标准监听器——带 readline、会话落盘、端口占用检查、可选自动起 HTTP 投递 |
| `scripts/infra/m00-smb-and-responder.sh` | 3229B | SMB 投递 + 认证捕获/中继基础设施（Responder 监听 / ntlmrelayx 中继 / smbserve |
| `scripts/infra/m05-lolbas-notes.md` | 3162B | AppLocker 拒绝自定义 EXE 时，用**被策略放行的系统程序**承载执行。 |
| `scripts/infra/m05-xsl-exec.xsl` | 1656B | XSL 脚本执行模板——通过 msxsl.exe 或 wmic /format 触发内嵌脚本（常规脚本入口受限时的替代） |
| `scripts/infra/m08-chisel-socks.sh` | 5008B | chisel 隧道备选（Ligolo 不可用时的 SOCKS/单服务转发/反连收口）+ proxychains 配置助手 |
| `scripts/infra/m08-ligolo-ng-setup.sh` | 6265B | Ligolo-ng 全流程助手——proxy 启动、tun/路由、agent 投放、反连转发、文件传输、双层穿透 |
| `scripts/infra/m09-domain-fronting-nginx.conf` | 2568B | 域前置（Domain Fronting）前端/后端分离配置——前端用被允许的域名，后端接自己的服务 |
| `scripts/infra/m09-https-listener.sh` | 4066B | HTTPS 监听端搭建与 TLS 排查——自签证书、指纹记录、握手失败定位 |
| `scripts/infra/m10-download-fallbacks.md` | 2848B | 命令执行后某个下载工具被拦时，按顺序换下一个。**每次只换一个变量**并记录结果。 |
| `scripts/infra/m12-laps-and-trust-notes.md` | 5047B | 查询 LAPS 密码的两种实现差异，以及子域→林根的信任/Extra SID 判断与命令 |
| `scripts/infra/m14-kiosk-breakout.md` | 3399B | 只有受限 Kiosk 桌面（浏览器或单一应用）时的执行机会获取路径 |
| `scripts/infra/m15-winrm-lateral.md` | 5217B |  |
| `scripts/infra/m16-ics-invite.ics` | 1948B | 日历邀请模板 —— 通过 LOCATION/DESCRIPTION/URL/ATTACH 引用攻击机资源, |

## jscript

| 文件 | 大小 | 用途 |
|---|---|---|
| `scripts/jscript/m03-dotnettojscript-loader.js` | 3175B | DotNetToJScript 桥接产物的骨架/粘贴容器 + 宿主预检。 |
| `scripts/jscript/m03-simple-dropper.js` | 2788B | 最小 JScript 下载器——从攻击机 HTTP 拉取文件到目标并保存；可选再执行。 |
| `scripts/jscript/m03-supersharpshooter-loader.js` | 2641B | SuperSharpShooter 产物的"分离式第二阶段"加载器（场景 10 实验形态）。 |
| `scripts/jscript/m03-wsh-amsi-probe.js` | 3835B | WSH 宿主 AMSI 实验探针（场景 10）。分两段： |

## linux

| 文件 | 大小 | 用途 |
|---|---|---|
| `scripts/linux/m11-responder-relay-sql.sh` | 5465B | MSSQL 对外认证触发的一键编排——Responder 捕获(→hashcat) 或 ntlmrelayx |
| `scripts/linux/m12-ad-enum-linux.sh` | 17351B | 从 Linux（Kali）侧对 AD/LDAP 做枚举的命令模板集合——ldapsearch 基础/用户/ |
| `scripts/linux/m12-adcs-esc1-esc8.sh` | 4192B | ADCS 攻击——模板枚举、ESC1 证书申请与认证、ESC8 中继到 Web Enrollment |
| `scripts/linux/m12-kerberos-tickets-linux.sh` | 4739B | 加域 Linux 上的 Kerberos 票据使用——ccache/keytab 载入、格式转换、按服务要 TGS、认证 |
| `scripts/linux/m13-artifactory-replace.sh` | 3681B | 制品库（Artifactory/Nexus 等）替换下游制品——确认路径、架构与业务行为后替换并验证 |
| `scripts/linux/m13-ssh-controlmaster-hijack.sh` | 3183B | 利用已认证的 SSH 复用连接（ControlMaster 套接字）或 SSH Agent 转发，无密码跳到下一跳 |
| `scripts/linux/m13-sudo-gtfobins.sh` | 2697B | sudo 只允许某个具体程序（vim/find/lua 等）时的提权命令速查与自动探测 |
| `scripts/linux/m16-auth-capture.sh` | 3866B | 场景 13 认证接收端一键脚本 —— Responder 捕获 Net-NTLMv2 / ntlmrelayx 中继 / |

## powershell

| 文件 | 大小 | 用途 |
|---|---|---|
| `scripts/powershell/m00-recon-defenses.ps1` | 5600B | 落地后一次性侦察——位数/系统/语言模式/AMSI/AppLocker/Defender/出网能力/代理配置 |
| `scripts/powershell/m01-reflective-runner.ps1` | 3230B | 反射加载 .NET 程序集（内存执行，不落地临时文件），替代被拦的 Add-Type 动态编译 |
| `scripts/powershell/m01-stager-download-encrypted.ps1` | 3163B | 加密/混淆的下载执行 stager（HTTP(S) 取第二阶段并在内存中执行，不落地明文） |
| `scripts/powershell/m05-amsi-bypass-variants.ps1` | 5662B | AMSI 处理的多个实验版本，按宿主（PowerShell / WSH / .NET）选择匹配的实现 |
| `scripts/powershell/m05-applocker-enum.ps1` | 4821B | 枚举 AppLocker 有效策略、可写允许路径与 DLL 规则集状态，输出可直接使用的执行目录候选 |
| `scripts/powershell/m05-clm-bypass-runspace.ps1` | 3465B | 通过自定义 Runspace 绕过 Constrained Language Mode（CLM），并在新 Runspac |
| `scripts/powershell/m06-fodhelper-uac.ps1` | 5008B | 当前用户已是本地管理员组成员但会话未提升（中完整性）时，用 Fodhelper/ComputerDefaults 等自动 |
| `scripts/powershell/m06-service-hijack.ps1` | 5844B | 手工服务二进制劫持的完整自动化——先保存原配置（注册表导出 + 原 exe 备份），替换为 payload 并启动服务， |
| `scripts/powershell/m06-sigmapotato-reflect.ps1` | 4675B | 在 SeImpersonate 上下文中用 .NET 反射内存加载 SigmaPotato.exe（不落盘），执行任意  |
| `scripts/powershell/m07-credential-sources.ps1` | 8738B | 按"凭据来源"分类收集 Windows 凭据材料（SAM / LSA Secrets / 注册表 AutoLogon / |
| `scripts/powershell/m07-invoke-mimikatz-reflect.ps1` | 6989B | LSASS 无强保护时的凭据获取——内存加载 Invoke-Mimikatz（不落盘 ps1/exe）或 comsvcs |
| `scripts/powershell/m08-port-forward.ps1` | 5632B | Windows 跳板上的转发助手——netsh portproxy（正向收口/转发）与 ssh -L/-R 隧道两种形态 |
| `scripts/powershell/m09-proxy-aware-downloader.ps1` | 7025B | 代理感知的下载/执行器。自动读取系统代理（WinINet 用户上下文）或使用显式代理下载 URL， |
| `scripts/powershell/m11-powerupsql-templates.ps1` | 4972B | PowerUpSQL 侦察与执行模板——实例发现、权限确认、链接爬取(单跳/多跳)、 |
| `scripts/powershell/m11-sqlrecon-templates.ps1` | 4680B | SQLRecon.exe 模板封装——枚举(sqlspns)、info/whoami、links 系列、 |
| `scripts/powershell/m12-ad-enum-windows.ps1` | 4558B | Windows 侧 AD 枚举与 Kerberoast/ASREPRoast 模板（PowerView / AD 模块  |
| `scripts/powershell/m12-delegation-attacks.ps1` | 5471B | 委派攻击模板——非约束委派票据捕获、约束委派 S4U、RBCD 全流程（命令速查 + 前置检查） |
| `scripts/powershell/m14-jea-file-copy.ps1` | 7946B | 自动化“JEA 过宽文件复制”利用——连接 JEA 受限端点、枚举可用命令、无害探边界、 |
| `scripts/powershell/m14-jit-admin-window.ps1` | 3720B | JIT 临时管理员权限窗口利用——授权状态查询、认证状态刷新、窗口内执行既定命令 |
| `scripts/powershell/m15-winrm-auth-matrix.ps1` | 8195B | WinRM 横移的 PowerShell Remoting 认证三模板（明文 / NTLM 哈希 / Kerberos） |

## python

| 文件 | 大小 | 用途 |
|---|---|---|
| `scripts/python/m00-delivery-server.py` | 5732B | 投递服务器——HTTP/HTTPS 双通道，记录每个请求的来源、User-Agent、路径，用于确认"目标是否真的下载了 |
| `scripts/python/m04-build-sideload-package.py` | 7934B | 把 DLL 旁加载目录包打成 ZIP 交付件，并在打包前做一致性校验： |
| `scripts/python/m09-dns-c2-client.py` | 5851B | DNS 通道客户端模板——通过 DNS 查询把指令取回、把结果分片回传（场景 32 的验证用） |
| `scripts/python/m09-dns-c2-server.py` | 8204B | 极简 DNS C2 服务端——把命令编码进 DNS A 记录响应回给目标，同时接收目标经子域 hex 回传的输出。 |
| `scripts/python/m13-xor-encoder.py` | 4336B | 对 Linux payload（ELF / 原始 shellcode 文件）做单字节 XOR 编码， |

## sql

| 文件 | 大小 | 用途 |
|---|---|---|
| `scripts/sql/m11-linked-server-queries.sql` | 8179B | Linked Server 侦察与远程执行模板——单跳/多跳、EXEC ... AT、引号转义、 |

## vba

| 文件 | 大小 | 用途 |
|---|---|---|
| `scripts/vba/m01-callback-ping.vba` | 4302B |  |
| `scripts/vba/m01-detect-arch.vba` | 2034B | 识别 Office 宿主位数并回传（投递 payload 前必须先做这一步） |
| `scripts/vba/m01-embedded-dotnet-runner.vba` | 2301B | VBA 内直接加载并执行 .NET 程序集（不依赖下载、不启动 PowerShell 子进程） |
| `scripts/vba/m01-shellcode-runner-vba-archbranch.vba` | 3421B | 用 VBA 编译期常量自动匹配 Office 位数，避免投递位数不匹配的 Runner 导致宿主崩溃 |
| `scripts/vba/m01-shellcode-runner-vba-x64.vba` | 2818B | x64 Office 下的进程内 shellcode Runner（不创建 PowerShell/子进程） |
| `scripts/vba/m01-shellcode-runner-vba-x86.vba` | 2062B | x86（32 位）Office 下的进程内 shellcode Runner |

