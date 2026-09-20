::: warning 仅限授权使用
本笔记仅用于 OSEP 官方实验 / 考试环境，或已获得书面授权的测试。禁止对未授权系统使用。
:::

# 97 · 考场快速定位表（现象 → 场景 → 文档）

> 考试现场最快的用法：**先看现象，再定位场景，再打开模块文档对应小节**。
>
> 不要从头翻 56 个场景。三张表分别是：按入口、按限制条件、按第一手验证命令。

---

## 1. 按入口定位

| 入口 | 场景 | 模块文档 |
|---|---|---|
| Word 文档投递（后台用户打开） | 1, 2, 3, 4, 5, 17 | [01-word-vba-office](/zh/modules/01-word-vba-office) |
| 邮件链接 / HTA | 6, 7, 8 | [02-hta](/zh/modules/02-hta) |
| 邮件附件（JScript/脚本） | 9, 10, 17 | [03-jscript-dotnettojscript](/zh/modules/03-jscript-dotnettojscript) |
| ZIP 附件（宿主 + DLL） | 11, 12 | [04-dll-sideloading](/zh/modules/04-dll-sideloading) |
| 日历邀请（ICS） | 13 | [16-ics-calendar](/zh/modules/16-ics-calendar) |
| Web 上传 ASPX（IIS） | 14 | [10-web-entry-webshell](/zh/modules/10-web-entry-webshell) |
| Web SQL 注入 | 15, 44 | [10-web-entry-webshell](/zh/modules/10-web-entry-webshell)、[11-mssql](/zh/modules/11-mssql) |
| Web 命令注入 | 16 | [10-web-entry-webshell](/zh/modules/10-web-entry-webshell) |
| 自定义 EXE 投递 | 18, 19, 20 | [05-applocker-clm-amsi](/zh/modules/05-applocker-clm-amsi) |
| AppLocker 允许目录 | 21, 22 | [05-applocker-clm-amsi](/zh/modules/05-applocker-clm-amsi) |
| 受信任宿主（InstallUtil/Workflow/XSL） | 23, 24 | [05-applocker-clm-amsi](/zh/modules/05-applocker-clm-amsi) |
| 本地管理员普通令牌 | 25 | [06-uac-windows-privesc](/zh/modules/06-uac-windows-privesc) |
| 服务账户 + SeImpersonate | 26 | [06-uac-windows-privesc](/zh/modules/06-uac-windows-privesc) |
| 服务配置/路径可写 | 27 | [06-uac-windows-privesc](/zh/modules/06-uac-windows-privesc) |
| 企业代理出网 | 28, 29 | [09-c2-egress-channels](/zh/modules/09-c2-egress-channels) |
| 分阶段通信 | 30, 31 | [09-c2-egress-channels](/zh/modules/09-c2-egress-channels) |
| DNS 通道 / 域前置 | 32, 33 | [09-c2-egress-channels](/zh/modules/09-c2-egress-channels) |
| 内网跳板 | 34, 35 | [08-pivoting-tunneling](/zh/modules/08-pivoting-tunneling) |
| Linux 上传站（执行 ELF） | 36, 37 | [13-linux](/zh/modules/13-linux) |
| Linux 共享库加载 | 38 | [13-linux](/zh/modules/13-linux) |
| sudo 单程序 | 39 | [13-linux](/zh/modules/13-linux) |
| 制品库（Artifactory） | 40 | [13-linux](/zh/modules/13-linux) |
| Kiosk 受限桌面 | 41 | [14-kiosk-jea-jit](/zh/modules/14-kiosk-jea-jit) |
| JEA 端点 | 42 | [14-kiosk-jea-jit](/zh/modules/14-kiosk-jea-jit) |
| JIT 临时权限 | 43 | [14-kiosk-jea-jit](/zh/modules/14-kiosk-jea-jit) |
| SQL 低权限登录 | 44 | [11-mssql](/zh/modules/11-mssql) |
| Linked Server | 45 | [11-mssql](/zh/modules/11-mssql) |
| 本地高权限 + LSASS 保护 | 46 | [07-credentials-lsass](/zh/modules/07-credentials-lsass) |
| 加域 Linux 票据 | 47 | [12-ad-attacks](/zh/modules/12-ad-attacks) |
| SSH 复用连接 | 48 | [13-linux](/zh/modules/13-linux) |
| 域用户可读 LAPS | 49 | [12-ad-attacks](/zh/modules/12-ad-attacks) |
| 非约束委派主机 | 50 | [12-ad-attacks](/zh/modules/12-ad-attacks) |
| 计算机对象写权限 | 51 | [12-ad-attacks](/zh/modules/12-ad-attacks) |
| 约束委派服务账户 | 52 | [12-ad-attacks](/zh/modules/12-ad-attacks) |
| 子域 → 林根 | 53 | [12-ad-attacks](/zh/modules/12-ad-attacks) |
| ADCS ESC1 | 54 | [12-ad-attacks](/zh/modules/12-ad-attacks) |
| ADCS ESC8 | 55 | [12-ad-attacks](/zh/modules/12-ad-attacks) |
| 仅 WinRM 可达 | 56 | [15-winrm-lateral](/zh/modules/15-winrm-lateral) |

---

## 2. 按限制条件定位（考试中最常遇到）

| 观察到的现象 | 场景 | 第一反应 |
|---|---|---|
| 宏能跑，但 Office 起不了 PowerShell | 2 | 改纯 VBA 宿主内执行，不要依赖子进程 |
| 第二阶段脚本被扫描拦截 | 3, 10 | 换与宿主匹配的 AMSI 处理；PS 的版本不能套用到 WSH |
| Add-Type 动态编译的临时文件被删 | 4 | 换反射 Runner / 预编译 C# |
| 文档关闭后会话消失 | 5 | 迁移到同用户常驻进程 / 计划任务 |
| EXE 被 AppLocker 拒绝 | 6, 21, 22 | 枚举有效规则找可写允许目录；或改投 DLL |
| PowerShell 处于 CLM | 7 | 自定义 Runspace 绕过 |
| 简单脚本能跑、加 .NET 桥接被拦 | 10 | 拆分第二阶段，把被检测内容挪出去 |
| DLL 加载后宿主闪退 | 12 | 检查导出表/调用约定，用 Proxy DLL 全转发 |
| 邀请发出但没认证到达 | 13 | 检查客户端版本/配置，不要假定"收到=会认证" |
| 上传的 ASPX/EXE 被查杀 | 14, 18, 37 | 精简特征 + 编码/加密 + 换宿主形态 |
| 一种下载工具被拦，另一种可以 | 15 | 按 curl → certutil → bitsadmin → PS 顺序换 |
| 命令长度受限、复杂引号被截断 | 16 | 短第一阶段 + 分离下载执行 |
| 目标无法访问我的文件服务器 | 17 | 用内嵌第二阶段版本 |
| EXE 落地即被删 | 18 | 区分"加载器被检测"与"内容被检测" |
| 能落地能启动，进入执行/通信阶段被终止 | 19 | 行为检测：换进程内/跨进程实现 |
| 原生 EXE 不能当托管程序集 | 20 | 用 Assembly.Load + 反射调用入口 |
| InstallUtil 被策略阻止 | 23 | 换 Workflow Compiler |
| 常规脚本入口受限 | 24 | 用 XSL 处理路线 |
| 是管理员但高权限操作被拒 | 25 | 令牌未提升 → Fodhelper 等 UAC 绕过 |
| 自动提权工具失败，但能改服务 | 27 | 手工服务二进制劫持 + 保存/恢复原配置 |
| 用户态能回连，SYSTEM 后失联 | 29 | 两种上下文的代理设置不同（WinHTTP vs WinINet） |
| 第一阶段成功，第二阶段始终没有 | 30 | 全阶段统一路径：地址/端口/协议 |
| HTTPS 在握手或请求阶段失败 | 31 | 证书信任 / TLS 版本 / UA / 代理检查 |
| 直连和常规代理都不通 | 32, 33 | DNS 通道；或域前置（依赖服务支持） |
| 从 Kali 访问内网被拒，跳板可以 | 34 | 端口转发 + 回连路径与跳板一致 |
| 正向访问通，目标主动回连不通 | 35 | 在目标可达位置设监听/转发 |
| ELF 被 AV 检测 | 37 | 自定义 ELF / 编码加载（Windows 手段无效） |
| 需要从可控位置加载共享库 | 38 | 分别准备 LD_PRELOAD / LD_LIBRARY_PATH 版本 |
| sudo 只允许 vim/find/lua | 39 | 对应 GTFOBins 命令与参数限制 |
| 能覆盖制品，不能登录下游 | 40 | 匹配下游架构/文件名/业务行为 |
| 只有 Kiosk 桌面 | 41 | 文件对话框/配置/已装应用找执行机会 |
| JEA 只暴露少量命令 | 42 | 利用过宽的文件复制写入其他位置 |
| 临时管理员窗口很短 | 43 | 先备好窗口内命令，避免现场试错 |
| SQL 能登录但不能执行系统命令 | 44 | 用该身份触发对外认证 + 中继 |
| Linked Server 能查不能远程执行 | 45 | 检查远端映射账户与 RPC out 配置 |
| LSASS 访问失败 | 46 | 换凭据来源，不要假定能绕过保护 |
| 加域 Linux 有票据，下一跳是 Windows | 47 | 票据格式转换 + Kerberos 认证 |
| 没有 SSH 密码但有活跃连接 | 48 | ControlMaster 套接字 / Agent 转发 |
| 当前机器无本地提权点 | 49 | 读 LAPS 拿另一台机器本地管理员 |
| 控制了非约束委派主机 | 50 | 诱导认证 + 票据捕获 |
| 对计算机对象有写权限 | 51 | RBCD 配置 + S4U 票据 |
| 约束委派只能访问指定服务 | 52 | 由委派配置与 SPN 决定目标，注意协议转换 |
| 子域已控，目标是林根 | 53 | 判断信任关系与 Extra SID 条件 |
| 低权限用户可申请模板 | 54 | ESC1：模板条件判定 → 申请 → 认证 |
| CA 有 HTTP 注册入口 | 55 | ESC8：中继到 Web Enrollment |
| 凭据有效但只开放 WinRM | 56 | 密码/哈希/票据三种认证模板 |

---

## 3. 第一手验证命令卡

| 要确认的事 | 命令 |
|---|---|
| 目标是否访问了我的投递地址 | 看 `~/osep/logs/http-80.log` / SMB 服务端输出 |
| 宏/脚本是否真的执行 | 无害回调：`curl http://LHOST/worked`、`nslookup LHOST`、写临时文件 |
| Office 位数 | WMI 查 `winword.exe` 命令行是否含 `Program Files (x86)`（M01 场景 1） |
| 当前身份与特权 | `whoami /priv`、`whoami /groups` |
| 系统与补丁 | `systeminfo` |
| 出网能力 | 直连 `curl -v http://LHOST/`；代理 `curl -x PROXY`；DNS `nslookup x.LHOST` |
| AppLocker 有效规则 | `Get-AppLockerPolicy -Effective -Xml`、`Test-Path` 逐路径试探 |
| 语言模式 | `$ExecutionContext.SessionState.LanguageMode` |
| AMSI 是否生效 | 触发已知被扫字符串，观察是否报 "script content is blocked" |
| 服务配置 | `sc qc <svc>`、`sc query`、`icacls <binpath>` |
| 域内可达性 | `netexec smb TARGET -u USER -p PASS -d DOMAIN` |
| WinRM 可达性 | `netexec winrm TARGET -u USER -p PASS -d DOMAIN` |
| 委派/ACL | `bloodhound-python` 或 SharpHound 采集后看图 |
| 证书模板 | `certipy find -u USER -p PASS -dc-ip DC` |
| Linux 提权点 | `sudo -l`、`find / -perm -4000`、`getcap -r / 2>/dev/null` |
| 共享库加载 | `ldd <bin>`、`LD_DEBUG=libs <bin>` |
| SSH 复用 | `ssh -O check USER@TARGET`、`ls -l /tmp/ssh-*`、`ssh-add -l` |

---

## 4. 使用顺序（考场 5 步）

1. **确认入口** → 查表 1
2. **确认限制** → 查表 2
3. **跑第一手验证** → 查表 3（先证明投递成功，再怀疑查杀）
4. **打开模块文档的"场景 N"小节** → 按"准备 → 执行 → 验证"照做
5. **卡住就翻该小节的"失败分支与备选"** → 一次只改一个变量并记录
