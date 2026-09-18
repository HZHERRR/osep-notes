# 现象定位表

::: warning 仅供学习 / 授权实验
这是**限制条件 → 技术路线**的对照，不是任何厂商的考题或靶场答案。  
在官方实验 / 考试里用时，遵守对方协议；不要把付费靶场的主机名、逐步通关写进公开仓库。
:::

用法：先看入口，再看限制，再打开对应主题页复制命令。一次只改一个变量。

## 按入口

| 你看到的入口 | 先看 |
|---|---|
| Word / `.docm` 会被打开 | [Office 宏](/topics/office-macros) |
| 邮件链接 / `.hta`，没有 Office | [HTA](/topics/hta) |
| 邮件附件 `.js` / `.vbs`，EXE 被拦 | [WSH 与 .NET](/topics/wsh-dotnet) |
| ZIP 里有签名程序 + 同目录 DLL | [DLL 旁加载](/topics/dll-sideloading) |
| 日历邀请 | [日历邀请](/topics/calendar) |
| IIS 可上传 `.aspx` | [Web 入口](/topics/web-entry) |
| SQL 注入 / `xp_cmdshell` | [MSSQL](/topics/mssql)、[Web 入口](/topics/web-entry) |
| 命令注入很短 | [载荷与监听](/lab/payloads) 最短下载 |
| 自定义 EXE 被删或被拒 | [AppLocker 与 AMSI](/topics/applocker-amsi) |
| 已是本地管理员但没提升 | [Windows 提权](/topics/windows-privesc) |
| IIS / SQL 服务账户 + SeImpersonate | [Windows 提权](/topics/windows-privesc) |
| 能改某个服务路径 | [Windows 提权](/topics/windows-privesc) |
| 浏览器能出网、自定义程序不能 | [出网通道](/topics/egress) |
| 内网站点只放行某网段 | [隧道与转发](/topics/pivoting) |
| Linux 上传执行 ELF | [Linux](/topics/linux) |
| `sudo -l` 只有 vim/find | [Linux](/topics/linux) |
| 只有 Kiosk 桌面 | [Kiosk / JEA / JIT](/topics/kiosk-jea-jit) |
| 凭据对，只开 5985 | [WinRM](/topics/winrm) |
| 加域 Linux 有票 | [Active Directory](/topics/ad) |

## 按限制

| 现象 | 第一反应 | 页面 |
|---|---|---|
| 宏能跑，Office 起不了 PowerShell | 进程内 VBA，不要 `Shell powershell` | [Office 宏](/topics/office-macros) |
| 第二阶段脚本被声明恶意 | AMSI；换宿主或先处理再 IEX | [AppLocker 与 AMSI](/topics/applocker-amsi) |
| `Add-Type` 临时文件被删 | 预编译 C# / 反射加载 | [Office 宏](/topics/office-macros) |
| 文档一关会话没了 | 迁移到长寿进程 | [Office 宏](/topics/office-macros) |
| EXE 被 AppLocker 拒 | 允许目录 / DLL / InstallUtil | [AppLocker 与 AMSI](/topics/applocker-amsi) |
| PowerShell 是 ConstrainedLanguage | 自定义 Runspace 或非 powershell 宿主 | [AppLocker 与 AMSI](/topics/applocker-amsi) |
| 简单脚本能跑，一加 .NET 桥接被拦 | 拆第二阶段；WSH 的 AMSI ≠ PS 的 | [WSH 与 .NET](/topics/wsh-dotnet) |
| DLL 加载后宿主闪退 | 导出表 / 位数 / `.def` 转发 | [DLL 旁加载](/topics/dll-sideloading) |
| 邀请发出但没认证 | 客户端不一定会拉外部资源 | [日历邀请](/topics/calendar) |
| 上传的 ASPX 被杀 | 精简；内存加载 | [Web 入口](/topics/web-entry) |
| curl 不行 certutil 可以 | 换下载器，不要重打注入 | [载荷与监听](/lab/payloads) |
| 用户态能回连，SYSTEM 后失联 | WinHTTP vs WinINet 代理 | [出网通道](/topics/egress) |
| 第一阶段通、第二阶段没有 | 地址/端口/协议不一致 | [出网通道](/topics/egress) |
| SOCKS 正向通，目标回连不到 Kali | 接收点放跳板 | [隧道与转发](/topics/pivoting) |
| LSASS 读不了 | 换 SAM / LSA Secrets，别死磕 | [凭据](/topics/credentials) |
| SQL 能登录不能 `xp_cmdshell` | UNC 触发认证 / impersonate | [MSSQL](/topics/mssql) |

## 落地后第一组命令

拿到任意 Windows 会话立刻跑：

```powershell
whoami
whoami /priv
whoami /groups
hostname
[Environment]::Is64BitProcess
[Environment]::Is64BitOperatingSystem
$ExecutionContext.SessionState.LanguageMode
Get-MpComputerStatus | Select RealTimeProtectionEnabled, AMSI*
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL
netsh winhttp show proxy
```

Linux：

```bash
id; uname -a; sudo -l
find / -perm -4000 2>/dev/null | head
env | grep -i proxy
ls -l /tmp/ssh-* 2>/dev/null
klist 2>/dev/null
```
