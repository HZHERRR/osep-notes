# AppLocker 与 AMSI

落地之后先侦察限制，再决定执行形态。把「文件被删」和「进程跑起来后被杀」当成两类问题。

## 落地侦察（公开命令）

```powershell
$ExecutionContext.SessionState.LanguageMode
whoami /groups
whoami /priv

# AppLocker 有效策略（需要相应权限；没有就记「查不到」）
Get-AppLockerPolicy -Effective -Xml

Get-MpComputerStatus | Select-Object AMSI*, RealTimeProtectionEnabled
reg query "HKLM\Software\Microsoft\AMSI"
```

看进程里有没有 `amsi.dll`，比猜「有没有 Defender」更直接。

可写且可能被规则放行的目录，要**用有效策略**判断，不要背网传路径。不同企业的 AppLocker 差很多。

## 静态 vs 行为

| 现象 | 处理方向 |
|---|---|
| 无害 hello 能保存能运行，你的文件落地即消失 | 静态特征：换形态（托管程序集、受信任宿主），不要只 XOR 三次 |
| 能启动，执行到内存分配 / 远线程 / 出网时被杀 | 行为：换实现，或先确认是不是出网问题 |
| 只有脚本被拦 | AMSI / 脚本规则；换宿主比改字符串更有效 |

对照实验：先投一个只 `printf("ok")` 的程序。没有这步，后面的「免杀」都没有基线。

## Constrained Language Mode

CLM 下 PowerShell 不是「完全不能用」，而是动态能力和 .NET 使用面被砍。`powershell.exe` 这个进程还在，所以「AppLocker 放行了 powershell」≠「能反射加载」。

社区长期讨论的思路是：在**不是 powershell.exe 的托管进程**里创建 Runspace，语言模式可能不同。这是概念，不是保证。本站不提供现成绕过程序。公开示例见 [chvancooten/OSEP-Code-Snippets](https://github.com/chvancooten/OSEP-Code-Snippets) 等个人仓库——使用前自己审计，且只放进隔离实验网。

## 受信任宿主（LOLBAS）

默认规则常放行 `%SystemRoot%` 下的签名程序。实验室里用来**加载你的程序集**而不是「直启用户 EXE」的公开宿主包括：

| 宿主 | 备注 |
|---|---|
| `InstallUtil.exe` | `/U` 触发卸载路径上的用户代码，是老而公开的手法 |
| `Microsoft.Workflow.Compiler.exe` | InstallUtil 不可用时的备选之一 |
| `msxsl.exe` / `wmic ... /format:` | XSL 里带脚本；常规脚本入口被拦时的旁路 |

权威列表：[LOLBAS](https://lolbas-project.github.io/)。这些程序本身不是漏洞，是「策略没覆盖到的合法二进制」。

```text
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U lab.dll
```

`lab.dll` 由你在实验机编译。不要把编译结果推到这个站点仓库。

## AMSI

AMSI 在脚本引擎把内容交去执行时扫描。网上的一句话 bypass **随补丁失效**，公开复制它们的价值很低，法律和平台风险却高。这里只保留判断：

- 探针：无害但常被特征命中的字符串是否被拦，用来判断 AMSI 是否生效
- PowerShell 与 WSH 的集成点不同，不能共用同一段处理
- 失效时换扫描上下文（换宿主、改「何时把代码变成脚本引擎可见文本」），而不是堆更多混淆层

## 托管程序集 vs 原生 EXE

`Assembly.Load` 加载的是 .NET 程序集。原生 EXE 不能当程序集用。需要「工具能跑但 EXE 不能直启」时，先确认它是不是托管的：

```powershell
[Reflection.AssemblyName]::GetAssemblyName("C:\path\tool.dll").FullName
```

## 防御侧

- WDAC 比 AppLocker 更难绕；规则要覆盖 DLL 和脚本，不只是 EXE
- 对 InstallUtil、mshta、wmic、msxsl 做应用控制或 ASR
- AMSI 配合云提交；不要只靠本地签名
- 行为规则关注「系统目录二进制加载用户目录程序集」
