# WSH 与 .NET

Windows Script Host（`cscript.exe` / `wscript.exe`）解释 `.js` / `.vbs`。它**不是** .NET 进程。脚本附件能运行、独立 EXE 不能，是实验室里很常见的组合。

## 先判断什么

- 脚本规则：AppLocker 默认对脚本的处理和 EXE 不同，先枚举有效规则
- 宿主位数：64 位 Windows 上，双击通常走 `System32` 的 64 位 `wscript`；`SysWOW64` 才是 32 位
- .NET 版本：现代 Windows 默认有 4.x；2.0/3.5 需要功能已启用
- AMSI：Win10+ 会扫描**送进脚本引擎的文本**。文件表面上是「下载逻辑」、真正攻击内容是运行时 `eval` 拼出来的，扫描点在后者

## 位数（最容易静默失败）

| 宿主 | 能加载的程序集 |
|---|---|
| 64 位 `cscript` / `wscript` | x64 或 AnyCPU |
| 32 位宿主 | x86 或 AnyCPU |

若脚本还要把代码注入其它进程，shellcode 位数必须跟**目标进程**一致，不是跟操作系统一致。失败时脚本常常没有任何输出，只能靠监听和进程列表判断。

先打印宿主信息：

```bat
echo %PROCESSOR_ARCHITECTURE%
cscript //nologo //E:JScript -e "WScript.Echo(GetObject(\"winmgmts:\").Get(\"Win32_Processor\").AddressWidth)"
```

## 桥接类工具（只点名，不附带产物）

要把托管代码放进 WSH 进程，社区里长期使用的公开工具包括：

- [DotNetToJScript](https://github.com/tyranid/DotNetToJScript)
- SharpShooter / SuperSharpShooter 一类生成器

它们把程序集序列化进脚本，运行时在 WSH 里激活 `[ComVisible]` 类型。本站不托管生成结果。在授权实验里自己编译、自己改类型名，避免默认工程名当指纹。

```bat
:: 目标机上的 .NET 编译器（实验用）
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /platform:anycpu /out:demo.dll demo.cs
```

## AMSI 与「看起来无害的 dropper」

纯下载、只把文件存到磁盘的 JScript，正文往往不像「攻击脚本」，有时能过内容扫描；一旦把大段第二阶段内嵌、或 `eval` 动态拼出，就可能被拦。处理思路是**换扫描上下文**（换宿主、换「数据 vs 代码」的边界），而不是复制网上过期的 bypass。

PowerShell 的 AMSI 处理不能直接套到 WSH：集成点不同。

## 失败分类

| 现象 | 先查 |
|---|---|
| 双击无回连，`cscript` 也无 | 位数、.NET 版本、脚本规则 |
| 简单脚本能跑，一加 .NET 桥接被拦 | 内容扫描 / AMSI；拆第二阶段 |
| EXE 能下不能跑 | 这正是走 WSH 的原因；不要让脚本再 `Run(pay.exe)` |

## 防御侧

- AppLocker 脚本规则覆盖 `cscript` / `wscript` / `mshta`
- 约束 WSH；能关就关
- 监控脚本宿主加载 CLR、异常的子进程和出网
