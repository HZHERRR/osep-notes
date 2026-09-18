# Scenario map

Fifty-six constrained situations. Open the module, follow **Situation → Prepare → Procedure → If it fails**.

| # | Constraint | Module |
|---|---|---|
| 1 | Site accepts Word; AV present; Office bitness unknown | [01](/modules/01-word-vba-office) |
| 2 | Word opens, but Office cannot spawn PowerShell | [01](/modules/01-word-vba-office) |
| 3 | PowerShell starts; stage two is content-blocked | [01](/modules/01-word-vba-office) |
| 4 | `Add-Type` temp files are deleted | [01](/modules/01-word-vba-office) |
| 5 | Session dies when the document closes | [01](/modules/01-word-vba-office) |
| 6 | Mail works; no Office macro | [02](/modules/02-hta) |
| 7 | HTA runs under AppLocker + CLM + AMSI | [02](/modules/02-hta) |
| 8 | Combined HTA download+exec fails; split works | [02](/modules/02-hta) |
| 9 | JScript attachment runs; EXE does not | [03](/modules/03-jscript-dotnettojscript) |
| 10 | Simple JScript runs; complex script is scanned | [03](/modules/03-jscript-dotnettojscript) |
| 11 | User opens a ZIP’d program; no macro/script | [04](/modules/04-dll-sideloading) |
| 12 | DLL loads and the host immediately crashes | [04](/modules/04-dll-sideloading) |
| 13 | Calendar invite accepted; no macro | [16](/modules/16-ics-calendar) |
| 14 | ASPX upload on IIS with AV | [10](/modules/10-web-entry-webshell) |
| 15 | Classic ASP SQLi can run OS commands; downloader blocked | [10](/modules/10-web-entry-webshell) |
| 16 | Command injection accepts only a short string | [10](/modules/10-web-entry-webshell) |
| 17 | No stable egress; download stage never arrives | [09](/modules/09-c2-egress-channels) |
| 18 | Custom EXE is deleted on landing | [05](/modules/05-applocker-clm-amsi) |
| 19 | EXE starts, then dies when it runs payload | [05](/modules/05-applocker-clm-amsi) |
| 20 | Need a managed tool; its EXE cannot run from disk | [05](/modules/05-applocker-clm-amsi) |
| 21 | AppLocker blocks EXE except in an allowed directory | [05](/modules/05-applocker-clm-amsi) |
| 22 | EXE rules are tight; DLL/host rules differ | [05](/modules/05-applocker-clm-amsi) |
| 23 | InstallUtil unavailable; another trusted host is | [05](/modules/05-applocker-clm-amsi) |
| 24 | Normal script hosts blocked; XSL path is open | [05](/modules/05-applocker-clm-amsi) |
| 25 | Local admin, but the token is not elevated | [06](/modules/06-uac-windows-privesc) |
| 26 | Service account with impersonation rights | [06](/modules/06-uac-windows-privesc) |
| 27 | Auto potatoes fail; you can still change a service | [06](/modules/06-uac-windows-privesc) |
| 28 | Browser reaches the internet; custom payload does not | [09](/modules/09-c2-egress-channels) |
| 29 | User session egresses; SYSTEM does not | [09](/modules/09-c2-egress-channels) |
| 30 | Stage one returns; stage two never does | [09](/modules/09-c2-egress-channels) |
| 31 | HTTPS only, inspection breaks the channel | [09](/modules/09-c2-egress-channels) |
| 32 | HTTP(S) dead; DNS is allowed in the lab | [09](/modules/09-c2-egress-channels) |
| 33 | Destination domains filtered; lab supports domain fronting | [09](/modules/09-c2-egress-channels) |
| 34 | Internal site only accepts a given subnet | [08](/modules/08-pivoting-tunneling) |
| 35 | Forward proxy works; the target cannot call back | [08](/modules/08-pivoting-tunneling) |
| 36 | Linux upload executes ELF but checks business output | [13](/modules/13-linux) |
| 37 | Linux AV flags common ELF | [13](/modules/13-linux) |
| 38 | Linux binary loads a library from a path you control | [13](/modules/13-linux) |
| 39 | sudo allows only one editor/interpreter | [13](/modules/13-linux) |
| 40 | You can overwrite an artifact; you cannot log into the consumer | [13](/modules/13-linux) |
| 41 | Kiosk desktop only | [14](/modules/14-kiosk-jea-jit) |
| 42 | JEA exposes a few cmdlets | [14](/modules/14-kiosk-jea-jit) |
| 43 | Short JIT admin window | [14](/modules/14-kiosk-jea-jit) |
| 44 | SQL login works; OS commands do not | [11](/modules/11-mssql) |
| 45 | Linked Server can query, not execute remotely | [11](/modules/11-mssql) |
| 46 | LSASS access fails | [07](/modules/07-credentials-lsass) |
| 47 | Domain-joined Linux has tickets; next hop is Windows | [12](/modules/12-ad-attacks) |
| 48 | No SSH password; a multiplexed session exists | [13](/modules/13-linux) |
| 49 | No local privesc; current user can read LAPS | [12](/modules/12-ad-attacks) |
| 50 | You control an unconstrained-delegation host | [12](/modules/12-ad-attacks) |
| 51 | Write access on a computer object | [12](/modules/12-ad-attacks) |
| 52 | Constrained delegation to specific SPNs | [12](/modules/12-ad-attacks) |
| 53 | Child domain owned; forest root is the goal | [12](/modules/12-ad-attacks) |
| 54 | Low-priv user can enroll a bad template | [12](/modules/12-ad-attacks) |
| 55 | CA HTTP enrollment is reachable | [12](/modules/12-ad-attacks) |
| 56 | Creds work; only WinRM is open | [15](/modules/15-winrm-lateral) |
