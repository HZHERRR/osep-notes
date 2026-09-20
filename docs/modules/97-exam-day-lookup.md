::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 97 · Exam-day lookup (symptom → scenario → doc)

> The fastest way to use this on the exam: **read the symptom first, then locate the scenario, then open the matching section of the module doc**.
>
> Do not flip through all 56 scenarios from the top. The three tables are: by entry, by constraint, by first-hand verification command.

---

## 1. Locate by entry

| Entry | Scenarios | Module doc |
|---|---|---|
| Word document delivery (background user opens it) | 1, 2, 3, 4, 5, 17 | [01-word-vba-office](/modules/01-word-vba-office) |
| Mail link / HTA | 6, 7, 8 | [02-hta](/modules/02-hta) |
| Mail attachment (JScript/script) | 9, 10, 17 | [03-jscript-dotnettojscript](/modules/03-jscript-dotnettojscript) |
| ZIP attachment (host + DLL) | 11, 12 | [04-dll-sideloading](/modules/04-dll-sideloading) |
| Calendar invite (ICS) | 13 | [16-ics-calendar](/modules/16-ics-calendar) |
| Web ASPX upload (IIS) | 14 | [10-web-entry-webshell](/modules/10-web-entry-webshell) |
| Web SQL injection | 15, 44 | [10-web-entry-webshell](/modules/10-web-entry-webshell), [11-mssql](/modules/11-mssql) |
| Web command injection | 16 | [10-web-entry-webshell](/modules/10-web-entry-webshell) |
| Custom EXE delivery | 18, 19, 20 | [05-applocker-clm-amsi](/modules/05-applocker-clm-amsi) |
| AppLocker allowed directory | 21, 22 | [05-applocker-clm-amsi](/modules/05-applocker-clm-amsi) |
| Trusted host (InstallUtil/Workflow/XSL) | 23, 24 | [05-applocker-clm-amsi](/modules/05-applocker-clm-amsi) |
| Local admin with a normal token | 25 | [06-uac-windows-privesc](/modules/06-uac-windows-privesc) |
| Service account + SeImpersonate | 26 | [06-uac-windows-privesc](/modules/06-uac-windows-privesc) |
| Service config/path writable | 27 | [06-uac-windows-privesc](/modules/06-uac-windows-privesc) |
| Egress through a corporate proxy | 28, 29 | [09-c2-egress-channels](/modules/09-c2-egress-channels) |
| Staged comms | 30, 31 | [09-c2-egress-channels](/modules/09-c2-egress-channels) |
| DNS channel / domain fronting | 32, 33 | [09-c2-egress-channels](/modules/09-c2-egress-channels) |
| Internal pivot | 34, 35 | [08-pivoting-tunneling](/modules/08-pivoting-tunneling) |
| Linux upload point (run ELF) | 36, 37 | [13-linux](/modules/13-linux) |
| Linux shared library loading | 38 | [13-linux](/modules/13-linux) |
| sudo on a single program | 39 | [13-linux](/modules/13-linux) |
| Artifact repository (Artifactory) | 40 | [13-linux](/modules/13-linux) |
| Restricted Kiosk desktop | 41 | [14-kiosk-jea-jit](/modules/14-kiosk-jea-jit) |
| JEA endpoint | 42 | [14-kiosk-jea-jit](/modules/14-kiosk-jea-jit) |
| JIT temporary privileges | 43 | [14-kiosk-jea-jit](/modules/14-kiosk-jea-jit) |
| Low-privilege SQL login | 44 | [11-mssql](/modules/11-mssql) |
| Linked Server | 45 | [11-mssql](/modules/11-mssql) |
| Local high privilege + LSASS protection | 46 | [07-credentials-lsass](/modules/07-credentials-lsass) |
| Domain-joined Linux tickets | 47 | [12-ad-attacks](/modules/12-ad-attacks) |
| SSH connection reuse | 48 | [13-linux](/modules/13-linux) |
| Domain user can read LAPS | 49 | [12-ad-attacks](/modules/12-ad-attacks) |
| Unconstrained delegation host | 50 | [12-ad-attacks](/modules/12-ad-attacks) |
| Write access on a computer object | 51 | [12-ad-attacks](/modules/12-ad-attacks) |
| Constrained delegation service account | 52 | [12-ad-attacks](/modules/12-ad-attacks) |
| Child domain → forest root | 53 | [12-ad-attacks](/modules/12-ad-attacks) |
| ADCS ESC1 | 54 | [12-ad-attacks](/modules/12-ad-attacks) |
| ADCS ESC8 | 55 | [12-ad-attacks](/modules/12-ad-attacks) |
| WinRM only | 56 | [15-winrm-lateral](/modules/15-winrm-lateral) |

Full constraint list: [scenario map](/scenarios).

---

## 2. Locate by constraint (what you hit most on the exam)

| Symptom you see | Scenarios | First move |
|---|---|---|
| Macro runs, but Office cannot start PowerShell | 2 | Move to pure in-host VBA execution; do not depend on a child process |
| Stage-2 script blocked by scanning | 3, 10 | Switch to AMSI handling matched to the host; the PS version does not carry over to WSH |
| Temp file from Add-Type dynamic compilation deleted | 4 | Switch to a reflective runner / precompiled C# |
| Session dies when the document closes | 5 | Migrate to a persistent process under the same user / a scheduled task |
| EXE denied by AppLocker | 6, 21, 22 | Enumerate effective rules to find a writable allowed directory; or deliver a DLL instead |
| PowerShell is in CLM | 7 | Bypass with a custom Runspace |
| Simple script runs, but adding a .NET bridge gets blocked | 10 | Split stage 2; move the detected content out |
| Host crashes after the DLL loads | 12 | Check the export table/calling convention; use a proxy DLL that forwards everything |
| Invite sent, but no authentication arrives | 13 | Check the client version/config; do not assume “received = will authenticate” |
| Uploaded ASPX/EXE gets flagged | 14, 18, 37 | Trim signatures + encode/encrypt + change the host form |
| One download tool is blocked, another works | 15 | Rotate in this order: curl → certutil → bitsadmin → PS |
| Command length limited, complex quoting truncated | 16 | Short stage 1 + split download-and-execute |
| Target cannot reach my file server | 17 | Use the embedded-stage-2 version |
| EXE deleted the moment it lands | 18 | Separate “the loader is detected” from “the content is detected” |
| Lands and starts, then killed at the execution/comms stage | 19 | Behavioral detection: switch to an in-process/cross-process implementation |
| Native EXE cannot be loaded as a managed assembly | 20 | Use Assembly.Load + reflection to call the entry point |
| InstallUtil blocked by policy | 23 | Switch to the Workflow Compiler |
| Normal script entry points restricted | 24 | Take the XSL route |
| You are admin, but high-privilege operations are denied | 25 | Token is not elevated → Fodhelper and similar UAC bypasses |
| Auto-privesc tools fail, but you can modify a service | 27 | Manual service binary hijacking + save/restore the original config |
| Callback works in user context, lost after SYSTEM | 29 | The two contexts use different proxy settings (WinHTTP vs WinINet) |
| Stage 1 succeeds, stage 2 never arrives | 30 | One path for all stages: address/port/protocol |
| HTTPS fails at the handshake or the request stage | 31 | Check certificate trust / TLS version / UA / proxy |
| Neither direct nor the usual proxy works | 32, 33 | DNS channel; or domain fronting (depends on service support) |
| Internal access from Kali is denied, the pivot works | 34 | Port forwarding + a callback path that matches the pivot |
| Outbound access works, target-initiated callback does not | 35 | Put a listener/forward at a location the target can reach |
| ELF detected by AV | 37 | Custom ELF / encoded loading (Windows techniques do not apply) |
| Need to load a shared library from a location you control | 38 | Prepare separate LD_PRELOAD / LD_LIBRARY_PATH builds |
| sudo only allows vim/find/lua | 39 | The matching GTFOBins command and its parameter limits |
| Can overwrite the artifact, cannot log in downstream | 40 | Match the downstream architecture/filename/business behavior |
| Only the Kiosk desktop is available | 41 | Look for execution in file dialogs/config/installed apps |
| JEA exposes only a few commands | 42 | Abuse an over-broad file copy to write elsewhere |
| The temporary admin window is very short | 43 | Prepare the in-window commands beforehand; do not improvise live |
| SQL login works, but you cannot run system commands | 44 | Use that identity to trigger outbound authentication + relay |
| Linked Server can query but not execute remotely | 45 | Check the remote mapped account and the RPC out setting |
| LSASS access fails | 46 | Switch credential source; do not assume you can bypass the protection |
| Domain-joined Linux has tickets, the next hop is Windows | 47 | Ticket format conversion + Kerberos authentication |
| No SSH password, but there is an active connection | 48 | ControlMaster socket / agent forwarding |
| No local privesc point on this machine | 49 | Read LAPS to get local admin on another machine |
| You control an unconstrained delegation host | 50 | Coerce authentication + capture the ticket |
| You have write access on a computer object | 51 | RBCD configuration + S4U ticket |
| Constrained delegation only reaches the specified service | 52 | The delegation config and SPN decide the target; watch the protocol transition |
| Child domain owned, the objective is the forest root | 53 | Triage the trust relationship and the Extra SID conditions |
| A low-privilege user can request the template | 54 | ESC1: judge the template conditions → request → authenticate |
| The CA has an HTTP enrollment endpoint | 55 | ESC8: relay to Web Enrollment |
| Credentials are valid, but only WinRM is open | 56 | Authentication templates for password/hash/ticket |

---

## 3. First-hand verification command card

| What you want to confirm | Command |
|---|---|
| Whether the target hit my delivery address | Check `~/osep/logs/http-80.log` / the SMB server output |
| Whether the macro/script actually ran | Harmless callback: `curl http://LHOST/worked`, `nslookup LHOST`, write a temp file |
| Office bitness | WMI: check whether the `winword.exe` command line contains `Program Files (x86)` (M01 scenario 1) |
| Current identity and privileges | `whoami /priv`, `whoami /groups` |
| System and patches | `systeminfo` |
| Egress capability | Direct `curl -v http://LHOST/`; proxy `curl -x PROXY`; DNS `nslookup x.LHOST` |
| Effective AppLocker rules | `Get-AppLockerPolicy -Effective -Xml`, probe paths one by one with `Test-Path` |
| Language mode | `$ExecutionContext.SessionState.LanguageMode` |
| Whether AMSI is active | Trigger a known-scanned string and watch for “script content is blocked” |
| Service configuration | `sc qc <svc>`, `sc query`, `icacls <binpath>` |
| Domain reachability | `netexec smb TARGET -u USER -p PASS -d DOMAIN` |
| WinRM reachability | `netexec winrm TARGET -u USER -p PASS -d DOMAIN` |
| Delegation/ACL | Collect with `bloodhound-python` or SharpHound and read the graph |
| Certificate templates | `certipy find -u USER -p PASS -dc-ip DC` |
| Linux privesc points | `sudo -l`, `find / -perm -4000`, `getcap -r / 2>/dev/null` |
| Shared library loading | `ldd <bin>`, `LD_DEBUG=libs <bin>` |
| SSH reuse | `ssh -O check USER@TARGET`, `ls -l /tmp/ssh-*`, `ssh-add -l` |

Copy-paste version of the same checks:

```powershell
whoami
whoami /priv
whoami /groups
[Environment]::Is64BitProcess
$ExecutionContext.SessionState.LanguageMode
Get-AppLockerPolicy -Effective -Xml
netsh winhttp show proxy
```

```bash
id; sudo -l
klist
nc -nvz TARGET 5985
```

---

## 4. Order of use (5 steps on the exam)

1. **Confirm the entry** → table 1
2. **Confirm the constraint** → table 2
3. **Run the first-hand verification** → table 3 (prove delivery worked before you suspect AV)
4. **Open the “scenario N” section of the module doc** → follow prepare → execute → verify
5. **Stuck? Go to that section’s “failure branches and alternatives”** → change one variable at a time and log it
