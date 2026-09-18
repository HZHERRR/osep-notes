::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test.
:::

# 97 · Field lookup

Match the **constraint**, open the module, run the first verification commands. Do not start at scenario 1 every time.

## By entry

| You have | Open |
|---|---|
| Word document | [01](/modules/01-word-vba-office) |
| Mail link / HTA | [02](/modules/02-hta) |
| JScript / VBS attachment | [03](/modules/03-jscript-dotnettojscript) |
| ZIP with host + DLL | [04](/modules/04-dll-sideloading) |
| Calendar invite | [16](/modules/16-ics-calendar) |
| ASPX upload | [10](/modules/10-web-entry-webshell) |
| SQL injection | [10](/modules/10-web-entry-webshell), [11](/modules/11-mssql) |
| Short command injection | [10](/modules/10-web-entry-webshell) |
| Custom EXE | [05](/modules/05-applocker-clm-amsi) |
| AppLocker allowed directory | [05](/modules/05-applocker-clm-amsi) |
| InstallUtil / Workflow / XSL | [05](/modules/05-applocker-clm-amsi) |
| Admin without elevation | [06](/modules/06-uac-windows-privesc) |
| Service account + SeImpersonate | [06](/modules/06-uac-windows-privesc) |
| Writable service | [06](/modules/06-uac-windows-privesc) |
| Corporate proxy | [09](/modules/09-c2-egress-channels) |
| Staged channel | [09](/modules/09-c2-egress-channels) |
| DNS / domain fronting | [09](/modules/09-c2-egress-channels) |
| Internal pivot | [08](/modules/08-pivoting-tunneling) |
| Linux ELF upload | [13](/modules/13-linux) |
| Kiosk / JEA / JIT | [14](/modules/14-kiosk-jea-jit) |
| LSASS blocked | [07](/modules/07-credentials-lsass) |
| Linux tickets → Windows | [12](/modules/12-ad-attacks) |
| WinRM only | [15](/modules/15-winrm-lateral) |

Full constraint list: [scenario map](/scenarios).

## First commands

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
