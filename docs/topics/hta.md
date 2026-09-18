# HTA

HTML Application 由 `mshta.exe` 承载。它是系统目录里的签名程序，在「默认 AppLocker 规则」环境里常常能跑，而用户自己的 EXE 不能。

## 先判断什么

- 有没有 Office？没有宏入口时，邮件链接 / `.hta` 是另一类客户端执行
- AppLocker 有效规则是否放行 `%SystemRoot%\System32\mshta.exe`
- 目标是「点链接」还是「双击附件」——网关经常丢掉 `.hta` 附件，链接更常见
- 失败是 **HTA 没执行**，还是 **HTA 执行了但下一阶段没有**

## 无害对照

最小 HTA 只做一件事：用 JScript / VBScript 访问你实验机上的一个 URL，或写一个本地文件。服务器日志里要能看到：

1. `GET /xxx.hta`
2. 随后的回调请求

两步都有，才能证明 `mshta` → 脚本引擎 → 出网 是通的。窗口应用 `<HTA:APPLICATION WINDOWSTATE="minimize">` 并在结束时关闭，避免一直停在桌面上。

## 下载和执行拆开

实验室里常见「下载和执行写在同一段脚本里没反应，拆开却可以」。不要一上来认定是杀软：

- 文件还没写完就开始执行
- 工作目录 / 权限导致第二步找不到文件
- 第一段脚本结束，`mshta` 进程退出，异步下载被干掉

先给每一步一个 HTTP 回显（「写完了」「要执行了」），用日志定位卡在哪。这是时序问题，不是编码问题。

## 和 PowerShell / CLM 的关系

HTA 可以再拉起 `powershell.exe`。若语言模式是 Constrained Language，或 `powershell.exe` 本身被应用控制拒绝，这条短链会断。下一步通常是换**受信任的 .NET 宿主**（见 [AppLocker 与 AMSI](/topics/applocker-amsi)），而不是把同一段 `IEX(DownloadString)` 换种混淆再试。

位数：64 位系统的 `System32\mshta.exe` 是 64 位，会拉 64 位 PowerShell；需要 32 位时明确走 `SysWOW64`。

## 公开参考

- [LOLBAS: Mshta](https://lolbas-project.github.io/lolbas/Binaries/Mshta/)
- 邮件发送（实验网 SMTP）：

```bash
swaks --body 'Please see http://LHOST/note.hta' \
  --add-header "MIME-Version: 1.0" --add-header "Content-Type: text/html" \
  --header "Subject: lab" -t USER@DOMAIN -f sender@lab --server SMTP_SERVER
```

本站不提供可投递的 HTA 文件。自己写的实验文件不要提交到 GitHub Pages。

## 防御侧

- AppLocker / WDAC 不要只拦用户目录 EXE，把脚本宿主纳入规则
- 邮件网关拦 `.hta`，并注意 `mshta http://...` 形式的快捷方式
- 监控 `mshta.exe` 出网、以及它创建 `powershell` / `cmd` / `csc` / `InstallUtil` 的进程链
