# Windows 提权

拿到立足点之后，先看**当前令牌是什么**，再选路线。不要先跑自动脚本。

```powershell
whoami /all
net localgroup administrators
```

关注：完整性级别（Mandatory Label）、是否属于 Administrators、`SeImpersonatePrivilege` / `SeAssignPrimaryTokenPrivilege`、能否改服务配置。

## 三条常见形态

| 你看到的 | 更可能的方向 |
|---|---|
| 已在管理员组，但是 Medium 完整性 | UAC 相关：未提升令牌 |
| 服务账户 / IIS 池账户，有 `SeImpersonatePrivilege` | 令牌模拟类公开工具（Potato 家族等） |
| 对某服务有写权限或可停启 | 服务二进制 / 配置劫持 |

## 未提升的管理员

`BUILTIN\Administrators` + `Medium Mandatory Level` 表示 UAC 把你关在过滤令牌里。自动提升的系统程序若读取 **HKCU** 下的协议处理项，就可能被用来以高完整性执行命令。公开讨论最多的是 `fodhelper.exe` 与 `HKCU\Software\Classes\ms-settings\Shell\Open\command`。

实验室里：

1. 先确认 `EnableLUA` 和当前用户确实在管理员组；不是管理员则这条无效
2. 读微软文档和公开 writeup 理解触发条件，在**授权 VM** 上自己验证
3. 用完清理 HKCU 下的实验键，这是基本 OPSEC，也避免把实验机搞坏

本站不放「注册表一键反弹」的现成命令。AlwaysInstallElevated 是另一条独立检查：`HKLM` 与 `HKCU` 的 `AlwaysInstallElevated` 都为 1 时，`msiexec` 安装用户 MSI 会以 SYSTEM 跑——先读键再决定要不要在实验里验证。

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

## SeImpersonate

IIS 应用池、SQL 服务账户经常带这个特权。公开工具链是 PrintSpoofer / GodPotato / SigmaPotato 等，**从官方或作者仓库取、在实验网用**。依赖服务没开（例如 Print Spooler 停了）时换工具，而不是换特权判断。

先看特权，再看依赖服务是否存在，最后才选二进制。

## 服务劫持

```cmd
sc qc SERVICE
sc sdshow SERVICE
accesschk.exe -quvcw USER SERVICE
```

能改 `BINARY_PATH_NAME` 或能写服务映像文件时，才谈劫持。实验纪律：

1. 先导出注册表 / 备份原二进制
2. 换成你的实验程序
3. 验证权限
4. **恢复原配置**（授权测试报告里「可恢复」和「能提权」一样重要）

服务程序若不以服务控制管理器期望的方式注册，`sc start` 可能报 1053，但副作用可能已经发生。验证看结果，不要只看 SCM 报错。

## 失败分类

| 现象 | 先查 |
|---|---|
| UAC 手法没反应 | 用户根本不是管理员；或 Consent 策略不允许静默提升 |
| Potato 类失败 | 特权不存在；依赖服务停；AV 拦特定工具名 |
| 改了服务路径没有 SYSTEM | 服务以低权账户运行；或映像没被真正启动 |

## 防御侧

- 普通运维不要给 SeImpersonate；能用虚拟账户 / gMSA 就不要用高权服务账户
- 服务 ACL 收紧；可写目录不要放 SYSTEM 服务映像
- 关不必要的自动提升协议处理；监控 HKCU 下 `ms-settings` 一类异常键
- 及时打补丁，历史内核提权一般不是现代实验的主路径
