# WinRM

凭据是对的，但 445 不通时，把基于 SMB 的横移整段划掉：PsExec、多数 `wmiexec` 落地、`smbexec`、`admin$` 再触发计划任务。目标如果只暴露 5985/5986，执行面就是 WinRM。

## 先确认端口和权限

```bash
nc -nvz TARGET 5985
nc -nvz TARGET 5986

netexec winrm TARGET -u USER -p 'PASS'
netexec winrm TARGET -u USER -H NTHASH
netexec winrm TARGET -d DOMAIN -u USER -p 'PASS'
```

`(Pwn3d!)` 通常表示本地管理员。没有这个标记也可能仍在 `Remote Management Users` 里，命令能否跑要进会话再验证。

WinRM 默认允许的本地组是 Administrators 和 Remote Management Users。域里「用户合法」≠「这台机器允许他远程管理」。

## 进会话

```bash
evil-winrm -i TARGET -u USER -p 'PASS'
evil-winrm -i TARGET -u USER -H NTHASH
evil-winrm -i TARGET -S   # 5986 HTTPS；自签证书问题按工具文档处理
```

Kerberos：需要能解析 FQDN、能访问 KDC、时钟可用。`evil-winrm -k` 的具体参数以当前版本 `--help` 为准。

会话本身就是执行通道。尽量内存执行或让目标从它**已经能出网**的路径拉实验脚本，不要幻想再用 SMB 把文件拷进去。

## 明确放弃的方法

445 不通时不要再试：

- `impacket-psexec` / `smbexec`
- 依赖 `admin$` 的 WMI 执行
- SMB 中继到这台机器
- 把脚本放到 `\\TARGET\C$`

省下来的时间用来确认 5985 的 ACL、防火墙和凭证类型（密码 / 哈希 / 票）。

## 失败分类

| 现象 | 先查 |
|---|---|
| 认证失败 | 密码/哈希错；时钟；NLA vs WinRM 不是一回事 |
| 认证成功立刻断开 | 该用户不在允许组；语言模式；会话配额 |
| HTTPS 证书错误 | `-S` / 忽略自签；时间 |
| 能进不能出网 | 见 [出网通道](/topics/egress)；WinRM 身份的代理 |

## 防御侧

- 管理端口不要对全网开放；跳板 + 受限组
- 能用 JEA 就不要给完整 WinRM 管理员会话
- 5986 + 受控证书；禁未加密 5985（若策略允许）
- 监控非跳板来源的 5985 认证
