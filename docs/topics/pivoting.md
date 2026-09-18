# 隧道与转发

**内网某台机器能访问 ≠ 你的 Kali 能访问。** 正向（你发起）和目标主动回连是两条路。

把 Kali 的地址填进目标侧的反向连接 / UNC / 认证回调里，是实验里最浪费时间的错误：目标到 Kali 的路由常常不存在。

## 四种方向

| 类型 | 谁在听 | 谁发起 | 解决什么 |
|---|---|---|---|
| 本地转发 `-L` | Kali | Kali | 你要访问内网服务 |
| 动态 SOCKS `-D` | Kali | Kali | 浏览器 / 扫描器进内网 |
| 远程转发 `-R` / 在跳板上 listen | 目标可达的那台机器 | 目标主动连 | 反向 shell、NTLM 回连 |
| 整网 tun（Ligolo） | Kali tun | Kali | 像在本地一样访问整段网 |

SOCKS 只承载 **Kali 发起的连接**。SQL `xp_dirtree`、反向 shell、认证回调走的是目标自己的路由，SOCKS 帮不上忙。接收点必须放在目标能连上的位置，再经隧道送回 Kali。

## SSH

```bash
# Kali 访问内网网站
ssh -L 127.0.0.1:8081:INTERNAL:8081 USER@PIVOT

# SOCKS
ssh -D 1080 USER@PIVOT

# 让 PIVOT 听一个端口，转到 Kali 的监听（目标主动连 PIVOT）
ssh -R 0.0.0.0:4444:127.0.0.1:4444 USER@PIVOT
```

`GatewayPorts` 未开时，`-R` 可能只绑在跳板的 127.0.0.1。

## Ligolo-ng

公开项目：[nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)。实验流程概念上是：Kali 起 proxy → 已控主机跑 agent → 加路由 / listener。

```bash
# 代理端（Kali）示例，以你安装的版本为准
./proxy -selfcert
ip route add 10.10.20.0/24 dev ligolo
```

`-selfcert` 是明文通道，实验可接受；授权报告里不要写成「加密隧道」。Windows 跳板用对应的 agent。需要目标主动连回来时，在 Ligolo 里把 listener 开在 **agent 那一侧的地址**，`to` 指回 Kali 监听。

## Chisel / sshuttle

[jpillora/chisel](https://github.com/jpillora/chisel) 适合「只有 HTTP 出网」时的 SOCKS。`sshuttle` 适合 Linux 跳板整段转发。选你已经验证能在跳板上执行的那一个，不要三条一起上。

## 端口纪律

改任何地址或端口后，用无害连接验证（curl 一个静态页、`nc` 打一下端口）。不要假设「正向通了，回连也会通」。

## 防御侧

- 分段、出站默认拒绝；跳板网段不能随意连核心
- 监控新的 tun 接口、异常的 `ssh -R`、内部主机对陌生地址的 4444/11601
- SMB 签名强制，减少「回连认证被中继」的价值，见 [MSSQL](/topics/mssql)
