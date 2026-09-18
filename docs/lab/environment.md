# 实验环境

下面假设攻击机是 Kali 或同类 Debian，目标是你自己的 Windows / Linux 虚拟机或官方实验网。不要把这套目录当作生产 C2。

## 目录

```bash
mkdir -p ~/lab/{payloads/{win/{x86,x64},linux,web},listeners,logs,loot,tools,tickets}
cd ~/lab
```

| 目录 | 放什么 |
|---|---|
| `payloads/win/x86`、`x64` | 按位数分开的 Windows 实验载荷，**不要混放** |
| `payloads/linux` | ELF、共享库 |
| `payloads/web` | 仅实验网内使用的上传测试文件 |
| `listeners` | 监听命令备忘 |
| `logs` | 每个入口一份投递 / 回连日志 |
| `loot` | 哈希、票据、截图（实验数据，勿公开） |
| `tools` | 交叉编译产物、从官方渠道取得的工具 |
| `tickets` | Kerberos ccache，按会话分文件 |

## 端口（示例，可改，但要固定）

| 端口 | 用途 |
|---|---|
| 80 | HTTP 投递 |
| 443 | HTTPS 投递 |
| 445 | SMB 投递 / 认证实验 |
| 1080 | SOCKS |
| 4444 | 反向连接监听 |
| 5985 / 5986 | WinRM（目标侧） |
| 11601 | Ligolo-ng 代理端 |

```bash
# 投递服务：一定要看请求日志，否则分不清「没打开」和「打开了但没执行」
cd ~/lab/payloads && python3 -m http.server 80 2>&1 | tee ~/lab/logs/http-80.log

# 监听（readline + 落盘）
rlwrap -cAr nc -lvnp 4444 | tee ~/lab/logs/shell-4444.log
```

HTTPS 自签证书只用于实验；记下指纹，排错时先对指纹再怀疑载荷。

```bash
openssl req -newkey rsa:2048 -nodes -keyout ~/lab/tools/key.pem \
  -x509 -days 365 -out ~/lab/tools/cert.pem -subj "/CN=lab"
openssl x509 -in ~/lab/tools/cert.pem -noout -fingerprint -sha256
```

## 每次入口的三步验证

1. 投递日志里有没有请求
2. 无害回调有没有到（`curl` / `nslookup` / 写文件）
3. 会话是否稳定：立刻 `whoami /priv`、确认位数、确认出网路径

缺任何一步就不要进入「免杀 / 注入」排错，否则变量太多。

## 位数

Windows 载荷在生成前先确定目标进程位数。Office、`mshta`、`wscript`、IIS 工作进程可能和操作系统位数不一致。不确定就准备两套，用探测结果选择，不要赌。

## 编译链（Kali）

```bash
sudo apt install -y mingw-w64 gcc python3-pip

# 语法级检查示例，不是「一键生成马」
x86_64-w64-mingw32-gcc -o hello-x64.exe hello.c -s -O2
i686-w64-mingw32-gcc   -o hello-x86.exe hello.c -s -O2
gcc -shared -fPIC -o libdemo.so demo.c
```

.NET 程序集优先用目标机已有的 `csc.exe` 编译，实验环境通常比在 Kali 上装一整套 Mono 更稳。

## staged 与路径一致

所有阶段必须走**已经验证可达的同一条路径**（地址、端口、协议、代理）。第一阶段通、第二阶段不通，优先查路径而不是换编码。详见 [出网通道](/topics/egress)。

## 节奏

- 每个入口先做无害对照，再上实验载荷
- 一次只改一个变量，并记下来
- 先走能稳定验证的路径，再处理需要组合条件的链（例如应用控制 + 语言模式 + 脚本扫描同时存在）
