# Active Directory

先写清「票是谁的、要去哪个服务、以什么身份」，再敲命令。票据方向错了，工具再熟也没用。

示例域名用 `corp.example`，不要填任何付费靶场的主机名。

## Linux 上持票访问 Windows

时钟偏差必须小于约 5 分钟。访问目标用 **与 SPN 一致的 FQDN**，不要用 IP。

```bash
export KRB5CCNAME=/home/kali/lab/tickets/current.ccache
klist -e
sudo ntpdate dc01.corp.example

smbclient -k -L //ws02.corp.example
impacket-wmiexec -k -no-pass CORP.EXAMPLE/USER@ws02.corp.example
```

`KRB_AP_ERR_MODIFIED` 多半是 SPN / 加密类型 / 主机名不一致，不是「网络不通」。切换票据必须重新 `export KRB5CCNAME` 并立刻 `klist`。

kirbi（Rubeus 输出）和 ccache 之间要转换格式。工具用 Impacket 自带的转换或 `ticketConverter.py`，以你安装的版本为准。

## LAPS

当前用户对计算机对象的 `ms-Mcs-AdmPwd` 有读权限时，可能直接得到本地管理员密码。这是 ACL 问题。

```bash
# 概念：LDAP 读属性。具体过滤器按环境改。
ldapsearch -H ldap://dc01.corp.example -D 'USER@corp.example' -w 'PASS' \
  -b 'dc=corp,dc=example' 'ms-Mcs-AdmPwd=*' ms-Mcs-AdmPwd
```

读到密码后，用它做的是**该机本地管理员**操作，不是域管。

## 委派

| 类型 | 你需要的 | 得到的 |
|---|---|---|
| 非约束委派 | 控制一台被标记 Unconstrained 的机器，并让高权账户向它认证 | 内存里可能出现对方 TGT |
| 约束委派 | 服务账户被允许向指定 SPN 做 S4U | 只能冒充用户访问那些 SPN |
| 基于资源的约束委派（RBCD） | 对目标计算机对象有写 `msDS-AllowedToActOnBehalfOfOtherIdentity` 的权限 | 让你控制的账户代表管理员访问该机 |

强制认证的公开手法（Printerbug / PetitPotam / coercer 等）只在授权范围且协议允许时使用。抓到票先 `klist` / 看缓存身份，再决定要不要 DCSync——DCSync 需要对应目录复制权限或足够的票据。

## 子域到林根

先画信任：方向、是否可传递、SID filtering / Extra SID 是否能用。不要假设「子域管理员等于林管」。命令仍是 Impacket / Rubeus / 票据操作，逻辑是信任模型。

## ADCS

公开参考：[Certified Pre-Owned](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)、[ly4k/Certipy](https://github.com/ly4k/Certipy)。

| 编号 | 前提（极简） |
|---|---|
| ESC1 | 低权用户可申请的模板允许 ENROLLEE_SUPPLIES_SUBJECT 等，能把别人（含高权）写进证书 |
| ESC8 | CA 的 Web Enrollment 可被 NTLM 中继 |

```bash
certipy find -u USER@corp.example -p 'PASS' -dc-ip DC_IP
```

没有可申请的脆弱模板时，再评估 Web Enrollment 中继，而不是反复改 ESC1 参数。中继同样受 SMB/HTTP 签名和授权范围约束。

## 失败分类

| 现象 | 先查 |
|---|---|
| 有票不能用 | FQDN、时钟、`KRB5CCNAME`、加密类型 |
| 委派抓不到票 | 对方没来认证；或来的不是你要的账户 |
| ESC1 申请被拒 | 模板权限、CA 权限、主题替代不被允许 |

## 防御侧

- 取消非约束委派；用 gMSA；收紧 RBCD 写权限
- LAPS ACL 最小；监控对 `ms-Mcs-AdmPwd` 的读取
- ADCS 模板审计；关 HTTP 注册或强制签名 / EPA
- 特权账户不上工作站；不能被普通服务器强制认证
