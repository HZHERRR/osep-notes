# 练习清单

在隔离实验网里逐项练，而不是在公开站上准备「改 IP 就能用」的文件包。

## 基础设施

- [ ] 攻击机目录、HTTP/HTTPS/SMB 投递、请求日志可见
- [ ] `nc` / `rlwrap` 监听，输出落盘
- [ ] mingw-w64 能编 x86 与 x64 的无害 hello
- [ ] Linux `gcc` 能编可执行文件和 `-shared -fPIC`
- [ ] 无害回调：HTTP、DNS、写文件 三种都能在实验机上看到

## 入口（概念级）

- [ ] 能解释 Office 32/64 位与宏位数为何必须一致
- [ ] 能区分「宏能跑但起不了 PowerShell」和「宏根本没跑」
- [ ] 知道 `mshta` 为什么常被默认 AppLocker 规则放行
- [ ] 知道 WSH 不是 .NET 进程，跨运行时需要桥接类工具
- [ ] 能用 ProcMon 判断 DLL 是从宿主目录加载还是从 System32 加载
- [ ] 能解释 ICS 邀请「收到 ≠ 会认证」

## 执行限制

- [ ] 能用 `whoami /priv`、语言模式、AppLocker 有效规则做一次落地侦察
- [ ] 能分清静态删除和行为终止
- [ ] 知道 InstallUtil / Workflow Compiler / `wmic /format` 属于 LOLBAS 思路，而不是万能钥匙
- [ ] 不依赖网上复制的 AMSI 一句话（补丁会失效）；理解它扫描的是脚本引擎看到的内容

## 权限与凭据

- [ ] 能从完整性级别判断要不要做 UAC 相关实验
- [ ] 知道 `SeImpersonatePrivilege` 指向哪类公开工具家族
- [ ] LSASS 打不开时，能列出 SAM / LSA Secrets / 配置文件等替代来源
- [ ] 会看 `RunAsPPL`、`LsaCfgFlags`

## 网络

- [ ] 正向访问和目标主动回连是两条路
- [ ] Ligolo / SSH `-L` `-D` `-R` 各解决什么
- [ ] 用户会话与 SYSTEM 的代理可能不同
- [ ] 分阶段载荷必须共用已验证路径

## 域与 Linux

- [ ] `KRB5CCNAME`、时钟偏差、SPN 必须用 FQDN
- [ ] LAPS、非约束 / 约束 / 基于资源的约束委派、ADCS ESC1/ESC8 能各用一句话说清前提
- [ ] `sudo -l` + GTFOBins；`LD_PRELOAD` / `LD_LIBRARY_PATH` 的加载顺序
- [ ] SSH ControlMaster 套接字意味着什么
- [ ] 仅 5985 开放时，哪些基于 SMB 的横移可以直接放弃
