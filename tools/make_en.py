#!/usr/bin/env python3
"""Copy zh modules to English locale with label/phrase translation outside fences."""
from __future__ import annotations

import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ZH_MOD = ROOT / "docs" / "zh" / "modules"
EN_MOD = ROOT / "docs" / "modules"

# Longest first
PAIRS = [
    ("""::: warning 仅限授权使用
本笔记仅用于 OSEP 官方实验 / 考试环境，或已获得书面授权的测试。禁止对未授权系统使用。
:::""",
     """::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::"""),
    ("# 模块 M01：Word / VBA 宏入口与载荷形态", "# Module 01 — Word / VBA"),
    ("# 模块 M02：HTA 入口（邮件无 Office 宏时的第一阶段）", "# Module 02 — HTA"),
    ("# 模块 M03：JScript / DotNetToJScript 客户端代码执行", "# Module 03 — JScript / .NET"),
    ("# 04 · DLL 旁加载（DLL Sideloading）", "# Module 04 — DLL sideloading"),
    ("# 模块 M05：", "# Module 05 — "),
    ("# 06 · UAC Bypass & Windows 本地提权（场景 25–27）", "# Module 06 — Windows privilege escalation"),
    ("# 07 · 凭据获取：LSASS / LSA / SAM 与替代来源（场景 46）", "# Module 07 — Credentials"),
    ("# 08 · 隧道与端口转发（Pivoting & Tunneling）", "# Module 08 — Pivoting"),
    ("# 09 ·", "# Module 09 —"),
    ("# 模块 M11：MSSQL", "# Module 11 — MSSQL"),
    ("# 12 · AD 攻击：", "# Module 12 — AD: "),
    ("# 13 · Linux 攻击面", "# Module 13 — Linux"),
    ("# 14 · 场景 41–43：Kiosk 突破 · JEA 越权文件复制 · JIT 时间窗", "# Module 14 — Kiosk / JEA / JIT"),
    ("# 模块 M15：WinRM 横移（凭据有效 · 仅 WinRM 开放）", "# Module 15 — WinRM"),
    ("# 16 · ICS 日历邀请触发认证（场景 13）", "# Module 16 — Calendar invites"),
    ("# 模块 M10：", "# Module 10 — "),
    ("**失败分支与备选**", "**If it fails**"),
    ("**考试注意 / OPSEC**", "**Exam notes / OPSEC**"),
    ("**考试注意 OPSEC**", "**Exam notes / OPSEC**"),
    ("**准备（攻击机侧）**", "**Prepare (attacker)**"),
    ("**前提与假设**", "**Assumptions**"),
    ("**场景回顾**", "**Situation**"),
    ("**执行步骤**", "**Procedure**"),
    ("**用到的脚本**", "**Lab files**"),
    ("**本模块的共同原则**", "**Rules for this module**"),
    ("本页其余实验文件", "Other lab files on this page"),
    ("覆盖场景", "Covers scenarios"),
    ("教材依据", "Course mapping"),
    ("前置依赖", "Prerequisites"),
    ("攻击机", "attacker box"),
    ("目标机", "target"),
    ("验证", "Verify"),
    ("## 场景", "## Scenario"),
    ("# 模块 ", "# Module "),
    ("先探测，再投递", "Probe first, deliver second"),
    ("宏里做的事越少越稳", "Keep the macro tiny"),
    ("失败时先分清是", "When it fails, first decide whether it is"),
    ("宏没跑", "the macro never ran"),
    ("宏跑了但下一步被拦", "the macro ran but the next stage was blocked"),
]


def translate_chunk(text: str) -> str:
    text = text.replace("/zh/modules/", "/modules/")
    for a, b in PAIRS:
        text = text.replace(a, b)
    return text


ABSTRACTS = {
    "01-word-vba-office.md": "Office macros. Probe with a harmless callback, learn bitness, then choose in-process VBA vs a PowerShell child. If Word closes the session, migrate.",
    "02-hta.md": "mshta.exe as a signed host when Office is missing. Split download and execute if a combined stager dies.",
    "03-jscript-dotnettojscript.md": "WSH is not a .NET process. Bridge with DotNetToJScript. Match host bitness.",
    "04-dll-sideloading.md": "Replace a private DLL next to a host EXE. Keep the export table. Confirm with ProcMon before you pack a ZIP.",
    "05-applocker-clm-amsi.md": "Enumerate AppLocker, language mode, and AMSI. Distinguish static delete vs behavioral kill. Use trusted hosts (InstallUtil, Workflow, XSL).",
    "06-uac-windows-privesc.md": "whoami /all first. Filtered admin token → UAC. SeImpersonate → potato family. Writable service → hijack.",
    "07-credentials-lsass.md": "If PPL or Credential Guard is on, skip LSASS and take SAM/LSA Secrets/GPP/config files.",
    "08-pivoting-tunneling.md": "Forward access is not a callback path. Put listeners on the pivot the target can reach.",
    "09-c2-egress-channels.md": "User vs SYSTEM proxy. Every stage of a staged payload uses the same proven path.",
    "10-web-entry-webshell.md": "Prove RCE with a tiny page. Swap downloaders when one is blocked. Watch command length.",
    "11-mssql.md": "Login is not xp_cmdshell. Impersonate, linked servers, or trigger outbound SMB auth.",
    "12-ad-attacks.md": "Tickets, LAPS, delegation, trusts, ADCS. Write down who the ticket is for before you run a tool.",
    "13-linux.md": "Wrappers, LD_PRELOAD, sudo/GTFOBins, artifact swap, SSH ControlMaster.",
    "14-kiosk-jea-jit.md": "Dialog escape, over-broad Copy-Item, short admin windows.",
    "15-winrm-lateral.md": "If 445 is closed, drop psexec. evil-winrm / netexec on 5985/5986.",
    "16-ics-calendar.md": "An invite is not an authentication. Log first, then capture or relay.",
}


def translate_file(src: Path) -> str:
    raw = src.read_text(encoding="utf-8")
    parts = re.split(r"(````+[^\n]*\n.*?````+)", raw, flags=re.S)
    out = []
    for i, part in enumerate(parts):
        if i % 2 == 1:
            out.append(part)  # keep code
        else:
            out.append(translate_chunk(part))
    return "".join(out)


def main() -> None:
    EN_MOD.mkdir(parents=True, exist_ok=True)
    skip = {
        "00-environment-and-infra.md",
        "97-exam-day-lookup.md",
        "98-exam-note-template.md",
        "99-pre-exam-checklist.md",
    }
    for md in sorted(ZH_MOD.glob("*.md")):
        if md.name in skip:
            continue
        dest = EN_MOD / md.name
        text = translate_file(md)
        abs_ = ABSTRACTS.get(md.name)
        if abs_:
            text = text.replace(
                "::: warning Authorized use only",
                "::: warning Authorized use only",
                1,
            )
            needle = ":::\n\n# "
            if needle in text:
                pre, rest = text.split(needle, 1)
                title, body = rest.split("\n", 1)
                text = (
                    pre
                    + needle
                    + title
                    + "\n\n"
                    + abs_
                    + "\n\nSwitch to **中文** in the header for the original full narrative. Lab listings on this page are complete.\n"
                    + body
                )
        dest.write_text(text, encoding="utf-8")
        print("en", dest.name)


if __name__ == "__main__":
    main()
