# Scope & Course Guidelines (PEN-300 / OSEP)

::: warning Authorized use only (PEN-300 Chapter 1 Copyright)
The technical notes, command templates, and lab scripts on this site are strictly for the **isolated OffSec hosted VPN lab environment (PEN-300 Labs)**, the **official OSEP certification exam**, your own isolated local lab, or penetration tests covered by explicit **written authorization (Rules of Engagement)**. Attempting any technique described here against systems you do not own or lack explicit permission to test — even “just to run a single probe command” — is illegal. OffSec and the author disclaim all liability for unauthorized actions.
:::

## 1. Course Positioning: Advanced Penetration Testing vs. Red Teaming (PEN-300 §2.1)

Per `pen-300.pdf` Section 2.1 (*About The PEN-300 Course*), keep the following operational boundary clear before using these modules:

| Dimension | Advanced Penetration Testing (PEN-300 Scope) | Red Teaming / Adversary Simulation (Out of Scope) |
|---|---|---|
| **Primary Goal** | Test the security of a client organization’s **IT infrastructure** (hardened endpoints, production servers, and Active Directory) and compromise internal systems | Test and train the client organization’s human security personnel (**Blue Team**) on detection, alerting, and incident response |
| **Technical Focus** | **Bypassing automated security mechanisms** (client-side execution controls, antivirus, application whitelisting / AppLocker / CLM, AMSI, network filters, and web proxies) | Mimicking advanced adversary TTPs while actively evading live human blue-team monitoring and forensic investigation |
| **Entry Models** | **External Penetration Test**: breach the perimeter via social engineering / client-side vectors (Office macros, HTA, JScript, ICS calendar invites, ZIP sideloading) or internet-facing web apps;<br>**Assumed Breach**: start from standard/low-privileged internal access and focus on lateral movement and domain compromise | Multi-month stealth campaigns often combining physical, supply-chain, or long-haul C2 operations |

> **Bottom line**: PEN-300 (*Evasion Techniques and Breaching Defenses*) builds on PEN-200 (OSCP) to teach **advanced penetration testing against mature organizations — it is not a Red Team course**. In the labs and exam, prioritize simple, reliable chains that defeat automated defenses rather than over-engineering for live EDR/blue-team evasion.

---

## 2. Permitted Scope & Academic Integrity (PEN-300 §1 & §2.2.3)

### Allowed

- **OffSec’s official VPN lab and exam networks**: isolated environments accessed via your personal VPN connectivity pack under OffSec’s terms and agreement.
- **Your own isolated lab**: local virtual machines (VMware, VirtualBox, etc.) segregated from production networks and the public Internet.
- **Authorized penetration tests**: engagements governed by a signed statement of work and written Rules of Engagement (RoE).

### Not Allowed

- **Any unauthorized host or network**: never run reconnaissance, delivery, or exploitation commands against targets without explicit written permission.
- **Breaching OffSec Copyright & Academic Policy**:
  - Do not copy, redistribute, publish, or commercially exploit `pen-300.pdf` course publications or videos;
  - Do not post complete lab or exam solutions (“spoilers”) or flags on public repositories, blogs, forums, or social media;
  - As stated in `pen-300.pdf` Chapter 1, violating OffSec’s Academic Policy ([https://www.offsec.com/legal-docs/](https://www.offsec.com/legal-docs/)) can result in **revocation of all existing OffSec certifications and a lifetime ban from OffSec courses, exams, and purchases**.

---

## 3. PEN-300 VPN Lab Mechanics & Restrictions (PEN-300 §2.4)

### 3.1 Dedicated VMs & Module Switching (§2.4.1–§2.4.4)

- **Dedicated Per-Student Environment**: Every virtual machine in the PEN-300 labs is **assigned exclusively to you** and is not shared with other students. The lab contains two machine sets:
  1. **Module VMs**: dedicated client targets paired with each course chapter and exercise (running modern OSes such as Windows 10, Windows Server 2019, and Ubuntu 20.04);
  2. **Challenge Labs**: multi-host black-box penetration testing simulations unlocked after completing the course modules (**no credentials are provided**).
- **Single Active Module Rule**: You cannot have client machines from multiple modules active simultaneously. Selecting a new module in the Control Panel automatically removes the active client machines from the previous module.
- **Kali VM Baseline (§2.4.4)**: Course materials assume the latest stable **64-bit Kali Linux build** (VMware officially supported by Student Administrators) running commands as a **non-root user**. When copy-pasting code snippets from the PDF book modules, watch for unintended whitespace or line breaks introduced by PDF formatting (§2.3.2).

### 3.2 Revert Rules (§2.4.2)

- **Daily Quota & Cooldown**: Each student receives **12 reverts every 24 hours**, resetting daily at **00:00 GMT+0**, with a **minimum 5-minute cooldown** between reverts (contact Live Support / Student Administrators if you need your counter reset).
- **Full-Group Reverts Only**: You **cannot revert a single virtual machine** in isolation. Triggering a revert resets **all virtual machines associated with that module or challenge** to maintain Active Directory stability (which can take several minutes on larger AD modules).
- **Extended VPN Disconnection**: Disconnecting from the VPN for an extended period automatically removes your active VMs, requiring a fresh revert when you reconnect. **Always copy developed scripts, loot, and notes back to your Kali VM before disconnecting from the VPN.**

### 3.3 Lab Behavior and Lab Restrictions (PEN-300 §2.4.5)

::: danger Strictly Enforced Lab Restrictions (Violations May Disable Lab Access)
OffSec strictly enforces the following rules inside the internal VPN lab network:
1. **Do not ARP spoof or conduct any other type of poisoning or man-in-the-middle (MITM) attacks** against the network (when using Responder or `ntlmrelayx` in Calendar M16 or MSSQL M11 scenarios, only capture or relay directed authentication explicitly triggered toward your Kali IP — never run active ARP/DNS/LLMNR/NBT-NS poisoning across the subnet).
2. **Do not perform brute-force attacks** against the VPN infrastructure.
3. **Do not attempt to hack into other students’ clients or Kali machines**.
:::

---

## 4. OSEP Exam Rules & Tool Boundaries (PEN-300 §2.5 & Exam Guide)

### 4.1 Exam Window & Passing Criteria (§2.5)

| Item | Official Requirement (verify against the latest [OSEP Exam Guide](https://help.offsec.com/hc/en-us/articles/360050293792-OSEP-Exam-Guide) on exam day) |
|---|---|
| **Pre-Exam Check-In** | Log in **15 minutes before** your scheduled start time for proctoring identity verification and VPN pack download |
| **Lab Duration** | **47 hours and 45 minutes** in a dedicated, remotely proctored enterprise network environment |
| **Report Window** | **24 additional hours** after the exam lab ends to compile and submit your penetration test report |
| **Passing Criteria** | Compromise the designated target section of the network, **or** earn at least **100 points** by compromising individual hosts (PEN-300 §2.5) |
| **Grading Turnaround** | Results are delivered within **10 business days** after report acceptance |

### 4.2 Permitted vs. Prohibited Tools (OSEP Exam Guide — not in `pen-300.pdf`)

`pen-300.pdf` does not list exam-permitted tools. The boundary below comes from the OSEP Exam Guide; the current guide is the authority, so re-check it before exam day.

- **Permitted**: standard open-source offensive tooling (Kali packages, Impacket, Mimikatz, Rubeus, Certipy, Chisel, Ligolo-ng, NetExec, evil-winrm, Metasploit Framework Community) and your own custom or modified C / C# / PowerShell / JScript / VBA code.
- **Prohibited**: commercial or automated exploitation platforms (`Cobalt Strike`, `Metasploit Pro`, etc.), network spoofing/poisoning (`ARP`/`DNS`/`NBNS`/`IP`), and interactive AI chatbots.

### 4.3 Evidence & Report Reproducibility

- **Proof files**: the exam guide defines the per-host proof-file names (`local.txt` for a low-privilege foothold, `proof.txt` for elevated `SYSTEM` / `root` / local Administrator) and the final objective. Confirm the exact filenames in the current guide; they are not specified in `pen-300.pdf`.
- **Same-Terminal Screenshots**: Every flag screenshot must show both the target’s IP configuration (`ipconfig` on Windows, `ifconfig` or `ip addr` on Linux) and the raw flag file contents (`type` or `cat` with full path) in the **same terminal window** without cropping out context.
- **Reproducibility**: Grading evaluates the quality, accuracy, and reproducibility of your documentation. Include full command lines, modified source code, and step-by-step outputs for every compromised host.

---

## 5. Troubleshooting Discipline & Unified Placeholders

### Operational Discipline

1. **Confirm delivery logs before blaming AV**: When a payload fails to call back, check your HTTP / SMB delivery logs first to separate “file was never requested or opened” from “payload was blocked statically or behaviorally.”
2. **Probe bitness and defenses before delivering live payloads**: Before generating Windows payloads, confirm host process architecture (x86 vs. x64), PowerShell language mode (`FullLanguage` vs. `ConstrainedLanguage`), effective AppLocker rules, and egress path (direct, corporate proxy, or DNS).
3. **Change one variable at a time**: Every stage of a multi-stage payload must travel over the **same verified communication path**. Change one variable per attempt, log the outcome, and switch to an alternate branch if a vector stalls for more than 30 minutes (see [00-environment-and-infra](/modules/00-environment-and-infra) and [97-exam-day-lookup](/modules/97-exam-day-lookup)).

### Unified Placeholders (Shared Across All 20 Modules)

All documentation pages and embedded scripts use the following 9 placeholders — substitute them before running or compiling:

| Placeholder | Meaning | Example |
|---|---|---|
| `LHOST` | Attacker IP (or pivot listener IP) reachable from the target | `192.168.45.172` |
| `LPORT` | Listening port on the attacker box or pivot | `443` / `4444` |
| `TARGET` | Target IP address or FQDN hostname (Kerberos requires FQDN) | `192.168.152.150` / `dc01.corp.local` |
| `DOMAIN` | Active Directory domain FQDN | `corp.local` |
| `USER` | Authentication username (local or domain account) | `offsec` / `sqlsvc` |
| `PASS` | Cleartext password | `Password123!` |
| `NTHASH` | NTLM hash (32-char hex for Pass-the-Hash / ticket requests) | `8846f7eaee8fb117ad06bdd830b7586c` |
| `PAYLOAD` | Payload filename delivered or dropped on target | `runner.exe` / `stage2.ps1` |
| `URL` | Full HTTP(S) delivery URL on our server | `http://192.168.45.172/stage2.ps1` |
