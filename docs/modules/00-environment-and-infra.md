::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 00 · Environment and infrastructure (shared by all modules)

> This document does not belong to any single scenario. It is the attacker-box preparation, payload matrix, listener/callback conventions, and decision flow shared by all 56 scenarios.
>
> Every module’s “Prepare (attacker side)” section assumes you have already stood up the infrastructure described here.

---

## 1. Environment assumptions

| Role | System | Notes |
|---|---|---|
| Attacker box | Kali Linux (official exam image) | All listeners, builds, delivery, and tunneling happen here |
| Entry target | Windows 10/11 + Office | Defender present; AppLocker / CLM / AMSI may be enabled |
| Domain environment | AD DS (child domains, ADCS, MSSQL, IIS possible) | Domain Admins, delegation, certificates, SQL service accounts, etc. |
| Linux target | Domain-joined or standalone | ELF execution, shared libraries, sudo, SSH reuse, Kerberos tickets |
| Network limits | Segmentation + proxies, maybe only a few egress paths allowed | Decides whether you go direct, through a proxy, over DNS, or with domain fronting |

**Core principle**: the techniques in this cheat sheet are “old, but they get through the exam environment.” The exam environment is not a modern EDR battlefield — do not complicate the chain chasing novelty. **The simpler it is, the more reliable it is, and one failed attempt costs an enormous amount of time.**

---

## 2. Attacker-box directories and naming conventions

```bash
mkdir -p ~/osep/{payloads/{win/{x86,x64},linux,web},listeners,logs,loot,tools}
cd ~/osep
```

| Directory | What goes in it |
|---|---|
| `payloads/win/x86`, `payloads/win/x64` | Windows payloads split by architecture (**never mix them**) |
| `payloads/linux` | ELF, shared libraries, encoded loaders |
| `payloads/web` | ASPX/JSP/PHP shells, uploaded files |
| `listeners` | Listener scripts, listener command notes |
| `logs` | One log file per entry, to confirm callbacks and troubleshoot |
| `loot` | Hashes, tickets, credentials, screenshots |
| `tools` | Build outputs and third-party tools (trusted sources only) |

**Unified placeholders** (consistent across the whole project; do not invent your own):

| Placeholder | Meaning |
|---|---|
| `LHOST` | Attacker-box IP reachable from the target |
| `LPORT` | Listening port |
| `TARGET` | Target IP / hostname |
| `DOMAIN` | AD domain name |
| `USER` / `PASS` / `NTHASH` | Credentials |
| `PAYLOAD` | Payload file name |
| `URL` | Our HTTP(S) address |

---

## 3. Ports and infrastructure planning

Fix one port set so you do not mix them up during the exam:

| Port | Use |
|---|---|
| 80 | HTTP delivery (python3 -m http.server / nginx) |
| 443 | HTTPS delivery (self-signed cert, record the fingerprint) |
| 445 | SMB delivery (impacket-smbserver / with Responder stopped) |
| 8080 | Spare HTTP / SOCKS front end |
| 4444 | General-purpose reverse shell listener |
| 4445 | Spare listener (second session) |
| 11601 | Ligolo-ng proxy |
| 5985 | WinRM (target side) |

```bash
# HTTP delivery + request log (confirm the target really downloaded it)
cd ~/osep/payloads && python3 -m http.server 80 2>&1 | tee ~/osep/logs/http-80.log

# HTTPS delivery
openssl req -newkey rsa:2048 -nodes -keyout ~/osep/tools/key.pem \
  -x509 -days 365 -out ~/osep/tools/cert.pem -subj "/CN=LHOST"
# Note the fingerprint; use it on the target side if the cert must be trusted
openssl x509 -in ~/osep/tools/cert.pem -noout -fingerprint -sha256

# SMB delivery (temporary share, no authentication required)
impacket-smbserver share ~/osep/payloads -smb2support

# Listener with readline (strongly recommended — fewer broken keystrokes in the exam)
rlwrap -cAr nc -lvnp 4444 | tee ~/osep/logs/shell-4444.log
```

**Callback verification, three checks** (do them for every entry):

1. Did the target hit the delivery address → check the HTTP/SMB log
2. Did the payload actually execute → prove it first with a harmless callback (`curl`/`nslookup`/writing a file)
3. Is the session stable → immediately run `whoami /priv`, `systeminfo`, and confirm architecture and user

---

## 4. Payload matrix (pick the shape by entry type)

| Entry | First choice | Needs egress | Notes |
|---|---|---|---|
| Word macro | VBA in-process Runner / PowerShell stager | Depends on scenario | Probe bitness first when unknown |
| HTA | HTA + PowerShell / embedded C# | Depends on scenario | Prefer a non-EXE form under AppLocker |
| JScript | DotNetToJScript + C# stage 2 | Depends on scenario | WSH host; AMSI handling must be done separately |
| Mail ZIP | Proxy DLL + sideload host | No | Keep the host running normally |
| Mail / web | InstallUtil / Workflow / XSL | No | Trusted host, bypasses AppLocker |
| Web (ASPX) | Minimal ASPX + managed load | Yes | Service account; watch AV detection |
| Web (command injection) | Short command + downloader fallback | Yes | Watch the length limit |
| Linux | Custom ELF / shared library | Depends on scenario | Keep the business output and lifetime |

**Bitness rule**: pin down the target’s architecture before generating any Windows payload. Probing methods are in [01-word-vba-office](/modules/01-word-vba-office) scenario 1; when you are unsure, **prepare both** and select with branching logic.

**Staged vs stageless**: every stage must travel **the same verified-reachable communication path**. If stage one gets through but stage two does not, 90% of the time it is a mismatched address/port/protocol or a different proxy context (see [09-c2-egress-channels](/modules/09-c2-egress-channels)).

---

## 5. Triage order when you are blocked (general decision tree)

```
No reaction from the payload
├─ no request in the delivery log → delivery blocked / user never opened → change delivery method (HTTP→SMB→mail attachment)
├─ request seen, no execution     → payload killed statically → encode/encrypt/change the host form (module M05)
├─ executed, then exited at once  → bitness mismatch / missing dependency / export mismatch (M01, M04)
├─ executed, then terminated      → behavior detection → switch to in-process / cross-process implementation (M05 scenario 19)
├─ stage one up, stage two not    → communication path / proxy context mismatch (M09)
└─ session up, then drops quickly → host lifetime problem → migrate / persist (M01 scenario 5)
```

**Troubleshooting discipline**: change one variable at a time; after every change, write down “what I changed and what the result was.” The exam scores the process, not luck.

---

## 6. Build environment preparation (Kali side)

```bash
# Windows cross-compilation (x64 / x86)
sudo apt install -y mingw-w64
x86_64-w64-mingw32-gcc -o payload-x64.exe payload.c -lws2_32 -s -O2
i686-w64-mingw32-gcc   -o payload-x86.exe payload.c -lws2_32 -s -O2

# Shared library / Proxy DLL
x86_64-w64-mingw32-gcc -shared -o proxy.dll proxy.c proxy.def -s
x86_64-w64-mingw32-g++ -shared -o proxy.dll proxy.cpp proxy.def -s

# Linux side
gcc -o loader loader.c -O2
gcc -shared -fPIC -o libpayload.so libpayload.c -O2
```

Compile .NET assemblies with the `csc.exe` already present on the target (more reliable in the exam environment than installing Mono), or pre-compile on your own box with `mcs`/`dotnet` and deliver only the assembly.

---

## 8. Related docs

| Doc | Contents |
|---|---|
| [01-word-vba-office](/modules/01-word-vba-office) | Word/VBA entry, bitness probing, Runner |
| [02-hta](/modules/02-hta) | HTA entry and AppLocker/CLM/AMSI combinations |
| [05-applocker-clm-amsi](/modules/05-applocker-clm-amsi) | AV evasion and trusted hosts |
| [09-c2-egress-channels](/modules/09-c2-egress-channels) | Egress channels: proxy, DNS, domain fronting, staging |
| [99-pre-exam-checklist](/modules/99-pre-exam-checklist) | Pre-exam item-by-item checklist |
