::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 00 · Lab environment

Shared attacker-box setup for every situation. Each module’s **Prepare** section assumes this is already done.

## Assumptions

| Role | System | Notes |
|---|---|---|
| Attacker | Kali (official exam image) | Listeners, builds, delivery, tunnels |
| Entry | Windows 10/11 + Office | Defender; maybe AppLocker / CLM / AMSI |
| Domain | AD DS (child domains, ADCS, MSSQL, IIS possible) | |
| Linux | Domain-joined or standalone | ELF, libraries, sudo, SSH reuse, Kerberos |
| Network | Segments, proxies, few egress paths | Direct, proxy, DNS, or domain fronting |

Keep the chain simple. The exam is not a modern EDR bake-off. A failed attempt is expensive.

## Directories

```bash
mkdir -p ~/osep/{payloads/{win/{x86,x64},linux,web},listeners,logs,loot,tools}
cd ~/osep
```

| Path | Contents |
|---|---|
| `payloads/win/x86`, `x64` | Keep architectures separate |
| `payloads/linux` | ELF, shared objects |
| `payloads/web` | Upload tests |
| `listeners` | Listener notes |
| `logs` | One log per entry |
| `loot` | Hashes, tickets, screenshots |
| `tools` | Trusted builds only |

Placeholders (do not invent a second set): `LHOST` `LPORT` `TARGET` `DOMAIN` `USER` `PASS` `NTHASH` `PAYLOAD` `URL`.

## Ports

| Port | Use |
|---|---|
| 80 | HTTP delivery |
| 443 | HTTPS delivery (record cert fingerprint) |
| 445 | SMB delivery |
| 8080 | Spare HTTP / SOCKS |
| 4444 | Reverse shell |
| 4445 | Second session |
| 11601 | Ligolo-ng proxy |
| 5985 | WinRM on the target |

```bash
cd ~/osep/payloads && python3 -m http.server 80 2>&1 | tee ~/osep/logs/http-80.log

openssl req -newkey rsa:2048 -nodes -keyout ~/osep/tools/key.pem \
  -x509 -days 365 -out ~/osep/tools/cert.pem -subj "/CN=LHOST"
openssl x509 -in ~/osep/tools/cert.pem -noout -fingerprint -sha256

impacket-smbserver share ~/osep/payloads -smb2support
rlwrap -cAr nc -lvnp 4444 | tee ~/osep/logs/shell-4444.log
```

Every entry: (1) delivery log has a request, (2) a harmless callback fired, (3) `whoami /priv` and bitness on a stable session.

## Payload shape

| Entry | First choice |
|---|---|
| Word | In-process VBA runner / PowerShell stager |
| HTA | HTA + PowerShell / embedded C# |
| JScript | DotNetToJScript + C# |
| ZIP | Proxy DLL beside the host |
| Trusted host | InstallUtil / Workflow / XSL |
| ASPX | Tiny page + managed load |
| Short RCE | Short downloader |
| Linux | Custom ELF / library |

Resolve bitness before you generate Windows payloads — see [01](/modules/01-word-vba-office). If unsure, prepare both. Staged payloads must share one proven path; see [09](/modules/09-c2-egress-channels).

## When nothing comes back

```
no result
├─ no request in the log     → delivery / user never opened
├─ request, no execution     → static detection → change host form
├─ runs and exits            → bitness / missing export
├─ runs and is killed        → behavior → change injection
├─ stage one only            → path / proxy mismatch
└─ session dies quickly      → host lifetime → migrate
```

Change one variable per try. Write down what you changed.

## Compilers

```bash
sudo apt install -y mingw-w64
x86_64-w64-mingw32-gcc -o payload-x64.exe payload.c -lws2_32 -s -O2
i686-w64-mingw32-gcc   -o payload-x86.exe payload.c -lws2_32 -s -O2
x86_64-w64-mingw32-gcc -shared -o proxy.dll proxy.c proxy.def -s
gcc -o loader loader.c -O2
gcc -shared -fPIC -o libpayload.so libpayload.c -O2
```

Prefer `csc.exe` on the target for .NET.

## Pace

Twenty to thirty minutes per entry: probe, deliver, verify, then switch. On every new session: identity, bitness, egress.
