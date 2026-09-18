# How to read

Each module is a chain of **situations**: the same attack path under a different constraint.

Inside a situation you will usually see:

1. **Situation** — what failed
2. **Assumptions** — what you already have
3. **Prepare (attacker)** — what to stage on Kali
4. **Procedure** — numbered steps
5. **Lab files** — copy-paste listings used in that step
6. **Verify** — how you know it worked
7. **If it fails** — the next branch
8. **Exam notes / OPSEC** — time and traces

Probe with a harmless callback before you send a real payload. Keep x86 and x64 apart. Every stage of a staged payload must use the **same** reachable path (address, port, protocol, proxy).
