::: warning Authorized use only
:::

# 99 · Pre-exam list

Generate and **run** each item in the 48–72 hours before the exam. You will not have time to compile on the clock.

## Infrastructure

- [ ] `~/osep/{payloads,listeners,logs,loot,tools}`
- [ ] HTTP 80/443 with a visible request log
- [ ] TLS cert fingerprint recorded
- [ ] SMB delivery (`impacket-smbserver`)
- [ ] `rlwrap` listener logging to disk
- [ ] mingw-w64 hello for x64 and x86
- [ ] Linux `gcc` and `-shared -fPIC`
- [ ] Harmless callbacks: HTTP, DNS, write-file
- [ ] Bitness probe (module 01)
- [ ] Egress probes: direct, proxy, DNS

## Entry

- [ ] Word: callback + arch probe + x86/x64 runners
- [ ] In-process VBA (no `powershell.exe` child)
- [ ] AMSI-aware PowerShell stage
- [ ] Precompiled C# runner (no `Add-Type` temps)
- [ ] Migration plan when Word closes
- [ ] HTA + InstallUtil (x86/x64)
- [ ] Full HTA + CLM + AMSI chain, tested together
- [ ] HTA download and execute split
- [ ] JScript / DotNetToJScript
- [ ] Sideload ZIP: host + proxy + original DLL

Then walk [the scenario map](/scenarios) and tick anything you actually compiled.
