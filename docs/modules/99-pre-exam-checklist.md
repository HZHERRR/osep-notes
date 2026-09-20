::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 99 · Pre-exam checklist (assets, scenario by scenario)

> How to use it: in the 48–72 hours before the exam, **actually build and verify each item below once**, then tick it off.
>
> Principle: there is no time in the exam environment to compile and debug on the spot — **every asset must be in a “change one IP and it runs” state**.
>
> The scenario numbers match [the scenario map](/scenarios); the module docs live under `docs/`.

---

## A. Shared infrastructure (do these 10 first)

- [ ] Attacker-box directories created: `~/osep/{payloads,listeners,logs,loot,tools}`
- [ ] HTTP delivery working (80/443), with a **visible request log**
- [ ] HTTPS delivery certificate generated, **fingerprint recorded**
- [ ] SMB delivery working (`impacket-smbserver`)
- [ ] Listeners wrapped in `rlwrap`, session output written to disk under `~/osep/logs/`
- [ ] mingw-w64 cross-compile verified (build one hello for x64 and one for x86)
- [ ] Linux build environment verified (executable + `-shared -fPIC`)
- [ ] Harmless callback payloads tested (`curl` / `nslookup` / write-file, all three)
- [ ] Bitness probe payload tested (see M01 scenario 1)
- [ ] Egress probe commands ready (direct / proxy / DNS, all three)

---

## B. Entry stage (scenarios 1–17)

- [ ] **Scenario 1** Word macro: harmless callback macro + bitness-detection macro + one x86 and one x64 runner ([01-word-vba-office](/modules/01-word-vba-office))
- [ ] **Scenario 2** Execute inside the macro: a VBA version that does not rely on a PowerShell child process, built and tested
- [ ] **Scenario 3** PS stage 2 blocked by AMSI: an AMSI-handling build matched to the PowerShell host + a short-macro stage 1
- [ ] **Scenario 4** Add-Type blocked: two tracks — reflective runner (load a precompiled assembly in memory) + precompiled C#
- [ ] **Scenario 5** Lost when the document closes: an execution build that outlives the document + a migration plan table by user/bitness/privilege
- [ ] **Scenario 6** No Office + AppLocker: HTA stage 1 + InstallUtil assembly (one x86, one x64)
- [ ] **Scenario 7** HTA + AppLocker + CLM + AMSI: the full combined chain verified end to end (not components in isolation)
- [ ] **Scenario 8** HTA download and execute split: a two-stage build + a single-file build with completion confirmation
- [ ] **Scenario 9** JScript: DotNetToJScript bridge + the C# stage 2 it loads
- [ ] **Scenario 10** JScript blocked by AMSI: an AMSI experiment build specific to the WSH host + a split stage-2 structure
- [ ] **Scenario 11** ZIP + DLL sideloading: a proxy DLL package verified against the host version (directory layout + architecture match)
- [ ] **Scenario 12** Proxy DLL crashes the host: how to triage the export table/calling convention + a proxy DLL that keeps the host running
- [ ] **Scenario 13** ICS invite: invite template + authentication receiver + follow-up commands
- [ ] **Scenario 14** ASPX entry: trimmed ASPX + managed-loading build + a stage 2 you can swap independently
- [ ] **Scenario 15** Downloader blocked: fallback command matrix for curl / certutil / bitsadmin / PowerShell
- [ ] **Scenario 16** Command length limited: short stage 1 + split download-and-execute + an encoded-parameter build
- [ ] **Scenario 17** No stable egress: one embedded-stage-2 build each for VBA / C# / JScript

---

## C. Payloads and evasion (scenarios 18–24)

- [ ] **Scenario 18** EXE deleted the moment it lands: a method to locate the static signature + encoded/encrypted builds + a custom C# runner
- [ ] **Scenario 19** Killed at the execution stage: one comparison sample each for in-process / cross-process / process hollowing
- [ ] **Scenario 20** Managed tool cannot land on disk: assembly loader + entry-point/argument/dependency adaptation
- [ ] **Scenario 21** AppLocker directory rules: effective-rule enumeration + a plan to execute from a writable allowed path
- [ ] **Scenario 22** EXE strict / DLL lax: a DLL payload for the specified host
- [ ] **Scenario 23** InstallUtil blocked: Workflow Compiler input file + assembly
- [ ] **Scenario 24** Normal scripts restricted: XSL execution file + invocation template

---

## D. Privilege escalation and credentials (scenarios 25–27, 46)

- [ ] **Scenario 25** Admin with a normal token: Fodhelper payload + command template + notes on applicable OS/UAC settings
- [ ] **Scenario 26** SeImpersonate: a token-impersonation tool compatible with the lab systems + the EXE/command payload it needs
- [ ] **Scenario 27** Service binary hijacking: service-type + command-type payloads + commands to **save/restore the original config**
- [ ] **Scenario 46** LSASS protected: alternative credential commands grouped by source (LSA Secrets / SAM / DPAPI / config) + how the tool is loaded

---

## E. Comms and tunneling (scenarios 28–35)

- [ ] **Scenario 28** Corporate proxy only: an HTTP(S) payload/downloader that uses the system proxy + a proxy-authenticated build
- [ ] **Scenario 29** Lost after SYSTEM: a comms build verified separately in user context and in SYSTEM context
- [ ] **Scenario 30** Stage 2 never appears: both staged and stageless forms, with the same path across all stages
- [ ] **Scenario 31** HTTPS inspection: an HTTPS setup with configurable certificate/headers/User-Agent
- [ ] **Scenario 32** DNS channel: client + server configuration
- [ ] **Scenario 33** Domain fronting: split front-end/back-end configuration (depends on the specific service supporting it)
- [ ] **Scenario 34** Restricted internal access: a port-forward template reached from the pivot + a payload matching the callback path
- [ ] **Scenario 35** Target cannot call back out: listener/forward configuration at a location the target can reach + an address-parameter template

---

## F. Linux (scenarios 36–40, 48)

- [ ] **Scenario 36** ELF business-logic inspection: a payload matched to the architecture and runtime libraries that keeps its output and lifetime
- [ ] **Scenario 37** Linux AV: custom ELF / loaded build
- [ ] **Scenario 38** Shared library loading: two shared-library payloads, one for LD_LIBRARY_PATH and one for LD_PRELOAD
- [ ] **Scenario 39** sudo on a single program: notes on the exact commands and parameter limits for vim / find / lua
- [ ] **Scenario 40** Artifact replacement: a replacement artifact matching the downstream architecture/filename/business behavior + a packaging template
- [ ] **Scenario 48** SSH reuse: connection commands for both the ControlMaster socket and agent forwarding + the next-hop payload

---

## G. Miscellaneous entry points and special cases (scenarios 41–43, 56)

- [ ] **Scenario 41** Kiosk: notes on breaking out + the payload to run once you get execution
- [ ] **Scenario 42** JEA file copy: DLL payload + JEA file-operation template (must satisfy the service-load and trigger conditions at the same time)
- [ ] **Scenario 43** JIT temporary admin: query authorization state + update authentication state + in-window commands
- [ ] **Scenario 56** WinRM only: authentication templates for all three of password / hash / Kerberos + how to drop a payload inside the session

---

## H. MSSQL and AD (scenarios 44–45, 47, 49–55)

- [ ] **Scenario 44** Low-privilege SQL auth trigger: trigger authentication + relay command template + the payload once you have execution rights
- [ ] **Scenario 45** Linked Server: single-hop/multi-hop query and execution templates + short payloads and escaping
- [ ] **Scenario 47** Domain-joined Linux tickets: format conversion + Kerberos authentication + proxy and domain configuration
- [ ] **Scenario 49** LAPS read: a query method matched to the target’s LAPS implementation + remote execution template
- [ ] **Scenario 50** Unconstrained delegation: trigger authentication + ticket handling + follow-up authentication commands
- [ ] **Scenario 51** RBCD: RBCD configuration + service ticket + parameterized commands to access the target service
- [ ] **Scenario 52** Constrained delegation: protocol-transition conditions + target SPN + ticket-use template
- [ ] **Scenario 53** Child domain to forest root: trust-relationship triage + Extra SID + cross-domain authentication commands
- [ ] **Scenario 54** ESC1: template enumeration + certificate request + format conversion + certificate authentication
- [ ] **Scenario 55** ESC8: relay configuration + certificate authentication template

---

## I. Three things to do in every session during the exam

```text
1. whoami /priv         → identity and available privileges (decides the privesc route)
2. systeminfo           → bitness, version, patches (decides payload form)
3. egress probe         → direct / proxy / DNS (decides the C2 channel)
```

Verify credentials the moment you get them:

```text
netexec smb TARGET -u USER -p PASS -d DOMAIN        # is the credential valid, which hosts can it reach
netexec winrm TARGET -u USER -p PASS -d DOMAIN      # is WinRM the only way in
```

---

## J. Troubleshooting discipline when it fails

1. **Change one variable at a time**, then verify and log it immediately.
2. Confirm “did the delivery succeed” first, and only then suspect “was the payload flagged”.
3. Stage 1 and stage 2 must take the same path; a mismatch is the most common silent failure.
4. User context works but SYSTEM does not = a proxy/authentication context problem, not a network problem.
5. Do not assume LSASS protection can be bypassed without verifying it — switch credential source instead.
