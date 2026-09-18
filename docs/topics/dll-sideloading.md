# DLL 旁加载

::: warning 仅供学习 / 授权实验
先做只转发、DllMain 打日志的对照包，确认宿主不崩，再考虑实验载荷。
:::

宿主用裸名加载同目录 DLL 时，搜索顺序第一项就是 EXE 所在目录。

## 锁定宿主

```bash
file Host.exe                    # PE32 vs PE32+
x86_64-w64-mingw32-objdump -p original.dll | less
```

Windows：

```cmd
dumpbin /headers Host.exe
dumpbin /exports original.dll
```

ProcMon：进程名 = Host.exe，操作 = Load Image，路径在宿主目录而不是 System32。

## 生成 .def

```bash
printf 'EXPORTS\n' > forward.def
x86_64-w64-mingw32-objdump -p original.dll \
  | sed -n '/Export Name Pointer Table/,/Ordinal Hint Table/p' \
  | grep -o '"[^"]*"' | tr -d '"' \
  | sed 's/.*/& = original.&/' >> forward.def
```

```text
EXPORTS
  Foo = original.Foo
  Bar = original.Bar
```

## Proxy 骨架（DllMain 里只打日志 / 可换成实验逻辑）

```c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        /* 对照：MessageBoxA(NULL, "loaded", "lab", 0); */
        /* 实验：CreateThread(... runner ...); */
    }
    return TRUE;
}
```

```bash
# 先把原 DLL 改名为 original.dll
x86_64-w64-mingw32-gcc -shared -O2 -o legit.dll proxy.c forward.def -s
# 目录包：
#   Host.exe     原版
#   legit.dll    你的 proxy（文件名 = 宿主加载名）
#   original.dll 改名后的原 DLL
```

x86 宿主用 `i686-w64-mingw32-gcc`。缺导出或位数错 = 闪退。

## 失败

| 现象 | 查 |
|---|---|
| 立刻闪退 | 导出、位数、调用约定 |
| 宿主正常无副作用 | DLL 没从该目录加载 |
| 无害 proxy 正常、带逻辑被删 | 静态特征 |
