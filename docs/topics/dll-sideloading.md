# DLL 旁加载

当宏和脚本都不可用，但用户会解压并运行 ZIP 里的「正常程序」时，执行面往往是：**宿主用裸文件名加载同目录 DLL**。

这是 Windows 加载器行为，不是漏洞编号。

## 搜索顺序（SafeDllSearchMode 默认开）

宿主 EXE 目录 → System32 → 16 位 System → Windows 目录 → 当前目录 → `PATH`。

旁加载成立的前提：宿主用**裸名或相对路径**加载私有 DLL。若导入的是 System32 的绝对路径、或目标在 KnownDLLs 里，这条路不通。

旁加载 ≠ 劫持：前者替换的是「本来就该从宿主目录加载」的私有 DLL；后者是替换系统 DLL。实验里只讨论前者。

## 为什么会闪退

宿主导入表里有 `legit.dll!Foo`，加载器必须在你提供的 DLL 导出表里找到 `Foo`。缺导出、位数不对、调用约定不对，进程会直接起不来。

稳妥做法是 **Proxy DLL**：

1. 把原 DLL 改名（例如 `original.dll`）
2. 你的 DLL 占用原来的文件名
3. 用 `.def` 把每个导出写成 `Foo = original.Foo`
4. 你的代码只放在 `DllMain` 或单独线程，宿主功能靠转发保持

`.def` 静态转发能保住原函数名和调用约定，一般比手写每个函数更不容易崩。

```text
EXPORTS
  Foo = original.Foo
  Bar = original.Bar
```

从已有 DLL 列导出（Kali）：

```bash
x86_64-w64-mingw32-objdump -p original.dll
file original.dll    # PE32 vs PE32+
```

Windows 上用 `dumpbin /exports`、`dumpbin /headers`。

## 实验前锁定的三件事

1. **确切版本**：导出表随版本变，版本错就是闪退
2. **架构**：x86 宿主只能加载 x86 DLL
3. **ProcMon 证据**：过滤进程名 + `Load Image`，确认候选 DLL 的路径就在宿主目录，而不是 `C:\Windows\System32`

目录包形态（概念）：

```text
sideload/
  Host.exe          原版宿主，不要改
  legit.dll         你的 proxy（文件名 = 宿主加载名）
  original.dll      改名后的原 DLL
```

本站不提供带载荷的 proxy 源码。先做一个**只转发、DllMain 里只打日志**的对照版，确认宿主能正常工作，再考虑实验载荷。

## 失败分类

| 现象 | 先查 |
|---|---|
| 双击立即闪退 | 导出缺失、位数、`.def` 序号 |
| 宿主起来但没有任何副作用 | DLL 没被加载（绝对路径 / KnownDLLs）或你的代码没在加载时跑起来 |
| 无害 proxy 正常、带实验逻辑后被删 | 静态特征；问题在内容不在旁加载机制 |

## 防御侧

- 对应用程序目录做完整性控制；能签就签
- WDAC / 仅允许加载微软签名的 DLL
- 监控「非厂商目录出现与系统 DLL 同名的模块」以及进程加载路径异常
