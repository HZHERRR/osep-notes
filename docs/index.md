---
layout: home
hero:
  name: OSEP Notes
  text: 授权实验用的方法论笔记
  tagline: 命令、源码骨架、失败分支。仅限授权实验、官方考试环境与个人学习。
  actions:
    - theme: brand
      text: 现象定位
      link: /lab/exam-lookup
    - theme: alt
      text: 载荷与监听
      link: /lab/payloads
features:
  - title: 先判断，再动手
    details: 被拦时先分清是投递失败、静态特征、行为检测、位数不匹配，还是出网路径不一致。
  - title: 可复制的源码
    details: VBA / HTA / C# / PowerShell / ASPX 骨架和 Impacket、Ligolo、msfvenom 命令。自己替换 LHOST 后在 lab 里编译。
  - title: 学习用途
    details: 每页标注授权范围。不托管编译好的 exe/dll。禁止对未授权系统使用。
---

## 阅读顺序

1. [使用边界](/disclaimer)
2. [现象定位](/lab/exam-lookup) — 看到什么限制，打开哪一页
3. [载荷与监听](/lab/payloads) — msfvenom / 反向 shell / 下载器
4. [实验环境](/lab/environment)
5. 按主题复制源码：[Office 宏](/topics/office-macros) 起

与 OffSec / OSEP 考试**没有官方关系**。技术点来自公开资料与个人实验整理。
