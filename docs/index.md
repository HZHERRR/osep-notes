---
layout: home
hero:
  name: OSEP Notes
  text: 授权实验用的方法论笔记
  tagline: 判断场景、选择路线、使用公开工具。不含可执行 payload，不含考试或实验靶场答案。
  actions:
    - theme: brand
      text: 使用边界
      link: /disclaimer
    - theme: alt
      text: 从环境开始
      link: /lab/environment
features:
  - title: 先判断，再动手
    details: 被拦时先分清是投递失败、静态特征、行为检测、位数不匹配，还是出网路径不一致。
  - title: 公开工具命令
    details: Impacket、Ligolo、evil-winrm、ldapsearch、msfvenom 等常见工具的占位符模板。需要自己的实验环境去生成和验证。
  - title: 故意不托管的东西
    details: 不提供 webshell、shellcode runner、AMSI 绕过、C2 协议实现。这些应只存在于你自己的隔离实验网。
---

## 阅读顺序

1. [使用边界](/disclaimer) — 授权范围与本站不放什么
2. [怎么读这些笔记](/guide/how-to-read) — 占位符、页面结构
3. [实验环境](/lab/environment) — 攻击机目录、端口、编译链
4. 按主题看 [Office 宏](/topics/office-macros) 起的各篇

与 OffSec / OSEP 考试**没有官方关系**。技术点来自公开资料与个人实验整理。
