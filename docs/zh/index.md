---
layout: home
title: OSEP 笔记
titleTemplate: 实战行动手册

hero:
  name: OSEP / FIELD MANUAL
  text: 受限环境下的技术行动手册
  tagline: 面向授权 OSEP 环境，以场景组织执行、提权、横向移动与证据记录。
  actions:
    - theme: brand
      text: 打开场景清单
      link: /zh/scenarios
    - theme: alt
      text: 建立实验基线
      link: /zh/modules/00-environment-and-infra

features:
  - title: M01–M05 · 执行约束
    details: Office、HTA、JScript、DLL 旁加载、AppLocker、CLM 与 AMSI 路径。
    link: /zh/modules/01-word-vba-office
    linkText: 从执行阶段开始
  - title: M06–M15 · 身份与移动
    details: 提权、凭据、出网、隧道、服务、目录攻击、Linux 与横向访问。
    link: /zh/modules/06-uac-windows-privesc
    linkText: 追踪攻击路径
  - title: M97–M99 · 考试行动
    details: 考场定位、证据记录模板和考前状态检查。
    link: /zh/modules/97-exam-day-lookup
    linkText: 打开考试参考
---

<div class="home-workflow" aria-label="行动循环">
  <p>OPERATING LOOP</p>
  <ol>
    <li><strong>01</strong><span>观察当前约束</span></li>
    <li><strong>02</strong><span>验证可达路径</span></li>
    <li><strong>03</strong><span>每次只改变一个变量</span></li>
    <li><strong>04</strong><span>记录可复核证据</span></li>
  </ol>
</div>

## 从条件出发，而不是从工具出发

每个模块都围绕明确的实战条件组织。先确认可以观察到的路径，执行最小且可回退的测试，并在改变下一个变量之前保存结果。

> **仅限授权使用。** 这些笔记仅适用于 OSEP 官方实验与考试环境、你自己的隔离实验室，或已获得书面授权的系统。
