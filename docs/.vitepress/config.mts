import { defineConfig } from 'vitepress'

const base =
  process.env.VITEPRESS_BASE ||
  (process.env.GITHUB_ACTIONS ? '/osep-notes/' : '/')

export default defineConfig({
  title: 'OSEP Notes',
  description: '授权实验用的进攻性安全方法论笔记。不含可执行 payload，不含考试或实验靶场答案。',
  lang: 'zh-CN',
  base,
  cleanUrls: true,
  lastUpdated: true,
  themeConfig: {
    logo: undefined,
    nav: [
      { text: '开始', link: '/disclaimer' },
      { text: '方法', link: '/lab/environment' },
      { text: '主题', link: '/topics/office-macros' },
      { text: '参考', link: '/references' },
    ],
    sidebar: [
      {
        text: '开始',
        items: [
          { text: '使用边界', link: '/disclaimer' },
          { text: '怎么读这些笔记', link: '/guide/how-to-read' },
        ],
      },
      {
        text: '实验方法',
        items: [
          { text: '实验环境', link: '/lab/environment' },
          { text: '失败排查', link: '/lab/decision-tree' },
          { text: '记录模板', link: '/lab/notes-template' },
          { text: '练习清单', link: '/lab/prep-checklist' },
        ],
      },
      {
        text: '主题',
        items: [
          { text: 'Office 宏', link: '/topics/office-macros' },
          { text: 'HTA', link: '/topics/hta' },
          { text: 'WSH 与 .NET', link: '/topics/wsh-dotnet' },
          { text: 'DLL 旁加载', link: '/topics/dll-sideloading' },
          { text: 'AppLocker 与 AMSI', link: '/topics/applocker-amsi' },
          { text: 'Windows 提权', link: '/topics/windows-privesc' },
          { text: '凭据', link: '/topics/credentials' },
          { text: '隧道与转发', link: '/topics/pivoting' },
          { text: '出网通道', link: '/topics/egress' },
          { text: 'Web 入口', link: '/topics/web-entry' },
          { text: 'MSSQL', link: '/topics/mssql' },
          { text: 'Active Directory', link: '/topics/ad' },
          { text: 'Linux', link: '/topics/linux' },
          { text: 'Kiosk / JEA / JIT', link: '/topics/kiosk-jea-jit' },
          { text: 'WinRM', link: '/topics/winrm' },
          { text: '日历邀请', link: '/topics/calendar' },
        ],
      },
      {
        text: '其它',
        items: [{ text: '参考链接', link: '/references' }],
      },
    ],
    search: { provider: 'local' },
    outline: { label: '本页目录', level: [2, 3] },
    docFooter: { prev: '上一页', next: '下一页' },
    lastUpdated: { text: '最后更新' },
    returnToTopLabel: '回到顶部',
    sidebarMenuLabel: '目录',
    darkModeSwitchLabel: '主题',
    footer: {
      message: '仅供授权测试、自建实验与个人学习。与 OffSec 无关。本站不托管可执行 payload。',
      copyright: '内容为个人笔记，公开工具命令来自各项目官方文档。',
    },
  },
})
