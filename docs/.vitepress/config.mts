import { defineConfig } from 'vitepress'

const base =
  process.env.VITEPRESS_BASE ||
  (process.env.GITHUB_ACTIONS ? '/osep-notes/' : '/')

const enSidebar = [
  {
    text: 'Start',
    items: [
      { text: 'Scope', link: '/disclaimer' },
      { text: 'How to read', link: '/conventions' },
      { text: 'Scenario map', link: '/scenarios' },
    ],
  },
  {
    text: 'Modules',
    items: [
      { text: '00 Lab environment', link: '/modules/00-environment-and-infra' },
      { text: '01 Word / VBA', link: '/modules/01-word-vba-office' },
      { text: '02 HTA', link: '/modules/02-hta' },
      { text: '03 JScript / .NET', link: '/modules/03-jscript-dotnettojscript' },
      { text: '04 DLL sideloading', link: '/modules/04-dll-sideloading' },
      { text: '05 AppLocker / AMSI', link: '/modules/05-applocker-clm-amsi' },
      { text: '06 Windows privesc', link: '/modules/06-uac-windows-privesc' },
      { text: '07 Credentials', link: '/modules/07-credentials-lsass' },
      { text: '08 Pivoting', link: '/modules/08-pivoting-tunneling' },
      { text: '09 Egress', link: '/modules/09-c2-egress-channels' },
      { text: '10 Web entry', link: '/modules/10-web-entry-webshell' },
      { text: '11 MSSQL', link: '/modules/11-mssql' },
      { text: '12 Active Directory', link: '/modules/12-ad-attacks' },
      { text: '13 Linux', link: '/modules/13-linux' },
      { text: '14 Kiosk / JEA / JIT', link: '/modules/14-kiosk-jea-jit' },
      { text: '15 WinRM', link: '/modules/15-winrm-lateral' },
      { text: '16 Calendar invites', link: '/modules/16-ics-calendar' },
    ],
  },
  {
    text: 'Exam',
    items: [
      { text: '97 Field lookup', link: '/modules/97-exam-day-lookup' },
      { text: '98 Note template', link: '/modules/98-exam-note-template' },
      { text: '99 Pre-exam list', link: '/modules/99-pre-exam-checklist' },
    ],
  },
]

const zhSidebar = [
  {
    text: '开始',
    items: [
      { text: '使用边界', link: '/zh/disclaimer' },
      { text: '阅读方式', link: '/zh/conventions' },
      { text: '场景清单', link: '/zh/scenarios' },
    ],
  },
  {
    text: '模块',
    items: [
      { text: '00 实验环境', link: '/zh/modules/00-environment-and-infra' },
      { text: '01 Word / VBA', link: '/zh/modules/01-word-vba-office' },
      { text: '02 HTA', link: '/zh/modules/02-hta' },
      { text: '03 JScript / .NET', link: '/zh/modules/03-jscript-dotnettojscript' },
      { text: '04 DLL 旁加载', link: '/zh/modules/04-dll-sideloading' },
      { text: '05 AppLocker / AMSI', link: '/zh/modules/05-applocker-clm-amsi' },
      { text: '06 Windows 提权', link: '/zh/modules/06-uac-windows-privesc' },
      { text: '07 凭据', link: '/zh/modules/07-credentials-lsass' },
      { text: '08 隧道', link: '/zh/modules/08-pivoting-tunneling' },
      { text: '09 出网', link: '/zh/modules/09-c2-egress-channels' },
      { text: '10 Web 入口', link: '/zh/modules/10-web-entry-webshell' },
      { text: '11 MSSQL', link: '/zh/modules/11-mssql' },
      { text: '12 Active Directory', link: '/zh/modules/12-ad-attacks' },
      { text: '13 Linux', link: '/zh/modules/13-linux' },
      { text: '14 Kiosk / JEA / JIT', link: '/zh/modules/14-kiosk-jea-jit' },
      { text: '15 WinRM', link: '/zh/modules/15-winrm-lateral' },
      { text: '16 日历邀请', link: '/zh/modules/16-ics-calendar' },
    ],
  },
  {
    text: '考试',
    items: [
      { text: '97 考场定位', link: '/zh/modules/97-exam-day-lookup' },
      { text: '98 记录模板', link: '/zh/modules/98-exam-note-template' },
      { text: '99 考前清单', link: '/zh/modules/99-pre-exam-checklist' },
    ],
  },
]

export default defineConfig({
  title: 'OSEP Notes',
  description: 'Authorized-lab notes for OSEP. English by default.',
  base,
  cleanUrls: true,
  lastUpdated: true,
  appearance: true,
  ignoreDeadLinks: true,
  locales: {
    root: {
      label: 'English',
      lang: 'en',
      themeConfig: {
        nav: [
          { text: 'Scope', link: '/disclaimer' },
          { text: 'Scenarios', link: '/scenarios' },
          { text: 'Modules', link: '/modules/00-environment-and-infra' },
        ],
        sidebar: enSidebar,
        search: { provider: 'local' },
        outline: { label: 'On this page', level: [2, 3] },
        docFooter: { prev: 'Previous', next: 'Next' },
        lastUpdated: { text: 'Updated' },
        returnToTopLabel: 'Top',
        sidebarMenuLabel: 'Menu',
        darkModeSwitchLabel: 'Theme',
        footer: {
          message: 'Authorized labs and the official exam environment only.',
        },
      },
    },
    zh: {
      label: '中文',
      lang: 'zh-CN',
      link: '/zh/',
      themeConfig: {
        nav: [
          { text: '使用边界', link: '/zh/disclaimer' },
          { text: '场景清单', link: '/zh/scenarios' },
          { text: '模块', link: '/zh/modules/00-environment-and-infra' },
        ],
        sidebar: zhSidebar,
        search: { provider: 'local' },
        outline: { label: '本页目录', level: [2, 3] },
        docFooter: { prev: '上一页', next: '下一页' },
        lastUpdated: { text: '最后更新' },
        returnToTopLabel: '回到顶部',
        sidebarMenuLabel: '目录',
        darkModeSwitchLabel: '主题',
        footer: {
          message: '仅限授权实验与官方考试环境。',
        },
      },
    },
  },
})
