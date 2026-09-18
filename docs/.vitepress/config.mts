import { defineConfig } from 'vitepress'

const base =
  process.env.VITEPRESS_BASE ||
  (process.env.GITHUB_ACTIONS ? '/osep-notes/' : '/')

export default defineConfig({
  title: 'OSEP 私人教材',
  description: '个人备考教材（不公开）。仅限授权实验与官方考试环境。',
  lang: 'zh-CN',
  base,
  cleanUrls: true,
  lastUpdated: true,
  themeConfig: {
    nav: [
      { text: '目录', link: '/prep-readme' },
      { text: '场景清单', link: '/scenarios' },
      { text: '模块', link: '/modules/00-environment-and-infra' },
    ],
    sidebar: [
      {
        text: '说明',
        items: [
          { text: '使用边界', link: '/disclaimer' },
          { text: '教材说明', link: '/prep-readme' },
          { text: '产出规范', link: '/conventions' },
          { text: '56 个场景', link: '/scenarios' },
          { text: '脚本索引', link: '/scripts-index' },
        ],
      },
      {
        text: '模块',
        items: [
          { text: '00 环境与基础设施', link: '/modules/00-environment-and-infra' },
          { text: '01 Word / VBA', link: '/modules/01-word-vba-office' },
          { text: '02 HTA', link: '/modules/02-hta' },
          { text: '03 JScript / DotNetToJScript', link: '/modules/03-jscript-dotnettojscript' },
          { text: '04 DLL 旁加载', link: '/modules/04-dll-sideloading' },
          { text: '05 AppLocker / CLM / AMSI', link: '/modules/05-applocker-clm-amsi' },
          { text: '06 Windows 提权', link: '/modules/06-uac-windows-privesc' },
          { text: '07 凭据 / LSASS', link: '/modules/07-credentials-lsass' },
          { text: '08 隧道', link: '/modules/08-pivoting-tunneling' },
          { text: '09 出网通道', link: '/modules/09-c2-egress-channels' },
          { text: '10 Web 入口', link: '/modules/10-web-entry-webshell' },
          { text: '11 MSSQL', link: '/modules/11-mssql' },
          { text: '12 Active Directory', link: '/modules/12-ad-attacks' },
          { text: '13 Linux', link: '/modules/13-linux' },
          { text: '14 Kiosk / JEA / JIT', link: '/modules/14-kiosk-jea-jit' },
          { text: '15 WinRM', link: '/modules/15-winrm-lateral' },
          { text: '16 日历邀请', link: '/modules/16-ics-calendar' },
        ],
      },
      {
        text: '考试',
        items: [
          { text: '97 考场定位表', link: '/modules/97-exam-day-lookup' },
          { text: '98 记录模板', link: '/modules/98-exam-note-template' },
          { text: '99 考前清单', link: '/modules/99-pre-exam-checklist' },
        ],
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
      message: '私人教材。仅限授权实验、官方考试环境与个人学习。禁止公开转载。',
    },
  },
})
