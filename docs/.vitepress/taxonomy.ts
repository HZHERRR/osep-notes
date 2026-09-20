// Single source of truth for the site's taxonomy.
// Imported by .vitepress/config.mts (sidebar) and by the theme's field components,
// so the home page can never drift from the navigation.

export interface Entry {
  /** Module number as printed on the sheet, e.g. "12". Empty for start pages. */
  num: string
  en: string
  zh: string
  link: string
}

export interface Group {
  en: string
  zh: string
  /** One line, both languages: what condition this group covers. */
  conditionEn: string
  conditionZh: string
  entries: Entry[]
}

const entry = (num: string, en: string, zh: string, link: string): Entry => ({ num, en, zh, link })

export const groups: Group[] = [
  {
    en: 'Start',
    zh: '开始',
    conditionEn: 'Orientation, the boundary of authorized use, and the scenario index.',
    conditionZh: '定位、授权边界，以及场景索引。',
    entries: [
      entry('', 'Overview', '概览', '/'),
      entry('', 'Scope', '使用边界', '/disclaimer'),
      entry('', 'Scenario map', '场景清单', '/scenarios'),
    ],
  },
  {
    en: 'Foundation',
    zh: '基础环境',
    conditionEn: 'The lab itself: addressing, directory layout, monitoring, and delivery.',
    conditionZh: '实验环境本身：寻址、目录结构、监控与投递。',
    entries: [entry('00', 'Lab environment', '实验环境', '/modules/00-environment-and-infra')],
  },
  {
    en: 'Delivery & execution',
    zh: '投递与执行',
    conditionEn: 'You have a way in but the host will not run what you send it.',
    conditionZh: '进得去，但目标主机不肯运行你投递的东西。',
    entries: [
      entry('01', 'Word / VBA', 'Word / VBA', '/modules/01-word-vba-office'),
      entry('02', 'HTA', 'HTA', '/modules/02-hta'),
      entry('03', 'JScript / .NET', 'JScript / .NET', '/modules/03-jscript-dotnettojscript'),
      entry('04', 'DLL sideloading', 'DLL 旁加载', '/modules/04-dll-sideloading'),
      entry('05', 'AppLocker / AMSI', 'AppLocker / AMSI', '/modules/05-applocker-clm-amsi'),
      entry('16', 'Calendar invites', '日历邀请', '/modules/16-ics-calendar'),
    ],
  },
  {
    en: 'Privilege & credentials',
    zh: '提权与凭据',
    conditionEn: 'You are on the box but not yet anyone who matters.',
    conditionZh: '已经在机器上，但还不是任何有分量的人。',
    entries: [
      entry('06', 'Windows privesc', 'Windows 提权', '/modules/06-uac-windows-privesc'),
      entry('07', 'Credentials', '凭据', '/modules/07-credentials-lsass'),
    ],
  },
  {
    en: 'Pivot & access',
    zh: '隧道与访问',
    conditionEn: 'The next host is reachable only from the one you already hold.',
    conditionZh: '下一台主机只能从你已控制的那台到达。',
    entries: [
      entry('08', 'Pivoting', '隧道', '/modules/08-pivoting-tunneling'),
      entry('09', 'Egress', '出网', '/modules/09-c2-egress-channels'),
      entry('15', 'WinRM', 'WinRM', '/modules/15-winrm-lateral'),
    ],
  },
  {
    en: 'Services & directory',
    zh: '服务与目录',
    conditionEn: 'A listening service or the directory itself is the way through.',
    conditionZh: '一个在听的服务，或者目录本身，就是通路。',
    entries: [
      entry('10', 'Web entry', 'Web 入口', '/modules/10-web-entry-webshell'),
      entry('11', 'MSSQL', 'MSSQL', '/modules/11-mssql'),
      entry('12', 'Active Directory', 'Active Directory', '/modules/12-ad-attacks'),
    ],
  },
  {
    en: 'Constrained systems',
    zh: '受限系统',
    conditionEn: 'The target is not Windows, or it is Windows with the doors welded shut.',
    conditionZh: '目标不是 Windows，或者是被焊死了门窗的 Windows。',
    entries: [
      entry('13', 'Linux', 'Linux', '/modules/13-linux'),
      entry('14', 'Kiosk / JEA / JIT', 'Kiosk / JEA / JIT', '/modules/14-kiosk-jea-jit'),
    ],
  },
  {
    en: 'Exam',
    zh: '考试',
    conditionEn: 'The clock is running and the answer has to be found, not derived.',
    conditionZh: '时钟在走，答案要被找到，而不是被推导出来。',
    entries: [
      entry('97', 'Field lookup', '考场定位', '/modules/97-exam-day-lookup'),
      entry('98', 'Note template', '记录模板', '/modules/98-exam-note-template'),
      entry('99', 'Pre-exam list', '考前清单', '/modules/99-pre-exam-checklist'),
    ],
  },
]

/** VitePress sidebar shape, derived from the taxonomy above. */
export function sidebarFor(locale: 'en' | 'zh', collapsed = true) {
  return groups.map((group, index) => ({
    text: group[locale],
    // The first group stays open; everything else starts folded.
    collapsed: index === 0 ? false : collapsed,
    items: group.entries.map((e) => ({
      text: e.num ? `${e.num} ${e[locale]}` : e[locale],
      link: e.link,
    })),
  }))
}

export const moduleCount = groups.reduce(
  (total, group) => total + group.entries.filter((e) => e.num).length,
  0,
)
