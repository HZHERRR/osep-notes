import { defineConfig } from 'vitepress'
import { sidebarFor } from './taxonomy'

const base =
  process.env.VITEPRESS_BASE ||
  (process.env.GITHUB_ACTIONS ? '/osep-notes/' : '/')

const enSidebar = sidebarFor('en')
const zhSidebar = sidebarFor('zh')

export default defineConfig({
  title: 'OSEP Notes',
  description: 'Authorized-lab notes for OSEP. English by default.',
  base,
  cleanUrls: true,
  lastUpdated: false,
  appearance: true,
  ignoreDeadLinks: true,
  themeConfig: {
    search: { provider: 'local' },
    outline: { level: [2, 3] },
  },
  markdown: {
    theme: 'github-dark',
  },
  locales: {
    root: {
      label: 'English',
      lang: 'en',
      themeConfig: {
        nav: [
          { text: 'Scenarios', link: '/scenarios' },
          { text: 'Modules', link: '/modules/00-environment-and-infra' },
          { text: 'Scope', link: '/disclaimer' },
        ],
        sidebar: enSidebar,
        socialLinks: [
          { icon: 'github', link: 'https://github.com/hzherrr/osep-notes' },
        ],
        search: {
          provider: 'local',
          options: {
            translations: {
              button: { buttonText: 'Search', buttonAriaLabel: 'Search the notes' },
              modal: {
                displayDetails: 'Display detailed list',
                resetButtonTitle: 'Reset search',
                noResultsText: 'No results for',
                footer: { selectText: 'select', navigateText: 'navigate', closeText: 'close' },
              },
            },
          },
        },
        outline: { label: 'On this page', level: [2, 3] },
        docFooter: { prev: 'Previous', next: 'Next' },
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
          { text: '场景清单', link: '/zh/scenarios' },
          { text: '技术模块', link: '/zh/modules/00-environment-and-infra' },
          { text: '使用边界', link: '/zh/disclaimer' },
        ],
        sidebar: zhSidebar,
        socialLinks: [
          { icon: 'github', link: 'https://github.com/hzherrr/osep-notes' },
        ],
        search: {
          provider: 'local',
          options: {
            translations: {
              button: { buttonText: '搜索', buttonAriaLabel: '搜索笔记' },
              modal: {
                displayDetails: '显示详细列表',
                resetButtonTitle: '清除查询条件',
                noResultsText: '未找到结果',
                footer: { selectText: '选择', navigateText: '切换', closeText: '关闭' },
              },
            },
          },
        },
        outline: { label: '本页目录', level: [2, 3] },
        docFooter: { prev: '上一页', next: '下一页' },
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
