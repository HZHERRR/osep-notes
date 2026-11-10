import { defineConfig } from 'vitepress'
import { sidebarFor } from './taxonomy'
import taskLists from 'markdown-it-task-lists'

const base =
  process.env.VITEPRESS_BASE ||
  (process.env.GITHUB_ACTIONS ? '/osep-notes/' : '/')

const enSidebar = sidebarFor('en')

export default defineConfig({
  title: 'OSEP-Cheat Sheet',
  description: 'Authorized-lab notes for OSEP.',
  base,
  cleanUrls: true,
  lastUpdated: false,
  appearance: true,
  ignoreDeadLinks: true,
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
    outline: { label: 'On this page', level: 2 },
    docFooter: { prev: 'Previous', next: 'Next' },
    returnToTopLabel: 'Top',
    sidebarMenuLabel: 'Menu',
    darkModeSwitchLabel: 'Theme',
    footer: {
      message: 'Authorized labs and the official exam environment only.',
    },
  },
  markdown: {
    theme: {
      light: 'github-light',
      dark: 'github-dark',
    },
    config: (md) => {
      md.use(taskLists, { enabled: false, label: true, lineNumber: false })
      md.renderer.rules.table_open = (tokens, idx, options, _env, self) =>
        `<div class="table-scroll">${self.renderToken(tokens, idx, options)}`
      md.renderer.rules.table_close = (tokens, idx, options, _env, self) =>
        `${self.renderToken(tokens, idx, options)}</div>`
    },
  },
})
