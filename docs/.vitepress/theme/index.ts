import DefaultTheme from 'vitepress/theme'
import './custom.css'
import { h } from 'vue'
import type { Theme } from 'vitepress'

const theme: Theme = {
  extends: DefaultTheme,
  Layout() {
    return h(DefaultTheme.Layout, null, {
      'layout-top': () => h('div', { class: 'ht-grid', 'aria-hidden': 'true' }),
    })
  },
}

export default theme
