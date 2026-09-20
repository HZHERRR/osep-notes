import DefaultTheme from 'vitepress/theme'
import './custom.css'
import { h } from 'vue'
import type { Theme } from 'vitepress'
import ReadingProgress from './ReadingProgress.vue'

const theme: Theme = {
  extends: DefaultTheme,
  Layout() {
    return h(DefaultTheme.Layout, null, {
      'layout-top': () => h(ReadingProgress),
    })
  },
}

export default theme
