import DefaultTheme from 'vitepress/theme'
import { h } from 'vue'
import type { Theme } from 'vitepress'
import './storm.css'
import StormTitle from './StormTitle.vue'
import StormField from './StormField.vue'
import StormIndex from './StormIndex.vue'
import AppearanceSwitch from './AppearanceSwitch.vue'
import WeatherFront from './WeatherFront.vue'

const theme: Theme = {
  extends: DefaultTheme,
  Layout() {
    return h(DefaultTheme.Layout, null, {
      'layout-top': () => h(WeatherFront),
      // One control cluster: language and appearance, both square and named for
      // what they switch to.
      'nav-bar-content-after': () =>
        h('div', { class: 'storm-controls' }, [h(AppearanceSwitch)]),
    })
  },
  enhanceApp({ app }) {
    // Authored into Markdown, so they must be globally registered.
    app.component('StormTitle', StormTitle)
    app.component('StormField', StormField)
    app.component('StormIndex', StormIndex)
  },
}

export default theme
