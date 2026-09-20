<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vitepress'

const route = useRoute()
const progress = ref(0)
const visible = ref(false)

let frame = 0
let observer: ResizeObserver | undefined

function articleElement() {
  return document.querySelector<HTMLElement>('.VPDoc .vp-doc')
}

function update() {
  cancelAnimationFrame(frame)
  frame = requestAnimationFrame(() => {
    const article = articleElement()
    visible.value = Boolean(article)

    if (!article) {
      progress.value = 0
      return
    }

    const articleTop = window.scrollY + article.getBoundingClientRect().top
    const readableDistance = Math.max(article.scrollHeight - window.innerHeight * 0.55, 1)
    progress.value = Math.min(Math.max((window.scrollY - articleTop) / readableDistance, 0), 1)
  })
}

function observeArticle() {
  observer?.disconnect()
  const article = articleElement()
  if (article) observer?.observe(article)
  update()
}

onMounted(() => {
  observer = new ResizeObserver(update)
  window.addEventListener('scroll', update, { passive: true })
  window.addEventListener('resize', update, { passive: true })
  observeArticle()
})

watch(
  () => route.path,
  () => nextTick(observeArticle),
)

onBeforeUnmount(() => {
  cancelAnimationFrame(frame)
  observer?.disconnect()
  window.removeEventListener('scroll', update)
  window.removeEventListener('resize', update)
})
</script>

<template>
  <div v-if="visible" class="reading-progress" aria-hidden="true">
    <span :style="{ transform: `scaleX(${progress})` }" />
  </div>
</template>
