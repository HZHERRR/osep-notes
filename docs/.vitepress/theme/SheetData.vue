<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vitepress'
import { groups } from '../taxonomy'

const route = useRoute()
const zh = computed(() => route.path === '/zh' || route.path.startsWith('/zh/'))

// Real taxonomy data only: which sheet this is, and the front it belongs to.
const found = computed(() => {
  const path = route.path.replace(/\/$/, '') || '/'
  for (const group of groups) {
    for (const entry of group.entries) {
      const link = entry.link.replace(/\/$/, '') || '/'
      if (link === path && entry.num) return { group, entry }
    }
  }
  return null
})

// The scenario ids printed in this sheet's own tables, read from the page.
const scenarios = computed(() => {
  if (typeof document === 'undefined') return []
  const ids = new Set<string>()
  document.querySelectorAll('.vp-doc table').forEach((table) => {
    table.querySelectorAll('td:first-child, th:first-child').forEach((cell) => {
      const value = (cell.textContent || '').trim()
      if (/^\d{1,3}$/.test(value)) ids.add(value)
    })
  })
  return [...ids].sort((a, b) => Number(a) - Number(b))
})
</script>

<template>
  <div v-if="found" class="sheet-data">
    <p class="sheet-data-num">{{ found.entry.num }}</p>
    <p class="sheet-data-front">{{ zh ? found.group.zh : found.group.en }}</p>
    <dl v-if="scenarios.length" class="sheet-data-scenarios">
      <dt>{{ zh ? '场景' : 'Scenarios' }}</dt>
      <dd>{{ scenarios.join(' · ') }}</dd>
    </dl>
  </div>
</template>

<style scoped>
.sheet-data {
  padding-bottom: 1.1rem;
  margin-bottom: 1.1rem;
  border-bottom: 1px solid var(--storm-hair);
}

.sheet-data-num {
  margin: 0;
  font-family: var(--storm-mono);
  font-size: 1.5rem;
  font-variant-numeric: tabular-nums;
  line-height: 1;
}

.sheet-data-front {
  margin: 0.45rem 0 0;
  color: var(--storm-rain);
  font-size: 0.72rem;
  font-weight: 600;
  letter-spacing: 0.12em;
  line-height: 1.5;
  text-transform: uppercase;
}

.sheet-data-scenarios {
  margin: 0.9rem 0 0;
}

.sheet-data-scenarios dt {
  color: var(--storm-rain);
  font-size: 0.66rem;
  font-weight: 600;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.sheet-data-scenarios dd {
  margin: 0.3rem 0 0;
  font-family: var(--storm-mono);
  font-size: 0.78rem;
  font-variant-numeric: tabular-nums;
  line-height: 1.7;
}
</style>
