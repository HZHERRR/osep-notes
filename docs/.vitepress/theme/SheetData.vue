<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vitepress'
import { groups } from '../taxonomy'

const route = useRoute()
const zh = computed(() => route.path === '/zh' || route.path.startsWith('/zh/'))

// Real taxonomy data: find the current module and group for both EN and ZH routes.
const found = computed(() => {
  const cleanPath = route.path.replace(/^\/zh/, '').replace(/\/$/, '') || '/'
  for (const group of groups) {
    for (const entry of group.entries) {
      const link = entry.link.replace(/\/$/, '') || '/'
      if (link === cleanPath && entry.num) return { group, entry }
    }
  }
  return null
})

// Scenarios: only read from tables where the first column explicitly represents Scenarios.
const scenarios = computed(() => {
  if (typeof document === 'undefined') return []
  const ids = new Set<string>()
  document.querySelectorAll('.vp-doc table').forEach((table) => {
    const firstTh = table.querySelector('thead th:first-child')
    const thText = (firstTh?.textContent || '').trim().toLowerCase()
    if (thText.includes('scenario') || thText.includes('场景')) {
      table.querySelectorAll('tbody td:first-child').forEach((cell) => {
        const val = (cell.textContent || '').trim()
        if (/^\d{1,3}$/.test(val)) ids.add(val)
      })
    }
  })
  return [...ids].sort((a, b) => Number(a) - Number(b))
})
</script>

<template>
  <div v-if="found" class="sheet-data">
    <div class="sheet-data-header">
      <span class="sheet-data-num">{{ found.entry.num }}</span>
      <span class="sheet-data-front">{{ zh ? found.group.zh : found.group.en }}</span>
    </div>
    <div class="sheet-data-title">{{ found.entry[zh ? 'zh' : 'en'] }}</div>
    <dl v-if="scenarios.length" class="sheet-data-scenarios">
      <dt>{{ zh ? '包含场景' : 'Covered scenarios' }}</dt>
      <dd>{{ scenarios.join(' · ') }}</dd>
    </dl>
  </div>
</template>

<style scoped>
.sheet-data {
  padding: 0 0 1rem 1rem;
  margin-bottom: 0.8rem;
  border-left: 1px solid var(--storm-hair);
  border-bottom: 1px solid var(--storm-hair);
}

.sheet-data-header {
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
}

.sheet-data-num {
  font-family: var(--storm-mono);
  font-size: 1.35rem;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
  line-height: 1;
  color: var(--storm-mass);
}

.sheet-data-front {
  color: var(--storm-rain);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}

.sheet-data-title {
  margin-top: 0.35rem;
  font-size: 0.88rem;
  font-weight: 600;
  color: var(--storm-mass);
  line-height: 1.35;
}

.sheet-data-scenarios {
  margin: 0.75rem 0 0;
}

.sheet-data-scenarios dt {
  color: var(--storm-rain);
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}

.sheet-data-scenarios dd {
  margin: 0.25rem 0 0;
  font-family: var(--storm-mono);
  font-size: 0.78rem;
  font-variant-numeric: tabular-nums;
  line-height: 1.6;
  color: var(--storm-mass);
}
</style>
