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

// Scenarios: read from covers line, headings, or tables
const scenarios = computed(() => {
  if (typeof document === 'undefined') return []
  const ids = new Set<string>()

  // 1. Check top blockquote "Covers scenarios: ..." or "覆盖场景：..."
  const blockquotes = document.querySelectorAll('.vp-doc blockquote')
  for (const bq of blockquotes) {
    const text = bq.textContent || ''
    const match = text.match(/(?:Covers scenarios|覆盖场景)[：:\s]*([0-9\s,、–-]+)/i)
    if (match && match[1]) {
      const parts = match[1].split(/[,、\s]+/)
      for (const p of parts) {
        const trimmed = p.trim()
        if (/^\d{1,3}$/.test(trimmed)) ids.add(trimmed)
      }
    }
  }

  // 2. Check Scenario headings (e.g. "Scenario 18:" or "场景 18：")
  document.querySelectorAll('.vp-doc h2').forEach((h2) => {
    const text = (h2.textContent || '').trim()
    const match = text.match(/(?:Scenario|场景)\s*(\d{1,3})/i)
    if (match && match[1]) {
      ids.add(match[1])
    }
  })

  // 3. Fallback: read from tables where first column is Scenario / 场景
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
  <div v-if="found" class="tactical-sheet-data">
    <div class="tactical-sheet-header">
      <span class="tactical-sheet-badge">[{{ found.entry.num }}]</span>
      <span class="tactical-sheet-phase">{{ zh ? found.group.zh : found.group.en }}</span>
    </div>
    <div class="tactical-sheet-title">{{ found.entry[zh ? 'zh' : 'en'] }}</div>
    <div v-if="scenarios.length" class="tactical-sheet-scenarios">
      <div class="tactical-scenarios-label">
        <span class="tactical-scenarios-dot"></span>
        <span>{{ zh ? '覆盖场景' : 'COVERED SCENARIOS' }}</span>
      </div>
      <div class="tactical-scenarios-pills">
        <span v-for="id in scenarios" :key="id" class="tactical-scenario-pill">
          #{{ id }}
        </span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.tactical-sheet-data {
  padding: 0.85rem 1rem;
  margin-bottom: 1.25rem;
  border: 1px solid var(--tac-border);
  border-radius: 8px;
  background: var(--tac-card);
}

.tactical-sheet-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.tactical-sheet-badge {
  font-family: var(--tac-mono);
  font-size: 0.85rem;
  font-weight: 700;
  color: var(--tac-accent);
}

.tactical-sheet-phase {
  color: var(--tac-text-3);
  font-family: var(--tac-mono);
  font-size: 0.72rem;
  font-weight: 650;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}

.tactical-sheet-title {
  margin-top: 0.4rem;
  font-size: 0.92rem;
  font-weight: 600;
  color: var(--tac-text-1);
  line-height: 1.35;
}

.tactical-sheet-scenarios {
  margin-top: 0.75rem;
  padding-top: 0.65rem;
  border-top: 1px solid var(--tac-border);
}

.tactical-scenarios-label {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  color: var(--tac-text-3);
  font-family: var(--tac-mono);
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.tactical-scenarios-dot {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: var(--tac-accent);
}

.tactical-scenarios-pills {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
  margin-top: 0.4rem;
}

.tactical-scenario-pill {
  padding: 0.12rem 0.4rem;
  border: 1px solid var(--tac-border-firm);
  border-radius: 4px;
  background: rgba(255, 255, 255, 0.03);
  color: var(--tac-text-2);
  font-family: var(--tac-mono);
  font-size: 0.72rem;
  font-weight: 600;
}
</style>
