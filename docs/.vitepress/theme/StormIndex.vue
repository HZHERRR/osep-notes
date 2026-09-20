<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vitepress'
import { groups, type Group } from '../taxonomy'

const route = useRoute()
const zh = computed(() => route.path === '/zh' || route.path.startsWith('/zh/'))

function slug(name: string) {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
}

function formatNums(group: Group): string {
  const nums = group.entries.map((e) => e.num).filter(Boolean)
  if (!nums.length) {
    return zh.value ? `${group.entries.length} 篇` : `${group.entries.length} docs`
  }
  if (nums.length === 1) return nums[0]

  const intNums = nums.map((n) => ({ raw: n, val: parseInt(n, 10) }))
  const ranges: string[] = []
  let start = intNums[0]
  let prev = intNums[0]

  for (let i = 1; i < intNums.length; i++) {
    const cur = intNums[i]
    if (cur.val === prev.val + 1) {
      prev = cur
    } else {
      if (start.val === prev.val) {
        ranges.push(start.raw)
      } else if (prev.val === start.val + 1) {
        ranges.push(`${start.raw}, ${prev.raw}`)
      } else {
        ranges.push(`${start.raw}–${prev.raw}`)
      }
      start = cur
      prev = cur
    }
  }

  if (start.val === prev.val) {
    ranges.push(start.raw)
  } else if (prev.val === start.val + 1) {
    ranges.push(`${start.raw}, ${prev.raw}`)
  } else {
    ranges.push(`${start.raw}–${prev.raw}`)
  }

  return ranges.join(', ')
}
</script>

<template>
  <nav class="tactical-index" :aria-label="zh ? '模块快速索引' : 'Module quick index'">
    <div class="tactical-index-header">
      <div class="tactical-index-title-group">
        <span class="tactical-status-indicator"></span>
        <span class="tactical-index-title">{{ zh ? '战术模块索引' : 'FIELD INDEX' }}</span>
      </div>
      <span class="tactical-index-badge">{{ zh ? '共 20 模块' : '20 MODULES' }}</span>
    </div>
    <ul class="tactical-index-list">
      <li v-for="group in groups" :key="group.en" class="tactical-index-item">
        <a :href="`#${slug(group.en)}`" class="tactical-index-link">
          <span class="tactical-index-name">{{ zh ? group.zh : group.en }}</span>
          <span class="tactical-index-nums">{{ formatNums(group) }}</span>
        </a>
      </li>
    </ul>
  </nav>
</template>

<style scoped>
.tactical-index {
  border: 1px solid var(--tac-border);
  border-radius: 8px;
  background: var(--tac-card);
  padding: 1rem 1.25rem;
  box-shadow: 0 4px 14px rgba(0, 0, 0, 0.15);
}

.tactical-index-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding-bottom: 0.75rem;
  border-bottom: 1px solid var(--tac-border);
}

.tactical-index-title-group {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.tactical-status-indicator {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--tac-accent);
}

.tactical-index-title {
  color: var(--tac-text-2);
  font-family: var(--tac-mono);
  font-size: 0.74rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.tactical-index-badge {
  color: var(--tac-text-3);
  font-family: var(--tac-mono);
  font-size: 0.72rem;
  letter-spacing: 0.04em;
}

.tactical-index-list {
  margin: 0.25rem 0 0;
  padding: 0;
  list-style: none;
}

.tactical-index-item + .tactical-index-item {
  border-top: 1px solid var(--tac-border);
}

.tactical-index-link {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.6rem 0.4rem;
  border-radius: 4px;
  color: var(--tac-text-1);
  text-decoration: none !important;
  transition: background-color 120ms ease-out, color 120ms ease-out;
}

.tactical-index-link:hover {
  background: var(--tac-card-hover);
}

.tactical-index-link:hover .tactical-index-name {
  color: var(--tac-accent);
}

.tactical-index-name {
  font-size: 0.88rem;
  font-weight: 500;
  letter-spacing: -0.01em;
  transition: color 120ms ease-out;
}

.tactical-index-nums {
  color: var(--tac-text-3);
  font-family: var(--tac-mono);
  font-size: 0.78rem;
  font-variant-numeric: tabular-nums;
  letter-spacing: 0.04em;
  white-space: nowrap;
}
</style>
