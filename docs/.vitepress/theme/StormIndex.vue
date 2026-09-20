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
  <nav class="storm-index" :aria-label="zh ? '模块索引' : 'Module index'">
    <div class="storm-index-header">
      <span class="storm-index-title">{{ zh ? '全字段索引' : 'Field index' }}</span>
      <span class="storm-index-badge">{{ zh ? '共 20 模块' : '20 modules' }}</span>
    </div>
    <ul>
      <li v-for="group in groups" :key="group.en">
        <a :href="`#${slug(group.en)}`">
          <span class="storm-index-name">{{ zh ? group.zh : group.en }}</span>
          <span class="storm-index-nums">{{ formatNums(group) }}</span>
        </a>
      </li>
    </ul>
  </nav>
</template>

<style scoped>
.storm-index {
  border-top: 2px solid var(--storm-mass);
  background: transparent;
}

.storm-index-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.65rem 0;
  border-bottom: 1px solid var(--storm-hair-strong);
}

.storm-index-title {
  color: var(--storm-rain);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.storm-index-badge {
  color: var(--storm-rain);
  font-size: 0.72rem;
  font-family: var(--storm-mono);
  letter-spacing: 0.04em;
}

.storm-index ul {
  margin: 0;
  padding: 0;
  list-style: none;
}

.storm-index li + li {
  border-top: 1px solid var(--storm-hair);
}

.storm-index a {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 1.2rem;
  padding: 0.58rem 0;
  color: var(--storm-mass);
  text-decoration: none;
  transition: color 140ms ease-out;
}

.storm-index a:hover .storm-index-name {
  color: var(--storm-rain);
}

.storm-index a:hover .storm-index-nums {
  color: var(--storm-mass);
}

.storm-index-name {
  font-size: 0.92rem;
  font-weight: 500;
  letter-spacing: -0.01em;
}

.storm-index-nums {
  color: var(--storm-rain);
  font-family: var(--storm-mono);
  font-size: 0.8rem;
  font-variant-numeric: tabular-nums;
  letter-spacing: 0.04em;
  white-space: nowrap;
  transition: color 140ms ease-out;
}
</style>
