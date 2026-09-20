<script setup lang="ts">
// The field index: the whole body of material as one hairline rail. The reader
// sees the entire field before scrolling, which is the surface's whole job.
import { computed } from 'vue'
import { useRoute } from 'vitepress'
import { groups } from '../taxonomy'

const route = useRoute()
const zh = computed(() => route.path === '/zh' || route.path.startsWith('/zh/'))

function slug(name: string) {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
}
</script>

<template>
  <nav class="storm-index" :aria-label="zh ? '模块索引' : 'Module index'">
    <p class="storm-index-title">{{ zh ? '全字段索引' : 'Field index' }}</p>
    <ul>
      <li v-for="group in groups" :key="group.en">
        <a :href="`#${slug(group.en)}`">
          <span class="storm-index-name">{{ zh ? group.zh : group.en }}</span>
          <span class="storm-index-nums">
            <template v-for="entry in group.entries" :key="entry.link">
              <span v-if="entry.num">{{ entry.num }}</span>
            </template>
          </span>
        </a>
      </li>
    </ul>
  </nav>
</template>

<style scoped>
.storm-index {
  border-top: 1px solid var(--storm-mass);
}

.storm-index-title {
  margin: 0;
  padding: 0.62rem 0;
  border-bottom: 1px solid var(--storm-hair);
  color: var(--storm-rain);
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.15em;
  text-transform: uppercase;
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
  gap: 1rem;
  padding: 0.5rem 0;
  color: var(--storm-mass);
  text-decoration: none;
}

.storm-index-name {
  font-size: 0.94rem;
  font-weight: 550;
  transition: color 140ms ease-out;
}

.storm-index a:hover .storm-index-name {
  color: var(--storm-rain);
}

.storm-index-nums {
  color: var(--storm-rain);
  font-family: var(--storm-mono);
  font-size: 0.72rem;
  font-variant-numeric: tabular-nums;
  letter-spacing: 0.06em;
  white-space: nowrap;
}
</style>
