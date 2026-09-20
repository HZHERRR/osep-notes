<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, withBase } from 'vitepress'
import { groups } from '../taxonomy'

const route = useRoute()
const zh = computed(() => route.path === '/zh' || route.path.startsWith('/zh/'))

function href(link: string) {
  const path = zh.value ? (link === '/' ? '/zh/' : `/zh${link}`) : link
  return withBase(path)
}

function isActive(link: string) {
  if (route.path === '/' || route.path === '/zh/' || route.path === '/zh') {
    return false
  }
  return route.path === href(link)
}

function slug(name: string) {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
}
</script>

<template>
  <div class="tactical-field-matrix">
    <section
      v-for="group in groups"
      :id="slug(group.en)"
      :key="group.en"
      class="tactical-group-section"
    >
      <div class="tactical-group-meta">
        <div class="tactical-group-pill">
          <span class="tactical-group-dot"></span>
          <h2 class="tactical-group-name">{{ zh ? group.zh : group.en }}</h2>
        </div>
        <p class="tactical-group-condition">{{ zh ? group.conditionZh : group.conditionEn }}</p>
      </div>

      <div class="tactical-group-body">
        <div class="tactical-module-grid">
          <a
            v-for="entry in group.entries"
            :key="entry.link"
            class="tactical-module-card"
            :class="{ 'is-active': isActive(entry.link) }"
            :href="href(entry.link)"
          >
            <div class="tactical-card-top">
              <span v-if="entry.num" class="tactical-card-badge">[{{ entry.num }}]</span>
              <span v-else class="tactical-card-badge is-start">INDEX</span>
              <span class="tactical-card-arrow">→</span>
            </div>
            <div class="tactical-card-title">{{ entry[zh ? 'zh' : 'en'] }}</div>
          </a>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.tactical-field-matrix {
  border-bottom: 1px solid var(--tac-border);
}

.tactical-group-section {
  display: grid;
  grid-template-columns: minmax(15rem, 280px) 1fr;
  gap: 1.5rem 3rem;
  padding: 2.2rem 0;
  border-top: 1px solid var(--tac-border);
}

.tactical-group-meta {
  min-width: 0;
}

.tactical-group-pill {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.tactical-group-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--tac-accent);
  flex-shrink: 0;
}

.tactical-group-name {
  margin: 0;
  font-family: var(--tac-mono);
  font-size: 0.84rem;
  font-weight: 700;
  letter-spacing: 0.06em;
  line-height: 1.4;
  text-transform: uppercase;
  color: var(--tac-text-1);
}

.tactical-group-condition {
  margin: 0.6rem 0 0;
  color: var(--tac-text-2);
  font-size: 0.86rem;
  line-height: 1.6;
}

.tactical-group-body {
  min-width: 0;
}

.tactical-module-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 0.75rem;
}

.tactical-module-card {
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  padding: 0.85rem 1rem;
  border: 1px solid var(--tac-border);
  border-radius: 6px;
  background: var(--tac-card);
  text-decoration: none !important;
  transition: all 140ms ease-out;
}

.tactical-module-card:hover {
  border-color: var(--tac-border-firm);
  background: var(--tac-card-hover);
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.tactical-module-card.is-active {
  border-color: var(--tac-accent);
  background: var(--tac-accent-soft);
}

.tactical-card-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.5rem;
}

.tactical-card-badge {
  font-family: var(--tac-mono);
  font-size: 0.76rem;
  font-weight: 650;
  color: var(--tac-accent);
  letter-spacing: 0.04em;
}

.tactical-card-badge.is-start {
  color: var(--tac-cyan);
}

.tactical-card-arrow {
  color: var(--tac-text-3);
  font-size: 0.85rem;
  transition: transform 140ms ease-out, color 140ms ease-out;
}

.tactical-module-card:hover .tactical-card-arrow {
  color: var(--tac-accent);
  transform: translateX(2px);
}

.tactical-card-title {
  color: var(--tac-text-1);
  font-size: 0.92rem;
  font-weight: 550;
  line-height: 1.4;
  word-break: break-word;
}

@media (max-width: 1100px) {
  .tactical-module-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 768px) {
  .tactical-group-section {
    grid-template-columns: 1fr;
    gap: 1.25rem;
    padding: 1.6rem 0;
  }

  .tactical-module-grid {
    grid-template-columns: 1fr;
  }
}
</style>
