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

/** Anchor target for the field index rail on the home page. */
function slug(name: string) {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
}
</script>

<template>
  <div class="storm-fronts">
    <section v-for="group in groups" :id="slug(group.en)" :key="group.en" class="storm-front">
      <div class="storm-front-meta">
        <h2 class="storm-front-name">{{ zh ? group.zh : group.en }}</h2>
        <p class="storm-front-condition">{{ zh ? group.conditionZh : group.conditionEn }}</p>
      </div>
      <div class="storm-front-body">
        <ul class="storm-entries">
          <li v-for="entry in group.entries" :key="entry.link">
            <a
              class="storm-entry"
              :class="{ 'is-here': isActive(entry.link) }"
              :href="href(entry.link)"
            >
              <span v-if="entry.num" class="storm-entry-num">{{ entry.num }}</span>
              <span v-else class="storm-entry-num storm-entry-arrow">→</span>
              <span class="storm-entry-name">{{ entry[zh ? 'zh' : 'en'] }}</span>
            </a>
          </li>
        </ul>
      </div>
    </section>
  </div>
</template>

<style scoped>
.storm-fronts {
  border-bottom: 1px solid var(--storm-hair);
}

.storm-front {
  display: grid;
  grid-template-columns: minmax(14rem, 260px) 1fr;
  gap: 1.5rem 3rem;
  padding: 1.8rem 0 2rem;
  border-top: 1px solid var(--storm-hair);
}

.storm-front-meta {
  min-width: 0;
}

.storm-front-name {
  margin: 0;
  font-size: 0.85rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  line-height: 1.4;
  text-transform: uppercase;
  color: var(--storm-mass);
}

.storm-front-condition {
  margin: 0.45rem 0 0;
  color: var(--storm-rain);
  font-size: 0.85rem;
  line-height: 1.55;
}

.storm-front-body {
  min-width: 0;
}

.storm-entries {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 0.35rem 1.8rem;
  margin: 0;
  padding: 0;
  list-style: none;
}

.storm-entry {
  display: flex;
  align-items: baseline;
  gap: 0.6rem;
  padding: 0.42rem 0.5rem;
  border-radius: 2px;
  color: var(--storm-mass);
  font-size: 0.94rem;
  line-height: 1.45;
  text-decoration: none !important;
  transition:
    background-color 140ms ease-out,
    color 140ms ease-out;
}

.storm-entry:hover {
  background: var(--storm-hair);
  color: var(--storm-mass);
}

.storm-entry-num {
  width: 1.8rem;
  flex-shrink: 0;
  color: var(--storm-rain);
  font-family: var(--storm-mono);
  font-size: 0.8rem;
  font-weight: 500;
  font-variant-numeric: tabular-nums;
  transition: color 140ms ease-out;
}

.storm-entry:hover .storm-entry-num {
  color: var(--storm-mass);
}

.storm-entry-arrow {
  color: var(--storm-rain);
  font-size: 0.88rem;
}

.storm-entry-name {
  font-weight: 500;
}

.storm-entry.is-here {
  background: var(--storm-hair-strong);
}

.storm-entry.is-here .storm-entry-name {
  font-weight: 700;
}

@media (max-width: 1080px) {
  .storm-entries {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 768px) {
  .storm-front {
    grid-template-columns: 1fr;
    gap: 0.85rem;
    padding: 1.4rem 0 1.6rem;
  }

  .storm-entries {
    grid-template-columns: 1fr;
    gap: 0.2rem;
  }
}
</style>
