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
      <h2 class="storm-front-name">{{ zh ? group.zh : group.en }}</h2>
      <div class="storm-front-body">
        <p class="storm-front-condition">{{ zh ? group.conditionZh : group.conditionEn }}</p>
        <ul class="storm-entries">
          <li v-for="entry in group.entries" :key="entry.link">
            <a
              class="storm-entry"
              :class="{ 'is-here': isActive(entry.link) }"
              :href="href(entry.link)"
            >
              <span v-if="entry.num" class="storm-entry-num">{{ entry.num }}</span>
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
  grid-template-columns: minmax(9rem, 20%) 1fr;
  gap: 1.5rem 2.5rem;
  padding: 1.6rem 0 1.7rem;
  border-top: 1px solid var(--storm-hair);
}

.storm-front-name {
  margin: 0;
  font-size: 0.82rem;
  font-weight: 700;
  letter-spacing: 0.13em;
  line-height: 1.5;
  text-transform: uppercase;
}

.storm-front-condition {
  max-width: 46ch;
  margin: 0 0 1rem;
  color: var(--storm-rain);
  font-size: 0.88rem;
  line-height: 1.6;
}

.storm-entries {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(15rem, 1fr));
  gap: 0.1rem 2rem;
  margin: 0;
  padding: 0;
  list-style: none;
}

.storm-entry {
  display: flex;
  align-items: baseline;
  gap: 0.7rem;
  padding: 0.32rem 0;
  color: var(--storm-mass);
  font-size: 0.98rem;
  line-height: 1.4;
  text-decoration: none;
  border-bottom: 1px solid transparent;
  transition: border-color 160ms ease-out;
}

.storm-entry:hover {
  border-bottom-color: var(--storm-mass);
}

.storm-entry-num {
  min-width: 1.6rem;
  color: var(--storm-rain);
  font-family: var(--storm-mono);
  font-size: 0.78rem;
  font-variant-numeric: tabular-nums;
}

.storm-entry.is-here .storm-entry-name {
  font-weight: 700;
}

.storm-entry.is-here .storm-entry-num::before {
  content: '';
  display: inline-block;
  width: 0.32rem;
  height: 0.32rem;
  margin-right: 0.28rem;
  background: var(--storm-mass);
  vertical-align: 0.16rem;
}

@media (max-width: 720px) {
  .storm-front {
    grid-template-columns: 1fr;
    gap: 0.6rem;
  }
}
</style>
