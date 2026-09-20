<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vitepress'

const props = withDefaults(
  defineProps<{
    /** One string per printed line. The layout keeps them as authored. */
    lines: string[]
    /** Index of the line that receives subtle emphasis. -1 disables. */
    dissolve?: number
  }>(),
  { dissolve: -1 },
)

const route = useRoute()
const zh = computed(() => route.path === '/zh' || route.path.startsWith('/zh/'))
const activeIndex = computed(() => props.dissolve)
</script>

<template>
  <div class="tactical-hero-header">
    <div class="tactical-kicker">
      <span class="tactical-kicker-dot"></span>
      <span class="tactical-kicker-text">
        {{ zh ? 'OFFSEC PEN-300 // 备忘速查表' : 'OFFSEC PEN-300 // CHEAT SHEET' }}
      </span>
    </div>
    <h1 class="storm-title">
      <span
        v-for="(line, index) in lines"
        :key="line"
        class="storm-line"
        :class="{ 'is-highlight': index === activeIndex }"
      >
        {{ line }}
      </span>
    </h1>
  </div>
</template>

<style scoped>
.tactical-hero-header {
  margin: 0;
}

.tactical-kicker {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.25rem 0.65rem;
  margin-bottom: 1.25rem;
  border: 1px solid var(--tac-border);
  border-radius: 9999px;
  background: var(--tac-card);
}

.tactical-kicker-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--tac-accent);
  box-shadow: 0 0 8px var(--tac-accent);
}

.tactical-kicker-text {
  font-family: var(--tac-mono);
  font-size: 0.72rem;
  font-weight: 650;
  letter-spacing: 0.06em;
  color: var(--tac-text-2);
  text-transform: uppercase;
}

.storm-title {
  margin: 0;
  font-weight: 800;
  font-size: clamp(2rem, 3.8vw, 3rem);
  line-height: 1.15;
  letter-spacing: -0.025em;
  text-wrap: balance;
  color: var(--tac-text-1);
}

.storm-line {
  display: block;
}

.storm-line.is-highlight {
  color: var(--tac-accent);
}

@media (max-width: 640px) {
  .storm-title {
    font-size: clamp(1.75rem, 6.5vw, 2.25rem);
    line-height: 1.2;
  }
}
</style>
