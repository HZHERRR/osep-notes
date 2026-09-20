<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(
  defineProps<{
    /** One string per printed line. The layout keeps them as authored. */
    lines: string[]
    /** Index of the line that receives subtle emphasis. -1 disables. */
    dissolve?: number
  }>(),
  { dissolve: -1 },
)

const activeIndex = computed(() => props.dissolve)
</script>

<template>
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
</template>

<style scoped>
.storm-title {
  margin: 0;
  font-weight: 800;
  font-size: clamp(2.2rem, 4.6vw, 3.8rem);
  line-height: 1.1;
  letter-spacing: -0.025em;
  text-transform: uppercase;
  text-wrap: balance;
  color: var(--storm-mass);
}

.storm-line {
  display: block;
}

.storm-line.is-highlight {
  color: var(--storm-mass);
}

@media (max-width: 640px) {
  .storm-title {
    font-size: clamp(1.9rem, 7.5vw, 2.6rem);
    line-height: 1.15;
  }
}
</style>
