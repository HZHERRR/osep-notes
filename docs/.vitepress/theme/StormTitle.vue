<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { peel, reducedMotion } from './weather'

const props = withDefaults(
  defineProps<{
    /** One string per printed line. The layout keeps them as authored. */
    lines: string[]
    /** Index of the line that dissolves into weather. -1 dissolves nothing. */
    dissolve?: number
  }>(),
  { dissolve: -1 },
)

const root = ref<HTMLElement | null>(null)
const spent = ref(false)

/** Everything before the final word stays set; the final word is the weather. */
function head(line: string) {
  const cut = line.lastIndexOf(' ')
  return cut < 0 ? '' : line.slice(0, cut + 1)
}

function tail(line: string) {
  const cut = line.lastIndexOf(' ')
  return cut < 0 ? line : line.slice(cut + 1)
}

function chars(line: string) {
  const word = [...tail(line)]
  const last = Math.max(word.length - 1, 1)
  return word.map((char, i) => ({
    char,
    // 0 index keeps the storm mass; the last glyph is fully silver.
    mix: `${Math.round((1 - i / last) * 100)}%`,
    i,
  }))
}

onMounted(() => {
  if (props.dissolve < 0) return
  // The spent state is the design, not the animation: the last word settles into
  // loosened, silvered type whether or not the particles are allowed to run.
  spent.value = true
  if (reducedMotion()) return
  const line = root.value?.querySelectorAll<HTMLElement>('.storm-line')[props.dissolve]
  if (!line) return
  // Let the first paint land before the letters start leaving.
  window.setTimeout(() => peel(line), 280)
})

const dissolving = computed(() => props.dissolve)
</script>

<template>
  <h1 ref="root" class="storm-title">
    <span
      v-for="(line, index) in lines"
      :key="line"
      class="storm-line"
      :class="{ 'is-spent': spent && index === dissolving }"
    >
      <template v-if="spent && index === dissolving"
        >{{ head(line)
        }}<span
          v-for="c in chars(line)"
          :key="c.i"
          class="storm-char"
          :style="{ '--mix': c.mix, '--i': c.i }"
          >{{ c.char }}</span
        ></template
      >
      <template v-else>{{ line }}</template>
    </span>
  </h1>
</template>

<style scoped>
.storm-title {
  margin: 0;
  font-weight: 800;
  font-stretch: 92%;
  font-size: clamp(2.6rem, 7.4vw, 5.5rem);
  line-height: 0.94;
  letter-spacing: -0.035em;
  /* Archivo's space is only 0.19em, which disappears between caps. */
  word-spacing: 0.1em;
  text-transform: uppercase;
  text-wrap: balance;
}

.storm-line {
  display: block;
}

/* Kerning loosens into wind: the last word walks from the storm mass to silver,
   opens its tracking, and lifts a little, character by character. This is the
   settled state of the type — visible with motion on or off. */
.storm-char {
  display: inline-block;
  color: color-mix(in oklab, var(--storm-mass) var(--mix), var(--storm-silver));
  /* Capped: ten characters walking 0.012em each would otherwise add ~14% to the
     word's width with nothing stopping it on a narrow phone. */
  letter-spacing: min(calc(var(--i) * 0.012em), 0.09em);
  transform: translateY(calc(var(--i) * -0.008em));
}

@media (max-width: 420px) {
  .storm-char {
    letter-spacing: min(calc(var(--i) * 0.006em), 0.045em);
    transform: none;
  }
}
</style>
