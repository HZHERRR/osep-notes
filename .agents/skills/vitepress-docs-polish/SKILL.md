---
name: vitepress-docs-polish
description: Improve the visual design, information architecture, and responsive reading experience of this VitePress documentation site while preserving its technical content, routes, and bilingual structure.
---

# VitePress docs polish

Treat the site as a field manual: calm, precise, fast to scan, and comfortable for long technical reading. Preserve its restrained security-notebook character without copying another site's visual identity.

## Design decisions

- Keep Markdown content, existing clean URLs, English and Chinese routes, search, and light/dark modes working.
- Use a readable sans-serif for prose and headings. Reserve monospace typography for code, module numbers, navigation labels, and compact metadata.
- Give navigation, reading content, and the on-page outline visibly different hierarchy. The article must remain the dominant surface.
- Prefer a content measure around 720–800px on wide screens. Collapse or hide secondary navigation before squeezing tables or prose.
- Keep tables readable: do not use `word-break: break-word` or `overflow-wrap: anywhere` on cells. Let wide tables scroll horizontally and keep short identifiers intact.
- Group long module navigation into meaningful sections. Preserve numeric prefixes because they communicate study order.
- Use a small, purposeful palette and consistent spacing, radius, border, and shadow tokens. Avoid decorative gradients, excessive cards, and low-contrast borders.
- Keep prose near 68–76 characters per line with generous line height. Let tables and code use the wider article column instead of widening every paragraph.
- Make the root page a compact technical orientation page instead of an immediate redirect. Prefer concrete module entry points and an operational workflow over a marketing-sized hero.
- Do not add vanity metrics such as language counts, generic feature totals, or decorative statistics. Every prominent homepage element must help the reader enter or use the technical material.

## Implementation boundaries

- Extend the default VitePress theme rather than replacing Markdown rendering or introducing a second frontend framework.
- Prefer changes in `docs/.vitepress/config.mts`, `docs/.vitepress/theme`, and the two locale index pages. Change module content only when the user requests editorial changes.
- Keep dependencies minimal. Do not add a UI library for styling that can be expressed in the existing theme.
- Preserve accessibility: visible focus styles, adequate contrast, semantic heading order, keyboard-accessible navigation, and motion reduction.

## Verification

After material changes:

1. Run `npm run docs:build`.
2. Preview the built site with its GitHub Pages base path.
3. Inspect representative English and Chinese pages in light and dark modes.
4. Check approximately 390px, 768px, and 1280px widths. Include a long module page with tables and code blocks.
5. Confirm there is no accidental horizontal page overflow, broken navigation, or arbitrarily split English words.
