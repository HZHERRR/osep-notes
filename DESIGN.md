# Design System — Tactical Ops Console

<!-- impeccable:design-schema 1 -->

## World

- **Name:** Tactical Ops Console
- **Archetype:** Dark-first developer and security operations console (inspired by Linear, Raycast, and modern offensive security tooling).
- **Thesis:** An offensive security field reference is a tactical operations manual, not an avant-garde art experiment or generic blog. It replaces low-contrast monochrome ambiguity and oversized display typography with instant condition-first wayfinding, terminal-grade code blocks, and three explicit semantic status signals.
- **Audience Scene:** Operators sitting at Kali attack machines against Windows domain targets, preparing for or undergoing the 48-hour OSEP (PEN-300) exam. Fast command copying, zero distraction, high contrast in low ambient light.

## Color System

### Dark Theme (Default & Primary Experience)
- `--tac-bg`: `#090b0e` (Obsidian deep console ground)
- `--tac-panel`: `#0e1117` (Elevated panel / sidebar / nav)
- `--tac-card`: `#131722` (Interactive card surface)
- `--tac-card-hover`: `#181d2b` (Elevated interactive hover)
- `--tac-border`: `rgba(255, 255, 255, 0.08)` (Subtle hairline seam)
- `--tac-border-firm`: `rgba(255, 255, 255, 0.16)` (Focus / active boundary)
- `--tac-text-1`: `#f3f4f6` (Primary high-contrast typography)
- `--tac-text-2`: `#94a3b8` (Secondary metadata, description, labels)
- `--tac-text-3`: `#64748b` (Muted telemetry, inactive state)

### Light Theme (Crisp Field Paper)
- `--tac-bg`: `#f8fafc` (Clean slate paper canvas)
- `--tac-panel`: `#ffffff` (Solid surface)
- `--tac-card`: `#ffffff` (Card surface)
- `--tac-card-hover`: `#f1f5f9` (Hover tint)
- `--tac-border`: `rgba(15, 23, 42, 0.08)`
- `--tac-border-firm`: `rgba(15, 23, 42, 0.16)`
- `--tac-text-1`: `#0f172a`
- `--tac-text-2`: `#475569`
- `--tac-text-3`: `#94a3b8`

### Functional Semantic Signals
- **Tactical Emerald (`#10b981` / Light `#059669`):** Execution success, active state, verified exploit payload, validation tips (`.custom-block.tip`).
- **Tactical Amber (`#f59e0b` / Light `#d97706`):** Prerequisites, pre-condition warnings, procedure cautions (`.custom-block.warning`, `.storm-boundary`).
- **Tactical Crimson (`#ef4444` / Light `#dc2626`):** OPSEC detection risks, AV/EDR signatures, dangerous failure modes (`.custom-block.danger`).
- **Tactical Cyan (`#38bdf8` / Light `#0284c7`):** Scenario tags, telemetry, protocol markers (`.custom-block.info`).

## Typography

- **UI Sans:** `-apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif`
  - Display / Hero Headline: `clamp(2rem, 3.8vw, 3rem)`, weight 800, line-height 1.15, letter-spacing `-0.025em`.
  - Article `h1`: `clamp(1.9rem, 3.2vw, 2.45rem)`, weight 800, line-height 1.2, letter-spacing `-0.022em`.
  - Article `h2`: `1.35rem`, weight 700, line-height 1.35, letter-spacing `-0.015em`.
  - Article `h3`: `1.1rem`, weight 650, line-height 1.4.
  - Body: `1rem`, line-height `1.75`, max measure 75ch.
- **Code & Telemetry Mono:** `'Spline Sans Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace`
  - Code Blocks: `0.875rem`, line-height `1.7`, tab-size 4.
  - Badges & Telemetry: `0.72rem - 0.76rem`, weight 650, letter-spacing `0.04em - 0.08em`.

## Component Architecture

1. **Terminal-Grade Code Blocks:**
   - Dark plate container (`#0b0d13`) with subtle 1px border.
   - Dedicated 28px header bar with uppercase language badge on the right and copy button.
   - Generous interior padding (`1.25rem 1.4rem`) preventing overlap between code text and utility buttons.
2. **Tactical Admonitions / Callouts:**
   - Solid 8px rounded container with 1px tinted border and 8-12% soft background.
   - Monospace uppercase titles with semantic color assignment.
3. **Interactive Operational Matrix (Home):**
   - 3-column responsive card grid per operational phase.
   - Monospace module number badges (`[01]`, `[05]`, `[12]`) with subtle hover elevation and arrow transition.
4. **Header & Navigation:**
   - Sleek blur navbar (`backdrop-filter: blur(14px)`).
   - Monospace command prompt logo `> OSEP Notes`.
   - Compact search button with `⌘K` badge.
   - Minimalist pill switchers for Language (`EN / 中文`) and Theme (`Dark / Light`).
5. **Telemetry & Wayfinding:**
   - Right-rail scenario telemetry card displaying module status and `#scenario` pill badges.
   - 2px emerald scanline progress bar tracking reading progression through each technical module.
