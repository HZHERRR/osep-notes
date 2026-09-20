  ui-lg:
    fontFamily: "Archivo, system-ui, sans-serif"
    fontSize: "0.98rem"
    fontWeight: 550
    lineHeight: 1.6
    letterSpacing: "normal"
    fontFeature: "field entries, admonition prose, the boundary band"
  ui:
    fontFamily: "Archivo, system-ui, sans-serif"
    fontSize: "0.94rem"
    fontWeight: 430
    lineHeight: 1.5
    letterSpacing: "normal"
    fontFeature: "sidebar entries, the field index rail"
  ui-sm:
    fontFamily: "Archivo, system-ui, sans-serif"
    fontSize: "0.88rem"
    fontFeature: "table cells, front condition lines"
  ui-xs:
    fontFamily: "Archivo, system-ui, sans-serif"
    fontSize: "0.78rem"
    fontFeature: "the sheet readout's scenario numerals"
  subhead:
    fontFamily: "Archivo, system-ui, sans-serif"
    fontSize: "1.16rem"
    fontWeight: 700
    lineHeight: 1.35
    letterSpacing: "-0.014em"
    fontFeature: "h3 within an article"
---
name: OSEP Notes
description: Authorized-lab field notes where language behaves as weather — achromatic letter-mass on a paper-white field.
colors:
  storm-ink: "#15161a"
  rain-grey: "#63666c"
  silver-flash: "#7f8791"
  paper-field: "#f1f1ee"
  hairline-rule: "rgb(21 22 26 / 0.15)"
  hairline-firm: "rgb(21 22 26 / 0.4)"
  code-plate: "#15161a"
  code-plate-ink: "#e9e7e1"
  code-plate-rain: "#8d9199"
  scroll-cue: "rgb(21 22 26 / 0.22)"
  plate-control: "rgb(255 255 255 / 0.18)"
  plate-control-hover: "rgb(255 255 255 / 0.1)"
typography:
  display:
    fontFamily: "Archivo, system-ui, sans-serif"
    fontSize: "clamp(2.6rem, 7.4vw, 5.5rem)"
    fontWeight: 800
    lineHeight: 0.94
    letterSpacing: "-0.035em"
    fontFeature: "font-variation-settings: 'wdth' 92"
  headline:
    fontFamily: "Archivo, system-ui, sans-serif"
    fontSize: "clamp(1.95rem, 3.1vw, 2.75rem)"
    fontWeight: 800
    lineHeight: 1.06
    letterSpacing: "-0.032em"
    fontFeature: "font-variation-settings: 'wdth' 96"
  title:
    fontFamily: "Archivo, system-ui, sans-serif"
    fontSize: "1.52rem"
    fontWeight: 750
    lineHeight: 1.2
    letterSpacing: "-0.022em"
    fontFeature: "font-variation-settings: 'wdth' 98"
  section:
    fontFamily: "Archivo, system-ui, sans-serif"
    fontSize: "0.72rem"
    fontWeight: 700
    lineHeight: 1.5
    letterSpacing: "0.13em"
    fontFeature: "text-transform: uppercase"
  body:
    fontFamily: "Archivo, system-ui, sans-serif"
    fontSize: "1.0625rem"
    fontWeight: 430
    lineHeight: 1.72
    letterSpacing: "normal"
  code:
    fontFamily: "Spline Sans Mono, ui-monospace, monospace"
    fontSize: "0.83rem"
    fontWeight: 400
    lineHeight: 1.7
    letterSpacing: "normal"
  label:
    fontFamily: "Spline Sans Mono, ui-monospace, monospace"
    fontSize: "0.66rem"
    fontWeight: 500
    lineHeight: 1.2
    letterSpacing: "0.14em"
    fontFeature: "text-transform: uppercase"
  nav:
    fontFamily: "Archivo, system-ui, sans-serif"
    fontSize: "0.8rem"
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: "0.1em"
    fontFeature: "text-transform: uppercase; font-variation-settings: 'wdth' 96 (site title only)"
  rail:
    fontFamily: "Archivo, system-ui, sans-serif"
    fontSize: "0.84rem"
    fontWeight: 400
    lineHeight: 1.45
    letterSpacing: "normal"
rounded:
  none: "0"
spacing:
  unit: "0.34rem"
  hairline: "1px"
  inline: "1.5rem"
  measure: "70ch"
  measure-lede: "62ch"
  stack-2: "1.7rem"
  section-break: "3.6rem"
  home-bleed: "clamp(2.5rem, 6vw, 5.5rem)"
components:
  action-primary:
    backgroundColor: "{colors.storm-ink}"
    textColor: "{colors.paper-field}"
    rounded: "{rounded.none}"
    padding: "0.72rem 1.15rem"
  action-primary-hover:
    backgroundColor: "transparent"
    textColor: "{colors.storm-ink}"
    rounded: "{rounded.none}"
    padding: "0.72rem 1.15rem"
  action-quiet:
    backgroundColor: "transparent"
    textColor: "{colors.storm-ink}"
    rounded: "{rounded.none}"
    padding: "0.72rem 1.15rem"
  action-quiet-hover:
    backgroundColor: "{colors.storm-ink}"
    textColor: "{colors.paper-field}"
    rounded: "{rounded.none}"
    padding: "0.72rem 1.15rem"
  control-switch:
    backgroundColor: "transparent"
    textColor: "{colors.storm-ink}"
    typography: "{typography.nav}"
    rounded: "{rounded.none}"
    padding: "0.3rem 0.62rem"
  control-switch-hover:
    backgroundColor: "{colors.storm-ink}"
    textColor: "{colors.paper-field}"
    rounded: "{rounded.none}"
    padding: "0.3rem 0.62rem"
  rail-entry:
    backgroundColor: "transparent"
    textColor: "{colors.storm-ink}"
    typography: "{typography.body}"
    rounded: "{rounded.none}"
    padding: "0.32rem 0"
  rail-entry-hover:
    backgroundColor: "transparent"
    textColor: "{colors.storm-ink}"
    rounded: "{rounded.none}"
    padding: "0.32rem 0"
  code-plate:
    backgroundColor: "{colors.code-plate}"
    textColor: "{colors.code-plate-ink}"
    typography: "{typography.code}"
    rounded: "{rounded.none}"
    padding: "1.15rem 1.25rem"
  table-head:
    backgroundColor: "transparent"
    textColor: "{colors.rain-grey}"
    typography: "{typography.section}"
    padding: "0.6rem 0.85rem 0.6rem 0"
  content-card:
    backgroundColor: "transparent"
    textColor: "{colors.storm-ink}"
    rounded: "{rounded.none}"
    padding: "1.6rem 0 1.7rem"
  admonition:
    backgroundColor: "transparent"
    textColor: "{colors.storm-ink}"
    rounded: "{rounded.none}"
    padding: "1rem 1.2rem"
  admonition-mass:
    backgroundColor: "{colors.storm-ink}"
    textColor: "{colors.paper-field}"
    rounded: "{rounded.none}"
    padding: "1rem 1.2rem"
  boundary-band:
    backgroundColor: "{colors.storm-ink}"
    textColor: "{colors.paper-field}"
    rounded: "{rounded.none}"
    padding: "clamp(2.5rem, 5vw, 4rem) 1.5rem clamp(3rem, 6vw, 5rem)"
---

# Design System: OSEP Notes

## Overview

**Creative North Star: "Alphabet Storm"**

Letters condense into words, break into weather, and reshape the landscape according to grammar. The page is a paper-white field with no weather on it yet; the site's own type is the weather. A single monumental grotesk behaves as matter: it sets a headline at monumental scale, and the same letterforms lift off the page as drifting glyphs. Where the world needs weight it adds mass, where it needs hierarchy it adds scale, and where it needs a boundary it inverts the whole field to near-black. Nothing is a colour; everything is a density.

The palette is strictly achromatic. A storm-letter near-black carries body ink *and* weather mass — they are the same substance at different scales — while one rain grey marks grammar the reader has already spent and one silver marks a word caught mid-transformation. Force comes from mass, scale, and hairline contrast. There are no cards, no shadows, no rounded corners, and no gradients except two functional fades. Every container is a rule, not a box: a hairline says *this is grouped* and a firmer hairline says *this is a boundary*. Remove all the content and the page still reads as a weather chart — hairlines, letter-mass blocks, one dissolving line.

Rhythm is long-form and unhurried, because the reader is a practitioner working through dense technical prose for hours, often in low light: a 70ch measure, generous leading, and section breaks large enough that a front is visibly a new weather system. Motion is one word-weather event per view and nothing else; the type's loosened tracking is the settled state, visible with motion on or off, so the world survives `prefers-reduced-motion` with its identity intact. Depth is expressed as surface density (open field, dense plate, full mass) rather than as shadow, so the code plate is the densest object on any page and the inverted mass band is the loudest thing the system can say.

**Key Characteristics:**
- Strictly achromatic: near-black mass, rain grey, one silver, paper field — no hue anywhere, including focus and system UI.
- Hairline-only containers: 1px rules at `rgb(21 22 26 / 0.15)` and `rgb(21 22 26 / 0.4)`; no cards, no boxes, no corner radius (0 everywhere).
- One family for display and text (Archivo, variable 100–900 / 62–125% width), with Spline Sans Mono reserved for code and identifiers.
- Depth by density inversion, never by shadow: field → code plate → full-mass band.
- One word-weather event per view, readable text preserved throughout, and nothing at all under `prefers-reduced-motion`.
- Both self-hosted fonts, because the exam scene has no outside network and a CDN font is a broken font.

## Colors

Strictly achromatic. Four greys do all the work, and the differences between them are load-bearing.

### Primary

- **Storm Ink** (#15161a): The world's one accent, and it is not a colour — it is mass. It is the body ink, the weather mass, the pressed button, the active rail marker, the text selection, the focus ring, the code plate, and the inverted boundary band. Anywhere the design needs to be loud, this is the loudest thing available; anywhere it needs to be quiet, this is still the ink. One value, both jobs.

### Secondary

- **Rain Grey** (#63666c): Spent grammar and secondary voice. Used for ledes, conditions, table headers, rail labels, outline links, the scroll cue's source, list markers, and — the load-bearing case — a sidebar sheet the reader has already been through, so progress survives losing the colour. It passes 5.09:1 on the field, which is why it can carry whole paragraphs, not just chrome.
- **Silver Flash** (#7f8791): A word mid-transformation, and nothing else. It appears in exactly one place in the shipped build — the dissolving final word of the home headline — measured at 3.21:1 against the field. That is below AA for body text, and it is legitimate only because it is never body text: it is display type at 88px, and it is mid-disintegration by definition. Do not reach for it as a lighter grey.

### Neutral

- **Paper Field** (#f1f1ee): The ground in the light appearance. It is both the page background and the nav, sidebar, aside, search, and code-adjacent surfaces — one field, not a stack of layered panels.
- **Hairline Rule** (`rgb(21 22 26 / 0.15)`): The default container. Dividers, table row rules, inline-code outlines, search border, rail borders, sidebar edge.
- **Hairline Firm** (`rgb(21 22 26 / 0.4)`): The boundary hairline. Blockquote left rule, admonition outline, table header rule, and the default outline of the small controls in the nav.
- **Code Plate Ink** (#e9e7e1) and **Code Plate Rain** (#8d9199): The two inks that live only inside the near-black code plate — 14.62:1 and 5.72:1 respectively, so the plate reads as a lit page rather than a hole.
- **Scroll Cue** (`rgb(21 22 26 / 0.22)`): The gradient source for the table overflow shadows, guarded by opaque field-coloured covers.

The dark appearance swaps the same roles rather than adding new ones: field `#0f1013`, mass `#edece7`, rain `#9a9ea6`, silver `#6b7280`, hair `rgb(237 236 231 / 0.16)`, hair-firm `rgb(237 236 231 / 0.42)`, code plate `#07080a` (darker than the field, which is why the night plate takes a hairline edge while the light one does not), plate ink `#dcdee2`, plate rain `#7c8189`, scroll cue `rgb(0 0 0 / 0.55)`. Every pair clears AA for its role: mass 16.08:1, rain 7.08:1, plate ink 14.87:1, plate rain 5.11:1.

### Named Rules

**The No-Hue Rule.** No hue anywhere, in either appearance, on any surface, in any state. Mass, scale, and hairline contrast carry all hierarchy and all emphasis. A chromatic accent — error red, links blue, a tinted badge — is out of world, and so is a browser default focus ring or a tinted system scrollbar on a surface this world owns.

**The One Silver Rule.** Silver is used in exactly one place: the dissolving word in a monumental display line. It is a transformation state, never a text colour, never a hover state, and never a decorative tint. If a second use is considered, the answer is mass or rain grey.

**The Mass Inversion Rule.** Inverted mass (`#f1f1ee` on `#15161a`, 15.98:1) means exactly one thing: this is a boundary or a destructive branch. The code plate is the same mass, which is deliberate — code is the densest object in the system, and the authorized-use boundary and the warning/danger branches are its peers, not its children.

## Typography

**Display Font:** Archivo (variable, wght 100–900, wdth 62–125%; with system-ui, sans-serif)
**Body Font:** Archivo — the same face, lower down the weight axis
**Label/Mono Font:** Spline Sans Mono (variable, wght 300–700; with ui-monospace, SFMono-Regular, Menlo, monospace)

**Character:** One grotesk behaving as matter. Display and prose are the same family so that a headline and the paragraph beneath it are the same substance at different pressures; the difference between them is weight, width, scale, and tracking, never a second typeface. The mono is not a style choice — it marks the things a reader copies, types, or compares character by character: commands, identifiers, module numbers, scenario IDs, keyboard hints, and language tags on code plates. Both faces are self-hosted (latin + latin-ext woff2), because the exam scene has no outside network.

Width is a live axis, not a variant: display sets at 92% width with -0.035em tracking, the h1 at 96%, the h2 at 98%, and the nav title at 96% — the type physically narrows as it grows. Word-spacing is added at display scale (0.1em) because Archivo's own space is only 0.19em, which vanishes between uppercase letters.

### Hierarchy

- **Display** (800, `clamp(2.6rem, 7.4vw, 5.5rem)`, 0.94): The home headline only — three authored lines, uppercase, 92% width, -0.035em tracking, 0.1em word-spacing. Its final word dissolves into letter-mass.
- **Headline** (800, `clamp(1.95rem, 3.1vw, 2.75rem)`, 1.06): A module or page title. 96% width, -0.032em, balanced wrapping.
- **Title** (750, 1.52rem, 1.2): Every `h2`, i.e. every section front. 98% width, -0.022em, preceded by the fading hairline.
- **Section** (700, 0.72rem, 1.5, 0.13–0.15em, uppercase): The micro-rail: `h4`, admonition titles, table headers, sidebar group names, the field index title, the boundary label. This is the system's third voice — it labels, it never speaks.
- **Body** (430, 1.0625rem, 1.72, 70ch max; 62ch for an `h1 + p` lede): Technical prose. 430 is light enough to keep hours of reading comfortable and heavy enough to hold at low contrast.
- **Code** (400, 0.83rem, 1.7 in a plate; 0.84em inline at weight 500): The mono, on the densest surface in the system. Inline code takes an outline rather than a tint, so it stays legible inside a mass-inverted admonition.
- **Label** (500, 0.66rem, 0.14em, uppercase): The language tag on a code plate — the only mono micro-label in the system.
- **Nav** (600, 0.8rem, 0.1em, uppercase): Top-bar menu items and the control cluster; the site title runs at 1.06rem/800/96% width.
- **Rail** (400, 0.84rem, 1.45): The on-this-page outline, and the smallest reading text in the system.

### Named Rules

**The One Family Rule.** Display and text are Archivo. Code and identifiers are Spline Sans Mono. There is no third face, no serif, no display cut, and no glyph or symbol font. Hierarchy is built from weight, width, scale, tracking, and case — never from adding a family.

**The Readable Text Rule.** No motion, effect, or state in this system may reduce legibility of text the reader is meant to read: prose holds a 70ch measure, 1.0625rem minimum, 1.72 leading, and no tracking games. The one place contrast dips below AA is the silver dissolving word, and that is display type, not prose.

**The Self-Hosted Font Rule.** Every face ships as a woff2 in `docs/.vitepress/theme/fonts/` with a latin and a latin-ext file and an explicit `unicode-range`. A CDN font is a broken font: the exam scene has no outside network, and a missing face falls back to a system grotesk that is not this world.

## Layout

One open field, one reading column, and a rail. The shell is 1560px wide at most; inside it a document holds to 768px of content, with a 270px sidebar on the left and a 230px aside on the right. The whole layout is single-column reading — there is no multi-column prose, no card grid on a reading page, and no centered hero.

The home page is the one compositional exception, and it is a landscape rather than a menu: a two-column field (`minmax(0, 1.75fr)` against a `minmax(15rem, 0.8fr)` index) whose left side is the monumental statement and whose right side is the field index — the entire body of material as one hairline rail, visible before any scrolling. Below it the taxonomy lays out as fronts: each front is a two-column strip (`minmax(9rem, 20%)` for the front's name against the entries), entries flowing into `repeat(auto-fill, minmax(15rem, 1fr))`. The page closes on a full-bleed mass band carrying the authorized-use boundary.

Rhythm is density-scaled rather than uniform: 1px hairlines are the only dividers; list and rail rows sit on 0.32–0.34rem of vertical padding; related blocks stand 1.7rem apart; a section front opens 3.6rem after the previous material with 1.15rem between its hairline and its title; the home field breathes on `clamp(2.5rem, 6vw, 5.5rem)` and the boundary band on `clamp(2.5rem, 5vw, 4rem)` / `clamp(3rem, 6vw, 5rem)`. Wide tables keep a 620px minimum and scroll horizontally rather than wrapping or breaking identifier tokens; prose gets `overflow-wrap: break-word` while table cells and code keep `word-break: normal` so `m12-delegation-attacks.ps1` and `AllowedToAct` never split mid-token.

Breakpoints are only three, and each one removes a rail rather than shrinking type: below 960px the sidebar and aside collapse and the content container goes full width, the home hero becomes a single column, and the home field tightens its top padding; below 720px a front becomes a single column with its name above its entries. Reading text never changes size across breakpoints.

### Named Rules

**The One Column Rule.** A reading page has exactly one column of prose at a 70ch measure. Multi-column prose, card grids, side-by-side comparisons, and centered marketing arrangements are not part of how this world lays out a page. A second column is only ever a rail.

**The Fading Hairline Rule.** Every horizontal division loses ink as it runs out: `h2::before` goes mass → 0.4 → 0.15 → transparent across its length, and the horizontal rule does the same over 30%. A rule is a front passing over the page, not a box edge. Use the fade for divisions inside a page; keep the firm 0.4 hairline for boundaries around content.

## Elevation & Depth

There are no shadows in this system. Not at rest, not on hover, not on focus, not as a focus ring. The only `box-shadow` declarations in the shipped stylesheet are `none !important` overrides that delete VitePress's own shadows from search and keyboard-hint chrome.

Depth is conveyed by density inversion instead, in three tiers: the **open field** (`#f1f1ee`, the page itself), the **dense plate** (`#15161a` — code, the densest object on any page, and at night an edge hairline because the plate goes darker than the field rather than lighter), and the **full mass band** (the authorized-use boundary and the warning/danger admonitions, where the field inverts to paper-white on near-black). A reader never wonders what is on top of what, because nothing is on top of anything; the question the system answers instead is *how much matter is here*.

Everything else is a hairline: 0.15 for a grouping, 0.4 for a boundary, a 0.34rem square for a position mark, and a 1px reading-progress line pinned under the top bar. Focus is an outline, never a glow — 2px solid mass at 2px offset, square corners.

### Named Rules

**The Density Rule.** Depth is density, not elevation. Something is "higher" only because it is darker, bolder, or more inked — never because it floats, blurs, or casts. A new surface earns depth by choosing a tier (field, plate, mass), not by acquiring a shadow.

**The Gradient Ban.** Gradients are banned except for two functional fades, both achromatic, both serving overflow or division: the hairline that fades out beneath a section title, and the table scroll shadows (a field-coloured cover travelling with the content, plus a scroll-cue radial that appears only on a side that still has content). A decorative gradient, a coloured overlay, or a gradient as a text fill is out of world.

## Shapes

The form language is the square. Corner radius is 0 everywhere and is not a per-component decision: buttons, controls, search, code plates, inline code, admonitions, pager links, tables, and the focus outline all take `border-radius: 0`, and the stylesheet restates it in each place because VitePress ships rounded defaults — the guard is the rule, not the inheritance. Where VitePress ships a rounded pill — the appearance switch, the search key hints, the pager — the build overrides that radius to 0 and, for the appearance switch, replaces the control with one built in this vocabulary.

There are no cards and no boxes: a container is a horizontal or vertical hairline, and content is grouped by proximity and by rule rather than by enclosure. Border weight carries meaning: 0.15 hairline for grouping, 0.4 hairline for boundary, 1px solid mass for an inverted edge (table top rule, code plate at night, search shell, active rail marker). The system's only other geometry is the square mark: a solid 0.34rem square for the current position, a hollow 0.3rem square for a spent sheet, and a hollow 0.34rem square in the field index — the system's one place where a mark is drawn rather than inked.

### Named Rules

**The Square-Corner Rule.** Radius is 0. Everywhere. There is no `rounded` exception and no "just this once" pill; if a component arrives with a radius, the radius is removed, not tolerated. A mark may be a small square, but nothing gets rounded.

**The Rule-Not-Box Rule.** Containers are rules. If a group of content seems to need a box, it needs a hairline and more space instead. Enclosure by border is reserved for the two cases where the boundary itself is the message: the mass-inverted band and the admonition outline.

## Components

### Buttons

- **Shape:** Square (0 radius), 1px border in mass (quiet) or a solid mass fill (primary), 0.72rem × 1.15rem padding, 0.78rem/700 uppercase text at 0.1em tracking.
- **Primary:** Filled storm ink with paper-white text ("Open scenario map"). On hover it empties to transparent with mass text — the inverse of the quiet variant's hover.
- **Secondary / Quiet:** Transparent with a mass hairline and mass text ("Establish the lab baseline"). On hover it fills with mass and inverts its text to the field.
- **Hover / Focus:** Colour and background swap in 160ms ease-out. Focus is a 2px solid mass outline at 2px offset, square.
- **Note:** The two variants are inverses of each other, so no button carries a second accent: the whole vocabulary is filled and unfilled.

### Chips

None. The system has no chip, tag, badge, or pill. A status is a hairline square, a hairline rule, or an inverted band — never a rounded token with a tint.

### Cards / Containers

- **Corner Style:** None (0 radius); there are no cards in this system.
- **Background:** Transparent, or one of the three density tiers (field, code plate, mass band).
- **Shadow Strategy:** None — see Elevation & Depth.
- **Border:** 1px hairline (0.15 grouping, 0.4 boundary), or a 1px solid mass top rule for a table.
- **Internal Padding:** 1.15rem × 1.25rem for a code plate, 1rem × 1.2rem for an admonition, 0.5rem vertical for a rail row.

### Inputs / Fields

- **Style:** The search control is a transparent square with a 0.15 hairline border, uppercase-free 0.82rem placeholder text, and keyboard hints drawn as mono glyphs in a 0.15 hairline box at 0 radius.
- **Focus:** Border shifts to solid mass. Focus rings stay the system's 2px mass outline.
- **Error / Disabled:** No error styling exists, because the only input is search. A disabled control recedes to rain grey with a `progress` cursor (the language control while a weather event runs). A reader with storage disabled simply gets no spent-sheet marking; nothing is disabled as a result.

### Navigation

- **Top bar:** Field background with a single 0.15 hairline along the bottom, no blur and no shadow. The site title is 1.06rem/800 at 96% width, uppercase, 0.14em word-spacing. Menu links are 0.8rem/600 uppercase at 0.1em tracking, mass at rest and rain grey on hover or active.
- **Controls (signature):** The built-in appearance pill and translations menu are removed and replaced by a cluster of two square hairline controls that name what they will switch *to*: the language control ("中文" / "English") and the appearance control ("Dark" / "Light"). Both are 0.78rem/600, 0.3rem × 0.62rem, 0.4 hairline border, and fill with mass on hover. The language control carries `lang` and an aria-label in the target language, and disables itself while the weather event runs.
- **Sidebar:** A 270px rail of letter-mass index, closed by a 0.15 hairline on its right edge. Group names are 0.72rem/700 uppercase at 0.14em, each group standing 1.6rem below the last; entry rows sit on 0.34rem of vertical padding. Entries are 0.94rem/430 with underline-on-hover; the active entry takes a 0.34rem mass square; a spent entry recedes to rain grey with a hollow square. Progress is communicated by shape as well as colour.
- **On-this-page rail:** A 0.15 hairline left edge with 0.84rem/400 links in rain grey; hover and active go to mass, and the active link takes weight 650.
- **Mobile:** The sidebar and aside collapse entirely below 960px; navigation is the top bar plus VitePress's own screen menu, restyled to the same uppercase/tracking vocabulary.

### Code Plate (signature)

The densest object in the system: a 0-radius near-black plate (`#15161a` light, `#07080a` dark) with paper-white ink at 0.83rem/1.7 on a 1.15rem × 1.25rem padding. The language tag is the system's only mono micro-label — 0.66rem/500 uppercase at 0.14em in plate-rain, pinned top-right. Code never wraps and scrolls horizontally; line-highlight and the copy button work in translucent white rather than a tint, and the button takes a 0.18 white hairline that firms to plate-ink on hover. At night the plate gains a 0.15 hairline edge, because it sits darker than the field instead of lighter.

### Reference Table (signature)

The system's densest *reading* form, and the reason tables are load-bearing here: a 620px minimum width that scrolls rather than wraps, a 1px solid mass top rule, 0.15 hairlines between rows, and no vertical borders at all. Headers are 0.68rem/700 uppercase at 0.12em in rain grey over a 0.4 hairline. The first column is monospaced with `tabular-nums`, because it is usually an identifier; the rest is Archivo at 0.88rem. Cells never break a token. Overflow is signalled by the two-layer scroll shadow described in the Gradient Ban, and the marker wraps tables at runtime so authored Markdown stays plain.

### Admonitions (signature)

VitePress custom blocks, restyled as fronts rather than coloured boxes — there is no hue to tint them with, so weight does the work. Tip, info, and details are transparent with a 0.15 hairline and a 0.72rem/700 uppercase title. Warning and danger invert completely: mass fill, field text, including links and bold, because they are the system's boundary voice. Both carry a 1rem × 1.2rem padding and a 68ch inner measure, and inline code keeps its outline so it stays readable on the mass ground.

### Sheet Meta (signature)

The rail block that says which sheet the reader is on: the module number in mono at 1.5rem with `tabular-nums` and line-height 1, the front's name below it at 0.72rem/600 uppercase in rain grey, then a definition list of the scenario identifiers printed in that sheet — read from the sheet's own tables at runtime, so the rail can never claim a scenario the page does not carry. The block closes on a 0.15 hairline.

### Reading Meter

A 1px mass line pinned under the top bar, scaled horizontally from the left to the reader's position in the article. It is `aria-hidden` and it is linear — 90ms linear transform, the system's one mechanical, un-eased transition, because it reports position rather than performing it.

### Field Index (home)

The whole body of material as one rail: a 1px solid mass top rule, a rain-grey 0.68rem/700 uppercase title over a 0.15 hairline, then one row per front between 0.15 hairlines — the front's name at 0.94rem/550 against the module numbers it holds, in mono at 0.72rem with tabular numerals and 0.06em tracking. Hover recedes the name to rain grey; the whole rail is anchor links into the fields below.

## Do's and Don'ts

### Do:

- **Do** keep every surface strictly achromatic. If a new state needs emphasis, spend mass, scale, or a firmer hairline — never a hue.
- **Do** reach for the three density tiers first: open field, dense plate (`#15161a`), full mass band. They are the system's entire depth vocabulary.
- **Do** use hairline rules (0.15 for grouping, 0.4 for a boundary) instead of boxes, cards, and enclosures.
- **Do** set display and body in Archivo, and reach for Spline Sans Mono only for what a reader copies, types, or compares: commands, identifiers, module numbers, scenario IDs, keyboard hints, plate language tags.
- **Do** keep prose at a 70ch measure, 1.0625rem, 1.72 leading, and set display type at 92% width with -0.035em tracking and 0.1em word-spacing so uppercase lines do not collide.
- **Do** self-host both faces as latin + latin-ext woff2 with explicit `unicode-range`, and keep the CJK fallback chain behind Archivo.
- **Do** preserve the readable text through any weather event, allow one event per view, cap it in both particle count and time, and stop the frame loop when it settles.
- **Do** ship `prefers-reduced-motion: reduce` as a real alternative: no particles at all, and the loosened silvered tracking as the settled static state so the world still reads.
- **Do** carry state by weight and shape as well as colour — a bolded entry plus a filled square for current, a hollow square for spent — so nothing depends on grey alone.
- **Do** keep tokens square: `border-radius: 0` restated on every component, even where it looks redundant.

### Don't:

- **Don't** introduce a hue anywhere: no accent colour, no error red, no link blue, no tinted badge, no coloured gradient, no coloured shadow. This includes the browser's default focus ring and system scrollbars on surfaces this world owns.
- **Don't** use silver (`#7f8791` / `#6b7280`) as a text colour or a hover state. It is the transformation flash in the dissolving display word, and it is used in exactly one place.
- **Don't** use shadows, glows, blurs, or `backdrop-filter` for depth, and don't let a hover lift an element. Depth is density.
- **Don't** round a corner, and don't let an imported component keep its radius, pill, or rounded control. Restyle the control in this vocabulary instead.
- **Don't** enclose content in a card, and don't introduce a second accent to distinguish variants — the button vocabulary is filled and unfilled, nothing more.
- **Don't** add a third typeface, a serif, or a glyph/symbol icon font. Marks are drawn as squares and hairlines.
- **Don't** use a gradient decoratively; only the section-title hairline fade and the table overflow scroll shadows are permitted, and both are achromatic.
- **Don't** reduce reading text below 1.0625rem, and don't trade legibility for a motion effect — nothing in the system may make a line harder to read while it moves.
- **Don't** add a second motion vocabulary. Ease-out colour and border swaps (140–160ms) and the single weather event are the whole set; a bouncy, springy, or looping animation is out of world.
- **Don't** fabricate identifiers, counts, or status to fill a rail. Sheet meta reads the page's real taxonomy and real table contents, and shows nothing when there is nothing.
