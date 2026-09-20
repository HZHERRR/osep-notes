# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

The author: a security practitioner working through the OSEP (PEN-300) course material, sitting at
an attack machine (Kali) with one or more Windows targets in front of them. Two scenes matter:

1. **Study / lab.** Working a module, trying to get a technique to land on a target, needing the
   exact command, the prerequisite, and the failure branch without re-reading a whole chapter.
2. **Exam.** Open-book, time-boxed, no network to the outside world. Hunting for "which scenario
   covers this" and "what do I check first" in seconds, then copying a command.

A secondary audience is a small number of peers who read the same notes, including Chinese-speaking
readers who prefer the `zh` route. They read; they do not administer.

## Product Purpose

A scenario-driven technical field reference for authorized OSEP lab and exam work. It exists because
course material and cheat sheets are organized by tool, while real work is organized by the condition
you are stuck in. Success is a reader who finds the right procedure, the assumption it depends on,
and the failure branch in under a minute — during study, and under exam pressure.

## Positioning

Organized by **operating condition, not by tool**. Every module states the situation, the assumptions
that must hold, the smallest reversible procedure, how to validate it worked, and what to do when it
fails — followed by OPSEC notes. A tool-indexed cheat sheet cannot truthfully copy that structure,
because its unit is the command, not the condition.

## Operating Context

- Authorized lab ranges and the official exam environment only; the site states this boundary on
  every entry path.
- Kali attacker plus Windows domain targets; commands are copy-pasted into a terminal, often with
  placeholders (`LHOST`, `DOMAIN`, `USER`, `NTHASH`) substituted by hand.
- Long-form reading on a laptop, in a browser, frequently in low light and for hours at a time.
- Bilingual by construction: English at the root, Chinese under `/zh/`, mirrored structure.
- A working session is interrupted and resumed constantly; the reader arrives deep-linked into the
  middle of a module far more often than at the homepage.

## Capabilities and Constraints

Confirmed and non-negotiable:

- VitePress 1.6.4 static build, Vue theme extension, deployed to GitHub Pages under base
  `/osep-notes/` by a GitHub Actions workflow. No server runtime.
- English routes at `/`, Chinese routes under `/zh/`; both mirror the same module set. Clean URLs.
- Local (offline) search must keep working — the exam scene has no outside network.
- Light and dark appearance both ship; the site follows the OS by default.
- Content set: 00, 01–16, 97, 98, 99 modules, plus `scenarios` and `disclaimer`, each in both
  languages.
- Markdown stays the content format; the twenty module files are authored directly and must not be
  rewritten into another format.
- Admonitions, fenced code, and wide tables are load-bearing content types. Tables carry
  identifier-heavy cells (`m12-delegation-attacks.ps1`, `AllowedToAct`) that must not be broken
  mid-token; they may scroll.
- Dependencies stay minimal: no UI framework or component library is added for styling that the
  VitePress theme can express.

Open / undecided:

- The English module text is a mechanical translation of the Chinese source and is visibly broken in
  places. Content rewriting is **not** part of the visual redesign and is not authorized here; the
  design must survive it, and the issue is recorded for a separate decision.
- No analytics, comments, accounts, or telemetry, and none are being added.

## Brand Commitments

- Name: **OSEP Notes**. The authorized-use boundary is a fixed, first-class message, never fine
  print: authorized labs, the official exam, or systems with written authorization.
- Voice: operator-to-operator, plain, specific, unhyped. No marketing register, no gamification, no
  vanity metrics, no motivational copy.
- The existing visual identity (warm paper canvas, rust-orange accent, Geist Sans / Geist Mono) is
  **explicitly released by the user** and carries no authority over the next design.

## Evidence on Hand

- Real material: the twenty English and twenty Chinese module files, `scenarios`, `disclaimer`, and
  the sidebar taxonomy in `docs/.vitepress/config.mts`. This is the only content that may appear.
- Real structure: modules cluster as execution constraints (00–05, 16), privilege and credentials
  (06–07), pivot and access (08, 09, 15), services and directory (10–12), constrained systems
  (13–14), and exam operations (97–99).
- Absences that must not be fabricated: no user counts, no testimonials, no completion rates, no
  benchmark numbers, no certification claims, no endorsements by OffSec or anyone else.

## Product Principles

1. **Condition first.** Every surface answers "what situation am I in and what do I do next" before
   it demonstrates a technique.
2. **Findable under pressure.** The reader arrives mid-module and in a hurry; wayfinding beats
   ornament, and search must work with no network.
3. **Show the failure branch.** A procedure without its assumptions and its failure path is
   incomplete, and the design should give that material equal dignity with the happy path.
4. **Long-reading comfort is a feature.** Hours in front of dense technical prose and wide tables,
   often in low light; legibility and rhythm are functional requirements.
5. **Say the boundary out loud.** Authorized use is stated wherever a reader could otherwise mistake
   the material for general-purpose tooling.

## Accessibility & Inclusion

- Keyboard reachable navigation, a visible focus state on every interactive element, and a logical
  heading order.
- Both appearances meet WCAG AA for body text; nothing communicates state by color alone.
- `prefers-reduced-motion` is honored with an intentional alternative, not a global animation kill.
- Chinese routes read correctly with proper CJK font fallback, line breaking, and punctuation.
- Tested at roughly 390px, 768px, and 1280px and above, including a long table-heavy module.
