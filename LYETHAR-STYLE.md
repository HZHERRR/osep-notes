# Lyethar Methodology — writing style guide

Source: [lyethar.gitbook.io/methodology](https://lyethar.gitbook.io/methodology). Distilled from the intro, Engagement Strategy, and technique pages: [SMB Enumeration](https://lyethar.gitbook.io/methodology/readme/enumeration/smb-enumeration), [REDIS Exploitation](https://lyethar.gitbook.io/methodology/readme/exploitation/vulnerable-services/redis-exploitation), [SeImpersonatePrivilege](https://lyethar.gitbook.io/methodology/readme/privilege-escalation/windows/dangerous-privileges/seimpersonateprivilege), [Kerberoasting](https://lyethar.gitbook.io/methodology/readme/active-directory/exploitation/kerberoasting), plus Exploitation Methodology / SQL injection / SMBPass Change / ASREPRoast. Imitate the **phase judgment + command** skeleton and direct operator voice — not the typos, GIFs, or “congratulations” filler. Site is **English only**; do not keep a Chinese edition.

## Page skeleton

- H1 is the technique name (`SMB Enumeration`, `SeImpersonatePrivilege`), not a lecture title or “Scenario N” heading.
- Open with at most 1–3 sentences: what this is for, when it matters, or the entry paths. Skip theory if the title plus a command is enough (ASREPRoast is just the command).
- Put the decision next: which condition, which option first, what to do if it fails. Then the commands for that branch.
- Use action or tool headings (`Version Check`, `List`, `Connect`, `Brute Force`, `PrintSpoofer`, `Kerberoasting with Rubeus`) — never a generic `Steps` or `Overview`.
- Multi-step procedures are checklists (`- [ ] Generate payload` / `Transfer` / `Start listener` / `Execute`), not numbered essays.
- After a foothold or new creds, end the branch with the next phase cue: rerun enumeration against every service, or stabilize before privilege escalation.
- Link HackTricks, GitHub, or a known exploit repo instead of rewriting general reference material on the page.

## “When / if” decision phrasing

- Condition first, action second: `If SeImpersonatePrivilege is Enabled, start potato attacks.`
- State the default path and the fallback in the same breath: `If the machine is x64, try PrintSpoofer first — it is easier and needs no extra steps. If that fails, try JuicyPotato. If it is x86, go straight to JuicyPotato.`
- Name the fork, then work it: `There are three ways in: a vulnerable service, credential reuse / spray, or brute force. Identify which applies and work from there.`
- Missing info is still a decision: `If we have a version, searchsploit it. If we do not, fire all exploits and prioritize RCE.`
- Failures are inline if/then, not a formal symptom table: `If the exploit does not land, the reverse shell may be the problem — try nc, bash, python, and bash -c. Cycle allowed ports.`
- Prefer `If X, do Y. If that fails, do Z.` over “it is recommended” or “you should consider.”

## How to introduce a command

- One short cue, then a fenced block. The heading can be the only intro (`### Version Check` + command).
- Typical cues: `Enumerate with:`, `Authenticate with the following command:`, `Execute:` — then the fence. No preamble paragraph.
- Stack equivalent tools in one block; label variants with trailing `#` comments (`# Null user`, `# Creds`, `# Pass-the-Hash`).
- Use `<IP>`, `<DOMAIN/username:password>` placeholders, or one worked example with real paths when quoting or paths are fiddly — then say to edit accordingly.
- Show the exact syntax that made it work when it is non-obvious (quoting, `bash -c`, a required path). Do not dump a second explanation of the same command.

## What to cut

- Textbook explainers (`what is Kerberos`, long “three rules” preambles). One casual sentence is the cap.
- Formal scaffolding: `## Scenario N`, `### Steps`, Purpose / Dependencies / Usage / Test status docblocks, bilingual headings.
- Symptom/fix tables when a single if/then line covers it. Keep a short table only for a dense cheat-sheet lookup.
- Re-documenting material that is already in HackTricks or an upstream README — link it.
- Duplicate commands, celebration lines, and any Chinese copy of a page.

## Voice and balance

- Operator talking to a teammate: first-person plural `we` or imperative. Decisive, typo-clean English.
- Prose is the judgment; code is the work. Most pages are short cue + commands. Add a walkthrough only when the chain (Redis + LFI, CLSID cycling) needs it.

## Before → after

- “Macros are the most common OSEP initial-access path. Three rules: Probe first, deliver second…” → “If bitness is unknown, probe first — delivering a Runner on the wrong arch is a gamble.”
- “## Scenario 1: Bitness unknown, AV present / ### Steps / 1. Start the delivery server…” → “If Office bitness is unknown and AV is present:” then a checklist and the commands.
- “| No request in the delivery log | Doc never opened, or MotW / macro security blocked it… |” → “If there is no request in the delivery log, the doc never opened or MotW blocked it — try a zip, SMB share, legacy `.doc`, or `.xlsm`.”
- “The session lives in `WINWORD.EXE`. Stabilize **before** you bother with privilege escalation.” → “If closing Word kills the session, migrate or persist first — don’t start privilege escalation yet.”
- “Purpose: Delivery server — HTTP/HTTPS dual channel; … Scenario: Shared infrastructure… Dependencies: Python 3.7+…” → “Start the delivery server and watch the log:” then the command only.
