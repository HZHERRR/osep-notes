::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 98 · Exam log and report template

> OSEP requires a penetration test report, and grading also looks at whether the process is reproducible. **Log as you go** — do not write it up afterwards.
>
> How to use it: every time you enter a scenario, copy the “per-scenario record template” and paste it into your notes (Obsidian, Notion, or plain text, all fine).

---

## 1. Running log (the whole exam)

| Time | Target | Entry | Scenario # | Action | Result | Artifact |
|---|---|---|---|---|---|---|
| 09:12 | web01 | ASPX upload | 14 | Upload trimmed ASPX, verify whoami | Success, iis apppool | `loot/web01-whoami.txt` |
| 09:35 | web01 | same as above | 26 | SeImpersonate → PrintSpoofer | Failed: spooler service stopped | Logged under scenario 26 failure branch |
| 09:48 | web01 | same as above | 26 | Switch to SigmaPotato, in-memory load | Success, SYSTEM | `loot/web01-system.txt` |

**Discipline**: log a line for every failure too, and write down “why I think it failed + what I try next”. This stretch is the most convincing part of the report.

---

## 2. Per-scenario record template

```markdown
### Scenario N: <title>

**Time**: HH:MM
**Target**: TARGET (role: entry / pivot / final objective)
**Entry**: <Word macro / HTA / ASPX / WinRM ...>
**Initial identity**: <user / service account / domain user>
**Initial privileges**: <whoami /priv summary>

#### 1. Symptom and call
- Observed:
- Judged this is scenario N because:
- Ruled out:

#### 2. Prepared assets (scripts/payloads ready before the exam)
- `...`: purpose

#### 3. Execution
| Step | Command (reproducible) | Output highlights | OK? |
|---|---|---|---|
| 1 | `...` | `...` | ✓/✗ |

#### 4. Key artifacts
- Credentials:
- Hashes/tickets:
- Sessions:
- Files:

#### 5. Failure branch log
| Attempt | Failure symptom | Why I think so | Next step |
|---|---|---|---|

#### 6. Final result
- Access gained:
- Next hop:

#### 7. Report points (written for the reviewer)
- What the vulnerability/misconfiguration is:
- Impact:
- Fix recommendation (one sentence is enough):
```

---

## 3. Suggested report structure (per common OSEP requirements)

```text
1. Executive summary
   - Objectives met, timeline, key privilege-escalation path (one sentence, one diagram)
2. Scope and methodology
   - Authorization statement, target list, time window
3. Attack path (one chapter per host)
   - Host X: initial access → privilege escalation → lateral movement → evidence
   - Every step: command + output screenshot/text + why it works
4. Findings (by severity)
   - Issue description / reproduction steps / evidence / impact / fix recommendation
5. Appendix
   - Full command list, script list, credentials and hashes (redacted), timeline
```

---

## 4. Things that are easy to miss while logging

- [ ] The **complete output** of every command (do not just write “it worked”)
- [ ] Timestamps (the report timeline needs them)
- [ ] Bitness and OS version (this decides payload form)
- [ ] Failed attempts (the reviewer reads how you troubleshot)
- [ ] Where each credential came from (which machine, which file, which dump)
- [ ] The session’s initial process and user (you will compare against it after migration)

---

## 5. How this relates to the other docs

| Doc | Purpose |
|---|---|
| [97-exam-day-lookup](/modules/97-exam-day-lookup) | Symptom → scenario quick lookup |
| [99-pre-exam-checklist](/modules/99-pre-exam-checklist) | Item-by-item check of pre-exam assets |
| [00-environment-and-infra](/modules/00-environment-and-infra) | Attacker box and infrastructure |
| This file | Logging during the exam and the final report |
