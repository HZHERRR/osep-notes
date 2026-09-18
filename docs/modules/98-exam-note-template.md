::: warning Authorized use only
:::

# 98 · Note template

Write as you go. The report has to be reproducible.

## Running log

| Time | Host | Entry | Action | Result | Artifact |
|---|---|---|---|---|---|
| 09:12 | web01 | ASPX | whoami | iis apppool | `loot/web01-whoami.txt` |

Log failures too: why you think it failed, what you try next.

## Per-host

```markdown
### TARGET

Time:
Role: entry / pivot / objective
Entry:
Identity:
whoami /priv:

#### What you saw
-

#### Steps
| Step | Command | Output | OK? |
|---|---|---|---|
| 1 | | | |

#### If it failed
| Try | Symptom | Call | Next |
|---|---|---|---|

#### For the report
Issue / impact / fix:
```
