#!/usr/bin/env bash
#
# nft-geoblock.sh -- load country IP blocks into an nftables set.
#
# usage: nft-geoblock.sh [-n name] [-p ports] [-w] [-s] CC [CC ...]
#
#   -n name   table and set name (default: geoip)
#   -p ports  comma-separated ports/ranges, e.g. "80,443" or "1000-2000"
#   -w        whitelist mode (default: blacklist)
#   -s        unsafe: allow SSH (22) to be filtered
#   CC        two-letter country codes, e.g. DE ES FR
#
# Port 22 (SSH) is protected by default:
#   with -p:     port 22 is rejected in the port list
#   without -p:  an SSH exemption (tcp dport 22 accept) is added
# The -s flag disables both protections, so SSH can be filtered like
# any other port (with -p) or be subject to the geoblock rule (without -p).
#
# Port 80 (HTTP-01) is protected when certbot is present:
#   if port 80 is affected by the rule (no -p, or -p list/range covers
#   80) and certbot / /etc/letsencrypt is detected, renewal hooks are
#   written to /etc/letsencrypt/renewal-hooks/{pre,post} that temporarily
#   insert an "accept" rule above the geoblock rule during renewal.

set -euo pipefail

PROG=${0##*/}
NAME=geoip
FAMILY=inet
HOOK=input
PRIORITY=mangle
WHITELIST=0
SSH_PROTECTED=1
PORTS=""
TMP_RULES=$(mktemp)

usage() {
    cat >&2 <<EOF
usage: $PROG [-n name] [-p ports] [-w] [-s] CC [CC ...]

  -n name   table and set name (default: geoip)
  -p ports  comma-separated ports/ranges, e.g. "80,443" or "1000-2000"
  -w        whitelist mode (default: blacklist)
  -s        unsafe: allow SSH (22) to be filtered
  CC        two-letter country codes, e.g. DE ES FR

Port 22 (SSH) is protected by default: with -p it is rejected in the
port list, without -p an SSH exemption is added. -s disables both.

If port 80 is affected and certbot is installed, Let's Encrypt renewal
hooks are written so HTTP-01 challenges are not blocked.
EOF
    exit 2
}

die() { echo "$PROG: $*" >&2; exit 1; }

while getopts 'n:p:wsh' opt; do
    case $opt in
        n) NAME=$OPTARG ;;
        p) PORTS=$OPTARG ;;
        w) WHITELIST=1 ;;
        s) SSH_PROTECTED=0 ;;
        h) usage ;;
        ?) usage ;;
    esac
done
shift $((OPTIND - 1))

[[ $# -ge 1 ]] || usage
[[ $EUID -eq 0 ]] || die "must be run as root"
command -v nft  >/dev/null || die "nft not installed"
command -v curl >/dev/null || die "curl not installed"

trap 'rm -f "$TMP_RULES"' EXIT

# Reject port 22 anywhere in the list (also inside ranges like 20-30)
# unless -s was given.
validate_ports() {
    local ports="$1" p lo hi
    local IFS=','
    for p in $ports; do
        p=${p// /}
        if [[ $p =~ ^([0-9]+)-([0-9]+)$ ]]; then
            lo=${BASH_REMATCH[1]}; hi=${BASH_REMATCH[2]}
            if (( lo < 1 || hi > 65535 || lo > hi )); then
                die "invalid port range: $p"
            fi
            if (( SSH_PROTECTED )) && (( lo <= 22 && 22 <= hi )); then
                die "port 22 (SSH) in range '$p' must not be filtered (use -s to override)"
            fi
        elif [[ $p =~ ^[0-9]+$ ]]; then
            if (( p < 1 || p > 65535 )); then
                die "invalid port: $p"
            fi
            if (( SSH_PROTECTED )) && (( p == 22 )); then
                die "port 22 (SSH) must not be filtered (use -s to override)"
            fi
        else
            die "invalid port spec: $p"
        fi
    done
}

# True if the port spec contains 80 (individually or inside a range).
port_spec_has_80() {
    local ports="$1" p lo hi
    local IFS=','
    for p in $ports; do
        p=${p// /}
        if [[ $p =~ ^([0-9]+)-([0-9]+)$ ]]; then
            lo=${BASH_REMATCH[1]}; hi=${BASH_REMATCH[2]}
            (( lo <= 80 && 80 <= hi )) && return 0
        elif [[ $p =~ ^[0-9]+$ ]]; then
            (( p == 80 )) && return 0
        fi
    done
    return 1
}

# True if the geoblock rule touches port 80 at all:
#   - no -p (all ports matched) -> yes
#   - -p given and 80 in list/range -> yes
port_80_affected() {
    [[ -z $PORTS ]] && return 0
    port_spec_has_80 "$PORTS"
}

# True if both renewal hooks exist and reference the current table.
certbot_hooks_up_to_date() {
    local dir=/etc/letsencrypt/renewal-hooks
    local pre="$dir/pre/01-open-port-80"
    local post="$dir/post/01-close-port-80"
    [[ -f $pre && -f $post ]] \
        && grep -qF "list chain $FAMILY $NAME input" "$pre" \
        && grep -qF "list chain $FAMILY $NAME input" "$post"
}

# Write certbot renewal hooks that temporarily accept port 80 during
# HTTP-01 challenges. Writes the hooks only if they are missing or
# reference a different table/set.
install_certbot_hooks() {
    local dir=/etc/letsencrypt/renewal-hooks
    local pre="$dir/pre/01-open-port-80"
    local post="$dir/post/01-close-port-80"

    if certbot_hooks_up_to_date; then
        echo "$PROG: certbot renewal hooks already present, skipping" >&2
        return 0
    fi

    mkdir -p "$dir/pre" "$dir/post"

    # pre: remove stale accept rules (from aborted previous runs),
    #      then insert a fresh accept rule above the geoblock rule.
    cat > "$pre" <<EOF
#!/usr/bin/env bash
# Auto-generated by $PROG -- do not edit by hand.
set -uo pipefail
handles=\$(nft -a list chain $FAMILY $NAME input 2>/dev/null \\
    | grep -F 'Certbot HTTP-01 Challenge' \\
    | grep -oE 'handle [0-9]+' \\
    | awk '{print \$2}') || true
for h in \$handles; do
    nft delete rule $FAMILY $NAME input handle "\$h" 2>/dev/null || true
done
nft insert rule $FAMILY $NAME input tcp dport 80 counter accept \\
    comment '"Certbot HTTP-01 Challenge"'
EOF
    chmod 0755 "$pre"

    # post: remove every accept rule carrying our comment.
    cat > "$post" <<EOF
#!/usr/bin/env bash
# Auto-generated by $PROG -- do not edit by hand.
set -uo pipefail
handles=\$(nft -a list chain $FAMILY $NAME input 2>/dev/null \\
    | grep -F 'Certbot HTTP-01 Challenge' \\
    | grep -oE 'handle [0-9]+' \\
    | awk '{print \$2}') || true
for h in \$handles; do
    nft delete rule $FAMILY $NAME input handle "\$h" 2>/dev/null || true
done
EOF
    chmod 0755 "$post"

    echo "$PROG: installed certbot renewal hooks" \
         "($pre, $post)" >&2
}

# Build port match and (optional) SSH exemption.
if [[ -n $PORTS ]]; then
    validate_ports "$PORTS"
    PORT_MATCH="tcp dport { $PORTS } "
    SSH_EXCEPTION=""
else
    PORT_MATCH=""
    if (( SSH_PROTECTED )); then
        SSH_EXCEPTION="tcp dport 22 accept"
    else
        SSH_EXCEPTION=""
    fi
fi

# Verdict applied by the rule that references the set.
if [[ $WHITELIST -eq 1 ]]; then
    VERDICT=accept
else
    VERDICT=drop
fi

{
    echo "add table $FAMILY $NAME"
    echo "add set   $FAMILY $NAME $NAME { type ipv4_addr; flags interval; }"
    echo "add chain $FAMILY $NAME input { type filter hook $HOOK priority $PRIORITY; policy accept; }"
    echo "flush chain $FAMILY $NAME input"
    echo "flush set   $FAMILY $NAME $NAME"

    for cc in "$@"; do
        cc=${cc^^}
        if [[ ! $cc =~ ^[A-Z]{2}$ ]]; then
            echo "$PROG: invalid CC: $cc" >&2
            continue
        fi
        if ! curl -fsSL "https://www.ipdeny.com/ipblocks/data/countries/${cc,,}.zone" \
            | awk -v f="$FAMILY" -v t="$NAME" -v s="$NAME" \
              '/^[0-9]/{print "add element " f " " t " " s " { " $1 " }"}'; then
            echo "$PROG: download failed: $cc" >&2
        fi
    done

    if [[ -n $SSH_EXCEPTION ]]; then
        echo "add rule $FAMILY $NAME input $SSH_EXCEPTION"
    fi

    # Set lookup; the verdict is part of the rule, not the element.
    # ct state new ensures established flows (including replies to
    # locally initiated sessions) are not disturbed by the drop.
    # In whitelist mode a trailing drop catches non-matching sources.
    echo "add rule $FAMILY $NAME input ${PORT_MATCH}ip saddr @$NAME ct state new $VERDICT"
    if [[ $WHITELIST -eq 1 ]]; then
        echo "add rule $FAMILY $NAME input ${PORT_MATCH}ct state new drop"
    fi
} > "$TMP_RULES"

entries=$(awk '/^add element /{n++} END{print n+0}' "$TMP_RULES")
if (( entries == 0 )); then
    die "no entries collected"
fi

nft -f "$TMP_RULES"

if port_80_affected; then
    if command -v certbot >/dev/null 2>&1 || [ -d /etc/letsencrypt ]; then
        install_certbot_hooks
    else
        echo "$PROG: note: port 80 is affected but certbot was not" \
             "detected; skipping renewal hooks" >&2
    fi
fi

n=$(nft list set "$FAMILY" "$NAME" "$NAME" 2>/dev/null \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | wc -l)
echo "$NAME: $n entries"
