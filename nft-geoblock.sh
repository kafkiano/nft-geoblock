#!/usr/bin/env bash
#
# nft-geoblock.sh -- load country IP blocks into an nftables set.
#
# usage: nft-geoblock.sh [-n name] [-p ports] [-w] [-s] [-d] CC [CC ...]
#
#   -n name   table and set name (default: geoip)
#   -p ports  comma-separated ports/ranges, e.g. "80,443" or "1000-2000"
#   -w        whitelist mode (default: blacklist)
#   -s        unsafe: allow SSH (22) to be filtered
#   -d        dry-run: print ruleset to stdout, do not apply
#   CC        two-letter country codes, e.g. DE ES FR
#
# Port 22 (SSH) is protected by default:
#   with -p:     port 22 is rejected in the port list
#   without -p:  an SSH exemption (tcp dport 22 accept) is added
# The -s flag disables both protections, so SSH can be filtered like
# any other port (with -p) or be subject to the geoblock rule (without -p).

set -euo pipefail

PROG=${0##*/}
NAME=geoip
FAMILY=inet
HOOK=input
PRIORITY=mangle
WHITELIST=0
SSH_PROTECTED=1
DRY_RUN=0
PORTS=""
TMP_RULES=$(mktemp)

usage() {
    cat >&2 <<EOF
usage: $PROG [-n name] [-p ports] [-w] [-s] [-d] CC [CC ...]

  -n name   table and set name (default: geoip)
  -p ports  comma-separated ports/ranges, e.g. "80,443" or "1000-2000"
  -w        whitelist mode (default: blacklist)
  -s        unsafe: allow SSH (22) to be filtered
  -d        dry-run: print ruleset to stdout, do not apply
  CC        two-letter country codes, e.g. DE ES FR

Port 22 (SSH) is protected by default: with -p it is rejected in the
port list, without -p an SSH exemption is added. -s disables both.
EOF
    exit 2
}

die() { echo "$PROG: $*" >&2; exit 1; }

while getopts 'n:p:wsdh' opt; do
    case $opt in
        n) NAME=$OPTARG ;;
        p) PORTS=$OPTARG ;;
        w) WHITELIST=1 ;;
        s) SSH_PROTECTED=0 ;;
        d) DRY_RUN=1 ;;
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

if (( DRY_RUN )); then
    cat "$TMP_RULES"
    exit 0
fi

nft -f "$TMP_RULES"

n=$(nft list set "$FAMILY" "$NAME" "$NAME" 2>/dev/null \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | wc -l)
echo "$NAME: $n entries"