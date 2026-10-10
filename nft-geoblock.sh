#!/usr/bin/env bash
#
# nft-geoblock.sh -- load country IP blocks into an nftables verdict map.
#
# usage: nft-geoblock.sh [-n name] [-p ports] [-w] CC [CC ...]
#
#   -n name   table and map name (default: geoip)
#   -p ports  comma-separated ports/ranges, e.g. "80,443" or "1000-2000"
#   -w        whitelist mode (default: blacklist)
#   CC        two-letter country codes, e.g. DE ES FR
#
# Port 22 (SSH) can never be filtered: without -p it is auto-exempted,
# with -p any occurrence of 22 aborts the script.

set -euo pipefail

PROG=${0##*/}
NAME=geoip
FAMILY=inet
HOOK=input
PRIORITY=mangle
WHITELIST=0
PORTS=""
TMP_RULES=$(mktemp)

usage() {
    cat >&2 <<EOF
usage: $PROG [-n name] [-p ports] [-w] CC [CC ...]

  -n name   table and map name (default: geoip)
  -p ports  comma-separated ports/ranges, e.g. "80,443" or "1000-2000"
  -w        whitelist mode (default: blacklist)
  CC        two-letter country codes, e.g. DE ES FR

Port 22 (SSH) is never filtered.
EOF
    exit 2
}

die() { echo "$PROG: $*" >&2; exit 1; }

while getopts 'n:p:wh' opt; do
    case $opt in
        n) NAME=$OPTARG ;;
        p) PORTS=$OPTARG ;;
        w) WHITELIST=1 ;;
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

# Reject port 22 anywhere in the list (also inside ranges like 20-30).
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
            if (( lo <= 22 && 22 <= hi )); then
                die "port 22 (SSH) in range '$p' must not be filtered"
            fi
        elif [[ $p =~ ^[0-9]+$ ]]; then
            if (( p < 1 || p > 65535 )); then
                die "invalid port: $p"
            fi
            if (( p == 22 )); then
                die "port 22 (SSH) must not be filtered"
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
    SSH_EXCEPTION="tcp dport 22 accept"
fi

# In whitelist mode map elements carry :accept, otherwise :drop.
if [[ $WHITELIST -eq 1 ]]; then
    VERDICT=accept
else
    VERDICT=drop
fi

{
    echo "add table $FAMILY $NAME"
    echo "add map   $FAMILY $NAME $NAME { type ipv4_addr : verdict; flags interval; }"
    echo "add chain $FAMILY $NAME input { type filter hook $HOOK priority $PRIORITY; policy accept; }"
    echo "flush chain $FAMILY $NAME input"
    echo "flush map $FAMILY $NAME $NAME"

    for cc in "$@"; do
        cc=${cc^^}
        if [[ ! $cc =~ ^[A-Z]{2}$ ]]; then
            echo "$PROG: invalid CC: $cc" >&2
            continue
        fi
        curl -fsSL "https://www.ipdeny.com/ipblocks/data/countries/${cc,,}.zone" \
            | awk -v f="$FAMILY" -v t="$NAME" -v m="$NAME" -v v="$VERDICT" \
              '/^[0-9]/{print "add element " f " " t " " m " { " $1 " : " v " }"}' \
            || echo "$PROG: download failed: $cc" >&2
    done

    if [[ -n $SSH_EXCEPTION ]]; then
        echo "add rule $FAMILY $NAME input $SSH_EXCEPTION"
    fi

    # vmap applies the verdict stored in the map; in whitelist mode a
    # trailing drop catches non-matching sources on the matched ports.
    echo "add rule $FAMILY $NAME input ${PORT_MATCH}ip saddr vmap @$NAME"
    if [[ $WHITELIST -eq 1 ]]; then
        echo "add rule $FAMILY $NAME input ${PORT_MATCH}drop"
    fi
} > "$TMP_RULES"

MIN_LINES=4
if [[ -n $SSH_EXCEPTION ]]; then
    MIN_LINES=$((MIN_LINES + 1))
fi
if [[ $WHITELIST -eq 1 ]]; then
    MIN_LINES=$((MIN_LINES + 2))
else
    MIN_LINES=$((MIN_LINES + 1))
fi

if [[ $(wc -l < "$TMP_RULES") -le $MIN_LINES ]]; then
    die "no entries collected"
fi

nft -f "$TMP_RULES"

n=$(nft list map "$FAMILY" "$NAME" "$NAME" 2>/dev/null | grep -c '^[[:space:]]*[0-9]' || true)
echo "$NAME: $n entries"
