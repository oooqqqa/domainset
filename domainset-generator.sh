#!/usr/bin/env bash
set -euo pipefail

MIN_LINES=${MIN_LINES:-1000}

# 规范化域名格式：
#   ||example.com^       -> .example.com
#   example.com          -> example.com
#   server=/example.com/ -> .example.com
normalize() {
    awk '
    { gsub(/\r/, "") }
    /^\|\|[A-Za-z0-9._-]+\^$/ { sub(/^\|\|/, "."); sub(/\^.*/, ""); print; next }
    /^[.]?[A-Za-z0-9._-]+$/ { print; next }
    /^server=\/[A-Za-z0-9._-]+\// { sub(/^server=\//, "."); sub(/\/.*/, ""); print; next }
    { unmatched++ }
    END { if (unmatched) printf("WARN: %d lines skipped\n", unmatched) > "/dev/stderr" }
    '
}

process() {
    local output=$1; shift
    if [[ $# -eq 0 ]]; then
        echo "process: no sources for $output" >&2
        return 1
    fi

    local tmp
    tmp=$(mktemp)
    trap 'rm -f "$tmp"' EXIT

    for url in "$@"; do
        curl -fsSL "$url" || { echo "curl failed: $url" >&2; exit 1; }
    done | normalize | LC_ALL=C sort -u > "$tmp"

    local count
    count=$(wc -l < "$tmp")
    if (( count < MIN_LINES )); then
        echo "$output: only $count lines (need $MIN_LINES), aborting" >&2
        rm -f "$tmp"
        exit 1
    fi

    mv "$tmp" "$output"
    printf "%s: %d\n" "$output" "$count"
}

process blocklist.txt \
    https://big.oisd.nl

process nsfw.txt \
    https://nsfw.oisd.nl \
    https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/nsfw.txt

# server=/012233.com/114.114.114.114 -> .012233.com
process chinese-mainland.txt \
    https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/refs/heads/master/accelerated-domains.china.conf

trap - EXIT
