#!/usr/bin/env bash
set -euo pipefail

DEFAULT_MIN_LINES=${MIN_LINES:-1000}
TMPDIR_CREATED=

cleanup() {
    if [[ -n "${TMPDIR_CREATED:-}" ]]; then
        rm -rf "$TMPDIR_CREATED"
    fi
}

min_lines_for() {
    local output=$1

    case "$output" in
        blocklist.txt) printf "%s\n" "${BLOCKLIST_MIN_LINES:-$DEFAULT_MIN_LINES}" ;;
        nsfw.txt) printf "%s\n" "${NSFW_MIN_LINES:-$DEFAULT_MIN_LINES}" ;;
        chinese-mainland.txt) printf "%s\n" "${CHINESE_MAINLAND_MIN_LINES:-$DEFAULT_MIN_LINES}" ;;
        *) printf "%s\n" "$DEFAULT_MIN_LINES" ;;
    esac
}

# Normalize supported domain-list formats:
#   ||example.com^       -> .example.com
#   example.com          -> example.com
#   server=/example.com/ -> .example.com
normalize() {
    local source=${1:-stdin}

    awk -v source="$source" '
    function trim(value) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
        return value
    }

    function valid_domain(domain, labels, count, i, label) {
        if (domain ~ /^\./) {
            domain = substr(domain, 2)
        }
        if (domain == "" || domain ~ /\.$/ || length(domain) > 253) {
            return 0
        }

        count = split(domain, labels, ".")
        if (count < 2) {
            return 0
        }

        for (i = 1; i <= count; i++) {
            label = labels[i]
            if (length(label) < 1 || length(label) > 63) {
                return 0
            }
            if (label !~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/) {
                return 0
            }
        }

        return 1
    }

    function emit(domain, leading_dot) {
        domain = tolower(domain)
        if (!valid_domain(domain)) {
            return 0
        }
        print leading_dot domain
        return 1
    }

    {
        gsub(/\r/, "")
        line = trim($0)

        if (line == "" || line ~ /^[#!;]/) {
            next
        }

        if (line ~ /^\|\|[A-Za-z0-9.-]+\^$/) {
            sub(/^\|\|/, "", line)
            sub(/\^$/, "", line)
            if (emit(line, ".")) {
                next
            }
        } else if (line ~ /^[.]?[A-Za-z0-9.-]+$/) {
            leading_dot = line ~ /^\./ ? "." : ""
            sub(/^\./, "", line)
            if (emit(line, leading_dot)) {
                next
            }
        } else if (line ~ /^server=\/[A-Za-z0-9.-]+\//) {
            sub(/^server=\//, "", line)
            sub(/\/.*/, "", line)
            if (emit(line, ".")) {
                next
            }
        }

        skipped++
        if (sample_count < 5) {
            sample_count++
            samples[sample_count] = line
        }
    }

    END {
        if (skipped) {
            printf("WARN: %s: %d unsupported or invalid lines skipped\n", source, skipped) > "/dev/stderr"
            for (i = 1; i <= sample_count; i++) {
                printf("WARN: %s: skipped sample: %s\n", source, samples[i]) > "/dev/stderr"
            }
        }
    }
    '
}

fetch_source() {
    local source=$1

    curl -fsSL "$source" || {
        echo "curl failed: $source" >&2
        exit 1
    }
}

process() {
    local output=$1
    shift

    if [[ $# -eq 0 ]]; then
        echo "process: no sources for $output" >&2
        return 1
    fi

    local tmp
    tmp=$(mktemp "$TMPDIR_CREATED/$output.XXXXXX")

    local source
    for source in "$@"; do
        fetch_source "$source" | normalize "$source"
    done | LC_ALL=C sort -u > "$tmp"

    local count min_lines
    count=$(wc -l < "$tmp")
    min_lines=$(min_lines_for "$output")
    if (( count < min_lines )); then
        echo "$output: only $count lines (need $min_lines), aborting" >&2
        exit 1
    fi

    mv "$tmp" "$output"
    printf "%s: %d\n" "$output" "$count"
}

main() {
    TMPDIR_CREATED=$(mktemp -d)
    trap cleanup EXIT

    process blocklist.txt \
        https://big.oisd.nl

    process nsfw.txt \
        https://nsfw.oisd.nl

    process chinese-mainland.txt \
        https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/refs/heads/master/accelerated-domains.china.conf
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
