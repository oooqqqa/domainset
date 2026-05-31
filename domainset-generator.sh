#!/usr/bin/env bash
set -euo pipefail

source_url=https://big.oisd.nl
output_file=ads.txt
min_domain_count=300000
curl_connect_timeout=10
curl_max_time=120
tmp_file=

cleanup() {
    if [[ -n "${tmp_file:-}" ]]; then
        rm -f "$tmp_file"
    fi
}

die() {
    echo "error: $*" >&2
    exit 1
}

line_count() {
    local file=$1

    wc -l < "$file" | awk '{print $1}'
}

fetch_oisd() {
    curl \
        --fail \
        --silent \
        --show-error \
        --location \
        --connect-timeout "$curl_connect_timeout" \
        --max-time "$curl_max_time" \
        "$source_url"
}

normalize_oisd() {
    local source=${1:-stdin}

    awk -v source="$source" '
    function valid_domain(domain, labels, count, i, label) {
        if (domain == "" || domain ~ /^\./ || domain ~ /\.$/ || length(domain) > 253) {
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

    function fail(reason) {
        printf("error: %s: line %d: %s: %s\n", source, NR, reason, raw) > "/dev/stderr"
        exit 1
    }

    {
        raw = $0
        gsub(/\r/, "")
        line = $0
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)

        if (line == "" || line == "[Adblock Plus]" || line ~ /^!/) {
            next
        }

        if (line !~ /^\|\|[A-Za-z0-9.-]+\^$/) {
            fail("unsupported input")
        }

        sub(/^\|\|/, "", line)
        sub(/\^$/, "", line)
        domain = tolower(line)

        if (!valid_domain(domain)) {
            fail("invalid domain")
        }

        print "." domain
    }
    '
}

main() {
    local count

    tmp_file=$(mktemp "$output_file.XXXXXX")
    trap cleanup EXIT

    fetch_oisd | normalize_oisd "$source_url" | LC_ALL=C sort -u > "$tmp_file"

    count=$(line_count "$tmp_file")
    if (( count < min_domain_count )); then
        die "$output_file: only $count domains (need $min_domain_count)"
    fi

    mv "$tmp_file" "$output_file"
    tmp_file=
    printf "%s: %d domains\n" "$output_file" "$count"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
