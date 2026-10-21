#!/usr/bin/env bash
set -euo pipefail

oisd_source_url=https://big.oisd.nl
china_source_url=https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf
apple_china_source_url=https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/apple.china.conf
ads_output_file=ads.txt
china_output_file=china.txt
apple_china_output_file=apple-china.txt
# About 70% of each upstream's size in 2026-10; raise them as the upstreams grow.
min_ads_count=160000
min_china_count=75000
min_apple_china_count=110
curl_connect_timeout=10
curl_max_time=120
curl_retry_count=2
curl_retry_delay=10
work_dir=
staged_files=()

cleanup() {
    if [[ -n "${work_dir:-}" ]]; then
        rm -rf "$work_dir"
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

fetch_url() {
    local url=$1
    local output_file=$2

    curl \
        --fail \
        --silent \
        --show-error \
        --location \
        --connect-timeout "$curl_connect_timeout" \
        --max-time "$curl_max_time" \
        --retry "$curl_retry_count" \
        --retry-delay "$curl_retry_delay" \
        --retry-all-errors \
        --output "$output_file" \
        "$url"
}

normalize_domains() {
    local input_format=$1
    local source=${2:-stdin}

    awk -v input_format="$input_format" -v source="$source" '
    function valid_domain(domain, min_labels, labels, count, i, label) {
        if (domain == "" || domain ~ /^\./ || domain ~ /\.$/ || length(domain) > 253) {
            return 0
        }

        count = split(domain, labels, ".")
        if (count < min_labels) {
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

        if (line == "") {
            next
        }

        if (input_format == "oisd") {
            if (line == "[Adblock Plus]" || line ~ /^!/) {
                next
            }
            if (line !~ /^\|\|[A-Za-z0-9.-]+\^$/) {
                fail("unsupported input")
            }
            sub(/^\|\|/, "", line)
            sub(/\^$/, "", line)
        } else if (input_format == "dnsmasq-china") {
            if (line ~ /^#/) {
                next
            }
            if (line !~ /^server=\/[A-Za-z0-9.-]+\/[^\/[:space:]]+$/) {
                fail("unsupported input")
            }
            sub(/^server=\//, "", line)
            sub(/\/[^\/]+$/, "", line)
        } else {
            fail("unknown input format")
        }

        domain = tolower(line)

        min_labels = (input_format == "dnsmasq-china" ? 1 : 2)
        if (!valid_domain(domain, min_labels)) {
            fail("invalid domain")
        }

        print "." domain
    }
    '
}

normalize_oisd() {
    normalize_domains oisd "${1:-stdin}"
}

normalize_dnsmasq_china() {
    normalize_domains dnsmasq-china "${1:-stdin}"
}

generate_list() {
    local source_url=$1
    local output_file=$2
    local min_domain_count=$3
    local normalizer=$4
    local count staged_file source_file

    if [[ -z "$work_dir" ]]; then
        # Stage next to the outputs so install_lists renames within one filesystem.
        work_dir=$(mktemp -d "$(dirname "$output_file")/.domainset.XXXXXX") || return 1
        trap cleanup EXIT
    fi
    staged_file="$work_dir/$(basename "$output_file")"
    source_file="$staged_file.source"

    # Download to a file: curl truncates it before a retry, unlike a pipe.
    if ! fetch_url "$source_url" "$source_file"; then
        echo "error: $output_file: download failed" >&2
        return 1
    fi

    if ! "$normalizer" "$source_url" < "$source_file" | LC_ALL=C sort -u > "$staged_file"; then
        echo "error: $output_file: normalization failed" >&2
        return 1
    fi

    count=$(line_count "$staged_file") || return 1
    if (( count < min_domain_count )); then
        die "$output_file: only $count domains (need $min_domain_count)"
    fi

    staged_files+=("$output_file")
}

install_lists() {
    local output_file

    for output_file in "${staged_files[@]}"; do
        mv "$work_dir/$(basename "$output_file")" "$output_file" || return 1
        printf "%s: %d domains\n" "$output_file" "$(line_count "$output_file")"
    done
    staged_files=()
}

main() {
    generate_list "$oisd_source_url" "$ads_output_file" "$min_ads_count" normalize_oisd || return 1
    generate_list "$china_source_url" "$china_output_file" "$min_china_count" normalize_dnsmasq_china || return 1
    generate_list "$apple_china_source_url" "$apple_china_output_file" "$min_apple_china_count" normalize_dnsmasq_china || return 1
    install_lists
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
