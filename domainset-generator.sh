#!/usr/bin/env bash
set -euo pipefail

oisd_source_url=https://big.oisd.nl
china_source_url=https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf
ads_output_file=ads.txt
china_output_file=china.txt
min_ads_count=50000
min_china_count=50000
previous_dir=${PREVIOUS_DIR:-}
allow_large_change=${ALLOW_LARGE_CHANGE:-false}
max_change_percent=30
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

fetch_url() {
    local url=$1

    curl \
        --fail \
        --silent \
        --show-error \
        --location \
        --connect-timeout "$curl_connect_timeout" \
        --max-time "$curl_max_time" \
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
    local count previous_count delta previous_file

    tmp_file=$(mktemp "$output_file.XXXXXX") || return 1
    trap cleanup EXIT

    if ! fetch_url "$source_url" | "$normalizer" "$source_url" | LC_ALL=C sort -u > "$tmp_file"; then
        cleanup
        tmp_file=
        echo "error: $output_file: download or normalization failed" >&2
        return 1
    fi

    count=$(line_count "$tmp_file") || return 1
    if (( count < min_domain_count )); then
        die "$output_file: only $count domains (need $min_domain_count)"
    fi

    if [[ -n "$previous_dir" ]]; then
        previous_file="$previous_dir/$(basename "$output_file")"
        [[ -s "$previous_file" ]] || die "$output_file: missing previous list: $previous_file"
        previous_count=$(line_count "$previous_file") || return 1
        (( previous_count > 0 )) || die "$output_file: empty previous list"
        delta=$((count - previous_count))
        (( delta >= 0 )) || delta=$((-delta))
        if (( delta * 100 > previous_count * max_change_percent )); then
            if [[ "$allow_large_change" != true ]]; then
                die "$output_file: count changed from $previous_count to $count (limit $max_change_percent%); previous release preserved"
            fi
            echo "warning: $output_file: allowing count change from $previous_count to $count" >&2
        fi
    fi

    mv "$tmp_file" "$output_file" || return 1
    tmp_file=
    printf "%s: %d domains\n" "$output_file" "$count"
}

main() {
    generate_list "$oisd_source_url" "$ads_output_file" "$min_ads_count" normalize_oisd || return 1
    generate_list "$china_source_url" "$china_output_file" "$min_china_count" normalize_dnsmasq_china || return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
