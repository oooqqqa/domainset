#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
domainsets_file=${DOMAINSETS_FILE:-"$repo_root/domainsets.tsv"}
default_min_lines_override=${MIN_LINES:-}
tmpdir_created=

cleanup() {
    if [[ -n "${tmpdir_created:-}" ]]; then
        rm -rf "$tmpdir_created"
    fi
}

min_lines_for() {
    local output=$1
    local row_output env_var default_min_lines _source_name source_url override

    while IFS=$'\t' read -r row_output env_var default_min_lines _source_name source_url; do
        [[ "$row_output" == "output" ]] && continue
        [[ "$row_output" == "$output" ]] || continue

        override=${!env_var:-}
        printf "%s\n" "${override:-${MIN_LINES:-$default_min_lines}}"
        return 0
    done < "$domainsets_file"

    printf "%s\n" "${MIN_LINES:-1000}"
}

validate_min_lines() {
    local name=$1
    local value=$2

    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
        echo "error: $name must be a non-negative integer: $value" >&2
        exit 1
    fi
}

validate_config() {
    local row_output env_var default_min_lines _source_name source_url

    [[ -z "$default_min_lines_override" ]] || validate_min_lines MIN_LINES "$default_min_lines_override"

    while IFS=$'\t' read -r row_output env_var default_min_lines _source_name source_url; do
        [[ "$row_output" == "output" ]] && continue
        validate_min_lines "$env_var" "$(min_lines_for "$row_output")"
    done < "$domainsets_file"
}

# Supported domain-list formats normalize to canonical output:
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
        sub(/^\./, "", domain)
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
            printf("warning: %s: %d unsupported or invalid lines skipped\n", source, skipped) > "/dev/stderr"
            for (i = 1; i <= sample_count; i++) {
                printf("warning: %s: skipped sample: %s\n", source, samples[i]) > "/dev/stderr"
            }
        }
    }
    '
}

fetch_source() {
    local source=$1

    curl -fsSL "$source" || {
        echo "error: curl failed: $source" >&2
        exit 1
    }
}

process() {
    local output=$1
    shift

    if [[ $# -eq 0 ]]; then
        echo "error: $output: no sources configured" >&2
        return 1
    fi

    local tmp
    tmp=$(mktemp "$tmpdir_created/$output.XXXXXX")

    local source
    for source in "$@"; do
        fetch_source "$source" | normalize "$source"
    done | LC_ALL=C sort -u > "$tmp"

    local count min_lines
    count=$(wc -l < "$tmp")
    min_lines=$(min_lines_for "$output")
    if (( count < min_lines )); then
        echo "error: $output: only $count lines (need $min_lines)" >&2
        exit 1
    fi

    mv "$tmp" "$output"
    printf "%s: %d\n" "$output" "$count"
}

generate_configured_outputs() {
    local output _env_var _default_min_lines _source_name source_url

    while IFS=$'\t' read -r output _env_var _default_min_lines _source_name source_url; do
        [[ "$output" == "output" ]] && continue
        process "$output" "$source_url"
    done < "$domainsets_file"
}

main() {
    validate_config

    tmpdir_created=$(mktemp -d)
    trap cleanup EXIT

    generate_configured_outputs
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
