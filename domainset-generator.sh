#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DOMAINSETS_FILE=${DOMAINSETS_FILE:-"$REPO_ROOT/domainsets.tsv"}
DEFAULT_MIN_LINES=${MIN_LINES:-}
TMPDIR_CREATED=

cleanup() {
    if [[ -n "${TMPDIR_CREATED:-}" ]]; then
        rm -rf "$TMPDIR_CREATED"
    fi
}

min_lines_for() {
    local output=$1
    local row_output env_var default_min_lines source_name source_url override

    while IFS=$'\t' read -r row_output env_var default_min_lines source_name source_url; do
        [[ "$row_output" == "output" ]] && continue
        [[ "$row_output" == "$output" ]] || continue

        override=${!env_var:-}
        printf "%s\n" "${override:-${MIN_LINES:-$default_min_lines}}"
        return 0
    done < "$DOMAINSETS_FILE"

    printf "%s\n" "${MIN_LINES:-1000}"
}

validate_min_lines() {
    local name=$1
    local value=$2

    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
        echo "$name must be a non-negative integer: $value" >&2
        exit 1
    fi
}

validate_config() {
    local row_output env_var default_min_lines source_name source_url

    [[ -z "$DEFAULT_MIN_LINES" ]] || validate_min_lines MIN_LINES "$DEFAULT_MIN_LINES"

    while IFS=$'\t' read -r row_output env_var default_min_lines source_name source_url; do
        [[ "$row_output" == "output" ]] && continue
        validate_min_lines "$env_var" "$(min_lines_for "$row_output")"
    done < "$DOMAINSETS_FILE"
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

generate_configured_outputs() {
    local output env_var default_min_lines source_name source_url

    while IFS=$'\t' read -r output env_var default_min_lines source_name source_url; do
        [[ "$output" == "output" ]] && continue
        process "$output" "$source_url"
    done < "$DOMAINSETS_FILE"
}

main() {
    validate_config

    TMPDIR_CREATED=$(mktemp -d)
    trap cleanup EXIT

    generate_configured_outputs
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
