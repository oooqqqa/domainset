#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DOMAINSETS_FILE=${DOMAINSETS_FILE:-"$REPO_ROOT/domainsets.tsv"}
GENERATED_AT=${GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}
DISPLAY_GENERATED_AT=${DISPLAY_GENERATED_AT:-$(date -u -d "$GENERATED_AT" +%Y-%m-%d\ %H:%M:%S 2>/dev/null || printf "%s" "$GENERATED_AT")}
COMMIT_SHA=${GITHUB_SHA:-$(git -C "$REPO_ROOT" rev-parse HEAD)}
NOTES_FILE=${NOTES_FILE:-release-notes.md}
SUMMARY_FILE=${SUMMARY_FILE:-}

hash_file() {
    local file=$1

    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    else
        shasum -a 256 "$file" | awk '{print $1}'
    fi
}

line_count() {
    local file=$1

    wc -l < "$file" | awk '{print $1}'
}

write_checksums() {
    local output env_var default_min_lines source_name source_url

    : > SHA256SUMS
    while IFS=$'\t' read -r output env_var default_min_lines source_name source_url; do
        [[ "$output" == "output" ]] && continue
        [[ -s "$output" ]] || { echo "$output: missing or empty" >&2; exit 1; }
        printf '%s  %s\n' "$(hash_file "$output")" "$output" >> SHA256SUMS
    done < "$DOMAINSETS_FILE"
}

write_notes_table() {
    local target=$1
    local output env_var default_min_lines source_name source_url count

    {
        printf '## Generated lists\n\n'
        printf '| File | Source | Lines |\n'
        printf '| --- | --- | ---: |\n'
    } >> "$target"

    while IFS=$'\t' read -r output env_var default_min_lines source_name source_url; do
        [[ "$output" == "output" ]] && continue
        count=$(line_count "$output")
        printf '| `%s` | %s | %s |\n' "$output" "$source_name" "$count" >> "$target"
    done < "$DOMAINSETS_FILE"
}

write_notes() {
    {
        printf 'Auto-updated: %s UTC\n\n' "$DISPLAY_GENERATED_AT"
        printf 'This is a rolling `latest` release updated by GitHub Actions.\n\n'
    } > "$NOTES_FILE"

    write_notes_table "$NOTES_FILE"

    {
        printf '\n## Verification\n\n'
        printf 'Use `SHA256SUMS` to verify downloaded files. `manifest.json` includes source URLs, line counts, commit, and checksums.\n'
    } >> "$NOTES_FILE"

    if [[ -n "$SUMMARY_FILE" ]]; then
        write_notes_table "$SUMMARY_FILE"
    fi
}

write_manifest() {
    local output env_var default_min_lines source_name source_url count hash comma index total

    total=$(($(wc -l < "$DOMAINSETS_FILE") - 1))
    index=0

    {
        printf '{\n'
        printf '  "generated_at": "%s",\n' "$GENERATED_AT"
        printf '  "commit": "%s",\n' "$COMMIT_SHA"
        printf '  "sources": {\n'
    } > manifest.json

    while IFS=$'\t' read -r output env_var default_min_lines source_name source_url; do
        [[ "$output" == "output" ]] && continue
        index=$((index + 1))
        comma=","
        [[ "$index" -eq "$total" ]] && comma=""
        printf '    "%s": ["%s"]%s\n' "$output" "$source_url" "$comma" >> manifest.json
    done < "$DOMAINSETS_FILE"

    {
        printf '  },\n'
        printf '  "files": {\n'
    } >> manifest.json

    index=0
    while IFS=$'\t' read -r output env_var default_min_lines source_name source_url; do
        [[ "$output" == "output" ]] && continue
        index=$((index + 1))
        count=$(line_count "$output")
        hash=$(hash_file "$output")
        comma=","
        [[ "$index" -eq "$total" ]] && comma=""
        printf '    "%s": {"lines": %s, "sha256": "%s"}%s\n' "$output" "$count" "$hash" "$comma" >> manifest.json
    done < "$DOMAINSETS_FILE"

    {
        printf '  }\n'
        printf '}\n'
    } >> manifest.json
}

main() {
    write_checksums
    write_notes
    write_manifest
}

main "$@"
