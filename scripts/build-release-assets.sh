#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DOMAINSETS_FILE=${DOMAINSETS_FILE:-"$REPO_ROOT/domainsets.tsv"}
GENERATED_AT=${GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}
DISPLAY_GENERATED_AT=${DISPLAY_GENERATED_AT:-$(date -u -d "$GENERATED_AT" +%Y-%m-%d\ %H:%M:%S 2>/dev/null || printf "%s" "$GENERATED_AT")}
COMMIT_SHA=${GITHUB_SHA:-$(git -C "$REPO_ROOT" rev-parse HEAD)}
NOTES_FILE=${NOTES_FILE:-release-notes.md}
SUMMARY_FILE=${SUMMARY_FILE:-}
MANIFEST_TMPDIR=

cleanup() {
    if [[ -n "${MANIFEST_TMPDIR:-}" ]]; then
        rm -rf "$MANIFEST_TMPDIR"
    fi
}

require_tools() {
    command -v jq >/dev/null 2>&1 || { echo "jq is required to write manifest.json" >&2; exit 1; }
}

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
        printf 'This release is updated by GitHub Actions.\n\n'
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
    local output env_var default_min_lines source_name source_url count hash
    local manifest_tmp manifest_dir sources_tmp files_tmp

    MANIFEST_TMPDIR=$(mktemp -d)
    manifest_dir=$MANIFEST_TMPDIR
    manifest_tmp="$manifest_dir/manifest.tmp"
    sources_tmp="$manifest_dir/sources.json"
    files_tmp="$manifest_dir/files.json"

    printf '{}\n' > "$sources_tmp"
    printf '{}\n' > "$files_tmp"
    while IFS=$'\t' read -r output env_var default_min_lines source_name source_url; do
        [[ "$output" == "output" ]] && continue

        count=$(line_count "$output")
        hash=$(hash_file "$output")

        jq --arg output "$output" --arg source_url "$source_url" \
            '. + {($output): [$source_url]}' "$sources_tmp" > "$manifest_tmp"
        mv "$manifest_tmp" "$sources_tmp"

        jq --arg output "$output" --argjson lines "$count" --arg sha256 "$hash" \
            '. + {($output): {lines: $lines, sha256: $sha256}}' "$files_tmp" > "$manifest_tmp"
        mv "$manifest_tmp" "$files_tmp"
    done < "$DOMAINSETS_FILE"

    jq -n \
        --arg generated_at "$GENERATED_AT" \
        --arg commit "$COMMIT_SHA" \
        --slurpfile sources "$sources_tmp" \
        --slurpfile files "$files_tmp" \
        '{
            generated_at: $generated_at,
            commit: $commit,
            sources: $sources[0],
            files: $files[0]
        }' > manifest.json
}

main() {
    trap cleanup EXIT

    require_tools
    write_checksums
    write_notes
    write_manifest
}

main "$@"
