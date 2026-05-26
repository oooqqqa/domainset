#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
domainsets_file=${DOMAINSETS_FILE:-"$repo_root/domainsets.tsv"}
generated_at=${GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}
display_generated_at=${DISPLAY_GENERATED_AT:-$(date -u -d "$generated_at" +%Y-%m-%d\ %H:%M:%S 2>/dev/null || printf "%s" "$generated_at")}
commit_sha=${GITHUB_SHA:-$(git -C "$repo_root" rev-parse HEAD)}
notes_file=${NOTES_FILE:-release-notes.md}
summary_file=${SUMMARY_FILE:-}
manifest_tmpdir=

cleanup() {
    if [[ -n "${manifest_tmpdir:-}" ]]; then
        rm -rf "$manifest_tmpdir"
    fi
}

require_tools() {
    command -v jq >/dev/null 2>&1 || { echo "error: jq is required to write manifest.json" >&2; exit 1; }
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
    local output _env_var _default_min_lines source_name source_url

    : > SHA256SUMS
    while IFS=$'\t' read -r output _env_var _default_min_lines source_name source_url; do
        [[ "$output" == "output" ]] && continue
        [[ -s "$output" ]] || { echo "error: $output: missing or empty" >&2; exit 1; }
        printf '%s  %s\n' "$(hash_file "$output")" "$output" >> SHA256SUMS
    done < "$domainsets_file"
}

write_notes_table() {
    local target=$1
    local output _env_var _default_min_lines source_name source_url count

    {
        printf '## Generated lists\n\n'
        printf '| File | Source | Lines |\n'
        printf '| --- | --- | ---: |\n'
    } >> "$target"

    while IFS=$'\t' read -r output _env_var _default_min_lines source_name source_url; do
        [[ "$output" == "output" ]] && continue
        count=$(line_count "$output")
        printf "| \`%s\` | %s | %s |\n" "$output" "$source_name" "$count" >> "$target"
    done < "$domainsets_file"
}

write_notes() {
    {
        printf 'Generated at: %s UTC\n\n' "$display_generated_at"
        printf 'This release is updated by GitHub Actions.\n\n'
    } > "$notes_file"

    write_notes_table "$notes_file"

    {
        printf '\n## Verification\n\n'
        printf "Use \`SHA256SUMS\` to verify downloaded files. \`manifest.json\` includes source URLs, line counts, commit, and checksums.\n"
    } >> "$notes_file"

    if [[ -n "$summary_file" ]]; then
        write_notes_table "$summary_file"
    fi
}

write_manifest() {
    local output _env_var _default_min_lines _source_name source_url count hash
    local manifest_tmp manifest_dir sources_tmp files_tmp

    manifest_tmpdir=$(mktemp -d)
    manifest_dir=$manifest_tmpdir
    manifest_tmp="$manifest_dir/manifest.tmp"
    sources_tmp="$manifest_dir/sources.json"
    files_tmp="$manifest_dir/files.json"

    printf '{}\n' > "$sources_tmp"
    printf '{}\n' > "$files_tmp"
    while IFS=$'\t' read -r output _env_var _default_min_lines _source_name source_url; do
        [[ "$output" == "output" ]] && continue

        count=$(line_count "$output")
        hash=$(hash_file "$output")

        jq --arg output "$output" --arg source_url "$source_url" \
            '. + {($output): [$source_url]}' "$sources_tmp" > "$manifest_tmp"
        mv "$manifest_tmp" "$sources_tmp"

        jq --arg output "$output" --argjson lines "$count" --arg sha256 "$hash" \
            '. + {($output): {lines: $lines, sha256: $sha256}}' "$files_tmp" > "$manifest_tmp"
        mv "$manifest_tmp" "$files_tmp"
    done < "$domainsets_file"

    jq -n \
        --arg generated_at "$generated_at" \
        --arg commit "$commit_sha" \
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
