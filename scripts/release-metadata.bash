#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$repo_root/domainset-generator.sh"
generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
commit=${GITHUB_SHA:?GITHUB_SHA is required}

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

ads_count=$(line_count ads.txt)
china_count=$(line_count china.txt)
ads_hash=$(hash_file ads.txt)
china_hash=$(hash_file china.txt)

printf '%s  ads.txt\n%s  china.txt\n' "$ads_hash" "$china_hash" > SHA256SUMS
jq -n \
    --arg generated_at "$generated_at" --arg commit "$commit" \
    --arg ads_source "$oisd_source_url" --arg china_source "$china_source_url" \
    --arg ads_hash "$ads_hash" --arg china_hash "$china_hash" \
    --argjson ads_count "$ads_count" --argjson china_count "$china_count" \
    '{generated_at: $generated_at, commit: $commit, format: "Surge DOMAIN-SET",
      files: {"ads.txt": {source: $ads_source, lines: $ads_count, sha256: $ads_hash},
              "china.txt": {source: $china_source, lines: $china_count, sha256: $china_hash}}}' \
    > manifest.json
{
    printf 'Generated at: %s (UTC)\n\nCommit: `%s`\n\n' "$generated_at" "$commit"
    printf '| File | Purpose | Entries | Source |\n| --- | --- | ---: | --- |\n'
    printf '| ads.txt | Domain blocking | %s | %s |\n' "$ads_count" "$oisd_source_url"
    printf '| china.txt | DNS routing to a Chinese resolver | %s | %s |\n\n' "$china_count" "$china_source_url"
    printf '%s\n' 'china.txt is a DNS acceleration list, not a guarantee that every matching destination should use DIRECT.'
    printf '\n%s\n' 'SHA256SUMS verifies the two lists; manifest.json records their sources, counts, checksums and generator commit.'
} > release-notes.md
