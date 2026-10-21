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
apple_china_count=$(line_count apple-china.txt)
ads_hash=$(hash_file ads.txt)
china_hash=$(hash_file china.txt)
apple_china_hash=$(hash_file apple-china.txt)

jq -n \
    --arg generated_at "$generated_at" --arg commit "$commit" \
    --arg ads_source "$oisd_source_url" --arg china_source "$china_source_url" \
    --arg apple_china_source "$apple_china_source_url" \
    --arg apple_china_hash "$apple_china_hash" --argjson apple_china_count "$apple_china_count" \
    --arg ads_hash "$ads_hash" --arg china_hash "$china_hash" \
    --argjson ads_count "$ads_count" --argjson china_count "$china_count" \
    '{generated_at: $generated_at, commit: $commit, format: "Surge DOMAIN-SET",
      files: {"ads.txt": {source: $ads_source, lines: $ads_count, sha256: $ads_hash},
              "china.txt": {source: $china_source, lines: $china_count, sha256: $china_hash},
              "apple-china.txt": {source: $apple_china_source, lines: $apple_china_count, sha256: $apple_china_hash}}}' \
    > manifest.json
{
    printf 'Generated at: %s (UTC)\n\nCommit: %s\n\n' "$generated_at" "$commit"
    printf '| File | Purpose | Entries | Source |\n| --- | --- | ---: | --- |\n'
    printf '| ads.txt | Domain blocking | %s | %s |\n' "$ads_count" "$oisd_source_url"
    printf '| china.txt | DNS routing to a Chinese resolver | %s | %s |\n' "$china_count" "$china_source_url"
    printf '| apple-china.txt | Apple DNS routing to a Chinese resolver | %s | %s |\n\n' "$apple_china_count" "$apple_china_source_url"
    printf '%s\n' 'china.txt and apple-china.txt are DNS acceleration lists, not a guarantee that every matching destination should use DIRECT.'
    printf '\n%s\n' 'manifest.json records the sources, counts, SHA256 checksums and generator commit.'
} > release-notes.md
