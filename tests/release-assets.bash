#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

config_file="$tmpdir/domainsets.tsv"
escaped_config_file="$tmpdir/domainsets-escaped.tsv"
notes_file="$tmpdir/release-notes.md"
summary_file="$tmpdir/summary.md"

cat > "$config_file" <<'EOF'
output	env_var	default_min_lines	source_name	source_url
ads.txt	ADS_MIN_LINES	2	OISD big	https://example.test/ads
nsfw.txt	NSFW_MIN_LINES	2	OISD NSFW	https://example.test/nsfw
chinese-mainland.txt	CHINESE_MAINLAND_MIN_LINES	2	felixonmars dnsmasq china list	https://example.test/china
EOF

cd "$tmpdir"

printf 'a.example\nb.example\n' > ads.txt
printf 'n.example\ns.example\n' > nsfw.txt
printf 'c.example\nm.example\n' > chinese-mainland.txt

DOMAINSETS_FILE="$config_file" \
GENERATED_AT=2026-05-25T00:00:00Z \
DISPLAY_GENERATED_AT="2026-05-25 00:00:00" \
GITHUB_SHA=abc123 \
NOTES_FILE="$notes_file" \
SUMMARY_FILE="$summary_file" \
    bash "$repo_root/scripts/build-release-assets.sh"

grep -F 'Generated at: 2026-05-25 00:00:00 UTC' "$notes_file" >/dev/null
grep -F 'This release is updated by GitHub Actions.' "$notes_file" >/dev/null
grep -F "| \`ads.txt\` | OISD big | 2 |" "$notes_file" >/dev/null
grep -F "Use \`SHA256SUMS\` to verify downloaded files." "$notes_file" >/dev/null

grep -F "| \`chinese-mainland.txt\` | felixonmars dnsmasq china list | 2 |" "$summary_file" >/dev/null

grep -F '  ads.txt' SHA256SUMS >/dev/null
grep -F '  nsfw.txt' SHA256SUMS >/dev/null
grep -F '  chinese-mainland.txt' SHA256SUMS >/dev/null

jq -e \
    '.generated_at == "2026-05-25T00:00:00Z"
        and .commit == "abc123"
        and .sources["ads.txt"] == ["https://example.test/ads"]
        and .files["chinese-mainland.txt"].lines == 2' \
    manifest.json >/dev/null

cat > "$escaped_config_file" <<'EOF'
output	env_var	default_min_lines	source_name	source_url
quoted"name.txt	QUOTED_MIN_LINES	1	Quoted source	https://example.test/path?name="quoted"\value
EOF

printf 'quoted.example\n' > 'quoted"name.txt'

DOMAINSETS_FILE="$escaped_config_file" \
GENERATED_AT=2026-05-25T00:00:00Z \
GITHUB_SHA='abc"123\sha' \
NOTES_FILE="$notes_file.escaped" \
    bash "$repo_root/scripts/build-release-assets.sh"

jq -e \
    --arg file 'quoted"name.txt' \
    --arg commit 'abc"123\sha' \
    --arg source_url 'https://example.test/path?name="quoted"\value' \
    '.commit == $commit
        and .sources[$file] == [$source_url]
        and .files[$file].lines == 1' \
    manifest.json >/dev/null

printf 'release asset tests passed\n'
