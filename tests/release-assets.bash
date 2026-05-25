#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

config_file="$tmpdir/domainsets.tsv"
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

grep -F 'Auto-updated: 2026-05-25 00:00:00 UTC' "$notes_file" >/dev/null
grep -F '| `ads.txt` | OISD big | 2 |' "$notes_file" >/dev/null
grep -F 'Use `SHA256SUMS` to verify downloaded files.' "$notes_file" >/dev/null

grep -F '| `chinese-mainland.txt` | felixonmars dnsmasq china list | 2 |' "$summary_file" >/dev/null

grep -F '  ads.txt' SHA256SUMS >/dev/null
grep -F '  nsfw.txt' SHA256SUMS >/dev/null
grep -F '  chinese-mainland.txt' SHA256SUMS >/dev/null

grep -F '"generated_at": "2026-05-25T00:00:00Z"' manifest.json >/dev/null
grep -F '"commit": "abc123"' manifest.json >/dev/null
grep -F '"ads.txt": ["https://example.test/ads"]' manifest.json >/dev/null
grep -F '"chinese-mainland.txt": {"lines": 2,' manifest.json >/dev/null

printf 'release asset tests passed\n'
