#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$repo_root/domainset-generator.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

stdout_file="$tmpdir/stdout"
stderr_file="$tmpdir/stderr"
expected_file="$tmpdir/expected"

cat > "$expected_file" <<'EOF'
.example.com
example.org
.server.example.net
.mixed-case.example
.server-leading-dot.example
EOF

normalize "test-source" > "$stdout_file" 2> "$stderr_file" <<'EOF'
# comment
! adblock comment
; dnsmasq comment
||Example.COM^
example.org
server=/server.example.net/114.114.114.114
.Mixed-Case.Example
server=/.server-leading-dot.example/114.114.114.114
bad_domain
singlelabel
bad..example.com
-bad.example.com
bad-.example.com
EOF

diff -u "$expected_file" "$stdout_file"

grep -F "WARN: test-source: 5 unsupported or invalid lines skipped" "$stderr_file" >/dev/null
grep -F "WARN: test-source: skipped sample: bad_domain" "$stderr_file" >/dev/null
grep -F "WARN: test-source: skipped sample: singlelabel" "$stderr_file" >/dev/null

[[ "$(min_lines_for ads.txt)" == "300000" ]]
[[ "$(min_lines_for nsfw.txt)" == "300000" ]]
[[ "$(min_lines_for chinese-mainland.txt)" == "100000" ]]

MIN_LINES=42 bash -c 'source "$1"; [[ "$(min_lines_for ads.txt)" == "42" ]]' _ "$repo_root/domainset-generator.sh"
ADS_MIN_LINES=7 bash -c 'source "$1"; [[ "$(min_lines_for ads.txt)" == "7" ]]' _ "$repo_root/domainset-generator.sh"

if MIN_LINES=not-a-number bash -c 'source "$1"; validate_config' _ "$repo_root/domainset-generator.sh" 2> "$stderr_file"; then
    echo "expected invalid MIN_LINES to fail" >&2
    exit 1
fi
grep -F "MIN_LINES must be a non-negative integer: not-a-number" "$stderr_file" >/dev/null

printf 'normalize tests passed\n'
