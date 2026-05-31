#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$repo_root/domainset-generator.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

stdout_file="$tmpdir/stdout"
stderr_file="$tmpdir/stderr"
expected_file="$tmpdir/expected"
main_dir="$tmpdir/main"
fail_dir="$tmpdir/fail"

cat > "$expected_file" <<'EOF'
.example.com
.sub.example.net
.mixed-case.example
EOF

normalize_oisd "test-source" > "$stdout_file" 2> "$stderr_file" <<'EOF'
[Adblock Plus]
! comment

||Example.COM^
||sub.example.net^
||Mixed-Case.Example^
EOF

diff -u "$expected_file" "$stdout_file"
[[ ! -s "$stderr_file" ]]

if normalize_oisd "bad-source" > "$stdout_file" 2> "$stderr_file" <<'EOF'
||valid.example^
example.org
EOF
then
    echo "error: unsupported input should fail" >&2
    exit 1
fi
grep -F "error: bad-source: line 2: unsupported input: example.org" "$stderr_file" >/dev/null

if normalize_oisd "bad-source" > "$stdout_file" 2> "$stderr_file" <<'EOF'
||bad..example^
EOF
then
    echo "error: invalid domain should fail" >&2
    exit 1
fi
grep -F "error: bad-source: line 1: invalid domain: ||bad..example^" "$stderr_file" >/dev/null

mkdir "$main_dir"
cat > "$expected_file" <<'EOF'
.a.example
.b.example
EOF

(
    cd "$main_dir"
    source "$repo_root/domainset-generator.sh"
    output_file=ads.txt
    min_domain_count=2

    fetch_oisd() {
        cat <<'EOF'
[Adblock Plus]
||b.example^
||a.example^
||b.example^
EOF
    }

    main
) > "$stdout_file" 2> "$stderr_file"

diff -u "$expected_file" "$main_dir/ads.txt"
grep -F "ads.txt: 2 domains" "$stdout_file" >/dev/null
[[ ! -s "$stderr_file" ]]

mkdir "$fail_dir"
if (
    cd "$fail_dir"
    source "$repo_root/domainset-generator.sh"
    output_file=ads.txt
    min_domain_count=2

    fetch_oisd() {
        cat <<'EOF'
[Adblock Plus]
||only.example^
EOF
    }

    main
) > "$stdout_file" 2> "$stderr_file"
then
    echo "error: small output should fail" >&2
    exit 1
fi
grep -F "error: ads.txt: only 1 domains (need 2)" "$stderr_file" >/dev/null
[[ ! -e "$fail_dir/ads.txt" ]]
shopt -s nullglob
leftovers=("$fail_dir"/ads.txt.*)
(( ${#leftovers[@]} == 0 ))

printf 'normalize tests passed\n'
