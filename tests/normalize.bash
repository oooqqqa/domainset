#!/usr/bin/env bash
# Mocks replace functions that the sourced generator calls.
# shellcheck disable=SC2329
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

normalize_domains oisd "test-source" > "$stdout_file" 2> "$stderr_file" <<'EOF'
[Adblock Plus]
! comment

||Example.COM^
||sub.example.net^
||Mixed-Case.Example^
EOF

diff -u "$expected_file" "$stdout_file"
[[ ! -s "$stderr_file" ]]

if normalize_domains oisd "bad-source" > "$stdout_file" 2> "$stderr_file" <<'EOF'
||valid.example^
example.org
EOF
then
    echo "error: unsupported input should fail" >&2
    exit 1
fi
grep -F "error: bad-source: line 2: unsupported input: example.org" "$stderr_file" >/dev/null

if normalize_domains oisd "bad-source" > "$stdout_file" 2> "$stderr_file" <<'EOF'
||bad..example^
EOF
then
    echo "error: invalid domain should fail" >&2
    exit 1
fi
grep -F "error: bad-source: line 1: invalid domain: ||bad..example^" "$stderr_file" >/dev/null

cat > "$expected_file" <<'EOF'
.0.zone
.cn
.example.cn
.mixed-case.example
.resolver-v4.example
.resolver-v6.example
EOF

# The resolver address is discarded whatever its form.
normalize_domains dnsmasq-china "china-test-source" > "$stdout_file" 2> "$stderr_file" <<'EOF'
# comment

server=/0.zone/114.114.114.114
server=/cn/114.114.114.114
server=/example.cn/114.114.114.114
server=/Mixed-Case.Example/114.114.114.114
server=/resolver-v4.example/8.8.8.8
server=/resolver-v6.example/2001:db8::1
EOF

diff -u "$expected_file" "$stdout_file"
[[ ! -s "$stderr_file" ]]

if normalize_domains dnsmasq-china "bad-china-source" > "$stdout_file" 2> "$stderr_file" <<'EOF'
server=/valid.example/114.114.114.114
address=/example.org/8.8.8.8
EOF
then
    echo "error: unsupported dnsmasq input should fail" >&2
    exit 1
fi
grep -F "error: bad-china-source: line 2: unsupported input: address=/example.org/8.8.8.8" "$stderr_file" >/dev/null

if normalize_domains dnsmasq-china "bad-china-source" > "$stdout_file" 2> "$stderr_file" <<'EOF'
server=/bad..example/114.114.114.114
EOF
then
    echo "error: invalid dnsmasq domain should fail" >&2
    exit 1
fi
grep -F "error: bad-china-source: line 1: invalid domain: server=/bad..example/114.114.114.114" "$stderr_file" >/dev/null

mkdir "$main_dir"
cat > "$tmpdir/expected-ads" <<'EOF'
.a.example
.b.example
EOF
cat > "$tmpdir/expected-china" <<'EOF'
.china.example
.cn
.example.cn
EOF

(
    cd "$main_dir"
    umask 022
    source "$repo_root/domainset-generator.sh"
    oisd_source_url=mock://oisd
    china_source_url=mock://china
    min_ads_count=2
    min_china_count=3
    min_apple_china_count=2
    apple_china_source_url=mock://apple-china

    fetch_url() {
        case "$1" in
            mock://oisd)
                cat > "$2" <<'EOF'
[Adblock Plus]
||b.example^
||a.example^
||b.example^
EOF
                ;;
            mock://apple-china)
                cat > "$2" <<'EOF'
# Apple China
server=/itunes.apple.com/114.114.114.114
server=/APPLE.COM.CN/114.114.114.114
server=/itunes.apple.com/114.114.114.114
EOF
                ;;
            mock://china)
                cat > "$2" <<'EOF'
# comment
server=/cn/114.114.114.114
server=/example.cn/114.114.114.114
server=/china.example/114.114.114.114
EOF
                ;;
            *)
                return 1
                ;;
        esac
    }

    main
) > "$stdout_file" 2> "$stderr_file"

printf '.apple.com.cn\n.itunes.apple.com\n' > "$tmpdir/expected-apple-china"
diff -u "$tmpdir/expected-apple-china" "$main_dir/apple-china.txt"
diff -u "$tmpdir/expected-ads" "$main_dir/ads.txt"
diff -u "$tmpdir/expected-china" "$main_dir/china.txt"
grep -F "ads.txt: 2 domains" "$stdout_file" >/dev/null
grep -F "china.txt: 3 domains" "$stdout_file" >/dev/null
grep -F "apple-china.txt: 2 domains" "$stdout_file" >/dev/null
[[ ! -s "$stderr_file" ]]
[[ "$(ls -A "$main_dir")" == $'ads.txt\napple-china.txt\nchina.txt' ]]
# Outputs follow the umask instead of mktemp's private 0600 mode.
[[ "$(ls -l "$main_dir/ads.txt")" == -rw-r--r--* ]]

mkdir "$fail_dir"
if (
    cd "$fail_dir"
    source "$repo_root/domainset-generator.sh"
    output_file=ads.txt

    fetch_url() {
        cat > "$2" <<'EOF'
[Adblock Plus]
||only.example^
EOF
    }

    generate_list mock://oisd "$output_file" 2 oisd
) > "$stdout_file" 2> "$stderr_file"
then
    echo "error: small output should fail" >&2
    exit 1
fi
grep -F "error: ads.txt: only 1 domains (need 2)" "$stderr_file" >/dev/null
[[ -z "$(ls -A "$fail_dir")" ]]

printf 'normalize tests passed\n'
