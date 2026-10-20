#!/usr/bin/env bash
# Mocks replace functions that the sourced generator calls.
# shellcheck disable=SC2329
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT
export REVIEW_REPO_ROOT="$repo_root"

# A conditional function call must propagate both parser and fetch failures.
for mode in parse fetch; do
    mkdir "$task_tmp/$mode"
    (
        cd "$task_tmp/$mode"
        source "$repo_root/domainset-generator.sh"
        printf '.old.example\n' > ads.txt
        fetch_url() {
            printf '||valid.example^\n' > "$2"
            if [[ "$mode" == parse ]]; then
                printf 'invalid-input\n' >> "$2"
            else
                return 1
            fi
        }
        if generate_list mock://source ads.txt 1 normalize_oisd; then
            echo 'error: failed pipeline accepted' >&2
            exit 1
        fi
        [[ "$(cat ads.txt)" == '.old.example' ]]
    ) > "$task_tmp/$mode.log" 2>&1
    [[ "$(ls -A "$task_tmp/$mode")" == ads.txt ]]
done

# A failed list must not leave the other list updated.
mkdir "$task_tmp/partial"
if (
    cd "$task_tmp/partial"
    source "$repo_root/domainset-generator.sh"
    printf '.old.example\n' > ads.txt
    printf '.old.cn\n' > china.txt
    min_ads_count=1
    min_china_count=1
    fetch_url() {
        if [[ "$1" == "$oisd_source_url" ]]; then
            printf '||new.example^\n' > "$2"
        else
            printf 'invalid-input\n' > "$2"
        fi
    }
    main
) > "$task_tmp/partial.log" 2>&1
then
    echo 'error: partial update accepted' >&2
    exit 1
fi
[[ "$(cat "$task_tmp/partial/ads.txt")" == '.old.example' ]]
[[ "$(cat "$task_tmp/partial/china.txt")" == '.old.cn' ]]
[[ "$(ls -A "$task_tmp/partial")" == $'ads.txt\nchina.txt' ]]

run_change_case() {
    local name=$1 count=$2 expected=$3 allow=${4:-false} minimum=${5:-1}
    mkdir "$task_tmp/$name"
    if bash -c '
        set -euo pipefail
        cd "$1"
        source "$REVIEW_REPO_ROOT/domainset-generator.sh"
        mkdir previous
        for i in {1..10}; do printf ".old%s.example\n" "$i"; done > previous/ads.txt
        printf ".original.example\n" > ads.txt
        previous_dir=previous
        allow_large_change=$3
        # Capture fixture size in a global; fetch_url gets the URL and output file as $1 and $2.
        fixture_count=$2
        fetch_url() {
            local i
            for (( i=1; i <= fixture_count; i++ )); do printf "||new%s.example^\n" "$i"; done > "$2"
        }
        generate_list mock://source ads.txt "$4" normalize_oisd
        install_lists
    ' _ "$task_tmp/$name" "$count" "$allow" "$minimum" > "$task_tmp/$name.log" 2>&1; then
        [[ "$expected" == pass ]] || { cat "$task_tmp/$name.log"; return 1; }
        [[ "$(wc -l < "$task_tmp/$name/ads.txt")" -eq "$count" ]]
    else
        [[ "$expected" == fail ]] || { cat "$task_tmp/$name.log"; return 1; }
        [[ "$(cat "$task_tmp/$name/ads.txt")" == '.original.example' ]]
    fi
    [[ "$(ls -A "$task_tmp/$name")" == $'ads.txt\nprevious' ]]
}
run_change_case decrease 6 fail
run_change_case increase 14 fail
run_change_case lower-bound 7 pass
run_change_case upper-bound 13 pass
run_change_case reviewed 14 pass true
run_change_case minimum 1 fail true 2

# Upstream resolver changes do not alter the domain list.
(
    source "$repo_root/domainset-generator.sh"
    normalize_dnsmasq_china test <<'EOF'
server=/example.cn/8.8.8.8
server=/example.net/2001:db8::1
EOF
) > "$task_tmp/resolvers"
printf '.example.cn\n.example.net\n' > "$task_tmp/expected"
diff -u "$task_tmp/expected" "$task_tmp/resolvers"

(
    cd "$task_tmp"
    printf '.ads.example\n' > ads.txt
    printf '.cn\n.china.example\n' > china.txt
    GITHUB_SHA=test-commit bash "$repo_root/scripts/release-metadata.bash"
    jq -e '.commit == "test-commit" and .files["ads.txt"].lines == 1
        and .files["china.txt"].lines == 2 and .generated_at != ""
        and .files["china.txt"].source != ""' manifest.json >/dev/null
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c SHA256SUMS
    else
        shasum -a 256 -c SHA256SUMS
    fi
    grep -F 'DNS routing' release-notes.md >/dev/null
) > "$task_tmp/metadata.log"
printf 'reliability tests passed\n'
