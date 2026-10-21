#!/usr/bin/env bash
# Mocks replace functions that the sourced generator calls.
# shellcheck disable=SC2329
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT

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
        # set -e is off inside the condition, so only die can stop the subshell.
        if (generate_list mock://source ads.txt 1 oisd); then
            echo 'error: failed pipeline accepted' >&2
            exit 1
        fi
        [[ "$(cat ads.txt)" == '.old.example' ]]
    ) > "$task_tmp/$mode.log" 2>&1
    [[ "$(ls -A "$task_tmp/$mode")" == ads.txt ]]
done

# Failure in either dnsmasq list must preserve all existing outputs.
for failed_source in china apple; do
    mkdir "$task_tmp/partial-$failed_source"
    if (
        cd "$task_tmp/partial-$failed_source"
        source "$repo_root/domainset-generator.sh"
        printf '.old.example\n' > ads.txt
        printf '.old.cn\n' > china.txt
        printf '.old.apple.cn\n' > apple-china.txt
        min_ads_count=1
        min_china_count=1
        min_apple_china_count=1
        fetch_url() {
            case "$1" in
                "$oisd_source_url") printf '||new.example^\n' > "$2" ;;
                "$china_source_url")
                    if [[ "$failed_source" == china ]]; then
                        printf 'invalid-input\n' > "$2"
                    else
                        printf 'server=/new.cn/114.114.114.114\n' > "$2"
                    fi
                    ;;
                "$apple_china_source_url") printf 'invalid-input\n' > "$2" ;;
                *) return 1 ;;
            esac
        }
        main
    ) > "$task_tmp/partial-$failed_source.log" 2>&1
    then
        echo 'error: partial update accepted' >&2
        exit 1
    fi
    [[ "$(cat "$task_tmp/partial-$failed_source/ads.txt")" == '.old.example' ]]
    [[ "$(cat "$task_tmp/partial-$failed_source/china.txt")" == '.old.cn' ]]
    [[ "$(cat "$task_tmp/partial-$failed_source/apple-china.txt")" == '.old.apple.cn' ]]
    [[ "$(ls -A "$task_tmp/partial-$failed_source")" == $'ads.txt\napple-china.txt\nchina.txt' ]]
done

# Upstream resolver changes do not alter the domain list.
(
    source "$repo_root/domainset-generator.sh"
    normalize_domains dnsmasq-china test <<'EOF'
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
    printf '.apple.com.cn\n' > apple-china.txt
    GITHUB_SHA=test-commit bash "$repo_root/scripts/release-metadata.bash"
    jq -e '.commit == "test-commit" and .files["ads.txt"].lines == 1
        and .files["china.txt"].lines == 2 and .generated_at != ""
        and .files["china.txt"].source != ""
        and (.files | length) == 3
        and .files["apple-china.txt"].lines == 1
        and (.files["apple-china.txt"].source | endswith("/apple.china.conf"))' manifest.json >/dev/null
    china_hash=$(shasum -a 256 china.txt 2>/dev/null || sha256sum china.txt)
    [[ "$(jq -r '.files["china.txt"].sha256' manifest.json)" == "${china_hash%% *}" ]]
    grep -F 'DNS routing' release-notes.md >/dev/null
) > "$task_tmp/metadata.log"
printf 'reliability tests passed\n'
