#!/usr/bin/env bash
# Mocks replace functions that the sourced generator calls.
# shellcheck disable=SC2329
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT

# A download or parse failure in any list must preserve every existing output.
# set -e is off inside the `if` condition, so this also checks that failures exit via die.
for mode in fetch parse; do
    dir="$task_tmp/$mode"
    mkdir "$dir"
    if (
        cd "$dir"
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
                # Valid lines come first so the minimum count cannot mask a missed failure.
                "$china_source_url")
                    printf 'server=/new.cn/114.114.114.114\n' > "$2"
                    [[ "$mode" != fetch ]] || return 1
                    ;;
                "$apple_china_source_url")
                    printf 'server=/new.apple.cn/1.1.1.1\n' > "$2"
                    [[ "$mode" != parse ]] || printf 'invalid-input\n' >> "$2"
                    ;;
            esac
        }
        main
    ) > "$dir.log" 2>&1
    then
        echo "error: $mode failure accepted" >&2
        exit 1
    fi
    [[ "$(cat "$dir/ads.txt")" == '.old.example' ]]
    [[ "$(cat "$dir/china.txt")" == '.old.cn' ]]
    [[ "$(cat "$dir/apple-china.txt")" == '.old.apple.cn' ]]
    [[ "$(ls -A "$dir")" == $'ads.txt\napple-china.txt\nchina.txt' ]]
done

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
