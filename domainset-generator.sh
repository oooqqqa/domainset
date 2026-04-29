#!/usr/bin/env bash
set -euo pipefail

# 最小行数阈值：低于此值视为异常（上游源可能返回空内容或格式变更）
MIN_LINES=${MIN_LINES:-1000}

process() {
    local output=$1; shift
    (( $# > 0 )) || {
        echo "no sources" >&2
        return 1
    }

    local tmp
    tmp=$(mktemp)
    # 确保临时文件在脚本退出时被清理
    trap 'rm -f "$tmp"' EXIT

    for url in "$@"; do
        curl -fsSL "$url" || {
            echo "failed: $url" >&2
            exit 1
        }
    done | awk '
    BEGIN { unmatched = 0 }
    {
        gsub(/\r/, "")
    }
    /^\|\|[A-Za-z0-9._-]+\^$/ {
        sub(/^\|\|/, ".")
        sub(/\^.*/, "")
        print
        next
    }
    /^[.]?[A-Za-z0-9._-]+$/ {
        print
        next
    }
    /^server=\/[A-Za-z0-9._-]+\// {
        sub(/^server=\//, ".")
        sub(/\/.*/, "")
        print
        next
    }
    { unmatched++ }
    END {
        if (unmatched > 0)
            printf("WARN: %d lines not matched by any rule\n", unmatched) > "/dev/stderr"
    }
    ' | LC_ALL=C sort -u > "$tmp"

    # 内容验证：检查最小行数
    local count
    count=$(wc -l < "$tmp")
    if (( count < MIN_LINES )); then
        echo "ERROR: $output has only $count lines (expected >= $MIN_LINES), aborting to avoid overwriting valid data" >&2
        rm -f "$tmp"
        exit 1
    fi

    mv "$tmp" "$output"

    printf "%s: %d\n" "$output" "$count"
}

process "blocklist.txt" \
    https://big.oisd.nl

process "nsfw.txt" \
    https://nsfw.oisd.nl \
    https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/nsfw.txt

# 示例行：server=/012233.com/114.114.114.114
# 提取域名：012233.com，加一个前缀点 -> .012233.com
process "chinese-mainland.txt" \
    https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/refs/heads/master/accelerated-domains.china.conf

# 所有文件处理完成，清除 trap（临时文件已 mv 走）
trap - EXIT
