#!/usr/bin/env bash
set -euo pipefail

tmp_files=()
processed_lists=()

CUSTOM_RULES_LIST="ntp.nasa.gov
av.samsungiotcloud.cn
safebrowsing.urlsec.qq.com
safebrowsing.googleapis.com
safebrowsing.googleapis-cn.com
.jddebug.com"

ADBLOCK_SOURCES=(
  "https://big.oisd.nl/"
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt"
)

DOMAIN_SOURCES=(
  "https://raw.githubusercontent.com/geekdada/surge-list/refs/heads/master/domain-set/dns-filter.txt"
  "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/refs/heads/master/anti-ad-surge2.txt"
)

OUTPUT_FILE="reject.txt"
OUTPUT_MINI_FILE="reject-mini.txt"

create_temp() {
  local tmp
  tmp=$(mktemp)
  tmp_files+=("$tmp")
  echo "$tmp"
}

cleanup() {
  if [[ ${#tmp_files[@]} -gt 0 ]]; then
    rm -f "${tmp_files[@]}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

log()   { printf "INFO: %s\n" "$*"; }
warn()  { printf "WARN: %s\n" "$*" >&2; }
err()   { printf "ERROR: %s\n" "$*" >&2; }

download_file() {
  local url="$1" dest="$2"
  log "Downloading $(basename "$url")"
  if ! curl -fsSL --connect-timeout 30 --max-time 120 "$url" -o "$dest"; then
    err "Failed to download $url"
    return 1
  fi
  if [[ ! -s "$dest" ]]; then
    err "Downloaded file is empty: $url"
    return 1
  fi
}

process_adblock_format() {
  grep -E '^\|\|[^/]+\^$' "$1" | sed -E 's/^\|\|(.*)\^$/.\1/' | grep -v '^.$'
}

process_plain_domains() {
  grep -vE '^\s*($|#)' "$1" | grep -E '^\.?[a-zA-Z0-9.-]+$'
}

line_count() {
  [[ -f "$1" && -s "$1" ]] && wc -l < "$1" || echo "0"
}

log "Building custom rules"
custom_tmp=$(create_temp)
echo "$CUSTOM_RULES_LIST" | grep -vE '^\s*($|#)' > "$custom_tmp"

handle_source() {
  local url="$1" format="$2"
  local raw=$(create_temp)
  local processed=$(create_temp)

  if download_file "$url" "$raw"; then
    if [[ "$format" == "adblock" ]]; then
      process_adblock_format "$raw" > "$processed"
    else
      process_plain_domains "$raw" > "$processed"
    fi

    if [[ -s "$processed" ]]; then
      processed_lists+=("$processed")
      log "Parsed $(line_count "$processed") rules from $(basename "$url")"
    else
      warn "No valid rules from $url"
    fi
  else
    err "Skipping failed source: $url"
  fi
}

log "Processing Adblock sources"
for url in "${ADBLOCK_SOURCES[@]}"; do
  handle_source "$url" "adblock"
done

log "Processing plain domain sources"
for url in "${DOMAIN_SOURCES[@]}"; do
  handle_source "$url" "plain"
done

if [[ ${#processed_lists[@]} -eq 0 ]]; then
  err "No valid input lists were processed"
  exit 1
fi

log "Generating full reject list"
{
  cat "$custom_tmp"
  cat "${processed_lists[@]}"
} | awk '!seen[$0]++' > "$OUTPUT_FILE"

log "Generating mini reject list"
external_tmp=$(create_temp)
cat "${processed_lists[@]}" > "$external_tmp"

awk '{count[$0]++} END {for (d in count) if (count[d] >= 2) print d}' "$external_tmp" > "${external_tmp}_filtered"

{
  cat "$custom_tmp"
  cat "${external_tmp}_filtered"
} | awk '!seen[$0]++' > "$OUTPUT_MINI_FILE"

log "$(printf "Custom Rules:     %6d" "$(line_count "$custom_tmp")")"
log "$(printf "External Rules:   %6d" "$(cat "${processed_lists[@]}" | wc -l)")"
log "$(printf "Final Reject:     %6d" "$(line_count "$OUTPUT_FILE")")"
log "$(printf "Mini Reject:      %6d" "$(line_count "$OUTPUT_MINI_FILE")")"
log "Finished. Output files: $OUTPUT_FILE, $OUTPUT_MINI_FILE"
