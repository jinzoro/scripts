#!/usr/bin/env bash
set -euo pipefail

########## CONFIG ##########
# SAN hostnames to test via SNI
DOMAINS=(
  int-content.ihg.com
  int-auth-content.ihg.com
  int-connect-content.ihg.com
  int-hcms-content.ihg.com
  int-oc-content.ihg.com
  int-rest-content.ihg.com
)

# Load balancers (IP or DNS). Add :port or leave blank for 443.
LBS=(
  44.221.210.202
  34.198.159.179
  # ihg-cs-awsuse1-sz-lb-01.cloudpowered.systems:443
)

# sslyze flags (set to "" for minimal scan; common: --regular)
SSLyze_FLAGS=${SSLyze_FLAGS:---regular}

# Parallel jobs (increase to speed up)
PARALLEL_JOBS=${PARALLEL_JOBS:-6}

# Output directory (timestamped)
OUTPUT_ROOT=${OUTPUT_ROOT:-sslyze_reports}
######## END CONFIG ########

# --- sanity checks ---
command -v sslyze >/dev/null 2>&1 || {
  echo "Error: sslyze not found in PATH." >&2
  exit 1
}

TS=$(date +%Y%m%d-%H%M%S)
OUTDIR="${OUTPUT_ROOT}/${TS}"
mkdir -p "$OUTDIR"

# Normalize target to include :443 if no port is present
normalize_target() {
  local t="$1"
  if [[ "$t" == *:* ]]; then
    printf "%s" "$t"
  else
    printf "%s:443" "$t"
  fi
}

# Make a filesystem-friendly name
safe_name() {
  local s="$1"
  s="${s//:/-}"    # replace ':' with '-'
  s="${s//\//_}"   # replace '/' with '_'
  printf "%s" "$s"
}

# Run one scan with basic retry (useful for transient LB timeouts)
run_scan() {
  local target="$1" sni="$2"
  local base="sslyze_${sni}_on_$(safe_name "$target")"
  local txt="${OUTDIR}/${base}.txt"
  local json="${OUTDIR}/${base}.json"

  echo "[*] Scanning target=${target} sni=${sni}"
  # retry up to 2 times if it fails
  for attempt in 1 2 3; do
    if sslyze $SSLyze_FLAGS "$target" --sni="$sni" >"$txt" --json_out "$json"; then
      echo "[✓] Done: $base"
      return 0
    else
      echo "[!] Attempt $attempt failed for $base" >&2
      sleep 2
    fi
  done
  echo "[x] Failed after retries: $base" >&2
  return 1
}

# Simple parallelism with job cap
MAX_JOBS="$PARALLEL_JOBS"
for lb in "${LBS[@]}"; do
  target="$(normalize_target "$lb")"
  for host in "${DOMAINS[@]}"; do
    # limit concurrent jobs
    while (( $(jobs -rp | wc -l) >= MAX_JOBS )); do
      wait -n || true
    done
    run_scan "$target" "$host" &
  done
done

# wait for remaining jobs
wait

echo
echo "All scans finished. Reports in: $OUTDIR"
