#!/usr/bin/env bash
# Mirror NIST's NVD JSON feeds to one rolling GitHub release.
#   - the CPE dictionary and CPE match tarballs (nvdcpe-2.0.tar.gz, nvdcpematch-2.0.tar.gz)
#   - the CVE feeds: nvdcve-2.0-<year>.json.gz for every year since 2002, -modified and -recent
# each with its .meta. Only feeds whose .meta sha256 changed since the release's copy are
# fetched; every verified file replaces its asset in the single release RELEASE_TAG, the
# data file before its .meta, so a reader that finds a .meta can trust the file beside it.
# Up to PARALLEL feeds are processed at once, a big one as several byte ranges; every log
# line names its feed, a progress line is printed while each download runs, and a per-feed
# table goes to the job summary.
# Needs: curl, gh (authenticated via GH_TOKEN), tar, gzip, sha256sum.
set -euo pipefail

BASE=https://nvd.nist.gov/feeds/json
REPO="${GITHUB_REPOSITORY:?set GITHUB_REPOSITORY owner/repo}"
RELEASE_TAG="${RELEASE_TAG:-feeds}"
# Stop starting new downloads after this many seconds; what is verified by then is published,
# the rest waits for the next run (the job has a hard limit and NIST can be very slow).
BUDGET_SECONDS="${BUDGET_SECONDS:-15000}"
# Feeds processed at once. Kept small: NIST throttles and cuts long streams.
PARALLEL="${PARALLEL:-4}"
# A file is downloaded as one byte range per SEGMENT_MIB, at most SEGMENTS ranges at once.
SEGMENTS="${SEGMENTS:-6}"
SEGMENT_MIB="${SEGMENT_MIB:-32}"
# Seconds between progress lines while a download runs.
PROGRESS_SECONDS="${PROGRESS_SECONDS:-30}"
ASSET_BASE="https://github.com/$REPO/releases/download/$RELEASE_TAG"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"
START=$(date +%s)
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
mkdir results

# Feed list: path under $BASE without extension, and the data extension.
# The big CPE match tarball goes first so it is not the one left running at the end.
feeds() {
  echo "cpematch/2.0/nvdcpematch-2.0 tar.gz"
  echo "cpe/2.0/nvdcpe-2.0 tar.gz"
  echo "cve/2.0/nvdcve-2.0-modified json.gz"
  echo "cve/2.0/nvdcve-2.0-recent json.gz"
  local y; for y in $(seq "$(date -u +%Y)" -1 2002); do echo "cve/2.0/nvdcve-2.0-$y json.gz"; done
}

meta_field() { sed -n "s/^$2:\([^[:space:]]*\).*/\1/p" "$1" | tr -d '\r'; }
elapsed() { echo $(( $(date +%s) - START )); }
mib() { awk -v b="$1" 'BEGIN { printf "%.1f MiB", b / 1048576 }'; }
hms() { printf '%dh%02dm%02ds' $(($1/3600)) $(($1%3600/60)) $(($1%60)); }

# content_sha <file> <ext>: the sha256 NIST publishes — of the files inside a tar.gz, of the
# uncompressed JSON for a json.gz.
content_sha() {
  case $2 in
    tar.gz) tar -xzOf "$1" | sha256sum | cut -d' ' -f1 ;;
    *)      gzip -dc "$1" | sha256sum | cut -d' ' -f1 ;;
  esac
}

fsize() { stat -c %s "$1" 2>/dev/null || echo 0; }

# fetch_part <tag> <url> <part> <first-byte> <last-byte>: fetch one byte range into <part>,
# resuming from what is on disk. HTTP/1.1 only: a resume over HTTP/2 can corrupt the file
# (measured). Only a 206 reply is kept, so a server that ignores the range cannot splice the
# wrong bytes in. An attempt gives up after 30s without data (NIST stalls often).
fetch_part() {
  local tag=$1 url=$2 part=$3 first=$4 last=$5 need have code tries=0 nogrow=0
  need=$(( last - first + 1 ))
  while :; do
    have=$(fsize "$part")
    [ "$have" -ge "$need" ] && break
    tries=$((tries+1))
    code=$(curl -s --http1.1 --connect-timeout 15 --speed-limit 1 --speed-time 30 \
      -r "$(( first + have ))-$last" -o "$part.chunk" -w '%{http_code}' "$url" || true)
    if [ "$code" = 206 ] && [ "$(fsize "$part.chunk")" -gt 0 ]; then
      cat "$part.chunk" >> "$part"; nogrow=0
    else
      nogrow=$((nogrow+1)); sleep 5
    fi
    rm -f "$part.chunk"
    [ $nogrow -ge 10 ] && { echo "::warning::$tag $part: no progress in 10 attempts (last HTTP $code)"; return 1; }
    [ $tries -ge 1000 ] && { echo "::warning::$tag $part: gave up after 1000 attempts"; return 1; }
  done
  [ "$(fsize "$part")" -eq "$need" ] || { echo "::warning::$tag $part: $(fsize "$part") bytes, want $need"; return 1; }
}

# download <tag> <url> <dest> <want-bytes>: NIST throttles each connection (measured: four range
# requests together ran 3x one stream), so a big file is fetched as up to SEGMENTS byte ranges
# at once, one per SEGMENT_MIB, then joined. Prints a progress line every PROGRESS_SECONDS.
download() {
  local tag=$1 url=$2 dest=$3 want=$4 n seg i first pids=() ok=1 t0 now cur prev=0 rate
  n=$(( (want + SEGMENT_MIB * 1048576 - 1) / (SEGMENT_MIB * 1048576) ))
  [ "$n" -ge 1 ] || n=1
  [ "$n" -le "$SEGMENTS" ] || n=$SEGMENTS
  seg=$(( (want + n - 1) / n ))
  rm -f "$dest" "$dest".part*
  t0=$(date +%s)
  if [ "$n" -gt 1 ]; then echo "$tag   in $n parts of up to $(mib "$seg")"; fi
  for (( i = 0; i < n; i++ )); do
    first=$(( i * seg ))
    last=$(( first + seg - 1 )); [ "$last" -lt "$want" ] || last=$(( want - 1 ))
    fetch_part "$tag" "$url" "$dest.part$i" "$first" "$last" &
    pids+=($!)
  done
  parts_size() { cat "$dest".part* 2>/dev/null | wc -c; }
  while :; do
    local alive=0 pid
    for pid in "${pids[@]}"; do kill -0 "$pid" 2>/dev/null && alive=1; done
    [ $alive -eq 1 ] || break
    sleep "$PROGRESS_SECONDS" & wait $! || true
    cur=$(parts_size); now=$(date +%s)
    rate=$(( (cur - prev) / PROGRESS_SECONDS )); prev=$cur
    echo "$tag   $(mib "$cur") / $(mib "$want") ($(( cur * 100 / want ))%), $(mib "$rate")/s, $((now - t0))s in"
  done
  for pid in "${pids[@]}"; do wait "$pid" || ok=0; done
  [ $ok -eq 1 ] || { rm -f "$dest".part*; return 1; }
  for (( i = 0; i < n; i++ )); do cat "$dest.part$i"; done > "$dest"
  rm -f "$dest".part*
  [ "$(fsize "$dest")" -eq "$want" ] || { echo "::warning::$tag $(fsize "$dest") bytes, want $want"; return 1; }
  echo "$tag   downloaded in $(( $(date +%s) - t0 ))s"
}

# result <name> <status> <bytes> <seconds> <note>: one line per feed in results/<name>.
result() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" > "results/$1"; }

# process_feed <path> <ext>: fetch, verify and publish one feed; always records a result.
process_feed() {
  local path=$1 ext=$2 name data meta tag want sha prev got t0
  name=$(basename "$path"); data="$name.$ext"; meta="$name.meta"; tag="[$name]"
  t0=$(date +%s)
  if ! curl -fsSL --retry 5 --retry-all-errors -o "$meta" "$BASE/$path.meta"; then
    echo "::warning::$tag .meta not fetched"; result "$name" failed 0 0 ".meta not fetched"; return
  fi
  want=$(meta_field "$meta" gzSize); sha=$(meta_field "$meta" sha256 | tr 'A-F' 'a-f')
  if [ -z "$want" ] || [ -z "$sha" ]; then
    echo "::warning::$tag .meta lacks gzSize/sha256"; result "$name" failed 0 0 ".meta lacks gzSize/sha256"; return
  fi
  prev=$(curl -fsSL "$ASSET_BASE/$meta" 2>/dev/null | sed -n 's/^sha256:\([^[:space:]]*\).*/\1/p' | tr -d '\r' | tr 'A-F' 'a-f' || true)
  if [ -n "$prev" ] && [ "$prev" = "$sha" ]; then
    echo "$tag unchanged"; result "$name" unchanged "$want" 0 ""; return
  fi
  echo "$tag fetching $(mib "$want")"
  if ! download "$tag" "$BASE/$path.$ext" "$data" "$want"; then
    result "$name" failed "$want" $(( $(date +%s) - t0 )) "download incomplete"; return
  fi
  if ! gzip -t "$data" 2>/dev/null; then
    echo "::warning::$tag gzip integrity failed"; result "$name" failed "$want" $(( $(date +%s) - t0 )) "gzip integrity failed"; return
  fi
  got=$(content_sha "$data" "$ext")
  if [ "$got" != "$sha" ]; then
    echo "::warning::$tag content sha256 $got, want $sha"; result "$name" failed "$want" $(( $(date +%s) - t0 )) "content sha256 mismatch"; return
  fi
  echo "$tag verified, uploading"
  # Data file first, then its .meta, each replacing the previous asset.
  if ! gh release upload "$RELEASE_TAG" --repo "$REPO" --clobber "$data" </dev/null ||
     ! gh release upload "$RELEASE_TAG" --repo "$REPO" --clobber "$meta" </dev/null; then
    echo "::warning::$tag upload failed"; result "$name" failed "$want" $(( $(date +%s) - t0 )) "upload failed"; return
  fi
  rm -f "$data"
  echo "$tag published in $(( $(date +%s) - t0 ))s"
  result "$name" published "$want" $(( $(date +%s) - t0 )) ""
}

count() { cat results/* 2>/dev/null | awk -F'\t' -v s="$1" '$2 == s' | wc -l; }
progress() {
  echo "== $(ls results | wc -l)/$total done after $(hms "$(elapsed)"): $(count published) published," \
       "$(count unchanged) unchanged, $(count failed) failed, $(count skipped) left for the next run;" \
       "$(jobs -rp | wc -l) running"
}

ensure_release() {
  if ! gh release view "$RELEASE_TAG" --repo "$REPO" >/dev/null 2>&1; then
    gh release create "$RELEASE_TAG" --repo "$REPO" --title "NVD feeds (rolling)" \
      --notes "Rolling mirror of NIST's NVD JSON feeds; every asset is replaced in place when NIST's .meta changes. Verified against each .meta (gzSize and content sha256)."
  fi
}

ensure_release
mapfile -t FEED_LIST < <(feeds)
total=${#FEED_LIST[@]}
echo "== $total feeds, $PARALLEL at a time, budget $(hms "$BUDGET_SECONDS")"
for line in "${FEED_LIST[@]}"; do
  read -r path ext <<<"$line"
  name=$(basename "$path")
  while [ "$(jobs -rp | wc -l)" -ge "$PARALLEL" ]; do wait -n || true; progress; done
  if [ "$(elapsed)" -ge "$BUDGET_SECONDS" ]; then
    echo "[$name] time budget spent, left for the next run"; result "$name" skipped 0 0 "time budget spent"; continue
  fi
  # A subshell that dies before recording a result (set -e) is reported as failed below.
  ( process_feed "$path" "$ext" ) &
done
while [ "$(jobs -rp | wc -l)" -gt 0 ]; do wait -n || true; progress; done
wait || true
for line in "${FEED_LIST[@]}"; do
  name=$(basename "${line%% *}")
  [ -f "results/$name" ] || result "$name" failed 0 0 "processing aborted (see log)"
done

published=$(count published); unchanged=$(count unchanged); failed=$(count failed); skipped=$(count skipped)
{
  echo "## NVD feed mirror"
  echo
  echo "$published published, $unchanged unchanged, $failed failed, $skipped left for the next run, in $(hms "$(elapsed)") with $PARALLEL at a time."
  echo
  echo "| Feed | Result | Size | Time | Note |"
  echo "|---|---|---:|---:|---|"
  for line in "${FEED_LIST[@]}"; do
    name=$(basename "${line%% *}")
    IFS=$'\t' read -r _ status bytes secs note < "results/$name"
    echo "| \`$name\` | $status | $(mib "$bytes") | $(hms "$secs") | $note |"
  done
} >> "$SUMMARY"

gh release edit "$RELEASE_TAG" --repo "$REPO" --notes "Rolling mirror of NIST's NVD JSON feeds, replaced in place when NIST's .meta changes and verified against it (gzSize, content sha256). Last run $(date -u +'%Y-%m-%d %H:%M UTC'): $published published, $unchanged unchanged, $failed failed, $skipped left for the next run." >/dev/null
echo "Done: $published published, $unchanged unchanged, $failed failed, $skipped left for the next run."
[ "$failed" -eq 0 ] || exit 1
