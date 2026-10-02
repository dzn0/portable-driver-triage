#!/usr/bin/env bash
# Shard-parallel driver for pipeline.analyze.
#
# Splits every .sys under pipeline_out/drivers/ into N shuffled shards and
# fires one `docker compose run` per shard in parallel. The shards are
# written to reports/_shards/ (inside the mounted volume) so each container
# can read its own sha-list without needing a separate bind mount.
#
# Safe to re-run: --skip-existing on pipeline.analyze means each container
# steps over drivers that already have a bundle for the chosen scope. Index
# writes are concurrency-safe after the O_APPEND patch to append_index().
#
# Usage:   scripts/shard-analyze.sh <scope> [workers]
# Example: scripts/shard-analyze.sh hid-input-control 8
set -euo pipefail

# Keep Git Bash on Windows from rewriting /work/... into a C:\ path when it
# is passed as a plain argv item to docker. Harmless on real Linux.
export MSYS_NO_PATHCONV=1

SCOPE="${1:?scope profile name required (see scope_profiles/)}"
WORKERS="${2:-8}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DRIVERS_DIR="pipeline_out/drivers"
SHARDS_DIR="reports/_shards/${SCOPE}"
LOG_DIR="reports/_shards/${SCOPE}/logs"

if [[ ! -d "$DRIVERS_DIR" ]]; then
  echo "error: $DRIVERS_DIR missing — run pipeline.collect first" >&2
  exit 2
fi

rm -rf "$SHARDS_DIR"
mkdir -p "$SHARDS_DIR" "$LOG_DIR"

# Build the full sha list, shuffled so each shard gets a mix of big/small
# drivers rather than concentrating slow ones in one worker.
ALL_LIST="$SHARDS_DIR/_all.lst"
find "$DRIVERS_DIR" -maxdepth 1 -type f -name '*.sys' -printf '%f\n' \
  | sed 's/\.sys$//' \
  | shuf > "$ALL_LIST"

TOTAL="$(wc -l < "$ALL_LIST")"
if [[ "$TOTAL" -eq 0 ]]; then
  echo "error: no drivers found under $DRIVERS_DIR" >&2
  exit 2
fi

echo "[shard] scope=$SCOPE workers=$WORKERS total=$TOTAL"

# Chunk round-robin so adjacent SHAs (which may share a vendor/size) spread
# across workers evenly. `split -n r/N` would be the gnu equivalent; we do
# it in awk for portability.
awk -v n="$WORKERS" -v out="$SHARDS_DIR" \
    '{ printf "%s\n", $0 > sprintf("%s/shard-%02d.lst", out, (NR-1) % n) }' \
    "$ALL_LIST"

pids=()
for i in $(seq 0 $((WORKERS-1))); do
  shard_name="$(printf 'shard-%02d.lst' "$i")"
  shard_in="$SHARDS_DIR/$shard_name"
  shard_log="$LOG_DIR/$shard_name.log"
  if [[ ! -s "$shard_in" ]]; then
    echo "[shard] worker $i: empty, skipping"
    continue
  fi
  n_in_shard="$(wc -l < "$shard_in")"
  echo "[shard] worker $i: $n_in_shard drivers -> $shard_log"

  # Each container is independent. --skip-existing is cheap (dir glob).
  docker compose run --rm --no-TTY analyze \
      pipeline.analyze --all \
      --scope "$SCOPE" \
      --skip-existing \
      --sha-list "/work/reports/_shards/${SCOPE}/${shard_name}" \
      > "$shard_log" 2>&1 &
  pids+=("$!")
done

echo "[shard] launched ${#pids[@]} workers; tailing in parallel..."
echo "[shard] follow a single worker with: tail -f ${LOG_DIR}/shard-00.lst.log"

status=0
for pid in "${pids[@]}"; do
  if ! wait "$pid"; then
    status=1
  fi
done

echo "[shard] all workers done (status=$status)"
if [[ -f reports/index.jsonl ]]; then
  echo "[shard] index rows: $(wc -l < reports/index.jsonl)"
fi
exit "$status"
