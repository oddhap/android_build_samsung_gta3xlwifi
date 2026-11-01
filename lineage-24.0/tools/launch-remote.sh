#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Launch from the Mac project checkout. Uploads setup code only, not keys.
set -euo pipefail
payload=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
integration=$(cd -- "$payload/.." && pwd)
key="/Users/oddi/Documents/Samsung-ARM64/.private/build_ed25519"
remote=builder@192.168.0.124
port=/srv/android/ports/lineage-24.0-arm64
remote_payload="$port/tools/$(date -u +%Y%m%dT%H%M%SZ)-$$"
ssh_opts=(-i "$key" -o BatchMode=yes -o ConnectTimeout=10)
[[ -r $key ]] || { printf 'SSH key is unavailable.\n' >&2; exit 1; }
# Do not replace the integration inputs of an active setup job.
remote_state=$(ssh "${ssh_opts[@]}" "$remote" 'bash -s' <<'STATE'
logs=/srv/android/logs/lineage-24.0-arm64
for name in migration setup; do
    if [[ -f $logs/$name.pid ]] && kill -0 "$(cat "$logs/$name.pid")" 2>/dev/null; then
        echo active
        exit 0
    fi
done
echo idle
STATE
)
[[ $remote_state == idle ]] || { echo 'Remote migration/setup is active; inspect its log.'; exit 0; }
ssh "${ssh_opts[@]}" "$remote" "mkdir -p $remote_payload /srv/android/logs/lineage-24.0-arm64"
scp "${ssh_opts[@]}" "$payload/setup.sh" "$payload/audit.py" "$payload/gta3xlwifi.xml" "$payload/legacy-vndk.xml" "$payload/port-revisions.xml" "$remote:$remote_payload/"
scp -r "${ssh_opts[@]}" "$integration" "$remote:$port/"
ssh "${ssh_opts[@]}" "$remote" "bash -s -- $remote_payload" <<'REMOTE'
set -euo pipefail
payload=$1
logs=/srv/android/logs/lineage-24.0-arm64
exec 8>"$logs/launch.lock"
flock -n 8 || { echo 'A launcher is already active.' >&2; exit 1; }
if [[ -f $logs/migration.pid ]] && kill -0 "$(cat "$logs/migration.pid")" 2>/dev/null; then
    echo "Migration is still running; inspect migration.log."
    exit 0
fi
if [[ -f $logs/setup.pid ]] && kill -0 "$(cat "$logs/setup.pid")" 2>/dev/null; then
    echo 'Setup is already running.'
    exit 0
fi
log="$logs/setup-$(date -u +%Y%m%dT%H%M%SZ).log"
nohup bash "$payload/setup.sh" </dev/null >"$log" 2>&1 8>&- &
printf '%s\n' "$!" > "$logs/setup.pid"
ln -sfn "$log" "$logs/setup-latest.log"
printf 'Started setup PID %s. Log: %s\n' "$(cat "$logs/setup.pid")" "$log"
REMOTE
printf '%s\n' 'Follow progress on the build VM: tail -f /srv/android/logs/lineage-24.0-arm64/setup-latest.log'
