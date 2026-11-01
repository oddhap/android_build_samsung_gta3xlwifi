#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run as builder on the Linux build VM. Does not build or install a ROM.
set -euo pipefail
export PATH="$HOME/bin:$PATH" LC_ALL=C.UTF-8 LANG=C.UTF-8
port=/srv/android/ports/lineage-23.2-arm64
top=/srv/android/src/lineage-23.2-arm64
artifacts=/srv/android/artifacts/lineage-23.2-arm64
logs=/srv/android/logs/lineage-23.2-arm64
baseline=/srv/android/src/lineage-21.0-arm64/device/samsung/gta3xlwifi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'Requires x86_64 Linux.'
[[ $EUID != 0 ]] || fail 'Run as builder, not root.'
[[ $(id -un) == builder ]] || fail 'This setup is configured for the builder account.'
[[ -d /srv/android && ! -L /srv/android ]] || fail 'Missing build volume.'
mountpoint -q /srv/android || fail '/srv/android must be mounted before setup.'
for path in "$port" "$top" "$artifacts" "$logs"; do
    [[ ! -L $path ]] || fail "Refusing symlink: $path"
done
mkdir -p "$port" "$artifacts" "$logs"
exec 9>"$logs/setup.lock"
flock -n 9 || fail 'Another 23.2 setup is active.'
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/setup.exit"; exit "$rc"' EXIT
if [[ -f $artifacts/SOURCE_SYNC_COMPLETE ]]; then
    printf 'Sources already prepared; not resyncing an existing port. See %s\n' "$artifacts/setup-report.json"
    exit 0
fi
if [[ ! -d $top/.repo ]]; then
    free_bytes=$(df --output=avail -B1 /srv/android | tail -1)
    (( free_bytes >= 450 * 1024 * 1024 * 1024 )) || fail 'Need at least 450 GiB free for initial independent checkout and build headroom.'
    [[ ! -e $top || -z $(ls -A "$top") ]] || fail 'Existing non-repo source directory is not empty.'
else
    [[ -f $port/manifest-head.txt ]] || fail 'Unrecognized existing checkout; refusing to resync.'
fi
df -h / /srv/android
free -h
nproc
packages=(git-core git-lfs gnupg flex bison build-essential zip curl
    zlib1g-dev libc6-dev-i386 lib32z1-dev x11proto-core-dev libx11-dev
    libgl1-mesa-dev libxml2-utils xsltproc unzip fontconfig python3
    python3-protobuf python3-venv ccache rsync lz4 liblz4-tool libssl-dev
    libelf-dev bc libncurses-dev schedtool squashfs-tools libxml2 repo)
missing=()
for package in "${packages[@]}"; do
    if [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true) != 'install ok installed' ]]; then
        # An existing official repo launcher is sufficient.
        if [[ $package == repo ]] && command -v repo >/dev/null; then continue; fi
        missing+=("$package")
    fi
done
if (( ${#missing[@]} )); then
    printf 'Missing packages: %s\n' "${missing[*]}"
    sudo -n true || fail 'Install the listed packages with sudo, then rerun setup. No interactive sudo is available in this background job.'
    sudo -n apt-get update
    sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
fi
git var GIT_AUTHOR_IDENT >/dev/null || fail 'Configure Git user.name and user.email for builder, then rerun.'
repo version
mkdir -p "$top"
cd "$top"
if [[ ! -f $port/manifest-head.txt ]]; then
    git ls-remote --exit-code https://github.com/LineageOS/android.git refs/heads/lineage-23.2 > "$port/manifest-head.txt.tmp"
    awk 'NF == 2 {print $1}' "$port/manifest-head.txt.tmp" > "$port/manifest-head.txt"
fi
manifest_head=$(cat "$port/manifest-head.txt")
[[ $manifest_head =~ ^[0-9a-f]{40}$ ]] || fail 'Invalid manifest revision.'
if [[ ! -d .repo ]]; then
    # Independent objects: no alternates into the preserved 21/TWRP trees.
    repo init -u https://github.com/LineageOS/android.git -b "$manifest_head" \
        --depth=1 --no-clone-bundle --git-lfs
fi
[[ $(git -C .repo/manifests rev-parse HEAD) == "$manifest_head" ]] || fail 'Manifest HEAD changed.'
mkdir -p .repo/local_manifests
if [[ -f .repo/local_manifests/gta3xlwifi.xml ]]; then
    cmp "$script_dir/gta3xlwifi.xml" .repo/local_manifests/gta3xlwifi.xml || fail 'Local manifest changed; inspect manually.'
else
    cp "$script_dir/gta3xlwifi.xml" .repo/local_manifests/gta3xlwifi.xml
fi
# Bounded retries keep an unattended overnight sync resilient to transient
# network/server errors. Never force checkout or discard local modifications.
sync_ok=false
for attempt in 1 2 3 4 5; do
    printf '\n[%s] Source sync attempt %s/5\n' "$(date -u +%FT%TZ)" "$attempt"
    if repo sync -c -j8 --no-clone-bundle --no-tags --optimized-fetch --fail-fast; then
        sync_ok=true
        break
    fi
    if (( attempt < 5 )); then
        delay=$((60 * attempt * attempt))
        printf 'Sync failed; retrying in %s seconds.\n' "$delay"
        sleep "$delay"
    fi
done
[[ $sync_ok == true ]] || fail 'Source sync failed after five attempts; inspect the log and rerun setup to resume.'
repo manifest -r -o "$artifacts/platform-manifest.xml.tmp"
python3 "$script_dir/audit.py" "$top" "$artifacts/platform-manifest.xml.tmp" "$artifacts/source-audit.json"
mv "$artifacts/platform-manifest.xml.tmp" "$artifacts/platform-manifest.xml"

# Reuse only hash-bound binary inputs from the working Android 14 baseline.
# These are experimental inputs for 23.2, not proof of Android 16 compatibility.
python3 - "$baseline" "$top/device/samsung/gta3xlwifi" "$artifacts" <<'PY'
import hashlib, json, shutil, sys
from pathlib import Path
src, dst, out = map(Path, sys.argv[1:])
expected = {
    'Image': '33c1a0d1b9e2696decd53fbedfc2231385b74464f4058a54b93ff06ff7c72553',
    'dtbo.img': 'b9041c37713a745290d9a0203423436b6caa7a1307ced79b6963b4f1f0271c4b',
    'vendor.img': '276777b5bde1dac2f31dbe9299c79e02c07486df6ff7b2ecad03cc722edee939',
}
def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for data in iter(lambda: f.read(1024 * 1024), b''): h.update(data)
    return h.hexdigest()
for name, sha in expected.items():
    if digest(src/'prebuilt'/name) != sha:
        raise SystemExit(f'Baseline checksum mismatch: {name}')
(dst/'prebuilt').mkdir(exist_ok=True)
for name, sha in expected.items():
    target = dst/'prebuilt'/name
    if target.exists() and digest(target) != sha:
        raise SystemExit(f'Refusing to overwrite changed port input: {target}')
    if not target.exists(): shutil.copy2(src/'prebuilt'/name, target)
    if digest(target) != sha: raise SystemExit(f'Copy verification failed: {name}')
stock = dst/'configs/stock'
if not stock.exists(): shutil.copytree(src/'configs/stock', stock, symlinks=True)
def tree_hashes(root):
    return {str(p.relative_to(root)): ('symlink:' + str(p.readlink()) if p.is_symlink() else digest(p))
            for p in sorted(root.rglob('*')) if p.is_file() or p.is_symlink()}
stock_hashes = tree_hashes(src/'configs/stock')
if not stock_hashes or stock_hashes != tree_hashes(stock):
    raise SystemExit('Stock metadata differs; inspect instead of overwriting.')
(out/'baseline-inputs.json').write_text(json.dumps({
    'baseline_android': '14', 'target_android': '16', 'files': expected,
    'stock_metadata': stock_hashes, 'android16_compatibility_tested': False,
}, indent=2) + '\n')
PY
# Product configuration bind-mounts CCACHE_DIR through nsjail. The bind source
# must already be a directory, even before the first compilation.
[[ ! -L /srv/android/ccache-lineage-23.2 ]] || fail 'Refusing a symlinked compiler cache.'
mkdir -p /srv/android/ccache-lineage-23.2
cat > "$port/env.sh" <<'ENV'
# Source this from a fresh Bash shell before source build/envsetup.sh.
export PATH="$HOME/bin:$PATH"
export LC_ALL=C.UTF-8 LANG=C.UTF-8
# Relative to this checkout: some 23.2 test_package rules reject absolute OUT_DIR.
export OUT_DIR=out
export USE_CCACHE=1 CCACHE_EXEC=/usr/bin/ccache
export CCACHE_DIR=/srv/android/ccache-lineage-23.2 CCACHE_MAXSIZE=30G
export LINEAGE_BUILD_JOBS=16
cd /srv/android/src/lineage-23.2-arm64
ENV
python3 - "$artifacts" "$manifest_head" <<'PY'
import datetime, json, sys
from pathlib import Path
out = Path(sys.argv[1])
(out/'setup-report.json').write_text(json.dumps({
    'status': 'sources-prepared-porting-required',
    'completed_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'branch': 'lineage-23.2', 'manifest_commit': sys.argv[2],
    'locked_manifest': str(out/'platform-manifest.xml'),
    'source_audit': str(out/'source-audit.json'),
    'compiled': False, 'device_modified': False,
    'existing_signing_keys_modified': False,
}, indent=2) + '\n')
PY
date -u +%FT%TZ > "$artifacts/SOURCE_SYNC_COMPLETE"
printf '23.2 sources and environment prepared. Device/platform porting and compilation remain.\n'
