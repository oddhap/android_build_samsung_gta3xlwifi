#!/usr/bin/env python3
"""Adapt isolated signing and OTA hooks; never generate or modify private keys."""
import hashlib
from pathlib import Path

ROOT = Path('/srv/android')
TOP = ROOT/'src/lineage-21.0-arm64'
DEVICE = TOP/'device/samsung/gta3xlwifi'
PORT = ROOT/'ports/lineage-21-arm64/lineage-21'
signer = PORT/'tools/sign-release.py'
text = signer.read_text()
text = text.replace("default=Path('/srv/android/src/lineage-21.0')", "default=Path('/srv/android/src/lineage-21.0-arm64')")
text = text.replace("default=Path('/srv/android/artifacts/lineage-21/release')", "default=Path('/srv/android/artifacts/lineage-21-arm64/release')")
if '    if pk8.exists() != cert.exists():' in text:
    start = text.index('    if pk8.exists() != cert.exists():')
    end = text.index('    return stem', start)
    text = text[:start] + '''    if not all(path.is_file() for path in (pk8, cert, pem)):
        raise SystemExit('Missing persistent signing material: ' + name)
''' + text[end:]
text = text.replace("key_map_file.write_text(json.dumps(mapping, indent=2) + '\\n')", "# The authoritative certificate map is read-only for this port.")
text = text.replace("'-privatekeys.zip'", "'-arm64-privatekeys.zip'")
text = text.replace('    # Vendor is not installed by this OTA; retain the tested stock partition.', '    if archive.read("IMAGES/vendor.img") != vendor_before:\n        raise SystemExit("Signing changed the reviewed hybrid vendor image")')
if '    vendor_before = ' not in text:
    text = text.replace("    old_boot = archive.read('BOOTABLE_IMAGES/boot.img')", "    old_boot = archive.read('BOOTABLE_IMAGES/boot.img')\n    vendor_before = archive.read('IMAGES/vendor.img')")
if '--resume-signed-target-files' not in text:
    text = text.replace('args = parser.parse_args()', '''parser.add_argument('--resume-signed-target-files', action='store_true',
                    help='Resume a completed signed ZIP; final signature verification remains mandatory')
args = parser.parse_args()''')
    expected_vendor = hashlib.sha256((DEVICE/'prebuilt/vendor.img').read_bytes()).hexdigest()
    text = text.replace("    vendor_before = archive.read('IMAGES/vendor.img')", f'''    vendor_before = archive.read('IMAGES/vendor.img')
    vendor_info = archive.getinfo('IMAGES/vendor.img')
    if hashlib.sha256(vendor_before).hexdigest() != '{expected_vendor}':
        raise SystemExit('Unsigned vendor differs from the reviewed image')''')
    text = text.replace('run(command)\nwith zipfile.ZipFile(signed)', '''if args.resume_signed_target_files:
    with zipfile.ZipFile(signed) as archive:
        if archive.testzip() is not None:
            raise SystemExit('Existing signed target-files ZIP failed CRC verification')
        if archive.read('IMAGES/boot.img') != old_boot:
            raise SystemExit('Existing signed boot differs from the current input')
else:
    run(command)
# sign_target_files_apks regenerates IMAGES and skips vendor without VENDOR/.
# This project deliberately ships a reviewed prebuilt vendor, not a rebuilt
# donor tree. Carry its exact bytes forward before whole-file OTA signing.
with zipfile.ZipFile(signed, 'a') as archive:
    if 'IMAGES/vendor.img' not in archive.namelist():
        archive.writestr(vendor_info, vendor_before)
with zipfile.ZipFile(signed)''')
signer.write_text(text)

hooks = DEVICE/'releasetools.py'
text = hooks.read_text()
if '_VENDOR_SHA256 =' not in text:
    vendor_sha = hashlib.sha256((DEVICE/'prebuilt/vendor.img').read_bytes()).hexdigest()
    text = text.replace('import re\n', 'import hashlib\nimport os\nimport sparse_img\nimport re\n')
    text = text.replace('_BIN = ', f'_VENDOR_SHA256 = "{vendor_sha}"\n_VENDOR_BYTES = 343932928\n\n_BIN = ', 1)
    anchor = '\n\ndef _end(info):'
    preflight = '''
    # TWRP uses vendor for decryption. Refuse all image writes while mounted.
    # Stop its crypto services after unlocking data, then unmount before install.
    info.script.AppendExtra('unmount("/vendor");')
    info.script.AppendExtra('assert(is_mounted("/vendor") == "" || '
                            'abort("Vendor is busy. Stop recovery crypto services before installation."));')
'''
    if text.count(anchor) != 1: raise SystemExit('Unexpected recovery hook source')
    text = text.replace(anchor, '\n' + preflight + anchor)
    text += '''

def _hybrid_vendor(archive, directory):
    data = archive.read("IMAGES/vendor.img")
    if hashlib.sha256(data).hexdigest() != _VENDOR_SHA256:
        raise ValueError("Hybrid vendor differs from the reviewed image")
    image = sparse_img.SparseImage(os.path.join(directory, "IMAGES", "vendor.img"),
                                  clobbered_blocks="0")
    if image.blocksize * image.total_blocks != _VENDOR_BYTES:
        raise ValueError("Hybrid vendor exceeds the physical vendor layout")
    return image


def FullOTA_GetBlockDifferences(info):
    # Prebuilt vendor is absent from VENDOR/ in target-files, so generic OTA
    # generation skips it. Explicitly include a standard block-image update.
    image = _hybrid_vendor(info.input_zip, info.input_tmp)
    return [common.BlockDifference("vendor", image, src=None)]


def IncrementalOTA_GetBlockDifferences(info):
    target = _hybrid_vendor(info.target_zip, info.target_tmp)
    source = sparse_img.SparseImage(os.path.join(info.source_tmp, "IMAGES", "vendor.img"),
                                   clobbered_blocks="0")
    if source.blocksize * source.total_blocks != _VENDOR_BYTES:
        raise ValueError("Source vendor has an incompatible physical layout")
    return [common.BlockDifference("vendor", target, src=source, check_first_block=True,
                                   version=4, disable_imgdiff=True)]
'''
if '_VENDOR_MOUNT_GUARD =' not in text:
    guard = b'''#!/sbin/sh
[ -r /proc/mounts ] || exit 2
seen=0
while read source mountpoint rest; do
    seen=1
    case "$mountpoint" in /vendor|/vendor/*) exit 1 ;; esac
done < /proc/mounts
[ "$seen" = 1 ] || exit 2
exit 0
'''
    text = text.replace('_VENDOR_BYTES = 343932928',
                        '_VENDOR_BYTES = 343932928\n_VENDOR_MOUNT_GUARD = ' + repr(guard))
    old = '''    info.script.AppendExtra('unmount("/vendor");')
    info.script.AppendExtra('assert(is_mounted("/vendor") == "" || '
                            'abort("Vendor is busy. Stop recovery crypto services before installation."));')'''
    new = '''    # AOSP updater cannot resolve this TWRP's vendor fstab volume.
    # Require the real mount table to be clear; never weaken the pre-write gate.
    common.ZipWriteStr(info.output_zip, "vendor-unmounted-check.sh", _VENDOR_MOUNT_GUARD)
    info.script.AppendExtra('package_extract_file("vendor-unmounted-check.sh", "/tmp/vendor-unmounted-check.sh");')
    info.script.AppendExtra('assert(run_program("/sbin/sh", "/tmp/vendor-unmounted-check.sh") == "0" || '
                            'abort("Vendor is mounted or its state cannot be verified. Stop recovery crypto services and unmount vendor."));')'''
    if text.count(old) != 1:
        raise SystemExit('Unexpected vendor preflight source')
    text = text.replace(old, new)
hooks.write_text(text)
print('Isolated signer requires existing keys; full/incremental OTA explicitly include vendor.')
