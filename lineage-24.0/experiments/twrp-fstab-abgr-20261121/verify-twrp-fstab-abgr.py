# Read-only: after the owner-approved write, boot the NEW TWRP and confirm it decrypts /data,
# has no /product in either fstab and is the reviewed image. Stays in TWRP so the owner can
# check the accent colour on screen; reboot to system is a separate step (--reboot-system).
# Never writes, formats, or changes recovery/keys.
from pathlib import Path
import subprocess, time, json, datetime, sys
W = Path(__file__).resolve().parent
adb = ['/opt/homebrew/bin/adb', '-s', 'R52N8038D1L']
AFTER = '33875693066aeb5e9f27bc2d469c3052b438552395cb476ed0d8340348765f05'
def run(args, timeout=60): return subprocess.run(adb + args, capture_output=True, timeout=timeout, check=True).stdout
def wait(state, secs):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        r = subprocess.run(adb + ['get-state'], capture_output=True, timeout=5)
        if r.stdout.strip() == state: return
        time.sleep(2)
    raise RuntimeError('state ' + state.decode() + ' not reached')
if '--reboot-system' in sys.argv:
    run(['reboot', 'system'], 20); print('rebooting to system'); sys.exit(0)
out = W/'post-write-check'; out.mkdir(exist_ok=False)
assert run(['get-state']).strip() in (b'device', b'recovery')
run(['reboot', 'recovery'], 20); time.sleep(8); wait(b'recovery', 150)
end = time.monotonic() + 120
while True:
    log = run(['exec-out', 'cat', '/tmp/recovery.log'])
    if b'Data successfully decrypted' in log or b'FBE keystore unavailable' in log or b'Unable to decrypt FBE device' in log or time.monotonic() > end: break
    time.sleep(3)
(out/'recovery.log').write_bytes(log)
ok = b'Data successfully decrypted' in log and b'FBE keystore unavailable' not in log
listing = run(['shell', 'ls /data/misc/vold/user_keys/ce/0/current; echo ---; ls /data/media/0; echo ---; '
               'grep -c product /etc/recovery.fstab /etc/twrp.fstab; echo ---; getenforce; '
               'dd if=/dev/block/platform/13500000.dwmmc0/by-name/recovery bs=4 skip=11 count=1 2>/dev/null | od -An -tx4; '
               'sha256sum /dev/block/platform/13500000.dwmmc0/by-name/recovery /system/lib64/libminuitwrp.so'], 120).decode()
(out/'listing.txt').write_text(listing)
keys, media, fstab, rest = listing.split('---\n')
rows = rest.split()
L = log.decode(errors='replace')
result = {'twrp_decrypted': ok, 'user_keys_ce0_names': keys.split(), 'media0_has_Android': 'Android' in media.split(),
          'fstab_product_counts': fstab.split(), 'product_in_twrp_log': [l for l in L.splitlines() if '/product' in l][:10],
          'pixel_format_log': [l for l in L.splitlines() if 'GGL_PIXEL_FORMAT' in l or 'red.offset' in l],
          'enforcing': rows[0] == 'Enforcing', 'recovery_header_word': rows[1], 'recovery_sha256': rows[2], 'libminuitwrp_sha256': rows[4],
          'at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
(out/'report.json').write_text(json.dumps(result, indent=2) + '\n'); print(json.dumps(result, indent=2))
assert ok and 'encrypted_key' in result['user_keys_ce0_names'] and result['media0_has_Android'] and result['enforcing']
assert all(x.endswith(':0') for x in result['fstab_product_counts'])
assert result['recovery_header_word'] == '220001ab' and result['recovery_sha256'] == AFTER
assert result['libminuitwrp_sha256'] == '24a239bf02102f04ddaf67633c9d57e4180f9c11380922c1c6f2f01484ef4a11'
print('PASS new TWRP decrypted /data, no /product, reviewed image. Owner: check the accent colour on screen.')
