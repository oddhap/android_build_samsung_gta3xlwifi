#!/usr/bin/env python3
"""Check the signed target-files and physical product image for usage fixes."""
import argparse, hashlib, json, re, struct, subprocess, tempfile, zipfile
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument('--release', type=Path, default=Path('/srv/android/artifacts/lineage-21-arm64/release'))
args = parser.parse_args()
top = Path('/srv/android/src/lineage-21.0-arm64')
device = top / 'device/samsung/gta3xlwifi'
checks = {'hardware_tested': False}
tree = args.release / 'verified-target-files'
inputs = json.loads(Path(__file__).resolve().parent.parent.joinpath('notes/source-inputs.lock.json').read_text())['inputs']
boot = (tree/'IMAGES/boot.img').read_bytes()
assert boot[:8] == b'ANDROID!'
fields = struct.unpack_from('<10I',boot,8)
kernel = boot[fields[7]:fields[7]+fields[0]]
assert hashlib.sha256(kernel).hexdigest() == inputs['kernel_sha256']
checks['original_kernel_preserved'] = True
for name,key in [('vendor.img','vendor_sha256'),('dtbo.img','dtbo_sha256')]:
    digest = hashlib.sha256()
    artifact = tree/'IMAGES'/name
    if not artifact.is_file():
        # These partitions are intentionally not built or written by this OTA.
        artifact = device/'prebuilt'/name
    with artifact.open('rb') as stream:
        while chunk := stream.read(4*1024*1024):
            digest.update(chunk)
    assert digest.hexdigest() == inputs[key],name
    checks[name+'_input_verified'] = True
with tempfile.TemporaryDirectory(dir=args.release, prefix='usage-layout-') as tmp:
    temp = Path(tmp)
    image = tree / 'IMAGES/product.img'
    raw = temp / 'product.raw.img'
    subprocess.run([str(top/'out/host/linux-x86/bin/simg2img'), str(image), str(raw)], check=True)
    for target, source in [('etc/init/init.gta3xlwifi.compat.rc','rootdir/init.gta3xlwifi.compat.rc'),
                           ('etc/permissions/permissions.gta3xlwifi.xml','configs/permissions.gta3xlwifi.xml')]:
        dumped = temp / Path(target).name
        subprocess.run([str(top/'out/host/linux-x86/bin/debugfs_static'), '-R',
                        'dump /'+target+' '+str(dumped), str(raw)], check=True, capture_output=True)
        data = dumped.read_bytes()
        assert data == (device/source).read_bytes()
        assert data == (tree/'PRODUCT'/target).read_bytes()
        checks[target+'_sha256'] = hashlib.sha256(data).hexdigest()
    script = (tree/'PRODUCT/etc/init/init.gta3xlwifi.compat.rc').read_text()
    subprocess.run([str(top/'out/host/linux-x86/bin/host_init_verifier'),
                    str(tree/'PRODUCT/etc/init/init.gta3xlwifi.compat.rc')], check=True)
    assert 'on shutdown\n    stop mobicore' in script
    assert 'on init\n    stop cpboot-daemon' in script
    assert 'shutdown critical' not in script and 'service cpboot-daemon' not in script
    profiles = json.loads((tree/'SYSTEM/etc/task_profiles.gta3xlwifi.json').read_text())
    entries = {p['Name']:p for p in profiles['Profiles']}
    for name in ('LowIoPriority','NormalIoPriority','HighIoPriority','MaxIoPriority'):
        assert entries[name]['Actions'] == []
    checks['unsupported_blkio_profiles_explicitly_skipped'] = True
    policy = (tree/'SYSTEM/system_ext/etc/selinux/system_ext_sepolicy.cil').read_text()
    for path in ('/devices/platform/13830000.i2c/i2c-6/6-003b/power_supply/s2mu005-fuelgauge/type',
                 '/devices/platform/13840000.i2c/i2c-7/7-003d/s2mu005-charger/power_supply/otg/type',
                 '/devices/platform/13840000.i2c/i2c-7/7-003d/s2mu005-charger/power_supply/s2mu005-charger/type',
                 '/devices/platform/13840000.i2c/i2c-7/7-003d/s2mu005-charger/power_supply/otg/online'):
        assert path in policy
    checks['exact_health_type_and_otg_online_labels_packaged'] = True
    apk = tree/'SYSTEM/system_ext/priv-app/Settings/Settings.apk'
    if not apk.is_file():
        matches = list(tree.glob('**/Settings/Settings.apk'))
        assert len(matches)==1, matches
        apk = matches[0]
    checks['signed_settings_apk_sha256'] = hashlib.sha256(apk.read_bytes()).hexdigest()
    phone = tree/'SYSTEM/priv-app/TeleService/TeleService.apk'
    checks['signed_teleservice_apk_sha256'] = hashlib.sha256(phone.read_bytes()).hexdigest()
    aapt = str(top/'out/host/linux-x86/bin/aapt2')
    resources = subprocess.check_output([aapt,'dump','resources',str(phone)],text=True)
    match = re.search(r'resource (0x[0-9a-f]+) bool/config_enable_telephony.*?\n\s+\(\) false',resources)
    assert match, 'Telephony static capability must be false'
    manifest = subprocess.check_output([aapt,'dump','xmltree','--file','AndroidManifest.xml',str(phone)],text=True)
    application = manifest.split('E: application',1)[1].split('E:',1)[0]
    for attribute in ('enabled','persistent'):
        assert re.search(r'android:'+attribute+r'\([^)]*\)=@'+match.group(1)+r'\b',application), attribute
    checks['telephony_application_disabled_and_nonpersistent_in_signed_apk'] = True

    framework = tree/'SYSTEM/framework/framework.jar'
    checks['framework_jar_sha256'] = hashlib.sha256(framework.read_bytes()).hexdigest()
    with zipfile.ZipFile(framework) as archive:
        dex = b''.join(archive.read(n) for n in archive.namelist() if n.endswith('.dex'))
        assert b'mCpuTimeInStateSupported' in dex
    checks['framework_cpu_capability_guard_compiled'] = True
checks['passed'] = True
(args.release/'usage-compat-check.json').write_text(json.dumps(checks,indent=2)+'\n')
print(json.dumps(checks,indent=2))
