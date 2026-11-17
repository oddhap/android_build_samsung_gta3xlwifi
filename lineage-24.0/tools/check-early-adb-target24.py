#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify packaged early USB ADB requests retain secure authentication and vendor USB ownership."""
import argparse,hashlib,json,subprocess,zipfile
from pathlib import Path
p=argparse.ArgumentParser()
for n in ['top','archive','geometry','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists()
def sha(f):
 h=hashlib.sha256()
 with f.open('rb') as s:
  for b in iter(lambda:s.read(1048576),b''):h.update(b)
 return h.hexdigest()
g=json.loads(a.geometry.read_text());assert g['artifact_checks_passed'] and sha(a.archive)==g['archive_sha256'];rel='device/samsung/gta3xlwifi/rootdir/init.gta3xlwifi.compat.rc';source=a.top/rel
with zipfile.ZipFile(a.archive) as z:
 b=z.read('PRODUCT/etc/init/init.gta3xlwifi.compat.rc');assert hashlib.sha256(b).hexdigest()==sha(source);s=b.decode();assert 'on post-fs-data\n    setprop persist.sys.usb.config adb\n' in s and 'on boot\n    setprop sys.usb.config adb\n' in s
 assert 'service adbd' not in s and 'adb.tcp.port' not in s and 'ro.adb.secure' not in s and 'sys.usb.configfs' not in '\n'.join(l for l in s.splitlines() if not l.startswith('#'))
 props={n:z.read(n).decode() for n in ['SYSTEM/build.prop','SYSTEM/system_ext/etc/build.prop']};assert any('ro.adb.secure=1' in t.splitlines() for t in props.values());assert all('ro.adb.secure=0' not in t.splitlines() for t in props.values());assert 'ro.debuggable=0' in props['SYSTEM/build.prop'].splitlines()
 tool=a.top/'out/host/linux-x86/bin/host_init_verifier';r=subprocess.run([str(tool),str(source)],capture_output=True,text=True);assert r.returncode==0,(r.stdout,r.stderr)
a.output.write_text(json.dumps(dict(passed=True,scope=__doc__,archive_sha256=g['archive_sha256'],packaged_rc_sha256=sha(source),authentication_required=True,ro_debuggable_unchanged_zero=True,tcp_listener_added=False,vendor_configfs_ownership_changed=False,host_init_verifier_sha256=sha(tool),host_init_verifier_exit=r.returncode,hardware_ADB_connectivity_proven=False,flash_ready=False),indent=2)+'\n');print('PASS packaged early USB ADB requests, init parser, secure authentication and unchanged USB ownership')
