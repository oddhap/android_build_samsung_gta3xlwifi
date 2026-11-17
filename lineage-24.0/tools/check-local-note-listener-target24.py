#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind actual compiled and packaged service to honest BPF observation applicability.

Local-network permission enforcement and flags remain unchanged. The legacy
backend does not supply BPF note-op observations; no events/readiness are faked.
"""
import argparse,hashlib,json,subprocess,zipfile
from pathlib import Path
p=argparse.ArgumentParser()
for n in ['top','archive','geometry','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists();T=a.top;A=Path('/srv/android/artifacts/lineage-24.0-arm64')
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
g=json.loads(a.geometry.read_text());assert g['artifact_checks_passed'] and sha(a.archive)==g['archive_sha256'];proof=A/'local-note-listener-host-20261117-01/report.json';r=json.loads(proof.read_text());assert r['passed'] and r['listener_selection_cases']==16 and r['AOSP_reporting_and_enforcement_cases']==64
for n,h in r['source_sha256'].items():assert sha(T/n)==h
# Exact untouched permission flags, JNI listener and upstream BPF packet code.
unchanged={n:h for n,h in r['inputs_sha256'].items() if n.startswith(str(T)+'/')}
for n,h in unchanged.items():assert sha(Path(n))==h
bp=T/'packages/modules/Connectivity/service/src/com/android/server/BpfNetMaps.java';assert 'if (mGta != null) return mGta.permissionPropagation;' in bp.read_text()
jar=T/'out/soong/.intermediates/packages/modules/Connectivity/service/service-connectivity-pre-jarjar/android_common_apex31/javac/service-connectivity-pre-jarjar.jar';javap=T/'prebuilts/jdk/jdk21/linux-x86/bin/javap'
x=subprocess.run([str(javap),'-c','-p','-classpath',str(jar),'com.android.server.ConnectivityService'],capture_output=True,text=True,check=True)
at=x.stdout.index('Dependencies.getLocalNetEventListener:');window=x.stdout[max(0,at-1600):at+350];assert 'Dependencies.isAtLeastB:' in window and 'BpfNetMaps.usesGta3xlwifiNetworking:' in window
prod=T/'out/target/product/gta3xlwifi';apex='SYSTEM/apex/com.android.tethering.capex'
with zipfile.ZipFile(a.archive) as z,zipfile.ZipFile(A/'runtime21-ota-build-20261117-01/target-files.zip') as old:
 h=hashlib.sha256(z.read(apex)).hexdigest();assert h==sha(prod/'system/apex/com.android.tethering.capex') and h!=hashlib.sha256(old.read(apex)).hexdigest()
 props=z.read('SYSTEM/build.prop').decode().splitlines();assert 'ro.gta3xlwifi.legacy_networking=true' in props and 'ro.debuggable=0' in props
 secure=[z.read(n).decode().splitlines() for n in ['SYSTEM/build.prop','SYSTEM/system_ext/etc/build.prop']];assert any('ro.adb.secure=1' in v for v in secure) and all('ro.adb.secure=0' not in v for v in secure)
# The graph assembles this exact compiled service into the verified CAPEX;
# retain the actual post-R8 JAR digest and all native/permission source hashes.
post=prod/'apex/com.android.tethering/javalib/service-connectivity.jar';assert post.is_file()
a.output.write_text(json.dumps(dict(passed=True,scope=__doc__,archive_sha256=g['archive_sha256'],host_report_sha256=sha(proof),actual_compiled_JAR_sha256=sha(jar),actual_packaged_service_JAR_sha256=sha(post),actual_CAPEX_sha256=h,constructor_bytecode=window,unchanged_permission_and_upstream_sources_sha256=unchanged,local_network_permission_flags_changed=False,enforcement_changed=False,legacy_local_network_note_ops_available=False,BPF_readiness_synthesized=False,hardware_boot_or_network_proven=False,flash_ready=False),indent=2)+'\n');print('PASS actual constructor bytecode, changed service CAPEX and retained permission enforcement; legacy note-op observations unavailable')
