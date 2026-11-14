from pathlib import Path
import fcntl,json,hashlib
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
a=Path('/srv/android/artifacts/lineage-24.0-arm64');o=a/'policy-client-final-inputs-20261114-01';assert not o.exists();o.mkdir()
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
old=json.loads((a/'held-provider-final-inputs-20261114-01/report.json').read_text())
for path,h in old['selected_inputs_sha256'].items():assert sha(path)==h
profiles={}
for flavor in ['production','debug']:
 p=a/('runtime-policy-'+flavor+'-20261114-01/strict/report.json');r=json.loads(p.read_text());assert r['passed_strict'];assert sha(p)==old['strict_profiles'][flavor]['report_sha256']
 for item in r['inputs']:assert sha(item['path'])==item['sha256']
 result=r['results'][0];assert result['neverallow_checks_enabled'] and result['exit_code']==0
 binary=Path(result['command'][result['command'].index('-o')+1]);assert sha(binary)==result['compiled_policy_sha256']==old['strict_profiles'][flavor]['compiled_policy_sha256']
 assert sha(result['command'][0])==r['compiler_sha256']
 profiles[flavor]={'strict_inputs_rehashed':len(r['inputs']),'report_sha256':sha(p),'policy_sha256':sha(binary),'assertions_enabled':True}
(o/'report.json').write_text(json.dumps({'passed':True,'selected_inputs_sha256':old['selected_inputs_sha256'],'strict_profiles':profiles,'source_policy_or_prebuilt_selection_changed':False,'flash_ready':False},indent=2)+'\n')
print('PASS: selected Image/latest21-MTP vendor/DTBO and both strict policy profiles unchanged')
