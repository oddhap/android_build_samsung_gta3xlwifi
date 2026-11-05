#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Give remaining exclusively vendor-declared private properties restricted ownership.

Vendor-private declaration origin is the ownership evidence; labels without an
actual context reference are explicitly recorded. No public-scope fallback and
no writer exception beyond the existing init exception. Any old core-writer
grants that conflict with restricted ownership must remain strict failures.
"""
import argparse, hashlib, importlib.util, json
from pathlib import Path

REVIEWED=set('''apm_prop armnn_prop boot_dram_info_prop boot_force_upload_prop
cache_status_prop ccm_prop compact_dump_prop cp_reserved_mem_prop ctl_factory_ssc_prop
debug_level_prop dolby_prop domain_read_prop em_version_prop facm_prop ina_status_prop
lmk_prop mobicore_prop multisim_prop nfc_ese_prop product_ship_prop receiver_error_prop
recovery_prop rfkilldisabled_prop rild_prop score_prop sec_audio_prop sec_audio_usb_prop
sec_bluetooth_prop sec_camera_prop sec_factory_facm_prop sec_ims_prop sec_timed_prop
security_prop security_sepolicy_prop smartamp_prop system_product_prop tzdaemon_prop
tztsdaemon_prop vendor_bluetooth_prop vendor_camera_motor_prop vendor_df_prop
vendor_factory_prop vendor_fastrpc_prop vendor_fr_dlymgr_prop vendor_fr_wkrmgr_prop
vendor_hostapd_prop vendor_hwc_prop vendor_ims_prop vendor_mbim_prop vendor_mediadrm_prop
vendor_mobicore_prop vendor_model_suffix_prop vendor_ofi_prop vendor_omadm_prop
vendor_prop vendor_rmnet_prop vendor_sensor_prop vendor_slog_prop vendor_tmfd_prop
vendor_wda_prop vendor_wvkprov_prop vendor_zram_prop vendor_zygoteinit_prop vramdiskd_prop
vzw_os_prop wpa_supplicant_prop'''.split())
def load(n):
 s=importlib.util.spec_from_file_location(n,Path(__file__).with_name(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
cil,forms=load('stage-vendor-uwb-namespace'),load('stage-platform-policy-port')
p=argparse.ArgumentParser(description=__doc__)
for n in ['baseline','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();base=json.loads(a.baseline.read_text());closure_path=a.baseline.parent.parent/'property-closure.json'
proof=json.loads(closure_path.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert proof['inputs_sha256'][str(a.baseline)]==sha(a.baseline)
assert set(proof['unowned_types'])==REVIEWED and len(REVIEWED)==66
paths=[Path(x['path']) for x in base['inputs'] if Path(x['path']).name=='vendor_sepolicy.cil'];assert len(paths)==1
src=paths[0]
for x in base['inputs']:assert sha(Path(x['path']))==x['sha256']==proof['inputs_sha256'][x['path']]
rows={x['type']:x for x in proof['rows']};selected=[]
for name in sorted(REVIEWED):
 row=rows[name];assert row['declaration_inputs']==[str(src)] and not row['owners'] and not row['vendor_scopes']
 assert all(c['name'].startswith(('vendor.','ro.vendor.','persist.vendor.')) for c in row['vendor_context_names'])
 selected.append(row)
out=a.output.resolve();assert not out.exists() and not out.is_relative_to(src.parent) and not out.is_relative_to(Path('/srv/android/src/lineage-24.0-arm64'))
original=src.read_text();group='vendor_samsung_port_restricted_properties';matches=[]
for kind,start,stop in forms.statements(original,cil.tokens):
 if kind!='typeattributeset':continue
 ts=cil.tokens(original[start:stop])
 if ts[2][1]!=group:continue
 assert ts[3][0]=='(' and ts[-2][0]==')' and all(x[0]=='symbol' for x in ts[4:-2])
 old=[x[1] for x in ts[4:-2]];assert len(old)==len(set(old))==32 and not set(old)&REVIEWED
 matches.append((start,stop,old))
assert len(matches)==1
start,stop,old=matches[0];new=sorted(set(old)|REVIEWED);assert len(new)==98
replacement=f'(typeattributeset {group} ('+' '.join(new)+'))'
staged=original[:start]+replacement+original[stop:]
assert cil.rule_counts(staged)==cil.rule_counts(original)
out.mkdir(parents=True);(out/'vendor_sepolicy.cil').write_text(staged)
(out/'reviewed-owner-origins.json').write_text(json.dumps(selected,indent=2)+'\n')
report={'scope':__doc__,'newly_owned_types':sorted(REVIEWED),'existing_group_members':old,'new_group_members':new,
 'before_group_statement':original[start:stop],'after_group_statement':replacement,
 'restricted_target_group_only_grows':set(old)<set(new),'all_other_vendor_text_byte_exact':True,
 'actual_context_references':sum(bool(r['vendor_context_names']) for r in selected),
 'unreferenced_private_types_recorded':sum(not r['vendor_context_names'] for r in selected),
 'core_writer_exceptions_added':False,'public_scope_assigned':False,'av_grants_added':False,
 'input_sha256':{str(a.baseline):sha(a.baseline),str(closure_path):sha(closure_path),str(src):sha(src)},
 'runner_sha256':sha(Path(__file__)),'staged_vendor_sha256':sha(out/'vendor_sepolicy.cil'),
 'effective_permission_delta_or_runtime_behavior_proved':False,'security_approved':False,'flash_ready':False}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');assert src.read_text()==original
print('STAGED: 66 exclusively vendor-declared property owners, restricted group 32 -> 98; old core-writer conflicts remain errors')
