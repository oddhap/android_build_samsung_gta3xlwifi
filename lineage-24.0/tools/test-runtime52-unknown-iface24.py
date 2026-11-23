#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host test for snapshot52: stats rows without an interface name are skipped, as in A17.

Issue oddhap/android_build_samsung_gta3xlwifi#5: system_server crash-looped every ~25 s
on Wi-Fi with "java.io.IOException: Missing real interface history: 0" from
Gta3xlwifiStatsConsumer.prepare (via BatteryStatsImpl / WifiPowerStatsCollector).
A17 BpfNetworkStats.cpp drops rows whose ifindex has no interface name and logs once
per read above MAX_UNKNOWN_IFACE_BYTES (maybeLogUnknownIface); the shim threw instead.

Reuses the complete Java fixture set of stats-removal-host-20261115-02 (RemovalTest
chain: poll 61, client 1467, consumer, factory, traffic, UID cleanup/receipt,
terminal abort, durable removal) with the actual A17 NetworkStats, and runs:
  baseline   unmodified fixtures + BEFORE sources       -> must pass (harness valid)
  regression updated fixtures + BEFORE sources          -> must fail (cases detect bug)
  fixed      updated fixtures + AFTER sources           -> must pass
Updated fixtures: the "missing names" consumer fault and the unknown-name TrafficStats
iface case now expect skip instead of IOException, plus new cases (ifindex 0 rows,
names table without the ifindex, summary, unsigned unknown counters, one log per read
at the A17 threshold). All other faults (name-table loss, counter overflow, frozen
loss, durable-store faults) still reject without ACK.

Usage: test-runtime52-unknown-iface24.py --top T --consumer-before F --traffic-before F
       --consumer-after F --traffic-after F --output NEW_DIR
"""
import argparse, fcntl, hashlib, json, re, shutil, subprocess
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
for n in ['top', 'consumer-before', 'traffic-before', 'consumer-after', 'traffic-after', 'output']:
    p.add_argument('--'+n, type=Path, required=True)
a = p.parse_args()
T = a.top.resolve(); O = a.output.resolve(); assert not O.exists()
FIX = Path('/srv/android/artifacts/lineage-24.0-arm64/stats-removal-host-20261115-02')
lock = Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a')
fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
O.mkdir(parents=True)
sha = lambda f: hashlib.sha256(Path(f).read_bytes()).hexdigest()
fix_report = json.loads((FIX/'report.json').read_text())
assert fix_report['passed'] and fix_report['durable_removal_cases'] == 62
SRV = T/'packages/modules/Connectivity/service/src/com/android/server'
unchanged = [SRV/f'Gta3xlwifi{n}.java' for n in ['NetpolicyClient', 'StatsAccess', 'StatsJournal', 'StatsPoller']]
before = {'Gta3xlwifiStatsConsumer.java': a.consumer_before, 'Gta3xlwifiTrafficStats.java': a.traffic_before}
after = {'Gta3xlwifiStatsConsumer.java': a.consumer_after, 'Gta3xlwifiTrafficStats.java': a.traffic_after}
assert 'Missing real interface history' in a.consumer_before.read_text()
assert 'Missing real interface history' not in a.consumer_after.read_text()
fixtures = sorted(f for f in FIX.rglob('*.java') if 'classes' not in f.relative_to(FIX).parts)
javac = T/'prebuilts/jdk/jdk21/linux-x86/bin/javac'

LOG_STUB = ('package android.util;public class Log{public static final java.util.List<String> errors='
            'new java.util.ArrayList<>();public static int wtf(String t,String m){throw new AssertionError(m);}'
            'public static int e(String t,String m){errors.add(t+": "+m);return 0;}}')
OLD_FAULTS = 'for(int fault=0;fault<4;++fault){Fixture f=new Fixture();if(fault==0)f.remote.missing=true;'
NEW_FAULTS = 'for(int fault=1;fault<4;++fault){Fixture f=new Fixture();'
FAULT_LINE = '  // Missing names/loss/unsigned overflow do not ACK or durably consume the bank.\n'
NEW_CASES = r'''  // Issue #5 / A17 BpfNetworkStats.cpp: rows whose ifindex has no name are dropped, the bank is ACKed.
  {android.util.Log.errors.clear();Fixture f=new Fixture();f.remote.rows=new long[][]{{10001,0,0,0,2,100,0,0},{10001,0,0,17,2,50,0,0}};NetworkStats s=f.poll();check(s.size()==1&&bytes(s,"wlan0",10001,0,0)==50);check(f.remote.acksCommitted==1&&f.store.writes==1&&f.remote.pending==0);check(android.util.Log.errors.isEmpty());}
  {Fixture f=new Fixture();f.remote.missing=true;check(f.poll().size()==0);check(f.remote.acksCommitted==1&&f.store.writes==1&&f.remote.pending==0);f.remote.missing=false;f.remote.rows=new long[0][];check(f.poll().size()==0&&f.remote.acksCommitted==2);f.recover();check(f.poll().size()==0);}
  {Fixture f=new Fixture();f.remote.missing=true;synchronized(f.lock){check(f.consumer.readSummary().size()==0&&f.remote.swaps==0&&f.store.writes==0);}}
  {android.util.Log.errors.clear();Fixture f=new Fixture();f.remote.rows=new long[][]{{10001,0,0,0,2,60000,1,50000},{10001,0,0,17,1,7,0,0},{10002,0,0,0,1,1,0,0}};NetworkStats s=f.poll();check(s.size()==1&&bytes(s,"wlan0",10001,0,0)==7&&f.remote.acksCommitted==1);check(android.util.Log.errors.equals(List.of("Gta3xlwifiStats: Unknown name for ifindex 0 with more than 110000 bytes of traffic")));}
  {android.util.Log.errors.clear();Fixture f=new Fixture();f.remote.rows=new long[][]{{10001,0,0,0,1,-1,0,0}};check(f.poll().size()==0&&f.remote.acksCommitted==1);check(android.util.Log.errors.size()==1&&android.util.Log.errors.get(0).endsWith(" "+Long.MAX_VALUE+" bytes of traffic"));}
  // A named row still validates its counters: unsigned overflow on wlan0 rejects without ACK.
  {Fixture f=new Fixture();f.remote.rows=new long[][]{{10001,0,0,0,1,5,0,0},{10001,0,0,17,1,-1,0,0}};rejected(f::poll);check(f.remote.acksCommitted==0&&f.store.writes==0&&f.remote.pending!=0);}
'''
OLD_TRAFFIC = 'remote.unknown=true;rejected(()->stats.iface("wlan0"));'
NEW_TRAFFIC = 'remote.unknown=true;check(stats.iface("wlan0").rxBytes==0);'


def stage(phase, sources, updated):
    d = O/phase; d.mkdir()
    for f in fixtures:
        q = d/'src'/f.relative_to(FIX); q.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(f, q)
    if updated:
        c = d/'src/ConsumerTest.java'; t = c.read_text()
        assert t.count(OLD_FAULTS) == 1 and t.count(FAULT_LINE) == 1
        loop_end = t.index('\n', t.index(OLD_FAULTS)) + 1
        t = t[:loop_end] + NEW_CASES + t[loop_end:]
        c.write_text(t.replace(OLD_FAULTS, NEW_FAULTS))
        tr = d/'src/TrafficTest.java'; t = tr.read_text(); assert t.count(OLD_TRAFFIC) == 1
        tr.write_text(t.replace(OLD_TRAFFIC, NEW_TRAFFIC))
    (d/'src/android/util/Log.java').write_text(LOG_STUB)
    # The current (unchanged) Gta3xlwifiStatsAccess gained the loopback-event and CLAT
    # socket calls after the 2026-11-15 fixtures; give the fixture binder interface
    # throwing defaults for them (not exercised here) so the actual file compiles.
    (d/'src/android/os/ParcelFileDescriptor.java').write_text('package android.os;public class ParcelFileDescriptor{}')
    i = d/'src/com/android/internal/net/IGta3xlwifiNetpolicy.java'; t = i.read_text().rstrip(); assert t.endswith('}')
    assert 'pollLoopbackEvents' not in t and 'tagClatSocket' not in t
    i.write_text(t[:-1] + 'default long[] pollLoopbackEvents(long session)throws android.os.RemoteException'
                 '{throw new UnsupportedOperationException();}\ndefault void tagClatSocket(long session,'
                 'android.os.ParcelFileDescriptor fd)throws android.os.RemoteException'
                 '{throw new UnsupportedOperationException();}\n}\n')
    prod = d/'prod'; prod.mkdir()
    files = list(unchanged)
    for name, f in sources.items():
        shutil.copyfile(f, prod/name); files.append(prod/name)
    cmd = [str(javac), '-source', '21', '-target', '21', '-d', str(d/'classes'), *map(str, files),
           *map(str, sorted((d/'src').rglob('*.java')))]
    x = subprocess.run(cmd, capture_output=True, text=True); (d/'compile.log').write_text(x.stdout+x.stderr)
    assert x.returncode == 0, (phase, x.stderr[-8000:])
    x = subprocess.run([str(javac.with_name('java')), '-ea', '-cp', str(d/'classes'), 'RemovalTest'],
                       capture_output=True, text=True, timeout=180)
    (d/'test.log').write_text(x.stdout+x.stderr)
    counts = dict(re.findall(r'^(\w+_cases)=(\d+)$', x.stdout, re.M))
    return {'returncode': x.returncode, 'stderr_tail': x.stderr[-1500:], 'cases': {k: int(v) for k, v in counts.items()},
            'sources_sha256': {str(f): sha(f) for f in files}}


res = {'baseline': stage('baseline', before, False), 'regression': stage('regression', before, True),
       'fixed': stage('fixed', after, True)}
b, r, f = res['baseline'], res['regression'], res['fixed']
assert b['returncode'] == 0 and not b['stderr_tail'] and b['cases'].get('durable_removal_cases') == 62, b
assert r['returncode'] != 0 and 'Expected IO failure' not in r['stderr_tail'], r  # new skip cases hit the old throw
assert f['returncode'] == 0 and not f['stderr_tail'] and f['cases'].get('durable_removal_cases') == 62, f
# Consumer: fault 0 (2 checks) removed, 14 new checks; traffic count unchanged (rejected -> check).
assert f['cases']['consumer_cases'] == b['cases']['consumer_cases'] - 2 + 14, (b['cases'], f['cases'])
assert f['cases']['traffic_cases'] == b['cases']['traffic_cases']
report = {'passed': True, 'scope': __doc__, 'issue': 'oddhap/android_build_samsung_gta3xlwifi#5',
          'fixture_set': str(FIX), 'fixture_report_sha256': sha(FIX/'report.json'),
          'fixtures_sha256': {str(x): sha(x) for x in fixtures}, 'phases': res,
          'before_sha256': {n: sha(x) for n, x in before.items()}, 'after_sha256': {n: sha(x) for n, x in after.items()},
          'actual_A17_NetworkStats_unmodified': True, 'hardware_tested': False}
(O/'report.json').write_text(json.dumps(report, indent=2)+'\n')
print('PASS unknown-iface host test:', {k: v['cases'] for k, v in res.items()}, 'regression rc', r['returncode'])
