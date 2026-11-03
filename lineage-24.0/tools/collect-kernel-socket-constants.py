#!/usr/bin/env python3
"""Read actual target socket UAPI constants via a data-only cross-compiled object.

Uses an existing SELinux hooks compile recipe, with dependency output removed and all
new outputs outside the kernel tree. Does not run target code or change source.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--src',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
p.add_argument('--report-dir',type=Path,required=True);args=p.parse_args()
src=args.src.resolve();out=args.out.resolve();dest=args.report_dir.resolve()
assert not dest.is_relative_to(src) and not dest.is_relative_to(out)
dest.mkdir(exist_ok=False)
source=src/'security/selinux/hooks.c';recipe=out/'security/selinux/.hooks.o.cmd'
text=source.read_text()
socket_header=src/'include/linux/socket.h'
names=set(re.findall(r'^#define\s+((?:PF|AF)_\w+)\s',socket_header.read_text(),re.M))
names.update(['SECINITSID_KERNEL','SOCK_STREAM','SOCK_DGRAM','SOCK_RAW','SOCK_SEQPACKET','SOCK_DCCP',
 'IPPROTO_IP','IPPROTO_TCP','IPPROTO_UDP','IPPROTO_ICMP','IPPROTO_ICMPV6','IPPROTO_SCTP'])
# Existing netlink selector switch uses only real legacy UAPI names.
start=text.index('static inline u16 socket_type_to_security_class(')
end=text.index('\n}',start)
names.update(re.findall(r'\bNETLINK_[A-Z0-9_]+\b',text[start:end]))
expressions=sorted(names)+['PROT_SOCK','SIN6_LEN_RFC2133','sizeof(struct sockaddr_in)','sizeof(struct sockaddr_in6)']
includes='\n'.join(line for line in text.splitlines() if line.startswith('#include'))
c=dest/'constants.c';c.write_text(includes+'\nconst unsigned long long fixture_constants[] = {\n'+',\n'.join(expressions)+'\n};\n')
command=shlex.split(recipe.read_text().splitlines()[0].split(':=',1)[1].replace('$(pound)','#'))
assert command[-1]==str(source) and command[-4]=='-c' and command[-3]=='-o'
command=[arg for arg in command if not arg.startswith('-Wp,-MD,')]
command[-2]=str(dest/'constants.o');command[-1]=str(c)
subprocess.run(command,cwd=out,check=True)
objcopy=Path(command[0]).with_name('aarch64-linux-android-objcopy')
subprocess.run([str(objcopy),'-O','binary','--only-section=.rodata','--only-section=.rodata.fixture_constants',str(dest/'constants.o'),str(dest/'constants.bin')],check=True)
data=(dest/'constants.bin').read_bytes();assert len(data)==8*len(expressions),(len(data),len(expressions))
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
r={'scope':'Target-compiled constant values only, not kernel execution or enforcement','constants':dict(zip(expressions,struct.unpack('<'+'Q'*len(expressions),data))),
   'inputs_sha256':{str(f):sha(f) for f in [source,socket_header,recipe,c,Path(command[0])]},'runner_sha256':sha(Path(__file__)),'object_sha256':sha(dest/'constants.o'),'binary_sha256':sha(dest/'constants.bin'),'command':command}
(dest/'constants.json').write_text(json.dumps(r,indent=2)+'\n');print('Captured',len(expressions),'actual target constants')
