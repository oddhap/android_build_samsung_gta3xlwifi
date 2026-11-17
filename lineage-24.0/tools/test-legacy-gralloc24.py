#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise actual libui mapper requirement/constructor with explicit HAL-load fixtures.

No actual HAL, Binder, graphics driver or device is executed. A genuine legacy
mapper must load; missing all mappers remains fatal. Modern selection is retained.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['composition','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();C=a.composition;O=a.output;assert not O.exists();O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def extract(s,m):
 start=s.index(m);b=s.index('{',start);i=b+1;depth=1
 while depth:depth+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[start:i]
s=(C/'GraphicBufferMapper.cpp').read_text();f=extract(s,'static bool requireMapper4()');ctor=extract(s,'GraphicBufferMapper::GraphicBufferMapper()');bp=(C/'libui.Android.bp').read_text();assert 'soong_config_variable("libui", "legacy_gralloc")' in bp and 'true: ["-DLEGACY_GRALLOC"]' in bp
rel='device/samsung/gta3xlwifi/BoardConfig.mk';b=(C/'files'/rel).read_text();assert '$(call soong_config_set_bool,libui,legacy_gralloc,true)' in b
# Execute the actual production Make macros for string/boolean type registration.
config=(C/'config.mk').read_text();macros='\n'.join(re.search(r'^define '+n+r'\n.*?^endef$',config,re.M|re.S).group() for n in ['soong_config_define_internal','soong_config_set_bool'])
type_cases=[]
for kind in ['baseline','files']:
 cfg=(C/kind/rel).read_text();cfg=cfg[cfg.index('# Retained Samsung mapper/allocator'):]
 mk=O/(kind+'.mk');mk.write_text(macros+'\n'+cfg+"\n.PHONY: all\nall:\n\t@printf '%s|%s\\n' '$(SOONG_CONFIG_libui_legacy_gralloc)' '$(SOONG_CONFIG_TYPE_libui_legacy_gralloc)'\n")
 result=subprocess.run(['make','-s','-f',str(mk)],capture_output=True,text=True,check=True)
 assert result.stdout==('true|\n' if kind=='baseline' else 'true|bool\n'),result.stdout
 type_cases.append({'kind':kind,'actual_make_output':result.stdout})
fixture=r'''
#include <memory>
#include <cstdio>
#include <cstdlib>
static unsigned apiLevel,available;static bool flag;
static unsigned android_get_device_api_level(){return apiLevel;}
namespace flags {static bool require_gralloc4_or_newer(){return flag;}}
#define LOG_ALWAYS_FATAL(...) std::abort()
namespace android {
struct Mapper {virtual ~Mapper()=default;virtual bool isLoaded()const=0;};
template<unsigned N>struct TestMapper:Mapper{bool isLoaded()const override{printf("try%u\n",N);return available&(1u<<N);}};
using Gralloc2Mapper=TestMapper<2>;using Gralloc3Mapper=TestMapper<3>;using Gralloc4Mapper=TestMapper<4>;using Gralloc5Mapper=TestMapper<5>;
struct GraphicBufferMapper {enum class Version{GRALLOC_2=2,GRALLOC_3=3,GRALLOC_4=4,GRALLOC_5=5};GraphicBufferMapper();std::unique_ptr<const Mapper> mMapper;Version mMapperVersion;};
'''
main=r'''
}
int main(int argc,char**argv){if(argc!=4)return 90;setvbuf(stdout,nullptr,_IONBF,0);apiLevel=atoi(argv[1]);flag=atoi(argv[2]);available=atoi(argv[3]);android::GraphicBufferMapper m;printf("chosen%u\n",static_cast<unsigned>(m.mMapperVersion));}
'''
results=[]
for mode in ['platform-default','device-legacy']:
 cpp=O/(mode+'.cpp');cpp.write_text(fixture+f+'\n'+ctor+main);exe=O/mode
 cmd=['g++','-std=c++17','-Wall','-Wextra','-Werror','-O1',str(cpp),'-o',str(exe)]
 # Legacy mode intentionally compiles out these static fixture helpers.
 if mode=='device-legacy':cmd[1:1]=['-DLEGACY_GRALLOC','-Wno-unused-function']
 subprocess.run(cmd,check=True)
 for api in [29,36,37]:
  for flagValue in [0,1]:
   for availableMask in [0,4,8,16,32,20,36,60]:
    minimum=4 if mode=='platform-default' and api>=36 and flagValue else 2
    expected=next((v for v in [5,4,3,2] if v>=minimum and availableMask&(1<<v)),None)
    r=subprocess.run([str(exe),str(api),str(flagValue),str(availableMask)],capture_output=True,text=True)
    if expected is None:assert r.returncode==-6,(mode,api,flagValue,availableMask,r.stdout,r.stderr)
    else:assert r.returncode==0 and r.stdout.endswith('chosen'+str(expected)+'\n'),(mode,api,flagValue,availableMask,r.stdout,r.stderr)
    results.append({'mode':mode,'api':api,'flag':flagValue,'available_fixture_mask':availableMask,'expected_mapper':expected,'exit':r.returncode,'trace':r.stdout})
r={'passed':True,'scope':__doc__,'boolean_config_registration_validated':True,'production_make_config_sha256':sha(C/'config.mk'),'type_cases':type_cases,'Android17_default_rejects_only_mapper2_reproduced':True,'legacy_path_requires_actual_loaded_mapper':True,'no_available_mapper_remains_fatal':True,'modern_mapper_preference_preserved':True,'source_sha256':{rel:sha(C/'files'/rel)},'unchanged_mapper_source_sha256':sha(C/'GraphicBufferMapper.cpp'),'unchanged_android_bp_sha256':sha(C/'libui.Android.bp'),'cases':results,'actual_device_HAL_or_graphics_validated':False,'policy_kernel_vendor_crypto_changed':False,'flash_ready':False};(O/'report.json').write_text(json.dumps(r,indent=2)+'\n');print('PASS 96 actual mapper-constructor cases; real-load requirement and modern preference retained')
