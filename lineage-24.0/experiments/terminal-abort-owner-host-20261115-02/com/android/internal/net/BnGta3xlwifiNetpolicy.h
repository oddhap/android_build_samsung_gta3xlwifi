#pragma once
#include <binder/IBinder.h>
namespace com::android::internal::net {
class BnGta3xlwifiNetpolicy:public ::android::IBinder{
 public:
 virtual ::android::binder::Status openSession(const ::android::sp<::android::IBinder>&,int32_t,int64_t*)=0;
 virtual ::android::binder::Status beginFrame(int64_t,int64_t,const std::vector<int32_t>&,int32_t,bool,bool,bool)=0;
 virtual ::android::binder::Status appendFrame(int64_t,int32_t,int32_t,const std::vector<int32_t>&)=0;
 virtual ::android::binder::Status commitFrame(int64_t,int64_t*)=0;
 virtual ::android::binder::Status abandonFrame(int64_t)=0;
 virtual ::android::binder::Status readGeneration(int64_t,int64_t*)=0;
 virtual ::android::binder::Status closeSession(const ::android::sp<::android::IBinder>&)=0;
virtual ::android::binder::Status readStats(int64_t,int32_t,int32_t,int64_t,std::vector<int64_t>*)=0;
 virtual ::android::binder::Status swapStats(int64_t,int32_t,int64_t,std::vector<int64_t>*)=0;
 virtual ::android::binder::Status acknowledgeStats(int64_t,int32_t,int64_t)=0;
 virtual ::android::binder::Status setStatsCounterset(int64_t,int32_t,int32_t)=0;
 virtual ::android::binder::Status removeUidAccounting(int64_t,int32_t,int64_t,int64_t)=0;
 virtual ::android::binder::Status removeUidAccountingOnce(int64_t,int32_t,int64_t,int64_t,int64_t)=0;
 virtual ::android::binder::Status abortSession(int64_t,const ::android::sp<::android::IBinder>&)=0;
};}
