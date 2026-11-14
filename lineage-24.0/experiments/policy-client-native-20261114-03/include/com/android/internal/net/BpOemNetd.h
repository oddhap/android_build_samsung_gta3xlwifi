/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: /srv/android/src/lineage-24.0-arm64/out/host/linux-x86/bin/aidl --lang=cpp --min_sdk_version=10000 -I/srv/android/ports/lineage-24.0-arm64/policy-client24-20261114-02/binder -I/srv/android/src/lineage-24.0-arm64/system/netd/server/binder -o /srv/android/artifacts/lineage-24.0-arm64/policy-client-native-20261114-03/generated -h /srv/android/artifacts/lineage-24.0-arm64/policy-client-native-20261114-03/include /srv/android/ports/lineage-24.0-arm64/policy-client24-20261114-02/binder/com/android/internal/net/IOemNetd.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
#pragma once

#include <binder/IBinder.h>
#include <binder/IInterface.h>
#include <utils/Errors.h>
#include <com/android/internal/net/IOemNetd.h>

namespace com {
namespace android {
namespace internal {
namespace net {
class LIBBINDER_EXPORTED BpOemNetd : public ::android::BpInterface<IOemNetd> {
public:
  explicit BpOemNetd(const ::android::sp<::android::IBinder>& _aidl_impl);
  virtual ~BpOemNetd() = default;
  ::android::binder::Status isAlive(bool* _aidl_return) override;
  ::android::binder::Status registerOemUnsolicitedEventListener(const ::android::sp<::com::android::internal::net::IOemNetdUnsolicitedEventListener>& listener) override;
  ::android::binder::Status getGta3xlwifiNetpolicy(::android::sp<::com::android::internal::net::IGta3xlwifiNetpolicy>* _aidl_return) override;
};  // class BpOemNetd
}  // namespace net
}  // namespace internal
}  // namespace android
}  // namespace com
