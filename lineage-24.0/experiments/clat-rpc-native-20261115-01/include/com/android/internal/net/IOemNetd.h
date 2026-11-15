/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: /srv/android/src/lineage-24.0-arm64/out/host/linux-x86/bin/aidl --lang=cpp --min_sdk_version=10000 -I/srv/android/ports/lineage-24.0-arm64/clat-rpc24-20261115-01/binder -I/srv/android/src/lineage-24.0-arm64/system/netd/server/binder -o /srv/android/artifacts/lineage-24.0-arm64/clat-rpc-native-20261115-01/generated -h /srv/android/artifacts/lineage-24.0-arm64/clat-rpc-native-20261115-01/include /srv/android/ports/lineage-24.0-arm64/clat-rpc24-20261115-01/binder/com/android/internal/net/IOemNetd.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
#pragma once

#include <binder/IBinder.h>
#include <binder/IInterface.h>
#include <binder/Status.h>
#include <binder/Trace.h>
#include <com/android/internal/net/IGta3xlwifiNetpolicy.h>
#include <com/android/internal/net/IOemNetdUnsolicitedEventListener.h>
#include <utils/StrongPointer.h>

namespace com::android::internal::net {
class IGta3xlwifiNetpolicy;
class IOemNetdUnsolicitedEventListener;
}  // namespace com::android::internal::net
namespace com {
namespace android {
namespace internal {
namespace net {
class LIBBINDER_EXPORTED IOemNetdDelegator;

class LIBBINDER_EXPORTED IOemNetd : public ::android::IInterface {
public:
  typedef IOemNetdDelegator DefaultDelegator;
  DECLARE_META_INTERFACE(OemNetd)
  virtual ::android::binder::Status isAlive(bool* _aidl_return) = 0;
  virtual ::android::binder::Status registerOemUnsolicitedEventListener(const ::android::sp<::com::android::internal::net::IOemNetdUnsolicitedEventListener>& listener) = 0;
  virtual ::android::binder::Status getGta3xlwifiNetpolicy(::android::sp<::com::android::internal::net::IGta3xlwifiNetpolicy>* _aidl_return) = 0;
};  // class IOemNetd

class LIBBINDER_EXPORTED IOemNetdDefault : public IOemNetd {
public:
  ::android::IBinder* onAsBinder() override {
    return nullptr;
  }
  ::android::binder::Status isAlive(bool* /*_aidl_return*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
  ::android::binder::Status registerOemUnsolicitedEventListener(const ::android::sp<::com::android::internal::net::IOemNetdUnsolicitedEventListener>& /*listener*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
  ::android::binder::Status getGta3xlwifiNetpolicy(::android::sp<::com::android::internal::net::IGta3xlwifiNetpolicy>* /*_aidl_return*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
};  // class IOemNetdDefault
}  // namespace net
}  // namespace internal
}  // namespace android
}  // namespace com
