/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: /srv/android/src/lineage-24.0-arm64/out/host/linux-x86/bin/aidl --lang=cpp --min_sdk_version=10000 -I/srv/android/ports/lineage-24.0-arm64/policy-frame24-20261114-01/binder -I/srv/android/src/lineage-24.0-arm64/system/netd/server/binder -o /srv/android/artifacts/lineage-24.0-arm64/policy-frame-native-20261114-01/generated -h /srv/android/artifacts/lineage-24.0-arm64/policy-frame-native-20261114-01/include /srv/android/ports/lineage-24.0-arm64/policy-frame24-20261114-01/binder/com/android/internal/net/IGta3xlwifiNetpolicy.aidl
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
#include <cstdint>
#include <utils/StrongPointer.h>
#include <vector>

namespace com {
namespace android {
namespace internal {
namespace net {
class LIBBINDER_EXPORTED IGta3xlwifiNetpolicyDelegator;

class LIBBINDER_EXPORTED IGta3xlwifiNetpolicy : public ::android::IInterface {
public:
  typedef IGta3xlwifiNetpolicyDelegator DefaultDelegator;
  DECLARE_META_INTERFACE(Gta3xlwifiNetpolicy)
  virtual ::android::binder::Status openSession(const ::android::sp<::android::IBinder>& client, int32_t protocolVersion, int64_t* _aidl_return) = 0;
  virtual ::android::binder::Status beginFrame(int64_t session, int64_t expectedGeneration, const ::std::vector<int32_t>& wordCounts, int32_t runtimeFlags, bool loopbackPermissionEnabled, bool uidMigrationEnabled, bool dataSaverEnabled) = 0;
  virtual ::android::binder::Status appendFrame(int64_t session, int32_t section, int32_t offset, const ::std::vector<int32_t>& words) = 0;
  virtual ::android::binder::Status commitFrame(int64_t session, int64_t* _aidl_return) = 0;
  virtual ::android::binder::Status abandonFrame(int64_t session) = 0;
};  // class IGta3xlwifiNetpolicy

class LIBBINDER_EXPORTED IGta3xlwifiNetpolicyDefault : public IGta3xlwifiNetpolicy {
public:
  ::android::IBinder* onAsBinder() override {
    return nullptr;
  }
  ::android::binder::Status openSession(const ::android::sp<::android::IBinder>& /*client*/, int32_t /*protocolVersion*/, int64_t* /*_aidl_return*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
  ::android::binder::Status beginFrame(int64_t /*session*/, int64_t /*expectedGeneration*/, const ::std::vector<int32_t>& /*wordCounts*/, int32_t /*runtimeFlags*/, bool /*loopbackPermissionEnabled*/, bool /*uidMigrationEnabled*/, bool /*dataSaverEnabled*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
  ::android::binder::Status appendFrame(int64_t /*session*/, int32_t /*section*/, int32_t /*offset*/, const ::std::vector<int32_t>& /*words*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
  ::android::binder::Status commitFrame(int64_t /*session*/, int64_t* /*_aidl_return*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
  ::android::binder::Status abandonFrame(int64_t /*session*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
};  // class IGta3xlwifiNetpolicyDefault
}  // namespace net
}  // namespace internal
}  // namespace android
}  // namespace com
