/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: /srv/android/src/lineage-24.0-arm64/out/host/linux-x86/bin/aidl --lang=cpp --min_sdk_version=10000 -I/srv/android/ports/lineage-24.0-arm64/clat-rpc24-20261115-01/binder -I/srv/android/src/lineage-24.0-arm64/system/netd/server/binder -o /srv/android/artifacts/lineage-24.0-arm64/clat-rpc-native-20261115-01/generated -h /srv/android/artifacts/lineage-24.0-arm64/clat-rpc-native-20261115-01/include /srv/android/ports/lineage-24.0-arm64/clat-rpc24-20261115-01/binder/com/android/internal/net/IGta3xlwifiNetpolicy.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
#pragma once

#include <binder/IBinder.h>
#include <binder/IInterface.h>
#include <binder/ParcelFileDescriptor.h>
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
  virtual ::android::binder::Status readGeneration(int64_t session, int64_t* _aidl_return) = 0;
  virtual ::android::binder::Status closeSession(const ::android::sp<::android::IBinder>& client) = 0;
  virtual ::android::binder::Status readStats(int64_t session, int32_t kind, int32_t bank, int64_t epoch, ::std::vector<int64_t>* _aidl_return) = 0;
  virtual ::android::binder::Status swapStats(int64_t session, int32_t expectedActiveBank, int64_t expectedActiveEpoch, ::std::vector<int64_t>* _aidl_return) = 0;
  virtual ::android::binder::Status acknowledgeStats(int64_t session, int32_t bank, int64_t epoch) = 0;
  virtual ::android::binder::Status setStatsCounterset(int64_t session, int32_t uid, int32_t counterset) = 0;
  virtual ::android::binder::Status removeUidAccounting(int64_t session, int32_t uid, int64_t expectedGeneration, int64_t expectedActiveEpoch) = 0;
  virtual ::android::binder::Status removeUidAccountingOnce(int64_t session, int32_t uid, int64_t expectedGeneration, int64_t expectedActiveEpoch, int64_t nonce) = 0;
  virtual ::android::binder::Status abortSession(int64_t session, const ::android::sp<::android::IBinder>& client) = 0;
  virtual ::android::binder::Status pollLoopbackEvents(int64_t session, ::std::vector<int64_t>* _aidl_return) = 0;
  virtual ::android::binder::Status tagClatSocket(int64_t session, const ::android::os::ParcelFileDescriptor& socket) = 0;
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
  ::android::binder::Status readGeneration(int64_t /*session*/, int64_t* /*_aidl_return*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
  ::android::binder::Status closeSession(const ::android::sp<::android::IBinder>& /*client*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
  ::android::binder::Status readStats(int64_t /*session*/, int32_t /*kind*/, int32_t /*bank*/, int64_t /*epoch*/, ::std::vector<int64_t>* /*_aidl_return*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
  ::android::binder::Status swapStats(int64_t /*session*/, int32_t /*expectedActiveBank*/, int64_t /*expectedActiveEpoch*/, ::std::vector<int64_t>* /*_aidl_return*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
  ::android::binder::Status acknowledgeStats(int64_t /*session*/, int32_t /*bank*/, int64_t /*epoch*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
  ::android::binder::Status setStatsCounterset(int64_t /*session*/, int32_t /*uid*/, int32_t /*counterset*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
  ::android::binder::Status removeUidAccounting(int64_t /*session*/, int32_t /*uid*/, int64_t /*expectedGeneration*/, int64_t /*expectedActiveEpoch*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
  ::android::binder::Status removeUidAccountingOnce(int64_t /*session*/, int32_t /*uid*/, int64_t /*expectedGeneration*/, int64_t /*expectedActiveEpoch*/, int64_t /*nonce*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
  ::android::binder::Status abortSession(int64_t /*session*/, const ::android::sp<::android::IBinder>& /*client*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
  ::android::binder::Status pollLoopbackEvents(int64_t /*session*/, ::std::vector<int64_t>* /*_aidl_return*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
  ::android::binder::Status tagClatSocket(int64_t /*session*/, const ::android::os::ParcelFileDescriptor& /*socket*/) override {
    return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
  }
};  // class IGta3xlwifiNetpolicyDefault
}  // namespace net
}  // namespace internal
}  // namespace android
}  // namespace com
