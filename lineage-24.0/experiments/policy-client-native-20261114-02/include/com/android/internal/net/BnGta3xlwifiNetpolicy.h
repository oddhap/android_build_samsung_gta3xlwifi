/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: /srv/android/src/lineage-24.0-arm64/out/host/linux-x86/bin/aidl --lang=cpp --min_sdk_version=10000 -I/srv/android/ports/lineage-24.0-arm64/policy-client24-20261114-01/binder -I/srv/android/src/lineage-24.0-arm64/system/netd/server/binder -o /srv/android/artifacts/lineage-24.0-arm64/policy-client-native-20261114-02/generated -h /srv/android/artifacts/lineage-24.0-arm64/policy-client-native-20261114-02/include /srv/android/ports/lineage-24.0-arm64/policy-client24-20261114-01/binder/com/android/internal/net/IGta3xlwifiNetpolicy.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
#pragma once

#include <binder/IInterface.h>
#include <com/android/internal/net/IGta3xlwifiNetpolicy.h>
#include <binder/Delegate.h>
#include <com/android/internal/net/BnGta3xlwifiNetpolicy.h>


namespace com {
namespace android {
namespace internal {
namespace net {
class LIBBINDER_EXPORTED BnGta3xlwifiNetpolicy : public ::android::BnInterface<IGta3xlwifiNetpolicy> {
public:
  static constexpr uint32_t TRANSACTION_openSession = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
  static constexpr uint32_t TRANSACTION_beginFrame = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
  static constexpr uint32_t TRANSACTION_appendFrame = ::android::IBinder::FIRST_CALL_TRANSACTION + 2;
  static constexpr uint32_t TRANSACTION_commitFrame = ::android::IBinder::FIRST_CALL_TRANSACTION + 3;
  static constexpr uint32_t TRANSACTION_abandonFrame = ::android::IBinder::FIRST_CALL_TRANSACTION + 4;
  static constexpr uint32_t TRANSACTION_readGeneration = ::android::IBinder::FIRST_CALL_TRANSACTION + 5;
  static constexpr uint32_t TRANSACTION_closeSession = ::android::IBinder::FIRST_CALL_TRANSACTION + 6;
  explicit BnGta3xlwifiNetpolicy();
  ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
};  // class BnGta3xlwifiNetpolicy

class LIBBINDER_EXPORTED IGta3xlwifiNetpolicyDelegator : public BnGta3xlwifiNetpolicy {
public:
  explicit IGta3xlwifiNetpolicyDelegator(const ::android::sp<IGta3xlwifiNetpolicy> &impl) : _aidl_delegate(impl) {}

  ::android::sp<IGta3xlwifiNetpolicy> getImpl() { return _aidl_delegate; }
  ::android::binder::Status openSession(const ::android::sp<::android::IBinder>& client, int32_t protocolVersion, int64_t* _aidl_return) override {
    return _aidl_delegate->openSession(client, protocolVersion, _aidl_return);
  }
  ::android::binder::Status beginFrame(int64_t session, int64_t expectedGeneration, const ::std::vector<int32_t>& wordCounts, int32_t runtimeFlags, bool loopbackPermissionEnabled, bool uidMigrationEnabled, bool dataSaverEnabled) override {
    return _aidl_delegate->beginFrame(session, expectedGeneration, wordCounts, runtimeFlags, loopbackPermissionEnabled, uidMigrationEnabled, dataSaverEnabled);
  }
  ::android::binder::Status appendFrame(int64_t session, int32_t section, int32_t offset, const ::std::vector<int32_t>& words) override {
    return _aidl_delegate->appendFrame(session, section, offset, words);
  }
  ::android::binder::Status commitFrame(int64_t session, int64_t* _aidl_return) override {
    return _aidl_delegate->commitFrame(session, _aidl_return);
  }
  ::android::binder::Status abandonFrame(int64_t session) override {
    return _aidl_delegate->abandonFrame(session);
  }
  ::android::binder::Status readGeneration(int64_t session, int64_t* _aidl_return) override {
    return _aidl_delegate->readGeneration(session, _aidl_return);
  }
  ::android::binder::Status closeSession(const ::android::sp<::android::IBinder>& client) override {
    return _aidl_delegate->closeSession(client);
  }
private:
  ::android::sp<IGta3xlwifiNetpolicy> _aidl_delegate;
};  // class IGta3xlwifiNetpolicyDelegator
}  // namespace net
}  // namespace internal
}  // namespace android
}  // namespace com
