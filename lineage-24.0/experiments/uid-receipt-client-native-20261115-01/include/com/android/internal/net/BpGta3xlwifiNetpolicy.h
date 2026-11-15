/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: /srv/android/src/lineage-24.0-arm64/out/host/linux-x86/bin/aidl --lang=cpp --min_sdk_version=10000 -I/srv/android/ports/lineage-24.0-arm64/uid-receipt-client24-20261115-01/binder -I/srv/android/src/lineage-24.0-arm64/system/netd/server/binder -o /srv/android/artifacts/lineage-24.0-arm64/uid-receipt-client-native-20261115-01/generated -h /srv/android/artifacts/lineage-24.0-arm64/uid-receipt-client-native-20261115-01/include /srv/android/ports/lineage-24.0-arm64/uid-receipt-client24-20261115-01/binder/com/android/internal/net/IGta3xlwifiNetpolicy.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
#pragma once

#include <binder/IBinder.h>
#include <binder/IInterface.h>
#include <utils/Errors.h>
#include <com/android/internal/net/IGta3xlwifiNetpolicy.h>

namespace com {
namespace android {
namespace internal {
namespace net {
class LIBBINDER_EXPORTED BpGta3xlwifiNetpolicy : public ::android::BpInterface<IGta3xlwifiNetpolicy> {
public:
  explicit BpGta3xlwifiNetpolicy(const ::android::sp<::android::IBinder>& _aidl_impl);
  virtual ~BpGta3xlwifiNetpolicy() = default;
  ::android::binder::Status openSession(const ::android::sp<::android::IBinder>& client, int32_t protocolVersion, int64_t* _aidl_return) override;
  ::android::binder::Status beginFrame(int64_t session, int64_t expectedGeneration, const ::std::vector<int32_t>& wordCounts, int32_t runtimeFlags, bool loopbackPermissionEnabled, bool uidMigrationEnabled, bool dataSaverEnabled) override;
  ::android::binder::Status appendFrame(int64_t session, int32_t section, int32_t offset, const ::std::vector<int32_t>& words) override;
  ::android::binder::Status commitFrame(int64_t session, int64_t* _aidl_return) override;
  ::android::binder::Status abandonFrame(int64_t session) override;
  ::android::binder::Status readGeneration(int64_t session, int64_t* _aidl_return) override;
  ::android::binder::Status closeSession(const ::android::sp<::android::IBinder>& client) override;
  ::android::binder::Status readStats(int64_t session, int32_t kind, int32_t bank, int64_t epoch, ::std::vector<int64_t>* _aidl_return) override;
  ::android::binder::Status swapStats(int64_t session, int32_t expectedActiveBank, int64_t expectedActiveEpoch, ::std::vector<int64_t>* _aidl_return) override;
  ::android::binder::Status acknowledgeStats(int64_t session, int32_t bank, int64_t epoch) override;
  ::android::binder::Status setStatsCounterset(int64_t session, int32_t uid, int32_t counterset) override;
  ::android::binder::Status removeUidAccounting(int64_t session, int32_t uid, int64_t expectedGeneration, int64_t expectedActiveEpoch) override;
  ::android::binder::Status removeUidAccountingOnce(int64_t session, int32_t uid, int64_t expectedGeneration, int64_t expectedActiveEpoch, int64_t nonce) override;
};  // class BpGta3xlwifiNetpolicy
}  // namespace net
}  // namespace internal
}  // namespace android
}  // namespace com
