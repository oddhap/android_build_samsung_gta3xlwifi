/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: /srv/android/src/lineage-24.0-arm64/out/host/linux-x86/bin/aidl --lang=cpp --min_sdk_version=10000 -I/srv/android/ports/lineage-24.0-arm64/policy-client24-20261114-01/binder -I/srv/android/src/lineage-24.0-arm64/system/netd/server/binder -o /srv/android/artifacts/lineage-24.0-arm64/policy-client-native-20261114-02/generated -h /srv/android/artifacts/lineage-24.0-arm64/policy-client-native-20261114-02/include /srv/android/ports/lineage-24.0-arm64/policy-client24-20261114-01/binder/com/android/internal/net/IOemNetd.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
#pragma once

#include <binder/IInterface.h>
#include <com/android/internal/net/IOemNetd.h>
#include <binder/Delegate.h>
#include <com/android/internal/net/BnGta3xlwifiNetpolicy.h>
#include <com/android/internal/net/BnOemNetd.h>
#include <com/android/internal/net/BnOemNetdUnsolicitedEventListener.h>


namespace com {
namespace android {
namespace internal {
namespace net {
class LIBBINDER_EXPORTED BnOemNetd : public ::android::BnInterface<IOemNetd> {
public:
  static constexpr uint32_t TRANSACTION_isAlive = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
  static constexpr uint32_t TRANSACTION_registerOemUnsolicitedEventListener = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
  static constexpr uint32_t TRANSACTION_getGta3xlwifiNetpolicy = ::android::IBinder::FIRST_CALL_TRANSACTION + 2;
  explicit BnOemNetd();
  ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
};  // class BnOemNetd

class LIBBINDER_EXPORTED IOemNetdDelegator : public BnOemNetd {
public:
  explicit IOemNetdDelegator(const ::android::sp<IOemNetd> &impl) : _aidl_delegate(impl) {}

  ::android::sp<IOemNetd> getImpl() { return _aidl_delegate; }
  ::android::binder::Status isAlive(bool* _aidl_return) override {
    return _aidl_delegate->isAlive(_aidl_return);
  }
  ::android::binder::Status registerOemUnsolicitedEventListener(const ::android::sp<::com::android::internal::net::IOemNetdUnsolicitedEventListener>& listener) override {
    ::android::sp<::com::android::internal::net::IOemNetdUnsolicitedEventListenerDelegator> _listener;
    if (listener) {
      _listener = ::android::sp<::com::android::internal::net::IOemNetdUnsolicitedEventListenerDelegator>::cast(delegate(listener));
    }
    return _aidl_delegate->registerOemUnsolicitedEventListener(_listener);
  }
  ::android::binder::Status getGta3xlwifiNetpolicy(::android::sp<::com::android::internal::net::IGta3xlwifiNetpolicy>* _aidl_return) override {
    auto _status = _aidl_delegate->getGta3xlwifiNetpolicy(_aidl_return);
    if (*_aidl_return) {
      *_aidl_return = ::android::sp<::com::android::internal::net::IGta3xlwifiNetpolicyDelegator>::cast(delegate(*_aidl_return));
    }
    return _status;
  }
private:
  ::android::sp<IOemNetd> _aidl_delegate;
};  // class IOemNetdDelegator
}  // namespace net
}  // namespace internal
}  // namespace android
}  // namespace com
