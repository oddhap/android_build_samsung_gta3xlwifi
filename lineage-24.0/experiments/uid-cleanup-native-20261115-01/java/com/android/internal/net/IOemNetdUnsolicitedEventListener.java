/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: /srv/android/src/lineage-24.0-arm64/out/host/linux-x86/bin/aidl --lang=java --min_sdk_version=10000 -I/srv/android/src/lineage-24.0-arm64/system/netd/server/binder -o /srv/android/artifacts/lineage-24.0-arm64/uid-cleanup-native-20261115-01/java /srv/android/src/lineage-24.0-arm64/system/netd/server/binder/com/android/internal/net/IOemNetdUnsolicitedEventListener.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
package com.android.internal.net;
/** @hide */
public interface IOemNetdUnsolicitedEventListener extends android.os.IInterface
{
  /** Default implementation for IOemNetdUnsolicitedEventListener. */
  public static class Default implements com.android.internal.net.IOemNetdUnsolicitedEventListener
  {
    /**
     * Notifies that a listener is registered.
     * 
     * It is a sample method and used for testing.
     */
    @Override public void onRegistered() throws android.os.RemoteException
    {
    }
    @Override
    public android.os.IBinder asBinder() {
      return null;
    }
  }
  /** Local-side IPC implementation stub class. */
  public static abstract class Stub extends android.os.Binder implements com.android.internal.net.IOemNetdUnsolicitedEventListener
  {
    /** Construct the stub and attach it to the interface. */
    @SuppressWarnings("this-escape")
    public Stub()
    {
      this.attachInterface(this, DESCRIPTOR);
    }
    /**
     * Cast an IBinder object into an com.android.internal.net.IOemNetdUnsolicitedEventListener interface,
     * generating a proxy if needed.
     */
    public static com.android.internal.net.IOemNetdUnsolicitedEventListener asInterface(android.os.IBinder obj)
    {
      if ((obj==null)) {
        return null;
      }
      android.os.IInterface iin = obj.queryLocalInterface(DESCRIPTOR);
      if (((iin!=null)&&(iin instanceof com.android.internal.net.IOemNetdUnsolicitedEventListener))) {
        return ((com.android.internal.net.IOemNetdUnsolicitedEventListener)iin);
      }
      return new com.android.internal.net.IOemNetdUnsolicitedEventListener.Stub.Proxy(obj);
    }
    @Override public android.os.IBinder asBinder()
    {
      return this;
    }
    @Override public boolean onTransact(int code, android.os.Parcel data, android.os.Parcel reply, int flags) throws android.os.RemoteException
    {
      if (code >= android.os.IBinder.FIRST_CALL_TRANSACTION && code <= android.os.IBinder.LAST_CALL_TRANSACTION) {
        data.enforceInterface(DESCRIPTOR);
      }
      switch (code)
      {
        case TRANSACTION_onRegistered:
        {
          this.onRegistered();
          break;
        }
        default:
        {
          return super.onTransact(code, data, reply, flags);
        }
      }
      return true;
    }
    private static final class Proxy implements com.android.internal.net.IOemNetdUnsolicitedEventListener
    {
      private android.os.IBinder mRemote;
      Proxy(android.os.IBinder remote)
      {
        mRemote = remote;
      }
      @Override public android.os.IBinder asBinder()
      {
        return mRemote;
      }
      public final java.lang.String getInterfaceDescriptor()
      {
        return DESCRIPTOR;
      }
      /**
       * Notifies that a listener is registered.
       * 
       * It is a sample method and used for testing.
       */
      @Override public void onRegistered() throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain(asBinder());
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          boolean _status = mRemote.transact(Stub.TRANSACTION_onRegistered, _data, null, android.os.IBinder.FLAG_ONEWAY);
        }
        finally {
          _data.recycle();
        }
      }
    }
    static final int TRANSACTION_onRegistered = (android.os.IBinder.FIRST_CALL_TRANSACTION + 0);
  }
  /** @hide */
  public static final java.lang.String DESCRIPTOR = "com.android.internal.net.IOemNetdUnsolicitedEventListener";
  /**
   * Notifies that a listener is registered.
   * 
   * It is a sample method and used for testing.
   */
  public void onRegistered() throws android.os.RemoteException;
}
