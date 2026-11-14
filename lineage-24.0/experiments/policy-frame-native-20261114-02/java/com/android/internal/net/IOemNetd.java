/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: /srv/android/src/lineage-24.0-arm64/out/host/linux-x86/bin/aidl --lang=java --min_sdk_version=10000 -I/srv/android/ports/lineage-24.0-arm64/policy-frame24-20261114-01/binder -I/srv/android/src/lineage-24.0-arm64/system/netd/server/binder -o /srv/android/artifacts/lineage-24.0-arm64/policy-frame-native-20261114-02/java /srv/android/ports/lineage-24.0-arm64/policy-frame24-20261114-01/binder/com/android/internal/net/IOemNetd.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
package com.android.internal.net;
/** @hide */
public interface IOemNetd extends android.os.IInterface
{
  /** Default implementation for IOemNetd. */
  public static class Default implements com.android.internal.net.IOemNetd
  {
    /** Returns true if the service is responding. */
    @Override public boolean isAlive() throws android.os.RemoteException
    {
      return false;
    }
    /**
     * Register oem unsolicited event listener
     * 
     * @param listener oem unsolicited event listener to register
     */
    @Override public void registerOemUnsolicitedEventListener(com.android.internal.net.IOemNetdUnsolicitedEventListener listener) throws android.os.RemoteException
    {
    }
    /** Private transport only. Handle lookup never grants networking readiness. */
    @Override public com.android.internal.net.IGta3xlwifiNetpolicy getGta3xlwifiNetpolicy() throws android.os.RemoteException
    {
      return null;
    }
    @Override
    public android.os.IBinder asBinder() {
      return null;
    }
  }
  /** Local-side IPC implementation stub class. */
  public static abstract class Stub extends android.os.Binder implements com.android.internal.net.IOemNetd
  {
    /** Construct the stub and attach it to the interface. */
    @SuppressWarnings("this-escape")
    public Stub()
    {
      this.attachInterface(this, DESCRIPTOR);
    }
    /**
     * Cast an IBinder object into an com.android.internal.net.IOemNetd interface,
     * generating a proxy if needed.
     */
    public static com.android.internal.net.IOemNetd asInterface(android.os.IBinder obj)
    {
      if ((obj==null)) {
        return null;
      }
      android.os.IInterface iin = obj.queryLocalInterface(DESCRIPTOR);
      if (((iin!=null)&&(iin instanceof com.android.internal.net.IOemNetd))) {
        return ((com.android.internal.net.IOemNetd)iin);
      }
      return new com.android.internal.net.IOemNetd.Stub.Proxy(obj);
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
        case TRANSACTION_isAlive:
        {
          boolean _result = this.isAlive();
          reply.writeNoException();
          reply.writeBoolean(_result);
          break;
        }
        case TRANSACTION_registerOemUnsolicitedEventListener:
        {
          com.android.internal.net.IOemNetdUnsolicitedEventListener _arg0;
          _arg0 = com.android.internal.net.IOemNetdUnsolicitedEventListener.Stub.asInterface(data.readStrongBinder());
          data.enforceNoDataAvail();
          this.registerOemUnsolicitedEventListener(_arg0);
          reply.writeNoException();
          break;
        }
        case TRANSACTION_getGta3xlwifiNetpolicy:
        {
          com.android.internal.net.IGta3xlwifiNetpolicy _result = this.getGta3xlwifiNetpolicy();
          reply.writeNoException();
          reply.writeStrongInterface(_result);
          break;
        }
        default:
        {
          return super.onTransact(code, data, reply, flags);
        }
      }
      return true;
    }
    private static final class Proxy implements com.android.internal.net.IOemNetd
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
      /** Returns true if the service is responding. */
      @Override public boolean isAlive() throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain(asBinder());
        android.os.Parcel _reply = android.os.Parcel.obtain();
        boolean _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          boolean _status = mRemote.transact(Stub.TRANSACTION_isAlive, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readBoolean();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      /**
       * Register oem unsolicited event listener
       * 
       * @param listener oem unsolicited event listener to register
       */
      @Override public void registerOemUnsolicitedEventListener(com.android.internal.net.IOemNetdUnsolicitedEventListener listener) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain(asBinder());
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeStrongInterface(listener);
          boolean _status = mRemote.transact(Stub.TRANSACTION_registerOemUnsolicitedEventListener, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      /** Private transport only. Handle lookup never grants networking readiness. */
      @Override public com.android.internal.net.IGta3xlwifiNetpolicy getGta3xlwifiNetpolicy() throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain(asBinder());
        android.os.Parcel _reply = android.os.Parcel.obtain();
        com.android.internal.net.IGta3xlwifiNetpolicy _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          boolean _status = mRemote.transact(Stub.TRANSACTION_getGta3xlwifiNetpolicy, _data, _reply, 0);
          _reply.readException();
          _result = com.android.internal.net.IGta3xlwifiNetpolicy.Stub.asInterface(_reply.readStrongBinder());
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
    }
    static final int TRANSACTION_isAlive = (android.os.IBinder.FIRST_CALL_TRANSACTION + 0);
    static final int TRANSACTION_registerOemUnsolicitedEventListener = (android.os.IBinder.FIRST_CALL_TRANSACTION + 1);
    static final int TRANSACTION_getGta3xlwifiNetpolicy = (android.os.IBinder.FIRST_CALL_TRANSACTION + 2);
  }
  /** @hide */
  public static final java.lang.String DESCRIPTOR = "com.android.internal.net.IOemNetd";
  /** Returns true if the service is responding. */
  public boolean isAlive() throws android.os.RemoteException;
  /**
   * Register oem unsolicited event listener
   * 
   * @param listener oem unsolicited event listener to register
   */
  public void registerOemUnsolicitedEventListener(com.android.internal.net.IOemNetdUnsolicitedEventListener listener) throws android.os.RemoteException;
  /** Private transport only. Handle lookup never grants networking readiness. */
  public com.android.internal.net.IGta3xlwifiNetpolicy getGta3xlwifiNetpolicy() throws android.os.RemoteException;
}
