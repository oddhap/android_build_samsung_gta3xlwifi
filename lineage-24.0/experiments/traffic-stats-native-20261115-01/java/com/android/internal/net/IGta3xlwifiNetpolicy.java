/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: /srv/android/src/lineage-24.0-arm64/out/host/linux-x86/bin/aidl --lang=java --min_sdk_version=10000 -I/srv/android/ports/lineage-24.0-arm64/traffic-stats24-20261115-01/binder -I/srv/android/src/lineage-24.0-arm64/system/netd/server/binder -o /srv/android/artifacts/lineage-24.0-arm64/traffic-stats-native-20261115-01/java /srv/android/ports/lineage-24.0-arm64/traffic-stats24-20261115-01/binder/com/android/internal/net/IGta3xlwifiNetpolicy.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
package com.android.internal.net;
/**
 * Private gta3xlwifi complete policy transport, separate from frozen INetd.
 * Protocol 1. Every call requires the system UID, including transferred handles.
 * A session or completed transport is not a networking readiness signal.
 * Sections/word encoding are defined by Gta3xlwifiPolicyFrame.h/.cpp.
 * Chunks have at most 4096 ints; the complete image is bounded independently.
 * @hide
 */
public interface IGta3xlwifiNetpolicy extends android.os.IInterface
{
  /** Default implementation for IGta3xlwifiNetpolicy. */
  public static class Default implements com.android.internal.net.IGta3xlwifiNetpolicy
  {
    @Override public long openSession(android.os.IBinder client, int protocolVersion) throws android.os.RemoteException
    {
      return 0L;
    }
    @Override public void beginFrame(long session, long expectedGeneration, int[] wordCounts, int runtimeFlags, boolean loopbackPermissionEnabled, boolean uidMigrationEnabled, boolean dataSaverEnabled) throws android.os.RemoteException
    {
    }
    @Override public void appendFrame(long session, int section, int offset, int[] words) throws android.os.RemoteException
    {
    }
    @Override public long commitFrame(long session) throws android.os.RemoteException
    {
      return 0L;
    }
    @Override public void abandonFrame(long session) throws android.os.RemoteException
    {
    }
    /** Committed generation or zero for verified held/unpublished state. */
    @Override public long readGeneration(long session) throws android.os.RemoteException
    {
      return 0L;
    }
    /** Explicit retirement, including an interrupted open with unknown session. */
    @Override public void closeSession(android.os.IBinder client) throws android.os.RemoteException
    {
    }
    /**
     * Genuine bounded stats. Kind0=state,1=frozen-bank,2=cumulative-app,
     * 3=cumulative-interface,4=kernel interface-name history. Schema/layout is documented with the service.
     * Unsigned64 counters retain their exact bits in long. No read consumes.
     * Caller must inspect actual loss, persist/deduplicate before ACK and never
     * automatically retry an uncertain SWAP. Connection is not stats readiness.
     */
    @Override public long[] readStats(long session, int kind, int bank, long epoch) throws android.os.RemoteException
    {
      return null;
    }
    /** Four words: active bank/epoch, frozen bank/epoch. */
    @Override public long[] swapStats(long session, int expectedActiveBank, long expectedActiveEpoch) throws android.os.RemoteException
    {
      return null;
    }
    /** Explicit receipt AFTER accepted/persisted data; native ACK is idempotent. */
    @Override public void acknowledgeStats(long session, int bank, long epoch) throws android.os.RemoteException
    {
    }
    @Override public void setStatsCounterset(long session, int uid, int counterset) throws android.os.RemoteException
    {
    }
    @Override
    public android.os.IBinder asBinder() {
      return null;
    }
  }
  /** Local-side IPC implementation stub class. */
  public static abstract class Stub extends android.os.Binder implements com.android.internal.net.IGta3xlwifiNetpolicy
  {
    /** Construct the stub and attach it to the interface. */
    @SuppressWarnings("this-escape")
    public Stub()
    {
      this.attachInterface(this, DESCRIPTOR);
    }
    /**
     * Cast an IBinder object into an com.android.internal.net.IGta3xlwifiNetpolicy interface,
     * generating a proxy if needed.
     */
    public static com.android.internal.net.IGta3xlwifiNetpolicy asInterface(android.os.IBinder obj)
    {
      if ((obj==null)) {
        return null;
      }
      android.os.IInterface iin = obj.queryLocalInterface(DESCRIPTOR);
      if (((iin!=null)&&(iin instanceof com.android.internal.net.IGta3xlwifiNetpolicy))) {
        return ((com.android.internal.net.IGta3xlwifiNetpolicy)iin);
      }
      return new com.android.internal.net.IGta3xlwifiNetpolicy.Stub.Proxy(obj);
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
        case TRANSACTION_openSession:
        {
          android.os.IBinder _arg0;
          _arg0 = data.readStrongBinder();
          int _arg1;
          _arg1 = data.readInt();
          data.enforceNoDataAvail();
          long _result = this.openSession(_arg0, _arg1);
          reply.writeNoException();
          reply.writeLong(_result);
          break;
        }
        case TRANSACTION_beginFrame:
        {
          long _arg0;
          _arg0 = data.readLong();
          long _arg1;
          _arg1 = data.readLong();
          int[] _arg2;
          _arg2 = data.createIntArray();
          int _arg3;
          _arg3 = data.readInt();
          boolean _arg4;
          _arg4 = data.readBoolean();
          boolean _arg5;
          _arg5 = data.readBoolean();
          boolean _arg6;
          _arg6 = data.readBoolean();
          data.enforceNoDataAvail();
          this.beginFrame(_arg0, _arg1, _arg2, _arg3, _arg4, _arg5, _arg6);
          reply.writeNoException();
          break;
        }
        case TRANSACTION_appendFrame:
        {
          long _arg0;
          _arg0 = data.readLong();
          int _arg1;
          _arg1 = data.readInt();
          int _arg2;
          _arg2 = data.readInt();
          int[] _arg3;
          _arg3 = data.createIntArray();
          data.enforceNoDataAvail();
          this.appendFrame(_arg0, _arg1, _arg2, _arg3);
          reply.writeNoException();
          break;
        }
        case TRANSACTION_commitFrame:
        {
          long _arg0;
          _arg0 = data.readLong();
          data.enforceNoDataAvail();
          long _result = this.commitFrame(_arg0);
          reply.writeNoException();
          reply.writeLong(_result);
          break;
        }
        case TRANSACTION_abandonFrame:
        {
          long _arg0;
          _arg0 = data.readLong();
          data.enforceNoDataAvail();
          this.abandonFrame(_arg0);
          reply.writeNoException();
          break;
        }
        case TRANSACTION_readGeneration:
        {
          long _arg0;
          _arg0 = data.readLong();
          data.enforceNoDataAvail();
          long _result = this.readGeneration(_arg0);
          reply.writeNoException();
          reply.writeLong(_result);
          break;
        }
        case TRANSACTION_closeSession:
        {
          android.os.IBinder _arg0;
          _arg0 = data.readStrongBinder();
          data.enforceNoDataAvail();
          this.closeSession(_arg0);
          reply.writeNoException();
          break;
        }
        case TRANSACTION_readStats:
        {
          long _arg0;
          _arg0 = data.readLong();
          int _arg1;
          _arg1 = data.readInt();
          int _arg2;
          _arg2 = data.readInt();
          long _arg3;
          _arg3 = data.readLong();
          data.enforceNoDataAvail();
          long[] _result = this.readStats(_arg0, _arg1, _arg2, _arg3);
          reply.writeNoException();
          reply.writeLongArray(_result);
          break;
        }
        case TRANSACTION_swapStats:
        {
          long _arg0;
          _arg0 = data.readLong();
          int _arg1;
          _arg1 = data.readInt();
          long _arg2;
          _arg2 = data.readLong();
          data.enforceNoDataAvail();
          long[] _result = this.swapStats(_arg0, _arg1, _arg2);
          reply.writeNoException();
          reply.writeLongArray(_result);
          break;
        }
        case TRANSACTION_acknowledgeStats:
        {
          long _arg0;
          _arg0 = data.readLong();
          int _arg1;
          _arg1 = data.readInt();
          long _arg2;
          _arg2 = data.readLong();
          data.enforceNoDataAvail();
          this.acknowledgeStats(_arg0, _arg1, _arg2);
          reply.writeNoException();
          break;
        }
        case TRANSACTION_setStatsCounterset:
        {
          long _arg0;
          _arg0 = data.readLong();
          int _arg1;
          _arg1 = data.readInt();
          int _arg2;
          _arg2 = data.readInt();
          data.enforceNoDataAvail();
          this.setStatsCounterset(_arg0, _arg1, _arg2);
          reply.writeNoException();
          break;
        }
        default:
        {
          return super.onTransact(code, data, reply, flags);
        }
      }
      return true;
    }
    private static final class Proxy implements com.android.internal.net.IGta3xlwifiNetpolicy
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
      @Override public long openSession(android.os.IBinder client, int protocolVersion) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain(asBinder());
        android.os.Parcel _reply = android.os.Parcel.obtain();
        long _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeStrongBinder(client);
          _data.writeInt(protocolVersion);
          boolean _status = mRemote.transact(Stub.TRANSACTION_openSession, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readLong();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public void beginFrame(long session, long expectedGeneration, int[] wordCounts, int runtimeFlags, boolean loopbackPermissionEnabled, boolean uidMigrationEnabled, boolean dataSaverEnabled) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain(asBinder());
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeLong(session);
          _data.writeLong(expectedGeneration);
          _data.writeIntArray(wordCounts);
          _data.writeInt(runtimeFlags);
          _data.writeBoolean(loopbackPermissionEnabled);
          _data.writeBoolean(uidMigrationEnabled);
          _data.writeBoolean(dataSaverEnabled);
          boolean _status = mRemote.transact(Stub.TRANSACTION_beginFrame, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      @Override public void appendFrame(long session, int section, int offset, int[] words) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain(asBinder());
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeLong(session);
          _data.writeInt(section);
          _data.writeInt(offset);
          _data.writeIntArray(words);
          boolean _status = mRemote.transact(Stub.TRANSACTION_appendFrame, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      @Override public long commitFrame(long session) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain(asBinder());
        android.os.Parcel _reply = android.os.Parcel.obtain();
        long _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeLong(session);
          boolean _status = mRemote.transact(Stub.TRANSACTION_commitFrame, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readLong();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public void abandonFrame(long session) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain(asBinder());
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeLong(session);
          boolean _status = mRemote.transact(Stub.TRANSACTION_abandonFrame, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      /** Committed generation or zero for verified held/unpublished state. */
      @Override public long readGeneration(long session) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain(asBinder());
        android.os.Parcel _reply = android.os.Parcel.obtain();
        long _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeLong(session);
          boolean _status = mRemote.transact(Stub.TRANSACTION_readGeneration, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readLong();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      /** Explicit retirement, including an interrupted open with unknown session. */
      @Override public void closeSession(android.os.IBinder client) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain(asBinder());
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeStrongBinder(client);
          boolean _status = mRemote.transact(Stub.TRANSACTION_closeSession, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      /**
       * Genuine bounded stats. Kind0=state,1=frozen-bank,2=cumulative-app,
       * 3=cumulative-interface,4=kernel interface-name history. Schema/layout is documented with the service.
       * Unsigned64 counters retain their exact bits in long. No read consumes.
       * Caller must inspect actual loss, persist/deduplicate before ACK and never
       * automatically retry an uncertain SWAP. Connection is not stats readiness.
       */
      @Override public long[] readStats(long session, int kind, int bank, long epoch) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain(asBinder());
        android.os.Parcel _reply = android.os.Parcel.obtain();
        long[] _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeLong(session);
          _data.writeInt(kind);
          _data.writeInt(bank);
          _data.writeLong(epoch);
          boolean _status = mRemote.transact(Stub.TRANSACTION_readStats, _data, _reply, 0);
          _reply.readException();
          _result = _reply.createLongArray();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      /** Four words: active bank/epoch, frozen bank/epoch. */
      @Override public long[] swapStats(long session, int expectedActiveBank, long expectedActiveEpoch) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain(asBinder());
        android.os.Parcel _reply = android.os.Parcel.obtain();
        long[] _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeLong(session);
          _data.writeInt(expectedActiveBank);
          _data.writeLong(expectedActiveEpoch);
          boolean _status = mRemote.transact(Stub.TRANSACTION_swapStats, _data, _reply, 0);
          _reply.readException();
          _result = _reply.createLongArray();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      /** Explicit receipt AFTER accepted/persisted data; native ACK is idempotent. */
      @Override public void acknowledgeStats(long session, int bank, long epoch) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain(asBinder());
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeLong(session);
          _data.writeInt(bank);
          _data.writeLong(epoch);
          boolean _status = mRemote.transact(Stub.TRANSACTION_acknowledgeStats, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      @Override public void setStatsCounterset(long session, int uid, int counterset) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain(asBinder());
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeLong(session);
          _data.writeInt(uid);
          _data.writeInt(counterset);
          boolean _status = mRemote.transact(Stub.TRANSACTION_setStatsCounterset, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
    }
    static final int TRANSACTION_openSession = (android.os.IBinder.FIRST_CALL_TRANSACTION + 0);
    static final int TRANSACTION_beginFrame = (android.os.IBinder.FIRST_CALL_TRANSACTION + 1);
    static final int TRANSACTION_appendFrame = (android.os.IBinder.FIRST_CALL_TRANSACTION + 2);
    static final int TRANSACTION_commitFrame = (android.os.IBinder.FIRST_CALL_TRANSACTION + 3);
    static final int TRANSACTION_abandonFrame = (android.os.IBinder.FIRST_CALL_TRANSACTION + 4);
    static final int TRANSACTION_readGeneration = (android.os.IBinder.FIRST_CALL_TRANSACTION + 5);
    static final int TRANSACTION_closeSession = (android.os.IBinder.FIRST_CALL_TRANSACTION + 6);
    static final int TRANSACTION_readStats = (android.os.IBinder.FIRST_CALL_TRANSACTION + 7);
    static final int TRANSACTION_swapStats = (android.os.IBinder.FIRST_CALL_TRANSACTION + 8);
    static final int TRANSACTION_acknowledgeStats = (android.os.IBinder.FIRST_CALL_TRANSACTION + 9);
    static final int TRANSACTION_setStatsCounterset = (android.os.IBinder.FIRST_CALL_TRANSACTION + 10);
  }
  /** @hide */
  public static final java.lang.String DESCRIPTOR = "com.android.internal.net.IGta3xlwifiNetpolicy";
  public long openSession(android.os.IBinder client, int protocolVersion) throws android.os.RemoteException;
  public void beginFrame(long session, long expectedGeneration, int[] wordCounts, int runtimeFlags, boolean loopbackPermissionEnabled, boolean uidMigrationEnabled, boolean dataSaverEnabled) throws android.os.RemoteException;
  public void appendFrame(long session, int section, int offset, int[] words) throws android.os.RemoteException;
  public long commitFrame(long session) throws android.os.RemoteException;
  public void abandonFrame(long session) throws android.os.RemoteException;
  /** Committed generation or zero for verified held/unpublished state. */
  public long readGeneration(long session) throws android.os.RemoteException;
  /** Explicit retirement, including an interrupted open with unknown session. */
  public void closeSession(android.os.IBinder client) throws android.os.RemoteException;
  /**
   * Genuine bounded stats. Kind0=state,1=frozen-bank,2=cumulative-app,
   * 3=cumulative-interface,4=kernel interface-name history. Schema/layout is documented with the service.
   * Unsigned64 counters retain their exact bits in long. No read consumes.
   * Caller must inspect actual loss, persist/deduplicate before ACK and never
   * automatically retry an uncertain SWAP. Connection is not stats readiness.
   */
  public long[] readStats(long session, int kind, int bank, long epoch) throws android.os.RemoteException;
  /** Four words: active bank/epoch, frozen bank/epoch. */
  public long[] swapStats(long session, int expectedActiveBank, long expectedActiveEpoch) throws android.os.RemoteException;
  /** Explicit receipt AFTER accepted/persisted data; native ACK is idempotent. */
  public void acknowledgeStats(long session, int bank, long epoch) throws android.os.RemoteException;
  public void setStatsCounterset(long session, int uid, int counterset) throws android.os.RemoteException;
}
