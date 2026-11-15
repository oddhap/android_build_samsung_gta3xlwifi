package com.android.internal.net; public interface IGta3xlwifiNetpolicy extends android.os.IInterface {
  public long openSession(android.os.IBinder client, int protocolVersion) throws android.os.RemoteException;
  public void beginFrame(long session, long expectedGeneration, int[] wordCounts, int runtimeFlags, boolean loopbackPermissionEnabled, boolean uidMigrationEnabled, boolean dataSaverEnabled) throws android.os.RemoteException;
  public void appendFrame(long session, int section, int offset, int[] words) throws android.os.RemoteException;
  public long commitFrame(long session) throws android.os.RemoteException;
  public void abandonFrame(long session) throws android.os.RemoteException;
  public long readGeneration(long session) throws android.os.RemoteException;
  public void closeSession(android.os.IBinder client) throws android.os.RemoteException;
  public long[] readStats(long session, int kind, int bank, long epoch) throws android.os.RemoteException;
  public long[] swapStats(long session, int expectedActiveBank, long expectedActiveEpoch) throws android.os.RemoteException;
  public void acknowledgeStats(long session, int bank, long epoch) throws android.os.RemoteException;
  public void setStatsCounterset(long session, int uid, int counterset) throws android.os.RemoteException;
default void removeUidAccounting(long session,int uid,long generation,long epoch)throws android.os.RemoteException{throw new UnsupportedOperationException();}
default void removeUidAccountingOnce(long session,int uid,long generation,long epoch,long nonce)throws android.os.RemoteException{throw new UnsupportedOperationException();}
}