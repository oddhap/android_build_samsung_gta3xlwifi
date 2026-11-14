package com.android.internal.net; public interface IGta3xlwifiNetpolicy extends android.os.IInterface {
  public long openSession(android.os.IBinder client, int protocolVersion) throws android.os.RemoteException;
  public void beginFrame(long session, long expectedGeneration, int[] wordCounts, int runtimeFlags, boolean loopbackPermissionEnabled, boolean uidMigrationEnabled, boolean dataSaverEnabled) throws android.os.RemoteException;
  public void appendFrame(long session, int section, int offset, int[] words) throws android.os.RemoteException;
  public long commitFrame(long session) throws android.os.RemoteException;
  public void abandonFrame(long session) throws android.os.RemoteException;
  public long readGeneration(long session) throws android.os.RemoteException;
  public void closeSession(android.os.IBinder client) throws android.os.RemoteException;
}