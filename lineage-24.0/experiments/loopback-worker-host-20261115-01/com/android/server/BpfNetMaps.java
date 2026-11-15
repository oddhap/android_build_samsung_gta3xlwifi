package com.android.server;
public class BpfNetMaps{public Object factoryLock;public int admissions;public void completeGta3xlwifiStatsAdmission(){if(factoryLock!=null&&Thread.holdsLock(factoryLock))throw new AssertionError("Factory lock held during policy admission");admissions++;}public int captures;final Gta3xlwifiStatsAccess access;
 public BpfNetMaps(android.content.Context c,com.android.server.connectivity.InterfaceTracker t){throw new UnsupportedOperationException("BpfNetMaps boundary");}
 public BpfNetMaps(Gta3xlwifiStatsAccess a){access=a;}
 public Gta3xlwifiStatsAccess gta3xlwifiStatsAccess(){captures++;return access;}
 public void swapActiveStatsMap(){throw new AssertionError("Private path attempted BPF swap");}}
