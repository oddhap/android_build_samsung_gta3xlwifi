package com.android.server;
public class BpfNetMaps{public int captures;final Gta3xlwifiStatsAccess access;
 public BpfNetMaps(android.content.Context c,com.android.server.connectivity.InterfaceTracker t){throw new UnsupportedOperationException("BpfNetMaps boundary");}
 public BpfNetMaps(Gta3xlwifiStatsAccess a){access=a;}
 public Gta3xlwifiStatsAccess gta3xlwifiStatsAccess(){captures++;return access;}
 public void swapActiveStatsMap(){throw new AssertionError("Private path attempted BPF swap");}}
