import com.android.server.*;class MapsEventMethods{Gta3xlwifiNetpolicyBackend mGta;private static Gta3xlwifiLoopbackEventPoller sGtaLoopbackPoller;public boolean startGta3xlwifiLoopbackEventConsumer(android.os.Handler handler) {
        if(mGta==null)return false;
        synchronized(BpfNetMaps.class){
            if(!mGta.loopbackMetrics)throw new IllegalStateException("Private loopback metrics disabled");
            if(sGtaLoopbackPoller==null){
                sGtaLoopbackPoller=new Gta3xlwifiLoopbackEventPoller(mGta.statsAccess(),handler);
                sGtaLoopbackPoller.start();
            }
        }
        return true;
    }}