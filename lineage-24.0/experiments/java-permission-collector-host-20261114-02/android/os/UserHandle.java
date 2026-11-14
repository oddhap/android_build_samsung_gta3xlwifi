package android.os; public class UserHandle { public static final int PER_USER_RANGE=100000;
public static boolean isApp(int uid) {
        if (uid > 0) {
            final int appId = getAppId(uid);
            return appId >= Process.FIRST_APPLICATION_UID && appId <= Process.LAST_APPLICATION_UID;
        } else {
            return false;
        }
    }
public static int getAppId(int uid) {
        return uid % PER_USER_RANGE;
    }
}