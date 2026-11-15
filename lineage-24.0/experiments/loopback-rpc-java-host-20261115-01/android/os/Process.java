package android.os; public class Process {public static final int SYSTEM_UID=1000;
public static final int FIRST_APPLICATION_UID=10000;
public static final int LAST_APPLICATION_UID=19999;
public static final int FIRST_SDK_SANDBOX_UID=20000;
public static boolean isApplicationUid(int uid) {
        return UserHandle.isApp(uid);
    }
public static final int toSdkSandboxUid(int uid) {
        return uid + (FIRST_SDK_SANDBOX_UID - FIRST_APPLICATION_UID);
    }
}