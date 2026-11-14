package android.net;public class ConnectivityManager{
public static final int BLOCKED_METERED_REASON_ADMIN_DISABLED = 1 << 18;
public static final int BLOCKED_METERED_REASON_DATA_SAVER = 1 << 16;
public static final int BLOCKED_METERED_REASON_MASK = 0xffff0000;
public static final int BLOCKED_METERED_REASON_USER_RESTRICTED = 1 << 17;
public static final int BLOCKED_REASON_APP_BACKGROUND = 1 << 6;
public static final int BLOCKED_REASON_APP_STANDBY = 1 << 2;
public static final int BLOCKED_REASON_BATTERY_SAVER = 1 << 0;
public static final int BLOCKED_REASON_DOZE = 1 << 1;
public static final int BLOCKED_REASON_LOW_POWER_STANDBY = 1 << 5;
public static final int BLOCKED_REASON_NONE = 0;
public static final int BLOCKED_REASON_OEM_DENY = 1 << 7;
public static final int BLOCKED_REASON_RESTRICTED_MODE = 1 << 3;
public static final int FIREWALL_CHAIN_BACKGROUND = 6;
public static final int FIREWALL_CHAIN_DOZABLE = 1;
public static final int FIREWALL_CHAIN_LOW_POWER_STANDBY = 5;
public static final int FIREWALL_CHAIN_METERED_ALLOW = 10;
public static final int FIREWALL_CHAIN_METERED_DENY_ADMIN = 12;
public static final int FIREWALL_CHAIN_METERED_DENY_USER = 11;
public static final int FIREWALL_CHAIN_OEM_DENY_1 = 7;
public static final int FIREWALL_CHAIN_OEM_DENY_2 = 8;
public static final int FIREWALL_CHAIN_OEM_DENY_3 = 9;
public static final int FIREWALL_CHAIN_POWERSAVE = 3;
public static final int FIREWALL_CHAIN_RESTRICTED = 4;
public static final int FIREWALL_CHAIN_STANDBY = 2;
public static final int FIREWALL_RULE_ALLOW = 1;
public static final int FIREWALL_RULE_DENY = 2;
}