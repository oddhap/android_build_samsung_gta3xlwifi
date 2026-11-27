/* SPDX-License-Identifier: Apache-2.0 */
import android.system.Os;
import android.system.OsConstants;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.File;

/**
 * Device probe (run with app_process as shell): counts /proc/self/fd after N reads of
 * /proc/sys/kernel/random/boot_id using the build-53 Gta3xlwifiStatsJournal pattern
 * (Os.open + try-with-resources new FileInputStream(fd)) and the build-54 pattern
 * (same, plus Os.close(fd) in finally).
 */
public final class FdLeakProbe {
    private static int count() { return new File("/proc/self/fd").list().length; }
    private static void read(boolean fixed) throws Exception {
        FileDescriptor fd = Os.open("/proc/sys/kernel/random/boot_id",
                OsConstants.O_RDONLY | OsConstants.O_CLOEXEC | OsConstants.O_NOFOLLOW, 0);
        try {
            try (FileInputStream in = new FileInputStream(fd)) {
                byte[] b = new byte[38];
                if (in.read(b) != 37) throw new IllegalStateException("boot_id length");
            }
        } finally {
            if (fixed) Os.close(fd);
        }
    }
    public static void main(String[] args) throws Exception {
        int n = 500;
        for (String mode : new String[] {"old", "fixed"}) {
            System.gc(); Runtime.getRuntime().runFinalization();
            int before = count();
            for (int i = 0; i < n; ++i) read(mode.equals("fixed"));
            System.gc(); Runtime.getRuntime().runFinalization(); Thread.sleep(200);
            System.out.println(mode + " reads=" + n + " fd_delta=" + (count() - before));
        }
    }
}
