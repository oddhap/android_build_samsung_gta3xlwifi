package com.android.net.module.util;public class NetworkStatsUtils{public static long multiplySafeByRational(long value, long num, long den) {
        if (den == 0) {
            throw new ArithmeticException("Invalid Denominator");
        }
        long x = value;
        long y = num;

        // Logic shamelessly borrowed from Math.multiplyExact()
        long r = x * y;
        long ax = Math.abs(x);
        long ay = Math.abs(y);
        if (((ax | ay) >>> 31 != 0)) {
            // Some bits greater than 2^31 that might cause overflow
            // Check the result using the divide operator
            // and check for the special case of Long.MIN_VALUE * -1
            if (((y != 0) && (r / y != x))
                    || (x == Long.MIN_VALUE && y == -1)) {
                // Use double math to avoid overflowing
                return (long) (((double) num / den) * value);
            }
        }
        return r / den;
    }}