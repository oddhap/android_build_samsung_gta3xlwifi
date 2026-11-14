/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.net.module.util.bpf;

import androidx.annotation.NonNull;

import com.android.net.module.util.Struct;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Locale;

public class LocalNetUidHostAllowlistKey extends Struct {
    @Field(order = 0, type = Type.U32)
    public final long lpmBitlen;
    @Field(order = 1, type = Type.U32)
    public final long uid;
    @Field(order = 2, type = Type.U32)
    public final long ifIndex;
    @NonNull
    @Field(order = 3, type = Type.IpAddress)
    public final InetAddress remoteAddress;

    /**
     * Constructor for internal struct usage.
     */
    public LocalNetUidHostAllowlistKey(long lpmBitlen, long uid, long ifIndex,
            @NonNull InetAddress remoteAddress) {
        this.lpmBitlen = lpmBitlen;
        this.uid = uid;
        this.ifIndex = ifIndex;
        this.remoteAddress = remoteAddress;
    }

    /**
     * Make a new LocalNetUidHostAllowlistKey for a specific remote address.
     *
     * <p>Although the allowlist is a trie and not a map, that is only for performance reasons, so
     * every key sets the prefix match bit length to cover the whole key.
     */
    public LocalNetUidHostAllowlistKey(long uid, long ifIndex, @NonNull InetAddress remoteAddress) {
        this(/* lpmBitlen=*/32 + 32 + 128, uid, ifIndex, remoteAddress);
    }

    /**
     * Make a new LocalNetUidHostAllowlistKey for all remote addresses on an interface.
     */
    public LocalNetUidHostAllowlistKey(long uid, long ifIndex) {
        this(/* lpmBitlen=*/32 + 32, uid, ifIndex, HostAny.address());
    }

    @Override
    @NonNull
    public String toString() {
        return String.format(Locale.ROOT,
                "LocalNetUidHostAllowlistKey{uid: %d, ifIndex: %d, remoteAddress: %s}",
                uid, ifIndex, remoteAddress);
    }
}
