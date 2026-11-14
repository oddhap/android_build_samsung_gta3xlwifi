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
package com.android.server.permission;

import android.annotation.FlaggedApi;
import android.annotation.NonNull;
import android.annotation.SystemApi;
import android.annotation.UserIdInt;
import android.util.SparseIntArray;

/**
 * An interface for managing permission states stored in a BPF map.
 *
 * <p>This interface provides methods to set, update, and remove permission states stored in a BPF
 * map.
 *
 * <p>Implementations of this interface are responsible for interacting with an actual BPF map and
 * ensuring that the permission states inside it are correctly updated.
 *
 * @hide
 */
@SystemApi(client = SystemApi.Client.SYSTEM_SERVER)
@FlaggedApi(android.permission.flags.Flags.FLAG_ACCESS_LOCAL_NETWORK_PERMISSION_ENABLED)
public interface PermissionBpfMap {
    /**
     * Set the permission states for a set of UIDs in the BPF map.
     *
     * @param uidsPermissionBits a mapping from UIDs to a bitmap of permission states. Bits in the
     *                        bitmap are in the same order as the list of permissions that was
     *                        passed in when this BPF map is registered in
     *                        {@link
     *                        com.android.server.permission.PermissionManagerLocal#registerBpfMap},
     *                        and are set to {@code 1} when the corresponding permission is
     *                        granted. A runtime permission is considered granted only if it is
     *                        fully granted including its app op.
     */
    void setUidsPermissionBits(@NonNull SparseIntArray uidsPermissionBits);

    /**
     * Deliver a complete permission snapshot at registration or when installed
     * user/package UID identities change, ordered before that mutation's later
     * mutation callbacks. User IDs and installed package UIDs come from the same
     * immutable permission-service state as the raw permission bits. Known UIDs
     * include packages with zero permission bits, which the sparse raw map omits.
     * Implementations must not call back into permission-state mutation here.
     * Existing map implementations delegate complete raw updates to their original
     * callback. Receivers must replace their complete user/known-UID identity image.
     */
    default void setInitialUidPermissions(@NonNull int[] userIds,
            @NonNull int[] knownPackageUids, @NonNull SparseIntArray uidsPermissionBits) {
        setUidsPermissionBits(uidsPermissionBits);
    }

    /**
     * Remove the permission states of all UIDs associated with an app ID from the BPF map.
     *
     * @param appId the app ID to remove
     */
    void removeAppId(int appId);

    /**
     * Remove the permission states of all UIDs associated with a user ID from the BPF map.
     *
     * @param userId the user ID to remove
     */
    void removeUser(@UserIdInt int userId);
}
