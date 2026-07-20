/*
 * Copyright contributors to Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
package org.hyperledger.besu.nativelib.gnark;

import org.hyperledger.besu.nativelib.common.BesuNativeLibraryLoader;

/**
 * Java interface to gnark
 */
public class LibGnark {

    @SuppressWarnings("WeakerAccess")
    public static final boolean ENABLED;

    static {
        boolean enabled;
        try {
            BesuNativeLibraryLoader.registerJNA(LibGnark.class, "gnark_jni");
            enabled = true;
        } catch (final Throwable t) {
            t.printStackTrace();
            enabled = false;
        }
        ENABLED = enabled;
    }

    public static native int computeMimcBn254(
            byte[] i, int i_len, byte[] o);

    public static native int computeMimcBls12377(
        byte[] i, int i_len, byte[] o);

    public static native int computePoseidon2Koalabear(
        byte[] i, int i_len, byte[] o);

}
