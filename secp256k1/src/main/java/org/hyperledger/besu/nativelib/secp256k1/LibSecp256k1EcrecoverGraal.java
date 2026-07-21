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
package org.hyperledger.besu.nativelib.secp256k1;

import org.graalvm.nativeimage.PinnedObject;
import org.graalvm.nativeimage.c.CContext;
import org.graalvm.nativeimage.c.function.CFunction;
import org.graalvm.nativeimage.c.type.CCharPointer;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * GraalVM native-image compatible interface to secp256k1_ecrecover static library.
 * Provides ECRECOVER operation for Ethereum precompile (address 0x01).
 *
 * <p>This class uses GraalVM's @CFunction annotation to call native C functions
 * directly from statically linked libraries, avoiding the overhead of JNA.
 *
 * <p>The native libraries required are:
 * <ul>
 *   <li>libsecp256k1.a - Core Bitcoin secp256k1 library</li>
 *   <li>libsecp256k1_ecrecover.a - JNI wrapper for ECRECOVER</li>
 * </ul>
 */
public class LibSecp256k1EcrecoverGraal {

    /** Size of message hash in bytes. */
    public static final int MESSAGE_HASH_SIZE = 32;

    /** Size of signature in bytes (r || s). */
    public static final int SIGNATURE_SIZE = 64;

    /** Size of recovered public key in bytes (uncompressed format). */
    public static final int PUBLIC_KEY_SIZE = 65;

    /** Private constructor to prevent instantiation of utility class. */
    private LibSecp256k1EcrecoverGraal() {}

    /**
     * CContext directives for configuring GraalVM native-image compilation.
     * Specifies header files and libraries required for static linking.
     */
    @CContext(LibSecp256k1EcrecoverGraal.Directives.class)
    public static class Directives implements CContext.Directives {
        @Override
        public List<String> getHeaderFiles() {
            // Specify the header files needed for compilation
            return Arrays.asList(
                "<secp256k1.h>",
                "<secp256k1_recovery.h>",
                "<secp256k1_ecrecover.h>"
            );
        }

        @Override
        public List<String> getLibraries() {
            // Specify the static libraries to link against
            // Order matters: list dependencies first, then dependents
            return Arrays.asList("secp256k1", "secp256k1_ecrecover");
        }

        @Override
        public List<String> getLibraryPaths() {
            // Library paths should be configured via native-image build arguments
            // (-H:CLibraryPath=<path>)
            return Collections.emptyList();
        }
    }

    /**
     * Native ECRECOVER function wrapper.
     *
     * <p>This function combines signature parsing, public key recovery, and serialization
     * into a single native call for optimal performance.
     *
     * @param messageHash pointer to 32-byte message hash
     * @param signature pointer to 64-byte compact signature (r || s)
     * @param recoveryId recovery ID (0 or 1)
     * @param outputBuffer pointer to 65-byte output buffer for uncompressed public key
     * @return 0 if recovery was successful, 1 otherwise
     */
    @CFunction(value = "secp256k1_ecrecover_jni")
    public static native int secp256k1EcrecoverNative(
            CCharPointer messageHash,
            CCharPointer signature,
            int recoveryId,
            CCharPointer outputBuffer);

    /**
     * Java-friendly wrapper for ECRECOVER operation.
     *
     * <p>Recovers the public key from an ECDSA signature using the secp256k1 curve.
     * This is the core operation for Ethereum transaction signature verification.
     *
     * <p><b>Input validation:</b>
     * <ul>
     *   <li>messageHash must be exactly 32 bytes</li>
     *   <li>signature must be exactly 64 bytes (r || s)</li>
     *   <li>recoveryId must be 0 or 1</li>
     *   <li>outputBuffer must be exactly 65 bytes</li>
     * </ul>
     *
     * <p><b>Output format:</b> The recovered public key is written to outputBuffer
     * in uncompressed format (65 bytes: 0x04 || x || y).
     *
     * @param messageHash 32-byte Keccak-256 hash of the signed message
     * @param signature 64-byte compact signature (r || s, each 32 bytes big-endian)
     * @param recoveryId recovery ID (0 or 1) for selecting the correct public key
     * @param outputBuffer 65-byte buffer to receive the recovered public key
     * @return 0 if recovery was successful, 1 if recovery failed or inputs are invalid
     * @throws IllegalArgumentException if input sizes are incorrect
     */
    public static int secp256k1Ecrecover(
            byte[] messageHash,
            byte[] signature,
            int recoveryId,
            byte[] outputBuffer) {

        // Validate input sizes
        if (messageHash.length != MESSAGE_HASH_SIZE) {
            throw new IllegalArgumentException(
                "Message hash must be " + MESSAGE_HASH_SIZE + " bytes, got " + messageHash.length);
        }
        if (signature.length != SIGNATURE_SIZE) {
            throw new IllegalArgumentException(
                "Signature must be " + SIGNATURE_SIZE + " bytes, got " + signature.length);
        }
        if (outputBuffer.length != PUBLIC_KEY_SIZE) {
            throw new IllegalArgumentException(
                "Output buffer must be " + PUBLIC_KEY_SIZE + " bytes, got " + outputBuffer.length);
        }
        if (recoveryId < 0 || recoveryId > 1) {
            throw new IllegalArgumentException(
                "Recovery ID must be 0 or 1, got " + recoveryId);
        }

        // Call native function with pinned byte arrays
        try (PinnedObject pinnedHash = PinnedObject.create(messageHash);
             PinnedObject pinnedSig = PinnedObject.create(signature);
             PinnedObject pinnedOutput = PinnedObject.create(outputBuffer)) {
            return secp256k1EcrecoverNative(
                pinnedHash.addressOfArrayElement(0),
                pinnedSig.addressOfArrayElement(0),
                recoveryId,
                pinnedOutput.addressOfArrayElement(0)
            );
        }
    }

    /**
     * Convenience method for ECRECOVER that allocates and returns the output buffer.
     *
     * @param messageHash 32-byte message hash
     * @param signature 64-byte compact signature (r || s)
     * @param recoveryId recovery ID (0 or 1)
     * @return 65-byte recovered public key in uncompressed format, or null if recovery failed
     */
    public static byte[] secp256k1EcrecoverWithAlloc(
            byte[] messageHash,
            byte[] signature,
            int recoveryId) {

        byte[] output = new byte[PUBLIC_KEY_SIZE];
        int result = secp256k1Ecrecover(messageHash, signature, recoveryId, output);

        return result == 0 ? output : null;
    }
}
