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
package org.hyperledger.besu.nativelib.boringssl;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Common logic shared between JNA and GraalVM implementations of BoringSSL precompiles
 */
public class BoringSSLPrecompilesCommon {

    public static final int STATUS_SUCCESS = 0;
    public static final int STATUS_FAIL = 1;
    public static final int STATUS_ERROR = 2;

    public static final int ERROR_BUF_SIZE = 256;

    // secp256r1 curve order
    public static final BigInteger SECP256R1_ORDER =
            new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

    // Wrapper result classes
    public static class P256VerifyResult {
        public final int status;
        public final String error;

        public P256VerifyResult(final int status, final String message) {
            this.status = status;
            this.error = message;
        }
    }

    public record ECRecoverResult(
            int status,
            Optional<byte[]> publicKey,
            Optional<String> error) {}

    /**
     * Validates ecrecover input parameters
     * @return Optional containing error result if validation fails, empty if valid
     */
    public static Optional<ECRecoverResult> validateEcrecoverInput(
            final byte[] hash, final byte[] sig, final int recovery_id) {

        // Validate signature length
        if (sig == null || sig.length != 64) {
            return Optional.of(new ECRecoverResult(STATUS_ERROR, Optional.empty(),
                    Optional.of("invalid signature length")));
        }

        if (hash == null || hash.length != 32) {
            return Optional.of(new ECRecoverResult(STATUS_ERROR, Optional.empty(),
                    Optional.of("invalid hash length")));
        }

        // Extract r and s values
        byte[] rBytes = new byte[32];
        byte[] sBytes = new byte[32];
        System.arraycopy(sig, 0, rBytes, 0, 32);
        System.arraycopy(sig, 32, sBytes, 0, 32);

        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        // Validate r and s are in range [1, n-1] before calling native method
        if (r.equals(BigInteger.ZERO) || r.compareTo(SECP256R1_ORDER) >= 0) {
            return Optional.of(new ECRecoverResult(STATUS_ERROR, Optional.empty(),
                    Optional.of("invalid signature r value")));
        }

        if (s.equals(BigInteger.ZERO) || s.compareTo(SECP256R1_ORDER) >= 0) {
            return Optional.of(new ECRecoverResult(STATUS_ERROR, Optional.empty(),
                    Optional.of("invalid signature s value")));
        }

        if (recovery_id < 0 || recovery_id > 1) {
            return Optional.of(new ECRecoverResult(STATUS_ERROR, Optional.empty(),
                    Optional.of("invalid recovery id " + recovery_id + " is not 0 or 1")));
        }

        return Optional.empty();
    }

    /**
     * Converts a null-terminated byte buffer to a Java String
     */
    public static String bytesToNullTermString(final byte[] buffer) {
        int nullTerminator = 0;
        while (nullTerminator < buffer.length && buffer[nullTerminator] != 0) {
            nullTerminator++;
        }
        return new String(buffer, 0, nullTerminator, StandardCharsets.UTF_8);
    }
}
