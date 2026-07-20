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

import org.graalvm.nativeimage.PinnedObject;
import org.graalvm.nativeimage.c.CContext;
import org.graalvm.nativeimage.c.function.CFunction;
import org.graalvm.nativeimage.c.type.CCharPointer;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * GraalVM native-image compatible interface to BoringSSL static library
 *
 * Note: This implementation only includes p256_verify, which is required for Ethereum mainnet.
 * The ecrecover_r1 function is not included as it is not necessary for mainnet configuration
 * and remains available in the standard JNA-based implementation if needed.
 */
public class BoringSSLPrecompilesGraal {

    public static final int STATUS_SUCCESS = BoringSSLPrecompilesCommon.STATUS_SUCCESS;
    public static final int STATUS_FAIL = BoringSSLPrecompilesCommon.STATUS_FAIL;
    public static final int STATUS_ERROR = BoringSSLPrecompilesCommon.STATUS_ERROR;

    @CContext(BoringSSLPrecompilesGraal.Directives.class)
    public static class Directives implements CContext.Directives {
        @Override
        public List<String> getHeaderFiles() {
            return Collections.singletonList("<p256_verify.h>");
        }

        @Override
        public List<String> getLibraries() {
            return Collections.singletonList("boringssl_precompiles");
        }

        @Override
        public List<String> getLibraryPaths() {
            // Library paths should be configured via native-image build arguments
            return Collections.emptyList();
        }
    }

    @CFunction(value = "p256_verify")
    public static native int p256VerifyNative(
            CCharPointer dataHash, int dataHashLength,
            CCharPointer signatureR, int signatureRLength,
            CCharPointer signatureS, int signatureSLength,
            CCharPointer publicKeyData, int publicKeyDataLength,
            CCharPointer errorMessageBuf, int errorMessageBufLen);

    // Wrapper result class - use common implementation
    public static class P256VerifyResult extends BoringSSLPrecompilesCommon.P256VerifyResult {
        public P256VerifyResult(final int status, final String message) {
            super(status, message);
        }
    }

    final static int ERROR_BUF_SIZE = BoringSSLPrecompilesCommon.ERROR_BUF_SIZE;

    /**
     * Java-friendly wrapper for p256_verify
     */
    public static P256VerifyResult p256Verify(final byte[] input, final int inputLength) {
        if (inputLength != 160) {
            return new P256VerifyResult(STATUS_ERROR, "incorrect input size");
        }

        byte[] dataHash = Arrays.copyOfRange(input, 0, 32);
        byte[] signatureR = Arrays.copyOfRange(input, 32, 64);
        byte[] signatureS = Arrays.copyOfRange(input, 64, 96);
        byte[] uncompressedPubKey = new byte[65];
        // uncompressed point prefix
        uncompressedPubKey[0] = 0x04;
        System.arraycopy(input, 96, uncompressedPubKey, 1, 64);

        byte[] errorBuf = new byte[ERROR_BUF_SIZE];

        try (PinnedObject pinnedDataHash = PinnedObject.create(dataHash);
             PinnedObject pinnedSignatureR = PinnedObject.create(signatureR);
             PinnedObject pinnedSignatureS = PinnedObject.create(signatureS);
             PinnedObject pinnedPublicKey = PinnedObject.create(uncompressedPubKey);
             PinnedObject pinnedErrorBuf = PinnedObject.create(errorBuf)) {

            int status = p256VerifyNative(
                    pinnedDataHash.addressOfArrayElement(0), dataHash.length,
                    pinnedSignatureR.addressOfArrayElement(0), signatureR.length,
                    pinnedSignatureS.addressOfArrayElement(0), signatureS.length,
                    pinnedPublicKey.addressOfArrayElement(0), uncompressedPubKey.length,
                    pinnedErrorBuf.addressOfArrayElement(0), ERROR_BUF_SIZE);

            return new P256VerifyResult(status, BoringSSLPrecompilesCommon.bytesToNullTermString(errorBuf));
        }
    }
}
