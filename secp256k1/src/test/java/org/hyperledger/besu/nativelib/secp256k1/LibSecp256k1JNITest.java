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

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt256;
import org.assertj.core.api.Assertions;
import org.junit.Assume;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class LibSecp256k1JNITest {

  private static final byte[] MESSAGE_HASH =
      Bytes.fromHexString("5cb4a1a2e0b9f7d3c8e6f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5")
          .toArrayUnsafe();

  // the field prime minus the curve order; recovery ids 2 and 3 need r below it, because they
  // use r + n as the x-coordinate
  private static final BigInteger P_MINUS_N =
      new BigInteger("14551231950b75fc4402da1722fc9baee", 16);

  private static final byte[] PUBLIC_KEY =
      Bytes.fromHexString(
              "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                  + "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
          .toArrayUnsafe();

  private static final byte[] PRIVATE_KEY =
      Bytes.fromHexString("0000000000000000000000000000000000000000000000000000000000000001")
          .toArrayUnsafe();

  @Test
  public void shouldLoadWhenTheLibraryIsBundledForThisPlatform() {
    // the parameterized tests skip themselves when the library can't be loaded, so a load failure
    // of a library that was built for this platform would otherwise go unnoticed
    String arch = System.getProperty("os.arch");
    if (List.of("amd64", "x86_64", "x64", "ia32e", "EMT64T").contains(arch)) {
      arch = "x86-64";
    }
    String resource =
        String.format("/lib-native/%s/%s", arch, System.mapLibraryName("secp256k1_ecrecover"));
    Assume.assumeNotNull(LibSecp256k1JNITest.class.getResource(resource));

    Assertions.assertThat(LibSecp256k1JNI.ENABLED).as("%s is bundled", resource).isTrue();
  }

  @Test
  public void ecrecoverShouldRecoverKeysForRecoveryIdsTwoAndThree() {
    Assume.assumeTrue("secp256k1 native must be enabled", LibSecp256k1JNI.ENABLED);

    // 2 + n is the x-coordinate of a curve point. The expected keys come from an independent
    // Python implementation and match BouncyCastle.
    final byte[] signature = signature(BigInteger.TWO, BigInteger.ONE);
    Assertions.assertThat(recover(signature, 2))
        .isEqualTo(
            "0x04fb884d14225968be94d1bca8e704a9afba8f7e71b33c8354f545025a5908f2b5"
                + "bc45b0cde0d27dcbe0946d8344bac0fb726b0854c8e5b8278bbb0a5547af5f21");
    Assertions.assertThat(recover(signature, 3))
        .isEqualTo(
            "0x04651fc48301ab6288a9c7c36f8ed40f0afcb398cb4e77293fedffefc5cdffa695"
                + "578931e05afc6838ba901223629ad3fd58d21af582f53c421a6d2f71148e7f2e");
  }

  @Test
  public void ecrecoverShouldFailForRecoveryIdTwoWithoutACurvePoint() {
    Assume.assumeTrue("secp256k1 native must be enabled", LibSecp256k1JNI.ENABLED);

    final byte[] outputBuffer = new byte[65];
    // 1 + n is not the x-coordinate of a curve point
    Assertions.assertThat(
            LibSecp256k1JNI.secp256k1_ecrecover_jni(
                MESSAGE_HASH, signature(BigInteger.ONE, BigInteger.ONE), 2, outputBuffer))
        .isEqualTo(1);
    // r + n would be the field prime itself, outside the field
    Assertions.assertThat(
            LibSecp256k1JNI.secp256k1_ecrecover_jni(
                MESSAGE_HASH, signature(P_MINUS_N, BigInteger.ONE), 2, outputBuffer))
        .isEqualTo(1);
  }

  @Test
  public void ecrecoverShouldFailForRecoveryIdsOutsideZeroToThree() {
    Assume.assumeTrue("secp256k1 native must be enabled", LibSecp256k1JNI.ENABLED);

    final byte[] signature = signature(BigInteger.TWO, BigInteger.ONE);
    for (final int recoveryId : new int[] {-1, 4}) {
      Assertions.assertThat(
              LibSecp256k1JNI.secp256k1_ecrecover_jni(
                  MESSAGE_HASH, signature, recoveryId, new byte[65]))
          .as("recovery id %d", recoveryId)
          .isEqualTo(1);
    }
  }

  @Test
  public void ecdhShouldClearTheOutputBufferWhenThePublicKeyIsNull() {
    Assume.assumeTrue("secp256k1 native must be enabled", LibSecp256k1JNI.ENABLED);

    byte[] outputBuffer = new byte[33];
    Arrays.fill(outputBuffer, (byte) 0xff);
    Assertions.assertThat(LibSecp256k1JNI.secp256k1_ecdh_jni(null, PRIVATE_KEY, outputBuffer))
        .isEqualTo(1);
    Assertions.assertThat(outputBuffer).containsOnly((byte) 0);
  }

  @Test
  public void ecdhShouldClearTheOutputBufferWhenThePrivateKeyIsNull() {
    Assume.assumeTrue("secp256k1 native must be enabled", LibSecp256k1JNI.ENABLED);

    byte[] outputBuffer = new byte[33];
    Arrays.fill(outputBuffer, (byte) 0xff);
    Assertions.assertThat(LibSecp256k1JNI.secp256k1_ecdh_jni(PUBLIC_KEY, null, outputBuffer))
        .isEqualTo(1);
    Assertions.assertThat(outputBuffer).containsOnly((byte) 0);
  }

  private static byte[] signature(final BigInteger r, final BigInteger s) {
    return Bytes.concatenate(UInt256.valueOf(r).toBytes(), UInt256.valueOf(s).toBytes())
        .toArrayUnsafe();
  }

  private static String recover(final byte[] signature, final int recoveryId) {
    final byte[] outputBuffer = new byte[65];
    Assertions.assertThat(
            LibSecp256k1JNI.secp256k1_ecrecover_jni(
                MESSAGE_HASH, signature, recoveryId, outputBuffer))
        .as("recovery id %d", recoveryId)
        .isEqualTo(0);
    return Bytes.wrap(outputBuffer).toHexString();
  }
}
