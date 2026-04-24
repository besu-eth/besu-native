/*
 * Copyright Besu Contributors
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

import org.apache.tuweni.bytes.Bytes;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class BLS12G1PointDecodingTests {

  // Valid G1 point from existing test data - 128 bytes with proper padding
  private static final String VALID_G1_POINT =
      "0000000000000000000000000000000012196c5a43d69224d8713389285f26b98f86ee910ab3dd668e413738282003cc5b7357af9a7af54bb713d62255e80f56"
          + "0000000000000000000000000000000006ba8102bfbeea4416b710c73e8cce3032c31c6269c44906f8ac4f7874ce99fb17559992486528963884ce429a992fee";

  // Invalid G1 point (not on curve)
  private static final String INVALID_G1_POINT_NOT_ON_CURVE =
      "00000000000000000000000000000000177b39d2b8d31753ee35033df55a1f891be9196aec9cd8f512e9069d21a8bdbf693bd2e826e792cd12cb554287adf4ca"
          + "0000000000000000000000000000000003c0f5770509862f754fc474cb163c41790d844f52939e2dec87b97c2a707831a4043ab47014d501f67862e95842ba5a";

  // G1 point that's on curve but not in subgroup
  private static final String G1_POINT_NOT_IN_SUBGROUP =
      "00000000000000000000000000000000054a4326bbddbdbbca126659e6686984046d2fa49270742e5b6d9017734acf2801f370eebe7af29dfc8d50483609dc00"
          + "000000000000000000000000000000001713e9ef64254fe96d874d16e33636f186e30d7e476db9f49a16698b771f10e0f8f08e5d8dba621b887c0d257cbd8eac";

  // Invalid padding (non-zero leading bytes)
  private static final String INVALID_G1_PADDING =
      "0100000000000000000000000000000012196c5a43d69224d8713389285f26b98f86ee910ab3dd668e413738282003cc5b7357af9a7af54bb713d62255e80f56"
          + "0000000000000000000000000000000006ba8102bfbeea4416b710c73e8cce3032c31c6269c44906f8ac4f7874ce99fb17559992486528963884ce429a992fee";

  // Invalid length input
  private static final String INVALID_LENGTH_INPUT = "0001020304";

  @Test
  public void testG1IsOnCurve_ValidPoint() {
    final byte[] input = Bytes.fromHexString(VALID_G1_POINT).toArrayUnsafe();

    boolean result = LibGnarkEIP2537.isG1OnCurve(input, input.length);

    assertThat(result).isTrue();
  }

  @Test
  public void testG1IsOnCurve_InvalidPoint() {
    final byte[] input = Bytes.fromHexString(INVALID_G1_POINT_NOT_ON_CURVE).toArrayUnsafe();

    int result = LibGnarkEIP2537.eip2537G1IsOnCurve(input, input.length);

    assertThat(result).isEqualTo(LibGnarkEIP2537.EIP2537_ERR_CODE_POINT_ON_CURVE_CHECK_FAILED);
  }

  @Test
  public void testG1IsOnCurve_InvalidPadding() {
    final byte[] input = Bytes.fromHexString(INVALID_G1_PADDING).toArrayUnsafe();

    int result = LibGnarkEIP2537.eip2537G1IsOnCurve(input, input.length);

    assertThat(result).isEqualTo(LibGnarkEIP2537.EIP2537_ERR_CODE_MALFORMED_POINT_PADDING);
  }

  @Test
  public void testG1IsOnCurve_InvalidLength() {
    final byte[] input = Bytes.fromHexString(INVALID_LENGTH_INPUT).toArrayUnsafe();

    int result = LibGnarkEIP2537.eip2537G1IsOnCurve(input, input.length);

    assertThat(result).isEqualTo(LibGnarkEIP2537.EIP2537_ERR_CODE_INVALID_INPUT_LENGTH);
  }

  @Test
  public void testG1IsInSubGroup_ValidPoint() {
    final byte[] input = Bytes.fromHexString(VALID_G1_POINT).toArrayUnsafe();

    boolean result = LibGnarkEIP2537.isG1InSubGroup(input, input.length);

    assertThat(result).isTrue();
  }

  @Test
  public void testG1IsInSubGroup_NotInSubGroup() {
    final byte[] input = Bytes.fromHexString(G1_POINT_NOT_IN_SUBGROUP).toArrayUnsafe();

    int result = LibGnarkEIP2537.eip2537G1IsInSubGroup(input, input.length);

    assertThat(result).isEqualTo(LibGnarkEIP2537.EIP2537_ERR_CODE_POINT_IN_SUBGROUP_CHECK_FAILED);
  }

  @Test
  public void testG1IsInSubGroup_NotOnCurve() {
    final byte[] input = Bytes.fromHexString(INVALID_G1_POINT_NOT_ON_CURVE).toArrayUnsafe();

    int result = LibGnarkEIP2537.eip2537G1IsInSubGroup(input, input.length);

    assertThat(result).isEqualTo(LibGnarkEIP2537.EIP2537_ERR_CODE_POINT_ON_CURVE_CHECK_FAILED);
  }

  @Test
  public void testG1IsOnCurve_ZeroPoint() {
    // Test the point at infinity (all zeros) which should be on curve
    final byte[] input = new byte[128]; // All zeros

    boolean result = LibGnarkEIP2537.isG1OnCurve(input, input.length);

    assertThat(result).isTrue();
  }
}
