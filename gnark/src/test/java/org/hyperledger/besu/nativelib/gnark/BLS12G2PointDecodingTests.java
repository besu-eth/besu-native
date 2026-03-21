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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import org.apache.tuweni.bytes.Bytes;
import org.junit.Ignore;
import org.junit.Test;

public class BLS12G2PointDecodingTests {

  // Valid G2 point - 256 bytes (512 hex chars)
  private static final String VALID_G2_POINT =
      "00000000000000000000000000000000124aca13d9ead2e5194eb097360743fc996551a5f339d644ded3571c5588a1fedf3f26ecdca73845241e47337e8ad990" +
      "000000000000000000000000000000000299bfd77515b688335e58acb31f7e0e6416840989cb08775287f90f7e6c921438b7b476cfa387742fcdc43bcecfe45f" +
      "00000000000000000000000000000000032e78350f525d673e75a3430048a7931d21264ac1b2c8dc58aee07e77790dfc9afb530b004145f0040c48bce128135e" +
      "0000000000000000000000000000000015963bcbd8fa50808bdce4f8de40eb9706c1a41ada22f0e469ecceb3e0b0fa3404ccdcc66a286b5a9e221c4a088a9145";

  // Invalid G2 point (not on curve)
  private static final String INVALID_G2_POINT_NOT_ON_CURVE =
    "000000000000000000000000000000000b2c619263417e8f6cffa2e53261cb8cf5fbbabb9e6f4188aeaabe50d434a0489b6cccd2b65b4d1393a26911021baffa" +
    "00000000000000000000000000000000007bcd4156af7ebe5e2f6ac63db859c9f42d5f11682792a0de2ec1db76648c0c98fdd8a82cf640bdcd309901afd4f570" +
    "00000000000000000000000000000000153a9002d117a518b2c1786f9e8b95b00e936f3f15302a27a16d7f2f8fc48ca834c0cf4fce456e96d72f01f252f4d084" +
    "000000000000000000000000000000001091fc53100190db07ec2057727859e65da996f6792ac5602cb9dfbc3ed4a5a67d6b82bd82112075ef8afc4155db2621";

  // G2 point that's on curve but not in subgroup
  private static final String G2_POINT_NOT_IN_SUBGROUP =
      "000000000000000000000000000000000380f5c0d9ae49e3904c5ae7ad83043158d68fa721b06b561e714b71a2c48c2307b5258892f999a882bed3549a286b7f" +
      "0000000000000000000000000000000004886f7f17a8e9918b4bfa8ebe450b0216ed5e1fa103dfc671332dc38b04ed3105526fb0dda7e032b6fb67debf9f0bc5" +
      "0000000000000000000000000000000018146b7ed1ecf2a4f2d1f75bb6e9ddbb9796bb03576686346995566cf3b3831ec5462e61028355504fc90f877408ac17" +
      "0000000000000000000000000000000003da9de8dcd94d7793b19e45a5521b1bc42f1a6d693139d03bb26402678ee6a635a4d50eaddfd326e446ed0330fa67fb";

  // Invalid padding (non-zero leading bytes)
  private static final String INVALID_G2_PADDING =
    "01000000000000000000000000000000124aca13d9ead2e5194eb097360743fc996551a5f339d644ded3571c5588a1fedf3f26ecdca73845241e47337e8ad990" +
    "000000000000000000000000000000000299bfd77515b688335e58acb31f7e0e6416840989cb08775287f90f7e6c921438b7b476cfa387742fcdc43bcecfe45f" +
    "00000000000000000000000000000000032e78350f525d673e75a3430048a7931d21264ac1b2c8dc58aee07e77790dfc9afb530b004145f0040c48bce128135e" +
    "0000000000000000000000000000000015963bcbd8fa50808bdce4f8de40eb9706c1a41ada22f0e469ecceb3e0b0fa3404ccdcc66a286b5a9e221c4a088a9145";

  // Invalid length input
  private static final String INVALID_LENGTH_INPUT = "0001020304";

  @Test
  public void testG2IsOnCurve_ValidPoint() {
    final byte[] input = Bytes.fromHexString(VALID_G2_POINT).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G2IsOnCurve(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isTrue();
  }

  @Test
  public void testG2IsOnCurve_InvalidPoint() {
    final byte[] input = Bytes.fromHexString(INVALID_G2_POINT_NOT_ON_CURVE).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G2IsOnCurve(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isFalse();
    String errorMsg = new String(error, 0, LibGnarkUtils.findFirstTrailingZeroIndex(error), UTF_8);
    assertThat(errorMsg).contains("invalid point: point is not on curve");
  }

  @Test
  public void testG2IsOnCurve_InvalidPadding() {
    final byte[] input = Bytes.fromHexString(INVALID_G2_PADDING).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];

    boolean result = LibGnarkEIP2537.eip2537G2IsOnCurve(
      input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);

    assertThat(result).isFalse();
    String errorMsg = new String(error, 0, LibGnarkUtils.findFirstTrailingZeroIndex(error), UTF_8);
    assertThat(errorMsg).contains("invalid point: point is not left padded with zero");
  }

  @Test
  public void testG2IsOnCurve_InvalidLength() {
    final byte[] input = Bytes.fromHexString(INVALID_LENGTH_INPUT).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];

    boolean result = LibGnarkEIP2537.eip2537G2IsOnCurve(
      input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);

    assertThat(result).isFalse();
    String errorMsg = new String(error, 0, LibGnarkUtils.findFirstTrailingZeroIndex(error), UTF_8);
    assertThat(errorMsg).contains("invalid input length for G2 point validation");
  }

  @Test
  public void testG2IsInSubGroup_ValidPoint() {
    final byte[] input = Bytes.fromHexString(VALID_G2_POINT).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G2IsInSubGroup(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isTrue();
  }

  @Test
  public void testG2IsInSubGroup_NotInSubGroup() {
    final byte[] input = Bytes.fromHexString(G2_POINT_NOT_IN_SUBGROUP).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G2IsInSubGroup(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isFalse();
    String errorMsg = new String(error, 0, LibGnarkUtils.findFirstTrailingZeroIndex(error), UTF_8);
    assertThat(errorMsg).contains("invalid point: subgroup check failed");
  }

  @Test
  public void testG2IsInSubGroup_NotOnCurve() {
    final byte[] input = Bytes.fromHexString(INVALID_G2_POINT_NOT_ON_CURVE).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G2IsInSubGroup(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isFalse();
    String errorMsg = new String(error, 0, LibGnarkUtils.findFirstTrailingZeroIndex(error), UTF_8);
    assertThat(errorMsg).contains("invalid point: point is not on curve");
  }

  @Test
  public void testG2IsOnCurve_ZeroPoint() {
    // Test the point at infinity (all zeros) which should be on curve
    final byte[] input = new byte[256]; // All zeros  
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G2IsOnCurve(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isTrue();
  }
}
