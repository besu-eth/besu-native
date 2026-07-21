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

import org.apache.tuweni.bytes.Bytes;
import org.junit.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

public class LibGnarkEIP196EdgeCaseTest {

  private static final byte GARBAGE_BYTE = (byte) 0xFF;

  @Test
  public void testG1AddEmptyInput() {
    byte[] input = new byte[0];
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_ADD_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS);
    // Empty input should return zero point
    assertThat(output).isEqualTo(new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES]);
  }

  @Test
  public void testG1AddPartialFirstPoint() {
    // Only 32 bytes (half a point)
    byte[] input = new byte[32];
    Arrays.fill(input, (byte) 0);
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_ADD_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    // Should pad with zeros and succeed (zero point is valid)
    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS);
  }

  @Test
  public void testG1AddPartialSecondPoint() {
    // Valid first point, partial second point
    Bytes firstPoint = Bytes.concatenate(
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000002"));

    // Only 96 bytes total (full first point + half second point)
    byte[] input = new byte[96];
    firstPoint.toArrayUnsafe();
    System.arraycopy(firstPoint.toArrayUnsafe(), 0, input, 0, 64);

    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_ADD_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    // Should pad second point with zeros and return first point
    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS);
    assertThat(Bytes.wrap(output, 0, 64)).isEqualTo(firstPoint);
  }

  @Test
  public void testG1AddTruncatedInput() {
    // Valid first point + partial second point (only X coordinate)
    Bytes firstPoint = Bytes.concatenate(
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000002"));
    Bytes secondPointX = Bytes.fromHexString(
        "0x0000000000000000000000000000000000000000000000000000000000000001");

    byte[] input = Bytes.concatenate(firstPoint, secondPointX).toArrayUnsafe();
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_ADD_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    // Should pad Y coordinate with zeros - results in invalid point
    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_POINT_ON_CURVE_CHECK_FAILED);
  }

  @Test
  public void testG1MulEmptyInput() {
    byte[] input = new byte[0];
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_MUL_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS);
    // Empty input should return zero
    assertThat(output).isEqualTo(new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES]);
  }

  @Test
  public void testG1MulPointOnlyNoScalar() {
    // Valid point but no scalar
    byte[] input = Bytes.concatenate(
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000002")
    ).toArrayUnsafe();

    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_MUL_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    // No scalar means multiply by 0, should return zero point
    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS);
    assertThat(output).isEqualTo(new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES]);
  }

  @Test
  public void testG1MulPartialScalar() {
    // Valid point + partial scalar (only 16 bytes instead of 32)
    Bytes point = Bytes.concatenate(
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000002"));
    Bytes partialScalar = Bytes.fromHexString("0x00000000000000000000000000000009");

    byte[] input = Bytes.concatenate(point, partialScalar).toArrayUnsafe();
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_MUL_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    // Should pad scalar with zeros and succeed
    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS);
  }

  @Test
  public void testG1MulInfinityPoint() {
    // Zero point (point at infinity) with non-zero scalar
    byte[] input = new byte[96];
    Arrays.fill(input, (byte) 0);
    input[95] = 0x09; // scalar = 9

    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_MUL_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    // Multiplying infinity by any scalar should return infinity (zero)
    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS);
    assertThat(output).isEqualTo(new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES]);
  }

  @Test
  public void testG1MulByTwo() {
    // Test special case optimization for scalar = 2
    Bytes point = Bytes.concatenate(
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000002"));
    Bytes scalarTwo = Bytes.fromHexString(
        "0x0000000000000000000000000000000000000000000000000000000000000002");

    byte[] input = Bytes.concatenate(point, scalarTwo).toArrayUnsafe();
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_MUL_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS);
    // Result should be non-zero (doubled point)
    assertThat(output).isNotEqualTo(new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES]);
  }

  @Test
  public void testPairingEmptyInput() {
    byte[] input = new byte[0];
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_PAIR_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS);
    // Empty input should return 1 (pairing succeeded)
    assertThat(output[31]).isEqualTo((byte) 0x01);
  }

  @Test
  public void testPairingInvalidLength() {
    // Not a multiple of 192
    byte[] input = new byte[100];
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_PAIR_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_INVALID_INPUT_PAIRING_LENGTH);
  }

  @Test
  public void testPairingMultiplePairs() {
    // Two pairs
    Bytes g1Point = Bytes.concatenate(
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000002"));

    Bytes g2Point = Bytes.concatenate(
        Bytes.fromHexString("0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"),
        Bytes.fromHexString("0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"),
        Bytes.fromHexString("0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"),
        Bytes.fromHexString("0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"));

    byte[] input = Bytes.concatenate(g1Point, g2Point, g1Point, g2Point).toArrayUnsafe();
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_PAIR_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS);
  }

  @Test
  public void testOutputBufferInitializationPairingWritesResult() {
    // Test that output buffer is properly written by Go code (not just relying on Java initialization)
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];
    Arrays.fill(output, GARBAGE_BYTE); // Fill with garbage to ensure Go writes the result

    // Valid pairing from test data
    Bytes g1Point = Bytes.concatenate(
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000002"));

    Bytes g2Point = Bytes.concatenate(
        Bytes.fromHexString("0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"),
        Bytes.fromHexString("0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"),
        Bytes.fromHexString("0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"),
        Bytes.fromHexString("0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"));

    Bytes g1Point2 = Bytes.concatenate(
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001"),
        Bytes.fromHexString("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"));

    byte[] input = Bytes.concatenate(g1Point, g2Point, g1Point2, g2Point).toArrayUnsafe();

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_PAIR_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS);
    // The key test: byte 31 should have been written by Go code (either 0x00 or 0x01, not 0xFF)
    assertThat(output[31]).isNotEqualTo(GARBAGE_BYTE);
    assertThat(output[31]).isIn((byte) 0x00, (byte) 0x01);
    // All other bytes should remain 0xFF
    for (int i = 0; i < 31; i++) {
      assertThat(output[i]).isEqualTo(GARBAGE_BYTE);
    }
    for (int i = 32; i < LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES; i++) {
      assertThat(output[i]).isEqualTo(GARBAGE_BYTE);
    }
  }

  @Test
  public void testPairingEmptyInputWritesOne() {
    // Initialized with zeros
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_PAIR_OPERATION_RAW_VALUE,
        new byte[0],
        0,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS);
    // Empty input should write 0x01 to byte 31
    assertThat(output[31]).isEqualTo((byte) 0x01);
    // All other bytes should remain 0
    for (int i = 0; i < 31; i++) {
      assertThat(output[i]).isEqualTo((byte) 0x00);
    }
    for (int i = 32; i < LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES; i++) {
      assertThat(output[i]).isEqualTo((byte) 0x00);
    }
  }

  @Test
  public void testPointNotInField() {
    // Point with coordinates >= field modulus
    byte[] input = Bytes.fromHexString(
        "0xff00000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000000000000000000000000000000000000000000000000000000"
    ).toArrayUnsafe();
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_ADD_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_POINT_NOT_IN_FIELD);
  }

  @Test
  public void testPointNotOnCurve() {
    // Valid field elements but not on curve
    byte[] input = Bytes.fromHexString("0x1234").toArrayUnsafe();
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_ADD_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_POINT_ON_CURVE_CHECK_FAILED);
  }

  @Test
  public void testOutputBufferExactSize() {
    byte[] input = Bytes.EMPTY.toArrayUnsafe();
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_ADD_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS);
  }

  @Test
  public void testOutputBufferOversizedIsAllowed() {
    final int oversizedOutputLength = 128;
    byte[] input = Bytes.fromHexString(
        "0x1b43c36e6eb9566ae50c78f79802a80a963cf4317079c9e201361b1afbd64d2b" +
            "2796ffa55aaf5946e40b8038cda20238c53f328d5e4150287564eb08ce1efa59" +
            "0d4d3c9a95606d838edb0b494a64d5ad5933335cd7acf5ee9409492135b44fed" +
            "2d02a128bfb4cb61db495d5389feba0c4943e8c8c936acf7231fc8edefb619b5"
    ).toArrayUnsafe();

    byte[] output = new byte[oversizedOutputLength]; // Oversized - should work fine
    Arrays.fill(output, GARBAGE_BYTE); // Fill with garbage

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_ADD_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS);
    Bytes expectedResult = Bytes.fromHexString(
        "0x29a99e2465491ddb57b131ea6d0469f4faaa4202bf870b3e82365b9c3a59cf82" +
            "27d26a8780d9d0c30452f13d9673e2d9cae926a2158b62f8cf4804adaa112e98");
    assertThat(Bytes.wrap(output, 0, 64)).isEqualTo(expectedResult);
    // Bytes 64+ remain untouched
    for (int i = 64; i < oversizedOutputLength; i++) {
      assertThat(output[i]).isEqualTo(GARBAGE_BYTE);
    }
  }

  @Test
  public void testAddOutputBufferUndersizedReturnsError() {
    int undersizedOutputLength = LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES - 1;
    byte[] input = Bytes.EMPTY.toArrayUnsafe();
    byte[] output = new byte[undersizedOutputLength];

    final int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_ADD_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);
    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_INVALID_OUTPUT_LENGTH);

    // Output should remain all zeros
    for (final byte b : output) {
      assertThat(b).isEqualTo((byte) 0x00);
    }
  }

  @Test
  public void testMulOutputBufferUndersizedReturnsError() {
    int undersizedOutputLength = LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES - 1;
    byte[] input = Bytes.EMPTY.toArrayUnsafe();
    byte[] output = new byte[undersizedOutputLength];

    final int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_MUL_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);
    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_INVALID_OUTPUT_LENGTH);

    // Output should remain all zeros
    for (final byte b : output) {
      assertThat(b).isEqualTo((byte) 0x00);
    }
  }

  @Test
  public void testPairingOutputBufferUndersizedReturnsError() {
    int undersizedOutputLength = LibGnarkEIP196.EIP196_PAIR_PREALLOCATE_FOR_RESULT_BYTES - 1;
    byte[] input = Bytes.EMPTY.toArrayUnsafe();
    byte[] output = new byte[undersizedOutputLength];

    final int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_PAIR_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);
    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_INVALID_OUTPUT_LENGTH);

    // Output should remain all zeros
    for (final byte b : output) {
      assertThat(b).isEqualTo((byte) 0x00);
    }
  }
}
