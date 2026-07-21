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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for verifying specific error codes returned by EIP-196 operations.
 */
public class LibGnarkEIP196ErrorCodeTest {

  @Test
  public void testErrorCodeSuccess() {
    Bytes g1Point1 = Bytes.concatenate(
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000002"));
    Bytes g1Point2 = Bytes.concatenate(
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000002"));

    byte[] input = Bytes.concatenate(g1Point1, g1Point2).toArrayUnsafe();
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_ADD_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS);
  }

  @Test
  public void testErrorCodePointNotInField() {
    // Point with X coordinate >= field modulus
    // bn254 field modulus is 21888242871839275222246405745257275088696311157297823662689037894645226208583
    // which is 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
    // So 0xff00...00 is definitely out of field
    byte[] input = Bytes.concatenate(
        Bytes.fromHexString("0xff00000000000000000000000000000000000000000000000000000000000000"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000000")
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
  public void testErrorCodePointNotInFieldYCoordinate() {
    // Valid X coordinate but Y coordinate out of field
    byte[] input = Bytes.concatenate(
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001"),
        Bytes.fromHexString("0xff00000000000000000000000000000000000000000000000000000000000000")
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
  public void testErrorCodePointOnCurveCheckFailed() {
    // Valid field elements but not satisfying curve equation y^2 = x^3 + 3
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
  public void testErrorCodePointOnCurveCheckFailedForMul() {
    // Invalid point for multiplication
    byte[] input = Bytes.concatenate(
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000000"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000009")
    ).toArrayUnsafe();
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_MUL_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_POINT_ON_CURVE_CHECK_FAILED);
  }

  @Test
  public void testErrorCodeInvalidInputPairingLength() {
    // Input length not a multiple of 192 (size of G1 + G2 pair)
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
  public void testErrorCodeInvalidInputPairingLength191() {
    // Just one byte short of a valid pair
    byte[] input = new byte[191];
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_PAIR_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_INVALID_INPUT_PAIRING_LENGTH);
  }

  @Test
  public void testErrorCodePointInSubgroupCheckFailed() {
    // G2 point that is on the curve but not in the correct subgroup
    // This is a known test vector
    Bytes g1Point = Bytes.concatenate(
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000002"));

    // G2 point on curve but not in subgroup
    Bytes g2PointNotInSubgroup = Bytes.concatenate(
        Bytes.fromHexString("0x1382cd45e5674247f9c900b5c6f6cabbc189c2fabe2df0bf5acd84c97818f508"),
        Bytes.fromHexString("0x1246178655ab8f2f26956b189894b7eb93cd4215b9937e7969e44305f80f521e"),
        Bytes.fromHexString("0x08331c0a261a74e7e75db1232956663cbc88110f726159c5cba1857ecd03fa64"),
        Bytes.fromHexString("0x1fbf8045ce3e79b5cde4112d38bcd0efbdb1295d2eefdf58151ae309d7ded7db"));

    byte[] input = Bytes.concatenate(g1Point, g2PointNotInSubgroup).toArrayUnsafe();
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_PAIR_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_POINT_IN_SUBGROUP_CHECK_FAILED);
  }

  @Test
  public void testErrorCodePointOnCurveCheckFailedForG2() {
    // Invalid G2 point in pairing
    Bytes g1Point = Bytes.concatenate(
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000002"));

    // G2 point not on curve (using invalid coordinates)
    Bytes invalidG2Point = Bytes.concatenate(
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000002"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000003"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000004"));

    byte[] input = Bytes.concatenate(g1Point, invalidG2Point).toArrayUnsafe();
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_PAIR_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_POINT_ON_CURVE_CHECK_FAILED);
  }

  @Test
  public void testErrorCodeForInvalidG1InPairing() {
    // Invalid G1 point in pairing (64 bytes but not on curve)
    Bytes invalidG1Point = Bytes.concatenate(
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000001234"),
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000005678"));

    Bytes validG2Point = Bytes.concatenate(
        Bytes.fromHexString("0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"),
        Bytes.fromHexString("0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"),
        Bytes.fromHexString("0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"),
        Bytes.fromHexString("0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"));

    byte[] input = Bytes.concatenate(invalidG1Point, validG2Point).toArrayUnsafe();
    byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(
        LibGnarkEIP196.EIP196_PAIR_OPERATION_RAW_VALUE,
        input,
        input.length,
        output);

    assertThat(errorCode).isEqualTo(LibGnarkEIP196.EIP196_ERR_CODE_POINT_ON_CURVE_CHECK_FAILED);
  }

  @Test
  public void testAllErrorCodesAreDifferent() {
    // Sanity check: ensure all error codes have unique values
    int[] errorCodes = {
        LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS,
        LibGnarkEIP196.EIP196_ERR_CODE_INVALID_INPUT_PAIRING_LENGTH,
        LibGnarkEIP196.EIP196_ERR_CODE_POINT_NOT_IN_FIELD,
        LibGnarkEIP196.EIP196_ERR_CODE_POINT_IN_SUBGROUP_CHECK_FAILED,
        LibGnarkEIP196.EIP196_ERR_CODE_POINT_ON_CURVE_CHECK_FAILED,
        LibGnarkEIP196.EIP196_ERR_CODE_PAIRING_CHECK_ERROR
    };

    // Check all values are unique
    for (int i = 0; i < errorCodes.length; i++) {
      for (int j = i + 1; j < errorCodes.length; j++) {
        assertThat(errorCodes[i]).isNotEqualTo(errorCodes[j]);
      }
    }

    // Check values are in expected range
    assertThat(LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS).isEqualTo(0);
    assertThat(LibGnarkEIP196.EIP196_ERR_CODE_INVALID_INPUT_PAIRING_LENGTH).isEqualTo(1);
    assertThat(LibGnarkEIP196.EIP196_ERR_CODE_POINT_NOT_IN_FIELD).isEqualTo(2);
    assertThat(LibGnarkEIP196.EIP196_ERR_CODE_POINT_IN_SUBGROUP_CHECK_FAILED).isEqualTo(3);
    assertThat(LibGnarkEIP196.EIP196_ERR_CODE_POINT_ON_CURVE_CHECK_FAILED).isEqualTo(4);
    assertThat(LibGnarkEIP196.EIP196_ERR_CODE_PAIRING_CHECK_ERROR).isEqualTo(5);
  }
}
