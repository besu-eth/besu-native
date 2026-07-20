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

import com.sun.jna.ptr.IntByReference;
import org.hyperledger.besu.nativelib.common.BesuNativeLibraryLoader;

public class LibGnarkEIP196 {

  public static final int EIP196_PREALLOCATE_FOR_RESULT_BYTES = 64;
  public static final int EIP196_PAIR_PREALLOCATE_FOR_RESULT_BYTES = 32;
  @SuppressWarnings("WeakerAccess")
  public static final byte EIP196_ADD_OPERATION_RAW_VALUE = 1;
  public static final byte EIP196_MUL_OPERATION_RAW_VALUE = 2;
  public static final byte EIP196_PAIR_OPERATION_RAW_VALUE = 3;

  public static final boolean ENABLED;

  // Keep in sync with the Go code. We use constant values to avoid passing strings from Java to Go
  // errCodeSuccess errorCode = iota
  // errCodeInvalidInputPairingLengthEIP196
  // errCodePointNotInFieldEIP196
  // errCodePointInSubgroupCheckFailedEIP196
  // errCodePointOnCurveCheckFailedEIP196
  // errCodePairingCheckErrorEIP196
  public static final int EIP196_ERR_CODE_SUCCESS = 0;
  public static final int EIP196_ERR_CODE_INVALID_INPUT_PAIRING_LENGTH = 1;
  public static final int EIP196_ERR_CODE_POINT_NOT_IN_FIELD = 2;
  public static final int EIP196_ERR_CODE_POINT_IN_SUBGROUP_CHECK_FAILED = 3;
  public static final int EIP196_ERR_CODE_POINT_ON_CURVE_CHECK_FAILED = 4;
  public static final int EIP196_ERR_CODE_PAIRING_CHECK_ERROR = 5;
  // only on java side
  public static final int EIP196_ERR_CODE_INVALID_OUTPUT_LENGTH = 6;

  static {
    boolean enabled;
    try {
      BesuNativeLibraryLoader.registerJNA(LibGnarkEIP196.class, "gnark_eip_196");
      enabled = true;
    } catch (final Throwable t) {
      t.printStackTrace();
      enabled = false;
    }
    ENABLED = enabled;
  }

  /**
   * SAFETY: This method validates output buffer size before calling native code to prevent JVM crashes from buffer overflows.
   * The native methods use JNA direct mapping without bounds checking.
   *
   * @param op Operation type (ADD=1, MUL=2, PAIR=3)
   * @param i Input data
   * @param i_len Length of valid input data
   * @param output Output buffer - MUST be at least EIP196_PREALLOCATE_FOR_RESULT_BYTES (64 bytes)
   * @return Error code: 0=success, 6=invalid output length, other codes from native operations
   */
  public static int eip196_perform_operation(
      byte op,
      byte[] i,
      int i_len,
      byte[] output) {

    int ret = -1;
    switch(op) {
      case EIP196_ADD_OPERATION_RAW_VALUE:
        if (output.length < EIP196_PREALLOCATE_FOR_RESULT_BYTES) {
          return EIP196_ERR_CODE_INVALID_OUTPUT_LENGTH;
        }
        ret = eip196altbn128G1Add(i, output, i_len);
        break;
      case  EIP196_MUL_OPERATION_RAW_VALUE:
        if (output.length < EIP196_PREALLOCATE_FOR_RESULT_BYTES) {
          return EIP196_ERR_CODE_INVALID_OUTPUT_LENGTH;
        }
        ret = eip196altbn128G1Mul(i, output, i_len);
        break;
      case EIP196_PAIR_OPERATION_RAW_VALUE:
        if (output.length < EIP196_PAIR_PREALLOCATE_FOR_RESULT_BYTES) {
          return EIP196_ERR_CODE_INVALID_OUTPUT_LENGTH;
        }
        ret = eip196altbn128Pairing(i, output, i_len);
        break;
      default:
        throw new RuntimeException("Not Implemented EIP-196 operation " + op);
    }

    return ret;
  }

  /**
   * Assumes output length bounds are already checked, otherwise can lead to JVM crash
   */
  private static native int eip196altbn128G1Add(
      byte[] input,
      byte[] output,
      int inputSize);

  /**
   * Assumes output length bounds are already checked, otherwise can lead to JVM crash
   */
  private static native int eip196altbn128G1Mul(
      byte[] input,
      byte[] output,
      int inputSize);

  /**
   * Assumes output length bounds are already checked, otherwise can lead to JVM crash
   */
  private static native int eip196altbn128Pairing(
      byte[] input,
      byte[] output,
      int inputSize);
}