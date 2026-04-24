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

import com.sun.jna.Library;
import org.hyperledger.besu.nativelib.common.BesuNativeLibraryLoader;

public class LibGnarkEIP2537 implements Library {

  @SuppressWarnings("WeakerAccess")
  public static final boolean ENABLED;

  // zero implies 'default' degree of parallelism, which is the number of cpu cores available
  private static int degreeOfMSMParallelism = 0;

  static {
    boolean enabled;
    try {
      BesuNativeLibraryLoader.registerJNA(LibGnarkEIP2537.class, "gnark_eip_2537");
      enabled = true;
    } catch (final Throwable t) {
      t.printStackTrace();
      enabled = false;
    }
    ENABLED = enabled;
  }

  // Keep in sync with the Go code. We use constant values to avoid passing strings from Java to Go
  // errCodeSuccess                           errorCode = 0
  // errCodeInvalidInputLengthEIP2537         errorCode = 1
  // errCodePointNotInFieldEIP2537            errorCode = 2
  // errCodePointInSubgroupCheckFailedEIP2537 errorCode = 3
  // errCodePointOnCurveCheckFailedEIP2537    errorCode = 4
  // errCodePairingCheckErrorEIP2537          errorCode = 5
  // errCodeMalformedPointPaddingEIP2537      errorCode = 6
  public static final int EIP2537_ERR_CODE_SUCCESS = 0;
  public static final int EIP2537_ERR_CODE_INVALID_INPUT_LENGTH = 1;
  public static final int EIP2537_ERR_CODE_POINT_NOT_IN_FIELD = 2;
  public static final int EIP2537_ERR_CODE_POINT_IN_SUBGROUP_CHECK_FAILED = 3;
  public static final int EIP2537_ERR_CODE_POINT_ON_CURVE_CHECK_FAILED = 4;
  public static final int EIP2537_ERR_CODE_PAIRING_CHECK_ERROR = 5;
  public static final int EIP2537_ERR_CODE_MALFORMED_POINT_PADDING = 6;
  // only on Java side
  public static final int EIP2537_ERR_CODE_INVALID_OUTPUT_LENGTH = 7;

  public static final int EIP2537_PREALLOCATE_FOR_G1 = 128;
  public static final int EIP2537_PREALLOCATE_FOR_G2 = 256;
  public static final int EIP2537_PAIR_PREALLOCATE_FOR_RESULT_BYTES = 32;

  public static final byte BLS12_G1ADD_OPERATION_SHIM_VALUE = 1;
  public static final byte BLS12_G1MULTIEXP_OPERATION_SHIM_VALUE = 2;
  public static final byte BLS12_G2ADD_OPERATION_SHIM_VALUE = 3;
  public static final byte BLS12_G2MULTIEXP_OPERATION_SHIM_VALUE = 4;
  public static final byte BLS12_PAIR_OPERATION_SHIM_VALUE = 5;
  public static final byte BLS12_MAP_FP_TO_G1_OPERATION_SHIM_VALUE = 6;
  public static final byte BLS12_MAP_FP2_TO_G2_OPERATION_SHIM_VALUE = 7;

  /**
   * Here as a compatibility shim for the pre-existing matter-labs implementation.
   *
   * <p>SAFETY: This method validates output buffer size before calling native code to prevent JVM
   * crashes from buffer overflows.
   *
   * <p>IMPORTANT: The output buffer MUST be zero-initialized before calling this method. The native
   * implementation relies on this pre-initialization for proper functioning.
   */
  public static int eip2537_perform_operation(byte op, byte[] i, int i_len, byte[] output) {
    switch (op) {
      case BLS12_G1ADD_OPERATION_SHIM_VALUE:
        if (output.length < EIP2537_PREALLOCATE_FOR_G1) {
          return EIP2537_ERR_CODE_INVALID_OUTPUT_LENGTH;
        }
        return eip2537blsG1Add(i, output, i_len);
      case BLS12_G1MULTIEXP_OPERATION_SHIM_VALUE:
        if (output.length < EIP2537_PREALLOCATE_FOR_G1) {
          return EIP2537_ERR_CODE_INVALID_OUTPUT_LENGTH;
        }
        return eip2537blsG1MultiExp(i, output, i_len, degreeOfMSMParallelism);
      case BLS12_G2ADD_OPERATION_SHIM_VALUE:
        if (output.length < EIP2537_PREALLOCATE_FOR_G2) {
          return EIP2537_ERR_CODE_INVALID_OUTPUT_LENGTH;
        }
        return eip2537blsG2Add(i, output, i_len);
      case BLS12_G2MULTIEXP_OPERATION_SHIM_VALUE:
        if (output.length < EIP2537_PREALLOCATE_FOR_G2) {
          return EIP2537_ERR_CODE_INVALID_OUTPUT_LENGTH;
        }
        return eip2537blsG2MultiExp(i, output, i_len, degreeOfMSMParallelism);
      case BLS12_PAIR_OPERATION_SHIM_VALUE:
        if (output.length < EIP2537_PAIR_PREALLOCATE_FOR_RESULT_BYTES) {
          return EIP2537_ERR_CODE_INVALID_OUTPUT_LENGTH;
        }
        return eip2537blsPairing(i, output, i_len);
      case BLS12_MAP_FP_TO_G1_OPERATION_SHIM_VALUE:
        if (output.length < EIP2537_PREALLOCATE_FOR_G1) {
          return EIP2537_ERR_CODE_INVALID_OUTPUT_LENGTH;
        }
        return eip2537blsMapFpToG1(i, output, i_len);
      case BLS12_MAP_FP2_TO_G2_OPERATION_SHIM_VALUE:
        if (output.length < EIP2537_PREALLOCATE_FOR_G2) {
          return EIP2537_ERR_CODE_INVALID_OUTPUT_LENGTH;
        }
        return eip2537blsMapFp2ToG2(i, output, i_len);
      default:
        throw new RuntimeException("Not Implemented EIP-2537 operation " + op);
    }
  }

  /**
   * Returns true if the G1 point is on the curve, false otherwise.
   * Delegates to the native method and maps the error code to a boolean.
   */
  public static boolean isG1OnCurve(byte[] input, int inputSize) {
    return eip2537G1IsOnCurve(input, inputSize) == EIP2537_ERR_CODE_SUCCESS;
  }

  /**
   * Returns true if the G1 point is on the curve and in the correct subgroup, false otherwise.
   * Delegates to the native method and maps the error code to a boolean.
   */
  public static boolean isG1InSubGroup(byte[] input, int inputSize) {
    return eip2537G1IsInSubGroup(input, inputSize) == EIP2537_ERR_CODE_SUCCESS;
  }

  /**
   * Returns true if the G2 point is on the curve, false otherwise.
   * Delegates to the native method and maps the error code to a boolean.
   */
  public static boolean isG2OnCurve(byte[] input, int inputSize) {
    return eip2537G2IsOnCurve(input, inputSize) == EIP2537_ERR_CODE_SUCCESS;
  }

  /**
   * Returns true if the G2 point is on the curve and in the correct subgroup, false otherwise.
   * Delegates to the native method and maps the error code to a boolean.
   */
  public static boolean isG2InSubGroup(byte[] input, int inputSize) {
    return eip2537G2IsInSubGroup(input, inputSize) == EIP2537_ERR_CODE_SUCCESS;
  }

  /** Assumes output length bounds are already checked, otherwise can lead to JVM crash */
  private static native int eip2537blsG1Add(byte[] input, byte[] output, int inputSize);

  /** Assumes output length bounds are already checked, otherwise can lead to JVM crash */
  private static native int eip2537blsG1MultiExp(
      byte[] input, byte[] output, int inputSize, int nbTasks);

  /** Assumes output length bounds are already checked, otherwise can lead to JVM crash */
  private static native int eip2537blsG2Add(byte[] input, byte[] output, int inputSize);

  /** Assumes output length bounds are already checked, otherwise can lead to JVM crash */
  private static native int eip2537blsG2MultiExp(
      byte[] input, byte[] output, int inputSize, int nbTasks);

  /** Assumes output length bounds are already checked, otherwise can lead to JVM crash */
  private static native int eip2537blsPairing(byte[] input, byte[] output, int inputSize);

  /** Assumes output length bounds are already checked, otherwise can lead to JVM crash */
  private static native int eip2537blsMapFpToG1(byte[] input, byte[] output, int inputSize);

  /** Assumes output length bounds are already checked, otherwise can lead to JVM crash */
  private static native int eip2537blsMapFp2ToG2(byte[] input, byte[] output, int inputSize);

  public static native int eip2537G1IsOnCurve(byte[] input, int inputSize);

  public static native int eip2537G2IsOnCurve(byte[] input, int inputSize);

  public static native int eip2537G1IsInSubGroup(byte[] input, int inputSize);

  public static native int eip2537G2IsInSubGroup(byte[] input, int inputSize);

  public static void setDegreeOfMSMParallelism(int nbTasks) {
    degreeOfMSMParallelism = nbTasks;
  }
}
