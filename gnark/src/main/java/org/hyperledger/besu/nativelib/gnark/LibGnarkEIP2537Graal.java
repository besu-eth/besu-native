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

import org.graalvm.nativeimage.PinnedObject;
import org.graalvm.nativeimage.c.CContext;
import org.graalvm.nativeimage.c.function.CFunction;
import org.graalvm.nativeimage.c.type.CCharPointer;

import java.util.Collections;
import java.util.List;

/**
 * GraalVM native-image compatible interface to gnark EIP-2537 static library.
 * Provides operations for BLS12-381 elliptic curve operations including G1/G2 addition,
 * multi-scalar multiplication, pairing checks, and curve/subgroup validation.
 */
public class LibGnarkEIP2537Graal {

    /** Recommended buffer size for operation results. */
    public static final int EIP2537_PREALLOCATE_FOR_RESULT_BYTES = 256;

    /** Recommended buffer size for error messages. */
    public static final int EIP2537_PREALLOCATE_FOR_ERROR_BYTES = 256;

    /** Operation code for BLS12-381 G1 point addition. */
    public static final byte BLS12_G1ADD_OPERATION_SHIM_VALUE = 1;

    /** Operation code for BLS12-381 G1 multi-scalar multiplication. */
    public static final byte BLS12_G1MULTIEXP_OPERATION_SHIM_VALUE = 2;

    /** Operation code for BLS12-381 G2 point addition. */
    public static final byte BLS12_G2ADD_OPERATION_SHIM_VALUE = 3;

    /** Operation code for BLS12-381 G2 multi-scalar multiplication. */
    public static final byte BLS12_G2MULTIEXP_OPERATION_SHIM_VALUE = 4;

    /** Operation code for BLS12-381 pairing check. */
    public static final byte BLS12_PAIR_OPERATION_SHIM_VALUE = 5;

    /** Operation code for mapping field element to G1. */
    public static final byte BLS12_MAP_FP_TO_G1_OPERATION_SHIM_VALUE = 6;

    /** Operation code for mapping field element to G2. */
    public static final byte BLS12_MAP_FP2_TO_G2_OPERATION_SHIM_VALUE = 7;

    /** Degree of parallelism for multi-scalar multiplication (0 = auto-detect CPU cores). */
    private static int degreeOfMSMParallelism = 0;

    /** Private constructor to prevent instantiation of utility class. */
    private LibGnarkEIP2537Graal() {}

    @CContext(LibGnarkEIP2537Graal.Directives.class)
    public static class Directives implements CContext.Directives {
        @Override
        public List<String> getHeaderFiles() {
            return Collections.singletonList("<libgnark_eip_2537.h>");
        }

        @Override
        public List<String> getLibraries() {
            return Collections.singletonList("gnark_eip_2537");
        }

        @Override
        public List<String> getLibraryPaths() {
            // Library paths should be configured via native-image build arguments
            return Collections.emptyList();
        }
    }

    @CFunction(value = "eip2537blsG1Add")
    public static native int eip2537blsG1AddNative(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            int outputLength,
            int errorLength);

    @CFunction(value = "eip2537blsG1MultiExp")
    public static native int eip2537blsG1MultiExpNative(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            int outputLength,
            int errorLength,
            int nbTasks);

    @CFunction(value = "eip2537blsG2Add")
    public static native int eip2537blsG2AddNative(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            int outputLength,
            int errorLength);

    @CFunction(value = "eip2537blsG2MultiExp")
    public static native int eip2537blsG2MultiExpNative(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            int outputLength,
            int errorLength,
            int nbTasks);

    @CFunction(value = "eip2537blsPairing")
    public static native int eip2537blsPairingNative(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            int outputLength,
            int errorLength);

    @CFunction(value = "eip2537blsMapFpToG1")
    public static native int eip2537blsMapFpToG1Native(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            int outputLength,
            int errorLength);

    @CFunction(value = "eip2537blsMapFp2ToG2")
    public static native int eip2537blsMapFp2ToG2Native(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            int outputLength,
            int errorLength);

    @CFunction(value = "eip2537G1IsOnCurve")
    public static native boolean eip2537G1IsOnCurveNative(
            CCharPointer input,
            CCharPointer error,
            int inputSize,
            int errorLength);

    @CFunction(value = "eip2537G2IsOnCurve")
    public static native boolean eip2537G2IsOnCurveNative(
            CCharPointer input,
            CCharPointer error,
            int inputSize,
            int errorLength);

    @CFunction(value = "eip2537G1IsInSubGroup")
    public static native boolean eip2537G1IsInSubGroupNative(
            CCharPointer input,
            CCharPointer error,
            int inputSize,
            int errorLength);

    @CFunction(value = "eip2537G2IsInSubGroup")
    public static native boolean eip2537G2IsInSubGroupNative(
            CCharPointer input,
            CCharPointer error,
            int inputSize,
            int errorLength);

    /**
     * Here as a compatibility shim for the pre-existing matter-labs implementation.
     *
     * IMPORTANT: The output buffer MUST be zero-initialized before calling this method.
     * The native implementation relies on this pre-initialization for proper functioning.
     */
    public static int eip2537_perform_operation(
            byte op,
            byte[] input,
            int inputLength,
            byte[] output,
            int[] outputLength,
            byte[] error,
            int[] errorLength) {

        int ret = -1;
        switch(op) {
            case BLS12_G1ADD_OPERATION_SHIM_VALUE:
                ret = eip2537blsG1Add(input, output, error, inputLength,
                    EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
                    EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
                outputLength[0] = 128;
                break;
            case BLS12_G1MULTIEXP_OPERATION_SHIM_VALUE:
                ret = eip2537blsG1MultiExp(input, output, error, inputLength,
                    EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
                    EIP2537_PREALLOCATE_FOR_ERROR_BYTES,
                    degreeOfMSMParallelism);
                outputLength[0] = 128;
                break;
            case BLS12_G2ADD_OPERATION_SHIM_VALUE:
                ret = eip2537blsG2Add(input, output, error, inputLength,
                    EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
                    EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
                outputLength[0] = 256;
                break;
            case BLS12_G2MULTIEXP_OPERATION_SHIM_VALUE:
                ret = eip2537blsG2MultiExp(input, output, error, inputLength,
                    EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
                    EIP2537_PREALLOCATE_FOR_ERROR_BYTES,
                    degreeOfMSMParallelism);
                outputLength[0] = 256;
                break;
            case BLS12_PAIR_OPERATION_SHIM_VALUE:
                ret = eip2537blsPairing(input, output, error, inputLength,
                    EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
                    EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
                outputLength[0] = 32;
                break;
            case BLS12_MAP_FP_TO_G1_OPERATION_SHIM_VALUE:
                ret = eip2537blsMapFpToG1(input, output, error, inputLength,
                    EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
                    EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
                outputLength[0] = 128;
                break;
            case BLS12_MAP_FP2_TO_G2_OPERATION_SHIM_VALUE:
                ret = eip2537blsMapFp2ToG2(input, output, error, inputLength,
                    EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
                    EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
                outputLength[0] = 256;
                break;
            default:
                throw new RuntimeException("Not Implemented EIP-2537 operation " + op);
        }

        if (ret != 0) {
            errorLength[0] = LibGnarkUtils.findFirstTrailingZeroIndex(error);
            outputLength[0] = 0;
        } else {
            errorLength[0] = 0;
        }
        return ret;
    }

    /**
     * Java-friendly wrapper for BLS12-381 G1 point addition.
     *
     * @param input input data containing two G1 points to add
     * @param output output buffer for result
     * @param error error message buffer
     * @param inputSize size of input data
     * @param outputLength size of output buffer
     * @param errorLength size of error buffer
     * @return result code from native function (0 = success)
     */
    public static int eip2537blsG1Add(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int outputLength,
            int errorLength) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedOutput = PinnedObject.create(output);
             PinnedObject pinnedError = PinnedObject.create(error)) {
            return eip2537blsG1AddNative(
                pinnedInput.addressOfArrayElement(0),
                pinnedOutput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize, outputLength, errorLength
            );
        }
    }

    /**
     * Java-friendly wrapper for BLS12-381 G1 multi-scalar multiplication.
     *
     * @param input input data containing G1 points and scalars
     * @param output output buffer for result
     * @param error error message buffer
     * @param inputSize size of input data
     * @param outputLength size of output buffer
     * @param errorLength size of error buffer
     * @param nbTasks number of parallel tasks (0 = auto-detect)
     * @return result code from native function (0 = success)
     */
    public static int eip2537blsG1MultiExp(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int outputLength,
            int errorLength,
            int nbTasks) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedOutput = PinnedObject.create(output);
             PinnedObject pinnedError = PinnedObject.create(error)) {
            return eip2537blsG1MultiExpNative(
                pinnedInput.addressOfArrayElement(0),
                pinnedOutput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize, outputLength, errorLength, nbTasks
            );
        }
    }

    /**
     * Java-friendly wrapper for BLS12-381 G2 point addition.
     *
     * @param input input data containing two G2 points to add
     * @param output output buffer for result
     * @param error error message buffer
     * @param inputSize size of input data
     * @param outputLength size of output buffer
     * @param errorLength size of error buffer
     * @return result code from native function (0 = success)
     */
    public static int eip2537blsG2Add(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int outputLength,
            int errorLength) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedOutput = PinnedObject.create(output);
             PinnedObject pinnedError = PinnedObject.create(error)) {
            return eip2537blsG2AddNative(
                pinnedInput.addressOfArrayElement(0),
                pinnedOutput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize, outputLength, errorLength
            );
        }
    }

    /**
     * Java-friendly wrapper for BLS12-381 G2 multi-scalar multiplication.
     *
     * @param input input data containing G2 points and scalars
     * @param output output buffer for result
     * @param error error message buffer
     * @param inputSize size of input data
     * @param outputLength size of output buffer
     * @param errorLength size of error buffer
     * @param nbTasks number of parallel tasks (0 = auto-detect)
     * @return result code from native function (0 = success)
     */
    public static int eip2537blsG2MultiExp(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int outputLength,
            int errorLength,
            int nbTasks) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedOutput = PinnedObject.create(output);
             PinnedObject pinnedError = PinnedObject.create(error)) {
            return eip2537blsG2MultiExpNative(
                pinnedInput.addressOfArrayElement(0),
                pinnedOutput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize, outputLength, errorLength, nbTasks
            );
        }
    }

    /**
     * Java-friendly wrapper for BLS12-381 pairing check operation.
     *
     * @param input input data containing pairs of G1 and G2 points
     * @param output output buffer for result (boolean encoded as bytes)
     * @param error error message buffer
     * @param inputSize size of input data
     * @param outputLength size of output buffer
     * @param errorLength size of error buffer
     * @return result code from native function (0 = success)
     */
    public static int eip2537blsPairing(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int outputLength,
            int errorLength) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedOutput = PinnedObject.create(output);
             PinnedObject pinnedError = PinnedObject.create(error)) {
            return eip2537blsPairingNative(
                pinnedInput.addressOfArrayElement(0),
                pinnedOutput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize, outputLength, errorLength
            );
        }
    }

    /**
     * Java-friendly wrapper for mapping field element to BLS12-381 G1 point.
     *
     * @param input input data containing field element
     * @param output output buffer for resulting G1 point
     * @param error error message buffer
     * @param inputSize size of input data
     * @param outputLength size of output buffer
     * @param errorLength size of error buffer
     * @return result code from native function (0 = success)
     */
    public static int eip2537blsMapFpToG1(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int outputLength,
            int errorLength) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedOutput = PinnedObject.create(output);
             PinnedObject pinnedError = PinnedObject.create(error)) {
            return eip2537blsMapFpToG1Native(
                pinnedInput.addressOfArrayElement(0),
                pinnedOutput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize, outputLength, errorLength
            );
        }
    }

    /**
     * Java-friendly wrapper for mapping field element to BLS12-381 G2 point.
     *
     * @param input input data containing field element
     * @param output output buffer for resulting G2 point
     * @param error error message buffer
     * @param inputSize size of input data
     * @param outputLength size of output buffer
     * @param errorLength size of error buffer
     * @return result code from native function (0 = success)
     */
    public static int eip2537blsMapFp2ToG2(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int outputLength,
            int errorLength) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedOutput = PinnedObject.create(output);
             PinnedObject pinnedError = PinnedObject.create(error)) {
            return eip2537blsMapFp2ToG2Native(
                pinnedInput.addressOfArrayElement(0),
                pinnedOutput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize, outputLength, errorLength
            );
        }
    }

    /**
     * Java-friendly wrapper for checking if a point is on the BLS12-381 G1 curve.
     *
     * @param input input data containing G1 point to validate
     * @param error error message buffer
     * @param inputSize size of input data
     * @param errorLength size of error buffer
     * @return true if point is on curve, false otherwise
     */
    public static boolean eip2537G1IsOnCurve(
            byte[] input,
            byte[] error,
            int inputSize,
            int errorLength) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedError = PinnedObject.create(error)) {
            return eip2537G1IsOnCurveNative(
                pinnedInput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize, errorLength
            );
        }
    }

    /**
     * Java-friendly wrapper for checking if a point is on the BLS12-381 G2 curve.
     *
     * @param input input data containing G2 point to validate
     * @param error error message buffer
     * @param inputSize size of input data
     * @param errorLength size of error buffer
     * @return true if point is on curve, false otherwise
     */
    public static boolean eip2537G2IsOnCurve(
            byte[] input,
            byte[] error,
            int inputSize,
            int errorLength) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedError = PinnedObject.create(error)) {
            return eip2537G2IsOnCurveNative(
                pinnedInput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize, errorLength
            );
        }
    }

    /**
     * Java-friendly wrapper for checking if a G1 point is in the correct subgroup.
     *
     * @param input input data containing G1 point to validate
     * @param error error message buffer
     * @param inputSize size of input data
     * @param errorLength size of error buffer
     * @return true if point is in subgroup, false otherwise
     */
    public static boolean eip2537G1IsInSubGroup(
            byte[] input,
            byte[] error,
            int inputSize,
            int errorLength) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedError = PinnedObject.create(error)) {
            return eip2537G1IsInSubGroupNative(
                pinnedInput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize, errorLength
            );
        }
    }

    /**
     * Java-friendly wrapper for checking if a G2 point is in the correct subgroup.
     *
     * @param input input data containing G2 point to validate
     * @param error error message buffer
     * @param inputSize size of input data
     * @param errorLength size of error buffer
     * @return true if point is in subgroup, false otherwise
     */
    public static boolean eip2537G2IsInSubGroup(
            byte[] input,
            byte[] error,
            int inputSize,
            int errorLength) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedError = PinnedObject.create(error)) {
            return eip2537G2IsInSubGroupNative(
                pinnedInput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize, errorLength
            );
        }
    }

    /**
     * Sets the degree of parallelism for multi-scalar multiplication operations.
     *
     * @param nbTasks number of parallel tasks (0 = auto-detect CPU cores)
     */
    public static void setDegreeOfMSMParallelism(int nbTasks) {
        degreeOfMSMParallelism = nbTasks;
    }
}
