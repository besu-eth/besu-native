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
import org.graalvm.nativeimage.c.type.CIntPointer;

import java.util.Collections;
import java.util.List;

/**
 * GraalVM native-image compatible interface to gnark EIP-196 static library.
 * Provides operations for Alt-BN128 elliptic curve operations including G1 addition,
 * scalar multiplication, and pairing checks.
 */
public class LibGnarkEIP196Graal {

    /** Recommended buffer size for operation results. */
    public static final int EIP196_PREALLOCATE_FOR_RESULT_BYTES = 128;

    /** Recommended buffer size for error messages. */
    public static final int EIP196_PREALLOCATE_FOR_ERROR_BYTES = 256;

    /** Operation code for G1 point addition. */
    public static final byte EIP196_ADD_OPERATION_RAW_VALUE = 1;

    /** Operation code for G1 scalar multiplication. */
    public static final byte EIP196_MUL_OPERATION_RAW_VALUE = 2;

    /** Operation code for pairing check. */
    public static final byte EIP196_PAIR_OPERATION_RAW_VALUE = 3;

    /** Private constructor to prevent instantiation of utility class. */
    private LibGnarkEIP196Graal() {}

    @CContext(LibGnarkEIP196Graal.Directives.class)
    public static class Directives implements CContext.Directives {
        @Override
        public List<String> getHeaderFiles() {
            return Collections.singletonList("<libgnark_eip_196.h>");
        }

        @Override
        public List<String> getLibraries() {
            return Collections.singletonList("gnark_eip_196");
        }

        @Override
        public List<String> getLibraryPaths() {
            // Library paths should be configured via native-image build arguments
            return Collections.emptyList();
        }
    }

    @CFunction(value = "eip196altbn128G1Add")
    public static native int eip196altbn128G1AddNative(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            CIntPointer outputSize,
            CIntPointer errorSize);

    @CFunction(value = "eip196altbn128G1Mul")
    public static native int eip196altbn128G1MulNative(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            CIntPointer outputSize,
            CIntPointer errorSize);

    @CFunction(value = "eip196altbn128Pairing")
    public static native int eip196altbn128PairingNative(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            CIntPointer outputSize,
            CIntPointer errorSize);

    /**
     * Compatibility shim for the pre-existing matter-labs implementation.
     * Routes operation codes to the appropriate native function.
     *
     * @param op operation code (ADD, MUL, or PAIR)
     * @param input input data buffer
     * @param inputLength length of input data
     * @param output output data buffer
     * @param outputSize output size reference (updated by native function)
     * @param error error message buffer
     * @param errorSize error size reference (updated by native function)
     * @return result code from native function
     */
    public static int eip196_perform_operation(
            byte op,
            byte[] input,
            int inputLength,
            byte[] output,
            int[] outputSize,
            byte[] error,
            int[] errorSize) {

        int ret = -1;
        switch(op) {
            case EIP196_ADD_OPERATION_RAW_VALUE:
                ret = eip196altbn128G1Add(input, output, error, inputLength, outputSize, errorSize);
                break;
            case EIP196_MUL_OPERATION_RAW_VALUE:
                ret = eip196altbn128G1Mul(input, output, error, inputLength, outputSize, errorSize);
                break;
            case EIP196_PAIR_OPERATION_RAW_VALUE:
                ret = eip196altbn128Pairing(input, output, error, inputLength, outputSize, errorSize);
                break;
            default:
                throw new RuntimeException("Not Implemented EIP-196 operation " + op);
        }

        return ret;
    }

    /**
     * Java-friendly wrapper for Alt-BN128 G1 point addition.
     *
     * @param input input data containing two G1 points to add
     * @param output output buffer for result
     * @param error error message buffer
     * @param inputSize size of input data
     * @param outputSize output size reference (updated by native function)
     * @param errorSize error size reference (updated by native function)
     * @return result code from native function
     */
    public static int eip196altbn128G1Add(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int[] outputSize,
            int[] errorSize) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedOutput = PinnedObject.create(output);
             PinnedObject pinnedError = PinnedObject.create(error);
             PinnedObject pinnedOutputSize = PinnedObject.create(outputSize);
             PinnedObject pinnedErrorSize = PinnedObject.create(errorSize)) {
            return eip196altbn128G1AddNative(
                pinnedInput.addressOfArrayElement(0),
                pinnedOutput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize,
                pinnedOutputSize.addressOfArrayElement(0),
                pinnedErrorSize.addressOfArrayElement(0)
            );
        }
    }

    /**
     * Java-friendly wrapper for Alt-BN128 G1 scalar multiplication.
     *
     * @param input input data containing G1 point and scalar
     * @param output output buffer for result
     * @param error error message buffer
     * @param inputSize size of input data
     * @param outputSize output size reference (updated by native function)
     * @param errorSize error size reference (updated by native function)
     * @return result code from native function
     */
    public static int eip196altbn128G1Mul(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int[] outputSize,
            int[] errorSize) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedOutput = PinnedObject.create(output);
             PinnedObject pinnedError = PinnedObject.create(error);
             PinnedObject pinnedOutputSize = PinnedObject.create(outputSize);
             PinnedObject pinnedErrorSize = PinnedObject.create(errorSize)) {
            return eip196altbn128G1MulNative(
                pinnedInput.addressOfArrayElement(0),
                pinnedOutput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize,
                pinnedOutputSize.addressOfArrayElement(0),
                pinnedErrorSize.addressOfArrayElement(0)
            );
        }
    }

    /**
     * Java-friendly wrapper for Alt-BN128 pairing check operation.
     *
     * @param input input data containing pairs of G1 and G2 points
     * @param output output buffer for result (boolean encoded as bytes)
     * @param error error message buffer
     * @param inputSize size of input data
     * @param outputSize output size reference (updated by native function)
     * @param errorSize error size reference (updated by native function)
     * @return result code from native function
     */
    public static int eip196altbn128Pairing(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int[] outputSize,
            int[] errorSize) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedOutput = PinnedObject.create(output);
             PinnedObject pinnedError = PinnedObject.create(error);
             PinnedObject pinnedOutputSize = PinnedObject.create(outputSize);
             PinnedObject pinnedErrorSize = PinnedObject.create(errorSize)) {
            return eip196altbn128PairingNative(
                pinnedInput.addressOfArrayElement(0),
                pinnedOutput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize,
                pinnedOutputSize.addressOfArrayElement(0),
                pinnedErrorSize.addressOfArrayElement(0)
            );
        }
    }
}
