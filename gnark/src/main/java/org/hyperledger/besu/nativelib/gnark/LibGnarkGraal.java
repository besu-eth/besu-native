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
import org.graalvm.word.WordFactory;

import java.util.Collections;
import java.util.List;

/**
 * GraalVM native-image compatible interface to gnark static library
 */
public class LibGnarkGraal {

    @CContext(LibGnarkGraal.Directives.class)
    public static class Directives implements CContext.Directives {
        @Override
        public List<String> getHeaderFiles() {
            return Collections.singletonList("<libgnark_jni.h>");
        }

        @Override
        public List<String> getLibraries() {
            return Collections.singletonList("gnark_jni");
        }

        @Override
        public List<String> getLibraryPaths() {
            // Library paths should be configured via native-image build arguments
            return Collections.emptyList();
        }
    }

    @CFunction(value = "computeMimcBn254")
    public static native int computeMimcBn254Native(
            CCharPointer input,
            int inputLength,
            CCharPointer output);

    @CFunction(value = "computeMimcBls12377")
    public static native int computeMimcBls12377Native(
            CCharPointer input,
            int inputLength,
            CCharPointer output);

    /**
     * Java-friendly wrapper for computeMimcBn254
     */
    public static int computeMimcBn254(byte[] input, int inputLength, byte[] output) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedOutput = PinnedObject.create(output)) {
            return computeMimcBn254Native(
                pinnedInput.addressOfArrayElement(0),
                inputLength,
                pinnedOutput.addressOfArrayElement(0)
            );
        }
    }

    /**
     * Java-friendly wrapper for computeMimcBls12377
     */
    public static int computeMimcBls12377(byte[] input, int inputLength, byte[] output) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedOutput = PinnedObject.create(output)) {
            return computeMimcBls12377Native(
                pinnedInput.addressOfArrayElement(0),
                inputLength,
                pinnedOutput.addressOfArrayElement(0)
            );
        }
    }
}
