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

import com.google.common.io.CharStreams;
import org.apache.tuweni.bytes.Bytes;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

@RunWith(Parameterized.class)
public class AltBN128G1AddPrecompiledContractTest {

  @Parameterized.Parameter(0)
  public String input;
  @Parameterized.Parameter(1)
  public String expectedResult;
  @Parameterized.Parameter(2)
  public String expectedGasUsed;
  @Parameterized.Parameter(3)
  public String notes;

  @Parameterized.Parameters
  public static Iterable<String[]> parameters() throws IOException {
    return CharStreams.readLines(
            new InputStreamReader(
                AltBN128G1AddPrecompiledContractTest.class.getResourceAsStream("eip196_g1_add.csv"), UTF_8))
        .stream()
        .map(line -> line.split(",", 4))
        .collect(Collectors.toList());
  }

  @Test
  public void shouldCalculate() {
    if ("input".equals(input)) {
      // skip the header row
      return;
    }
    final byte[] input = Bytes.fromHexString(this.input).toArrayUnsafe();

    final byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];

    int errorCode = LibGnarkEIP196.eip196_perform_operation(LibGnarkEIP196.EIP196_ADD_OPERATION_RAW_VALUE, input,
        input.length, output);
    final Bytes expectedComputation =
        expectedResult == null ? null : Bytes.fromHexString(expectedResult);
    if (errorCode != LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS) {
      assertThat(notes).isNotEmpty();
    } else {
      final Bytes actualComputation = Bytes.wrap(output, 0, LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES);
      assertThat(actualComputation).isEqualTo(expectedComputation);
      assertThat(notes).isEmpty();
    }
  }
}
