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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

public class LibGnarkEIP196ConcurrentTest {

  // Valid G1 point for testing
  private static final Bytes G1_POINT_1 = Bytes.concatenate(
      Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001"),
      Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000002"));

  // Another valid G1 point
  private static final Bytes G1_POINT_2 = Bytes.concatenate(
      Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001"),
      Bytes.fromHexString("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"));

  // Valid G2 point for testing
  private static final Bytes G2_POINT = Bytes.concatenate(
      Bytes.fromHexString("0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"),
      Bytes.fromHexString("0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"),
      Bytes.fromHexString("0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"),
      Bytes.fromHexString("0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"));

  // Scalar for multiplication
  private static final Bytes SCALAR = Bytes.fromHexString(
      "0x0000000000000000000000000000000000000000000000000000000000000009");

  @Test
  public void testConcurrentG1Add() throws Exception {
    final int threadCount = 10;
    final int operationsPerThread = 100;
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    List<Future<Boolean>> futures = new ArrayList<>();

    byte[] inputBytes = Bytes.concatenate(G1_POINT_1, G1_POINT_2).toArrayUnsafe();

    for (int i = 0; i < threadCount; i++) {
      futures.add(executor.submit(() -> {
        for (int j = 0; j < operationsPerThread; j++) {
          byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];
          int errorCode = LibGnarkEIP196.eip196_perform_operation(
              LibGnarkEIP196.EIP196_ADD_OPERATION_RAW_VALUE,
              inputBytes,
              inputBytes.length,
              output);

          if (errorCode != LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS) {
            return false;
          }
        }
        return true;
      }));
    }

    executor.shutdown();
    assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();

    for (Future<Boolean> future : futures) {
      assertThat(future.get()).isTrue();
    }
  }

  @Test
  public void testConcurrentG1Mul() throws Exception {
    final int threadCount = 10;
    final int operationsPerThread = 100;
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    List<Future<Boolean>> futures = new ArrayList<>();

    byte[] inputBytes = Bytes.concatenate(G1_POINT_1, SCALAR).toArrayUnsafe();

    for (int i = 0; i < threadCount; i++) {
      futures.add(executor.submit(() -> {
        for (int j = 0; j < operationsPerThread; j++) {
          byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];
          int errorCode = LibGnarkEIP196.eip196_perform_operation(
              LibGnarkEIP196.EIP196_MUL_OPERATION_RAW_VALUE,
              inputBytes,
              inputBytes.length,
              output);

          if (errorCode != LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS) {
            return false;
          }
        }
        return true;
      }));
    }

    executor.shutdown();
    assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();

    for (Future<Boolean> future : futures) {
      assertThat(future.get()).isTrue();
    }
  }

  @Test
  public void testConcurrentPairing() throws Exception {
    final int threadCount = 10;
    final int operationsPerThread = 50;
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    List<Future<Boolean>> futures = new ArrayList<>();

    byte[] inputBytes = Bytes.concatenate(G1_POINT_1, G2_POINT).toArrayUnsafe();

    for (int i = 0; i < threadCount; i++) {
      futures.add(executor.submit(() -> {
        for (int j = 0; j < operationsPerThread; j++) {
          byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];
          int errorCode = LibGnarkEIP196.eip196_perform_operation(
              LibGnarkEIP196.EIP196_PAIR_OPERATION_RAW_VALUE,
              inputBytes,
              inputBytes.length,
              output);

          if (errorCode != LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS) {
            return false;
          }
        }
        return true;
      }));
    }

    executor.shutdown();
    assertThat(executor.awaitTermination(60, TimeUnit.SECONDS)).isTrue();

    for (Future<Boolean> future : futures) {
      assertThat(future.get()).isTrue();
    }
  }

  @Test
  public void testMixedConcurrentOperations() throws Exception {
    final int threadCount = 15;
    final int operationsPerThread = 50;
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    List<Future<Boolean>> futures = new ArrayList<>();

    byte[] addInput = Bytes.concatenate(G1_POINT_1, G1_POINT_2).toArrayUnsafe();
    byte[] mulInput = Bytes.concatenate(G1_POINT_1, SCALAR).toArrayUnsafe();
    byte[] pairingInput = Bytes.concatenate(G1_POINT_1, G2_POINT).toArrayUnsafe();

    // Mix of different operations
    for (int i = 0; i < threadCount; i++) {
      final int threadId = i;
      futures.add(executor.submit(() -> {
        for (int j = 0; j < operationsPerThread; j++) {
          byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];
          int errorCode;

          // Different threads do different operations
          if (threadId % 3 == 0) {
            errorCode = LibGnarkEIP196.eip196_perform_operation(
                LibGnarkEIP196.EIP196_ADD_OPERATION_RAW_VALUE,
                addInput,
                addInput.length,
                output);
          } else if (threadId % 3 == 1) {
            errorCode = LibGnarkEIP196.eip196_perform_operation(
                LibGnarkEIP196.EIP196_MUL_OPERATION_RAW_VALUE,
                mulInput,
                mulInput.length,
                output);
          } else {
            errorCode = LibGnarkEIP196.eip196_perform_operation(
                LibGnarkEIP196.EIP196_PAIR_OPERATION_RAW_VALUE,
                pairingInput,
                pairingInput.length,
                output);
          }

          if (errorCode != LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS) {
            return false;
          }
        }
        return true;
      }));
    }

    executor.shutdown();
    assertThat(executor.awaitTermination(60, TimeUnit.SECONDS)).isTrue();

    for (Future<Boolean> future : futures) {
      assertThat(future.get()).isTrue();
    }
  }

  @Test
  public void testConcurrentWithErrors() throws Exception {
    final int threadCount = 10;
    final int operationsPerThread = 50;
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    List<Future<Boolean>> futures = new ArrayList<>();

    // Invalid point (not on curve)
    byte[] invalidInput = Bytes.fromHexString("0x1234").toArrayUnsafe();
    byte[] validInput = Bytes.concatenate(G1_POINT_1, G1_POINT_2).toArrayUnsafe();

    for (int i = 0; i < threadCount; i++) {
      final int threadId = i;
      futures.add(executor.submit(() -> {
        for (int j = 0; j < operationsPerThread; j++) {
          byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];
          byte[] input = (threadId % 2 == 0) ? validInput : invalidInput;
          int expectedError = (threadId % 2 == 0) ?
              LibGnarkEIP196.EIP196_ERR_CODE_SUCCESS :
              LibGnarkEIP196.EIP196_ERR_CODE_POINT_ON_CURVE_CHECK_FAILED;

          int errorCode = LibGnarkEIP196.eip196_perform_operation(
              LibGnarkEIP196.EIP196_ADD_OPERATION_RAW_VALUE,
              input,
              input.length,
              output);

          if (errorCode != expectedError) {
            return false;
          }
        }
        return true;
      }));
    }

    executor.shutdown();
    assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();

    for (Future<Boolean> future : futures) {
      assertThat(future.get()).isTrue();
    }
  }
}
