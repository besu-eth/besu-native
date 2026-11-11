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
#include "secp256k1_ecrecover.h"
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_recovery.h>
#include <string.h>

// None of the wrapped operations sign, so they use the immutable secp256k1_context_static, which
// can be shared between threads without synchronization. It requires the self tests that
// secp256k1_context_create would otherwise run.
__attribute__((constructor))
static void run_selftest() {
    secp256k1_selftest();
}

// Internal implementation with size validation
static int secp256k1_ecrecover_jni_impl(
    const unsigned char message_hash[], int message_hash_len,
    const unsigned char signature[], int signature_len,
    int recovery_id,
    unsigned char output_buffer[], int output_buffer_len) {

    // Validate inputs
    if (message_hash == NULL || signature == NULL || output_buffer == NULL) {
        return 1;
    }

    // Validate input array sizes
    if (message_hash_len != 32) {
        return 1; // message_hash must be exactly 32 bytes
    }
    if (signature_len != 64) {
        return 1; // signature must be exactly 64 bytes
    }
    if (output_buffer_len < 65) {
        return 1; // output_buffer must be at least 65 bytes
    }

    // libsecp256k1 aborts the process on a recovery id outside 0 to 3 instead of failing
    if (recovery_id < 0 || recovery_id > 3) {
        return 1;
    }

    secp256k1_ecdsa_recoverable_signature recoverable_sig;
    secp256k1_pubkey pubkey;
    size_t output_len = 65;

    // Step 1: Parse the signature with recovery ID
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(
            secp256k1_context_static, &recoverable_sig, signature, recovery_id) != 1) {
        return 1; // Failed to parse signature
    }

    // Step 2: Recover the public key from the signature
    if (secp256k1_ecdsa_recover(
            secp256k1_context_static, &pubkey, &recoverable_sig, message_hash) != 1) {
        return 1; // Failed to recover public key
    }

    // Step 3: Serialize the public key in uncompressed format
    if (secp256k1_ec_pubkey_serialize(
            secp256k1_context_static, output_buffer, &output_len, &pubkey,
            SECP256K1_EC_UNCOMPRESSED) != 1) {
        return 1; // Failed to serialize public key
    }

    // Verify we got the expected length
    if (output_len != 65) {
        return 1; // Unexpected output length
    }

    return 0; // Success
}

// Public API with backward compatibility (assumes standard sizes)
int secp256k1_ecrecover_jni(
    const unsigned char message_hash[32],
    const unsigned char signature[64],
    int recovery_id,
    unsigned char output_buffer[65]) {
    
    return secp256k1_ecrecover_jni_impl(
        message_hash, 32,
        signature, 64,
        recovery_id,
        output_buffer, 65);
}

// ECDH hash function that returns the compressed shared point instead of hashing it, because
// RLPx uses the x coordinate and discv5 uses the compressed point
static int copy_compressed_point(
    unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    (void) data;
    // branch-free, because the y coordinate is secret
    output[0] = 0x02 | (y32[31] & 1);
    memcpy(output + 1, x32, 32);
    return 1;
}

int secp256k1_ecdh_jni(
    const unsigned char public_key[64],
    const unsigned char private_key[32],
    unsigned char output_buffer[33]) {

    if (output_buffer == NULL) {
        return 1;
    }
    if (public_key == NULL || private_key == NULL) {
        memset(output_buffer, 0, 33);
        return 1;
    }

    unsigned char serialized_public_key[65];
    serialized_public_key[0] = 0x04;
    memcpy(serialized_public_key + 1, public_key, 64);

    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_parse(secp256k1_context_static, &pubkey, serialized_public_key, 65) != 1) {
        memset(output_buffer, 0, 33);
        return 1; // not a point on the curve
    }

    // fails for a zero or out-of-range private key, but still writes the public key multiplied by
    // one to the output, so it has to be cleared
    if (secp256k1_ecdh(
            secp256k1_context_static, output_buffer, &pubkey, private_key, copy_compressed_point,
            NULL) != 1) {
        memset(output_buffer, 0, 33);
        return 1;
    }

    return 0;
}
