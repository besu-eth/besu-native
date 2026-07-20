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
package org.hyperledger.besu.nativelib.secp256k1;

import org.graalvm.nativeimage.PinnedObject;
import org.graalvm.nativeimage.c.CContext;
import org.graalvm.nativeimage.c.function.CFunction;
import org.graalvm.nativeimage.c.type.CCharPointer;
import org.graalvm.nativeimage.c.type.CIntPointer;
import org.graalvm.word.PointerBase;
import org.graalvm.word.WordFactory;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * GraalVM native-image compatible interface to secp256k1 static library.
 * Provides full secp256k1 API for ECDSA operations including signing, verification,
 * key generation, and public key recovery.
 *
 * <p>This class uses GraalVM's @CFunction annotation to call native C functions
 * directly from statically linked libraries, avoiding the overhead of JNA.
 *
 * <p>Unlike JNA, this implementation treats secp256k1 structures as opaque byte arrays,
 * avoiding the need for @CStruct definitions which require struct definitions at compile time.
 *
 * <p>This class provides a simple byte-array based API. Implementing projects can
 * create their own type-safe wrapper classes if desired.
 *
 * <p>The native library required is:
 * <ul>
 *   <li>libsecp256k1.a - Core Bitcoin secp256k1 library with recovery module</li>
 * </ul>
 */
public class LibSecp256k1Graal {

    // Structure sizes (opaque to us, but we need to allocate the right amount)
    public static final int SECP256K1_PUBKEY_SIZE = 64;
    public static final int SECP256K1_ECDSA_SIGNATURE_SIZE = 64;
    public static final int SECP256K1_ECDSA_RECOVERABLE_SIGNATURE_SIZE = 65;

    // Context flags
    private static final int SECP256K1_FLAGS_TYPE_CONTEXT = 1;
    private static final int SECP256K1_FLAGS_TYPE_COMPRESSION = 1 << 1;
    private static final int SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = 1 << 8;
    private static final int SECP256K1_FLAGS_BIT_CONTEXT_SIGN = 1 << 9;
    private static final int SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY = 1 << 10;
    private static final int SECP256K1_FLAGS_BIT_COMPRESSION = 1 << 8;

    public static final int SECP256K1_CONTEXT_VERIFY =
        SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY;
    public static final int SECP256K1_CONTEXT_SIGN =
        SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN;
    public static final int SECP256K1_CONTEXT_DECLASSIFY =
        SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY;
    public static final int SECP256K1_CONTEXT_NONE = SECP256K1_FLAGS_TYPE_CONTEXT;

    public static final int SECP256K1_EC_COMPRESSED =
        SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION;
    public static final int SECP256K1_EC_UNCOMPRESSED = SECP256K1_FLAGS_TYPE_COMPRESSION;

    /** Lazy-initialized context holder to avoid static initialization issues with GraalVM. */
    private static class ContextHolder {
        static final PointerBase INSTANCE = createContext();
    }

    /**
     * Get the global secp256k1 context (lazily initialized).
     * The context is initialized for both verification and signing operations.
     *
     * @return the global context
     */
    public static PointerBase getContext() {
        return ContextHolder.INSTANCE;
    }

    /** Private constructor to prevent instantiation of utility class. */
    private LibSecp256k1Graal() {}

    /**
     * CContext directives for configuring GraalVM native-image compilation.
     * Specifies header files and libraries required for static linking.
     */
    @CContext(LibSecp256k1Graal.Directives.class)
    public static class Directives implements CContext.Directives {
        @Override
        public List<String> getHeaderFiles() {
            return Arrays.asList(
                "<secp256k1.h>",
                "<secp256k1_recovery.h>"
            );
        }

        @Override
        public List<String> getLibraries() {
            return Collections.singletonList("secp256k1");
        }

        @Override
        public List<String> getLibraryPaths() {
            // Library paths should be configured via native-image build arguments
            return Collections.emptyList();
        }
    }

    // ============ Context Management ============

    /**
     * Create a secp256k1 context object.
     *
     * @param flags which parts of the context to initialize
     * @return a newly created context object
     */
    @CFunction(value = "secp256k1_context_create")
    static native PointerBase secp256k1ContextCreate(int flags);

    /**
     * Updates the context randomization to protect against side-channel leakage.
     *
     * @param ctx pointer to a context object
     * @param seed32 pointer to a 32-byte random seed
     * @return 1 if randomization successfully updated, 0 if an error occurred
     */
    @CFunction(value = "secp256k1_context_randomize")
    static native int secp256k1ContextRandomize(PointerBase ctx, CCharPointer seed32);

    /**
     * Destroy a secp256k1 context object.
     *
     * @param ctx pointer to a context object
     */
    @CFunction(value = "secp256k1_context_destroy")
    static native void secp256k1ContextDestroy(PointerBase ctx);

    // ============ Public Key Operations ============

    /**
     * Parse a variable-length public key into the pubkey object.
     *
     * @param ctx a secp256k1 context object
     * @param pubkey pointer to a 64-byte pubkey buffer (output)
     * @param input pointer to a serialized public key
     * @param inputlen length of the array pointed to by input
     * @return 1 if the public key was fully valid, 0 otherwise
     */
    @CFunction(value = "secp256k1_ec_pubkey_parse")
    static native int secp256k1EcPubkeyParse(
        PointerBase ctx,
        CCharPointer pubkey,
        CCharPointer input,
        long inputlen);

    /**
     * Serialize a pubkey object into a serialized byte sequence.
     *
     * @param ctx a secp256k1 context object
     * @param output pointer to output array (33 or 65 bytes)
     * @param outputlen pointer to output length (input/output)
     * @param pubkey pointer to a 64-byte pubkey buffer
     * @param flags SECP256K1_EC_COMPRESSED or SECP256K1_EC_UNCOMPRESSED
     * @return 1 always
     */
    @CFunction(value = "secp256k1_ec_pubkey_serialize")
    static native int secp256k1EcPubkeySerialize(
        PointerBase ctx,
        CCharPointer output,
        CIntPointer outputlen,
        CCharPointer pubkey,
        int flags);

    /**
     * Compute the public key for a secret key.
     *
     * @param ctx pointer to a context object
     * @param pubkey pointer to 64-byte pubkey buffer (output)
     * @param seckey pointer to a 32-byte private key
     * @return 1 if secret was valid, 0 if secret was invalid
     */
    @CFunction(value = "secp256k1_ec_pubkey_create")
    static native int secp256k1EcPubkeyCreate(
        PointerBase ctx,
        CCharPointer pubkey,
        CCharPointer seckey);

    // ============ ECDSA Signature Operations ============

    /**
     * Parse an ECDSA signature in compact (64 bytes) format.
     *
     * @param ctx a secp256k1 context object
     * @param sig pointer to a 64-byte signature buffer (output)
     * @param input64 pointer to the 64-byte array to parse
     * @return 1 when the signature could be parsed, 0 otherwise
     */
    @CFunction(value = "secp256k1_ecdsa_signature_parse_compact")
    static native int secp256k1EcdsaSignatureParseCompact(
        PointerBase ctx,
        CCharPointer sig,
        CCharPointer input64);

    /**
     * Convert a signature to a normalized lower-S form.
     *
     * @param ctx a secp256k1 context object
     * @param sigout pointer to 64-byte output signature buffer (output)
     * @param sigin pointer to 64-byte input signature buffer
     * @return 1 if sigin was not normalized, 0 if it already was
     */
    @CFunction(value = "secp256k1_ecdsa_signature_normalize")
    static native int secp256k1EcdsaSignatureNormalize(
        PointerBase ctx,
        CCharPointer sigout,
        CCharPointer sigin);

    /**
     * Verify an ECDSA signature.
     *
     * @param ctx a secp256k1 context object
     * @param sig pointer to 64-byte signature buffer
     * @param msg32 the 32-byte message hash being verified
     * @param pubkey pointer to 64-byte pubkey buffer
     * @return 1 if correct signature, 0 if incorrect or unparseable signature
     */
    @CFunction(value = "secp256k1_ecdsa_verify")
    static native int secp256k1EcdsaVerify(
        PointerBase ctx,
        CCharPointer sig,
        CCharPointer msg32,
        CCharPointer pubkey);

    /**
     * Create an ECDSA signature.
     *
     * @param ctx a secp256k1 context object, initialized for signing
     * @param sig pointer to 64-byte signature buffer (output)
     * @param msg32 the 32-byte message hash being signed
     * @param seckey pointer to a 32-byte secret key
     * @param noncefp pointer to a nonce generation function (can be null for default)
     * @param ndata pointer to arbitrary data for nonce generation function (can be null)
     * @return 1 if signature created, 0 if nonce generation failed or secret key invalid
     */
    @CFunction(value = "secp256k1_ecdsa_sign")
    static native int secp256k1EcdsaSign(
        PointerBase ctx,
        CCharPointer sig,
        CCharPointer msg32,
        CCharPointer seckey,
        PointerBase noncefp,
        PointerBase ndata);

    // ============ Recoverable Signature Operations ============

    /**
     * Create a recoverable ECDSA signature.
     *
     * @param ctx a secp256k1 context object, initialized for signing
     * @param sig pointer to 65-byte recoverable signature buffer (output)
     * @param msg32 the 32-byte message hash being signed
     * @param seckey pointer to a 32-byte secret key
     * @param noncefp pointer to a nonce generation function (can be null for default)
     * @param ndata pointer to arbitrary data for nonce generation function (can be null)
     * @return 1 if signature created, 0 if nonce generation failed or secret key invalid
     */
    @CFunction(value = "secp256k1_ecdsa_sign_recoverable")
    static native int secp256k1EcdsaSignRecoverable(
        PointerBase ctx,
        CCharPointer sig,
        CCharPointer msg32,
        CCharPointer seckey,
        PointerBase noncefp,
        PointerBase ndata);

    /**
     * Parse a compact ECDSA signature (64 bytes + recovery id).
     *
     * @param ctx a secp256k1 context object
     * @param sig pointer to a 65-byte recoverable signature buffer (output)
     * @param input64 pointer to a 64-byte compact signature
     * @param recid the recovery id (0, 1, 2 or 3)
     * @return 1 when the signature could be parsed, 0 otherwise
     */
    @CFunction(value = "secp256k1_ecdsa_recoverable_signature_parse_compact")
    static native int secp256k1EcdsaRecoverableSignatureParseCompact(
        PointerBase ctx,
        CCharPointer sig,
        CCharPointer input64,
        int recid);

    /**
     * Serialize an ECDSA signature in compact format (64 bytes + recovery id).
     *
     * @param ctx a secp256k1 context object
     * @param output64 pointer to a 64-byte array (output)
     * @param recid pointer to an integer to hold the recovery id (output)
     * @param sig pointer to 65-byte recoverable signature buffer
     */
    @CFunction(value = "secp256k1_ecdsa_recoverable_signature_serialize_compact")
    static native void secp256k1EcdsaRecoverableSignatureSerializeCompact(
        PointerBase ctx,
        CCharPointer output64,
        CIntPointer recid,
        CCharPointer sig);

    /**
     * Recover an ECDSA public key from a signature.
     *
     * @param ctx pointer to a context object
     * @param pubkey pointer to 64-byte pubkey buffer (output)
     * @param sig pointer to 65-byte recoverable signature buffer
     * @param msg32 the 32-byte message hash assumed to be signed
     * @return 1 if public key successfully recovered, 0 otherwise
     */
    @CFunction(value = "secp256k1_ecdsa_recover")
    static native int secp256k1EcdsaRecover(
        PointerBase ctx,
        CCharPointer pubkey,
        CCharPointer sig,
        CCharPointer msg32);

    // ============ Helper Methods ============

    /**
     * Create and initialize the global context with randomization.
     *
     * @return initialized context (non-null, may be zero/invalid on error)
     */
    private static PointerBase createContext() {
        try {
            PointerBase context = secp256k1ContextCreate(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
            if (context.isNull()) {
                throw new RuntimeException("Failed to create secp256k1 context");
            }

            if (Boolean.parseBoolean(System.getProperty("secp256k1.randomize", "true"))) {
                byte[] seed = new byte[32];
                SecureRandom.getInstanceStrong().nextBytes(seed);
                try (PinnedObject pinnedSeed = PinnedObject.create(seed)) {
                    if (secp256k1ContextRandomize(context, pinnedSeed.addressOfArrayElement(0)) != 1) {
                        secp256k1ContextDestroy(context);
                        throw new RuntimeException("Failed to randomize secp256k1 context");
                    }
                }
            }
            return context;
        } catch (final Throwable t) {
            throw new RuntimeException("Failed to initialize secp256k1 context", t);
        }
    }

    /**
     * Java-friendly wrapper for public key parsing.
     *
     * @param ctx context object
     * @param pubkey 64-byte array to receive parsed public key
     * @param input serialized public key (33 or 65 bytes)
     * @return 1 if valid, 0 otherwise
     */
    public static int ecPubkeyParse(PointerBase ctx, byte[] pubkey, byte[] input) {
        if (pubkey.length != SECP256K1_PUBKEY_SIZE) {
            throw new IllegalArgumentException("Public key buffer must be " + SECP256K1_PUBKEY_SIZE + " bytes");
        }
        try (PinnedObject pinnedPubkey = PinnedObject.create(pubkey);
             PinnedObject pinnedInput = PinnedObject.create(input)) {
            return secp256k1EcPubkeyParse(
                ctx,
                pinnedPubkey.addressOfArrayElement(0),
                pinnedInput.addressOfArrayElement(0),
                input.length);
        }
    }

    /**
     * Java-friendly wrapper for public key serialization.
     *
     * @param ctx context object
     * @param pubkey 64-byte internal pubkey representation
     * @param compressed true for compressed (33 bytes), false for uncompressed (65 bytes)
     * @return serialized public key
     */
    public static byte[] ecPubkeySerialize(PointerBase ctx, byte[] pubkey, boolean compressed) {
        if (pubkey.length != SECP256K1_PUBKEY_SIZE) {
            throw new IllegalArgumentException("Public key must be " + SECP256K1_PUBKEY_SIZE + " bytes");
        }

        int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
        byte[] output = new byte[compressed ? 33 : 65];
        int[] outputLen = new int[] { output.length };

        try (PinnedObject pinnedPubkey = PinnedObject.create(pubkey);
             PinnedObject pinnedOutput = PinnedObject.create(output);
             PinnedObject pinnedOutputLen = PinnedObject.create(outputLen)) {
            secp256k1EcPubkeySerialize(
                ctx,
                pinnedOutput.addressOfArrayElement(0),
                (CIntPointer) pinnedOutputLen.addressOfArrayElement(0),
                pinnedPubkey.addressOfArrayElement(0),
                flags);
        }

        return output;
    }

    /**
     * Java-friendly wrapper for signature verification.
     *
     * @param ctx context object
     * @param signature 64-byte compact signature
     * @param message 32-byte message hash
     * @param pubkey 64-byte internal pubkey representation
     * @return 1 if valid signature, 0 otherwise
     */
    public static int ecdsaVerify(PointerBase ctx, byte[] signature, byte[] message, byte[] pubkey) {
        if (signature.length != 64) {
            throw new IllegalArgumentException("Signature must be 64 bytes");
        }
        if (message.length != 32) {
            throw new IllegalArgumentException("Message must be 32 bytes");
        }
        if (pubkey.length != SECP256K1_PUBKEY_SIZE) {
            throw new IllegalArgumentException("Public key must be " + SECP256K1_PUBKEY_SIZE + " bytes");
        }

        byte[] sig = new byte[SECP256K1_ECDSA_SIGNATURE_SIZE];
        try (PinnedObject pinnedSig = PinnedObject.create(sig);
             PinnedObject pinnedSignature = PinnedObject.create(signature);
             PinnedObject pinnedMessage = PinnedObject.create(message);
             PinnedObject pinnedPubkey = PinnedObject.create(pubkey)) {

            // Parse the signature
            int parseResult = secp256k1EcdsaSignatureParseCompact(
                ctx,
                pinnedSig.addressOfArrayElement(0),
                pinnedSignature.addressOfArrayElement(0));

            if (parseResult != 1) {
                return 0;
            }

            // Verify the signature
            return secp256k1EcdsaVerify(
                ctx,
                pinnedSig.addressOfArrayElement(0),
                pinnedMessage.addressOfArrayElement(0),
                pinnedPubkey.addressOfArrayElement(0));
        }
    }

    /**
     * Java-friendly wrapper for public key recovery from signature.
     *
     * @param ctx context object
     * @param signature 64-byte compact signature (r || s)
     * @param message 32-byte message hash
     * @param recid recovery id (0 or 1)
     * @return 64-byte recovered public key, or null if recovery failed
     */
    public static byte[] ecdsaRecover(PointerBase ctx, byte[] signature, byte[] message, int recid) {
        if (signature.length != 64) {
            throw new IllegalArgumentException("Signature must be 64 bytes");
        }
        if (message.length != 32) {
            throw new IllegalArgumentException("Message must be 32 bytes");
        }

        byte[] recoverableSig = new byte[SECP256K1_ECDSA_RECOVERABLE_SIGNATURE_SIZE];
        byte[] pubkey = new byte[SECP256K1_PUBKEY_SIZE];

        try (PinnedObject pinnedRecSig = PinnedObject.create(recoverableSig);
             PinnedObject pinnedSignature = PinnedObject.create(signature);
             PinnedObject pinnedMessage = PinnedObject.create(message);
             PinnedObject pinnedPubkey = PinnedObject.create(pubkey)) {

            // Parse recoverable signature
            int parseResult = secp256k1EcdsaRecoverableSignatureParseCompact(
                ctx,
                pinnedRecSig.addressOfArrayElement(0),
                pinnedSignature.addressOfArrayElement(0),
                recid);

            if (parseResult != 1) {
                return null;
            }

            // Recover public key
            int recoverResult = secp256k1EcdsaRecover(
                ctx,
                pinnedPubkey.addressOfArrayElement(0),
                pinnedRecSig.addressOfArrayElement(0),
                pinnedMessage.addressOfArrayElement(0));

            return recoverResult == 1 ? pubkey : null;
        }
    }

    /**
     * Java-friendly wrapper for public key creation from private key.
     *
     * @param ctx context object
     * @param seckey 32-byte private key
     * @return 64-byte internal public key representation, or null if invalid
     */
    public static byte[] ecPubkeyCreate(PointerBase ctx, byte[] seckey) {
        if (seckey.length != 32) {
            throw new IllegalArgumentException("Private key must be 32 bytes");
        }

        byte[] pubkey = new byte[SECP256K1_PUBKEY_SIZE];
        try (PinnedObject pinnedPubkey = PinnedObject.create(pubkey);
             PinnedObject pinnedSeckey = PinnedObject.create(seckey)) {
            int result = secp256k1EcPubkeyCreate(
                ctx,
                pinnedPubkey.addressOfArrayElement(0),
                pinnedSeckey.addressOfArrayElement(0));

            return result == 1 ? pubkey : null;
        }
    }

    /**
     * Java-friendly wrapper for signature parsing.
     *
     * @param ctx context object
     * @param signature 64-byte array to receive parsed signature
     * @param compact64 64-byte compact signature to parse
     * @return 1 if valid, 0 otherwise
     */
    public static int ecdsaSignatureParseCompact(PointerBase ctx, byte[] signature, byte[] compact64) {
        if (signature.length != SECP256K1_ECDSA_SIGNATURE_SIZE) {
            throw new IllegalArgumentException("Signature buffer must be " + SECP256K1_ECDSA_SIGNATURE_SIZE + " bytes");
        }
        if (compact64.length != 64) {
            throw new IllegalArgumentException("Compact signature must be 64 bytes");
        }
        try (PinnedObject pinnedSignature = PinnedObject.create(signature);
             PinnedObject pinnedCompact = PinnedObject.create(compact64)) {
            return secp256k1EcdsaSignatureParseCompact(
                ctx,
                pinnedSignature.addressOfArrayElement(0),
                pinnedCompact.addressOfArrayElement(0));
        }
    }

    /**
     * Java-friendly wrapper for signature serialization.
     *
     * @param ctx context object
     * @param signature 64-byte internal signature representation
     * @return 64-byte compact signature
     */
    public static byte[] ecdsaSignatureSerializeCompact(PointerBase ctx, byte[] signature) {
        if (signature.length != SECP256K1_ECDSA_SIGNATURE_SIZE) {
            throw new IllegalArgumentException("Signature must be " + SECP256K1_ECDSA_SIGNATURE_SIZE + " bytes");
        }

        byte[] compact = new byte[64];
        try (PinnedObject pinnedSignature = PinnedObject.create(signature);
             PinnedObject pinnedCompact = PinnedObject.create(compact)) {
            secp256k1EcdsaSignatureSerializeCompact(
                ctx,
                pinnedCompact.addressOfArrayElement(0),
                pinnedSignature.addressOfArrayElement(0));
        }
        return compact;
    }

    /**
     * Serialize an ECDSA signature in compact format (64 bytes).
     *
     * @param ctx a secp256k1 context object
     * @param output64 pointer to a 64-byte array (output)
     * @param sig pointer to 64-byte signature buffer
     */
    @CFunction(value = "secp256k1_ecdsa_signature_serialize_compact")
    static native void secp256k1EcdsaSignatureSerializeCompact(
        PointerBase ctx,
        CCharPointer output64,
        CCharPointer sig);

    /**
     * Java-friendly wrapper for signature normalization.
     *
     * @param ctx context object
     * @param normalized 64-byte array to receive normalized signature
     * @param signature 64-byte internal signature representation
     * @return 1 if signature was not normalized, 0 if it already was
     */
    public static int ecdsaSignatureNormalize(PointerBase ctx, byte[] normalized, byte[] signature) {
        if (normalized.length != SECP256K1_ECDSA_SIGNATURE_SIZE) {
            throw new IllegalArgumentException("Normalized buffer must be " + SECP256K1_ECDSA_SIGNATURE_SIZE + " bytes");
        }
        if (signature.length != SECP256K1_ECDSA_SIGNATURE_SIZE) {
            throw new IllegalArgumentException("Signature must be " + SECP256K1_ECDSA_SIGNATURE_SIZE + " bytes");
        }
        try (PinnedObject pinnedNormalized = PinnedObject.create(normalized);
             PinnedObject pinnedSignature = PinnedObject.create(signature)) {
            return secp256k1EcdsaSignatureNormalize(
                ctx,
                pinnedNormalized.addressOfArrayElement(0),
                pinnedSignature.addressOfArrayElement(0));
        }
    }

    /**
     * Java-friendly wrapper for recoverable signature parsing.
     *
     * @param ctx context object
     * @param recoverableSignature 65-byte array to receive parsed signature
     * @param compact64 64-byte compact signature to parse
     * @param recoveryId recovery ID (0-3)
     * @return 1 if valid, 0 otherwise
     */
    public static int ecdsaRecoverableSignatureParseCompact(
            PointerBase ctx,
            byte[] recoverableSignature,
            byte[] compact64,
            int recoveryId) {
        if (recoverableSignature.length != SECP256K1_ECDSA_RECOVERABLE_SIGNATURE_SIZE) {
            throw new IllegalArgumentException(
                "Recoverable signature buffer must be " + SECP256K1_ECDSA_RECOVERABLE_SIGNATURE_SIZE + " bytes");
        }
        if (compact64.length != 64) {
            throw new IllegalArgumentException("Compact signature must be 64 bytes");
        }
        try (PinnedObject pinnedRecSig = PinnedObject.create(recoverableSignature);
             PinnedObject pinnedCompact = PinnedObject.create(compact64)) {
            return secp256k1EcdsaRecoverableSignatureParseCompact(
                ctx,
                pinnedRecSig.addressOfArrayElement(0),
                pinnedCompact.addressOfArrayElement(0),
                recoveryId);
        }
    }

    /**
     * Java-friendly wrapper for recoverable signature serialization.
     *
     * @param ctx context object
     * @param compact64 64-byte array to receive compact signature (output)
     * @param recoveryId single-element array to receive recovery ID (output)
     * @param recoverableSignature 65-byte internal recoverable signature representation
     */
    public static void ecdsaRecoverableSignatureSerializeCompact(
            PointerBase ctx,
            byte[] compact64,
            int[] recoveryId,
            byte[] recoverableSignature) {
        if (compact64.length != 64) {
            throw new IllegalArgumentException("Compact signature buffer must be 64 bytes");
        }
        if (recoveryId.length != 1) {
            throw new IllegalArgumentException("Recovery ID array must have length 1");
        }
        if (recoverableSignature.length != SECP256K1_ECDSA_RECOVERABLE_SIGNATURE_SIZE) {
            throw new IllegalArgumentException(
                "Recoverable signature must be " + SECP256K1_ECDSA_RECOVERABLE_SIGNATURE_SIZE + " bytes");
        }
        try (PinnedObject pinnedCompact = PinnedObject.create(compact64);
             PinnedObject pinnedRecId = PinnedObject.create(recoveryId);
             PinnedObject pinnedRecSig = PinnedObject.create(recoverableSignature)) {
            secp256k1EcdsaRecoverableSignatureSerializeCompact(
                ctx,
                pinnedCompact.addressOfArrayElement(0),
                (CIntPointer) pinnedRecId.addressOfArrayElement(0),
                pinnedRecSig.addressOfArrayElement(0));
        }
    }

    /**
     * Java-friendly wrapper for creating a recoverable ECDSA signature.
     * Uses the default nonce generation function (RFC 6979).
     *
     * @param ctx context object (must be initialized with SECP256K1_CONTEXT_SIGN)
     * @param seckey 32-byte private key
     * @param message 32-byte message hash
     * @return 65-byte signature (64 bytes compact signature + 1 byte recovery id), or null if signing failed
     */
    public static byte[] ecdsaSignRecoverable(PointerBase ctx, byte[] seckey, byte[] message) {
        if (seckey.length != 32) {
            throw new IllegalArgumentException("Secret key must be 32 bytes");
        }
        if (message.length != 32) {
            throw new IllegalArgumentException("Message must be 32 bytes");
        }

        byte[] recSig = new byte[SECP256K1_ECDSA_RECOVERABLE_SIGNATURE_SIZE];
        try (PinnedObject pinnedRecSig = PinnedObject.create(recSig);
             PinnedObject pinnedMessage = PinnedObject.create(message);
             PinnedObject pinnedSeckey = PinnedObject.create(seckey)) {

            int result = secp256k1EcdsaSignRecoverable(
                ctx,
                pinnedRecSig.addressOfArrayElement(0),
                pinnedMessage.addressOfArrayElement(0),
                pinnedSeckey.addressOfArrayElement(0),
                WordFactory.nullPointer(),  // use default nonce function
                WordFactory.nullPointer()); // no extra nonce data

            if (result != 1) {
                return null;
            }

            // Serialize to compact format with recovery id
            byte[] compact64 = new byte[64];
            int[] recid = new int[1];
            try (PinnedObject pinnedCompact = PinnedObject.create(compact64);
                 PinnedObject pinnedRecid = PinnedObject.create(recid)) {

                secp256k1EcdsaRecoverableSignatureSerializeCompact(
                    ctx,
                    pinnedCompact.addressOfArrayElement(0),
                    (CIntPointer) pinnedRecid.addressOfArrayElement(0),
                    pinnedRecSig.addressOfArrayElement(0));

                // Return 65 bytes: 64-byte compact + 1-byte recid
                byte[] result65 = new byte[65];
                System.arraycopy(compact64, 0, result65, 0, 64);
                result65[64] = (byte) recid[0];
                return result65;
            }
        }
    }

    /**
     * Convert a recoverable ECDSA signature to a regular ECDSA signature.
     *
     * @param ctx a secp256k1 context object
     * @param sig pointer to 64-byte signature buffer (output)
     * @param recoverableSig pointer to 65-byte recoverable signature buffer
     */
    @CFunction(value = "secp256k1_ecdsa_recoverable_signature_convert")
    static native void secp256k1EcdsaRecoverableSignatureConvert(
        PointerBase ctx,
        CCharPointer sig,
        CCharPointer recoverableSig);

    /**
     * Java-friendly wrapper for converting recoverable signature to regular signature.
     *
     * @param ctx context object
     * @param signature 64-byte array to receive regular signature (output)
     * @param recoverableSignature 65-byte internal recoverable signature representation
     */
    public static void ecdsaRecoverableSignatureConvert(
            PointerBase ctx,
            byte[] signature,
            byte[] recoverableSignature) {
        if (signature.length != SECP256K1_ECDSA_SIGNATURE_SIZE) {
            throw new IllegalArgumentException("Signature buffer must be " + SECP256K1_ECDSA_SIGNATURE_SIZE + " bytes");
        }
        if (recoverableSignature.length != SECP256K1_ECDSA_RECOVERABLE_SIGNATURE_SIZE) {
            throw new IllegalArgumentException(
                "Recoverable signature must be " + SECP256K1_ECDSA_RECOVERABLE_SIGNATURE_SIZE + " bytes");
        }
        try (PinnedObject pinnedSig = PinnedObject.create(signature);
             PinnedObject pinnedRecSig = PinnedObject.create(recoverableSignature)) {
            secp256k1EcdsaRecoverableSignatureConvert(
                ctx,
                pinnedSig.addressOfArrayElement(0),
                pinnedRecSig.addressOfArrayElement(0));
        }
    }

    /**
     * Java-friendly wrapper for public key recovery from recoverable signature.
     *
     * @param ctx context object
     * @param recoverableSignature 65-byte internal recoverable signature representation
     * @param message 32-byte message hash
     * @return 64-byte recovered public key, or null if recovery failed
     */
    public static byte[] ecdsaRecover(PointerBase ctx, byte[] recoverableSignature, byte[] message) {
        if (recoverableSignature.length != SECP256K1_ECDSA_RECOVERABLE_SIGNATURE_SIZE) {
            throw new IllegalArgumentException(
                "Recoverable signature must be " + SECP256K1_ECDSA_RECOVERABLE_SIGNATURE_SIZE + " bytes");
        }
        if (message.length != 32) {
            throw new IllegalArgumentException("Message must be 32 bytes");
        }

        byte[] pubkey = new byte[SECP256K1_PUBKEY_SIZE];
        try (PinnedObject pinnedPubkey = PinnedObject.create(pubkey);
             PinnedObject pinnedRecSig = PinnedObject.create(recoverableSignature);
             PinnedObject pinnedMessage = PinnedObject.create(message)) {

            int recoverResult = secp256k1EcdsaRecover(
                ctx,
                pinnedPubkey.addressOfArrayElement(0),
                pinnedRecSig.addressOfArrayElement(0),
                pinnedMessage.addressOfArrayElement(0));

            return recoverResult == 1 ? pubkey : null;
        }
    }
}
