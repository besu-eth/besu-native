# Changelog

# Unreleased
* 

# 1.4.2
* BREAKING: `LibGnarkEIP196.eip196altbn128G1Add`, `eip196altbn128G1Mul` and `eip196altbn128Pairing` native methods visibility now private, use `eip196_perform_operation` instead
* perf: Optimize EIP-196 AltBn128 [#301](https://github.com/besu-eth/besu-native/pull/301)

# 1.4.1
* Add and export JNI functions for IsOnCurve and IsInSubgroup for both G1 and G2 points[#279](https://github.com/besu-eth/besu-native/pull/279)
* Dereference o_len ptr correctly [#289](https://github.com/besu-eth/besu-native/pull/289)
* Add the Poseidon2 hash function [#299](https://github.com/besu-eth/besu-native/pull/299)
* Bump Go to 1.25.4 [#302](https://github.com/besu-eth/besu-native/pull/302)
* Add tests for the poseidon2 wrapper [#300](https://github.com/besu-eth/besu-native/pull/300)

# 1.4.0
* perf: add boringssl for p256Verify precompile [#275](https://github.com/besu-eth/besu-native/pull/275)
* perf: add higher performing ecrecover-specific entrypoints for secp256k1/r1 [#277](https://github.com/besu-eth/besu-native/pull/277)

# 1.3.1
* perf: use latest gnark-crypto 0.17 [#262](https://github.com/besu-eth/besu-native/pull/262)
* tasks: clean-up for easier auditability
  * [#263](https://github.com/besu-eth/besu-native/pull/263)
  * [#264](https://github.com/besu-eth/besu-native/pull/264)
  * [#265](https://github.com/besu-eth/besu-native/pull/265)
  * [#266](https://github.com/besu-eth/besu-native/pull/266)
  * [#267](https://github.com/besu-eth/besu-native/pull/267)
  * [#268](https://github.com/besu-eth/besu-native/pull/268)
* add malleable signature support for secp256r1 curve [#270](https://github.com/besu-eth/besu-native/pull/270)

# 1.3.0
Pectra ready mainnet support release
* perf: reorder point checking in bls12-381 [#255](https://github.com/besu-eth/besu-native/pull/255)

# 1.2.1
Errata release
* include besu-native-common in published packages [#252](https://github.com/besu-eth/besu-native/pull/252)

# 1.2.0
Pectra mainnet support release
* bump constantine to v0.2.0 and nim to 2.2.2 [#246](https://github.com/besu-eth/besu-native/pull/246)
* refactor library loading to conform arch names [#245](https://github.com/besu-eth/besu-native/pull/245)
* bump gnark-crypto to 0.16.0, adds avx512 support and ARM assembly performance improvements [#240](https://github.com/besu-eth/besu-native/pull/240)
* add riscv64 support for building besu-native, no CI support yet [#244](https://github.com/besu-eth/besu-native/pull/244)

# 1.1.2
Ubuntu 20.04 glibc support release
* revert to ubuntu 20.04 for ci builds, update to gha 4.x for upload and download artifacts [#236](https://github.com/besu-eth/besu-native/pull/236)

# 1.1.1
bug fix release
* Ensure output length is set for low pair count MSM [#231](https://github.com/besu-eth/besu-native/pull/231)

# 1.1.0
* remove matter-labs BLS12-381 implementation, in favor of gnark and constantine implementations [#225](https://github.com/besu-eth/besu-native/pull/225)
* BLS12: Use mul/add rather than pippengers for low pair count G1/G2 MSM [#226](https://github.com/besu-eth/besu-native/pull/226)


# 1.0.0
* use latest commit from gnark-crypto with improved subgroup check performance [#221](https://github.com/besu-eth/besu-native/pull/221)
* test data generator / helper for ECC inputs [#216](https://github.com/besu-eth/besu-native/pull/216)

# 0.9.7
* bump to gnark-crypto 0.14.0 relase version [#212](https://github.com/besu-eth/besu-native/pull/212)
* use multiExp with configurable parallelism in gnark-crypto bls12 MSM precompiles [#217](https://github.com/besu-eth/besu-native/pull/217)
 
# 0.9.6
* Support for EIP2537 Constantine Lib [#210](https://github.com/besu-eth/besu-native/pull/210)
* Update lib256k1 to 0.5.1 [#213](https://github.com/besu-eth/besu-native/pull/213)

# 0.9.5
* Optimizations in bn254 ECMUL [#207](https://github.com/besu-eth/besu-native/pull/207)
* Linux aarch64 support for EIP196 constantine [#203](https://github.com/besu-eth/besu-native/pull/203)

# 0.9.4
* initial support for Constantine, bn254 curve [#184](https://github.com/besu-eth/besu-native/pull/184)
* clarify go stack release behavior in gnark-crypto [#197](https://github.com/besu-eth/besu-native/pull/197)

# 0.9.3
* remove long-deprecated altbn128 [#192](https://github.com/besu-eth/besu-native/pull/192)
* fix eip-196 point padding in gnark-crypto [#191](https://github.com/besu-eth/besu-native/pull/191)

# 0.9.2
* Additional malformed input handling for EIP-196 [#188](https://github.com/besu-eth/besu-native/pull/188)

# 0.9.1
* remove tuweni-bytes dependency from gnark-crypto artifcat [#182](https://github.com/besu-eth/besu-native/pull/182)
* fix for EIP-196 edge case [#185](https://github.com/besu-eth/besu-native/pull/185)

# 0.9.0
* implement EIP-196 and EIP-2537 using gnark-crypto, bump to java 21, gradle 8.8 [#168](https://github.com/besu-eth/besu-native/pull/168)

# 0.8.5
* ipa-multipoint : add verkle proof verification (#169)

# 0.8.4

* BLS12-381: Add subgroup checks to BLS-12 mul amd multiexp precompiles (#166)
* ipa-multipoint : Use debug-like to log the execption from the ffi::commit_to_scalars (#161)
* ipa-multipoint : Error handling and init no-copy in JNI (#158)
* ipa-multipoint : Removes pedersenHash method (#157)
* ipa-multipoint : Updates rust-verkle dependency (#156)
* ipa-multipoint : add update sparse commitment (#149)
* ipa-multipoint : add groupToField and return uncompressed serialized commitments (#146)
* ipa-multipoint : switch to LE bytes (#145)
* ipa-multipoint : update to a version of rust-verkle which uses little endian ipa-multipoint (#143)
* ipa-multipoint : Switch to `ffi_interface` ipa-multipoint (#139)
* ipa-multipoint : Modify test vectors to use canonical scalars for their input  (#142)
* ipa-multipoint : fix commit for verkle trie library(#141)
* ipa-multipoint : Fix linking error for LibIpaMultipoint(#131)

# 0.8.3

* add support for Mimc on bls12-377 [#132](https://github.com/besu-eth/besu-native/pull/132)
* FIX: javadoc issues [#125](https://github.com/besu-eth/besu-native/pull/125)
* ENH: adds ipa-multipoint library with Pedersen primitives [#123](https://github.com/besu-eth/besu-native/pull/123)
* Bump github.com/consensys/gnark-crypto in /gnark/gnark-jni [#122](https://github.com/besu-eth/besu-native/pull/122)

# 0.8.2

* Add k1 normalize signature method to secp256k1 [#118]](https://github.com/besu-eth/besu-native/pull/118)

# 0.8.1

* Handle incomplete input on modExp correctly [#114]](https://github.com/besu-eth/besu-native/pull/114)

# 0.8.0

* Add mimc/gnark library [#106](https://github.com/besu-eth/besu-native/pull/106)
* Change module names from `native` to `nativelib` [#108](https://github.com/besu-eth/besu-native/pull/108)
* Use Aurora's modexp implementation in arithmetic [#111](https://github.com/besu-eth/besu-native/pull/111)

# 0.7.0

* Add new "arithmetic" library to support basic (but expensive) arithmetic [#98](https://github.com/besu-eth/besu-native/pull/98)

# 0.6.2

* support computing proof with n arguments [#89](https://github.com/besu-eth/besu-native/pull/89)
* Java modules support [#90](https://github.com/besu-eth/besu-native/pull/90)
* Add CodeQL workflow for GitHub code scanning [#92](https://github.com/besu-eth/besu-native/pull/92)

# 0.6.1

* Update to latest jna, use separate build folders per os/arch [#79](https://github.com/besu-eth/besu-native/pull/79)
* Add linux arm64 build of bls12-381 [#81](https://github.com/besu-eth/besu-native/pull/81), [#80](https://github.com/besu-eth/besu-native/pull/80)
* Restrict builds of blake2f to x86-64 [#82](https://github.com/besu-eth/besu-native/pull/82) 

# 0.6.0

* Add native implementation of the Blake2bf compress function for EIP152 [#69](https://github.com/besu-eth/besu-native/pull/69)

# 0.5.0

* Add linux-arm64 native support [#61](https://github.com/besu-eth/besu-native/pull/61)
* Add ipa-multipoint library support [#56](https://github.com/besu-eth/besu-native/pull/56)

## 0.4.3

* Use non-blocking PRNG to generate secp256k1 context [#51](https://github.com/besu-eth/besu-native/pull/51)
* Padding R and S components if smaller than 31 bytes in SECP256R1 keys [#52](https://github.com/besu-eth/besu-native/pull/52)

## 0.4.2

* Fix Besu integration on MacOS [#48](https://github.com/besu-eth/besu-native/pull/48)

## 0.4.1

* Fix native representation of native secp256r1 signatures [#45](https://github.com/besu-eth/besu-native/pull/45)

## 0.4.0

* Added support for secp256r1 via OpenSSL libraries.

## 0.3.0

* Upgraded secp256k1 to commit ac05f61fcf639a15b5101131561620303e4bd808, which
  improves performance by using efficiently-computable endomorphism.
* Add support for MatterLab's EIP196/197 for ECPairings, which are faster than
  the sputnikvm code.

## 0.2.0

* Add support for EIP-2537 (BLS12-381 precompiles ) via MatterLabs library
* Randomize secp256k1 context by default, with java property
  `secp256k1.randomize` escape hatch to disable. In tight testing loop this
  flag should be set to false.

## 0.1.0

* Add support for AltBN128 precompiles via sputnik VM
* Add support for secp256k1 via Bitcoin core library
