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
package main

/*
#include <string.h>
*/
import "C"
import (
	"bytes"
	"math/big"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type errorCode = C.int

// keep in sync with the Java code. We use constant values to avoid passing strings from Java to Go
const (
	errCodeSuccess                           errorCode = iota
	errCodeInvalidInputLengthEIP2537
	errCodePointNotInFieldEIP2537
	errCodePointInSubgroupCheckFailedEIP2537
	errCodePointOnCurveCheckFailedEIP2537
	errCodePairingCheckErrorEIP2537
	errCodeMalformedPointPaddingEIP2537
)

const (
	EIP2537PreallocateForScalar      = 32                          // scalar int is 32 byte
	EIP2537PreallocateForFp          = 64                          // G1 points are 48 bytes, left padded with zero for 16 bytes
	EIP2537PreallocateForG1          = EIP2537PreallocateForFp * 2 // G1 points are 48 bytes, left padded with zero for 16 bytes
	EIP2537PreallocateForG2          = EIP2537PreallocateForG1 * 2 // G2 comprise 2 G1 points, left padded with zero for 16 bytes
	EIP2537PreallocateForResultBytes = EIP2537PreallocateForG2     // maximum for G2 point
)

// Predefine a zero slice of length 16
var zeroSlice = make([]byte, 16)

// bls12381 modulus
var q *fp.Element

func init() {
	q = new(fp.Element).SetBigInt(fp.Modulus())
}

/*

eip2537blsG1Add adds two G1 points together and returns a G1 Point.

- Input:
  - javaInputBuf: Pointer to a buffer containing two G1 points
  - javaOutputBuf: Pointer to a buffer where the resulting G1 point will be written
  - cInputLen: Length of the input buffer in bytes

- Returns:
  - errCodeSuccess if successful, result is written to javaOutputBuf
  - non-zero error code on failure

- Cryptography:
  - The field elements that comprise the G1 input points must be checked to be canonical.
  - Check that both G1 input points are on the curve
  - Do not check that input points are in the correct subgroup (See EIP-2537)

- JNI:
  - javaInputBuf must be at least 2*EIP2537PreallocateForG1 bytes (two G1 points)
  - javaOutputBuf must be at least EIP2537PreallocateForG1 bytes to safely store the result
  - javaOutputBuf must be zero initialized
*/
//export eip2537blsG1Add
func eip2537blsG1Add(javaInputBuf, javaOutputBuf *C.char, cInputLen C.int) errorCode {
	inputLen := int(cInputLen)

	if inputLen != 2*EIP2537PreallocateForG1 {
		return errCodeInvalidInputLengthEIP2537
	}
	input := (*[2 * EIP2537PreallocateForG1]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	result, errCode := _blsG1Add(input)
	if errCode != errCodeSuccess {
		return errCode
	}

	nonMontgomeryMarshalG1(result, javaOutputBuf)
	return errCodeSuccess
}

func _blsG1Add(input []byte) (*bls12381.G1Affine, errorCode) {
	p0, errCode := g1AffineDecodeOnCurve(input[:128])
	if errCode != errCodeSuccess {
		return nil, errCode
	}

	p1, errCode := g1AffineDecodeOnCurve(input[128:])
	if errCode != errCodeSuccess {
		return nil, errCode
	}

	result := p0.Add(p0, p1)
	return result, errCodeSuccess
}

/*

eip2537blsG1MultiExp performs multi-scalar multiplication on multiple G1 points in parallel.

- Input:
  - javaInputBuf: Pointer to a buffer containing a series of G1 point and scalar pairs
  - javaOutputBuf: Pointer to a buffer where the resulting G1 point will be written
  - cInputLen: Length of the input buffer in bytes
  - nbTasks: Number of parallel tasks to use for computation

- Returns:
  - errCodeSuccess if successful, result is written to javaOutputBuf
  - non-zero error code on failure

- Cryptography:
  - The field elements that comprise the G1 input points must be checked to be canonical.
  - The scalars are not required to be canonical.
  - Check that all input points are on the curve and in the correct subgroup.

- JNI:
  - javaInputBuf must be at least n*(EIP2537PreallocateForG1 + EIP2537PreallocateForScalar) bytes
  - javaOutputBuf must be at least EIP2537PreallocateForG1 bytes to safely store the result
  - javaOutputBuf must be zero initialized
*/
//export eip2537blsG1MultiExp
func eip2537blsG1MultiExp(javaInputBuf, javaOutputBuf *C.char, cInputLen C.int, nbTasks C.int) errorCode {
	inputLen := int(cInputLen)

	if inputLen == 0 || inputLen%(EIP2537PreallocateForG1+EIP2537PreallocateForScalar) != 0 {
		return errCodeInvalidInputLengthEIP2537
	}
	input := castBufferToSlice(unsafe.Pointer(javaInputBuf), inputLen)

	result, errCode := _blsG1MultiExp(input, int(nbTasks))
	if errCode != errCodeSuccess {
		return errCode
	}

	nonMontgomeryMarshalG1(result, javaOutputBuf)
	return errCodeSuccess
}

func _blsG1MultiExp(input []byte, nbTasks int) (*bls12381.G1Affine, errorCode) {
	var exprCount = len(input) / (EIP2537PreallocateForG1 + EIP2537PreallocateForScalar)

	g1Points := make([]bls12381.G1Affine, exprCount)
	scalars := make([]fr.Element, exprCount)

	for i := 0; i < exprCount; i++ {
		g1, errCode := g1AffineDecodeInSubGroup(input[i*160 : (i*160)+128])
		if errCode != errCodeSuccess {
			return nil, errCode
		}

		g1Points[i].Set(g1)
		scalars[i].SetBytes(input[(i*160)+128 : (i+1)*160])
	}

	// When the size of the multi scalar multiplication(MSM) is 1, this corresponds to
	// a scalar multiplication so we use the simpler scalar multiplication algorithm to
	// compute the MSM instead of using the general MSM algorithm. This is in accordance
	// with EIP-2537.
	//
	// When the MSM is of size 2 -- heuristically it has been shown to be faster than
	// using the general MSM algorithm, so we also special case it.
	if exprCount == 1 {
		var result bls12381.G1Affine
		var bi big.Int
		scalars[0].BigInt(&bi)
		result.ScalarMultiplication(&g1Points[0], &bi)
		return &result, errCodeSuccess
	} else if exprCount == 2 {
		var result bls12381.G1Affine
		var tmp bls12381.G1Affine
		var bi big.Int

		scalars[0].BigInt(&bi)
		tmp.ScalarMultiplication(&g1Points[0], &bi)

		scalars[1].BigInt(&bi)
		result.ScalarMultiplication(&g1Points[1], &bi)

		result.Add(&result, &tmp)
		return &result, errCodeSuccess
	}

	var affineResult bls12381.G1Affine
	_, err := affineResult.MultiExp(g1Points, scalars, ecc.MultiExpConfig{NbTasks: nbTasks})
	if err != nil {
		return nil, errCodePairingCheckErrorEIP2537
	}

	return &affineResult, errCodeSuccess
}

/*

eip2537blsG2Add adds two G2 points together and returns a G2 Point.

- Input:
  - javaInputBuf: Pointer to a buffer containing two G2 points
  - javaOutputBuf: Pointer to a buffer where the resulting G2 point will be written
  - cInputLen: Length of the input buffer in bytes

- Returns:
  - errCodeSuccess if successful, result is written to javaOutputBuf
  - non-zero error code on failure

- Cryptography:
  - The field elements that comprise the G2 input points must be checked to be canonical.
  - Check that both input points are on the curve
  - Do not check that input points are in the correct subgroup (See EIP-2537)

- JNI:
  - javaInputBuf must be at least 2*EIP2537PreallocateForG2 bytes (two G2 points)
  - javaOutputBuf must be at least EIP2537PreallocateForG2 bytes to safely store the result
  - javaOutputBuf must be zero initialized
*/
//export eip2537blsG2Add
func eip2537blsG2Add(javaInputBuf, javaOutputBuf *C.char, cInputLen C.int) errorCode {
	inputLen := int(cInputLen)

	if inputLen != 2*EIP2537PreallocateForG2 {
		return errCodeInvalidInputLengthEIP2537
	}
	input := (*[2 * EIP2537PreallocateForG2]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	result, errCode := _blsG2Add(input)
	if errCode != errCodeSuccess {
		return errCode
	}

	nonMontgomeryMarshalG2(result, javaOutputBuf)
	return errCodeSuccess
}

func _blsG2Add(input []byte) (*bls12381.G2Affine, errorCode) {
	p0, errCode := g2AffineDecodeOnCurve(input[:256])
	if errCode != errCodeSuccess {
		return nil, errCode
	}

	p1, errCode := g2AffineDecodeOnCurve(input[256:])
	if errCode != errCodeSuccess {
		return nil, errCode
	}

	result := p0.Add(p0, p1)
	return result, errCodeSuccess
}

/*

eip2537blsG2MultiExp performs multi-scalar multiplication on multiple G2 points in parallel.

- Input:
  - javaInputBuf: Pointer to a buffer containing a series of G2 point and scalar pairs
  - javaOutputBuf: Pointer to a buffer where the resulting G2 point will be written
  - cInputLen: Length of the input buffer in bytes
  - nbTasks: Number of parallel tasks to use for computation.

- Returns:
  - errCodeSuccess if successful, result is written to javaOutputBuf
  - non-zero error code on failure

- Cryptography:
  - The field elements that comprise the G2 input points must be checked to be canonical.
  - Check that all input points are on the curve and in the correct subgroup.

- JNI:
  - javaInputBuf must be at least n*(EIP2537PreallocateForG2 + EIP2537PreallocateForScalar) bytes
  - javaOutputBuf must be at least EIP2537PreallocateForG2 bytes to safely store the result
  - javaOutputBuf must be zero initialized
*/
//export eip2537blsG2MultiExp
func eip2537blsG2MultiExp(javaInputBuf, javaOutputBuf *C.char, cInputLen C.int, nbTasks C.int) errorCode {
	inputLen := int(cInputLen)

	if inputLen == 0 || inputLen%(EIP2537PreallocateForG2+EIP2537PreallocateForScalar) != 0 {
		return errCodeInvalidInputLengthEIP2537
	}
	input := castBufferToSlice(unsafe.Pointer(javaInputBuf), inputLen)

	result, errCode := _blsG2MultiExp(input, int(nbTasks))
	if errCode != errCodeSuccess {
		return errCode
	}

	nonMontgomeryMarshalG2(result, javaOutputBuf)
	return errCodeSuccess
}

func _blsG2MultiExp(input []byte, nbTasks int) (*bls12381.G2Affine, errorCode) {
	var exprCount = len(input) / (EIP2537PreallocateForG2 + EIP2537PreallocateForScalar)

	g2Points := make([]bls12381.G2Affine, exprCount)
	scalars := make([]fr.Element, exprCount)

	for i := 0; i < exprCount; i++ {
		g2Point, errCode := g2AffineDecodeInSubGroup(input[i*288 : (i*288)+256])
		if errCode != errCodeSuccess {
			return nil, errCode
		}

		g2Points[i].Set(g2Point)
		scalars[i].SetBytes(input[(i*288)+256 : (i+1)*288])
	}

	// When the size of the multi scalar multiplication(MSM) is 1, this corresponds to
	// a scalar multiplication so we use the simpler scalar multiplication algorithm to
	// compute the MSM instead of using the general MSM algorithm. This is in accordance
	// with EIP-2537.
	//
	// When the MSM is of size 2 -- heuristically it has been shown to be faster than
	// using the general MSM algorithm, so we also special case it.
	if exprCount == 1 {
		var result bls12381.G2Affine
		var bi big.Int
		scalars[0].BigInt(&bi)
		result.ScalarMultiplication(&g2Points[0], &bi)
		return &result, errCodeSuccess
	} else if exprCount == 2 {
		var result bls12381.G2Affine
		var tmp bls12381.G2Affine
		var bi big.Int

		scalars[0].BigInt(&bi)
		tmp.ScalarMultiplication(&g2Points[0], &bi)

		scalars[1].BigInt(&bi)
		result.ScalarMultiplication(&g2Points[1], &bi)

		result.Add(&result, &tmp)
		return &result, errCodeSuccess
	}

	var affineResult bls12381.G2Affine
	_, err := affineResult.MultiExp(g2Points, scalars, ecc.MultiExpConfig{NbTasks: nbTasks})
	if err != nil {
		return nil, errCodePairingCheckErrorEIP2537
	}

	return &affineResult, errCodeSuccess
}

/*

eip2537blsPairing performs a pairing check on a collection of G1 and G2 point pairs.

- Input:
  - javaInputBuf: Pointer to a buffer containing a series of G1 and G2 point pairs
  - javaOutputBuf: Pointer to a buffer where the result (32-byte value) will be written
  - cInputLen: Length of the input buffer in bytes

- Returns:
  - errCodeSuccess if successful, javaOutputBuf contains a 32-byte value: 0x01 if pairing check succeeded, 0x00 otherwise
  - non-zero error code on failure

- Cryptography:
  - The field elements that comprise the input points must be checked to be canonical.
  - Check that all input points are on the curve and in the correct subgroup.

- JNI:
  - javaInputBuf must be at least n*(EIP2537PreallocateForG1 + EIP2537PreallocateForG2) bytes
  - javaOutputBuf must be at least 32 bytes to safely store the result (0x01 for success, 0x00 otherwise)
  - javaOutputBuf must be zero initialized
*/
//export eip2537blsPairing
func eip2537blsPairing(javaInputBuf, javaOutputBuf *C.char, cInputLen C.int) errorCode {
	inputLen := int(cInputLen)

	if inputLen < (EIP2537PreallocateForG2+EIP2537PreallocateForG1) ||
		inputLen%(EIP2537PreallocateForG2+EIP2537PreallocateForG1) != 0 {
		return errCodeInvalidInputLengthEIP2537
	}
	input := castBufferToSlice(unsafe.Pointer(javaInputBuf), inputLen)

	isOne, errCode := _blsPairing(input)
	if errCode != errCodeSuccess {
		return errCode
	}

	if isOne {
		output := (*[32]byte)(unsafe.Pointer(javaOutputBuf))
		output[31] = 0x01
	}

	return errCodeSuccess
}

func _blsPairing(input []byte) (bool, errorCode) {
	var pairCount = len(input) / (EIP2537PreallocateForG2 + EIP2537PreallocateForG1)

	g1Points := make([]bls12381.G1Affine, pairCount)
	g2Points := make([]bls12381.G2Affine, pairCount)

	for i := 0; i < pairCount; i++ {
		g1, errCode := g1AffineDecodeInSubGroup(input[i*384 : i*384+128])
		if errCode != errCodeSuccess {
			return false, errCode
		}

		g2, errCode := g2AffineDecodeInSubGroup(input[i*384+128 : (i+1)*384])
		if errCode != errCodeSuccess {
			return false, errCode
		}

		g1Points[i] = *g1
		g2Points[i] = *g2
	}

	isOne, err := bls12381.PairingCheck(g1Points, g2Points)
	if err != nil {
		return false, errCodePairingCheckErrorEIP2537
	}

	return isOne, errCodeSuccess
}

/*

eip2537blsMapFpToG1 maps a field element to a point on the G1 curve.

- Input:
  - javaInputBuf: Pointer to a buffer containing one Fp field element
  - javaOutputBuf: Pointer to a buffer where the resulting G1 point will be written
  - cInputLen: Length of the input buffer in bytes

- Returns:
  - errCodeSuccess if successful, result is written to javaOutputBuf
  - non-zero error code on failure

- Cryptography:
  - The input field element must be checked to be canonical.
  - The resulting point is guaranteed to be on the curve and in the correct subgroup.

- JNI:
  - javaInputBuf must be at least EIP2537PreallocateForFp bytes to store the input field element
  - javaOutputBuf must be at least EIP2537PreallocateForG1 bytes to safely store the result
  - javaOutputBuf must be zero initialized
*/
//export eip2537blsMapFpToG1
func eip2537blsMapFpToG1(javaInputBuf, javaOutputBuf *C.char, cInputLen C.int) errorCode {
	inputLen := int(cInputLen)

	if inputLen != EIP2537PreallocateForFp {
		return errCodeInvalidInputLengthEIP2537
	}
	input := (*[EIP2537PreallocateForFp]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	result, errCode := _blsMapFpToG1(input)
	if errCode != errCodeSuccess {
		return errCode
	}

	nonMontgomeryMarshalG1(result, javaOutputBuf)
	return errCodeSuccess
}

func _blsMapFpToG1(input []byte) (*bls12381.G1Affine, errorCode) {
	if !isZero(input[:16]) {
		return nil, errCodeMalformedPointPaddingEIP2537
	}

	var fpElem fp.Element
	if err := fpElem.SetBytesCanonical(input[16:64]); err != nil {
		return nil, errCodePointNotInFieldEIP2537
	}

	result := bls12381.MapToG1(fpElem)
	return &result, errCodeSuccess
}

/*

eip2537blsMapFp2ToG2 maps a field element in the quadratic extension field Fp^2 to a point on the G2 curve.

- Input:
  - javaInputBuf: Pointer to a buffer containing one Fp^2 field element (two Fp elements)
  - javaOutputBuf: Pointer to a buffer where the resulting G2 point will be written
  - cInputLen: Length of the input buffer in bytes

- Returns:
  - errCodeSuccess if successful, result is written to javaOutputBuf
  - non-zero error code on failure

- Cryptography:
  - The input field elements must be checked to be canonical.
  - The resulting point is guaranteed to be on the curve and in the correct subgroup.

- JNI:
  - javaInputBuf must be at least 2*EIP2537PreallocateForFp bytes to store the input Fp^2 field element
  - javaOutputBuf must be at least EIP2537PreallocateForG2 bytes to safely store the result
  - javaOutputBuf must be zero initialized
*/
//export eip2537blsMapFp2ToG2
func eip2537blsMapFp2ToG2(javaInputBuf, javaOutputBuf *C.char, cInputLen C.int) errorCode {
	inputLen := int(cInputLen)

	if inputLen != 2*EIP2537PreallocateForFp {
		return errCodeInvalidInputLengthEIP2537
	}
	input := (*[2 * EIP2537PreallocateForFp]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	result, errCode := _blsMapFp2ToG2(input)
	if errCode != errCodeSuccess {
		return errCode
	}

	nonMontgomeryMarshalG2(result, javaOutputBuf)
	return errCodeSuccess
}

func _blsMapFp2ToG2(input []byte) (*bls12381.G2Affine, errorCode) {
	if hasWrongG1Padding(input) {
		return nil, errCodeMalformedPointPaddingEIP2537
	}

	var g2 bls12381.G2Affine
	if err := g2.X.A0.SetBytesCanonical(input[16:64]); err != nil {
		return nil, errCodePointNotInFieldEIP2537
	}
	if err := g2.X.A1.SetBytesCanonical(input[80:128]); err != nil {
		return nil, errCodePointNotInFieldEIP2537
	}

	result := bls12381.MapToG2(g2.X)
	return &result, errCodeSuccess
}

// isZero checks if the first 16 bytes of a byte slice are all zeros.
func isZero(slice []byte) bool {
	return bytes.Equal(slice[:16], zeroSlice)
}

// hasWrongG1Padding returns true if the G1 element is not correctly padded.
func hasWrongG1Padding(input []byte) bool {
	return !isZero(input[:16]) || !isZero(input[64:80])
}

// hasWrongG2Padding returns true if the G2 element is not correctly aligned.
func hasWrongG2Padding(input []byte) bool {
	return !isZero(input[:16]) || !isZero(input[64:80]) || !isZero(input[128:144]) || !isZero(input[192:208])
}

/*

eip2537G1IsInSubGroup checks if a G1 point is in the correct subgroup.

- Input:
  - javaInputBuf: Pointer to a buffer containing a G1 point
  - cInputLen: Length of the input buffer in bytes

- Returns:
  - errCodeSuccess if the G1 point is on the curve and in the subgroup
  - non-zero error code indicating the specific reason for rejection
*/
//export eip2537G1IsInSubGroup
func eip2537G1IsInSubGroup(javaInputBuf *C.char, cInputLen C.int) errorCode {
	inputLen := int(cInputLen)

	if inputLen != EIP2537PreallocateForG1 {
		return errCodeInvalidInputLengthEIP2537
	}
	input := (*[EIP2537PreallocateForG1]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	_, errCode := g1AffineDecodeInSubGroup(input)
	return errCode
}

// g1AffineDecodeInSubGroup decodes a byte slice into a G1 affine point and verifies
// that the point is on the curve and in the correct subgroup.
func g1AffineDecodeInSubGroup(input []byte) (*bls12381.G1Affine, errorCode) {
	g1, errCode := g1AffineDecodeOnCurve(input)
	if errCode != errCodeSuccess {
		return nil, errCode
	}

	if !g1.IsInSubGroup() {
		return nil, errCodePointInSubgroupCheckFailedEIP2537
	}
	return g1, errCodeSuccess
}

/*

eip2537G1IsOnCurve checks if a G1 point is on the curve.

- Input:
  - javaInputBuf: Pointer to a buffer containing a G1 point
  - cInputLen: Length of the input buffer in bytes

- Returns:
  - errCodeSuccess if the G1 point is on the curve
  - non-zero error code indicating the specific reason for rejection
*/
//export eip2537G1IsOnCurve
func eip2537G1IsOnCurve(javaInputBuf *C.char, cInputLen C.int) errorCode {
	inputLen := int(cInputLen)

	if inputLen != EIP2537PreallocateForG1 {
		return errCodeInvalidInputLengthEIP2537
	}
	input := (*[EIP2537PreallocateForG1]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	_, errCode := g1AffineDecodeOnCurve(input)
	return errCode
}

// g1AffineDecodeOnCurve decodes a byte slice into a G1 affine point and verifies
// that the point is on the curve, without performing a subgroup check.
func g1AffineDecodeOnCurve(input []byte) (*bls12381.G1Affine, errorCode) {
	if hasWrongG1Padding(input) {
		return nil, errCodeMalformedPointPaddingEIP2537
	}
	var g1x, g1y fp.Element
	if err := g1x.SetBytesCanonical(input[16:64]); err != nil {
		return nil, errCodePointNotInFieldEIP2537
	}
	if err := g1y.SetBytesCanonical(input[80:128]); err != nil {
		return nil, errCodePointNotInFieldEIP2537
	}

	g1 := &bls12381.G1Affine{X: g1x, Y: g1y}
	if !g1.IsOnCurve() {
		return nil, errCodePointOnCurveCheckFailedEIP2537
	}

	return g1, errCodeSuccess
}

/*

eip2537G2IsInSubGroup checks if a G2 point is in the correct subgroup.

- Input:
  - javaInputBuf: Pointer to a buffer containing a G2 point
  - cInputLen: Length of the input buffer in bytes

- Returns:
  - errCodeSuccess if the G2 point is on the curve and in the subgroup
  - non-zero error code indicating the specific reason for rejection
*/
//export eip2537G2IsInSubGroup
func eip2537G2IsInSubGroup(javaInputBuf *C.char, cInputLen C.int) errorCode {
	inputLen := int(cInputLen)

	if inputLen != EIP2537PreallocateForG2 {
		return errCodeInvalidInputLengthEIP2537
	}
	input := (*[EIP2537PreallocateForG2]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	_, errCode := g2AffineDecodeInSubGroup(input)
	return errCode
}

// g2AffineDecodeInSubGroup decodes a byte slice into a G2 affine point and verifies
// that the point is on the curve and in the correct subgroup.
func g2AffineDecodeInSubGroup(input []byte) (*bls12381.G2Affine, errorCode) {
	g2, errCode := g2AffineDecodeOnCurve(input)
	if errCode != errCodeSuccess {
		return nil, errCode
	}

	if !g2.IsInSubGroup() {
		return nil, errCodePointInSubgroupCheckFailedEIP2537
	}
	return g2, errCodeSuccess
}

/*

eip2537G2IsOnCurve checks if a G2 point is on the curve.

- Input:
  - javaInputBuf: Pointer to a buffer containing a G2 point
  - cInputLen: Length of the input buffer in bytes

- Returns:
  - errCodeSuccess if the G2 point is on the curve
  - non-zero error code indicating the specific reason for rejection
*/
//export eip2537G2IsOnCurve
func eip2537G2IsOnCurve(javaInputBuf *C.char, cInputLen C.int) errorCode {
	inputLen := int(cInputLen)

	if inputLen != EIP2537PreallocateForG2 {
		return errCodeInvalidInputLengthEIP2537
	}
	input := (*[EIP2537PreallocateForG2]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	_, errCode := g2AffineDecodeOnCurve(input)
	return errCode
}

// g2AffineDecodeOnCurve decodes a byte slice into a G2 affine point and verifies
// that the point is on the curve, without performing a subgroup check.
func g2AffineDecodeOnCurve(input []byte) (*bls12381.G2Affine, errorCode) {
	if hasWrongG2Padding(input) {
		return nil, errCodeMalformedPointPaddingEIP2537
	}

	var g2 bls12381.G2Affine
	if err := g2.X.A0.SetBytesCanonical(input[16:64]); err != nil {
		return nil, errCodePointNotInFieldEIP2537
	}
	if err := g2.X.A1.SetBytesCanonical(input[80:128]); err != nil {
		return nil, errCodePointNotInFieldEIP2537
	}
	if err := g2.Y.A0.SetBytesCanonical(input[144:192]); err != nil {
		return nil, errCodePointNotInFieldEIP2537
	}
	if err := g2.Y.A1.SetBytesCanonical(input[208:256]); err != nil {
		return nil, errCodePointNotInFieldEIP2537
	}

	if !g2.IsOnCurve() {
		return nil, errCodePointOnCurveCheckFailedEIP2537
	}
	return &g2, errCodeSuccess
}

// castBufferToSlice converts an unsafe.Pointer to a Go byte slice of specified length.
//
// SAFETY: unsafe.Slice creates a slice that directly references
// the underlying memory. The caller must ensure that the memory remains valid for the
// lifetime of the slice.
func castBufferToSlice(buf unsafe.Pointer, length int) []byte {
	return unsafe.Slice((*byte)(buf), length)
}

// nonMontgomeryMarshal encodes a pair of base field elements as byte slices
// in big-endian form and writes them to the output buffer at the specified offset.
func nonMontgomeryMarshal(xVal, yVal *fp.Element, output *C.char, outputOffset int) {
	var x big.Int
	xVal.BigInt(&x)
	xBytes := x.Bytes()
	xLen := len(xBytes)

	if xLen > 0 {
		srcPtr := unsafe.Pointer(&xBytes[0])
		destAddr := uintptr(unsafe.Pointer(output)) + uintptr(outputOffset+64-xLen)
		destPtr := unsafe.Pointer(destAddr)
		C.memcpy(destPtr, srcPtr, C.size_t(xLen))
	}

	var y big.Int
	yVal.BigInt(&y)
	yBytes := y.Bytes()
	yLen := len(yBytes)

	if yLen > 0 {
		srcPtr := unsafe.Pointer(&yBytes[0])
		destAddr := uintptr(unsafe.Pointer(output)) + uintptr(outputOffset+128-yLen)
		destPtr := unsafe.Pointer(destAddr)
		C.memcpy(destPtr, srcPtr, C.size_t(yLen))
	}
}

// nonMontgomeryMarshalG1 converts a G1 affine point to its serialized form following EIP-2537
// and writes it to the output buffer.
func nonMontgomeryMarshalG1(g1 *bls12381.G1Affine, output *C.char) {
	nonMontgomeryMarshal(&g1.X, &g1.Y, output, 0)
}

// nonMontgomeryMarshalG2 converts a G2 affine point to its serialized form following EIP-2537
// and writes it to the output buffer.
func nonMontgomeryMarshalG2(g2 *bls12381.G2Affine, output *C.char) {
	nonMontgomeryMarshal(&g2.X.A0, &g2.X.A1, output, 0)
	nonMontgomeryMarshal(&g2.Y.A0, &g2.Y.A1, output, 128)
}

func main() {}
