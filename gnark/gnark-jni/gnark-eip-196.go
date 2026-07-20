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
	"errors"
	"math/big"
	"sync"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type errorCode = C.int

// keep in sync with the Java code. We use constant value to avoid passing strings from Java to Go
const (
	errCodeSuccess errorCode = iota
	errCodeInvalidInputPairingLengthEIP196
	errCodePointNotInFieldEIP196
	errCodePointInSubgroupCheckFailedEIP196
	errCodePointOnCurveCheckFailedEIP196
	errCodePairingCheckErrorEIP196
)

const (
	EIP196PreallocateForScalar = 32                         // scalar int is 32 byte
	EIP196PreallocateForFp     = 32                         // field elements are 32 bytes
	EIP196PreallocateForG1     = EIP196PreallocateForFp * 2 // G1 points are encoded as 2 concatenated field elements
	EIP196PreallocateForG2     = EIP196PreallocateForG1 * 2 // G2 points are encoded as 2 concatenated G1 points
)

var bigIntPool = sync.Pool{
	New: func() any {
		return new(big.Int)
	},
}

var EIP196ScalarTwo = big.NewInt(2)

//export eip196altbn128G1Add
func eip196altbn128G1Add(javaInputBuf, javaOutputBuf *C.char, cInputLen C.int) errorCode {
	inputLen := min(int(cInputLen), 2*EIP196PreallocateForG1) // max input length is 2 G1 points
	if inputLen == 0 {
		return errCodeSuccess
	}

	// Convert input C pointers to Go slices
	input := (*[2 * EIP196PreallocateForG1]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	// generate p0 g1 affine
	var p0 bn254.G1Affine
	if err := safeUnmarshalEIP196(&p0, input, 0); err != errCodeSuccess {
		return err
	}

	if inputLen < 2*EIP196PreallocateForG1 {
		// if incomplete input is all zero, return p0
		if isAllZeroEIP196(input, 64, 64) {
			g1AffineEncode(&p0, javaOutputBuf)
			return errCodeSuccess
		}
	}
	// generate p1 g1 affine
	var p1 bn254.G1Affine
	if err := safeUnmarshalEIP196(&p1, input, 64); err != errCodeSuccess {
		return err
	}

	// Use the Add method to combine points
	p0.Add(&p0, &p1)

	// marshal the resulting point and encode directly to the output buffer
	g1AffineEncode(&p0, javaOutputBuf)
	return errCodeSuccess

}

//export eip196altbn128G1Mul
func eip196altbn128G1Mul(javaInputBuf, javaOutputBuf *C.char, cInputLen C.int) errorCode {
	inputLen := int(cInputLen)

	if inputLen == 0 {
		// zero input returns 0
		return errCodeSuccess
	}

	if inputLen > EIP196PreallocateForG1+EIP196PreallocateForScalar {
		// trunc if input too long
		inputLen = EIP196PreallocateForG1 + EIP196PreallocateForScalar
	}

	// Convert input C pointers to Go slice
	input := (*[EIP196PreallocateForG1 + EIP196PreallocateForScalar]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	// infinity check:
	if isAllZeroEIP196(input, 0, 64) {
		return errCodeSuccess
	}

	// generate p0 g1 affine
	var p0 bn254.G1Affine
	if err := safeUnmarshalEIP196(&p0, input, 0); err != errCodeSuccess {
		return err
	}

	if inputLen < EIP196PreallocateForG1+1 {
		// if there is not even a partial input scalar, return 0
		return errCodeSuccess
	}

	// Convert byte slice to *big.Int
	scalarBytes := input[EIP196PreallocateForG1:]
	if 96 > int(cInputLen) {
		// if the input is truncated, copy the bytes to the high order portion of the scalar
		var bytes32 [32]byte
		scalarBytes = bytes32[:]
		copy(scalarBytes[:], input[64:int(cInputLen)])
	}

	scalar := bigIntPool.Get().(*big.Int)
	defer bigIntPool.Put(scalar)
	scalar.SetBytes(scalarBytes[:])

	var result *bn254.G1Affine
	if scalar.Cmp(EIP196ScalarTwo) == 0 {
		// if scalar == 2, double is faster
		result = p0.Double(&p0)
	} else {
		// multiply g1 point by scalar
		result = p0.ScalarMultiplication(&p0, scalar)
	}

	// marshal the resulting point and encode directly to the output buffer
	g1AffineEncode(result, javaOutputBuf)
	return errCodeSuccess
}

//export eip196altbn128Pairing
func eip196altbn128Pairing(javaInputBuf, javaOutputBuf *C.char, cInputLen C.int) C.int {
	inputLen := int(cInputLen)

	if inputLen == 0 {
		// Empty input means pairing succeeded with result 1
		output := (*[32]byte)(unsafe.Pointer(javaOutputBuf))
		output[31] = 0x01
		return errCodeSuccess
	}

	if inputLen%(EIP196PreallocateForG2+EIP196PreallocateForG1) != 0 {
		return errCodeInvalidInputPairingLengthEIP196
	}

	// Convert input C pointers to Go slice
	input := castBufferToSliceEIP196(unsafe.Pointer(javaInputBuf), inputLen)

	var pairCount = inputLen / (EIP196PreallocateForG2 + EIP196PreallocateForG1)
	g1Points := make([]bn254.G1Affine, pairCount)
	g2Points := make([]bn254.G2Affine, pairCount)

	for i := 0; i < pairCount; i++ {

		// g1 x and y are the first 64 bytes of each 192 byte pair
		if err := safeUnmarshalEIP196(&g1Points[i], input[i*192:i*192+64], 0); err != errCodeSuccess {
			return err
		}

		// g2 points are latter 128 bytes of each 192 byte pair
		if err := safeUnmarshalG2EIP196(&g2Points[i], input[i*192+64:(i+1)*192]); err != errCodeSuccess {
			return err
		}
	}

	isOne, err := bn254.PairingCheck(g1Points, g2Points)
	if err != nil {
		// this indicates internal pairing check error. Knowing gnark, it only happens when the input slices are with unequal lengths.
		// we have constructed them to be of equal length, so it is a sanity check
		return errCodePairingCheckErrorEIP196
	}

	// Write result to output buffer
	output := (*[32]byte)(unsafe.Pointer(javaOutputBuf))
	if isOne {
		output[31] = 0x01
	}
	// else: output is already zero-initialized on Java side

	return errCodeSuccess
}

func g1AffineEncode(point *bn254.G1Affine, output *C.char) error {
	// Check if point is not nil
	if point == nil {
		return errors.New("point cannot be nil")
	}
	bts := point.RawBytes()

	copy((*[64]byte)(unsafe.Pointer(output))[:], bts[:])

	return nil
}

func safeUnmarshalEIP196(g1 *bn254.G1Affine, input []byte, offset int) errorCode {
	var pointBytes []byte

	// If we effectively have _NO_ input, return empty
	if len(input)-offset <= 0 {
		return errCodeSuccess
	} else if len(input)-offset < 64 {
		// If we have some input, but it is incomplete, pad with zero
		var bytes64 [64]byte
		pointBytes = bytes64[:]
		shortLen := len(input) - offset
		copy(pointBytes, input[offset:len(input)])
		for i := shortLen; i < 64; i++ {
			pointBytes[i] = 0
		}
	} else {
		pointBytes = input[offset : offset+64]
	}

	if err := g1.X.SetBytesCanonical(pointBytes[0:32]); err != nil {
		return errCodePointNotInFieldEIP196
	}
	if err := g1.Y.SetBytesCanonical(pointBytes[32:64]); err != nil {
		return errCodePointNotInFieldEIP196
	}
	if !g1.IsOnCurve() {
		return errCodePointOnCurveCheckFailedEIP196
	}

	return errCodeSuccess
}

func safeUnmarshalG2EIP196(g2 *bn254.G2Affine, input []byte) errorCode {
	if len(input) < EIP196PreallocateForG2 {
		return errCodeInvalidInputPairingLengthEIP196
	}

	if err := g2.X.A1.SetBytesCanonical(input[:32]); err != nil {
		return errCodePointNotInFieldEIP196
	}
	if err := g2.X.A0.SetBytesCanonical(input[32:64]); err != nil {
		return errCodePointNotInFieldEIP196
	}
	if err := g2.Y.A1.SetBytesCanonical(input[64:96]); err != nil {
		return errCodePointNotInFieldEIP196
	}
	if err := g2.Y.A0.SetBytesCanonical(input[96:128]); err != nil {
		return errCodePointNotInFieldEIP196
	}

	if !g2.IsOnCurve() {
		return errCodePointOnCurveCheckFailedEIP196
	}
	if !g2.IsInSubGroup() {
		return errCodePointInSubgroupCheckFailedEIP196
	}

	return errCodeSuccess
}

// isAllZero checks if all elements in the byte slice are zero
func isAllZeroEIP196(data []byte, offset, length int) bool {

	if len(data) > offset {
		tail := offset + length
		if len(data) < tail {
			tail = len(data)
		}
		slice := data[offset:tail]
		for _, b := range slice {
			if b != 0 {
				return false
			}
		}
	}
	return true
}

func castBufferToSliceEIP196(buf unsafe.Pointer, length int) []byte {
	return unsafe.Slice((*byte)(buf), length)
}

func main() {
}
