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

import "C"
import (
	"unsafe"

	mimcBls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	mimcBn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	poseidon2KoalaBear "github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
)

func MiMCBls12377Hash(b []byte) []byte {
	hasher := mimcBls12377.NewMiMC()
	hasher.Write(b)
	return hasher.Sum(nil)
}

func MiMCBn254Hash(b []byte) []byte {
	hasher := mimcBn254.NewMiMC()
	hasher.Write(b)
	return hasher.Sum(nil)
}

func Poseidon2KoalaBearHash(b []byte) []byte {
	hasher := poseidon2KoalaBear.NewMerkleDamgardHasher()
	hasher.Write(b)
	return hasher.Sum(nil)
}

//export computeMimcBn254
func computeMimcBn254(input *C.char, inputLength C.int, output *C.char) C.int {
	inputSlice := C.GoBytes(unsafe.Pointer(input), inputLength)
	outputSlice := (*[32]byte)(unsafe.Pointer(output))[:]
	hash := MiMCBn254Hash(inputSlice)
	copy(outputSlice, hash)
	return C.int(len(hash))
}

//export computeMimcBls12377
func computeMimcBls12377(input *C.char, inputLength C.int, output *C.char) C.int {
	inputSlice := C.GoBytes(unsafe.Pointer(input), inputLength)
	outputSlice := (*[32]byte)(unsafe.Pointer(output))[:]
	hash := MiMCBls12377Hash(inputSlice)
	copy(outputSlice, hash)
	return C.int(len(hash))
}

//export computePoseidon2Koalabear
func computePoseidon2Koalabear(input *C.char, inputLength C.int, output *C.char) C.int {
	inputSlice := C.GoBytes(unsafe.Pointer(input), inputLength)
	outputSlice := (*[32]byte)(unsafe.Pointer(output))[:]
	hash := Poseidon2KoalaBearHash(inputSlice)
	copy(outputSlice, hash)
	return C.int(len(hash))
}

func main() {}
