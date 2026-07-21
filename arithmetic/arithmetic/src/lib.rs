/* Copyright contributors to Besu.
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
 */
mod arith;
mod mpnat;

use std::rc::Rc;
use std::io::Write;

use core::{
    cmp::{min, Ordering},
    mem::size_of,
};

#[derive(Debug, Clone)]
pub enum RuntimeError {
    /// Input was a bad format.
    BadFormat,
}


#[no_mangle]
pub extern "C" fn modexp_precompiled(
    i: *const std::os::raw::c_char,
    i_len: u32,
    o: *mut std::os::raw::c_char,
    o_len: *mut u32,
) -> u32 {
    let input_i8: &[libc::c_char] = unsafe { std::slice::from_raw_parts(i, i_len as usize) };
    let input: &[u8] = unsafe { std::mem::transmute(input_i8) };

    let raw_out_i8: &mut [libc::c_char] = unsafe { std::slice::from_raw_parts_mut(o, *o_len as usize) };
    let mut raw_out: &mut [u8] = unsafe { std::mem::transmute(raw_out_i8) };
    let answer = modexp_precompiled_impl(input);

    let written = raw_out.write(answer.as_slice());
    if let Ok(bytes_written) = written {
        unsafe { *o_len = bytes_written as u32 };
        0u32
    } else {
        1u32
    }
}


/// from revm - https://github.com/bluealloy/revm/blob/main/crates/revm_precompiles/src/modexp.rs
macro_rules! read_u64_with_overflow {
    ($input:expr,$from:expr,$to:expr, $overflow_limit:expr) => {{
        const SPLIT: usize = 32 - size_of::<u64>();
        let len = $input.len();
        let from_zero = min($from, len);
        let from = min(from_zero + SPLIT, len);
        let to = min($to, len);
        let overflow_bytes = &$input[from_zero..from];

        let mut len_bytes = [0u8; size_of::<u64>()];
        len_bytes[..to - from].copy_from_slice(&$input[from..to]);
        let out = u64::from_be_bytes(len_bytes) as usize;
        let overflow = !(out < $overflow_limit && overflow_bytes.iter().all(|&x| x == 0));
        (out, overflow)
    }};
}

/// from revm - https://github.com/bluealloy/revm/blob/main/crates/revm_precompiles/src/modexp.rs
fn modexp_precompiled_impl(input: &[u8]) -> Rc<Vec<u8>> {
    let len = input.len();
    let (base_len, base_overflow) = read_u64_with_overflow!(input, 0, 32, u32::MAX as usize);
    let (exp_len, exp_overflow) = read_u64_with_overflow!(input, 32, 64, u32::MAX as usize);
    let (mod_len, mod_overflow) = read_u64_with_overflow!(input, 64, 96, u32::MAX as usize);

    if base_overflow || mod_overflow {
        return Rc::new(Vec::new());
    }

    if base_len == 0 && mod_len == 0 {
        return Rc::new(Vec::new());
    }
    // set limit for exp overflow
    if exp_overflow {
        return Rc::new(Vec::new());
    }
    let base_start = 96;
    let base_end = base_start + base_len;
    let exp_end = base_end + exp_len;
    let mod_end = exp_end + mod_len;

    let read_big = |from: usize, to: usize| {
        let mut out = vec![0; to - from];
        let from = min(from, len);
        let to = min(to, len);
        out[..to - from].copy_from_slice(&input[from..to]);
        out
    };

    let base = read_big(base_start, base_end);
    let exponent = read_big(base_end, exp_end);
    let modulus = read_big(exp_end, mod_end);
    let bytes = modexp(base.as_slice(), exponent.as_slice(), modulus.as_slice());

    // write output to given memory, left padded and same length as the modulus.
    // always true except in the case of zero-length modulus, which leads to
    // output of length and value 1.
    match bytes.len().cmp(&mod_len) {
        Ordering::Equal => Rc::new(bytes.to_vec()),
        Ordering::Less => {
            let mut ret = Vec::with_capacity(mod_len);
            ret.extend(core::iter::repeat(0).take(mod_len - bytes.len()));
            ret.extend_from_slice(&bytes[..]);
            Rc::new(ret.to_vec())
        }
        Ordering::Greater => Rc::new(Vec::new()),
    }
}

// from aurora
/// Computes `(base ^ exp) % modulus`, where all values are given as big-endian
/// encoded bytes.
pub fn modexp(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
    let mut x = mpnat::MPNat::from_big_endian(base);
    let m = mpnat::MPNat::from_big_endian(modulus);
    if m.digits.len() == 1 && m.digits[0] == 0 {
        return Vec::new();
    }
    let result = x.modpow(exp, &m);
    result.to_big_endian()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modexp_precompiled() {
        let mut output_len: u32 = 32;
        let o_len_ptr = &mut output_len as *mut u32;

        let mut input = vec![0u8; 96];
        input[31] = 1;  // base_len = 1
        input[63] = 1;  // exp_len = 1
        input[95] = 1;  // mod_len = 1
        input.push(2);  // base = 2
        input.push(3);  // exp = 3
        input.push(5);  // mod = 5

        let input_i8: Vec<i8> = input.iter().map(|&x| x as i8).collect();
        let mut output = vec![0i8; output_len as usize];

        let result = modexp_precompiled(
            input_i8.as_ptr(),
            input_i8.len() as u32,
            output.as_mut_ptr(),
            o_len_ptr,
        );

		assert_eq!(result, 0); // Expect success
		assert_eq!(output_len, 1); // Expect output length to be 1
		assert_eq!(output[0], 3); // Expect output to be 3 (2^3 % 5 = 3)
    }
}