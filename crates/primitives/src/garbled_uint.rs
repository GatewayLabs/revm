use alloy_primitives::Uint;
use compute::{int::GarbledInt, uint::GarbledUint};
use std::vec;
use std::vec::Vec;

pub fn ruint_to_garbled_uint(value: &Uint<256, 4>) -> GarbledUint<256> {
    let bytes: [u8; 32] = value.to_le_bytes();

    let bits: Vec<bool> = bytes
        .iter()
        .flat_map(|&byte| (0..8).map(move |i| ((byte >> i) & 1) == 1))
        .collect();

    GarbledUint::<256>::new(bits)
}

pub fn garbled_uint_to_ruint<const BITS: usize>(garbled_uint: &GarbledUint<BITS>) -> Uint<BITS, 4> {
    let mut bytes = vec![0u8; (BITS + 7) / 8];
    let bits = &garbled_uint.bits;

    for (byte_idx, chunk) in bits.chunks(8).enumerate() {
        if byte_idx >= bytes.len() {
            break;
        }

        let mut byte_value = 0u8;
        for (bit_idx, &bit) in chunk.iter().enumerate() {
            if bit_idx < 8 {
                if bit {
                    byte_value |= 1 << bit_idx;
                }
            }
        }

        bytes[byte_idx] = byte_value;
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Uint::from_le_bytes(array)
}

pub fn ruint_to_garbled_uint64(value: &Uint<256, 4>) -> GarbledUint<64> {
    let bytes: [u8; 32] = value.to_le_bytes();

    let mut bits = Vec::with_capacity(64);
    for byte in bytes.iter().take(8) {
        for i in 0..8 {
            bits.push((byte & (1 << i)) != 0);
        }
    }

    GarbledUint::<64>::new(bits)
}

pub fn garbled_uint64_to_ruint<const N: usize>(value: &GarbledUint<N>) -> Uint<256, 4> {
    // Ensure we don't exceed the maximum number of chunks
    let chunk_count = (value.bits.len() + 7) / 8;
    let bytes: Vec<u8> = value
        .bits
        .chunks(8)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(0, |byte, (i, &bit)| byte | ((bit as u8) << i))
        })
        .collect();

    // Create a full array of zeros
    let mut array = [0u8; 32];
    // Copy only the available bytes
    array[..chunk_count].copy_from_slice(&bytes[..chunk_count]);
    Uint::from_le_bytes(array)
}

pub fn garbled_uint_to_bool(value: &GarbledUint<256>) -> bool {
    value.bits[0]
}

pub fn ruint_to_garbled_int(value: &Uint<256, 4>) -> GarbledInt<256> {
    let bytes: [u8; 32] = value.to_le_bytes();

    let bits: Vec<bool> = bytes
        .iter()
        .flat_map(|&byte| (0..8).map(move |i| ((byte >> i) & 1) == 1))
        .collect();

    GarbledInt::<256>::new(bits)
}

pub fn garbled_int_to_ruint(value: &GarbledInt<256>) -> Uint<256, 4> {
    let bytes: Vec<u8> = value
        .bits
        .chunks(8)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(0, |byte, (i, &bit)| byte | ((bit as u8) << i))
        })
        .collect();

    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Uint::from_le_bytes(array)
}
