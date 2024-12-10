use compute::{int::GarbledInt, uint::GarbledUint};
use primitives::ruint::Uint;

pub(crate) unsafe fn read_i16(ptr: *const u8) -> i16 {
    i16::from_be_bytes(core::slice::from_raw_parts(ptr, 2).try_into().unwrap())
}

pub fn uint_to_i64(value: &Uint<256, 4>) -> i64 {
    let bytes: [u8; 32] = value.to_le_bytes();
    let mut array = [0u8; 8];
    array.copy_from_slice(&bytes[0..8]);
    i64::from_le_bytes(array)
}

pub(crate) unsafe fn read_u16(ptr: *const u8) -> u16 {
    u16::from_be_bytes(core::slice::from_raw_parts(ptr, 2).try_into().unwrap())
}

pub fn ruint_to_garbled_uint(value: &Uint<256, 4>) -> GarbledUint<256> {
    let bytes: [u8; 32] = value.to_le_bytes();

    let bits: Vec<bool> = bytes
        .iter()
        .flat_map(|&byte| (0..8).map(move |i| ((byte >> i) & 1) == 1))
        .collect();

    GarbledUint::<256>::new(bits)
}

pub fn garbled_uint_to_ruint(value: &GarbledUint<256>) -> Uint<256, 4> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::{ruint::Uint, U256};

    #[test]
    fn test_ruint_to_garbled_uint() {
        let value = Uint::<256, 4>::from(123456789u64);
        let garbled = ruint_to_garbled_uint(&value);
        assert_eq!(garbled.bits.len(), 256);
    }

    #[test]
    fn test_garbled_uint_to_ruint() {
        let value = Uint::<256, 4>::from(123456789u64);
        let garbled = ruint_to_garbled_uint(&value);
        let result = garbled_uint_to_ruint(&garbled);
        assert_eq!(value, result);
    }

    #[test]
    fn test_ruint_to_garbled_int() {
        let value = Uint::<256, 4>::from(123456789u64);
        let garbled = ruint_to_garbled_int(&value);
        assert_eq!(garbled.bits.len(), 256);
    }

    #[test]
    fn test_negative_ruint_to_garbled_int() {
        let mut value = Uint::<256, 4>::from(10i64);
        // invert the bits
        for i in 0..256 {
            value.set_bit(i, !value.bit(i));
        }
        let converted = uint_to_i64(&value);

        // print the i64 value
        println!("{}", uint_to_i64(&value));

        value = Uint::<256, 4>::from(10i64);

        value = -value;
        let converted = uint_to_i64(&value);

        println!("{}", uint_to_i64(&value));

        let garbled = ruint_to_garbled_int(&value);
        assert_eq!(garbled.bits[0], true);
    }
}
