use core::ops::{Add, Div, Mul, Rem, Sub};

use super::i256::{i256_div, i256_mod};
use crate::{
    gas,
    instructions::utility::{garbled_uint_to_ruint, ruint_to_garbled_uint},
    Host, Interpreter,
};
use primitives::U256;
use specification::hardfork::Spec;

pub fn add<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);

    let garbled_op1 = ruint_to_garbled_uint(&op1);
    let garbled_op2 = ruint_to_garbled_uint(&op2);
    let result = garbled_op1.add(garbled_op2);

    *op2 = garbled_uint_to_ruint(&result);
}

pub fn mul<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::LOW);
    pop_top!(interpreter, op1, op2);

    let garbled_op1 = ruint_to_garbled_uint(&op1);
    let garbled_op2 = ruint_to_garbled_uint(&op2);
    let result = garbled_op1.mul(garbled_op2);

    *op2 = garbled_uint_to_ruint(&result);
}

pub fn sub<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);

    let garbled_op1 = ruint_to_garbled_uint(&op1);
    let garbled_op2 = ruint_to_garbled_uint(&op2);
    let result = garbled_op2.sub(garbled_op1);

    *op2 = garbled_uint_to_ruint(&result);
}

pub fn div<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::LOW);
    pop_top!(interpreter, op1, op2);
    if !op2.is_zero() {
        let garbled_op1 = ruint_to_garbled_uint(&op1);
        let garbled_op2 = ruint_to_garbled_uint(&op2);
        let result = garbled_op1.div(garbled_op2);

        *op2 = garbled_uint_to_ruint(&result);
    }
}

//TODO: Implement circuit for signed division
pub fn sdiv<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::LOW);
    pop_top!(interpreter, op1, op2);
    *op2 = i256_div(op1, *op2);
}

pub fn rem<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::LOW);
    pop_top!(interpreter, op1, op2);
    if !op2.is_zero() {
        let garbled_op1 = ruint_to_garbled_uint(&op1);
        let garbled_op2 = ruint_to_garbled_uint(&op2);
        let result = garbled_op1.rem(garbled_op2);

        *op2 = garbled_uint_to_ruint(&result);
    }
}

//TODO: Implement circuit for signed modulo
pub fn smod<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::LOW);
    pop_top!(interpreter, op1, op2);
    *op2 = i256_mod(op1, *op2)
}

//TODO: Implement circuit for signed addition
pub fn addmod<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::MID);
    pop_top!(interpreter, op1, op2, op3);
    *op3 = op1.add_mod(op2, *op3)
}

//TODO: Implement circuit for signed multiplication
pub fn mulmod<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::MID);
    pop_top!(interpreter, op1, op2, op3);
    *op3 = op1.mul_mod(op2, *op3)
}

//TODO?: Implement circuit for signed exponentiation
pub fn exp<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, _host: &mut H) {
    pop_top!(interpreter, op1, op2);
    gas_or_fail!(interpreter, gas::exp_cost(SPEC::SPEC_ID, *op2));
    *op2 = op1.pow(*op2);
}

/// Implements the `SIGNEXTEND` opcode as defined in the Ethereum Yellow Paper.
///
/// In the yellow paper `SIGNEXTEND` is defined to take two inputs, we will call them
/// `x` and `y`, and produce one output. The first `t` bits of the output (numbering from the
/// left, starting from 0) are equal to the `t`-th bit of `y`, where `t` is equal to
/// `256 - 8(x + 1)`. The remaining bits of the output are equal to the corresponding bits of `y`.
/// Note: if `x >= 32` then the output is equal to `y` since `t <= 0`. To efficiently implement
/// this algorithm in the case `x < 32` we do the following. Let `b` be equal to the `t`-th bit
/// of `y` and let `s = 255 - t = 8x + 7` (this is effectively the same index as `t`, but
/// numbering the bits from the right instead of the left). We can create a bit mask which is all
/// zeros up to and including the `t`-th bit, and all ones afterwards by computing the quantity
/// `2^s - 1`. We can use this mask to compute the output depending on the value of `b`.
/// If `b == 1` then the yellow paper says the output should be all ones up to
/// and including the `t`-th bit, followed by the remaining bits of `y`; this is equal to
/// `y | !mask` where `|` is the bitwise `OR` and `!` is bitwise negation. Similarly, if
/// `b == 0` then the yellow paper says the output should start with all zeros, then end with
/// bits from `b`; this is equal to `y & mask` where `&` is bitwise `AND`.
pub fn signextend<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::LOW);
    pop_top!(interpreter, ext, x);
    // For 31 we also don't need to do anything.
    if ext < U256::from(31) {
        let ext = ext.as_limbs()[0];
        let bit_index = (8 * ext + 7) as usize;
        let bit = x.bit(bit_index);
        let mask = (U256::from(1) << bit_index) - U256::from(1);
        *x = if bit { *x | !mask } else { *x & mask };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Contract, DummyHost};
    use primitives::ruint::Uint;

    fn generate_interpreter() -> Interpreter {
        let contract = Contract::default();
        let gas_limit = 10_000_000;
        let is_static = false;
        Interpreter::new(contract, gas_limit, is_static)
    }

    fn generate_host() -> DummyHost<
        wiring::EthereumWiring<database_interface::EmptyDBTyped<core::convert::Infallible>, ()>,
    > {
        DummyHost::default()
    }

    #[test]
    fn test_add() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();

        let op1 = Uint::<256, 4>::from(8u64);
        let op2 = Uint::<256, 4>::from(10u64);

        // Push values to the interpreter stack
        interpreter
            .stack
            .push(op2.clone())
            .expect("Failed to push op2 to stack");
        interpreter
            .stack
            .push(op1.clone())
            .expect("Failed to push op1 to stack");

        add(&mut interpreter, &mut host);

        let result = interpreter.stack.pop().unwrap();
        let expected_result = Uint::<256, 4>::from(18u64);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_sub() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();

        let op1 = Uint::<256, 4>::from(90u64);
        let op2 = Uint::<256, 4>::from(20u64);

        interpreter
            .stack
            .push(op1.clone())
            .expect("Failed to push op1 to stack");
        interpreter
            .stack
            .push(op2.clone())
            .expect("Failed to push op2 to stack");

        sub(&mut interpreter, &mut host);

        let result = interpreter.stack.pop().unwrap();
        let expected_result = Uint::<256, 4>::from(70u64);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_mul() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();

        // Create Uint<256, 4> values
        let op1 = Uint::<256, 4>::from(100u64);
        let op2 = Uint::<256, 4>::from(20u64);

        // Push values to the interpreter stack
        interpreter
            .stack
            .push(op2.clone())
            .expect("Failed to push op2 to stack");
        interpreter
            .stack
            .push(op1.clone())
            .expect("Failed to push op1 to stack");

        // Call the add function
        mul(&mut interpreter, &mut host);

        // Check the result
        let result = interpreter.stack.pop().unwrap();
        let expected_result = Uint::<256, 4>::from(2000u64);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_div() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();

        // Create Uint<256, 4> values
        let op1 = Uint::<256, 4>::from(100u64);
        let op2 = Uint::<256, 4>::from(20u64);

        // Push values to the interpreter stack
        interpreter
            .stack
            .push(op2.clone())
            .expect("Failed to push op2 to stack");
        interpreter
            .stack
            .push(op1.clone())
            .expect("Failed to push op1 to stack");

        // Call the add function
        div(&mut interpreter, &mut host);

        // Check the result
        let result = interpreter.stack.pop().unwrap();
        let expected_result = Uint::<256, 4>::from(5u64);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_rem() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();

        // Create Uint<256, 4> values
        let op1 = Uint::<256, 4>::from(100u64);
        let op2 = Uint::<256, 4>::from(20u64);

        // Push values to the interpreter stack
        interpreter
            .stack
            .push(op2.clone())
            .expect("Failed to push op2 to stack");
        interpreter
            .stack
            .push(op1.clone())
            .expect("Failed to push op1 to stack");

        // Call the add function
        rem(&mut interpreter, &mut host);

        // Check the result
        let result = interpreter.stack.pop().unwrap();
        let expected_result = Uint::<256, 4>::from(0u64);

        assert_eq!(result, expected_result);
    }
}
