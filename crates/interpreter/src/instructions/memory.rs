use crate::{gas, Host, Interpreter};
use core::cmp::max;
use primitives::U256;
use specification::hardfork::Spec;

pub fn mload<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, top);
    let offset = as_usize_or_fail!(interpreter, top);
    resize_memory!(interpreter, offset, 32);
    *top = interpreter.shared_memory.get_u256(offset).into();
}

pub fn mstore<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop!(interpreter, offset, value);
    let offset = as_usize_or_fail!(interpreter, offset);
    resize_memory!(interpreter, offset, 32);
    interpreter.shared_memory.set_u256(offset, value.into());
}

pub fn mstore8<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop!(interpreter, offset, value);
    let offset = as_usize_or_fail!(interpreter, offset);
    resize_memory!(interpreter, offset, 1);
    interpreter
        .shared_memory
        .set_byte(offset, value.to_u256().byte(0))
}

pub fn msize<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(
        interpreter,
        U256::from(interpreter.shared_memory.len()).into()
    );
}

// EIP-5656: MCOPY - Memory copying instruction
pub fn mcopy<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, _host: &mut H) {
    check!(interpreter, CANCUN);
    pop!(interpreter, dst, src, len);

    // into usize or fail
    let len = as_usize_or_fail!(interpreter, len);
    // deduce gas
    gas_or_fail!(interpreter, gas::copy_cost_verylow(len as u64));
    if len == 0 {
        return;
    }

    let dst = as_usize_or_fail!(interpreter, dst);
    let src = as_usize_or_fail!(interpreter, src);
    // resize memory
    resize_memory!(interpreter, max(dst, src), len);
    // copy memory in place
    interpreter.shared_memory.copy(dst, src, len);
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        instructions::utility::{garbled_uint64_to_ruint, ruint_to_garbled_uint},
        Contract, DummyHost, Interpreter,
    };
    use compute::uint::GarbledUint256;
    use primitives::{ruint::Uint, U256};

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

    // #[test]
    // fn test_mload_private() {
    //     let mut interpreter = generate_interpreter();
    //     // let mut host = generate_host();
    //     let mut host = generate_host();

    //     let raw_value = U256::from(42);

    //     // Set offset in memory where the value will be stored
    //     let offset = U256::from(0);

    //     // Stack the value and offset in the interpreter
    //     interpreter
    //         .stack
    //         .push(raw_value.into())
    //         .expect("Failed to push value to stack");
    //     interpreter
    //         .stack
    //         .push(offset.into())
    //         .expect("Failed to push offset to stack");

    //     // Calls the mstore function to store the value in memory
    //     mstore(&mut interpreter, &mut host);

    //     // Stack the offset again to load the value from memory
    //     interpreter
    //         .stack
    //         .push(offset.into())
    //         .expect("Failed to push offset to stack");

    //     // Calls the mload function to load the value from memory
    //     mload(&mut interpreter, &mut host);

    //     // Pops the value loaded from memory
    //     let loaded_value = interpreter
    //         .stack
    //         .pop()
    //         .expect("Failed to pop value from stack");

    //     let result: GarbledUint256 = interpreter
    //         .circuit_builder
    //         .compile_and_execute(&loaded_value.into())
    //         .unwrap();
    //     let expected_result = Uint::<256, 4>::from(raw_value);
    //     println!("result: {:?}", result);
    //     println!("expected_result: {:?}", expected_result);

    //     assert_eq!(garbled_uint64_to_ruint(&result), expected_result);
    // }

    // #[test]
    // fn test_mstore_private() {
    //     let mut interpreter = generate_interpreter();
    //     let mut host = generate_host();

    //     let raw_value = U256::from(42);

    //     // Set offset in memory where the value will be stored
    //     let offset = U256::from(0);

    //     // Stack the value and offset in the interpreter
    //     interpreter
    //         .stack
    //         .push(raw_value.into())
    //         .expect("Failed to push value to stack");
    //     interpreter
    //         .stack
    //         .push(offset.into())
    //         .expect("Failed to push offset to stack");

    //     // Calls the mstore function to store the value in memory
    //     mstore(&mut interpreter, &mut host);

    //     // Converts the raw value to a garbled value manually
    //     let garbled_value_manual = ruint_to_garbled_uint(&raw_value);

    //     // Checks whether the garbled value stored in memory is equal to the manually garbled value
    //     let stored_value = interpreter.private_memory.get(0).clone();
    //     let stored_value_converted: GarbledUint256 = interpreter
    //         .circuit_builder
    //         .compile_and_execute(&stored_value)
    //         .unwrap();

    //     assert_eq!(stored_value_converted, garbled_value_manual);

    //     // Stack the offset again to load the value from memory
    //     interpreter
    //         .stack
    //         .push(offset.into())
    //         .expect("Failed to push offset to stack");

    //     // Calls the mload function to load the value from memory
    //     mload(&mut interpreter, &mut host);

    //     // Pops the value loaded from memory
    //     let loaded_value = interpreter
    //         .stack
    //         .pop()
    //         .expect("Failed to pop value from stack");

    //     let result: GarbledUint256 = interpreter
    //         .circuit_builder
    //         .compile_and_execute(&loaded_value.into())
    //         .unwrap();
    //     let expected_result = Uint::<256, 4>::from(raw_value);
    //     println!("result: {:?}", result);
    //     println!("expected_result: {:?}", expected_result);

    //     assert_eq!(garbled_uint64_to_ruint(&result), expected_result);
    // }

    // #[test]
    // fn test_mstore8_private() {
    //     let mut interpreter = generate_interpreter();
    //     let mut host = generate_host();

    //     let raw_value = U256::from(42);

    //     // Set offset in memory where the value will be stored
    //     let offset = U256::from(0);

    //     // Stack the value and offset in the interpreter
    //     interpreter
    //         .stack
    //         .push(raw_value.into())
    //         .expect("Failed to push value to stack");
    //     interpreter
    //         .stack
    //         .push(offset.into())
    //         .expect("Failed to push offset to stack");

    //     // Calls the mstore function to store the value in memory
    //     mstore8(&mut interpreter, &mut host);

    //     // Converts the raw value to a garbled value manually
    //     let garbled_value_manual = ruint_to_garbled_uint(&raw_value);

    //     // Checks whether the garbled value stored in memory is equal to the manually garbled value
    //     let stored_value = interpreter.private_memory.get(0).clone();
    //     let stored_value_converted: GarbledUint256 = interpreter
    //         .circuit_builder
    //         .compile_and_execute(&stored_value)
    //         .unwrap();
    //     assert_eq!(stored_value_converted, garbled_value_manual);

    //     // Stack the offset again to load the value from memory
    //     interpreter
    //         .stack
    //         .push(offset.into())
    //         .expect("Failed to push offset to stack");

    //     // Calls the mload function to load the value from memory
    //     mload(&mut interpreter, &mut host);

    //     // Pops the value loaded from memory
    //     let loaded_value = interpreter
    //         .stack
    //         .pop()
    //         .expect("Failed to pop value from stack");

    //     let result: GarbledUint256 = interpreter
    //         .circuit_builder
    //         .compile_and_execute(&loaded_value.into())
    //         .unwrap();
    //     let expected_result = Uint::<256, 4>::from(raw_value);
    //     println!("result: {:?}", result);
    //     println!("expected_result: {:?}", expected_result);

    //     assert_eq!(garbled_uint64_to_ruint(&result), expected_result);
    // }

    // #[test]
    // fn test_msize_private() {
    //     let mut interpreter = generate_interpreter();
    //     let mut host = generate_host();

    //     // Calls the msize function to get the size of the private memory
    //     msize(&mut interpreter, &mut host);

    //     // Pops the size of the private memory
    //     let size = interpreter
    //         .stack
    //         .pop()
    //         .expect("Failed to pop value from stack");

    //     let result: GarbledUint256 = interpreter
    //         .circuit_builder
    //         .compile_and_execute(&size.into())
    //         .unwrap();
    //     let expected_result = Uint::<256, 4>::from(U256::from(0));
    //     println!("result: {:?}", result);
    //     println!("expected_result: {:?}", expected_result);

    //     assert_eq!(garbled_uint64_to_ruint(&result), expected_result);
    // }

    // #[test]
    // fn test_mload_public() {
    //     let mut interpreter = generate_interpreter();
    //     let mut host = generate_host();

    //     let raw_value = U256::from(253);

    //     // Set offset in memory where the value will be stored
    //     let offset = U256::from(0);

    //     // Stack the value and offset in the interpreter
    //     interpreter
    //         .stack
    //         .push(raw_value.into())
    //         .expect("Failed to push value to stack");
    //     interpreter
    //         .stack
    //         .push(offset.into())
    //         .expect("Failed to push offset to stack");

    //     // Calls the mstore function to store the value in memory
    //     mstore(&mut interpreter, &mut host);

    //     // Stack the offset again to load the value from memory
    //     interpreter
    //         .stack
    //         .push(offset.into())
    //         .expect("Failed to push offset to stack");

    //     // Calls the mload function to load the value from memory
    //     mload(&mut interpreter, &mut host);

    //     // Pops the value loaded from memory
    //     let loaded_value = interpreter
    //         .stack
    //         .pop()
    //         .expect("Failed to pop value from stack");

    //     let result: GarbledUint256 = interpreter
    //         .circuit_builder
    //         .compile_and_execute(&loaded_value.into())
    //         .unwrap();
    //     let expected_result = Uint::<256, 4>::from(raw_value);
    //     println!("result: {:?}", result);
    //     println!("expected_result: {:?}", expected_result);

    //     assert_eq!(garbled_uint64_to_ruint(&result), expected_result);
    // }

    // #[test]
    // fn test_mstore_boundary_conditions() {
    //     let mut interpreter = generate_interpreter();
    //     let mut host = generate_host();

    //     let raw_value = U256::from(100);

    //     // Set offset in memory where the value will be stored
    //     let offset = U256::from(0);

    //     // Stack the value and offset in the interpreter
    //     interpreter
    //         .stack
    //         .push(raw_value.into())
    //         .expect("Failed to push value to stack");
    //     interpreter
    //         .stack
    //         .push(offset.into())
    //         .expect("Failed to push offset to stack");

    //     // Calls the mstore function to store the value in memory
    //     mstore(&mut interpreter, &mut host);

    //     // Stack the offset again to load the value from memory
    //     interpreter
    //         .stack
    //         .push(offset.into())
    //         .expect("Failed to push offset to stack");

    //     // Calls the mload function to load the value from memory
    //     mload(&mut interpreter, &mut host);

    //     // Pops the value loaded from memory
    //     let loaded_value = interpreter
    //         .stack
    //         .pop()
    //         .expect("Failed to pop value from stack");

    //     let result: GarbledUint256 = interpreter
    //         .circuit_builder
    //         .compile_and_execute(&loaded_value.into())
    //         .unwrap();
    //     let expected_result = Uint::<256, 4>::from(raw_value);
    //     println!("result: {:?}", result);
    //     println!("expected_result: {:?}", expected_result);

    //     assert_eq!(garbled_uint64_to_ruint(&result), expected_result);
    // }

    // #[test]
    // fn test_mstore8_public() {
    //     let mut interpreter = generate_interpreter();
    //     let mut host = generate_host();

    //     let raw_value = U256::from(42);

    //     // Set offset in memory where the value will be stored
    //     let offset = U256::from(0);

    //     // Stack the value and offset in the interpreter
    //     interpreter
    //         .stack
    //         .push(raw_value.into())
    //         .expect("Failed to push value to stack");
    //     interpreter
    //         .stack
    //         .push(offset.into())
    //         .expect("Failed to push offset to stack");

    //     // Calls the mstore8 function to store the value in memory
    //     mstore8(&mut interpreter, &mut host);

    //     // Stack the offset again to load the value from memory
    //     interpreter
    //         .stack
    //         .push(offset.into())
    //         .expect("Failed to push offset to stack");

    //     // Calls the mload function to load the value from memory
    //     mload(&mut interpreter, &mut host);

    //     // Pops the value loaded from memory
    //     let loaded_value = interpreter
    //         .stack
    //         .pop()
    //         .expect("Failed to pop value from stack");

    //     let result: GarbledUint256 = interpreter
    //         .circuit_builder
    //         .compile_and_execute(&loaded_value.into())
    //         .unwrap();
    //     let expected_result = Uint::<256, 4>::from(raw_value);
    //     println!("result: {:?}", result);
    //     println!("expected_result: {:?}", expected_result);

    //     assert_eq!(garbled_uint64_to_ruint(&result), expected_result);
    // }

    // #[test]
    // fn test_msize_public() {
    //     let mut interpreter = generate_interpreter();
    //     let mut host = generate_host();

    //     // Calls the msize function to get the size of the public memory
    //     msize(&mut interpreter, &mut host);

    //     // Pops the size of the public memory
    //     let size = interpreter
    //         .stack
    //         .pop()
    //         .expect("Failed to pop value from stack");

    //     let result: GarbledUint256 = interpreter
    //         .circuit_builder
    //         .compile_and_execute(&size.into())
    //         .unwrap();
    //     let expected_result = Uint::<256, 4>::from(U256::from(0));
    //     println!("result: {:?}", result);
    //     println!("expected_result: {:?}", expected_result);

    //     assert_eq!(garbled_uint64_to_ruint(&result), expected_result);
    // }
}
