use crate::interpreter::StackValueData;
use crate::{gas, Host, Interpreter};
use compute::{prelude::GateIndexVec, uint::GarbledBoolean};
use specification::hardfork::Spec;

pub fn mload<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);

    // Get reference to top of stack without extra copy
    let top = unsafe { interpreter.stack.top_unsafe() };
    let offset = as_usize_or_fail!(interpreter, top.to_u256());

    // Only resize if we actually need to read from that location
    if offset >= interpreter.private_memory.len() {
        interpreter.private_memory.resize(offset + 32);
    }

    // Direct assignment without extra clone
    *top = StackValueData::Private(interpreter.private_memory.get(offset).clone());
}

pub fn mstore<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);

    let (offset_val, value) = unsafe { interpreter.stack.pop2_unsafe() };
    let offset = as_usize_or_fail!(
        interpreter,
        offset_val.evaluate(&interpreter.circuit_builder.borrow())
    );

    let garbled_value = match value {
        StackValueData::Public(public_val) => {
            // Pre-allocate GateIndexVec directly to avoid intermediate Vec
            let mut gate_indices = GateIndexVec::with_capacity(64);
            let value_bytes: [u8; 32] = public_val.to_le_bytes();

            // Process bytes directly without intermediate bits vector
            for byte in value_bytes.iter().take(8) {
                for i in 0..8 {
                    let bit = (byte & (1 << i)) != 0;
                    let bit_gate = interpreter
                        .circuit_builder
                        .borrow_mut()
                        .input(&GarbledBoolean::from(bit));
                    gate_indices.push(bit_gate[0]);
                }
            }
            gate_indices
        }
        StackValueData::Private(gate_vec) => gate_vec,
        StackValueData::Encrypted(_ciphertext) => {
            panic!("Cannot convert encrypted value to garbled value")
        }
    };

    let current_size = interpreter.private_memory.len();
    let new_size = offset.saturating_add(32);

    if new_size > current_size {
        interpreter.private_memory.resize(new_size);
    }

    *interpreter.private_memory.get_mut(offset) = garbled_value;
}

pub fn mstore8<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);

    let (offset_val, value) = unsafe { interpreter.stack.pop2_unsafe() };
    let offset = as_usize_or_fail!(
        interpreter,
        offset_val.evaluate(&interpreter.circuit_builder.borrow())
    );

    // Pre-allocate with exact capacity
    let mut gate_indices = GateIndexVec::with_capacity(64);

    match value {
        StackValueData::Public(public_val) => {
            // Extract single byte more efficiently
            let byte = public_val.as_limbs()[0] as u8;

            // Unroll first 8 bits loop
            for i in 0..8 {
                let bit_gate = interpreter
                    .circuit_builder
                    .borrow_mut()
                    .input(&GarbledBoolean::from((byte & (1 << i)) != 0));
                gate_indices.push(bit_gate[0]);
            }
        }
        StackValueData::Private(original_gates) => {
            // Copy first 8 gates one by one
            for i in 0..8.min(original_gates.len()) {
                gate_indices.push(original_gates[i]);
            }
        }
        StackValueData::Encrypted(_) => panic!("Cannot convert encrypted value to garbled value"),
    }

    // Fill remaining bits with zeros
    let zero_gate = interpreter
        .circuit_builder
        .borrow_mut()
        .input(&GarbledBoolean::from(false));
    while gate_indices.len() < 64 {
        gate_indices.push(zero_gate[0]);
    }

    // Resize memory only if needed
    if offset >= interpreter.private_memory.len() {
        interpreter.private_memory.resize(offset + 1);
    }

    *interpreter.private_memory.get_mut(offset) = gate_indices;
}

pub fn msize<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::BASE);

    // Calculate size in bytes directly
    let size_in_bytes = ((interpreter.private_memory.len() + 31) / 32) * 32;

    // Pre-allocate gate indices with capacity
    let mut gate_indices = GateIndexVec::with_capacity(64);

    // Add gates for each bit without intermediate Vec
    let mut remaining = size_in_bytes;
    for _ in 0..64 {
        let bit = remaining & 1 == 1;
        let bit_gate = interpreter
            .circuit_builder
            .borrow_mut()
            .input(&GarbledBoolean::from(bit));
        gate_indices.push(bit_gate[0]);
        remaining >>= 1;
    }

    interpreter
        .stack
        .push_stack_value_data(StackValueData::Private(gate_indices))
        .unwrap();
}

pub fn mcopy<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, _host: &mut H) {
    check!(interpreter, CANCUN);

    let (dst_val, src_val, len_val) = unsafe { interpreter.stack.pop3_unsafe() };

    let len = as_usize_or_fail!(interpreter, len_val.to_u256());
    if len == 0 {
        return;
    }
    gas_or_fail!(interpreter, gas::copy_cost_verylow(len as u64));

    let src = as_usize_or_fail!(interpreter, dst_val.to_u256());
    let dst = as_usize_or_fail!(interpreter, src_val.to_u256());

    // Resize memory only if necessary
    let new_size = core::cmp::max(dst + len, src + len);
    if new_size > interpreter.private_memory.len() {
        interpreter.private_memory.resize(new_size);
    }

    // Clone the source value before mutating memory
    let src_value = interpreter.private_memory.get(src).clone();
    *interpreter.private_memory.get_mut(dst) = src_value.clone();

    // Push the cloned value
    interpreter
        .stack
        .push_stack_value_data(StackValueData::Private(src_value))
        .unwrap();
}

#[cfg(test)]
mod tests {

    use core::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    use crate::{
        instructions::utility::{garbled_uint64_to_ruint, ruint_to_garbled_uint},
        Contract, DummyHost, Interpreter,
    };
    use compute::{prelude::WRK17CircuitBuilder, uint::GarbledUint256};
    use primitives::{ruint::Uint, U256};

    fn generate_interpreter() -> Interpreter {
        let contract = Contract::default();
        let gas_limit = 10_000_000;
        let is_static = false;
        Interpreter::new(
            contract,
            gas_limit,
            is_static,
            Rc::new(RefCell::new(WRK17CircuitBuilder::default())),
        )
    }

    fn generate_host() -> DummyHost<
        wiring::EthereumWiring<database_interface::EmptyDBTyped<core::convert::Infallible>, ()>,
    > {
        DummyHost::default()
    }

    #[test]
    fn test_mload_private() {
        let mut interpreter = generate_interpreter();
        // let mut host = generate_host();
        let mut host = generate_host();

        let raw_value = U256::from(42);

        // Set offset in memory where the value will be stored
        let offset = U256::from(0);

        // Stack the value and offset in the interpreter
        interpreter
            .stack
            .push(raw_value.into())
            .expect("Failed to push value to stack");
        interpreter
            .stack
            .push(offset.into())
            .expect("Failed to push offset to stack");

        // Calls the mstore function to store the value in memory
        mstore(&mut interpreter, &mut host);

        // Stack the offset again to load the value from memory
        interpreter
            .stack
            .push(offset.into())
            .expect("Failed to push offset to stack");

        // Calls the mload function to load the value from memory
        mload(&mut interpreter, &mut host);

        // Pops the value loaded from memory
        let loaded_value = interpreter
            .stack
            .pop()
            .expect("Failed to pop value from stack");

        let result: GarbledUint256 = interpreter
            .circuit_builder
            .borrow()
            .compile_and_execute(&loaded_value.into())
            .unwrap();
        let expected_result = Uint::<256, 4>::from(raw_value);
        println!("result: {:?}", result);
        println!("expected_result: {:?}", expected_result);

        assert_eq!(garbled_uint64_to_ruint(&result), expected_result);
    }

    #[test]
    fn test_mstore_private() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();

        let raw_value = U256::from(42);

        // Set offset in memory where the value will be stored
        let offset = U256::from(0);

        // Stack the value and offset in the interpreter
        interpreter
            .stack
            .push(raw_value.into())
            .expect("Failed to push value to stack");
        interpreter
            .stack
            .push(offset.into())
            .expect("Failed to push offset to stack");

        // Calls the mstore function to store the value in memory
        mstore(&mut interpreter, &mut host);

        // Converts the raw value to a garbled value manually
        let garbled_value_manual = ruint_to_garbled_uint(&raw_value);

        // Checks whether the garbled value stored in memory is equal to the manually garbled value
        let stored_value = interpreter.private_memory.get(0).clone();
        let stored_value_converted: GarbledUint256 = interpreter
            .circuit_builder
            .borrow()
            .compile_and_execute(&stored_value)
            .unwrap();

        assert_eq!(stored_value_converted, garbled_value_manual);

        // Stack the offset again to load the value from memory
        interpreter
            .stack
            .push(offset.into())
            .expect("Failed to push offset to stack");

        // Calls the mload function to load the value from memory
        mload(&mut interpreter, &mut host);

        // Pops the value loaded from memory
        let loaded_value = interpreter
            .stack
            .pop()
            .expect("Failed to pop value from stack");

        let result: GarbledUint256 = interpreter
            .circuit_builder
            .borrow()
            .compile_and_execute(&loaded_value.into())
            .unwrap();
        let expected_result = Uint::<256, 4>::from(raw_value);
        println!("result: {:?}", result);
        println!("expected_result: {:?}", expected_result);

        assert_eq!(garbled_uint64_to_ruint(&result), expected_result);
    }

    #[test]
    fn test_mstore8_private() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();

        let raw_value = U256::from(42);

        // Set offset in memory where the value will be stored
        let offset = U256::from(0);

        // Stack the value and offset in the interpreter
        interpreter
            .stack
            .push(raw_value.into())
            .expect("Failed to push value to stack");
        interpreter
            .stack
            .push(offset.into())
            .expect("Failed to push offset to stack");

        // Calls the mstore function to store the value in memory
        mstore8(&mut interpreter, &mut host);

        // Converts the raw value to a garbled value manually
        let garbled_value_manual = ruint_to_garbled_uint(&raw_value);

        // Checks whether the garbled value stored in memory is equal to the manually garbled value
        let stored_value = interpreter.private_memory.get(0).clone();
        let stored_value_converted: GarbledUint256 = interpreter
            .circuit_builder
            .borrow()
            .compile_and_execute(&stored_value)
            .unwrap();
        assert_eq!(stored_value_converted, garbled_value_manual);

        // Stack the offset again to load the value from memory
        interpreter
            .stack
            .push(offset.into())
            .expect("Failed to push offset to stack");

        // Calls the mload function to load the value from memory
        mload(&mut interpreter, &mut host);

        // Pops the value loaded from memory
        let loaded_value = interpreter
            .stack
            .pop()
            .expect("Failed to pop value from stack");

        let result: GarbledUint256 = interpreter
            .circuit_builder
            .borrow()
            .compile_and_execute(&loaded_value.into())
            .unwrap();
        let expected_result = Uint::<256, 4>::from(raw_value);
        println!("result: {:?}", result);
        println!("expected_result: {:?}", expected_result);

        assert_eq!(garbled_uint64_to_ruint(&result), expected_result);
    }

    #[test]
    fn test_msize_private() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();

        // Calls the msize function to get the size of the private memory
        msize(&mut interpreter, &mut host);

        // Pops the size of the private memory
        let size = interpreter
            .stack
            .pop()
            .expect("Failed to pop value from stack");

        let result: GarbledUint256 = interpreter
            .circuit_builder
            .borrow()
            .compile_and_execute(&size.into())
            .unwrap();
        let expected_result = Uint::<256, 4>::from(U256::from(0));
        println!("result: {:?}", result);
        println!("expected_result: {:?}", expected_result);

        assert_eq!(garbled_uint64_to_ruint(&result), expected_result);
    }

    #[test]
    fn test_mload_public() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();

        let raw_value = U256::from(253);

        // Set offset in memory where the value will be stored
        let offset = U256::from(0);

        // Stack the value and offset in the interpreter
        interpreter
            .stack
            .push(raw_value.into())
            .expect("Failed to push value to stack");
        interpreter
            .stack
            .push(offset.into())
            .expect("Failed to push offset to stack");

        // Calls the mstore function to store the value in memory
        mstore(&mut interpreter, &mut host);

        // Stack the offset again to load the value from memory
        interpreter
            .stack
            .push(offset.into())
            .expect("Failed to push offset to stack");

        // Calls the mload function to load the value from memory
        mload(&mut interpreter, &mut host);

        // Pops the value loaded from memory
        let loaded_value = interpreter
            .stack
            .pop()
            .expect("Failed to pop value from stack");

        let result: GarbledUint256 = interpreter
            .circuit_builder
            .borrow()
            .compile_and_execute(&loaded_value.into())
            .unwrap();
        let expected_result = Uint::<256, 4>::from(raw_value);
        println!("result: {:?}", result);
        println!("expected_result: {:?}", expected_result);

        assert_eq!(garbled_uint64_to_ruint(&result), expected_result);
    }

    #[test]
    fn test_mstore_boundary_conditions() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();

        let raw_value = U256::from(100);

        // Set offset in memory where the value will be stored
        let offset = U256::from(0);

        // Stack the value and offset in the interpreter
        interpreter
            .stack
            .push(raw_value.into())
            .expect("Failed to push value to stack");
        interpreter
            .stack
            .push(offset.into())
            .expect("Failed to push offset to stack");

        // Calls the mstore function to store the value in memory
        mstore(&mut interpreter, &mut host);

        // Stack the offset again to load the value from memory
        interpreter
            .stack
            .push(offset.into())
            .expect("Failed to push offset to stack");

        // Calls the mload function to load the value from memory
        mload(&mut interpreter, &mut host);

        // Pops the value loaded from memory
        let loaded_value = interpreter
            .stack
            .pop()
            .expect("Failed to pop value from stack");

        let result: GarbledUint256 = interpreter
            .circuit_builder
            .borrow()
            .compile_and_execute(&loaded_value.into())
            .unwrap();
        let expected_result = Uint::<256, 4>::from(raw_value);
        println!("result: {:?}", result);
        println!("expected_result: {:?}", expected_result);

        assert_eq!(garbled_uint64_to_ruint(&result), expected_result);
    }

    #[test]
    fn test_mstore8_public() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();

        let raw_value = U256::from(42);

        // Set offset in memory where the value will be stored
        let offset = U256::from(0);

        // Stack the value and offset in the interpreter
        interpreter
            .stack
            .push(raw_value.into())
            .expect("Failed to push value to stack");
        interpreter
            .stack
            .push(offset.into())
            .expect("Failed to push offset to stack");

        // Calls the mstore8 function to store the value in memory
        mstore8(&mut interpreter, &mut host);

        // Stack the offset again to load the value from memory
        interpreter
            .stack
            .push(offset.into())
            .expect("Failed to push offset to stack");

        // Calls the mload function to load the value from memory
        mload(&mut interpreter, &mut host);

        // Pops the value loaded from memory
        let loaded_value = interpreter
            .stack
            .pop()
            .expect("Failed to pop value from stack");

        let result: GarbledUint256 = interpreter
            .circuit_builder
            .borrow()
            .compile_and_execute(&loaded_value.into())
            .unwrap();
        let expected_result = Uint::<256, 4>::from(raw_value);
        println!("result: {:?}", result);
        println!("expected_result: {:?}", expected_result);

        assert_eq!(garbled_uint64_to_ruint(&result), expected_result);
    }

    #[test]
    fn test_msize_public() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();

        // Calls the msize function to get the size of the public memory
        msize(&mut interpreter, &mut host);

        // Pops the size of the public memory
        let size = interpreter
            .stack
            .pop()
            .expect("Failed to pop value from stack");

        let result: GarbledUint256 = interpreter
            .circuit_builder
            .borrow()
            .compile_and_execute(&size.into())
            .unwrap();
        let expected_result = Uint::<256, 4>::from(U256::from(0));
        println!("result: {:?}", result);
        println!("expected_result: {:?}", expected_result);

        assert_eq!(garbled_uint64_to_ruint(&result), expected_result);
    }
}
