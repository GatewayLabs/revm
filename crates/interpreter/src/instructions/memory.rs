use crate::{gas, Host, Interpreter};
use compute::{prelude::GateIndexVec, uint::GarbledBoolean};
use specification::hardfork::Spec;
use crate::interpreter::StackValueData;
use compute::uint::GarbledUint;

pub fn mload<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    
    let top = unsafe { interpreter.stack.top_unsafe() };
    let offset = as_usize_or_fail!(interpreter, top.to_u256());
    
    let current_size = interpreter.private_memory.len();
    let new_size = offset.saturating_add(32);
    
    if new_size > current_size {
        interpreter.private_memory.resize(new_size, &mut interpreter.circuit_builder);
    }
    
    let value = interpreter.private_memory.get(offset).clone();
    *top = StackValueData::Private(value);
}

pub fn mstore<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    
    let (offset_val, value) = unsafe { interpreter.stack.pop2_unsafe() };
    let offset = as_usize_or_fail!(interpreter, offset_val.to_u256());
    
    let garbled_value = match value {
        StackValueData::Public(public_val) => {
            let mut bits = Vec::with_capacity(64);
            let value_bytes: [u8; 32] = public_val.to_le_bytes();
            
            for byte in value_bytes.iter().take(8) {
                for i in 0..8 {
                    let bit = (byte & (1 << i)) != 0;
                    bits.push(bit);
                }
            }
            
            let mut gate_vec = Vec::with_capacity(64);
            for bit in bits {
                let bit_value = GarbledUint::<1>::new(vec![bit]);
                let gate = interpreter.circuit_builder.input(&bit_value);
                gate_vec.push(gate[0]);
            }
            
            GateIndexVec::new(gate_vec)
        },
        StackValueData::Private(gate_vec) => gate_vec,
    };
    
    let current_size = interpreter.private_memory.len();
    let new_size = offset.saturating_add(32);
    
    if new_size > current_size {
        interpreter.private_memory.resize(new_size, &mut interpreter.circuit_builder);
    }
    
    *interpreter.private_memory.get_mut(offset) = garbled_value;
}

pub fn mstore8<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    
    let (offset_val, value) = unsafe { interpreter.stack.pop2_unsafe() };
    let offset = as_usize_or_fail!(interpreter, offset_val.to_u256());
    
    let garbled_value = match value {
        StackValueData::Public(public_val) => {
            let byte = (public_val.as_limbs()[0] & 0xff) as u8;
            
            let mut gate_indices = GateIndexVec::with_capacity(64);
            
            for i in 0..8 {
                let bit = (byte & (1 << i)) != 0;
                let bit_gate = interpreter.circuit_builder.input(&GarbledBoolean::from(bit));
                gate_indices.push(bit_gate[0]);
            }
            
            for _ in 8..64 {
                let zero_gate = interpreter.circuit_builder.input(&GarbledBoolean::from(false));
                gate_indices.push(zero_gate[0]);
            }
            
            gate_indices
        },
        StackValueData::Private(original_gates) => {
            let mut gate_indices = GateIndexVec::with_capacity(64);
            
            for gate in original_gates.iter().take(8) {
                gate_indices.push(*gate);
            }
            
            while gate_indices.len() < 64 {
                let zero_gate = interpreter.circuit_builder.input(&GarbledBoolean::from(false));
                gate_indices.push(zero_gate[0]);
            }
            
            gate_indices
        }
    };
    
    
    let current_size = interpreter.private_memory.len();
    let new_size = offset.saturating_add(1);
    
    if new_size > current_size {
        interpreter.private_memory.resize(new_size, &mut interpreter.circuit_builder);
    }
    
    *interpreter.private_memory.get_mut(offset) = garbled_value;
}

pub fn msize<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    
    let size_in_words = (interpreter.private_memory.len() + 31) / 32;
    let size_in_bytes = size_in_words * 32;
    
    let mut bits = Vec::with_capacity(64);
    let mut size = size_in_bytes;
    for _ in 0..64 {
        bits.push((size & 1) == 1);
        size >>= 1;
    }
    
    let garbled_size = GarbledUint::<64>::new(bits);
    
    let result = interpreter.circuit_builder.input(&garbled_size);
    
    interpreter.stack.push_stack_value_data(StackValueData::Private(result)).unwrap();
}

pub fn mcopy<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, _host: &mut H) {
    check!(interpreter, CANCUN);
    
    let (dst_val, src_val, len_val) = unsafe { interpreter.stack.pop3_unsafe() };

    let len = as_usize_or_fail!(interpreter, len_val.to_u256());
    gas_or_fail!(interpreter, gas::copy_cost_verylow(len as u64));
    if len == 0 {
        return;
    }

    let src = as_usize_or_fail!(interpreter, dst_val.to_u256());
    let dst = as_usize_or_fail!(interpreter, src_val.to_u256());
    
    let current_size = interpreter.private_memory.len();
    let new_size = core::cmp::max(dst + len, src + len);
    
    if new_size > current_size {
        interpreter.private_memory.resize(new_size, &mut interpreter.circuit_builder);
    }

    let src_value = interpreter.private_memory.get(src).clone();

    *interpreter.private_memory.get_mut(dst) = src_value.clone();

    let dst_value = interpreter.private_memory.get(dst).clone();

    assert_eq!(src_value, dst_value, "MCOPY read back verification failed");

    interpreter.stack.push_stack_value_data(StackValueData::Private(src_value)).unwrap();
    
    // interpreter.private_memory.copy(dst, src, len);
}

#[cfg(test)]
mod tests {
    use std::os::macos::raw;

    use super::*;
    use crate::{instructions::utility::{garbled_uint64_to_ruint, garbled_uint_to_ruint, ruint_to_garbled_uint}, Contract, DummyHost, Interpreter};
    use compute::{prelude::GateIndexVec, uint::GarbledUint256};
    use primitives::{ruint::Uint, U256};
    use wiring::DefaultEthereumWiring;

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
    fn test_mload_private() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();

        let raw_value = U256::from(42);

        // Set offset in memory where the value will be stored
        let offset = U256::from(0);

        // Stack the value and offset in the interpreter
        interpreter.stack.push(raw_value).expect("Failed to push value to stack");
        interpreter.stack.push(offset.into()).expect("Failed to push offset to stack");

        // Calls the mstore function to store the value in memory
        mstore(&mut interpreter, &mut host);

        // Stack the offset again to load the value from memory
        interpreter.stack.push(offset.into()).expect("Failed to push offset to stack");

        // Calls the mload function to load the value from memory
        mload(&mut interpreter, &mut host);

        // Pops the value loaded from memory
        let loaded_value = interpreter.stack.pop().expect("Failed to pop value from stack");

        let result: GarbledUint256 = interpreter
            .circuit_builder
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
        interpreter.stack.push(raw_value).expect("Failed to push value to stack");
        interpreter.stack.push(offset.into()).expect("Failed to push offset to stack");

        // Calls the mstore function to store the value in memory
        mstore(&mut interpreter, &mut host);

        // Converts the raw value to a garbled value manually
        let garbled_value_manual = ruint_to_garbled_uint(&raw_value);

        // Checks whether the garbled value stored in memory is equal to the manually garbled value
        let stored_value = interpreter.private_memory.get(0).clone();
        let stored_value_converted: GarbledUint256 = interpreter
            .circuit_builder
            .compile_and_execute(&stored_value)
            .unwrap();

        assert_eq!(stored_value_converted, garbled_value_manual);

        // Stack the offset again to load the value from memory
        interpreter.stack.push(offset.into()).expect("Failed to push offset to stack");

        // Calls the mload function to load the value from memory
        mload(&mut interpreter, &mut host);

        // Pops the value loaded from memory
        let loaded_value = interpreter.stack.pop().expect("Failed to pop value from stack");

        let result: GarbledUint256 = interpreter
            .circuit_builder
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
        interpreter.stack.push(raw_value).expect("Failed to push value to stack");
        interpreter.stack.push(offset.into()).expect("Failed to push offset to stack");

        // Calls the mstore function to store the value in memory
        mstore8(&mut interpreter, &mut host);

        // Converts the raw value to a garbled value manually
        let garbled_value_manual = ruint_to_garbled_uint(&raw_value);

        // Checks whether the garbled value stored in memory is equal to the manually garbled value
        let stored_value = interpreter.private_memory.get(0).clone();
        let stored_value_converted: GarbledUint256 = interpreter
            .circuit_builder
            .compile_and_execute(&stored_value)
            .unwrap();
        assert_eq!(stored_value_converted, garbled_value_manual);

        // Stack the offset again to load the value from memory
        interpreter.stack.push(offset.into()).expect("Failed to push offset to stack");

        // Calls the mload function to load the value from memory
        mload(&mut interpreter, &mut host);

        // Pops the value loaded from memory
        let loaded_value = interpreter.stack.pop().expect("Failed to pop value from stack");

        let result: GarbledUint256 = interpreter
            .circuit_builder
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
        let size = interpreter.stack.pop().expect("Failed to pop value from stack");

        


        let result: GarbledUint256 = interpreter
            .circuit_builder
            .compile_and_execute(&size.into())
            .unwrap();
        let expected_result = Uint::<256, 4>::from(U256::from(0));
        println!("result: {:?}", result);
        println!("expected_result: {:?}", expected_result);

        assert_eq!(garbled_uint64_to_ruint(&result), expected_result);
    }
}