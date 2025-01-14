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
}