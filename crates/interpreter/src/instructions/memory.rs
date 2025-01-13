use crate::{gas, Host, Interpreter};
use primitives::U256;
use specification::hardfork::Spec;
use crate::interpreter::StackValueData;

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
    
    let garbled_value = value.to_garbled_value(&mut interpreter.circuit_builder);
    
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
    
    let garbled_value = value.to_garbled_value(&mut interpreter.circuit_builder);
    
    let current_size = interpreter.private_memory.len();
    let new_size = offset.saturating_add(1);
    
    if new_size > current_size {
        interpreter.private_memory.resize(new_size, &mut interpreter.circuit_builder);
    }
    
    *interpreter.private_memory.get_mut(offset) = garbled_value;
}

pub fn msize<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    let size = U256::from(interpreter.private_memory.len());
    push!(interpreter, size);
}

pub fn mcopy<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, _host: &mut H) {
    check!(interpreter, CANCUN);
    
    let (dst_val, src_val, len_val) = unsafe { interpreter.stack.pop3_unsafe() };

    let len = as_usize_or_fail!(interpreter, len_val.to_u256());
    gas_or_fail!(interpreter, gas::copy_cost_verylow(len as u64));
    if len == 0 {
        return;
    }

    let dst = as_usize_or_fail!(interpreter, dst_val.to_u256());
    let src = as_usize_or_fail!(interpreter, src_val.to_u256());
    
    let current_size = interpreter.private_memory.len();
    let new_size = core::cmp::max(dst + len, src + len);
    
    if new_size > current_size {
        interpreter.private_memory.resize(new_size, &mut interpreter.circuit_builder);
    }
    
    interpreter.private_memory.copy(dst, src, len);
}