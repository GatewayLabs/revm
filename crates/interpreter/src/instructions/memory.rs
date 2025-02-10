use crate::{
    gas,
    interpreter::{private_memory::PrivateMemoryValue, StackValueData},
    Host, Interpreter,
};
use core::cmp::max;
use primitives::U256;
use specification::hardfork::Spec;

pub fn mload<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, top);
    let shared_mem_offset = top.evaluate(&interpreter.circuit_builder.borrow());
    let shared_mem_offset = as_usize_or_fail!(interpreter, shared_mem_offset);
    resize_memory!(interpreter, shared_mem_offset, 32);
    let shared_mem = interpreter.shared_memory.get_u256(shared_mem_offset);

    if crate::interpreter::private_memory::is_private_tag(shared_mem.as_le_slice()) {
        let out = match interpreter
            .private_memory
            .get(shared_mem.try_into().unwrap())
        {
            PrivateMemoryValue::Private(val) => StackValueData::Private(val),
            _ => panic!("Cannot mload invalid PrivateMemoryValue type"),
        };
        *top = out;
    } else {
        *top = StackValueData::Public(shared_mem);
    }
}

pub fn mstore<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop!(interpreter, offset, value);

    let offset = offset.evaluate(&interpreter.circuit_builder.borrow());
    let offset = as_usize_or_fail!(interpreter, offset);

    resize_memory!(interpreter, offset, 32);

    match value {
        StackValueData::Public(value) => interpreter.shared_memory.set_u256(offset, value),
        StackValueData::Private(value) => {
            let private_ref = interpreter
                .private_memory
                .push(PrivateMemoryValue::Private(value));
            interpreter
                .shared_memory
                .set_u256(offset, private_ref.into());
        }
        StackValueData::Encrypted(value) => {
            let private_ref = interpreter
                .private_memory
                .push(PrivateMemoryValue::Encrypted(value));
            interpreter
                .shared_memory
                .set_u256(offset, private_ref.into());
        }
    }
}

pub fn mstore8<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop!(interpreter, offset, value);
    let offset = offset.evaluate(&interpreter.circuit_builder.borrow());
    let offset = as_usize_or_fail!(interpreter, offset);
    resize_memory!(interpreter, offset, 1);

    match value {
        StackValueData::Public(value) => interpreter.shared_memory.set_byte(offset, value.byte(0)),
        _ => panic!("Unable to implement with private StackValueData"),
    }
}

pub fn msize<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(
        interpreter,
        StackValueData::Public(U256::from(interpreter.shared_memory.len()))
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
