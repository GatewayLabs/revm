use crate::{
    gas,
    interpreter::{private_memory::is_u256_private_ref, StackValueData},
    Host, Interpreter,
};
use core::cmp::max;
use primitives::U256;
use specification::hardfork::Spec;

pub fn mload<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, top);

    let offset = as_usize_or_fail!(interpreter, top);
    resize_memory!(interpreter, offset, 32);

    let from_memory: U256 = interpreter.shared_memory.get_u256(offset).into();

    println!(
        "mload::is_u256_private_tag: {}",
        is_u256_private_ref(&from_memory)
    );

    *top = from_memory.into();
}

pub fn mstore<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop!(interpreter, offset, value);

    let offset = offset.evaluate(&interpreter);
    let offset = as_usize_or_fail!(interpreter, offset);

    resize_memory!(interpreter, offset, 32);
    interpreter.shared_memory.set_u256(offset, value.into());
}

pub fn mstore8<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop!(interpreter, offset, value);
    let offset = offset.evaluate(&interpreter);
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
