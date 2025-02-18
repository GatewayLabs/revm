use crate::{
    gas,
    interpreter::{
        private_memory::{PrivateMemoryValue, PrivateRef},
        StackValueData,
    },
    Host, Interpreter,
};
use core::cmp::max;
use primitives::U256;
use specification::hardfork::Spec;

pub fn mload<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, offset_ptr);

    let offset_val: U256 = match offset_ptr {
        StackValueData::Public(top) => *top,
        StackValueData::Private(top_ptr) => {
            let val_private = interpreter.private_memory.get(
                &PrivateRef::try_from(*top_ptr)
                    .expect("evaluate: unable to construct PrivateRef from U256"),
            );
            let PrivateMemoryValue::Garbled(gates) = val_private else {
                panic!("evaluate: unsupported PrivateMemoryValue type")
            };
            let result = interpreter
                .circuit_builder
                .borrow()
                .compile_and_execute(&gates)
                .expect("Failed to evaluate private value");
            result.try_into().unwrap()
        }
        _ => panic!("Unsupported StackValueData type"),
    };

    let offset = as_usize_or_fail!(interpreter, offset_val);
    resize_memory!(interpreter, offset, 32);

    let from_memory: U256 = interpreter.shared_memory.get_u256(offset).into();

    *offset_ptr = from_memory.into();
}

pub fn mstore<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop!(interpreter, offset, value);

    let offset = offset.evaluate_with_interpreter(&interpreter);
    let offset = as_usize_or_fail!(interpreter, offset);

    resize_memory!(interpreter, offset, 32);
    interpreter
        .shared_memory
        .set_u256(offset, value.evaluate_with_interpreter(&interpreter));
}

pub fn mstore8<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop!(interpreter, offset, value);
    let offset = offset.evaluate_with_interpreter(&interpreter);
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
    pop!(interpreter, src, dst, len);

    // into usize or fail
    let len = as_usize_or_fail!(interpreter, len.evaluate_with_interpreter(&interpreter));
    // deduce gas
    gas_or_fail!(interpreter, gas::copy_cost_verylow(len as u64));
    if len == 0 {
        return;
    }

    let dst = as_usize_or_fail!(interpreter, dst.evaluate_with_interpreter(&interpreter));
    let src = as_usize_or_fail!(interpreter, src.evaluate_with_interpreter(&interpreter));
    // resize memory
    resize_memory!(interpreter, max(dst, src), len);
    // copy memory in place
    interpreter.shared_memory.copy(dst, src, len);
}
