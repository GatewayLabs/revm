//! Utility macros to help implementing opcode instruction functions.

/// Fails the instruction if the current call is static.
#[macro_export]
macro_rules! require_non_staticcall {
    ($interp:expr) => {
        if $interp.is_static {
            $interp.instruction_result = $crate::InstructionResult::StateChangeDuringStaticCall;
            return;
        }
    };
}

/// Error if the current call is executing EOF.
#[macro_export]
macro_rules! require_eof {
    ($interp:expr) => {
        if !$interp.is_eof {
            $interp.instruction_result = $crate::InstructionResult::EOFOpcodeDisabledInLegacy;
            return;
        }
    };
}

/// Error if not init eof call.
#[macro_export]
macro_rules! require_init_eof {
    ($interp:expr) => {
        if !$interp.is_eof_init {
            $interp.instruction_result = $crate::InstructionResult::ReturnContractInNotInitEOF;
            return;
        }
    };
}

/// Check if the `SPEC` is enabled, and fail the instruction if it is not.
#[macro_export]
macro_rules! check {
    ($interp:expr, $min:ident) => {
        if const {
            !<SPEC as specification::hardfork::Spec>::SPEC_ID
                .is_enabled_in(specification::hardfork::SpecId::$min)
        } {
            $interp.instruction_result = $crate::InstructionResult::NotActivated;
            return;
        }
    };
}

/// Records a `gas` cost and fails the instruction if it would exceed the available gas.
#[macro_export]
macro_rules! gas {
    ($interp:expr, $gas:expr) => {
        $crate::gas!($interp, $gas, ())
    };
    ($interp:expr, $gas:expr, $ret:expr) => {
        if !$interp.gas.record_cost($gas) {
            $interp.instruction_result = $crate::InstructionResult::OutOfGas;
            return $ret;
        }
    };
}

/// Records a `gas` refund.
#[macro_export]
macro_rules! refund {
    ($interp:expr, $gas:expr) => {
        $interp.gas.record_refund($gas)
    };
}

/// Same as [`gas!`], but with `gas` as an option.
#[macro_export]
macro_rules! gas_or_fail {
    ($interp:expr, $gas:expr) => {
        $crate::gas_or_fail!($interp, $gas, ())
    };
    ($interp:expr, $gas:expr, $ret:expr) => {
        match $gas {
            Some(gas_used) => $crate::gas!($interp, gas_used, $ret),
            None => {
                $interp.instruction_result = $crate::InstructionResult::OutOfGas;
                return $ret;
            }
        }
    };
}

/// Resizes the interpreter memory if necessary. Fails the instruction if the memory or gas limit
/// is exceeded.
#[macro_export]
macro_rules! resize_memory {
    ($interp:expr, $offset:expr, $len:expr) => {
        $crate::resize_memory!($interp, $offset, $len, ())
    };
    ($interp:expr, $offset:expr, $len:expr, $ret:expr) => {
        let new_size = $offset.saturating_add($len);
        if new_size > $interp.shared_memory.len() {
            #[cfg(feature = "memory_limit")]
            if $interp.shared_memory.limit_reached(new_size) {
                $interp.instruction_result = $crate::InstructionResult::MemoryLimitOOG;
                return $ret;
            }

            // Note: we can't use `Interpreter` directly here because of potential double-borrows.
            if !$crate::interpreter::resize_memory(
                &mut $interp.shared_memory,
                &mut $interp.private_memory,
                &mut $interp.gas,
                new_size,
            ) {
                $interp.instruction_result = $crate::InstructionResult::MemoryOOG;
                return $ret;
            }
        }
    };
}

#[macro_export]
macro_rules! resize_private_memory {
    ($interp:expr, $offset:expr, $len:expr) => {
        $crate::resize_private_memory!($interp, $offset, $len, ())
    };
    ($interp:expr, $offset:expr, $len:expr, $ret:expr) => {
        let new_size = $offset.saturating_add($len);
        let current_size = $interp.private_memory.len();
        if new_size > current_size {
            #[cfg(feature = "memory_limit")]
            if $interp.shared_memory.limit_reached(new_size) {
                $interp.instruction_result = $crate::InstructionResult::MemoryLimitOOG;
                return $ret;
            }

            if !$crate::interpreter::resize_memory($interp, new_size) {
                $interp.instruction_result = $crate::InstructionResult::MemoryOOG;
                return $ret;
            }
        }
    };
}

/// Pops `Address` values from the stack. Fails the instruction if the stack is too small.
#[macro_export]
macro_rules! pop_address {
    ($interp:expr, $x1:ident) => {
        $crate::pop_address_ret!($interp, $x1, ())
    };
    ($interp:expr, $x1:ident, $x2:ident) => {
        $crate::pop_address_ret!($interp, $x1, $x2, ())
    };
}

/// Pop `Address` values from the stack, returns `ret` on stack underflow.
#[macro_export]
macro_rules! pop_address_ret {
    ($interp:expr, $x1:ident, $ret:expr) => {
        if $interp.stack.len() < 1 {
            $interp.instruction_result = $crate::InstructionResult::StackUnderflow;
            return $ret;
        }
        // SAFETY: Length is checked above.
        let $x1 = ::primitives::Address::from_word(::primitives::B256::from(unsafe {
            $interp.stack.pop_unsafe().to_u256()
        }));
    };
    ($interp:expr, $x1:ident, $x2:ident, $ret:expr) => {
        if $interp.stack.len() < 2 {
            $interp.instruction_result = $crate::InstructionResult::StackUnderflow;
            return $ret;
        }
        // SAFETY: Length is checked above.
        let $x1 = ::primitives::Address::from_word(::primitives::B256::from(unsafe {
            $interp.stack.pop_unsafe().to_u256()
        }));
        let $x2 = ::primitives::Address::from_word(::primitives::B256::from(unsafe {
            $interp.stack.pop_unsafe().to_u256()
        }));
    };
}

/// Pops `U256` values from the stack. Fails the instruction if the stack is too small.
#[macro_export]
macro_rules! pop {
    ($interp:expr, $x1:ident) => {
        $crate::pop_ret!($interp, $x1, ())
    };
    ($interp:expr, $x1:ident, $x2:ident) => {
        $crate::pop_ret!($interp, $x1, $x2, ())
    };
    ($interp:expr, $x1:ident, $x2:ident, $x3:ident) => {
        $crate::pop_ret!($interp, $x1, $x2, $x3, ())
    };
    ($interp:expr, $x1:ident, $x2:ident, $x3:ident, $x4:ident) => {
        $crate::pop_ret!($interp, $x1, $x2, $x3, $x4, ())
    };
    ($interp:expr, $x1:ident, $x2:ident, $x3:ident, $x4:ident, $x5:ident) => {
        $crate::pop_ret!($interp, $x1, $x2, $x3, $x4, $x5, ())
    };
}

/// Pops `U256` values from the stack, and returns `ret`.
/// Fails the instruction if the stack is too small.
#[macro_export]
macro_rules! pop_ret {
    ($interp:expr, $x1:ident, $ret:expr) => {
        if $interp.stack.len() < 1 {
            $interp.instruction_result = $crate::InstructionResult::StackUnderflow;
            return $ret;
        }
        // SAFETY: Length is checked above.
        let $x1 = unsafe { $interp.stack.pop_unsafe() };
    };
    ($interp:expr, $x1:ident, $x2:ident, $ret:expr) => {
        if $interp.stack.len() < 2 {
            $interp.instruction_result = $crate::InstructionResult::StackUnderflow;
            return $ret;
        }
        // SAFETY: Length is checked above.
        let ($x1, $x2) = unsafe { $interp.stack.pop2_unsafe() };
    };
    ($interp:expr, $x1:ident, $x2:ident, $x3:ident, $ret:expr) => {
        if $interp.stack.len() < 3 {
            $interp.instruction_result = $crate::InstructionResult::StackUnderflow;
            return $ret;
        }
        // SAFETY: Length is checked above.
        let ($x1, $x2, $x3) = unsafe { $interp.stack.pop3_unsafe() };
    };
    ($interp:expr, $x1:ident, $x2:ident, $x3:ident, $x4:ident, $ret:expr) => {
        if $interp.stack.len() < 4 {
            $interp.instruction_result = $crate::InstructionResult::StackUnderflow;
            return $ret;
        }
        // SAFETY: Length is checked above.
        let ($x1, $x2, $x3, $x4) = unsafe { $interp.stack.pop4_unsafe() };
    };
    ($interp:expr, $x1:ident, $x2:ident, $x3:ident, $x4:ident, $x5:ident, $ret:expr) => {
        if $interp.stack.len() < 5 {
            $interp.instruction_result = $crate::InstructionResult::StackUnderflow;
            return $ret;
        }
        // SAFETY: Length is checked above.
        let ($x1, $x2, $x3, $x4, $x5) = unsafe { $interp.stack.pop5_unsafe() };
    };
}

/// Pops `U256` values from the stack, and returns a reference to the top of the stack.
/// Fails the instruction if the stack is too small.
#[macro_export]
macro_rules! pop_top {
    ($interp:expr, $x1:ident) => {
        if $interp.stack.len() < 1 {
            $interp.instruction_result = $crate::InstructionResult::StackUnderflow;
            return;
        }
        // SAFETY: Length is checked above.
        let $x1 = unsafe { $interp.stack.top_unsafe() };
    };
    ($interp:expr, $x1:ident, $x2:ident) => {
        if $interp.stack.len() < 2 {
            $interp.instruction_result = $crate::InstructionResult::StackUnderflow;
            return;
        }
        // SAFETY: Length is checked above.
        let ($x1, $x2) = unsafe { $interp.stack.pop_top_unsafe() };
    };
    ($interp:expr, $x1:ident, $x2:ident, $x3:ident) => {
        if $interp.stack.len() < 3 {
            $interp.instruction_result = $crate::InstructionResult::StackUnderflow;
            return;
        }
        // SAFETY: Length is checked above.
        let ($x1, $x2, $x3) = unsafe { $interp.stack.pop2_top_unsafe() };
    };
}

/// Pops values from the stack and determines if it is a PrivateRef
#[macro_export]
macro_rules! pop_top_private {
    ($interp:expr, $x1:ident, $x1_priv:ident) => {
        pop_top!($interp, $x1);

        let mut cb = $interp.circuit_builder.borrow_mut();
        let val1 = match $x1 {
            StackValueData::Public(x1) => {
                let garbled_x1 = GarbledUint256::try_from(*x1)
                    .expect("error constructing GarbledUint from Uint<256,4>");
                let x1_gates = cb.input(&garbled_x1);
                PrivateMemoryValue::Garbled(x1_gates)
            }
            StackValueData::Private(x1_ref) => $interp.private_memory.get(x1_ref),
            _ => panic!("Unsupported StackValueData type"),
        };
        let PrivateMemoryValue::Garbled($x1_priv) = val1 else {
            panic!("x1 is not PrivateMemoryValue::Garbled")
        };

        drop(cb);
    };
    ($interp:expr, $x1:ident, $x2:ident, $x1_priv:ident, $x2_priv:ident) => {
        pop_top!($interp, $x1, $x2);

        let mut cb = $interp.circuit_builder.borrow_mut();
        let val1 = match $x1 {
            StackValueData::Public(x1) => {
                let garbled_x1 = GarbledUint256::try_from(x1)
                    .expect("error constructing GarbledUint from Uint<256,4>");
                let x1_gates = cb.input(&garbled_x1);
                PrivateMemoryValue::Garbled(x1_gates)
            }
            StackValueData::Private(x1_ref) => $interp.private_memory.get(&x1_ref),
            _ => panic!("Unsupported StackValueData type"),
        };
        let PrivateMemoryValue::Garbled($x1_priv) = val1 else {
            panic!("x1 is not PrivateMemoryValue::Garbled")
        };

        let val2 = match $x2 {
            StackValueData::Public(x2) => {
                let garbled_x2 = GarbledUint256::try_from(*x2)
                    .expect("error constructing GarbledUint from Uint<256,4>");
                let x2_gates = cb.input(&garbled_x2);
                PrivateMemoryValue::Garbled(x2_gates)
            }
            StackValueData::Private(x2_ref) => $interp.private_memory.get(x2_ref),
            _ => panic!("Unsupported StackValueData type"),
        };
        let PrivateMemoryValue::Garbled($x2_priv) = val2 else {
            panic!("x2 is not PrivateMemoryValue::Garbled")
        };
        drop(cb);
    };
}

// Pops 'StackValueData' and 'GateIndexVec' values from the stack. Fails the instruction if the stack is too small.
#[macro_export]
macro_rules! pop_top_gates {
    ($interp:expr, $x1:ident, $garbled_x1:ident) => {
        if $interp.stack.len() < 1 {
            $interp.instruction_result = $crate::InstructionResult::StackUnderflow;
            return;
        }
        // SAFETY: Length is checked above.
        let $x1 = unsafe { $interp.stack.top_unsafe() };
        let $garbled_x1 = $x1.to_garbled_value(&mut $interp.circuit_builder.borrow_mut());
    };
    ($interp:expr, $x1:ident, $x2:ident, $garbled_x1:ident, $garbled_x2:ident) => {
        if $interp.stack.len() < 2 {
            $interp.instruction_result = $crate::InstructionResult::StackUnderflow;
            return;
        }
        // SAFETY: Length is checked above.
        let ($x1, $x2, $garbled_x1, $garbled_x2) = unsafe {
            let (val1, val2) = $interp.stack.pop_top_unsafe();
            let mut cb = $interp.circuit_builder.borrow_mut();
            let (garbled_val1, garbled_val2) = (
                val1.to_garbled_value(&mut cb),
                val2.to_garbled_value(&mut cb),
            );
            drop(cb);
            (val1, val2, garbled_val1, garbled_val2)
        };
    };
    ($interp:expr, $x1:ident, $x2:ident, $x3:ident) => {
        if ($interp.stack.len() < 3) {
            $interp.instruction_result = $crate::InstructionResult::StackUnderflow;
            return;
        }
        // SAFETY: Length is checked above.
        let ($x1, $x2, $x3, $garbled_x1, $garbled_x2, $garbled_x3) = unsafe {
            let (val1, val2, val3) = $interp.stack.pop_top_unsafe();
            let cb = $interp.circuit_builder.borrow_mut();
            let (garbled_val1, garbled_val2, garbled_val3) = (
                val1.to_garbled_value(&mut cb),
                val2.to_garbled_value(&mut cb),
                val3.to_garbled_value(&mut cb),
            );
            drop(cb);
            (val1, val2, garbled_val1, garbled_val2, garbled_val3)
        };
    };
}

/// Pushes `B256` values onto the stack. Fails the instruction if the stack is full.
#[macro_export]
macro_rules! push_b256 {
    ($interp:expr, $($x:expr),* $(,)?) => ($(
        match $interp.stack.push_b256($x) {
            Ok(()) => {},
            Err(e) => {
                $interp.instruction_result = e;
                return;
            },
        }
    )*)
}

/// Pushes a `B256` value onto the stack. Fails the instruction if the stack is full.
#[macro_export]
macro_rules! push {
    ($interp:expr, $($x:expr),* $(,)?) => ($(
        match $interp.stack.push($x) {
            Ok(()) => {},
            Err(e) => {
                $interp.instruction_result = e;
                return;
            }
        }
    )*)
}

/// Converts a `U256` value to a `u64`, saturating to `MAX` if the value is too large.
#[macro_export]
macro_rules! as_u64_saturated {
    ($v:expr) => {
        match $v.as_limbs() {
            x => {
                if (x[1] == 0) & (x[2] == 0) & (x[3] == 0) {
                    x[0]
                } else {
                    u64::MAX
                }
            }
        }
    };
}

/// Converts a `U256` value to a `usize`, saturating to `MAX` if the value is too large.
#[macro_export]
macro_rules! as_usize_saturated {
    ($v:expr) => {
        usize::try_from($crate::as_u64_saturated!($v)).unwrap_or(usize::MAX)
    };
}

/// Converts a `U256` value to a `isize`, saturating to `isize::MAX` if the value is too large.
#[macro_export]
macro_rules! as_isize_saturated {
    ($v:expr) => {
        // `isize_try_from(u64::MAX)`` will fail and return isize::MAX
        // this is expected behavior as we are saturating the value.
        isize::try_from($crate::as_u64_saturated!($v)).unwrap_or(isize::MAX)
    };
}

/// Converts a `U256` value to a `usize`, failing the instruction if the value is too large.
#[macro_export]
macro_rules! as_usize_or_fail {
    ($interp:expr, $v:expr) => {
        $crate::as_usize_or_fail_ret!($interp, $v, ())
    };
    ($interp:expr, $v:expr, $reason:expr) => {
        $crate::as_usize_or_fail_ret!($interp, $v, $reason, ())
    };
}

/// Converts a `U256` value to a `usize` and returns `ret`,
/// failing the instruction if the value is too large.
#[macro_export]
macro_rules! as_usize_or_fail_ret {
    ($interp:expr, $v:expr, $ret:expr) => {
        $crate::as_usize_or_fail_ret!(
            $interp,
            $v,
            $crate::InstructionResult::InvalidOperandOOG,
            $ret
        )
    };

    ($interp:expr, $v:expr, $reason:expr, $ret:expr) => {
        match $v.as_limbs() {
            x => {
                if (x[0] > usize::MAX as u64) | (x[1] != 0) | (x[2] != 0) | (x[3] != 0) {
                    $interp.instruction_result = $reason;
                    return $ret;
                }
                x[0] as usize
            }
        }
    };
}
