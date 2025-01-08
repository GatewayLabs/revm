use super::i256::i256_cmp;
use crate::{
    gas,
    instructions::utility::{garbled_uint_to_ruint, ruint_to_garbled_uint},
    interpreter::StackValueData,
    Host, Interpreter,
};
use compute::prelude::{CircuitExecutor, GateIndexVec};
use primitives::U256;
use core::cmp::Ordering;
use specification::hardfork::Spec;

pub fn lt<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top_gates!(interpreter, _op1, op2, garbled_op1, garbled_op2);

    let result = interpreter.circuit_builder.lt(&garbled_op1, &garbled_op2);

    *op2 = StackValueData::Private(GateIndexVec::from(result));
}

pub fn gt<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top_gates!(interpreter, _op1, op2, garbled_op1, garbled_op2);

    let result = interpreter.circuit_builder.gt(&garbled_op1, &garbled_op2);

    *op2 = StackValueData::Private(GateIndexVec::from(result));
}

// TODO: Implement in garbled circuits
pub fn slt<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);
    *op2 = U256::from(i256_cmp(&op1.into(), &op2.to_u256()) == Ordering::Less).into();
}

// TODO: Implement in garbled circuits
pub fn sgt<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);
    *op2 = U256::from(i256_cmp(&op1.into(), &op2.to_u256()) == Ordering::Greater).into();
}

pub fn eq<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top_gates!(interpreter, _op1, op2, garbled_op1, garbled_op2);

    let result = interpreter.circuit_builder.eq(&garbled_op1, &garbled_op2);

    *op2 = StackValueData::Private(GateIndexVec::from(result));
}

// TODO: Is missing tests
pub fn iszero<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1);
    
    let result = match op1 {
        StackValueData::Public(value) => StackValueData::Public(U256::from(value.is_zero())),
        StackValueData::Private(garbled) => {
            let zero_bits = vec![false; 256];
            let zero = compute::uint::GarbledUint::<256>::new(zero_bits);
            let zero_gates = interpreter.circuit_builder.input(&zero);
            
            let result = interpreter.circuit_builder.eq(&garbled, &zero_gates);
            StackValueData::Private(GateIndexVec::from(result))
        }
    };
    
    *op1 = result;
}
pub fn bitand<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top_gates!(interpreter, _op1, op2, garbled_op1, garbled_op2);

    let result = interpreter.circuit_builder.and(&garbled_op1, &garbled_op2);

    *op2 = StackValueData::Private(GateIndexVec::from(result));
}

pub fn bitor<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top_gates!(interpreter, _op1, op2, garbled_op1, garbled_op2);

    let result = interpreter.circuit_builder.or(&garbled_op1, &garbled_op2);

    *op2 = StackValueData::Private(GateIndexVec::from(result));
}

pub fn bitxor<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top_gates!(interpreter, _op1, op2, garbled_op1, garbled_op2);

    let result = interpreter.circuit_builder.xor(&garbled_op1, &garbled_op2);

    *op2 = StackValueData::Private(GateIndexVec::from(result));
}

pub fn not<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top_gates!(interpreter, op1, garbled_op1);

    let result = interpreter.circuit_builder.not(&garbled_op1);

    *op1 = StackValueData::Private(GateIndexVec::from(result));
}

// TODO: Implement in garbled circuits
pub fn byte<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);

    let o1 = as_usize_saturated!(op1);
    *op2 = if o1 < 32 {
        // `31 - o1` because `byte` returns LE, while we want BE
        U256::from(op2.to_u256().byte(31 - o1)).into()
    } else {
        U256::ZERO.into()
    };
}

/// EIP-145: Bitwise shifting instructions in EVM
pub fn shl<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, _host: &mut H) {
    check!(interpreter, CONSTANTINOPLE);
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);

    let shift = as_usize_saturated!(op1);

    *op2 = if shift < 256 {
        let garbled_op2 = ruint_to_garbled_uint(&op2.to_u256());
        let shifted_op2 = garbled_op2 << shift;
        garbled_uint_to_ruint(&shifted_op2.into()).into()
    } else {
        U256::ZERO.into()
    }
}

/// EIP-145: Bitwise shifting instructions in EVM
pub fn shr<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, _host: &mut H) {
    check!(interpreter, CONSTANTINOPLE);
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);
    let shift = as_usize_saturated!(op1);
    *op2 = if shift < 256 {
        let garbled_op2 = ruint_to_garbled_uint(&op2.to_u256());
        let shifted_op2 = garbled_op2 >> shift;
        garbled_uint_to_ruint(&shifted_op2.into()).into()
    } else {
        U256::ZERO.into()
    }
}

/// EIP-145: Bitwise shifting instructions in EVM
// TODO: Implement in garbled circuits
pub fn sar<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, _host: &mut H) {
    check!(interpreter, CONSTANTINOPLE);
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);

    let shift = as_usize_saturated!(op1);
    *op2 = if shift < 256 {
        op2.to_u256().arithmetic_shr(shift).into()
    } else if op2.to_u256().bit(255) {
        U256::MAX.into()
    } else {
        U256::ZERO.into()
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instructions::bitwise::{byte, sar, shl, shr};
    use crate::instructions::utility::garbled_uint_to_bool;
    use crate::{Contract, DummyHost, Interpreter};
    use compute::uint::GarbledUint256;
    use primitives::{uint, U256};
    use specification::hardfork::LatestSpec;
    use wiring::{default::Env, DefaultEthereumWiring};

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
    fn test_lt() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();
        struct TestCase {
            op1: U256,
            op2: U256,
            expected: bool,
        }

        let test_cases = vec![
            TestCase {
                op1: U256::from(1u64),
                op2: U256::from(2u64),
                expected: true,
            },
            TestCase {
                op1: U256::from(2u64),
                op2: U256::from(1u64),
                expected: false,
            },
            TestCase {
                op1: U256::from(1u64),
                op2: U256::from(1u64),
                expected: false,
            },
            TestCase {
                op1: U256::from(1u64),
                op2: U256::from(0u64),
                expected: false,
            },
        ];

        for test in test_cases.iter() {
            interpreter
                .stack
                .push(test.op2)
                .expect("Failed to push op2 to stack");
            interpreter
                .stack
                .push(test.op1)
                .expect("Failed to push op1 to stack");

            lt(&mut interpreter, &mut host);

            let output_indices = interpreter.stack.pop().unwrap();

            let result: GarbledUint256 = interpreter
                .circuit_builder
                .compile_and_execute(&output_indices.into())
                .unwrap();

            assert_eq!(garbled_uint_to_bool(&result), test.expected, "Failed for op1: {:?}, op2: {:?}", test.op1, test.op2);
        }
    }

    #[test]
    fn test_gt() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();
        struct TestCase {
            op1: U256,
            op2: U256,
            expected: bool,
        }

        let test_cases = vec![
            TestCase {
                op1: U256::from(1u64),
                op2: U256::from(2u64),
                expected: false,
            },
            TestCase {
                op1: U256::from(2u64),
                op2: U256::from(1u64),
                expected: true,
            },
            TestCase {
                op1: U256::from(1u64),
                op2: U256::from(1u64),
                expected: false,
            },
            TestCase {
                op1: U256::from(1u64),
                op2: U256::from(0u64),
                expected: true,
            },
        ];

        for test in test_cases.iter() {
            interpreter
                .stack
                .push(test.op2)
                .expect("Failed to push op2 to stack");
            interpreter
                .stack
                .push(test.op1)
                .expect("Failed to push op1 to stack");

            gt(&mut interpreter, &mut host);

            let output_indices = interpreter.stack.pop().unwrap();

            let result: GarbledUint256 = interpreter
                .circuit_builder
                .compile_and_execute(&output_indices.into())
                .unwrap();

            assert_eq!(garbled_uint_to_bool(&result), test.expected, "Failed for op1: {:?}, op2: {:?}", test.op1, test.op2);
        }
    }

    #[test]
    fn test_eq() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();
        struct TestCase {
            op1: U256,
            op2: U256,
            expected: bool,
        }

        let test_cases = vec![
            TestCase {
                op1: U256::from(1u64),
                op2: U256::from(2u64),
                expected: false,
            },
            TestCase {
                op1: U256::from(2u64),
                op2: U256::from(1u64),
                expected: false,
            },
            TestCase {
                op1: U256::from(1u64),
                op2: U256::from(1u64),
                expected: true,
            },
            TestCase {
                op1: U256::from(1u64),
                op2: U256::from(0u64),
                expected: false,
            },
        ];

        for test in test_cases.iter() {
            interpreter
                .stack
                .push(test.op2)
                .expect("Failed to push op2 to stack");
            interpreter
                .stack
                .push(test.op1)
                .expect("Failed to push op1 to stack");

            eq(&mut interpreter, &mut host);

            let output_indices = interpreter.stack.pop().unwrap();

            let result: GarbledUint256 = interpreter
                .circuit_builder
                .compile_and_execute(&output_indices.into())
                .unwrap();

            assert_eq!(garbled_uint_to_bool(&result), test.expected, "Failed for op1: {:?}, op2: {:?}", test.op1, test.op2);
        }
    }

    #[test]
    fn test_not() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();
        struct TestCase {
            op1: U256,
            expected: U256,
        }

        let test_cases = vec![
            TestCase {
                op1: U256::from(1u64),
                expected: U256::from(0u64),
            },
            TestCase {
                op1: U256::from(0u64),
                expected: U256::from(1u64),
            },
            TestCase {
                op1: U256::from(0x1234567890abcdefu128),
                expected: U256::from(0xedcba9876f543210u128),
            },
        ];

        for test in test_cases.iter() {
            interpreter
                .stack
                .push(test.op1)
                .expect("Failed to push op1 to stack");

            not(&mut interpreter, &mut host);

            let output_indices = interpreter.stack.pop().unwrap();

            let result: GarbledUint256 = interpreter
                .circuit_builder
                .compile_and_execute(&output_indices.into())
                .unwrap();

            assert_eq!(garbled_uint_to_ruint(&result), test.expected, "Failed for op1: {:?}", test.op1);
        }
    }

    #[test]
    fn test_bitand () {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();
        struct TestCase {
            op1: U256,
            op2: U256,
            expected: U256,
        }

        let test_cases = vec![
            TestCase {
            op1: U256::from(0x1234567890abcdefu128),
            op2: U256::from(0xfedcba0987654321u128),
            expected: U256::from(0x0214440010044001u128),
            },
            TestCase {
            op1: U256::from(0xffffffffffffffffu128),
            op2: U256::from(0x0000000000000000u128),
            expected: U256::from(0x0000000000000000u128),
            },
            TestCase {
            op1: U256::from(0x0f0f0f0f0f0f0f0fu128),
            op2: U256::from(0xf0f0f0f0f0f0f0f0u128),
            expected: U256::from(0x0000000000000000u128),
            },
        ];

        for test in test_cases.iter() {
            interpreter
                .stack
                .push(test.op2)
                .expect("Failed to push op2 to stack");
            interpreter
                .stack
                .push(test.op1)
                .expect("Failed to push op1 to stack");

            bitand(&mut interpreter, &mut host);

            let output_indices = interpreter.stack.pop().unwrap();

            let result: GarbledUint256 = interpreter
                .circuit_builder
                .compile_and_execute(&output_indices.into())
                .unwrap();

            assert_eq!(garbled_uint_to_ruint(&result), test.expected, "Failed for op1: {:?}, op2: {:?}", test.op1, test.op2);
        }
    }

    #[test]
    fn test_bitor() {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();
        struct TestCase {
            op1: U256,
            op2: U256,
            expected: U256,
        }

        let test_cases = vec![
            TestCase {
                op1: U256::from(0xf000000000000000u64),
                op2: U256::from(0x1000000000000000u64),
                expected: U256::from(0xf000000000000000u64),
            },
            TestCase {
                op1: U256::from(0xffffffffffffffffu128),
                op2: U256::from(0x0000000000000000u128),
                expected: U256::from(0xffffffffffffffffu128),
            },
            TestCase {
                op1: U256::from(0x0f0f0f0f0f0f0f0fu128),
                op2: U256::from(0xf0f0f0f0f0f0f0f0u128),
                expected: U256::from(0xffffffffffffffffu128),
            },
            TestCase {
                op1: U256::from(0xf000000000000000u64),
                op2: U256::from(0x1000000000000000u64),
                expected: U256::from(0xf000000000000000u64),
            },
            TestCase {
                op1: U256::from(0x3400u64),
                op2: U256::from(0xdc00u64),
                expected: U256::from(0xfc00u64),
            }
        ];

        for test in test_cases.iter() {
            interpreter
                .stack
                .push(test.op2)
                .expect("Failed to push op2 to stack");
            interpreter
                .stack
                .push(test.op1)
                .expect("Failed to push op1 to stack");

            bitor(&mut interpreter, &mut host);

            let output_indices = interpreter.stack.pop().unwrap();

            let result: GarbledUint256 = interpreter
                .circuit_builder
                .compile_and_execute(&output_indices.into())
                .unwrap();
                
            let actual = garbled_uint_to_ruint(&result);

            assert_eq!(garbled_uint_to_ruint(&result), test.expected, 
                "Failed for op1: 0x{:x}, op2: 0x{:x}\nGot: 0x{:x}\nExpected: 0x{:x}", 
                test.op1, test.op2, actual, test.expected);
                }
    }

    #[test]
    fn test_bitxor () {
        let mut interpreter = generate_interpreter();
        let mut host = generate_host();
        struct TestCase {
            op1: U256,
            op2: U256,
            expected: U256,
        }

        let test_cases = vec![
            TestCase {
                op1: U256::from(0xf000000000000000u64),
                op2: U256::from(0x1000000000000000u64),
                expected: U256::from(0xe000000000000000u64),
            },
            TestCase {
                op1: U256::from(0xffffffffffffffffu128),
                op2: U256::from(0x0000000000000000u128),
                expected: U256::from(0xffffffffffffffffu128),
            },
            TestCase {
                op1: U256::from(0x0f0f0f0f0f0f0f0fu128),
                op2: U256::from(0xf0f0f0f0f0f0f0f0u128),
                expected: U256::from(0xffffffffffffffffu128),
            },
            TestCase {
                op1: U256::from(0xf000000000000000u64),
                op2: U256::from(0x1000000000000000u64),
                expected: U256::from(0xe000000000000000u64),
            },
            TestCase {
                op1: U256::from(0x1200u64),
                op2: U256::from(0xfe00u64),
                expected: U256::from(0xec00u64),
            },
            TestCase {
                op1: U256::from(0x3400u64),
                op2: U256::from(0xdc00u64),
                expected: U256::from(0xe800u64),
            }
        ];

        for test in test_cases.iter() {
            interpreter
                .stack
                .push(test.op2)
                .expect("Failed to push op2 to stack");
            interpreter
                .stack
                .push(test.op1)
                .expect("Failed to push op1 to stack");

            bitxor(&mut interpreter, &mut host);

            let output_indices = interpreter.stack.pop().unwrap();

            let result: GarbledUint256 = interpreter
                .circuit_builder
                .compile_and_execute(&output_indices.into())
                .unwrap();

           
                let actual = garbled_uint_to_ruint(&result);
    
                assert_eq!(garbled_uint_to_ruint(&result), test.expected, 
                    "Failed for op1: 0x{:x}, op2: 0x{:x}\nGot: 0x{:x}\nExpected: 0x{:x}", 
                    test.op1, test.op2, actual, test.expected);

        }
    }

    #[test]
    fn test_shift_left() {
        let mut host = DummyHost::new(Env::default());
        let mut interpreter = Interpreter::new(Contract::default(), u64::MAX, false);

        struct TestCase {
            value: U256,
            shift: U256,
            expected: U256,
        }

        uint! {
            let test_cases = [
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x00_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x01_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000002_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0xff_U256,
                    expected: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x0100_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x0101_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x00_U256,
                    expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x01_U256,
                    expected: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0xff_U256,
                    expected: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x0100_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0x01_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x01_U256,
                    expected: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe_U256,
                },
            ];
        }

        for test in test_cases {
            host.clear();
            push!(interpreter, test.value);
            push!(interpreter, test.shift);
            shl::<DummyHost<DefaultEthereumWiring>, LatestSpec>(&mut interpreter, &mut host);
            pop!(interpreter, res);
            assert_eq!(res, test.expected.into());
        }
    }

    #[test]
    fn test_logical_shift_right() {
        let mut host = DummyHost::new(Env::default());
        let mut interpreter = Interpreter::new(Contract::default(), u64::MAX, false);

        struct TestCase {
            value: U256,
            shift: U256,
            expected: U256,
        }

        uint! {
            let test_cases = [
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x00_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x01_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0x01_U256,
                    expected: 0x4000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0xff_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                },
                TestCase {
                    value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0x0100_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0x0101_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x00_U256,
                    expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x01_U256,
                    expected: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0xff_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x0100_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0x01_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
            ];
        }

        for test in test_cases {
            host.clear();
            push!(interpreter, test.value);
            push!(interpreter, test.shift);
            shr::<DummyHost<DefaultEthereumWiring>, LatestSpec>(&mut interpreter, &mut host);
            pop!(interpreter, res);
            assert_eq!(res, test.expected.into());
        }
    }

    #[test]
    fn test_arithmetic_shift_right() {
        let mut host = DummyHost::new(Env::default());
        let mut interpreter = Interpreter::new(Contract::default(), u64::MAX, false);

        struct TestCase {
            value: U256,
            shift: U256,
            expected: U256,
        }

        uint! {
        let test_cases = [
            TestCase {
                value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                shift: 0x00_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
            },
            TestCase {
                value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                shift: 0x01_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
            },
            TestCase {
                value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0x01_U256,
                expected: 0xc000000000000000000000000000000000000000000000000000000000000000_U256,
            },
            TestCase {
                value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0xff_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0x0100_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0x0101_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0x00_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0x01_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0xff_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0x0100_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0x01_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
            },
            TestCase {
                value: 0x4000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0xfe_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
            },
            TestCase {
                value: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0xf8_U256,
                expected: 0x000000000000000000000000000000000000000000000000000000000000007f_U256,
            },
            TestCase {
                value: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0xfe_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
            },
            TestCase {
                value: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0xff_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
            },
            TestCase {
                value: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0x0100_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
            },
        ];
            }

        for test in test_cases {
            host.clear();
            push!(interpreter, test.value);
            push!(interpreter, test.shift);
            sar::<DummyHost<DefaultEthereumWiring>, LatestSpec>(&mut interpreter, &mut host);
            pop!(interpreter, res);
            assert_eq!(res, test.expected.into());
        }
    }

    #[test]
    fn test_byte() {
        struct TestCase {
            input: U256,
            index: usize,
            expected: U256,
        }

        let mut host = DummyHost::<DefaultEthereumWiring>::new(Env::default());
        let mut interpreter = Interpreter::new(Contract::default(), u64::MAX, false);

        let input_value = U256::from(0x1234567890abcdef1234567890abcdef_u128);
        let test_cases = (0..32)
            .map(|i| {
                let byte_pos = 31 - i;

                let shift_amount = U256::from(byte_pos * 8);
                let byte_value = (input_value >> shift_amount) & U256::from(0xFF);
                TestCase {
                    input: input_value,
                    index: i,
                    expected: byte_value,
                }
            })
            .collect::<Vec<_>>();

        for test in test_cases.iter() {
            push!(interpreter, test.input);
            push!(interpreter, U256::from(test.index));
            byte(&mut interpreter, &mut host);
            pop!(interpreter, res);
            assert_eq!(res, test.expected.into(), "Failed at index: {}", test.index);
        }
    }
}
