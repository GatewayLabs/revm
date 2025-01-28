use super::utility::{garbled_uint_to_ruint, read_i16, read_u16};
use crate::{
    gas, interpreter::StackValueData, Host, InstructionResult, Interpreter, InterpreterResult,
};
use compute::uint::GarbledUint;
use primitives::{Bytes, U256};
use specification::hardfork::Spec;
use encryption::{
    elgamal::ElGamalEncryption,
    encryption_trait::Encryptor
};

pub fn rjump<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    require_eof!(interpreter);
    gas!(interpreter, gas::BASE);
    let offset = unsafe { read_i16(interpreter.instruction_pointer) } as isize;
    // In spec it is +3 but pointer is already incremented in
    // `Interpreter::step` so for revm is +2.
    interpreter.instruction_pointer = unsafe { interpreter.instruction_pointer.offset(offset + 2) };
}

pub fn rjumpi<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    require_eof!(interpreter);
    gas!(interpreter, gas::CONDITION_JUMP_GAS);
    pop!(interpreter, condition);
    // In spec it is +3 but pointer is already incremented in
    // `Interpreter::step` so for revm is +2.
    let mut offset = 2;

    match condition {
        StackValueData::Public(condition) => {
            if !condition.is_zero() {
                offset += unsafe { read_i16(interpreter.instruction_pointer) } as isize;
            }
        }
        StackValueData::Private(condition_gates) => {
            if let Ok(result) = interpreter
                .circuit_builder
                .compile_and_execute::<256>(&condition_gates)
            // NOTE: assume 256 bits due to public condition
            {
                if result != GarbledUint::zero() {
                    offset += unsafe { read_i16(interpreter.instruction_pointer) } as isize;
                }
            }
        }
        StackValueData::Encrypted(value, key) => {
            let decrypted = ElGamalEncryption::decrypt_to_u256(&value, &key);
            if !decrypted.is_zero() {
                offset += unsafe { read_i16(interpreter.instruction_pointer) } as isize;
            }
        }
    }

    interpreter.instruction_pointer = unsafe { interpreter.instruction_pointer.offset(offset) };
}

pub fn rjumpv<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    require_eof!(interpreter);
    gas!(interpreter, gas::CONDITION_JUMP_GAS);
    pop!(interpreter, case);
    let case = match case {
        StackValueData::Public(case) => {
            as_isize_saturated!(case)
        }
        StackValueData::Private(case_gates) => {
            if let Ok(result) = interpreter
                .circuit_builder
                .compile_and_execute::<256>(&case_gates)
            {
                let result = garbled_uint_to_ruint(&result);
                as_isize_saturated!(result)
            } else {
                return;
            }
        }
        StackValueData::Encrypted(value, key ) => {
            let decrypted = ElGamalEncryption::decrypt_to_u256(&value, &key);
            as_isize_saturated!(decrypted)
        }
    };

    let max_index = unsafe { *interpreter.instruction_pointer } as isize;
    // for number of items we are adding 1 to max_index, multiply by 2 as each offset is 2 bytes
    // and add 1 for max_index itself. Note that revm already incremented the instruction pointer
    let mut offset = (max_index + 1) * 2 + 1;

    if case <= max_index {
        offset += unsafe {
            read_i16(
                interpreter
                    .instruction_pointer
                    // offset for max_index that is one byte
                    .offset(1 + case * 2),
            )
        } as isize;
    }

    interpreter.instruction_pointer = unsafe { interpreter.instruction_pointer.offset(offset) };
}

pub fn jump<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::MID);
    pop!(interpreter, target);
    jump_inner(interpreter, target);
}

pub fn jumpi<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::HIGH);
    pop!(interpreter, target, cond);

    match cond {
        StackValueData::Public(cond) => {
            if !cond.is_zero() {
                jump_inner(interpreter, target);
            }
        }
        StackValueData::Private(cond) => {
            match interpreter
                .circuit_builder
                .compile_and_execute::<256>(&cond)
            {
                Ok(result) => {
                    if result != GarbledUint::zero() {
                        jump_inner(interpreter, target);
                    }
                }
                Err(_) => {
                    interpreter.instruction_result = InstructionResult::InvalidJump; // NOTE: define granular error for gate execution error
                    return;
                }
            };
        }
        StackValueData::Encrypted(value, key) => {
            let decrypted = ElGamalEncryption::decrypt_to_u256(&value, &key);
            if !decrypted.is_zero() {
                jump_inner(interpreter, target);
            }
        }
    }
}

#[inline]
fn jump_inner(interpreter: &mut Interpreter, target: StackValueData) {
    let target = match target {
        StackValueData::Public(target) => target,
        StackValueData::Private(target) => match interpreter
            .circuit_builder
            .compile_and_execute::<256>(&target)
        {
            Ok(result) => garbled_uint_to_ruint(&result),
            Err(_) => {
                interpreter.instruction_result = InstructionResult::InvalidJump; // NOTE: define granular error for gate execution error
                return;
            }
        },
        StackValueData::Encrypted(value, key ) => {
            ElGamalEncryption::decrypt_to_u256(&value, &key)
        }
    };

    let target = as_usize_or_fail!(interpreter, target, InstructionResult::InvalidJump);
    if !interpreter.contract.is_valid_jump(target) {
        interpreter.instruction_result = InstructionResult::InvalidJump;
        return;
    }
    // SAFETY: `is_valid_jump` ensures that `dest` is in bounds.
    interpreter.instruction_pointer = unsafe { interpreter.bytecode.as_ptr().add(target) };
}

pub fn jumpdest_or_nop<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::JUMPDEST);
}

pub fn callf<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    require_eof!(interpreter);
    gas!(interpreter, gas::LOW);

    let idx = unsafe { read_u16(interpreter.instruction_pointer) } as usize;

    if interpreter.function_stack.return_stack_len() >= 1024 {
        interpreter.instruction_result = InstructionResult::EOFFunctionStackOverflow;
        return;
    }

    // get target types
    let Some(types) = interpreter.eof().unwrap().body.types_section.get(idx) else {
        panic!("Invalid EOF in execution, expecting correct intermediate in callf")
    };

    // Check max stack height for target code section.
    // safe to subtract as max_stack_height is always more than inputs.
    if interpreter.stack.len() + (types.max_stack_size - types.inputs as u16) as usize > 1024 {
        interpreter.instruction_result = InstructionResult::StackOverflow;
        return;
    }

    // push current idx and PC to the callf stack.
    // PC is incremented by 2 to point to the next instruction after callf.
    interpreter
        .function_stack
        .push(interpreter.program_counter() + 2, idx);

    interpreter.load_eof_code(idx, 0)
}

pub fn retf<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    require_eof!(interpreter);
    gas!(interpreter, gas::RETF_GAS);

    let Some(fframe) = interpreter.function_stack.pop() else {
        panic!("Expected function frame")
    };

    interpreter.load_eof_code(fframe.idx, fframe.pc);
}

pub fn jumpf<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    require_eof!(interpreter);
    gas!(interpreter, gas::LOW);

    let idx = unsafe { read_u16(interpreter.instruction_pointer) } as usize;

    // get target types
    let Some(types) = interpreter.eof().unwrap().body.types_section.get(idx) else {
        panic!("Invalid EOF in execution, expecting correct intermediate in jumpf")
    };

    // Check max stack height for target code section.
    // safe to subtract as max_stack_height is always more than inputs.
    if interpreter.stack.len() + (types.max_stack_size - types.inputs as u16) as usize > 1024 {
        interpreter.instruction_result = InstructionResult::StackOverflow;
        return;
    }

    interpreter.function_stack.set_current_code_idx(idx);
    interpreter.load_eof_code(idx, 0)
}

pub fn pc<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    // - 1 because we have already advanced the instruction pointer in `Interpreter::step`
    push!(interpreter, U256::from(interpreter.program_counter() - 1));
}

#[inline]
fn return_inner(interpreter: &mut Interpreter, instruction_result: InstructionResult) {
    pop!(interpreter, offset, len);
    
    let len = match len {
        StackValueData::Public(val) => as_usize_or_fail!(interpreter, val),
        StackValueData::Private(gate_indices) => {
            match interpreter
                .circuit_builder
                .compile_and_execute::<256>(&gate_indices)
            {
                Ok(garbled_val) => {
                    let u256_val = garbled_uint_to_ruint(&garbled_val);
                    as_usize_or_fail!(interpreter, u256_val)
                },
                Err(_) => {
                    interpreter.instruction_result = InstructionResult::InvalidEOFInitCode;
                    0
                }
            }
        },
        StackValueData::Encrypted(value, key) => {
            let decrypted = ElGamalEncryption::decrypt_to_u256(&value, &key);
            as_usize_or_fail!(interpreter, decrypted)
        }
    };

    let mut output = Bytes::default();
    if len != 0 {
        let offset = match offset {
            StackValueData::Public(val) => as_usize_or_fail!(interpreter, val),
            StackValueData::Private(gate_indices) => {
                match interpreter
                    .circuit_builder
                    .compile_and_execute::<256>(&gate_indices)
                {
                    Ok(garbled_val) => {
                        let u256_val = garbled_uint_to_ruint(&garbled_val);
                        as_usize_or_fail!(interpreter, u256_val)
                    },
                    Err(_) => {
                        interpreter.instruction_result = InstructionResult::InvalidEOFInitCode;
                        0
                    }
                }
            },
            StackValueData::Encrypted(value, key) => {
                let decrypted = ElGamalEncryption::decrypt_to_u256(&value, &key);
                as_usize_or_fail!(interpreter, decrypted)
            }
        };

        resize_memory!(interpreter, offset, len);

        // Acessar diretamente os gate indices da memória privada
        let mut output_data: Vec<u8> = Vec::with_capacity(len);
        for i in 0..len {
            let gate_indices = interpreter.private_memory.get(offset + i);
            
            match interpreter
                .circuit_builder
                .compile_and_execute::<256>(gate_indices)
            {
                Ok(garbled_val) => {
                    let byte_val = garbled_uint_to_ruint(&garbled_val).as_limbs()[0] as u8;
                    output_data.push(byte_val);
                },
                Err(_) => {
                    interpreter.instruction_result = InstructionResult::InvalidEOFInitCode;
                    output_data.push(0);
                }
            }
        }

        output = Bytes::from(output_data);
    }

    interpreter.instruction_result = instruction_result;
    interpreter.next_action = crate::InterpreterAction::Return {
        result: InterpreterResult {
            output,
            gas: interpreter.gas,
            result: instruction_result,
        },
    };
}

pub fn ret<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    return_inner(interpreter, InstructionResult::Return);
}

/// EIP-140: REVERT instruction
pub fn revert<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, _host: &mut H) {
    check!(interpreter, BYZANTIUM);
    return_inner(interpreter, InstructionResult::Revert);
}

/// Stop opcode. This opcode halts the execution.
pub fn stop<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    interpreter.instruction_result = InstructionResult::Stop;
}

/// Invalid opcode. This opcode halts the execution.
pub fn invalid<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    interpreter.instruction_result = InstructionResult::InvalidFEOpcode;
}

/// Unknown opcode. This opcode halts the execution.
pub fn unknown<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    interpreter.instruction_result = InstructionResult::OpcodeNotFound;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::instructions::utility::ruint_to_garbled_uint;
    use crate::{table::make_instruction_table, DummyHost, FunctionReturnFrame, Gas, Interpreter};
    use bytecode::opcode::{
        CALLF, JUMP, JUMPDEST, JUMPF, JUMPI, NOP, PUSH1, RETF, RJUMP, RJUMPI, RJUMPV, STOP,
    };
    use bytecode::{
        eof::{Eof, TypesSection},
        Bytecode,
    };
    use compute::uint::GarbledUint256;
    use primitives::bytes;
    use specification::hardfork::PragueSpec;
    use std::sync::Arc;
    use wiring::DefaultEthereumWiring;

    #[test]
    fn rjump() {
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();
        let mut host = DummyHost::default();
        let mut interp =
            Interpreter::new_bytecode(Bytecode::LegacyRaw([RJUMP, 0x00, 0x02, STOP, STOP].into()));
        interp.is_eof = true;
        interp.gas = Gas::new(10000);

        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 5);
    }

    #[test]
    fn rjumpi() {
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();
        let mut host = DummyHost::default();
        let mut interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
            [RJUMPI, 0x00, 0x03, RJUMPI, 0x00, 0x01, STOP, STOP].into(),
        ));
        interp.is_eof = true;
        interp.stack.push(U256::from(1)).unwrap();
        interp.stack.push(U256::from(0)).unwrap();
        interp.gas = Gas::new(10000);

        // dont jump
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 3);
        // jumps to last opcode
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 7);
    }

    #[test]
    fn rjumpi_private() {
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();
        let mut host = DummyHost::default();
        let mut interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
            [RJUMPI, 0x00, 0x03, RJUMPI, 0x00, 0x01, STOP, STOP].into(),
        ));
        interp.is_eof = true;

        let garbled_one = GarbledUint::<256>::one();
        let garbled_one_gates = interp.circuit_builder.input(&garbled_one);
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(garbled_one_gates))
            .unwrap();

        let garbled_zero = GarbledUint::<256>::zero();
        let garbled_zero_gates = interp.circuit_builder.input(&garbled_zero);
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(garbled_zero_gates))
            .unwrap();
        interp.gas = Gas::new(10000);

        // don't jump
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 3);
        // jumps to last opcode
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 7);
    }

    #[test]
    fn rjumpv() {
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();
        let mut host = DummyHost::default();
        let mut interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
            [
                RJUMPV,
                0x01, // max index, 0 and 1
                0x00, // first x0001
                0x01,
                0x00, // second 0x002
                0x02,
                NOP,
                NOP,
                NOP,
                RJUMP,
                0xFF,
                (-12i8) as u8,
                STOP,
            ]
            .into(),
        ));
        interp.is_eof = true;
        interp.gas = Gas::new(1000);

        // more then max_index
        interp.stack.push(U256::from(10)).unwrap();
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 6);

        // cleanup
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 0);

        // jump to first index of vtable
        interp.stack.push(U256::from(0)).unwrap();
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 7);

        // cleanup
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 0);

        // jump to second index of vtable
        interp.stack.push(U256::from(1)).unwrap();
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 8);
    }

    #[test]
    fn rjumpv_private() {
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();
        let mut host = DummyHost::default();
        let mut interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
            [
                RJUMPV,
                0x01, // max index, 0 and 1
                0x00, // first x0001
                0x01,
                0x00, // second 0x002
                0x02,
                NOP,
                NOP,
                NOP,
                RJUMP,
                0xFF,
                (-12i8) as u8,
                STOP,
            ]
            .into(),
        ));
        interp.is_eof = true;
        interp.gas = Gas::new(1000);

        // more then max_index
        let garbled_ten = ruint_to_garbled_uint(&U256::from(10));
        let garbled_ten_gates = interp.circuit_builder.input(&garbled_ten);
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(garbled_ten_gates))
            .unwrap();
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 6);

        // cleanup
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 0);

        // jump to first index of vtable
        let garbled_zero = ruint_to_garbled_uint(&U256::from(0));
        let garbled_zero_gates = interp.circuit_builder.input(&garbled_zero);
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(garbled_zero_gates))
            .unwrap();
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 7);

        // cleanup
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 0);

        // jump to second index of vtable
        let garbled_one = ruint_to_garbled_uint(&U256::from(1));
        let garbled_one_gates = interp.circuit_builder.input(&garbled_one);
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(garbled_one_gates))
            .unwrap();
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 8);
    }

    #[test]
    fn jump() {
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();
        let mut host = DummyHost::default();

        // 1) Test JUMP to a valid address = 3
        let mut interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
            [PUSH1, 0x04, JUMP, 0x01, JUMPDEST, STOP].into(),
        ));
        interp.is_eof = true;
        interp.gas = Gas::new(10000);

        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 4, "jump to 4 should succeed");

        // 2) Test JUMP to invalid address = 0
        interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
            [PUSH1, 0x00, JUMP, 0x01, JUMPDEST, STOP].into(),
        ));
        interp.is_eof = true;
        interp.gas = Gas::new(10000);

        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        assert_eq!(
            interp.program_counter(),
            3,
            "jump to invalid address 0 should do nothing"
        );
    }

    #[test]
    fn jump_private() {
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();
        let mut host = DummyHost::default();
        let mut interp =
            Interpreter::new_bytecode(Bytecode::LegacyRaw([JUMP, 0x04, JUMPDEST, STOP].into()));
        interp.is_eof = true;
        interp.gas = Gas::new(10000);

        // Create a private target address
        let target = ruint_to_garbled_uint(&U256::from(2)); // JUMPDEST is at position 1
        let target_gates = interp.circuit_builder.input(&target);

        // Push the private target address onto the stack
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(target_gates))
            .unwrap();

        // Execute the step
        interp.step(&table, &mut host); // JUMP
                                        // Check if the program counter has jumped to the target address (1)
        assert_eq!(interp.program_counter(), 2);
    }

    #[test]
    fn jumpi() {
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();
        let mut host = DummyHost::default();
        let mut interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
            [JUMPI, 0x03, 0x00, JUMPDEST, STOP, STOP, STOP, STOP].into(),
        ));
        interp.is_eof = true;
        interp.gas = Gas::new(10000);

        // Push the condition (1) onto the stack
        interp.stack.push(U256::from(1)).unwrap();
        // Push the target address (3) onto the stack
        interp.stack.push(U256::from(3)).unwrap();

        // Execute the step
        interp.step(&table, &mut host);
        // Check if the program counter has jumped to the target address (3)
        assert_eq!(interp.program_counter(), 3);
    }

    #[test]
    fn jumpi_private() {
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();
        let mut host = DummyHost::default();
        let mut interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
            [JUMPI, 0x03, 0x00, JUMPDEST, STOP].into(),
        ));
        interp.is_eof = true;
        interp.gas = Gas::new(10000);

        // Create a private condition
        let condition = GarbledUint256::one();
        let condition_gates = interp.circuit_builder.input(&condition);

        // Push the private condition onto the stack
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(condition_gates))
            .unwrap();

        // Push the target address (3) onto the stack
        interp
            .stack
            .push_stack_value_data(StackValueData::Public(U256::from(3)))
            .unwrap();

        // Execute the step
        interp.step(&table, &mut host);
        // Check if the program counter has jumped to the target address (3)
        assert_eq!(interp.program_counter(), 3);
    }

    fn dummy_eof() -> Eof {
        let bytes = bytes!("ef000101000402000100010400000000800000fe");
        Eof::decode(bytes).unwrap()
    }

    fn eof_setup(bytes1: Bytes, bytes2: Bytes) -> Interpreter {
        eof_setup_with_types(bytes1, bytes2, TypesSection::default())
    }

    /// Two code section and types section is for last code.
    fn eof_setup_with_types(bytes1: Bytes, bytes2: Bytes, types: TypesSection) -> Interpreter {
        let mut eof = dummy_eof();

        eof.body.code_section.clear();
        eof.body.types_section.clear();
        eof.header.code_sizes.clear();

        eof.header.code_sizes.push(bytes1.len() as u16);
        eof.body.code_section.push(bytes1.clone());
        eof.body.types_section.push(TypesSection::new(0, 0, 11));

        eof.header.code_sizes.push(bytes2.len() as u16);
        eof.body.code_section.push(bytes2.clone());
        eof.body.types_section.push(types);

        let mut interp = Interpreter::new_bytecode(Bytecode::Eof(Arc::new(eof)));
        interp.gas = Gas::new(10000);
        interp
    }

    #[test]
    fn callf_retf_stop() {
        let table = make_instruction_table::<_, PragueSpec>();
        let mut host = DummyHost::<DefaultEthereumWiring>::default();

        let bytes1 = Bytes::from([CALLF, 0x00, 0x01, STOP]);
        let bytes2 = Bytes::from([RETF]);
        let mut interp = eof_setup(bytes1, bytes2.clone());

        // CALLF
        interp.step(&table, &mut host);

        assert_eq!(interp.function_stack.current_code_idx, 1);
        assert_eq!(
            interp.function_stack.return_stack[0],
            FunctionReturnFrame::new(0, 3)
        );
        assert_eq!(interp.instruction_pointer, bytes2.as_ptr());

        // RETF
        interp.step(&table, &mut host);

        assert_eq!(interp.function_stack.current_code_idx, 0);
        assert_eq!(interp.function_stack.return_stack, Vec::new());
        assert_eq!(interp.program_counter(), 3);

        // STOP
        interp.step(&table, &mut host);
        assert_eq!(interp.instruction_result, InstructionResult::Stop);
    }

    #[test]
    fn callf_stop() {
        let table = make_instruction_table::<_, PragueSpec>();
        let mut host = DummyHost::<DefaultEthereumWiring>::default();

        let bytes1 = Bytes::from([CALLF, 0x00, 0x01]);
        let bytes2 = Bytes::from([STOP]);
        let mut interp = eof_setup(bytes1, bytes2.clone());

        // CALLF
        interp.step(&table, &mut host);

        assert_eq!(interp.function_stack.current_code_idx, 1);
        assert_eq!(
            interp.function_stack.return_stack[0],
            FunctionReturnFrame::new(0, 3)
        );
        assert_eq!(interp.instruction_pointer, bytes2.as_ptr());

        // STOP
        interp.step(&table, &mut host);
        assert_eq!(interp.instruction_result, InstructionResult::Stop);
    }

    #[test]
    fn callf_stack_overflow() {
        let table = make_instruction_table::<_, PragueSpec>();
        let mut host = DummyHost::<DefaultEthereumWiring>::default();

        let bytes1 = Bytes::from([CALLF, 0x00, 0x01]);
        let bytes2 = Bytes::from([STOP]);
        let mut interp =
            eof_setup_with_types(bytes1, bytes2.clone(), TypesSection::new(0, 0, 1025));

        // CALLF
        interp.step(&table, &mut host);

        // stack overflow
        assert_eq!(interp.instruction_result, InstructionResult::StackOverflow);
    }

    #[test]
    fn jumpf_stop() {
        let table = make_instruction_table::<_, PragueSpec>();
        let mut host = DummyHost::<DefaultEthereumWiring>::default();

        let bytes1 = Bytes::from([JUMPF, 0x00, 0x01]);
        let bytes2 = Bytes::from([STOP]);
        let mut interp = eof_setup(bytes1, bytes2.clone());

        // JUMPF
        interp.step(&table, &mut host);

        assert_eq!(interp.function_stack.current_code_idx, 1);
        assert!(interp.function_stack.return_stack.is_empty());
        assert_eq!(interp.instruction_pointer, bytes2.as_ptr());

        // STOP
        interp.step(&table, &mut host);
        assert_eq!(interp.instruction_result, InstructionResult::Stop);
    }

    #[test]
    fn jumpf_stack_overflow() {
        let table = make_instruction_table::<_, PragueSpec>();
        let mut host = DummyHost::<DefaultEthereumWiring>::default();

        let bytes1 = Bytes::from([JUMPF, 0x00, 0x01]);
        let bytes2 = Bytes::from([STOP]);
        let mut interp =
            eof_setup_with_types(bytes1, bytes2.clone(), TypesSection::new(0, 0, 1025));

        // JUMPF
        interp.step(&table, &mut host);

        // stack overflow
        assert_eq!(interp.instruction_result, InstructionResult::StackOverflow);
    }
}
