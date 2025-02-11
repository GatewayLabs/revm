use super::utility::{garbled_uint_to_ruint, read_i16, read_u16};
use crate::instructions::utility::ruint_to_garbled_uint;
use crate::{
    gas,
    interpreter::{
        private_memory::{is_private_tag, PrivateMemoryValue},
        StackValueData,
    },
    Host, InstructionResult, Interpreter, InterpreterResult,
};
use compute::operations::circuits::types::GateIndexVec;
use compute::prelude::CircuitExecutor;
use compute::uint::GarbledUint256;
use primitives::{Bytes, U256};
use specification::hardfork::Spec;

pub fn rjump<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    require_eof!(interpreter);
    gas!(interpreter, gas::BASE);
    let offset = unsafe { read_i16(interpreter.instruction_pointer) } as isize;
    interpreter.instruction_pointer = unsafe { interpreter.instruction_pointer.offset(offset + 2) };
}

pub fn rjumpi<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    require_eof!(interpreter);
    gas!(interpreter, gas::CONDITION_JUMP_GAS);
    pop!(interpreter, condition);

    let current_pc = interpreter.program_counter() + 2;
    match condition {
        StackValueData::Public(condition) => {
            let mut offset = 2;
            if !condition.is_zero() {
                offset += unsafe { read_i16(interpreter.instruction_pointer) } as isize;
            }
            interpreter.instruction_pointer =
                unsafe { interpreter.instruction_pointer.offset(offset) };
        }
        StackValueData::Private(condition_gates) => {
            let jump_offset = unsafe { read_i16(interpreter.instruction_pointer) };
            let target_pc = (current_pc as isize + jump_offset as isize) as usize;

            let next_pc_gates =
                interpreter.setup_private_branch(&condition_gates, target_pc, current_pc);

            interpreter.handle_private_branch(next_pc_gates);
        }
        StackValueData::Encrypted(_ciphertext) => panic!("Cannot convert encrypted value to U256"),
    }
}

pub fn rjumpv<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    require_eof!(interpreter);
    gas!(interpreter, gas::CONDITION_JUMP_GAS);
    pop!(interpreter, case);
    match case {
        StackValueData::Public(case) => {
            let case = as_isize_saturated!(case);
            let max_index = unsafe { *interpreter.instruction_pointer } as isize;

            let mut offset = (max_index + 1) * 2 + 1;
            if case <= max_index {
                offset += unsafe { read_i16(interpreter.instruction_pointer.offset(1 + case * 2)) }
                    as isize;
            }
            interpreter.instruction_pointer =
                unsafe { interpreter.instruction_pointer.offset(offset) };
        }
        StackValueData::Private(case_gates) => {
            let mut cb = interpreter.circuit_builder.borrow_mut();
            let max_index = unsafe { *interpreter.instruction_pointer } as usize;
            let fallthrough_pc = interpreter.program_counter() + (max_index + 1) * 2 + 1;
            let fallthrough_pc_garbled = ruint_to_garbled_uint(&U256::from(fallthrough_pc));
            let fallthrough_pc_gates = cb.input(&fallthrough_pc_garbled);

            let mut next_pc_gates = fallthrough_pc_gates.clone();

            for i in 0..=max_index {
                let target_offset = unsafe {
                    read_i16(interpreter.instruction_pointer.offset(1 + (i as isize * 2)))
                } as usize;
                let target_pc = fallthrough_pc + target_offset;
                let target_pc_garbled = ruint_to_garbled_uint(&U256::from(target_pc));
                let target_pc_gates = cb.input(&target_pc_garbled);
                let case_value = ruint_to_garbled_uint(&U256::from(i));
                let case_value_gates = cb.input(&case_value);
                let eq_condition = cb.eq(&case_gates, &case_value_gates);
                next_pc_gates = cb.mux(&eq_condition, &target_pc_gates, &next_pc_gates);
            }
            drop(cb);
            interpreter.next_pc = Some(next_pc_gates);
            interpreter.handle_private_jump = true;
            return;
        }
        StackValueData::Encrypted(_ciphertext) => panic!("Cannot convert encrypted value to U256"),
    }
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
        StackValueData::Private(cond_gates) => {
            let mut cb = interpreter.circuit_builder.borrow_mut();

            let target_pc = match target {
                StackValueData::Public(target) => {
                    // Convert public target to private gates
                    let target_garbled = ruint_to_garbled_uint(&target);
                    let target_gates = cb.input(&target_garbled);
                    target_gates
                }
                StackValueData::Private(target_gates) => target_gates,
                StackValueData::Encrypted(_) => panic!("Cannot handle encrypted jump target"),
            };

            // Create private PC for current position
            let current_pc_garbled =
                ruint_to_garbled_uint(&U256::from(interpreter.program_counter()));
            let current_pc_gates = cb.input(&current_pc_garbled);

            let zero = GarbledUint256::zero();
            let zero_gates = cb.input(&zero);
            let condition = cb.ne(&cond_gates, &zero_gates);
            let next_pc_gates = cb.mux(&condition, &target_pc, &current_pc_gates);

            drop(cb);
            interpreter.next_pc = Some(next_pc_gates);
            interpreter.handle_private_jump = true;
        }
        StackValueData::Encrypted(_ciphertext) => {
            panic!("Cannot handle encrypted condition")
        }
    }
}

#[inline]
fn jump_inner(interpreter: &mut Interpreter, target: StackValueData) {
    match target {
        StackValueData::Public(target) => {
            let target = as_usize_or_fail!(interpreter, target, InstructionResult::InvalidJump);
            if !interpreter.contract.is_valid_jump(target) {
                interpreter.instruction_result = InstructionResult::InvalidJump;
                return;
            }
            // SAFETY: `is_valid_jump` ensures that `dest` is in bounds.
            interpreter.instruction_pointer = unsafe { interpreter.bytecode.as_ptr().add(target) };
        }
        StackValueData::Private(target_gates) => {
            interpreter.next_pc = Some(target_gates);
            interpreter.handle_private_jump = true;
        }
        StackValueData::Encrypted(_ciphertext) => panic!("Cannot handle encrypted jump target"),
    }
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
    push!(
        interpreter,
        U256::from(interpreter.program_counter() - 1).into()
    );
}

#[inline]
fn return_inner(interpreter: &mut Interpreter, instruction_result: InstructionResult) {
    // zero gas cost
    // gas!(interpreter, gas::ZERO);
    pop!(interpreter, offset, len);
    let len = as_usize_or_fail!(
        interpreter,
        len.evaluate(&interpreter.circuit_builder.borrow())
    );
    // important: offset must be ignored if len is zeros
    let mut output = Bytes::default();
    if len != 0 {
        let offset = as_usize_or_fail!(
            interpreter,
            offset.evaluate(&interpreter.circuit_builder.borrow())
        );
        resize_memory!(interpreter, offset, len);

        let shared_mem = interpreter.shared_memory.slice(offset, len);
        if is_private_tag(shared_mem) {
            let mut garbled_result: GarbledUint256 = GarbledUint256::default();
            match interpreter
                .private_memory
                .get(shared_mem.try_into().unwrap())
            {
                PrivateMemoryValue::Private(indices) => {
                    garbled_result = interpreter
                        .circuit_builder
                        .borrow()
                        .compile_and_execute(&indices)
                        .unwrap();
                    // Assign the Uint<256, 4> to a local variable
                    let ruint_value = garbled_uint_to_ruint::<256>(&garbled_result);
                    output = Into::<Bytes>::into(ruint_value.as_le_slice().to_vec());
                }
                _ => todo!(),
            }
        } else {
            output = shared_mem.to_vec().into()
        }
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
pub fn commit_private_jump_with_target(interpreter: &mut Interpreter, target: usize) {
    if interpreter.handle_private_jump {
        interpreter.instruction_pointer = unsafe { interpreter.bytecode.as_ptr().add(target) };
        interpreter.handle_private_jump = false;
        interpreter.next_pc = None;
    }
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
    use compute::prelude::GarbledUint;
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
        interp.stack.push(U256::from(1).into()).unwrap();
        interp.stack.push(U256::from(0).into()).unwrap();
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
        let garbled_one_gates = interp.circuit_builder.borrow_mut().input(&garbled_one);
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(garbled_one_gates))
            .unwrap();

        let garbled_zero = GarbledUint::<256>::zero();
        let garbled_zero_gates = interp.circuit_builder.borrow_mut().input(&garbled_zero);
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(garbled_zero_gates))
            .unwrap();
        interp.gas = Gas::new(10000);

        // First RJUMPI: condition in top of stack is false, so no jump.
        interp.step(&table, &mut host);
        commit_private_jump_with_target(&mut interp, 3);
        assert_eq!(interp.program_counter(), 3);

        // Second RJUMPI: condition is nonzero, so jump occurs.
        interp.step(&table, &mut host);
        commit_private_jump_with_target(&mut interp, 7);
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
        interp.stack.push(U256::from(10).into()).unwrap();
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 6);

        // cleanup
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 0);

        // jump to first index of vtable
        interp.stack.push(U256::from(0).into()).unwrap();
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 7);

        // cleanup
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 0);

        // jump to second index of vtable
        interp.stack.push(U256::from(1).into()).unwrap();
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
        interp.stack.push(U256::from(10).into()).unwrap();
        interp.step(&table, &mut host);
        commit_private_jump_with_target(&mut interp, 6);
        assert_eq!(interp.program_counter(), 6);

        // cleanup
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 0);

        // jump to first index of vtable
        interp.stack.push(U256::from(0).into()).unwrap();
        interp.step(&table, &mut host);
        commit_private_jump_with_target(&mut interp, 7);
        assert_eq!(interp.program_counter(), 7);

        // cleanup
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        interp.step(&table, &mut host);
        assert_eq!(interp.program_counter(), 0);

        // jump to second index of vtable
        interp.stack.push(U256::from(1).into()).unwrap();
        interp.step(&table, &mut host);
        commit_private_jump_with_target(&mut interp, 8);
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
        let target_gates = interp.circuit_builder.borrow_mut().input(&target);

        // Push the private target address onto the stack
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(target_gates))
            .unwrap();

        // Execute the step
        interp.step(&table, &mut host); // JUMP
                                        // Commit the private jump for testing
        commit_private_jump_with_target(&mut interp, 2);
        // Check if the program counter has been updated to expected value (2)
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
        interp.stack.push(U256::from(1).into()).unwrap();
        // Push the target address (3) onto the stack
        interp.stack.push(U256::from(3).into()).unwrap();

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
        let condition_gates = interp.circuit_builder.borrow_mut().input(&condition);

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
        commit_private_jump_with_target(&mut interp, 3);
        // Check if the program counter has been updated to expected value (3)
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

impl Interpreter {
    /// Sets up private branching logic and returns the next PC gates
    fn setup_private_branch(
        &self,
        condition_gates: &GateIndexVec,
        target_pc: usize,
        fallthrough_pc: usize,
    ) -> GateIndexVec {
        let mut cb = self.circuit_builder.borrow_mut();

        // Create PC gates for both paths using the already-borrowed cb
        let target_pc_garbled = ruint_to_garbled_uint(&U256::from(target_pc));
        let target_pc_gates = cb.input(&target_pc_garbled);
        let fallthrough_pc_garbled = ruint_to_garbled_uint(&U256::from(fallthrough_pc));
        let fallthrough_pc_gates = cb.input(&fallthrough_pc_garbled);

        // Create zero gates for comparison using cb
        let zero = GarbledUint256::zero();
        let zero_gates = cb.input(&zero);

        // Compare condition with zero and select path
        let condition = cb.ne(condition_gates, &zero_gates);
        cb.mux(&condition, &target_pc_gates, &fallthrough_pc_gates)
    }

    /// Handles the result of a private branch operation
    fn handle_private_branch(&mut self, next_pc_gates: GateIndexVec) {
        self.next_pc = Some(next_pc_gates);
        self.handle_private_jump = true;
    }
}
