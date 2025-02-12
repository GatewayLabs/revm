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

    let current_pc = interpreter.program_counter();
    let offset = unsafe { read_i16(interpreter.instruction_pointer) } as isize;
    let new_pc = current_pc + 2 + (offset as usize);

    // Create circuit wire for the new PC and update mappings
    let next_pc_gates = interpreter.create_pc_wire(new_pc);
    interpreter.update_pc_mapping(current_pc, next_pc_gates.clone());
    interpreter.current_pc_wire = Some(next_pc_gates);

    // Update actual PC
    interpreter.instruction_pointer = unsafe { interpreter.bytecode.as_ptr().add(new_pc) };
}

pub fn rjumpi<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    require_eof!(interpreter);
    gas!(interpreter, gas::CONDITION_JUMP_GAS);
    pop!(interpreter, condition);

    let base_pc = interpreter.program_counter() + 2;
    let jump_offset = unsafe { read_i16(interpreter.instruction_pointer) } as isize;
    let jump_dest = (base_pc as isize + jump_offset) as usize;

    match condition {
        StackValueData::Public(cond) => {
            let new_pc = if !cond.is_zero() { jump_dest } else { base_pc };
            // Create circuit wire for the new PC
            let next_pc_gates = interpreter.create_pc_wire(new_pc);
            let instr_pc = interpreter.program_counter() - 1;
            interpreter.update_pc_mapping(instr_pc, next_pc_gates);
            interpreter.instruction_pointer = unsafe { interpreter.bytecode.as_ptr().add(new_pc) };
        }
        StackValueData::Private(cond_gates) => {
            // Create circuit wires for both possible next PCs
            let base_pc_gates = interpreter.create_pc_wire(base_pc);
            let jump_dest_gates = interpreter.create_pc_wire(jump_dest);

            // Use MUX to select between jump destination and fallthrough
            let next_pc_gates = interpreter.circuit_builder.borrow_mut().mux(
                &cond_gates[0],
                &jump_dest_gates,
                &base_pc_gates,
            );

            let instr_pc = interpreter.program_counter() - 1;
            interpreter.update_pc_mapping(instr_pc, next_pc_gates);
            interpreter.instruction_pointer = unsafe { interpreter.bytecode.as_ptr().add(base_pc) };
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
            let new_pc = (interpreter.program_counter() as isize + offset) as usize;

            // Create circuit wire for the new PC and update mappings
            let next_pc_gates = interpreter.create_pc_wire(new_pc);
            let instr_pc = interpreter.program_counter() - 1;
            interpreter.update_pc_mapping(instr_pc, next_pc_gates.clone());
            interpreter.current_pc_wire = Some(next_pc_gates);

            interpreter.instruction_pointer =
                unsafe { interpreter.instruction_pointer.offset(offset) };
        }
        StackValueData::Private(case_gates) => {
            let instruction_pc = interpreter.program_counter() - 1;
            let max_index = unsafe { *interpreter.instruction_pointer } as usize;

            let fallthrough_pc = instruction_pc + 2 + 2 * (max_index + 1);
            let mut next_pc_gates = interpreter.create_pc_wire(fallthrough_pc);

            // Build MUX chain for each possible case
            for i in 0..=max_index {
                let offset =
                    unsafe { read_i16(interpreter.instruction_pointer.add(1 + i * 2)) } as isize;
                let target_pc = (fallthrough_pc as isize + offset) as usize;

                // Create circuit wire for this case's target PC
                let target_pc_gates = interpreter.create_pc_wire(target_pc);

                // Create equality check for this case
                let case_value = ruint_to_garbled_uint(&U256::from(i));
                let case_value_gates = interpreter.circuit_builder.borrow_mut().input(&case_value);
                let eq_condition = interpreter
                    .circuit_builder
                    .borrow_mut()
                    .eq(&case_gates, &case_value_gates);

                // MUX between current next_pc and this case's target
                next_pc_gates = interpreter.circuit_builder.borrow_mut().mux(
                    &eq_condition,
                    &target_pc_gates,
                    &next_pc_gates,
                );
            }

            // Update PC mappings
            interpreter.update_pc_mapping(instruction_pc, next_pc_gates.clone());
            interpreter.current_pc_wire = Some(next_pc_gates);

            interpreter.instruction_pointer =
                unsafe { interpreter.bytecode.as_ptr().add(fallthrough_pc) };
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
    pop!(interpreter, target, condition);
    let current_pc = interpreter.program_counter();
    let fallthrough_pc = current_pc;

    match condition {
        StackValueData::Public(cond) => {
            if !cond.is_zero() {
                jump_inner(interpreter, target);
            }
        }
        StackValueData::Private(cond_gates) => {
            let target_pc = match target {
                StackValueData::Public(target) => {
                    as_usize_or_fail!(interpreter, target, InstructionResult::InvalidJump)
                }
                StackValueData::Private(_) => {
                    panic!("Private jump targets not supported in public PC mode")
                }
                StackValueData::Encrypted(_) => panic!("Cannot handle encrypted jump target"),
            };

            // Create circuit wires for both possible next PCs
            let fallthrough_gates = interpreter.create_pc_wire(fallthrough_pc);
            let target_gates = interpreter.create_pc_wire(target_pc);

            // Use MUX to select between jump destination and fallthrough
            let next_pc_gates = interpreter.circuit_builder.borrow_mut().mux(
                &cond_gates[0],
                &target_gates,
                &fallthrough_gates,
            );

            // Store next PC gates in program counter mapping
            let instr_pc = interpreter.program_counter() - 1;
            interpreter.update_pc_mapping(instr_pc, next_pc_gates);
            interpreter.instruction_pointer =
                unsafe { interpreter.bytecode.as_ptr().add(fallthrough_pc) };
        }
        StackValueData::Encrypted(_ciphertext) => panic!("Cannot handle encrypted condition"),
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
            // Create circuit wire for the target PC
            let next_pc_gates = interpreter.create_pc_wire(target);
            let instr_pc = interpreter.program_counter() - 1;
            interpreter.update_pc_mapping(instr_pc, next_pc_gates.clone());

            // Update current PC wire
            interpreter.current_pc_wire = Some(next_pc_gates);

            // Update actual PC
            interpreter.instruction_pointer = unsafe { interpreter.bytecode.as_ptr().add(target) };
        }
        StackValueData::Private(target_gates) => {
            // For private targets, we need to evaluate the target in the circuit
            let target_value = interpreter.evaluate_private_target(&target_gates);
            let target =
                as_usize_or_fail!(interpreter, target_value, InstructionResult::InvalidJump);

            if !interpreter.contract.is_valid_jump(target) {
                interpreter.instruction_result = InstructionResult::InvalidJump;
                return;
            }

            // Store target gates in program counter mapping and current PC wire
            let instr_pc = interpreter.program_counter() - 1;
            interpreter.update_pc_mapping(instr_pc, target_gates.clone());
            interpreter.current_pc_wire = Some(target_gates);

            // Update actual PC
            interpreter.instruction_pointer = unsafe { interpreter.bytecode.as_ptr().add(target) };
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

    // Calculate return PC
    let return_pc = interpreter.program_counter() + 2;

    // Create circuit wire for return PC
    let return_pc_gates = interpreter.create_pc_wire(return_pc);
    interpreter.update_pc_mapping(return_pc - 1, return_pc_gates);

    // push current idx and PC to the callf stack.
    interpreter.function_stack.push(return_pc, idx);

    // Create circuit wire for target PC (0)
    let target_pc_gates = interpreter.create_pc_wire(0);
    interpreter.current_pc_wire = Some(target_pc_gates.clone());
    interpreter.update_pc_mapping(0, target_pc_gates);

    interpreter.load_eof_code(idx, 0)
}

pub fn retf<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    require_eof!(interpreter);
    gas!(interpreter, gas::RETF_GAS);

    let Some(fframe) = interpreter.function_stack.pop() else {
        panic!("Expected function frame")
    };

    // Create circuit wire for return PC
    let return_pc_gates = interpreter.create_pc_wire(fframe.pc);
    let current_pc = interpreter.program_counter();
    interpreter.update_pc_mapping(current_pc, return_pc_gates.clone());
    interpreter.current_pc_wire = Some(return_pc_gates);

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

impl Interpreter {
    /// Evaluates a private target value in the circuit and returns the target PC
    fn evaluate_private_target(&self, target_gates: &GateIndexVec) -> U256 {
        let private_value = StackValueData::Private(target_gates.clone());
        private_value.evaluate(&self.circuit_builder.borrow())
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
    use compute::prelude::WRK17CircuitBuilder;
    use compute::uint::GarbledUint256;
    use primitives::bytes;
    use specification::hardfork::PragueSpec;
    use std::cell::RefCell;
    use std::sync::Arc;
    use wiring::DefaultEthereumWiring;

    fn evaluate_circuit_pc(
        circuit_builder: &RefCell<WRK17CircuitBuilder>,
        pc_gates: &GateIndexVec,
    ) -> usize {
        let cb = circuit_builder.borrow();
        let result = cb.compile_and_execute(pc_gates).unwrap();
        let ruint_value = garbled_uint_to_ruint::<256>(&result);
        ruint_value.as_limbs()[0] as usize
    }

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
    fn jumpi_private() {
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();
        let mut host = DummyHost::default();

        for condition in [true, false] {
            // Bytecode layout:
            // [0] JUMPI
            // [1] NOP (fallthrough)
            // [2] NOP
            // [3] JUMPDEST (target)
            // [4] STOP
            let mut interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
                [JUMPI, NOP, NOP, JUMPDEST, STOP].into(),
            ));
            interp.is_eof = true;
            interp.gas = Gas::new(10000);

            // Push target address (3)
            let target = U256::from(3);
            interp
                .stack
                .push_stack_value_data(StackValueData::Public(target))
                .unwrap();

            // Create and push private condition
            let garbled_condition = if condition {
                GarbledUint256::one()
            } else {
                GarbledUint256::zero()
            };
            let condition_gates = interp
                .circuit_builder
                .borrow_mut()
                .input(&garbled_condition);
            interp
                .stack
                .push_stack_value_data(StackValueData::Private(condition_gates))
                .unwrap();

            // Execute JUMPI
            interp.step(&table, &mut host);

            // Get the program counter gates from mapping
            let pc = interp.program_counter();
            let pc_gates = interp.program_count_mapping.get(&pc).unwrap();
            let actual_pc = evaluate_circuit_pc(&interp.circuit_builder, pc_gates);

            // When condition is true, jump to target (3)
            // When false, continue to next instruction (1)
            let expected_pc = if condition { 3 } else { 1 };
            assert_eq!(actual_pc, expected_pc);
        }
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

        // Corrected test cases with proper offsets
        for (case, expected_pc) in [(2, 6), (0, 7), (1, 8)] {
            let mut interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
                [
                    RJUMPV, // [0]
                    0x01,   // [1] max_index
                    0x00, 0x01, // [2-3] case 0 offset (+1)
                    0x00, 0x02, // [4-5] case 1 offset (+2)
                    NOP,  // [6] fallthrough
                    NOP,  // [7] case 0 target
                    NOP,  // [8] case 1 target
                    STOP, // [9] end
                ]
                .into(),
            ));
            interp.is_eof = true;
            interp.gas = Gas::new(1000);

            // Create and push private case value
            let garbled_case = ruint_to_garbled_uint(&U256::from(case));
            let case_gates = interp.circuit_builder.borrow_mut().input(&garbled_case);
            interp
                .stack
                .push_stack_value_data(StackValueData::Private(case_gates))
                .unwrap();

            // Execute RJUMPV
            interp.step(&table, &mut host);

            // Get the program counter gates from mapping
            let pc = interp.program_counter();
            let pc_gates = interp.program_count_mapping.get(&pc).unwrap();
            let actual_pc = evaluate_circuit_pc(&interp.circuit_builder, pc_gates);
            assert_eq!(actual_pc, expected_pc);
        }
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

        // Create private target address
        let target = ruint_to_garbled_uint(&U256::from(2));
        let target_gates = interp.circuit_builder.borrow_mut().input(&target);
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(target_gates))
            .unwrap();

        // Execute JUMP
        interp.step(&table, &mut host);

        // Get the program counter gates from mapping
        let pc = interp.program_counter();
        let pc_gates = interp.program_count_mapping.get(&pc).unwrap();
        let actual_pc = evaluate_circuit_pc(&interp.circuit_builder, pc_gates);
        assert_eq!(actual_pc, 2);
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

    #[test]
    fn test_private_jump() {
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();
        let mut host = DummyHost::default();

        // Create bytecode: PUSH1 3, JUMP, STOP, JUMPDEST, STOP
        let mut interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
            [PUSH1, 0x03, JUMP, STOP, JUMPDEST, STOP].into(),
        ));
        interp.gas = Gas::new(10000);

        // Create private jump target
        let target = U256::from(3);
        let target_garbled = ruint_to_garbled_uint(&target);
        let target_gates = interp.circuit_builder.borrow_mut().input(&target_garbled);
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(target_gates))
            .unwrap();

        // Execute JUMP
        interp.step(&table, &mut host);

        // Verify PC wire is consistent
        let pc = interp.program_counter();
        assert_eq!(pc, 3, "Jump should go to PC=3");

        let pc_gates = interp.current_pc_wire.as_ref().unwrap();
        let circuit_pc =
            StackValueData::Private(pc_gates.clone()).evaluate(&interp.circuit_builder.borrow());
        assert_eq!(
            circuit_pc.as_limbs()[0] as usize,
            3,
            "Circuit PC should match actual PC"
        );
    }

    #[test]
    fn test_private_jumpi_taken() {
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();
        let mut host = DummyHost::default();

        // Create bytecode: PUSH1 3, PUSH1 1, JUMPI, STOP, JUMPDEST, STOP
        let mut interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
            [PUSH1, 0x03, PUSH1, 0x01, JUMPI, STOP, JUMPDEST, STOP].into(),
        ));
        interp.gas = Gas::new(10000);

        // Create private condition (true)
        let condition = GarbledUint256::one();
        let cond_gates = interp.circuit_builder.borrow_mut().input(&condition);
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(cond_gates))
            .unwrap();

        // Push target
        interp.stack.push(U256::from(3).into()).unwrap();

        // Execute JUMPI
        interp.step(&table, &mut host);

        // Verify PC wire is consistent
        let pc = interp.program_counter();
        assert_eq!(pc, 3, "Jump should be taken to PC=3");

        let pc_gates = interp.current_pc_wire.as_ref().unwrap();
        let circuit_pc =
            StackValueData::Private(pc_gates.clone()).evaluate(&interp.circuit_builder.borrow());
        assert_eq!(
            circuit_pc.as_limbs()[0] as usize,
            3,
            "Circuit PC should match actual PC"
        );
    }

    #[test]
    fn test_private_jumpi_not_taken() {
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();
        let mut host = DummyHost::default();

        // Create bytecode: PUSH1 3, PUSH1 0, JUMPI, STOP, JUMPDEST, STOP
        let mut interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
            [PUSH1, 0x03, PUSH1, 0x00, JUMPI, STOP, JUMPDEST, STOP].into(),
        ));
        interp.gas = Gas::new(10000);

        // Create private condition (false)
        let condition = GarbledUint256::zero();
        let cond_gates = interp.circuit_builder.borrow_mut().input(&condition);
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(cond_gates))
            .unwrap();

        // Push target
        interp.stack.push(U256::from(3).into()).unwrap();

        // Execute JUMPI
        interp.step(&table, &mut host);

        // Verify PC wire is consistent
        let pc = interp.program_counter();
        assert_eq!(pc, 5, "Jump should not be taken, PC should be 5");

        let pc_gates = interp.current_pc_wire.as_ref().unwrap();
        let circuit_pc =
            StackValueData::Private(pc_gates.clone()).evaluate(&interp.circuit_builder.borrow());
        assert_eq!(
            circuit_pc.as_limbs()[0] as usize,
            5,
            "Circuit PC should match actual PC"
        );
    }

    #[test]
    fn test_callf_retf() {
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();
        let mut host = DummyHost::default();

        // Create EOF bytecode with two sections
        let bytes1 = Bytes::from([CALLF, 0x00, 0x01, STOP]);
        let bytes2 = Bytes::from([RETF]);
        let mut interp = eof_setup(bytes1, bytes2.clone());

        // Execute CALLF
        interp.step(&table, &mut host);

        // Verify PC wire after CALLF
        let pc = interp.program_counter();
        assert_eq!(pc, 0, "CALLF should jump to PC=0 of section 1");

        let pc_gates = interp.current_pc_wire.as_ref().unwrap();
        let circuit_pc =
            StackValueData::Private(pc_gates.clone()).evaluate(&interp.circuit_builder.borrow());
        assert_eq!(
            circuit_pc.as_limbs()[0] as usize,
            0,
            "Circuit PC should match actual PC after CALLF"
        );

        // Execute RETF
        interp.step(&table, &mut host);

        // Verify PC wire after RETF
        let pc = interp.program_counter();
        assert_eq!(pc, 3, "RETF should return to PC=3");

        let pc_gates = interp.current_pc_wire.as_ref().unwrap();
        let circuit_pc =
            StackValueData::Private(pc_gates.clone()).evaluate(&interp.circuit_builder.borrow());
        assert_eq!(
            circuit_pc.as_limbs()[0] as usize,
            3,
            "Circuit PC should match actual PC after RETF"
        );
    }

    #[test]
    fn test_private_rjumpv() {
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();
        let mut host = DummyHost::default();

        // Create bytecode with RJUMPV table:
        // case 0: jump +1 (to STOP at PC 7)
        // case 1: jump +2 (to STOP at PC 8)
        // default: fallthrough to STOP at PC 6
        let mut interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
            [RJUMPV, 0x01, 0x00, 0x01, 0x00, 0x02, STOP, STOP, STOP].into(),
        ));
        interp.is_eof = true;
        interp.gas = Gas::new(10000);

        // Test case 0
        {
            // Create private case value (0)
            let case = GarbledUint256::zero();
            let case_gates = interp.circuit_builder.borrow_mut().input(&case);
            interp
                .stack
                .push_stack_value_data(StackValueData::Private(case_gates))
                .unwrap();

            // Execute RJUMPV
            interp.step(&table, &mut host);

            // Verify PC wire is consistent
            let pc = interp.program_counter();
            assert_eq!(pc, 7, "Case 0 should jump to PC=7");

            let pc_gates = interp.current_pc_wire.as_ref().unwrap();
            let circuit_pc = StackValueData::Private(pc_gates.clone())
                .evaluate(&interp.circuit_builder.borrow());
            assert_eq!(
                circuit_pc.as_limbs()[0] as usize,
                7,
                "Circuit PC should match actual PC for case 0"
            );
        }

        // Reset interpreter for case 1
        interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
            [RJUMPV, 0x01, 0x00, 0x01, 0x00, 0x02, STOP, STOP, STOP].into(),
        ));
        interp.is_eof = true;
        interp.gas = Gas::new(10000);

        // Test case 1
        {
            // Create private case value (1)
            let case = ruint_to_garbled_uint(&U256::from(1));
            let case_gates = interp.circuit_builder.borrow_mut().input(&case);
            interp
                .stack
                .push_stack_value_data(StackValueData::Private(case_gates))
                .unwrap();

            // Execute RJUMPV
            interp.step(&table, &mut host);

            // Verify PC wire is consistent
            let pc = interp.program_counter();
            assert_eq!(pc, 8, "Case 1 should jump to PC=8");

            let pc_gates = interp.current_pc_wire.as_ref().unwrap();
            let circuit_pc = StackValueData::Private(pc_gates.clone())
                .evaluate(&interp.circuit_builder.borrow());
            assert_eq!(
                circuit_pc.as_limbs()[0] as usize,
                8,
                "Circuit PC should match actual PC for case 1"
            );
        }

        // Reset interpreter for default case
        interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
            [RJUMPV, 0x01, 0x00, 0x01, 0x00, 0x02, STOP, STOP, STOP].into(),
        ));
        interp.is_eof = true;
        interp.gas = Gas::new(10000);

        // Test default case
        {
            // Create private case value (2 - out of range)
            let case = ruint_to_garbled_uint(&U256::from(2));
            let case_gates = interp.circuit_builder.borrow_mut().input(&case);
            interp
                .stack
                .push_stack_value_data(StackValueData::Private(case_gates))
                .unwrap();

            // Execute RJUMPV
            interp.step(&table, &mut host);

            // Verify PC wire is consistent
            let pc = interp.program_counter();
            assert_eq!(pc, 6, "Out of range case should fallthrough to PC=6");

            let pc_gates = interp.current_pc_wire.as_ref().unwrap();
            let circuit_pc = StackValueData::Private(pc_gates.clone())
                .evaluate(&interp.circuit_builder.borrow());
            assert_eq!(
                circuit_pc.as_limbs()[0] as usize,
                6,
                "Circuit PC should match actual PC for default case"
            );
        }
    }
}
