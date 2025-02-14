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

    // Create wire for new PC
    let new_pc_garbled = ruint_to_garbled_uint(&U256::from(new_pc));
    let new_pc_gates = interpreter
        .circuit_builder
        .borrow_mut()
        .input(&new_pc_garbled);

    // Update proposed PC wire
    interpreter.proposed_pc_wire = Some(new_pc_gates);
}

pub fn rjumpi<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    require_eof!(interpreter);
    gas!(interpreter, gas::CONDITION_JUMP_GAS);
    pop!(interpreter, condition);

    let current_pc = interpreter.program_counter();
    let offset = unsafe { read_i16(interpreter.instruction_pointer) } as isize;
    let jump_dest = current_pc + 2 + offset as usize;
    let fallthrough_pc = current_pc + 2;

    // Convert condition to wire
    let condition_wire = condition.is_zero_wire(&mut interpreter.circuit_builder.borrow_mut());

    // Create wires for both possible next PCs
    let jump_dest_garbled = ruint_to_garbled_uint(&U256::from(jump_dest));
    let jump_dest_gates = interpreter
        .circuit_builder
        .borrow_mut()
        .input(&jump_dest_garbled);

    let fallthrough_garbled = ruint_to_garbled_uint(&U256::from(fallthrough_pc));
    let fallthrough_gates = interpreter
        .circuit_builder
        .borrow_mut()
        .input(&fallthrough_garbled);

    // MUX between jump destination and fallthrough
    let next_pc_gates = interpreter.circuit_builder.borrow_mut().mux(
        &condition_wire[0],
        &jump_dest_gates,
        &fallthrough_gates,
    );

    // Update proposed PC wire
    interpreter.proposed_pc_wire = Some(next_pc_gates);
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

            // Create circuit wire for the new PC
            let next_pc_gates = interpreter.create_pc_wire(new_pc);
            interpreter.proposed_pc_wire = Some(next_pc_gates);
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

            interpreter.proposed_pc_wire = Some(next_pc_gates);
        }
        StackValueData::Encrypted(_ciphertext) => panic!("Cannot convert encrypted value to U256"),
    }
}

pub fn jump<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::MID);
    pop!(interpreter, target);

    let target_wire = target.to_wire(&mut interpreter.circuit_builder.borrow_mut());

    interpreter.proposed_pc_wire = Some(target_wire);
}

pub fn jumpi<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::HIGH);
    pop!(interpreter, target, condition);

    let fallthrough_wire = interpreter.proposed_pc_wire.as_ref().unwrap().clone();
    let selector = condition.is_zero_wire(&mut interpreter.circuit_builder.borrow_mut());
    let target_wire = target.to_wire(&mut interpreter.circuit_builder.borrow_mut());

    let proposed_pc =
        interpreter
            .circuit_builder
            .borrow_mut()
            .mux(&selector[0], &fallthrough_wire, &target_wire);

    interpreter.proposed_pc_wire = Some(proposed_pc);
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

    let Some(types) = interpreter.eof().unwrap().body.types_section.get(idx) else {
        panic!("Invalid EOF in execution, expecting correct intermediate in callf")
    };

    // safe to subtract as max_stack_height is always more than inputs.
    if interpreter.stack.len() + (types.max_stack_size - types.inputs as u16) as usize > 1024 {
        interpreter.instruction_result = InstructionResult::StackOverflow;
        return;
    }

    let return_pc = interpreter.program_counter() + 2;
    interpreter.create_pc_wire(return_pc);
    interpreter.function_stack.push(return_pc, idx);

    let target_pc_gates = interpreter.create_pc_wire(0);
    interpreter.proposed_pc_wire = Some(target_pc_gates);

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
    interpreter.proposed_pc_wire = Some(return_pc_gates);

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
mod control_tests {
    use super::*;
    use crate::{
        interpreter::{EMPTY_PRIVATE_MEMORY, EMPTY_SHARED_MEMORY},
        table::make_instruction_table,
        DummyHost, Gas,
    };
    use bytecode::Bytecode;
    use compute::{
        prelude::{GateIndexVec, WRK17CircuitBuilder},
        uint::GarbledUint256,
    };
    use primitives::{Bytes, U256};
    use specification::hardfork::PragueSpec;
    use wiring::{default::Env, DefaultEthereumWiring};

    // Helper function to evaluate the PC wire from the circuit builder
    fn evaluate_circuit_pc(
        circuit_builder: &std::cell::RefCell<WRK17CircuitBuilder>,
        pc_gates: &GateIndexVec,
    ) -> usize {
        let cb = circuit_builder.borrow();
        let result = cb.compile_and_execute(pc_gates).unwrap();
        let ruint_value = garbled_uint_to_ruint::<256>(&result);
        ruint_value.as_limbs()[0] as usize
    }

    // Helper to add JUMPDEST opcodes at jump targets
    fn add_jumpdest_at(bytecode: &mut Vec<u8>, target_pc: usize) {
        if target_pc < bytecode.len() {
            bytecode[target_pc] = 0x5b; // JUMPDEST opcode
        } else {
            bytecode.resize(target_pc, 0x00); // Pad with NOPs
            bytecode.push(0x5b); // Add JUMPDEST
        }
    }

    // Helper to create a test interpreter with mock bytecode
    fn setup_test_interpreter(
        bytecode: Vec<u8>,
    ) -> (Interpreter, DummyHost<DefaultEthereumWiring>) {
        let bytes = Bytes::from(bytecode);
        let legacy_raw = bytecode::LegacyRawBytecode::from(bytes);
        let mut interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(legacy_raw));
        interp.is_eof = true;
        interp.gas = Gas::new(10000);

        // Initialize PC wire to 0
        let initial_pc_wire = interp.create_pc_wire(0);
        interp.current_pc_wire = Some(initial_pc_wire);

        let host = DummyHost::<DefaultEthereumWiring>::new(Env::default());
        (interp, host)
    }

    #[test]
    fn test_jump_public() {
        let target_pc = 42;

        // Create bytecode: PUSH target_pc, JUMP
        let mut bytecode = vec![0x60]; // PUSH1
        bytecode.extend_from_slice(&[target_pc as u8]);
        bytecode.push(0x56); // JUMP

        // Add JUMPDEST at target and pad with NOPs
        add_jumpdest_at(&mut bytecode, target_pc);
        bytecode.push(0x00); // STOP

        let (mut interp, mut host) = setup_test_interpreter(bytecode);
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();

        // Run the interpreter
        interp.run(EMPTY_SHARED_MEMORY, EMPTY_PRIVATE_MEMORY, &table, &mut host);

        // Verify PC wire matches target
        let pc = evaluate_circuit_pc(
            &interp.circuit_builder,
            interp.current_pc_wire.as_ref().unwrap(),
        );
        assert_eq!(pc, target_pc, "Jump did not set the expected PC wire");
    }

    #[test]
    fn test_jump_private() {
        let target_pc = 42;

        // Create bytecode: JUMP (we'll push the private target onto stack manually)
        let mut bytecode = vec![0x56]; // JUMP
        add_jumpdest_at(&mut bytecode, target_pc);
        bytecode.push(0x00); // STOP

        let (mut interp, mut host) = setup_test_interpreter(bytecode);
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();

        // Create private target value and push to stack
        let target_garbled = ruint_to_garbled_uint(&U256::from(target_pc));
        let target_gates = interp.circuit_builder.borrow_mut().input(&target_garbled);
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(target_gates.clone()))
            .unwrap();

        // Run the interpreter
        interp.run(EMPTY_SHARED_MEMORY, EMPTY_PRIVATE_MEMORY, &table, &mut host);

        // Verify PC wire matches target
        let pc = evaluate_circuit_pc(
            &interp.circuit_builder,
            interp.current_pc_wire.as_ref().unwrap(),
        );
        assert_eq!(
            pc, target_pc,
            "Jump with private target did not set the expected PC wire"
        );
    }

    #[test]
    fn test_jumpi_public_taken() {
        let target_pc = 55;

        // Create bytecode: PUSH 1 (condition), PUSH target_pc, JUMPI
        let mut bytecode = vec![0x60]; // PUSH1
        bytecode.push(0x01); // condition = 1
        bytecode.push(0x60); // PUSH1
        bytecode.extend_from_slice(&[target_pc as u8]); // target
        bytecode.push(0x57); // JUMPI
        add_jumpdest_at(&mut bytecode, target_pc);
        bytecode.push(0x00); // STOP

        let (mut interp, mut host) = setup_test_interpreter(bytecode);
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();

        // Run the interpreter
        interp.run(EMPTY_SHARED_MEMORY, EMPTY_PRIVATE_MEMORY, &table, &mut host);

        // Verify PC wire matches target
        let pc = evaluate_circuit_pc(
            &interp.circuit_builder,
            interp.current_pc_wire.as_ref().unwrap(),
        );
        assert_eq!(
            pc, target_pc,
            "Jumpi with nonzero condition did not jump to target"
        );
    }

    #[test]
    fn test_jumpi_public_not_taken() {
        let target_pc = 55;
        let fallthrough_pc = 5; // PUSH1 + PUSH1 + JUMPI = 5 bytes

        // Create bytecode: PUSH 0 (condition), PUSH target_pc, JUMPI
        let mut bytecode = vec![0x60]; // PUSH1
        bytecode.push(0x00); // condition = 0
        bytecode.push(0x60); // PUSH1
        bytecode.extend_from_slice(&[target_pc as u8]); // target
        bytecode.push(0x57); // JUMPI
        add_jumpdest_at(&mut bytecode, target_pc);
        bytecode.push(0x00); // STOP

        let (mut interp, mut host) = setup_test_interpreter(bytecode);
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();

        // Run the interpreter
        interp.run(EMPTY_SHARED_MEMORY, EMPTY_PRIVATE_MEMORY, &table, &mut host);

        // Verify PC wire matches fallthrough
        let pc = evaluate_circuit_pc(
            &interp.circuit_builder,
            interp.current_pc_wire.as_ref().unwrap(),
        );
        assert_eq!(
            pc, fallthrough_pc,
            "Jumpi with zero condition did not fallthrough"
        );
    }

    #[test]
    fn test_jumpi_private_taken() {
        let target_pc = 55;

        // Create bytecode: JUMPI (we'll push private condition and target manually)
        let mut bytecode = vec![0x57]; // JUMPI
        add_jumpdest_at(&mut bytecode, target_pc);
        bytecode.push(0x00); // STOP

        let (mut interp, mut host) = setup_test_interpreter(bytecode);
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();

        // Create private condition (1) and target
        let condition_garbled = GarbledUint256::one();
        let condition_gates = interp
            .circuit_builder
            .borrow_mut()
            .input(&condition_garbled);

        let target_garbled = ruint_to_garbled_uint(&U256::from(target_pc));
        let target_gates = interp.circuit_builder.borrow_mut().input(&target_garbled);

        // Push condition first, then target (matching native EVM order)
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(condition_gates))
            .unwrap();
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(target_gates))
            .unwrap();

        // Run the interpreter
        interp.run(EMPTY_SHARED_MEMORY, EMPTY_PRIVATE_MEMORY, &table, &mut host);

        // Verify PC wire matches target
        let pc = evaluate_circuit_pc(
            &interp.circuit_builder,
            interp.current_pc_wire.as_ref().unwrap(),
        );
        assert_eq!(
            pc, target_pc,
            "Jumpi with private nonzero condition did not jump to target"
        );
    }

    #[test]
    fn test_jumpi_mixed_private_public() {
        let target_pc = 55;

        // Create bytecode: PUSH target_pc, JUMPI (we'll push private condition manually)
        let mut bytecode = vec![0x60]; // PUSH1
        bytecode.extend_from_slice(&[target_pc as u8]); // target
        bytecode.push(0x57); // JUMPI
        add_jumpdest_at(&mut bytecode, target_pc);
        bytecode.push(0x00); // STOP

        let (mut interp, mut host) = setup_test_interpreter(bytecode);
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();

        // Create private condition (1)
        let condition_garbled = GarbledUint256::one();
        let condition_gates = interp
            .circuit_builder
            .borrow_mut()
            .input(&condition_garbled);

        // Push condition first (private), then target (public) will be pushed by PUSH1
        interp
            .stack
            .push_stack_value_data(StackValueData::Private(condition_gates))
            .unwrap();

        // Run the interpreter
        interp.run(EMPTY_SHARED_MEMORY, EMPTY_PRIVATE_MEMORY, &table, &mut host);

        // Verify PC wire matches target
        let pc = evaluate_circuit_pc(
            &interp.circuit_builder,
            interp.current_pc_wire.as_ref().unwrap(),
        );
        assert_eq!(
            pc, target_pc,
            "Jumpi with public target and private condition did not jump correctly"
        );
    }
}
