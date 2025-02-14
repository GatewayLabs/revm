mod contract;
pub(crate) mod private_memory;
#[cfg(feature = "serde")]
pub mod serde;
pub(crate) mod shared_memory;
mod stack;

use crate::instructions::utility::ruint_to_garbled_uint;
use bytecode::opcode::OpCode;
use compute::prelude::{GateIndexVec, WRK17CircuitBuilder};
pub use contract::Contract;
pub use private_memory::{PrivateMemory, EMPTY_PRIVATE_MEMORY};
pub use shared_memory::{num_words, SharedMemory, EMPTY_SHARED_MEMORY};
pub use stack::{Stack, StackValueData, STACK_LIMIT};

use super::instructions::utility::garbled_uint_to_ruint;
use crate::{
    gas, push, push_b256, return_ok, return_revert, CallOutcome, CreateOutcome, FunctionStack, Gas,
    Host, InstructionResult, InterpreterAction,
};
use bytecode::{Bytecode, Eof};
use compute::prelude::CircuitExecutor;
use core::cell::RefCell;
use core::cmp::min;
use encryption::Keypair;
use primitives::{Bytes, U256};
use std::borrow::ToOwned;
use std::rc::Rc;
use std::sync::Arc;

pub const MAX_STEPS: usize = 10000;

/// EVM bytecode interpreter.
#[derive(Debug)]
pub struct Interpreter {
    /// The current instruction pointer.
    pub instruction_pointer: *const u8,
    /// The gas state.
    pub gas: Gas,
    /// Contract information and invoking data
    pub contract: Contract,
    /// The execution control flag. If this is not set to `Continue`, the interpreter will stop
    /// execution.
    pub instruction_result: InstructionResult,
    /// Currently run Bytecode that instruction result will point to.
    /// Bytecode is owned by the contract.
    pub bytecode: Bytes,
    /// Whether we are Interpreting the Ethereum Object Format (EOF) bytecode.
    /// This is local field that is set from `contract.is_eof()`.
    pub is_eof: bool,
    /// Is init flag for eof create
    pub is_eof_init: bool,
    /// Shared memory.
    ///
    /// Note: This field is only set while running the interpreter loop.
    /// Otherwise it is taken and replaced with empty shared memory.
    pub shared_memory: SharedMemory,
    pub private_memory: PrivateMemory,
    /// Stack.
    pub stack: Stack,
    /// EOF function stack.
    pub function_stack: FunctionStack,
    /// The return data buffer for internal calls.
    /// It has multi usage:
    ///
    /// * It contains the output bytes of call sub call.
    /// * When this interpreter finishes execution it contains the output bytes of this contract.
    pub return_data_buffer: Bytes,
    /// Whether the interpreter is in "staticcall" mode, meaning no state changes can happen.
    pub is_static: bool,
    /// Actions that the EVM should do.
    ///
    /// Set inside CALL or CREATE instructions and RETURN or REVERT instructions. Additionally those instructions will set
    /// InstructionResult to CallOrCreate/Return/Revert so we know the reason.
    pub next_action: InterpreterAction,
    pub circuit_builder: Rc<RefCell<WRK17CircuitBuilder>>,
    pub encryption_keypair: Option<Keypair>,
    /// Current program counter wire in the circuit
    pub current_pc_wire: Option<GateIndexVec>,
    /// Proposed next PC wire for control flow changes
    pub proposed_pc_wire: Option<GateIndexVec>,
}

impl<'cb> Default for Interpreter {
    fn default() -> Self {
        Self::new(
            Contract::default(),
            u64::MAX,
            false,
            Rc::new(RefCell::new(WRK17CircuitBuilder::default())),
        )
    }
}

impl Interpreter {
    /// Create new interpreter
    pub fn new(
        contract: Contract,
        gas_limit: u64,
        is_static: bool,
        circuit_builder: Rc<RefCell<WRK17CircuitBuilder>>,
    ) -> Self {
        if !contract.bytecode.is_execution_ready() {
            panic!("Contract is not execution ready {:?}", contract.bytecode);
        }

        let is_eof = contract.bytecode.is_eof();
        let bytecode = contract.bytecode.bytecode().clone();

        Self {
            instruction_pointer: bytecode.as_ptr(),
            bytecode,
            contract,
            gas: Gas::new(gas_limit),
            instruction_result: InstructionResult::Continue,
            function_stack: FunctionStack::default(),
            is_static,
            is_eof,
            is_eof_init: false,
            return_data_buffer: Bytes::new(),
            shared_memory: EMPTY_SHARED_MEMORY,
            stack: Stack::new(),
            next_action: InterpreterAction::None,
            circuit_builder,
            private_memory: EMPTY_PRIVATE_MEMORY,
            encryption_keypair: None,
            current_pc_wire: None,
            proposed_pc_wire: None,
        }
    }

    #[inline]
    pub fn reset_circuit_builder(&mut self) {
        self.circuit_builder = Rc::new(RefCell::new(WRK17CircuitBuilder::default()));
    }

    #[inline]
    pub fn set_encryption_keypair(&mut self, keypair: Keypair) {
        self.encryption_keypair = Some(keypair);
    }

    /// Set is_eof_init to true, this is used to enable `RETURNCONTRACT` opcode.
    #[inline]
    pub fn set_is_eof_init(&mut self) {
        self.is_eof_init = true;
    }

    #[inline]
    pub fn eof(&self) -> Option<&Arc<Eof>> {
        self.contract.bytecode.eof()
    }

    /// Test related helper
    #[cfg(test)]
    pub fn new_bytecode(bytecode: Bytecode) -> Self {
        Self::new(
            Contract::new(
                Bytes::new(),
                bytecode,
                None,
                primitives::Address::default(),
                None,
                primitives::Address::default(),
                U256::ZERO,
            ),
            0,
            false,
            Rc::new(RefCell::new(WRK17CircuitBuilder::default())),
        )
    }

    /// Load EOF code into interpreter. PC is assumed to be correctly set
    pub(crate) fn load_eof_code(&mut self, idx: usize, pc: usize) {
        // SAFETY: eof flag is true only if bytecode is Eof.
        let Bytecode::Eof(eof) = &self.contract.bytecode else {
            panic!("Expected EOF code section")
        };
        let Some(code) = eof.body.code(idx) else {
            panic!("Code not found")
        };
        self.bytecode = code.clone();
        self.instruction_pointer = unsafe { self.bytecode.as_ptr().add(pc) };
    }

    /// Inserts the output of a `create` call into the interpreter.
    ///
    /// This function is used after a `create` call has been executed. It processes the outcome
    /// of that call and updates the state of the interpreter accordingly.
    ///
    /// # Arguments
    ///
    /// * `create_outcome` - A `CreateOutcome` struct containing the results of the `create` call.
    ///
    /// # Behavior
    ///
    /// The function updates the `return_data_buffer` with the data from `create_outcome`.
    /// Depending on the `InstructionResult` indicated by `create_outcome`, it performs one of the following:
    ///
    /// - `Ok`: Pushes the address from `create_outcome` to the stack, updates gas costs, and records any gas refunds.
    /// - `Revert`: Pushes `StackValueData::Public(U256::ZERO` to the stack and updates gas costs)
    /// - `FatalExternalError`: Sets the `instruction_result` to `InstructionResult::FatalExternalError`.
    /// - `Default`: Pushes `StackValueData::Public(U256::ZERO` to the stack)
    ///
    /// # Side Effects
    ///
    /// - Updates `return_data_buffer` with the data from `create_outcome`.
    /// - Modifies the stack by pushing values depending on the `InstructionResult`.
    /// - Updates gas costs and records refunds in the interpreter's `gas` field.
    /// - May alter `instruction_result` in case of external errors.
    pub fn insert_create_outcome(&mut self, create_outcome: CreateOutcome) {
        self.instruction_result = InstructionResult::Continue;

        let instruction_result = create_outcome.instruction_result();
        self.return_data_buffer = if instruction_result.is_revert() {
            // Save data to return data buffer if the create reverted
            create_outcome.output().to_owned()
        } else {
            // Otherwise clear it
            Bytes::new()
        };

        match instruction_result {
            return_ok!() => {
                let address = create_outcome.address;
                push_b256!(self, address.unwrap_or_default().into_word());
                self.gas.erase_cost(create_outcome.gas().remaining());
                self.gas.record_refund(create_outcome.gas().refunded());
            }
            return_revert!() => {
                push!(self, StackValueData::Public(U256::ZERO).into());
                self.gas.erase_cost(create_outcome.gas().remaining());
            }
            InstructionResult::FatalExternalError => {
                panic!("Fatal external error in insert_create_outcome");
            }
            _ => {
                push!(self, StackValueData::Public(U256::ZERO).into())
            }
        }
    }

    pub fn insert_eofcreate_outcome(&mut self, create_outcome: CreateOutcome) {
        self.instruction_result = InstructionResult::Continue;
        let instruction_result = create_outcome.instruction_result();

        self.return_data_buffer = if *instruction_result == InstructionResult::Revert {
            // Save data to return data buffer if the create reverted
            create_outcome.output().to_owned()
        } else {
            // Otherwise clear it. Note that RETURN opcode should abort.
            Bytes::new()
        };

        match instruction_result {
            InstructionResult::ReturnContract => {
                push_b256!(
                    self,
                    create_outcome.address.expect("EOF Address").into_word()
                );
                self.gas.erase_cost(create_outcome.gas().remaining());
                self.gas.record_refund(create_outcome.gas().refunded());
            }
            return_revert!() => {
                push!(self, U256::ZERO.into());
                self.gas.erase_cost(create_outcome.gas().remaining());
            }
            InstructionResult::FatalExternalError => {
                panic!("Fatal external error in insert_eofcreate_outcome");
            }
            _ => {
                push!(self, U256::ZERO.into())
            }
        }
    }

    /// Inserts the outcome of a call into the virtual machine's state.
    ///
    /// This function takes the result of a call, represented by `CallOutcome`,
    /// and updates the virtual machine's state accordingly. It involves updating
    /// the return data buffer, handling gas accounting, and setting the memory
    /// in shared storage based on the outcome of the call.
    ///
    /// # Arguments
    ///
    /// * `shared_memory` - A mutable reference to the shared memory used by the virtual machine.
    /// * `call_outcome` - The outcome of the call to be processed, containing details such as
    ///   instruction result, gas information, and output data.
    ///
    /// # Behavior
    ///
    /// The function first copies the output data from the call outcome to the virtual machine's
    /// return data buffer. It then checks the instruction result from the call outcome:
    ///
    /// - `return_ok!()`: Processes successful execution, refunds gas, and updates shared memory.
    /// - `return_revert!()`: Handles a revert by only updating the gas usage and shared memory.
    /// - `InstructionResult::FatalExternalError`: Sets the instruction result to a fatal external error.
    /// - Any other result: No specific action is taken.
    pub fn insert_call_outcome(
        &mut self,
        shared_memory: &mut SharedMemory,
        call_outcome: CallOutcome,
    ) {
        self.instruction_result = InstructionResult::Continue;

        let out_offset = call_outcome.memory_start();
        let out_len = call_outcome.memory_length();
        let out_ins_result = *call_outcome.instruction_result();
        let out_gas = call_outcome.gas();
        self.return_data_buffer = call_outcome.result.output;

        let target_len = min(out_len, self.return_data_buffer.len());
        match out_ins_result {
            return_ok!() => {
                // return unspend gas.
                self.gas.erase_cost(out_gas.remaining());
                self.gas.record_refund(out_gas.refunded());
                shared_memory.set(out_offset, &self.return_data_buffer[..target_len]);
                push!(
                    self,
                    if self.is_eof {
                        U256::ZERO.into()
                    } else {
                        U256::from(1).into()
                    }
                );
            }
            return_revert!() => {
                self.gas.erase_cost(out_gas.remaining());
                shared_memory.set(out_offset, &self.return_data_buffer[..target_len]);
                push!(
                    self,
                    if self.is_eof {
                        U256::from(1).into()
                    } else {
                        U256::ZERO.into()
                    }
                );
            }
            InstructionResult::FatalExternalError => {
                panic!("Fatal external error in insert_call_outcome");
            }
            _ => {
                push!(
                    self,
                    if self.is_eof {
                        U256::from(2).into()
                    } else {
                        U256::ZERO.into()
                    }
                );
            }
        }
    }

    /// Returns the opcode at the current instruction pointer.
    #[inline]
    pub fn current_opcode(&self) -> u8 {
        unsafe { *self.instruction_pointer }
    }

    /// Returns a reference to the contract.
    #[inline]
    pub fn contract(&self) -> &Contract {
        &self.contract
    }

    /// Returns a reference to the interpreter's gas state.
    #[inline]
    pub fn gas(&self) -> &Gas {
        &self.gas
    }

    /// Returns a reference to the interpreter's stack.
    #[inline]
    pub fn stack(&self) -> &Stack {
        &self.stack
    }

    /// Returns a mutable reference to the interpreter's stack.
    #[inline]
    pub fn stack_mut(&mut self) -> &mut Stack {
        &mut self.stack
    }

    /// Returns the current program counter.
    #[inline]
    pub fn program_counter(&self) -> usize {
        // SAFETY: `instruction_pointer` should be at an offset from the start of the bytecode.
        // In practice this is always true unless a caller modifies the `instruction_pointer` field manually.
        unsafe { self.instruction_pointer.offset_from(self.bytecode.as_ptr()) as usize }
    }

    /// Executes the instruction at the current instruction pointer.
    ///
    /// Internally it will increment instruction pointer by one.
    #[inline]
    pub(crate) fn step<FN, H: Host + ?Sized>(&mut self, instruction_table: &[FN; 256], host: &mut H)
    where
        FN: Fn(&mut Interpreter, &mut H),
    {
        // Get current opcode.
        let opcode = unsafe { *self.instruction_pointer };
        println!("#️⃣ {:?}:{:?}", OpCode::name_by_op(opcode), opcode);

        // SAFETY: In analysis we are doing padding of bytecode so that we are sure that last
        // byte instruction is STOP so we are safe to just increment program_counter bcs on last instruction
        // it will do noop and just stop execution of this contract
        self.instruction_pointer = unsafe { self.instruction_pointer.offset(1) };

        // execute instruction.
        (instruction_table[opcode as usize])(self, host)
    }

    /// Take memory and replace it with empty memory.
    pub fn take_memory(&mut self) -> SharedMemory {
        core::mem::replace(&mut self.shared_memory, EMPTY_SHARED_MEMORY)
    }
    /// Take memory and replace it with empty memory.
    pub fn take_private_memory(&mut self) -> PrivateMemory {
        core::mem::replace(&mut self.private_memory, EMPTY_PRIVATE_MEMORY)
    }

    /// Executes the interpreter until it returns or stops.
    pub fn run<FN, H: Host + ?Sized>(
        &mut self,
        shared_memory: SharedMemory,
        private_memory: PrivateMemory,
        instruction_table: &[FN; 256],
        host: &mut H,
    ) -> InterpreterAction
    where
        FN: Fn(&mut Interpreter, &mut H),
    {
        self.next_action = InterpreterAction::None;
        self.shared_memory = shared_memory;
        self.private_memory = private_memory;

        // Initialize PC wire to 0
        let initial_pc_wire = self.create_pc_wire(0);
        self.current_pc_wire = Some(initial_pc_wire.clone());
        let initial_pc = self.evaluate_circuit_pc(&initial_pc_wire);

        // Track the last seen PC to detect infinite loops
        let mut last_pc = initial_pc;
        let mut same_pc_count = 0;

        // Instead of following jumps, iterate through all possible steps
        for step in 0..MAX_STEPS {
            // Early termination checks
            let current_pc = self.evaluate_circuit_pc(self.current_pc_wire.as_ref().unwrap());

            // Check if we've exceeded bytecode length
            if current_pc >= self.bytecode.len() {
                break;
            }

            // Check for potential infinite loop
            if current_pc == last_pc {
                same_pc_count += 1;
                if same_pc_count > 3 {
                    break;
                }
            } else {
                same_pc_count = 0;
                last_pc = current_pc;
            }

            // Create a constant wire for this step (used only for comparison)
            let step_wire = self.create_pc_wire(step);

            // Compare current PC with step index
            let is_this_step = {
                let mut cb = self.circuit_builder.borrow_mut();
                cb.eq(&self.current_pc_wire.as_ref().unwrap(), &step_wire)
            };
            let is_this_step = GateIndexVec::from(vec![is_this_step]);

            // Get opcode at current PC (not step)
            let opcode = self.bytecode[current_pc];

            // Stop if we hit a STOP opcode at an active step
            let is_step_active = {
                let cb = self.circuit_builder.borrow();
                let is_active_result = cb.compile_and_execute(&is_this_step).unwrap();
                let is_active_ruint = garbled_uint_to_ruint::<256>(&is_active_result);
                !is_active_ruint.is_zero()
            };
            if is_step_active && opcode == 0x00 {
                break;
            }

            // Execute step
            self.step_unrolled(instruction_table, host, opcode, &is_this_step, step);

            if self.instruction_result != InstructionResult::Continue {
                break;
            }
        }

        // Return next action if it is some
        if self.next_action.is_some() {
            return core::mem::take(&mut self.next_action);
        }

        // If not, return action without output as it is a halt
        InterpreterAction::Return {
            result: InterpreterResult {
                result: self.instruction_result,
                output: Bytes::new(),
                gas: self.gas,
            },
        }
    }

    /// Helper function to evaluate a PC wire value
    pub(crate) fn evaluate_circuit_pc(&self, pc_gates: &GateIndexVec) -> usize {
        let cb = self.circuit_builder.borrow();
        let result = cb.compile_and_execute(pc_gates).unwrap();
        let ruint_value = garbled_uint_to_ruint::<256>(&result);
        drop(cb);
        ruint_value.as_limbs()[0] as usize
    }

    fn step_unrolled<FN, H: Host + ?Sized>(
        &mut self,
        instruction_table: &[FN; 256],
        host: &mut H,
        opcode: u8,
        is_active: &GateIndexVec,
        step: usize,
    ) where
        FN: Fn(&mut Interpreter, &mut H),
    {
        // Get current PC state
        let old_pc = self.current_pc_wire.clone().unwrap();
        let old_pc_val = self.evaluate_circuit_pc(&old_pc);

        // Evaluate if this step is active
        let is_step_active = {
            let cb = self.circuit_builder.borrow();
            let is_active_result = cb.compile_and_execute(is_active).unwrap();
            let is_active_ruint = garbled_uint_to_ruint::<256>(&is_active_result);
            !is_active_ruint.is_zero()
        };

        // Only execute opcode if step is active
        if is_step_active {
            // For PUSH opcodes, compute next PC based on current PC
            if opcode >= 0x60 && opcode <= 0x7f {
                let n = (opcode - 0x5f) as usize;
                let next_pc = old_pc_val + 1 + n;

                // Create next PC wire using constant
                let next_pc_wire = self.create_pc_wire(next_pc);
                self.proposed_pc_wire = Some(next_pc_wire);

                // Handle push data
                let mut bytes = [0u8; 32];
                if old_pc_val + 1 + n <= self.bytecode.len() {
                    let data_slice = &self.bytecode[old_pc_val + 1..old_pc_val + 1 + n];
                    bytes[32 - n..].copy_from_slice(data_slice);
                }
                let push_value = U256::from_be_bytes(bytes);
                self.stack.push_stack_value_data(push_value.into()).unwrap();
            } else {
                // Default next PC is current + 1
                let default_next_pc = old_pc_val + 1;
                let default_next_pc_wire = self.create_pc_wire(default_next_pc);
                self.proposed_pc_wire = Some(default_next_pc_wire);

                // Execute opcode (may update proposed_pc_wire for jumps)
                (instruction_table[opcode as usize])(self, host);
            }

            // Update PC state using mux with is_active as selector
            let new_pc_state = {
                let mut cb = self.circuit_builder.borrow_mut();
                cb.mux(
                    &is_active[0],
                    self.proposed_pc_wire.as_ref().unwrap(),
                    &old_pc,
                )
            };
            self.current_pc_wire = Some(new_pc_state);
        }

        // Clear proposed PC wire
        self.proposed_pc_wire = None;
    }

    /// Creates a circuit wire for a PC value
    pub(crate) fn create_pc_wire(&mut self, pc: usize) -> GateIndexVec {
        let pc_garbled = ruint_to_garbled_uint(&U256::from(pc));
        self.circuit_builder.borrow_mut().constant(&pc_garbled)
    }

    /// Resize the memory to the new size. Returns whether the gas was enough to resize the memory.
    #[inline]
    #[must_use]
    pub fn resize_memory(&mut self, new_size: usize) -> bool {
        resize_memory(
            &mut self.shared_memory,
            &mut self.private_memory,
            &mut self.gas,
            new_size,
        )
    }
}

/// The result of an interpreter operation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct InterpreterResult {
    /// The result of the instruction execution.
    pub result: InstructionResult,
    /// The output of the instruction execution.
    pub output: Bytes,
    /// The gas usage information.
    pub gas: Gas,
}

impl InterpreterResult {
    /// Returns a new `InterpreterResult` with the given values.
    pub fn new(result: InstructionResult, output: Bytes, gas: Gas) -> Self {
        Self {
            result,
            output,
            gas,
        }
    }

    /// Returns whether the instruction result is a success.
    #[inline]
    pub const fn is_ok(&self) -> bool {
        self.result.is_ok()
    }

    /// Returns whether the instruction result is a revert.
    #[inline]
    pub const fn is_revert(&self) -> bool {
        self.result.is_revert()
    }

    /// Returns whether the instruction result is an error.
    #[inline]
    pub const fn is_error(&self) -> bool {
        self.result.is_error()
    }
}

/// Resize the memory to the new size. Returns whether the gas was enough to resize the memory.
#[inline(never)]
#[cold]
#[must_use]
pub fn resize_memory(
    memory: &mut SharedMemory,
    private_memory: &mut PrivateMemory,
    gas: &mut Gas,
    new_size: usize,
) -> bool {
    let new_words = num_words(new_size as u64);
    let new_cost = gas::memory_gas(new_words);
    let current_cost = memory.current_expansion_cost();
    let cost = new_cost - current_cost;
    let success = gas.record_cost(cost);
    if success {
        memory.resize((new_words as usize) * 32);
        private_memory.resize((new_words as usize) * 32);
    }
    success
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{table::InstructionTable, DummyHost};
    use specification::hardfork::CancunSpec;
    use wiring::DefaultEthereumWiring;

    #[test]
    fn object_safety() {
        let mut interp = Interpreter::new(
            Contract::default(),
            u64::MAX,
            false,
            Rc::new(RefCell::new(WRK17CircuitBuilder::default())),
        );

        let mut host = crate::DummyHost::<DefaultEthereumWiring>::default();
        let table: &InstructionTable<DummyHost<DefaultEthereumWiring>> =
            &crate::table::make_instruction_table::<DummyHost<DefaultEthereumWiring>, CancunSpec>();
        let _ = interp.run(EMPTY_SHARED_MEMORY, EMPTY_PRIVATE_MEMORY, table, &mut host);

        let host: &mut dyn Host<EvmWiringT = DefaultEthereumWiring> =
            &mut host as &mut dyn Host<EvmWiringT = DefaultEthereumWiring>;
        let table: &InstructionTable<dyn Host<EvmWiringT = DefaultEthereumWiring>> =
            &crate::table::make_instruction_table::<
                dyn Host<EvmWiringT = DefaultEthereumWiring>,
                CancunSpec,
            >();
        let _ = interp.run(EMPTY_SHARED_MEMORY, EMPTY_PRIVATE_MEMORY, table, host);
    }
}
