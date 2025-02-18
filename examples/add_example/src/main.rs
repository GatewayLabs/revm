//! Contract execution and private computation demonstration with comprehensive logging

use std::{cell::RefCell, rc::Rc};

use compute::prelude::{GarbledUint256, WRK17CircuitBuilder};
use std::time::Instant;

use database::InMemoryDB;
use interpreter::{
    instructions::utility::garbled_uint_to_ruint,
    interpreter::{Interpreter, PrivateMemory, PrivateMemoryValue, StackValueData},
    table::make_instruction_table,
    Contract, DummyHost, SharedMemory,
};
use revm::specification::hardfork::CancunSpec;
use revm::wiring::DefaultEthereumWiring;
use revm::{
    bytecode::Bytecode,
    primitives::{hex, keccak256, Address, Bytes, TxKind, B256, U256},
    state::AccountInfo,
    wiring::{
        result::{ExecutionResult, Output},
        EthereumWiring,
    },
    Evm,
};

// Runtime bytecode that adds 14 + 20
const RUNTIME_CODE: &[u8] = &[
    0x60, 0x14, // PUSH1 0x14 (20 decimal)
    0x60, 0x0E, // PUSH1 0x0E (14 decimal)
    0x01, // ADD (add the two values on top of the stack)
];

fn print_bytecode_details(bytecode: &Bytes) {
    println!("Bytecode Details:");
    println!("  Total Length: {}", bytecode.len());
    println!("  Hex Representation: {}", hex::encode(bytecode));

    println!("  Bytecode Breakdown:");
    for (i, &byte) in bytecode.iter().enumerate() {
        println!("    Byte {}: 0x{:02x} (Decimal: {})", i, byte, byte);
    }
}

fn main() -> anyhow::Result<()> {
    let bytecode = Bytecode::new_raw(Bytes::from(RUNTIME_CODE.to_vec()));
    print_bytecode_details(&bytecode.bytes());

    // Sender and contract configuration
    let sender = Address::from_slice(&[0x20; 20]);
    let contract_address = Address::from_slice(&[0x42; 20]); // Fixed contract address

    // Transaction parameters
    let gas_limit = 100_000u64;
    let gas_price = U256::from(100u64);
    let value = U256::ZERO;
    let initial_balance = U256::from(1_000_000_000_000u64);

    // Create in-memory database
    let mut db = InMemoryDB::default();

    // Insert sender account
    db.insert_account_info(
        sender,
        AccountInfo {
            balance: initial_balance,
            code_hash: B256::default(),
            code: None,
            nonce: 0,
        },
    );

    // Insert contract with runtime code
    db.insert_account_info(
        contract_address,
        AccountInfo {
            balance: U256::ZERO,
            code_hash: B256::from(keccak256(bytecode.bytes())),
            code: Some(bytecode.clone()),
            nonce: 1,
        },
    );

    // Create EVM instance
    let mut evm: Evm<'_, EthereumWiring<InMemoryDB, ()>> =
        Evm::<EthereumWiring<InMemoryDB, ()>>::builder()
            .with_db(db)
            .with_default_ext_ctx()
            .modify_tx_env(|tx| {
                tx.transact_to = TxKind::Call(contract_address); // Call the contract
                tx.data = bytecode.bytes().clone(); // Bytecode as call data
                tx.gas_limit = gas_limit;
                tx.gas_price = gas_price;
                tx.value = value;
                tx.caller = sender;
                tx.nonce = 0;
            })
            .modify_env(|env| {
                env.block.basefee = U256::ZERO;
                env.block.gas_limit = U256::from(gas_limit);
                env.block.number = U256::ZERO;
                env.block.timestamp = U256::ZERO;
            })
            .build();

    println!("\n--- EVM Execution Attempt ---");
    let result = evm.transact_commit()?;

    // Comprehensive EVM Execution Logging
    println!("EVM Execution Result:");
    println!("  Status: {:#?}", result);

    // Check EVM Execution Success
    match result {
        ExecutionResult::Success {
            reason,
            gas_used,
            output,
            ..
        } => {
            println!("  Execution Reason: {:?}", reason);
            println!("  Gas Used: {}", gas_used);

            // Verify output or additional checks if needed
            match output {
                Output::Call(data) => {
                    println!("  Call Output: {:?}", data);
                }
                Output::Create(address, _) => {
                    println!("  Created Contract Address: {:?}", address);
                }
            }
        }
        ExecutionResult::Revert {
            gas_used, output, ..
        } => {
            println!("  Execution Reverted");
            println!("  Gas Used: {}", gas_used);
            println!("  Revert Output: {:?}", output);
            return Err(anyhow::anyhow!("EVM Execution Reverted"));
        }
        ExecutionResult::Halt { reason, gas_used } => {
            println!("  Execution Halted");
            println!("  Reason: {:?}", reason);
            println!("  Gas Used: {}", gas_used);
            return Err(anyhow::anyhow!("EVM Execution Halted"));
        }
    }

    // Private Computation Circuit Verification
    let contract = Contract::new(
        Bytes::new(),
        bytecode.clone(),
        None,
        Address::default(),
        None,
        Address::default(),
        U256::ZERO,
    );

    // Create interpreter
    let mut interpreter = Interpreter::new(
        contract,
        u64::MAX,
        false,
        Rc::new(RefCell::new(WRK17CircuitBuilder::default())),
    );

    // Create host and instruction table
    let mut host = DummyHost::<DefaultEthereumWiring>::default();
    let table = &make_instruction_table::<DummyHost<DefaultEthereumWiring>, CancunSpec>();

    // Execute bytecode
    let _action = interpreter.run(SharedMemory::new(), PrivateMemory::new(), table, &mut host);

    // Verify and convert private result to public
    println!("\n--- Private Computation Verification ---");
    match interpreter.stack().peek(0) {
        Ok(value) => {
            println!("  Top of Stack Value: {:?}", value);

            if let StackValueData::Private(gate_indices) = value {
                println!("  Detected Private Value");
                println!("  Gate Indices: {:?}", gate_indices);

                let output_indices = interpreter.stack.pop().unwrap();
                let private_ref = output_indices.evaluate_with_interpreter(&interpreter);

                let PrivateMemoryValue::Garbled(gates) = interpreter
                    .private_memory
                    .get(&private_ref.try_into().unwrap())
                else {
                    panic!("cannot find PrivateMemoryValue");
                };

                let start = Instant::now();
                let result: GarbledUint256 = interpreter
                    .circuit_builder
                    .borrow()
                    .compile_and_execute(&gates)
                    .unwrap();

                let public_result = garbled_uint_to_ruint(&result);

                println!("  Private Computation Result: {:?}", public_result);
                let elapsed = start.elapsed();
                println!("Total execution time: {:.2?}", elapsed);

                // Verification against expected result
                let expected_result = 20 + 14;
                println!("  Expected Result: {}", expected_result);

                assert_eq!(
                    public_result.to_string(),
                    expected_result.to_string(),
                    "Private computation result does not match expected value"
                );

                println!("  ✅ Private Computation Verification Successful");
            } else {
                println!("  Value is already public: {:?}", value);
            }
        }
        Err(e) => {
            println!("  Error accessing stack: {:?}", e);
            return Err(anyhow::anyhow!("Failed to access interpreter stack"));
        }
    }

    Ok(())
}
