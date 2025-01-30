//! Contract execution and private computation demonstration with comprehensive logging

//! Example of a contract that adds two ElGamal-encrypted values and returns the result in clear.

use database::InMemoryDB;
use revm::{
    primitives::{hex, Bytes, TxKind, U256, Address, B256, keccak256},
    state::AccountInfo,
    wiring::{
        result::{ExecutionResult, Output},
        EthereumWiring,
    },
    Evm,
    bytecode::Bytecode,
};
use compute::prelude::GarbledUint256;
use interpreter::{
    instructions::utility::garbled_uint_to_ruint,
    interpreter::{Interpreter, PrivateMemory, StackValueData},
    table::make_instruction_table,
    Contract, DummyHost, SharedMemory
};
use revm::specification::hardfork::CancunSpec;
use revm::wiring::DefaultEthereumWiring;

/// RUNTIME_CODE that performs:
/// 1) `CALLDATACOPY` (customized to decrypt)
/// 2) `MLOAD` values
/// 3) `ADD`
/// 4) `RETURN` 32 bytes (the sum result)
///
/// - First 32 bytes of calldata: ciphertext of A
/// - Next 32 bytes of calldata: ciphertext of B
/// - Decryption occurs automatically inside the custom interpreter logic.
const RUNTIME_CODE: &[u8] = &[
    0x60, 0x00, // PUSH1 0 (memory offset where we store data)
    0x60, 0x00, // PUSH1 0 (calldata offset to read from)
    0x60, 0x40, // PUSH1 64 (length to copy: 2 * 32 bytes)
    0x37,       // CALLDATACOPY (overridden to decrypt to memory)
    0x60, 0x00, // PUSH1 0 (memory offset)
    0x51,       // MLOAD -> load first decrypted value
    0x60, 0x20, // PUSH1 32 (offset for second value in memory)
    0x51,       // MLOAD -> load second decrypted value
    0x01,       // ADD -> sum the two
    0x60, 0x00, // PUSH1 0 (where to store result in memory)
    0x52,       // MSTORE -> store sum at mem[0..32]
    0x60, 0x20, // PUSH1 32 (length of return data)
    0x60, 0x00, // PUSH1 0 (offset to return from)
    0xf3,       // RETURN
];

/// Helper function to print details about the bytecode
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
    // Prepare the bytecode
    let bytecode = Bytecode::new_raw(Bytes::from(RUNTIME_CODE.to_vec()));
    print_bytecode_details(&bytecode.bytes());

    // Sender and contract addresses
    let sender = Address::from_slice(&[0x20; 20]);
    let contract_address = Address::from_slice(&[0x42; 20]);

    // Transaction parameters
    let gas_limit = 100_000u64;
    let gas_price = U256::from(100u64);
    let value = U256::ZERO;
    let initial_balance = U256::from(1_000_000_000_000u64);

    // Create an in-memory database
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

    // Insert contract account with the runtime bytecode
    db.insert_account_info(
        contract_address,
        AccountInfo {
            balance: U256::ZERO,
            code_hash: B256::from(keccak256(bytecode.bytes())),
            code: Some(bytecode.clone()),
            nonce: 1,
        },
    );

    println!("Sending two ElGamal-encrypted values to be summed.");

    // Example "ciphertext" data (fake bytes)
    // - first 32 bytes for the ciphertext of A
    // - next 32 bytes for the ciphertext of B
    let fake_ciphertext_a = [0xde; 32];
    let fake_ciphertext_b = [0xad; 32];
    println!("Ciphertext A (first 32 bytes): 0x{}", hex::encode(&fake_ciphertext_a));
    println!("Ciphertext B (next 32 bytes): 0x{}", hex::encode(&fake_ciphertext_b));
    let mut call_data = Vec::new();
    call_data.extend_from_slice(&fake_ciphertext_a);
    call_data.extend_from_slice(&fake_ciphertext_b);

    // Create the EVM instance
    let mut evm: Evm<'_, EthereumWiring<InMemoryDB, ()>> =
        Evm::<EthereumWiring<InMemoryDB, ()>>::builder()
            .with_db(db)
            .with_default_ext_ctx()
            .modify_tx_env(|tx| {
                tx.transact_to = TxKind::Call(contract_address);
                tx.data = Bytes::from(call_data);
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

    println!("EVM Execution Result:");
    match result {
        ExecutionResult::Success { reason, gas_used, output, .. } => {
            println!("  Reason: {:?}", reason);
            println!("  Gas Used: {}", gas_used);

            match output {
                Output::Call(return_data) => {
                    println!("  Return Data (clear result): 0x{}", hex::encode(&return_data));
                    // This will be 32 bytes containing the sum of A + B in clear.
                    // If A was 14 and B was 20, we'd expect 0x...00000022 as the sum.
                    println!("Return Data (clear sum): 0x{}", hex::encode(&return_data));
                    // Verifique se a soma corresponde ao esperado (exemplo 0x22 se for 0x0E + 0x14)
                },
                Output::Create(_, _) => {
                    println!("  (Unexpected for CALL)");
                }
            }
        },
        ExecutionResult::Revert { gas_used, output, .. } => {
            println!("  Execution Reverted");
            println!("  Gas Used: {}", gas_used);
            println!("  Revert Output: {:?}", output);
            return Err(anyhow::anyhow!("EVM Execution Reverted"));
        },
        ExecutionResult::Halt { reason, gas_used } => {
            println!("  Execution Halted");
            println!("  Reason: {:?}", reason);
            println!("  Gas Used: {}", gas_used);
            return Err(anyhow::anyhow!("EVM Execution Halted"));
        }
    }

    // Remova ou ajuste a segunda chamada de `Interpreter::run` que chama as instruções novamente
    // pois ela faz o calldatacopy sem empurrar valores na pilha.
    // println!("\n--- Private Computation Verification ---");
    // let contract = Contract::new(
    //     Bytes::new(),
    //     bytecode.clone(),
    //     None,
    //     Address::default(),
    //     None,
    //     Address::default(),
    //     U256::ZERO,
    // );
    // let mut interpreter = Interpreter::new(contract, u64::MAX, false);
    // let mut host = DummyHost::<DefaultEthereumWiring>::default();
    // let table = &make_instruction_table::<DummyHost<DefaultEthereumWiring>, CancunSpec>();
    // let _action = interpreter.run(
    //     SharedMemory::new(),
    //     PrivateMemory::new(),
    //     table,
    //     &mut host,
    // );
    // match interpreter.stack().peek(0) {
    //     Err(e) => {
    //         println!("  Error accessing stack: {:?}", e);
    //         return Err(anyhow::anyhow!("Failed to access interpreter stack"));
    //     },
    //     _ => {}
    // }

    Ok(())
}
