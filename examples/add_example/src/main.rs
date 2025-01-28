//! Contract execution and private computation demonstration with comprehensive logging

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
    interpreter::{Interpreter, StackValueData}, 
    table::make_instruction_table, 
    Contract, 
    DummyHost, 
    SharedMemory
};
use revm::specification::hardfork::CancunSpec;
use revm::wiring::DefaultEthereumWiring;
use encryption::{elgamal::ElGamalEncryption, encryption_trait::Encryptor};
use solana_zk_sdk::encryption::elgamal::{ElGamalKeypair, ElGamalCiphertext as Ciphertext};
use bincode;

// Runtime bytecode que lê e escreve o Ciphertext completo
const RUNTIME_CODE: &[u8] = &[
    // Copy first number to memory
    0x60, 0x02,       // PUSH1 0x02 - valor do primeiro número (2)
    0x60, 0x00,       // PUSH1 0x00 - posição de memória
    0x52,             // MSTORE - armazena o primeiro número na memória no offset 0x00

    // Copy second number to memory 
    0x60, 0x05,       // PUSH1 0x05 - valor do segundo número (5)
    0x60, 0x20,       // PUSH1 0x20 - posição de memória para o segundo número
    0x52,             // MSTORE - armazena o segundo número na memória no offset 0x20

    // Load and add the two numbers
    0x60, 0x00,       // PUSH1 0x00 - primeiro offset de memória
    0x51,             // MLOAD - carrega o primeiro valor (2)
    0x60, 0x20,       // PUSH1 0x20 - segundo offset de memória
    0x51,             // MLOAD - carrega o segundo valor (5)
    0x01,             // ADD
    
    // Store the result
    0x60, 0x40,       // PUSH1 0x40 - offset para armazenar resultado
    0x52,             // MSTORE

    // Return the result
    0x60, 0x20,       // PUSH1 0x20 - tamanho (32 bytes)
    0x60, 0x40,       // PUSH1 0x40 - offset de onde retornar
    0xf3,             // RETURN
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
    println!("Starting ElGamal encrypted addition example...");

    // Generate ElGamal keypair
    let keypair = ElGamalKeypair::new_rand();
    let public_key = keypair.pubkey();

    // Create the values to be added and encrypt them
    let value1 = U256::from(14u64);
    let value2 = U256::from(20u64);

    println!("Original values: {} and {}", value1, value2);

    // Encrypt the values
    let encrypted_value1 = ElGamalEncryption::encrypt(&value1.to_le_bytes::<32>(), &public_key);
    let encrypted_value2 = ElGamalEncryption::encrypt(&value2.to_le_bytes::<32>(), &public_key);

    println!("Values encrypted successfully");

    // Debug prints for sizes
    println!("Size of commitment: {} bytes", std::mem::size_of_val(&encrypted_value1.commitment));
    println!("Size of handle: {} bytes", std::mem::size_of_val(&encrypted_value1.handle));

    // Serialize encrypted values into bytes for calldata
    let mut calldata = Vec::new();
    bincode::serialize_into(&mut calldata, &encrypted_value1).expect("Failed to serialize value1");
    println!("Size of serialized ciphertext: {} bytes", calldata.len());
    bincode::serialize_into(&mut calldata, &encrypted_value2).expect("Failed to serialize value2");
    println!("Raw calldata hex: 0x{}", hex::encode(&calldata));
    println!("Calldata size: {} bytes", calldata.len());
    let calldata = Bytes::from(calldata);

    let bytecode = Bytecode::new_raw(Bytes::from(RUNTIME_CODE));
    print_bytecode_details(&bytecode.bytes());

    // Sender and contract configuration
    let sender = Address::from_slice(&[0x20; 20]);
    let contract_address = Address::from_slice(&[0x42; 20]);
    
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
                tx.transact_to = TxKind::Call(contract_address);
                tx.data = calldata; // Pass encrypted values in calldata
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
        ExecutionResult::Success { reason, gas_used, output, .. } => {
            println!("  Execution Reason: {:?}", reason);
            println!("  Gas Used: {}", gas_used);
            
            // Verify output or additional checks if needed
            match output {
                Output::Call(data) => {
                    println!("  Call Output length: {} bytes", data.len());
                    println!("  Call Output hex: 0x{}", hex::encode(&data));
                    
                    // Debug print the raw bytes before attempting deserialization
                    println!("  Raw Output bytes: {:?}", data.as_ref());
                    
                    if data.len() == 64 {
                        let result_ciphertext: Ciphertext = bincode::deserialize(&data)
                            .expect("Failed to deserialize result");
                        
                        // Decrypt and verify the result
                        let result = ElGamalEncryption::decrypt_to_u256(&result_ciphertext, &keypair);
                        println!("Decrypted Result: {}", result);
                        
                        let expected = value1 + value2;
                        assert_eq!(
                            result,
                            expected,
                            "Decrypted result does not match expected value"
                        );
                        println!("✅ Result verified successfully!");
                    } else {
                        let mut byte_array = [0u8; 32];
                        byte_array.copy_from_slice(&data[..32]);
                        let result_value = U256::from_le_bytes(byte_array);
                        println!("Parsed value: {}", result_value);
                        
                        let expected = value1 + value2;
                        assert_eq!(
                            result_value,
                            expected,
                            "Result does not match expected value"
                        );
                        println!("✅ Result verified successfully!");
                    }
                },
                Output::Create(address, _) => {
                    println!("  Created Contract Address: {:?}", address);
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
    let mut interpreter = Interpreter::new(contract, gas_limit, false);

    // Push encrypted values to stack
    println!("Tipo do encrypted_value1: {:?}", encrypted_value1);
    println!("Tipo do keypair: {:?}", keypair);
    println!("Criando StackValueData::Encrypted...");
    let stack_value = StackValueData::Encrypted(encrypted_value1, keypair.clone());
    println!("StackValueData criado: {:?}", stack_value);
    if let Err(e) = interpreter.stack.push_stack_value_data(stack_value) {
        return Err(anyhow::anyhow!("Failed to push first encrypted value: {:?}", e));
    }
    if let Err(e) = interpreter.stack.push_stack_value_data(StackValueData::Encrypted(
        encrypted_value2,
        keypair.clone(),
    )) {
        return Err(anyhow::anyhow!("Failed to push second encrypted value: {:?}", e));
    }

    println!("\nStack after pushing encrypted values:");
    println!("{:?}", interpreter.stack);

    // Create host and instruction table
    let mut host = DummyHost::<DefaultEthereumWiring>::default();
    let table = &make_instruction_table::<DummyHost<DefaultEthereumWiring>, CancunSpec>();

    // Execute the addition
    println!("\nExecuting addition...");
    let _action = interpreter.run(
        SharedMemory::new(),
        table,
        &mut host,
    );

    // Verify and decrypt the result
    println!("\n--- Checking Result ---");
    match interpreter.stack().peek(0) {
        Ok(value) => {
            println!("Top of stack value: {:?}", value);
            
            match value {
                StackValueData::Encrypted(ciphertext, key) => {
                    let result = ElGamalEncryption::decrypt_to_u256(&ciphertext, &key);
                    println!("Decrypted Result: {}", result);
                    
                    // Verify the result
                    let expected = value1 + value2;
                    assert_eq!(
                        result, 
                        expected,
                        "Decrypted result does not match expected value"
                    );
                    println!("✅ Result verified successfully!");
                },
                StackValueData::Private(gate_indices) => {
                    let result: GarbledUint256 = interpreter.circuit_builder
                        .compile_and_execute(&gate_indices)
                        .map_err(|e| anyhow::anyhow!("Circuit compilation failed: {:?}", e))?;
                    
                    let public_result = garbled_uint_to_ruint(&result);
                    println!("Private computation result: {}", public_result);
                    // 64 -> 34
                },
                StackValueData::Public(value) => {
                    println!("Public result: {}", value);
                }
            }
        },
        Err(e) => {
            println!("Error accessing stack: {:?}", e);
            return Err(anyhow::anyhow!("Failed to access interpreter stack"));
        }
    }

    Ok(())
}
