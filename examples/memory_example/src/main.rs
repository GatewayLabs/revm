use revm::{
    primitives::{hex, Bytes, U256, Address},
    bytecode::Bytecode,
};
use compute::prelude::GarbledUint256;
use interpreter::{
    instructions::utility::garbled_uint_to_ruint, 
    interpreter::{Interpreter, StackValueData}, 
    table::make_instruction_table, 
    Contract, 
    DummyHost, 
    SharedMemory,
};
use revm::specification::hardfork::CancunSpec;
use revm::wiring::DefaultEthereumWiring;

// Runtime bytecode that:
// 1. PUSH1 0x42 (value to store)
// 2. PUSH1 0x00 (memory position 0)
// 3. MSTORE (store value at position 0)
// 4. PUSH1 0x00 (memory position 0)
// 5. MLOAD (load value from position 0)
const RUNTIME_CODE: &[u8] = &[
    0x60, 0x42,     // PUSH1 0x42 (decimal 66)
    0x60, 0x00,     // PUSH1 0x00 (position 0)
    0x52,           // MSTORE
    0x60, 0x00,     // PUSH1 0x00 (position 0)
    0x51,           // MLOAD
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

    println!("\n--- Setting up interpreter ---");
    // Contract setup
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
    let mut interpreter = Interpreter::new(contract, u64::MAX, false);

    // Create host and instruction table
    let mut host = DummyHost::<DefaultEthereumWiring>::default();
    let table = &make_instruction_table::<DummyHost<DefaultEthereumWiring>, CancunSpec>();

    println!("\n--- Executing bytecode ---");
    // Execute bytecode
    let _action = interpreter.run(
        SharedMemory::new(),
        table,
        &mut host,
    );

    // Verify the result
    println!("\n--- Private Memory Operation Verification ---");
    match interpreter.stack().peek(0) {
        Ok(value) => {
            println!("  Top of Stack Value after MLOAD: {:?}", value);
            
            if let StackValueData::Private(gate_indices) = value {
                println!("  Detected Private Value");
                println!("  Gate Indices: {:?}", gate_indices);
                
                let result: GarbledUint256 = interpreter.circuit_builder
                    .compile_and_execute(&gate_indices)
                    .map_err(|e| {
                        println!("  Circuit Compilation Error: {:?}", e);
                        e
                    })?;
                
                let public_result = garbled_uint_to_ruint(&result);
                
                println!("  Private Memory Operation Result: {:?}", public_result);
                
                // Verification against expected result
                let expected_result = 0x42;
                println!("  Expected Result: 0x{:x}", expected_result);
                
                assert_eq!(
                    public_result.as_limbs()[0], 
                    expected_result, 
                    "Private memory operation result does not match expected value"
                );
                
                println!("  ✅ Private Memory Operation Verification Successful");
                println!("  Successfully stored and loaded private value 0x42 from memory");
            } else {
                println!("  Value is not private: {:?}", value);
                return Err(anyhow::anyhow!("Expected private value"));
            }
        },
        Err(e) => {
            println!("  Error accessing stack: {:?}", e);
            return Err(anyhow::anyhow!("Failed to access interpreter stack"));
        }
    }

    Ok(())
}
