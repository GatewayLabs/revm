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

const RUNTIME_CODE: &[u8] = &[
    // Test 1: mstore/mload
    0x60, 0x42,     // PUSH1 0x42 (decimal 66)
    0x60, 0x00,     // PUSH1 0x00 (position 0)
    0x52,           // MSTORE
    0x60, 0x00,     // PUSH1 0x00 (position 0)
    0x51,           // MLOAD

    // Test 2: mstore8
    0x60, 0xFF,     // PUSH1 0xFF
    0x60, 0x20,     // PUSH1 0x20 (position 32)
    0x53,           // MSTORE8
    0x60, 0x20,     // PUSH1 0x20 (position 32)
    0x51,           // MLOAD

    // Test 3: mcopy
    0x60, 0x20,     // PUSH1 0x20 (length: 32)
    0x60, 0x40,     // PUSH1 0x40 (destination: 64)
    0x60, 0x00,     // PUSH1 0x00 (source: 0)
    0x5e,           // MCOPY
    0x60, 0x40,     // PUSH1 0x40 (position 64)
    0x51,           // MLOAD

    // Test 4: msize
    0x59,           // MSIZE
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

fn verify_garbled_value(interpreter: &mut Interpreter, index: usize, expected: Option<u64>, name: &str) -> anyhow::Result<()> {
    println!("\nVerifying {}:", name);
    match interpreter.stack().peek(index) {
        Ok(value) => {
            match value {
                StackValueData::Private(gate_indices) => {
                    let result: GarbledUint256 = interpreter.circuit_builder
                        .compile_and_execute(&gate_indices)
                        .expect(&format!("Failed to execute {} verification circuit", name));

                    println!("  Compiled bits: {:?}", result.bits);
                    println!("  Gate indices: {:?}", gate_indices);
                    
                    let computed_result = garbled_uint_to_ruint(&result);
                    println!("  {} result: 0x{:x}", name, computed_result);

                    if let Some(expected) = expected {
                        assert_eq!(
                            computed_result.as_limbs()[0], 
                            expected, 
                            "{} result does not match expected value", name
                        );
                    }
                    Ok(())
                },
                _ => Err(anyhow::anyhow!("Expected private value for {}", name))
            }
        },
        Err(e) => Err(anyhow::anyhow!("Failed to verify {}: {:?}", name, e)),
    }
}

fn main() -> anyhow::Result<()> {
    let bytecode = Bytecode::new_raw(Bytes::from(RUNTIME_CODE.to_vec()));
    print_bytecode_details(&bytecode.bytes());

    println!("\n--- Setting up interpreter ---");
    let contract = Contract::new(
        Bytes::new(),
        bytecode.clone(),
        None,
        Address::default(),
        None,
        Address::default(),
        U256::ZERO,
    );

    let mut interpreter = Interpreter::new(contract, u64::MAX, false);
    let mut host = DummyHost::<DefaultEthereumWiring>::default();
    let table = &make_instruction_table::<DummyHost<DefaultEthereumWiring>, CancunSpec>();

    println!("\n--- Executing bytecode ---");
    let _action = interpreter.run(
        SharedMemory::new(),
        table,
        &mut host,
    );

    println!("\n--- Private Memory Operation Verification ---");

    verify_garbled_value(&mut interpreter, 0, Some(96), "MSIZE")?;            // MSIZE -> 96
    verify_garbled_value(&mut interpreter, 1, Some(0x42), "MCOPY LOAD")?;    // MLOAD(0x40) -> 0x42
    verify_garbled_value(&mut interpreter, 2, Some(0x42), "MSTORE8 LOAD")?;  // MLOAD(0x20) -> 0x42
    verify_garbled_value(&mut interpreter, 3, Some(0xff), "INITIAL LOAD")?;  // MLOAD(0x00) -> 0xFF

    println!("\n✅ All memory operations verified successfully!");

    Ok(())
}