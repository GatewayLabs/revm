use std::{cell::RefCell, rc::Rc};

use compute::prelude::WRK17CircuitBuilder;
use interpreter::{
    interpreter::{Interpreter, PrivateMemory, StackValueData},
    table::make_instruction_table,
    Contract, DummyHost, SharedMemory,
};
use primitives::ruint::Uint;
use revm::specification::hardfork::CancunSpec;
use revm::wiring::DefaultEthereumWiring;
use revm::{
    bytecode::Bytecode,
    primitives::{hex, Address, Bytes, U256},
};

const RUNTIME_CODE: &[u8] = &[
    0x60, 0x42,  // PUSH1 0x42 (decimal 66)
    0x60, 0x00,  // PUSH1 0x00 (position 0)
    0x52,        // MSTORE
    
    0x60, 0xFF,  // PUSH1 0xFF
    0x60, 0x20,  // PUSH1 0x20 (position 32)
    0x53,        // MSTORE8
    
    0x60, 0x20,  // PUSH1 0x20 (length: 32)
    0x60, 0x40,  // PUSH1 0x40 (destination: 64)
    0x60, 0x00,  // PUSH1 0x00 (source: 0)
    0x5e,        // MCOPY
    
    0x60, 0x20,  // PUSH1 0x20
    0x51,        // MLOAD - MSTORE8 (0xFF)
    
    0x60, 0x00,  // PUSH1 0x00
    0x51,        // MLOAD - INITIAL (66)
    
    0x60, 0x40,  // PUSH1 0x40
    0x51,        // MLOAD - MCOPY (66)
    
    0x59,        // MSIZE (96)
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

fn verify_garbled_value(
    interpreter: &mut Interpreter,
    index: usize,
    expected: Option<u64>,
    name: &str,
) -> anyhow::Result<()> {
    println!("\nVerifying {:?}. Expected: {:?}:", name, expected.map(U256::from));
    match interpreter.stack().peek(index) {
        Ok(value) => match value {
            StackValueData::Private(_) => {
                println!("Private value ({:?})", name);
                let val = interpreter.stack.pop().unwrap();
                let result = val.evaluate_with_interpreter(&interpreter);

                println!("  {} result: 0x{:x}", name, result);

                if let Some(expected) = expected {
                    assert_eq!(
                        result.as_limbs()[0],
                        expected,
                        "{} result does not match expected value",
                        name
                    );
                }
                Ok(())
            },
            StackValueData::Public(value) => {
                println!("Public value ({:?}): {:?}", name, value);
                if let Some(expected) = expected {
                    assert_eq!(
                        value,
                        Uint::<256, 4>::from(expected),
                        "{} result does not match expected value",
                        name
                    );
                }
                Ok(())
            }
            _ => Err(anyhow::anyhow!("Expected private value for {}", name)),
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

    let mut interpreter = Interpreter::new(
        contract,
        u64::MAX,
        false,
        Rc::new(RefCell::new(WRK17CircuitBuilder::default())),
    );
    let mut host = DummyHost::<DefaultEthereumWiring>::default();
    let table = &make_instruction_table::<DummyHost<DefaultEthereumWiring>, CancunSpec>();

    println!("\n--- Executing bytecode ---");
    let _action = interpreter.run(SharedMemory::new(), PrivateMemory::new(), table, &mut host);

    println!("\n--- Private Memory Operation Verification ---");

    verify_garbled_value(&mut interpreter, 0, Some(96), "MSIZE")?;          // Top of stack
    verify_garbled_value(&mut interpreter, 1, Some(66), "MCOPY LOAD")?;     // Second from top
    verify_garbled_value(&mut interpreter, 2, Some(66), "INITIAL LOAD")?;   // Third from top
    verify_garbled_value(&mut interpreter, 3, Some(255), "MSTORE8 LOAD")?;  // Fourth from top

    println!("\n✅ All memory operations verified successfully!");

    Ok(())
}
