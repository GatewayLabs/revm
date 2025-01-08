//! Contract deployment demonstration

use database::InMemoryDB;
use revm::{
    primitives::{hex, Bytes, TxKind, U256, Address, B256},
    state::AccountInfo,
    wiring::{
        result::{ExecutionResult, Output},
        EthereumWiring,
    },
    Evm,
};

// Direct bytecode that adds 14 + 20
const BYTECODE: &[u8] = &[
    0x60, 0x14,       // PUSH1 0x14 (20 decimal)
    0x60, 0x0E,       // PUSH1 0x0E (14 decimal)
    0x01,             // ADD (add the two values on top of the stack)
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
    let bytecode: Bytes = BYTECODE.to_vec().into();
    print_bytecode_details(&bytecode);

    // Sender configuration
    let sender = Address::from_slice(&[0x20; 20]);
    
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

    // Create EVM instance 
    let mut evm: Evm<'_, EthereumWiring<InMemoryDB, ()>> =
        Evm::<EthereumWiring<InMemoryDB, ()>>::builder()
            .with_db(db)
            .with_default_ext_ctx()
            .modify_tx_env(|tx| {
                tx.transact_to = TxKind::Create;
                tx.data = bytecode.clone();
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

    println!("\n--- Execution Attempt ---");
    let result = evm.transact_commit()?;
    println!("Execution Result:");
    println!("{:#?}", result);

    Ok(())
}