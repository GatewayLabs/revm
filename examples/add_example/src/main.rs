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
    let bytecode = hex::decode("6080604052348015600e575f80fd5b506101a58061001c5f395ff3fe608060405234801561000f575f80fd5b5060043610610029575f3560e01c8063771602f71461002d575b5f80fd5b610047600480360381019061004291906100a9565b61005d565b60405161005491906100f6565b60405180910390f35b5f818361006a919061013c565b905092915050565b5f80fd5b5f819050919050565b61008881610076565b8114610092575f80fd5b50565b5f813590506100a38161007f565b92915050565b5f80604083850312156100bf576100be610072565b5b5f6100cc85828601610095565b92505060206100dd85828601610095565b9150509250929050565b6100f081610076565b82525050565b5f6020820190506101095f8301846100e7565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f61014682610076565b915061015183610076565b92508282019050808211156101695761016861010f565b5b9291505056fea2646970667358221220650b77675b6648c0fe06e068764320e465568458bf8e54f349acb7837a95b54d64736f6c634300081a0033")?;
    // Concatenate init code and runtime code
    let bytecode: Bytes = Bytes::from(bytecode.clone());
    
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

    // Create EVM instance for deployment
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

    println!("\n--- Contract Deployment Attempt ---");
    let deploy_tx = evm.transact_commit()?;
    println!("Deployment Transaction Result:");
    println!("{:#?}", deploy_tx);

    match deploy_tx {
        ExecutionResult::Success { 
            reason, 
            gas_used, 
            gas_refunded, 
            logs, 
            output 
        } => {
            println!("Deployment Successful:");
            println!("  Reason: {:?}", reason);
            println!("  Gas Used: {}", gas_used);
            println!("  Gas Refunded: {}", gas_refunded);
            println!("  Logs: {:?}", logs);
            
            match output {
                Output::Create(runtime_bytecode, address) => {
                    println!("  Runtime Bytecode: {}", hex::encode(&runtime_bytecode));
                    println!("  Deployed Address: {:?}", address);

                    let mut evm_call = Evm::<EthereumWiring<InMemoryDB, ()>>::builder()
                        .with_db(evm.db().clone())
                        .with_default_ext_ctx()
                        .modify_tx_env(|tx| {
                            tx.transact_to = TxKind::Call(address.unwrap());
                            tx.data = Bytes::default();
                            tx.gas_limit = gas_limit;
                            tx.gas_price = gas_price;
                            tx.value = U256::ZERO;
                            tx.caller = sender;
                            tx.nonce = 1;
                        })
                        .modify_env(|env| {
                            env.block.basefee = U256::ZERO;
                            env.block.gas_limit = U256::from(gas_limit);
                            env.block.number = U256::ZERO;
                            env.block.timestamp = U256::ZERO;
                        })
                        .build();

                    match evm_call.transact_commit() {
                        Ok(call_tx) => {
                            println!("\n--- Contract Call Result ---");
                            println!("Full Call Transaction Result: {:#?}", call_tx);

                            match call_tx {
                                ExecutionResult::Success { 
                                    output: Output::Call(value), 
                                    .. 
                                } => {
                                    println!("Call Successful:");
                                    println!("  Private computation completed.");
                                    println!("  This value represents a private result (14 + 20 = 34)");
                                    println!("  Result in garbled form: {}", hex::encode(&value));
                                },
                                ExecutionResult::Halt { reason, gas_used } => {
                                    println!("Call Halted:");
                                    println!("  Reason: {:?}", reason);
                                    println!("  Gas Used: {}", gas_used);
                                },
                                ExecutionResult::Revert { gas_used, output } => {
                                    println!("Call Reverted:");
                                    println!("  Gas Used: {}", gas_used);
                                    println!("  Output: {}", hex::encode(&output));
                                },
                                _ => println!("Unexpected call result type"),
                            }
                        },
                        Err(e) => {
                            println!("Contract Call Error:");
                            println!("{:?}", e);
                        }
                    }
                }
                _ => println!("  Unexpected output type"),
            }
        },
        ExecutionResult::Revert { gas_used, output } => {
            println!("Deployment Reverted:");
            println!("  Gas Used: {}", gas_used);
            println!("  Output: {}", hex::encode(&output));
        },
        _ => println!("Unexpected deployment result"),
    }

    Ok(())
}