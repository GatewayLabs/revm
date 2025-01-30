use database::InMemoryDB;
use encryption::{elgamal::ElGamalEncryption, encryption_trait::Encryptor};
use solana_zk_sdk::encryption::elgamal::{ElGamalKeypair, ElGamalCiphertext as Ciphertext};
use bincode;
use serde::{Serialize, Deserialize};
use std::fs;
use std::collections::HashMap;
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

#[derive(Serialize, Deserialize)]
struct KeypairStorage {
    keypairs: HashMap<String, String>,
}

const KEYPAIR_FILE: &str = "keypairs.json";

const RUNTIME_CODE: &[u8] = &[
    0x60, 0x04,       // PUSH1 0x04
    0x80,             // DUP1
    0x35,             // CALLDATALOAD
    0x60, 0x00,       // PUSH1 0x00
    0x52,             // MSTORE
    
    0x60, 0x44,       // PUSH1 0x44 (offset 68)
    0x80,             // DUP1
    0x35,             // CALLDATALOAD
    0x60, 0x20,       // PUSH1 0x20
    0x52,             // MSTORE
    
    0x60, 0x00,       // PUSH1 0x00
    0x51,             // MLOAD
    0x60, 0x20,       // PUSH1 0x20
    0x51,             // MLOAD
    0x01,             // ADD
    
    0x60, 0x40,       // PUSH1 0x40
    0x52,             // MSTORE
    
    0x60, 0x20,       // PUSH1 0x20
    0x60, 0x40,       // PUSH1 0x40
    0xf3              // RETURN
];


// Function to load keypair storage from file
fn load_keypair_storage() -> anyhow::Result<KeypairStorage> {
    match fs::read_to_string(KEYPAIR_FILE) {
        Ok(content) => {
            let storage: KeypairStorage = serde_json::from_str(&content)?;
            Ok(storage)
        }
        Err(_) => Ok(KeypairStorage {
            keypairs: HashMap::new(),
        })
    }
}

// Function to save keypair storage to file
fn save_keypair_storage(storage: &KeypairStorage) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(storage)?;
    fs::write(KEYPAIR_FILE, json)?;
    Ok(())
}

// Function to store keypair for a contract address
fn store_keypair(contract_address: &Address, keypair: &ElGamalKeypair) -> anyhow::Result<()> {
    let mut storage = load_keypair_storage()?;
    
    // Serialize keypair to base64 string
    let keypair_bytes = bincode::serialize(keypair)?;
    let keypair_str = base64::encode(&keypair_bytes);
    
    // Store with contract address as key
    storage.keypairs.insert(hex::encode(contract_address), keypair_str);
    
    save_keypair_storage(&storage)?;
    Ok(())
}

// Function to load keypair for a contract address
fn load_keypair(contract_address: &Address) -> anyhow::Result<Option<ElGamalKeypair>> {
    let storage = load_keypair_storage()?;
    
    if let Some(keypair_str) = storage.keypairs.get(&hex::encode(contract_address)) {
        let keypair_bytes = base64::decode(keypair_str)?;
        let keypair: ElGamalKeypair = bincode::deserialize(&keypair_bytes)?;
        Ok(Some(keypair))
    } else {
        Ok(None)
    }
}

fn main() -> anyhow::Result<()> {
    let keypair = ElGamalKeypair::new_rand();
    let public_key = keypair.pubkey();

    let value1 = U256::from(14u64);
    let value2 = U256::from(20u64);

    println!("[DEBUG] Input values: {} + {}", value1, value2);

    let encrypted_value1 = ElGamalEncryption::encrypt(&value1.to_le_bytes::<32>(), &public_key);
    let encrypted_value2 = ElGamalEncryption::encrypt(&value2.to_le_bytes::<32>(), &public_key);

    let mut calldata = Vec::new();
    calldata.extend_from_slice(&[0; 4]);
    bincode::serialize_into(&mut calldata, &encrypted_value1).expect("Failed to serialize value1");
    bincode::serialize_into(&mut calldata, &encrypted_value2).expect("Failed to serialize value2");

    println!("[DEBUG] Calldata size: {} bytes", calldata.len());

    let calldata = Bytes::from(calldata);
    let bytecode = Bytecode::new_raw(Bytes::from(RUNTIME_CODE));

    let sender = Address::from_slice(&[0x20; 20]);
    let contract_address = Address::from_slice(&[0x42; 20]);
    
    // Store the keypair for this contract
    store_keypair(&contract_address, &keypair)?;
    println!("[DEBUG] Stored keypair for contract: {:?}", contract_address);

    let gas_limit = 100_000u64;
    let gas_price = U256::from(100u64);
    let initial_balance = U256::from(1_000_000_000_000u64);

    let mut db = InMemoryDB::default();
    
    db.insert_account_info(
        sender,
        AccountInfo {
            balance: initial_balance,
            code_hash: B256::default(),
            code: None,
            nonce: 0,
        },
    );

    db.insert_account_info(
        contract_address,
        AccountInfo {
            balance: U256::ZERO,
            code_hash: B256::from(keccak256(bytecode.bytes())),
            code: Some(bytecode.clone()),
            nonce: 1,
        },
    );

    let mut evm: Evm<'_, EthereumWiring<InMemoryDB, ()>> =
        Evm::<EthereumWiring<InMemoryDB, ()>>::builder()
            .with_db(db)
            .with_default_ext_ctx()
            .modify_tx_env(|tx| {
                tx.transact_to = TxKind::Call(contract_address);
                tx.data = calldata;
                tx.gas_limit = gas_limit;
                tx.gas_price = gas_price;
                tx.value = U256::ZERO;
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

    match evm.transact_commit()? {
        ExecutionResult::Success { gas_used, output, .. } => {
            println!("[DEBUG] Gas used: {}", gas_used);
            
            match output {
                Output::Call(data) => {
                    println!("[DEBUG] Output size: {} bytes", data.len());
                    
                    if data.len() >= 32 {
                        let result_ciphertext: Ciphertext = bincode::deserialize(&data)
                            .expect("Failed to deserialize result");
                        
                        // Load the keypair for decryption
                        let keypair = load_keypair(&contract_address)?
                            .expect("Failed to load keypair for contract");
                            
                        let result = ElGamalEncryption::decrypt_to_u256(&result_ciphertext, &keypair);
                        println!("[DEBUG] Result: {}", result);
                        
                        let expected = value1 + value2;
                        assert_eq!(result, expected, "Result verification failed");
                        println!("[SUCCESS] Operation completed correctly");
                    } else {
                        return Err(anyhow::anyhow!("Invalid output length"));
                    }
                },
                Output::Create(..) => {
                    return Err(anyhow::anyhow!("Unexpected contract creation"));
                }
            }
        },
        ExecutionResult::Revert { gas_used, output } => {
            println!("[ERROR] Execution reverted");
            println!("[DEBUG] Gas used: {}", gas_used);
            println!("[DEBUG] Revert data: {:?}", output);
            return Err(anyhow::anyhow!("EVM execution reverted"));
        },
        ExecutionResult::Halt { reason, gas_used } => {
            println!("[ERROR] Execution halted");
            println!("[DEBUG] Reason: {:?}", reason);
            println!("[DEBUG] Gas used: {}", gas_used);
            return Err(anyhow::anyhow!("EVM execution halted"));
        }
    }

    Ok(())
}
