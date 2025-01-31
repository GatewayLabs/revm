use database::InMemoryDB;
use encryption::{elgamal::ElGamalEncryption, encryption_trait::Encryptor, Keypair, Ciphertext};
use bincode::{self, Options};
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

fn save_keypair_storage(storage: &KeypairStorage) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(storage)?;
    fs::write(KEYPAIR_FILE, json)?;
    Ok(())
}

fn store_keypair(contract_address: &Address, keypair: &Keypair) -> anyhow::Result<()> {
    let mut storage = load_keypair_storage()?;
    
    let keypair_bytes = bincode::serialize(keypair)?;
    let keypair_str = base64::encode(&keypair_bytes);
    
    storage.keypairs.insert(hex::encode(contract_address), keypair_str);
    
    save_keypair_storage(&storage)?;
    Ok(())
}

fn load_keypair(contract_address: &Address) -> anyhow::Result<Option<Keypair>> {
    let storage = load_keypair_storage()?;
    
    if let Some(keypair_str) = storage.keypairs.get(&hex::encode(contract_address)) {
        let keypair_bytes = base64::decode(keypair_str)?;
        let keypair: Keypair = bincode::deserialize(&keypair_bytes)?;
        Ok(Some(keypair))
    } else {
        Ok(None)
    }
}

fn main() -> anyhow::Result<()> {
    let keypair = Keypair::new_rand();
    let public_key = keypair.pubkey();

    let value1 = U256::from(234u64);
    let value2 = U256::from(100u64);

    println!("[DEBUG] Input values: {} + {}", value1, value2);

    let encrypted_value1 = ElGamalEncryption::encrypt(&value1.to_le_bytes::<32>(), &public_key);
    let encrypted_value2 = ElGamalEncryption::encrypt(&value2.to_le_bytes::<32>(), &public_key);

    let mut calldata = Vec::new();
    calldata.extend_from_slice(&[0; 4]); // Function selector

    // Serializa o primeiro ciphertext em duas partes de 32 bytes
    let ser_config = bincode::DefaultOptions::new()
        .with_big_endian()
        .with_fixint_encoding();

    // Serializando o primeiro ciphertext diretamente
    let serialized_value1 = ser_config
        .serialize(&encrypted_value1)
        .expect("Failed to serialize first ciphertext");
    
    // Serializando o segundo ciphertext diretamente
    let serialized_value2 = ser_config
        .serialize(&encrypted_value2)
        .expect("Failed to serialize second ciphertext");

    calldata.extend_from_slice(&serialized_value1);
    calldata.extend_from_slice(&serialized_value2);
    
    println!("[DEBUG] Calldata size: {} bytes", calldata.len());

    let calldata = Bytes::from(calldata);
    let bytecode = Bytecode::new_raw(Bytes::from(RUNTIME_CODE));

    println!("[DEBUG] Calldata hex: {}", 
    calldata.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
    );

    let sender = Address::from_slice(&[0x20; 20]);
    let contract_address = Address::from_slice(&[0x42; 20]);
    
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
                    if data.len() >= 64 {
                        let des_config = bincode::DefaultOptions::new()
                            .with_fixint_encoding()
                            .with_big_endian()
                            .with_no_limit();

                        let result_ciphertext: Ciphertext = des_config.deserialize(&data)
                            .map_err(|e| {
                                println!("[ERROR] Deserialization error details: {:?}", e);
                                e
                            })?;

                        let keypair = load_keypair(&contract_address)?
                            .expect("Failed to load keypair for contract");

                        let decrypted_bytes = ElGamalEncryption::decrypt(&result_ciphertext, &keypair)
                            .expect("Failed to decrypt bytes");

                        let mut bytes32 = [0u8; 32];
                        let len = decrypted_bytes.len().min(32);
                        bytes32[..len].copy_from_slice(&decrypted_bytes[..len]);
                        let result = U256::from_le_bytes(bytes32);
                        
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
            println!("[DEBUG] Revert data: {:02x?}", output);
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
