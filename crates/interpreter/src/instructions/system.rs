use crate::{gas, interpreter::StackValueData, Host, InstructionResult, Interpreter};
use primitives::{B256, KECCAK_EMPTY, U256};
use specification::hardfork::Spec;
use encryption::{elgamal::ElGamalEncryption, encryption_trait::Encryptor, Keypair, Ciphertext};

pub fn keccak256<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    pop_top!(interpreter, offset, len_ptr);
    let len = as_usize_or_fail!(interpreter, len_ptr);
    gas_or_fail!(interpreter, gas::keccak256_cost(len as u64));
    
    let hash = if len == 0 {
        KECCAK_EMPTY
    } else {
        let from = as_usize_or_fail!(interpreter, offset);
        
        let new_size = from.saturating_add(len);
        let current_size = core::cmp::max(
            interpreter.shared_memory.len(),
            interpreter.private_memory.len()
        );
        
        if new_size > current_size {
            #[cfg(feature = "memory_limit")]
            if interpreter.shared_memory.limit_reached(new_size) {
                interpreter.instruction_result = InstructionResult::MemoryLimitOOG;
                return;
            }

            let new_words = crate::interpreter::num_words(new_size as u64);
            let new_cost = crate::gas::memory_gas(new_words);
            let current_cost = interpreter.shared_memory.current_expansion_cost();
            let cost = new_cost - current_cost;
            
            if !interpreter.gas.record_cost(cost) {
                interpreter.instruction_result = InstructionResult::MemoryOOG;
                return;
            }
            
            interpreter.shared_memory.resize(new_size);
            interpreter.private_memory.resize(new_size);
        }

        primitives::keccak256(interpreter.shared_memory.slice(from, len))
    };
    
    *len_ptr = hash.into();
}

pub fn address<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    push_b256!(interpreter, interpreter.contract.target_address.into_word());
}

pub fn caller<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    push_b256!(interpreter, interpreter.contract.caller.into_word());
}

pub fn codesize<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    // Inform the optimizer that the bytecode cannot be EOF to remove a bounds check.
    assume!(!interpreter.contract.bytecode.is_eof());
    push!(interpreter, U256::from(interpreter.contract.bytecode.len()));
}

pub fn codecopy<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    pop!(interpreter, memory_offset, code_offset, len);
    let len = as_usize_or_fail!(interpreter, len);
    let Some(memory_offset) = memory_resize(interpreter, memory_offset, len) else {
        return;
    };
    let code_offset = as_usize_saturated!(code_offset);

    // Inform the optimizer that the bytecode cannot be EOF to remove a bounds check.
    assume!(!interpreter.contract.bytecode.is_eof());
    // Note: this can't panic because we resized memory to fit.
    interpreter.shared_memory.set_data(
        memory_offset,
        code_offset,
        len,
        interpreter.contract.bytecode.original_byte_slice(),
    );
}

fn find_value_position(offset: usize) -> Option<(usize, usize)> {
    if offset >= 68 && offset < 132 {
        Some((1, offset - 68))
    } else if offset >= 4 && offset < 68 {
        Some((0, offset - 4))
    } else {
        None
    }
}

fn decrypt_and_convert_value(input: &[u8], keypair: &Keypair, value_index: usize, value_offset: usize) -> Option<B256> {
    if value_offset >= 32 {
        return None;
    }

    let start_pos = 4 + (value_index * 64);
    if start_pos + 64 > input.len() {
        return None;
    }

    let ciphertext = bincode::deserialize::<Ciphertext>(&input[start_pos..start_pos + 64]).ok()?;
    let decrypted = ElGamalEncryption::decrypt(&ciphertext, keypair).ok()?;

    let mut word = B256::ZERO;
    let len = decrypted.len().min(32 - value_offset);
    word[32 - len..].copy_from_slice(&decrypted[..len]);

    Some(word)
}

fn extract_value_from_b256(word: B256) -> u64 {
    let bytes = word.as_slice();
    let mut result = bytes[23] as u64;
    if bytes[24] != 0 {
        result = (result << 8) | (bytes[24] as u64);
    }
    result
}

pub fn extract_word(input: &[u8], keypair: Option<&Keypair>, offset: usize) -> (B256, Option<StackValueData>) {
    if offset < input.len() {
        // Try to decrypt encrypted values
        if let Some((value_index, value_offset)) = find_value_position(offset) {
            if let Some(keypair) = keypair {
                if let Some(decrypted_word) = decrypt_and_convert_value(input, keypair, value_index, value_offset) {
                    let new_word = extract_value_from_b256(decrypted_word);
                    return (decrypted_word, Some(StackValueData::from(U256::from(new_word))));
                }
            }
        }

        // If decryption failed or not needed, copy raw bytes
        let mut word = B256::ZERO;
        let count = 32.min(input.len() - offset);
        word[..count].copy_from_slice(&input[offset..offset + count]);
        (word, None)
    } else {
        (B256::ZERO, None)
    }
}

pub fn calldataload<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, offset_ptr);
    let offset = as_usize_saturated!(offset_ptr);

    let (word, val) = extract_word(
        &interpreter.contract.input,
        interpreter.encryption_keypair.as_ref(),
        offset
    );
    *offset_ptr = val.unwrap_or(word.into());
}

pub fn calldatasize<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(interpreter, U256::from(interpreter.contract.input.len()));
}

pub fn callvalue<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(interpreter, interpreter.contract.call_value);
}

pub fn calldatacopy<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    pop!(interpreter, memory_offset, data_offset, len);
    let len = as_usize_or_fail!(interpreter, len);
    let Some(memory_offset) = memory_resize(interpreter, memory_offset, len) else {
        return;
    };

    let data_offset = as_usize_saturated!(data_offset);
    // Note: this can't panic because we resized memory to fit.
    interpreter.shared_memory.set_data(
        memory_offset,
        data_offset,
        len,
        &interpreter.contract.input,
    );
}

pub fn returndatasize<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, _host: &mut H) {
    check!(interpreter, BYZANTIUM);
    gas!(interpreter, gas::BASE);
    push!(
        interpreter,
        U256::from(interpreter.return_data_buffer.len())
    );
}

pub fn returndatacopy<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, _host: &mut H) {
    check!(interpreter, BYZANTIUM);
    pop!(interpreter, memory_offset, offset, len);

    let len = as_usize_or_fail!(interpreter, len);
    let data_offset = as_usize_saturated!(offset);

    // Old legacy behavior is to panic if data_end is out of scope of return buffer.
    // This behavior is changed in EOF.
    let data_end = data_offset.saturating_add(len);
    if data_end > interpreter.return_data_buffer.len() && !interpreter.is_eof {
        interpreter.instruction_result = InstructionResult::OutOfOffset;
        return;
    }

    let Some(memory_offset) = memory_resize(interpreter, memory_offset, len) else {
        return;
    };

    // Note: this can't panic because we resized memory to fit.
    interpreter.shared_memory.set_data(
        memory_offset,
        data_offset,
        len,
        interpreter.return_data_buffer.as_ref(),
    );
}

pub fn returndataload<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    require_eof!(interpreter);
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, offset);
    let offset_usize = as_usize_saturated!(offset);

    let mut output = [0u8; 32];
    if let Some(available) = interpreter
        .return_data_buffer
        .len()
        .checked_sub(offset_usize)
    {
        let copy_len = available.min(32);
        output[..copy_len].copy_from_slice(
            &interpreter.return_data_buffer[offset_usize..offset_usize + copy_len],
        );
    }

    *offset = B256::from(output).into();
}

pub fn gas<H: Host + ?Sized>(interpreter: &mut Interpreter, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(interpreter, U256::from(interpreter.gas.remaining()));
}

pub fn memory_resize(
    interpreter: &mut Interpreter,
    memory_offset: StackValueData,
    len: usize,
) -> Option<usize> {
    gas_or_fail!(interpreter, gas::copy_cost_verylow(len as u64), None);
    if len == 0 {
        return None;
    }
    let memory_offset = as_usize_or_fail_ret!(interpreter, memory_offset.to_u256(), None);
    resize_memory!(interpreter, memory_offset, len, None);

    Some(memory_offset)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{table::make_instruction_table, DummyHost, Gas, InstructionResult};
    use bytecode::opcode::{RETURNDATACOPY, RETURNDATALOAD};
    use bytecode::Bytecode;
    use primitives::bytes;
    use specification::hardfork::PragueSpec;
    use wiring::DefaultEthereumWiring;

    #[test]
    fn returndataload() {
        let table = make_instruction_table::<DummyHost<DefaultEthereumWiring>, PragueSpec>();
        let mut host = DummyHost::default();

        let mut interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
            [
                RETURNDATALOAD,
                RETURNDATALOAD,
                RETURNDATALOAD,
                RETURNDATALOAD,
            ]
            .into(),
        ));
        interp.is_eof = true;
        interp.gas = Gas::new(10000);

        interp.stack.push(U256::from(0)).unwrap();
        interp.return_data_buffer =
            bytes!("000000000000000400000000000000030000000000000002000000000000000100");
        interp.step(&table, &mut host);
        assert_eq!(
            interp.stack.data(),
            &vec![U256::from_limbs([0x01, 0x02, 0x03, 0x04]).into()]
        );

        let _ = interp.stack.pop();
        let _ = interp.stack.push(U256::from(1));

        interp.step(&table, &mut host);
        assert_eq!(interp.instruction_result, InstructionResult::Continue);
        assert_eq!(
            interp.stack.data(),
            &vec![U256::from_limbs([0x0100, 0x0200, 0x0300, 0x0400]).into()]
        );

        let _ = interp.stack.pop();
        let _ = interp.stack.push(U256::from(32));
        interp.step(&table, &mut host);
        assert_eq!(interp.instruction_result, InstructionResult::Continue);
        assert_eq!(
            interp.stack.data(),
            &vec![U256::from_limbs([0x00, 0x00, 0x00, 0x00]).into()]
        );

        // Offset right at the boundary of the return data buffer size
        let _ = interp.stack.pop();
        let _ = interp
            .stack
            .push(U256::from(interp.return_data_buffer.len()));
        interp.step(&table, &mut host);
        assert_eq!(interp.instruction_result, InstructionResult::Continue);
        assert_eq!(
            interp.stack.data(),
            &vec![U256::from_limbs([0x00, 0x00, 0x00, 0x00]).into()]
        );
    }

    #[test]
    fn returndatacopy() {
        let table = make_instruction_table::<_, PragueSpec>();
        let mut host = DummyHost::<DefaultEthereumWiring>::default();

        let mut interp = Interpreter::new_bytecode(Bytecode::LegacyRaw(
            [
                RETURNDATACOPY,
                RETURNDATACOPY,
                RETURNDATACOPY,
                RETURNDATACOPY,
                RETURNDATACOPY,
                RETURNDATACOPY,
            ]
            .into(),
        ));
        interp.is_eof = true;
        interp.gas = Gas::new(10000);

        interp.return_data_buffer =
            bytes!("000000000000000400000000000000030000000000000002000000000000000100");
        interp.shared_memory.resize(256);

        // Copying within bounds
        interp.stack.push(U256::from(32)).unwrap();
        interp.stack.push(U256::from(0)).unwrap();
        interp.stack.push(U256::from(0)).unwrap();
        interp.step(&table, &mut host);
        assert_eq!(interp.instruction_result, InstructionResult::Continue);
        assert_eq!(
            interp.shared_memory.slice(0, 32),
            &interp.return_data_buffer[0..32]
        );

        // Copying with partial out-of-bounds (should zero pad)
        interp.stack.push(U256::from(64)).unwrap();
        interp.stack.push(U256::from(16)).unwrap();
        interp.stack.push(U256::from(64)).unwrap();
        interp.step(&table, &mut host);
        assert_eq!(interp.instruction_result, InstructionResult::Continue);
        assert_eq!(
            interp.shared_memory.slice(64, 16),
            &interp.return_data_buffer[16..32]
        );
        assert_eq!(&interp.shared_memory.slice(80, 48), &[0u8; 48]);

        // Completely out-of-bounds (should be all zeros)
        interp.stack.push(U256::from(32)).unwrap();
        interp.stack.push(U256::from(96)).unwrap();
        interp.stack.push(U256::from(128)).unwrap();
        interp.step(&table, &mut host);
        assert_eq!(interp.instruction_result, InstructionResult::Continue);
        assert_eq!(&interp.shared_memory.slice(128, 32), &[0u8; 32]);

        // Large offset
        interp.stack.push(U256::from(32)).unwrap();
        interp.stack.push(U256::MAX).unwrap();
        interp.stack.push(U256::from(0)).unwrap();
        interp.step(&table, &mut host);
        assert_eq!(interp.instruction_result, InstructionResult::Continue);
        assert_eq!(&interp.shared_memory.slice(0, 32), &[0u8; 32]);

        // Offset just before the boundary of the return data buffer size
        interp.stack.push(U256::from(32)).unwrap();
        interp
            .stack
            .push(U256::from(interp.return_data_buffer.len() - 32).into())
            .unwrap();
        interp.stack.push(U256::from(0)).unwrap();
        interp.step(&table, &mut host);
        assert_eq!(interp.instruction_result, InstructionResult::Continue);
        assert_eq!(
            interp.shared_memory.slice(0, 32),
            &interp.return_data_buffer[interp.return_data_buffer.len() - 32..]
        );

        // Offset right at the boundary of the return data buffer size
        interp.stack.push(U256::from(32)).unwrap();
        interp
            .stack
            .push(U256::from(interp.return_data_buffer.len()).into())
            .unwrap();
        interp.stack.push(U256::from(0)).unwrap();
        interp.step(&table, &mut host);
        assert_eq!(interp.instruction_result, InstructionResult::Continue);
        assert_eq!(&interp.shared_memory.slice(0, 32), &[0u8; 32]);
    }
}