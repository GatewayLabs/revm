use compute::prelude::GateIndexVec;
use core::fmt;
use encryption::Ciphertext;
use primitives::ruint::Uint;
use primitives::{Bytes, U256};
use std::hash::{Hash, Hasher};
use std::vec::Vec;

#[macro_export]
macro_rules! push_private_memory {
    ($interp: expr, $private_value: expr, $result: ident) => {
        *$result = StackValueData::Private(
            $interp
                .private_memory
                .push(
                    crate::interpreter::private_memory::PrivateMemoryValue::Garbled($private_value),
                )
                .into(),
        );
    };
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrivateRef {
    tag: [u8; 4],
    index: [u8; 28],
}

impl PrivateRef {
    pub fn new(index: Uint<192, 3>) -> Self {
        Self {
            tag: DEFAULT_PRIVATE_REF_TAG.clone(),
            index: index.to_le_bytes(),
        }
    }
}

const DEFAULT_PRIVATE_REF_TAG: &[u8; 4] = b"PRIV";

/// Encode a PrivateRef as U256 representation
impl Into<Uint<256, 4>> for PrivateRef {
    fn into(self) -> U256 {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&DEFAULT_PRIVATE_REF_TAG[..]);
        bytes[4..].copy_from_slice(&self.index);
        U256::from_le_bytes(bytes)
    }
}

#[inline]
pub(crate) fn is_bytes_private_ref(bytes: &Bytes) -> bool {
    if bytes.len() < 4 {
        return false;
    } else {
        return bytes[..4] == *DEFAULT_PRIVATE_REF_TAG;
    }
}

#[inline]
pub(crate) fn is_u256_private_ref(val: &U256) -> bool {
    val.to_le_bytes::<32>()[..4] == *DEFAULT_PRIVATE_REF_TAG
}

#[inline]
pub(crate) fn is_private_ref(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == DEFAULT_PRIVATE_REF_TAG[..]
}

impl TryFrom<&[u8]> for PrivateRef {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if !is_private_ref(value) {
            return Err(());
        }

        let mut tag: [u8; 4] = [0; 4];
        tag.copy_from_slice(&value[..4]);

        let mut index: [u8; 28] = [0; 28];
        index.copy_from_slice(&value[4..]);

        Ok(PrivateRef { tag, index })
    }
}

/// Decode PrivateRef struct from U256 representation
impl TryFrom<Uint<256, 4>> for PrivateRef {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value.to_le_bytes();
        if !is_private_ref(&bytes) {
            return Err(());
        }

        let mut tag: [u8; 4] = [0; 4];
        tag.copy_from_slice(&bytes[..4]);

        let mut index = [0u8; 28];
        index.copy_from_slice(&bytes[4..]);

        Ok(PrivateRef { tag, index })
    }
}

#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Eq, Clone, Debug)]
pub enum PrivateMemoryValue {
    Garbled(GateIndexVec),
    Encrypted(Ciphertext),
}

impl std::hash::Hash for PrivateMemoryValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            PrivateMemoryValue::Garbled(gate_index_vec) => {
                for gate_index in gate_index_vec.iter() {
                    gate_index.hash(state);
                }
            }
            PrivateMemoryValue::Encrypted(ciphertext) => {
                ciphertext.to_bytes().hash(state);
            }
        }
    }
}

impl std::cmp::PartialEq for PrivateMemoryValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Garbled(l0), Self::Garbled(r0)) => l0 == r0,
            (Self::Encrypted(l0), Self::Encrypted(r0)) => l0 == r0,
            _ => false,
        }
    }
}

impl PrivateMemoryValue {
    pub fn copy(&self) -> Self {
        match self {
            Self::Garbled(gate_index_vec) => Self::Garbled(gate_index_vec.clone()),
            Self::Encrypted(ciphertext) => Self::Encrypted(ciphertext.clone()),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            PrivateMemoryValue::Garbled(val) => {
                // GateIndexVec aliases Vec<GateIndex: u32>
                val.iter().flat_map(|&x| x.to_le_bytes().to_vec()).collect()
            }
            _ => todo!(),
        }
    }
}

/// A sequential memory for private data, which uses
/// a `Vec` for internal representation.
/// A [PrivateMemory] instance should always be obtained using
/// the `new` static method to ensure memory safety.
#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PrivateMemory {
    /// The underlying buffer.
    pub data: Vec<PrivateMemoryValue>,
    /// Memory checkpoints for each depth.
    checkpoints: Vec<usize>,
    /// Invariant: equals `self.checkpoints.last()`
    last_checkpoint: usize,
}

/// Empty private memory.
///
/// Used as placeholder inside Interpreter when it is not running.
pub const EMPTY_PRIVATE_MEMORY: PrivateMemory = PrivateMemory {
    data: Vec::new(),
    checkpoints: Vec::new(),
    last_checkpoint: 0,
};

impl fmt::Debug for PrivateMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateMemory")
            .field("current_len", &self.len())
            .finish_non_exhaustive()
    }
}

impl Default for PrivateMemory {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateMemory {
    /// Creates a new memory instance that can be shared between calls.
    ///
    /// The default initial capacity is 4KiB.
    #[inline]
    pub fn new() -> Self {
        Self {
            data: Vec::with_capacity(4096),
            checkpoints: Vec::with_capacity(32),
            last_checkpoint: 0,
        }
    }

    /// Prepares the private memory for a new context.
    #[inline]
    pub fn new_context(&mut self) {
        let new_checkpoint = self.data.len();
        self.checkpoints.push(new_checkpoint);
        self.last_checkpoint = new_checkpoint;
    }

    /// Prepares the private memory for returning to the previous context.
    #[inline]
    pub fn free_context(&mut self) {
        if let Some(old_checkpoint) = self.checkpoints.pop() {
            self.last_checkpoint = self.checkpoints.last().cloned().unwrap_or_default();
            self.data.truncate(old_checkpoint);
        }
    }

    /// Resizes the memory in-place so that `len` is equal to `new_len`.
    #[inline]
    pub fn resize(&mut self, new_size: usize) {
        self.data.resize(
            self.last_checkpoint + new_size,
            PrivateMemoryValue::Garbled(GateIndexVec::new(vec![0, 8])),
        );
    }

    #[inline]
    pub fn push(&mut self, value: PrivateMemoryValue) -> PrivateRef {
        self.data.push(value);

        let id = self.data.len() - 1;

        let mut index: [u8; 28] = [0; 28];
        index[..id.to_le_bytes().len()].copy_from_slice(&id.to_le_bytes());

        PrivateRef {
            index,
            tag: DEFAULT_PRIVATE_REF_TAG.clone(),
        }
    }

    #[inline]
    pub fn get(&self, private_ref: &PrivateRef) -> PrivateMemoryValue {
        let mut index_bytes = [0u8; 8];
        index_bytes.copy_from_slice(&private_ref.index[..8]);
        let index = usize::from_le_bytes(index_bytes);

        self.data.get(index).unwrap().clone()
    }

    /// Returns the length of the current memory range.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len() - self.last_checkpoint
    }

    /// Returns `true` if the current memory range is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod test {
    use crate::{
        instructions::utility::{garbled_uint_to_ruint, ruint_to_garbled_uint},
        interpreter::{
            private_memory::{is_private_ref, is_u256_private_ref, PrivateMemoryValue},
            PrivateMemory,
        },
    };
    use compute::{
        prelude::WRK17CircuitBuilder,
        uint::{GarbledUint, GarbledUint256},
    };
    use primitives::U256;

    #[test]
    fn test_private_ref() {}

    #[test]
    fn test_private_memory_push_and_get() {
        let mut memory = PrivateMemory::new();

        let mut circuit_builder = WRK17CircuitBuilder::default();
        let garbled_uint = ruint_to_garbled_uint(&U256::from(128_u8));
        let gate_index_vec = circuit_builder.input(&garbled_uint);

        let ref1 = memory.push(PrivateMemoryValue::Garbled(gate_index_vec.clone()));
        let ref2 = memory.push(PrivateMemoryValue::Garbled(gate_index_vec.clone()));

        let ref_as_u256: U256 = ref1.into();
        assert!(is_u256_private_ref(&ref_as_u256));

        match memory.get(&ref1) {
            PrivateMemoryValue::Encrypted(_) => panic!("expected PrivateMemoryValue::Private"),
            PrivateMemoryValue::Garbled(value) => {
                assert_eq!(value.len(), gate_index_vec.len());
                for i in 0..value.len() {
                    assert_eq!(value[i], gate_index_vec[i]);
                }
            }
        }

        match memory.get(&ref2) {
            PrivateMemoryValue::Encrypted(_) => panic!("expected PrivateMemoryValue::Private"),
            PrivateMemoryValue::Garbled(gates) => {
                if let Ok(result) = circuit_builder.compile_and_execute::<256>(&gates) {
                    assert!(garbled_uint_to_ruint(&result) == (U256::from(128_u8)));
                } else {
                    panic!("Unable to compute fetched memory")
                }
            }
        }
    }

    #[test]
    fn test_private_memory_len_and_is_empty() {
        let mut memory = PrivateMemory::new();
        assert_eq!(memory.len(), 0);
        assert!(memory.is_empty());

        let mut circuit_builder = WRK17CircuitBuilder::default();
        let gate_index_vec = circuit_builder.input(&GarbledUint256::zero());

        memory.push(PrivateMemoryValue::Garbled(gate_index_vec));

        assert_eq!(memory.len(), 1);
        assert!(!memory.is_empty());
    }

    #[test]
    fn test_private_memory_default() {
        let memory = PrivateMemory::default();
        assert_eq!(memory.len(), 0);
        assert!(memory.is_empty());
    }

    #[test]
    fn test_private_memory_copy() {
        let mut memory = PrivateMemory::new();

        let mut circuit_builder = WRK17CircuitBuilder::default();
        let gate_index_vec = circuit_builder.input(&GarbledUint256::zero());

        memory.push(PrivateMemoryValue::Garbled(gate_index_vec.clone()));

        let copied_memory = memory.clone();

        assert_eq!(memory.len(), copied_memory.len());
        for i in 0..memory.len() {
            let mut index_bytes = [0u8; 8];
            let vec = memory.data[i].to_vec();
            index_bytes.copy_from_slice(&vec[..8]);
            let _private_ref = usize::from_le_bytes(index_bytes);
            assert_eq!(memory.data[i], copied_memory.data[i]);
        }
    }

    #[test]
    fn test_private_memory_context_management() {
        let mut memory = PrivateMemory::new();

        let mut circuit_builder = WRK17CircuitBuilder::default();
        let gate_index_vec = circuit_builder.input(&GarbledUint256::zero());

        memory.new_context();
        let private_ref1 = memory.push(PrivateMemoryValue::Garbled(gate_index_vec.clone()));
        assert_eq!(memory.len(), 1);

        memory.new_context();
        let private_ref2 = memory.push(PrivateMemoryValue::Garbled(gate_index_vec.clone()));
        assert_eq!(memory.len(), 1);

        memory.free_context();
        assert_eq!(memory.len(), 1);

        memory.free_context();
        assert_eq!(memory.len(), 0);
    }
}
