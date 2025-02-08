use compute::prelude::GateIndexVec;
use core::fmt;
use core::ops::Index;
use encryption::Ciphertext;
use primitives::ruint::Uint;
use primitives::U256;
use std::hash::{Hash, Hasher};
use std::vec::Vec;

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct PrivateRef {
    tag: [u8; 4],
    index: [u8; 28],
}

const DEFAULT_PRIVATE_REF_TAG: &[u8; 4] = b"PRIV";

/// Encode a PrivateRef as U256 representation
impl Into<Uint<256, 4>> for PrivateRef {
    fn into(self) -> U256 {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&DEFAULT_PRIVATE_REF_TAG[..]);
        bytes[4..].copy_from_slice(&self.index);
        U256::from_le_bytes::<32>(bytes)
    }
}

#[inline]
pub(crate) fn is_private_tag(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == DEFAULT_PRIVATE_REF_TAG[..]
}

impl TryFrom<&[u8]> for PrivateRef {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if !is_private_tag(value) {
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
        let bytes = value.to_le_bytes::<32>();
        if !is_private_tag(&bytes) {
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
#[derive(Eq, Clone)]
pub enum PrivateMemoryValue {
    Private(GateIndexVec),
    Encrypted(Ciphertext),
}

impl std::hash::Hash for PrivateMemoryValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            PrivateMemoryValue::Private(gate_index_vec) => {
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
            (Self::Private(l0), Self::Private(r0)) => l0 == r0,
            (Self::Encrypted(l0), Self::Encrypted(r0)) => l0 == r0,
            _ => false,
        }
    }
}

impl PrivateMemoryValue {
    pub fn copy(&self) -> Self {
        match self {
            Self::Private(gate_index_vec) => Self::Private(gate_index_vec.clone()),
            Self::Encrypted(ciphertext) => Self::Encrypted(ciphertext.clone()),
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
    data: Vec<PrivateMemoryValue>,
}

/// Empty private memory.
///
/// Used as placeholder inside Interpreter when it is not running.
pub const EMPTY_PRIVATE_MEMORY: PrivateMemory = PrivateMemory { data: Vec::new() };

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
        Self::default()
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
    pub fn get(&self, private_ref: PrivateRef) -> PrivateMemoryValue {
        let mut index_bytes = [0u8; 8];
        index_bytes.copy_from_slice(&private_ref.index[..8]);
        let index = usize::from_le_bytes(index_bytes);

        self.data.get(index).unwrap().clone()
    }

    /// Returns the length of the current memory range.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the current memory range is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
