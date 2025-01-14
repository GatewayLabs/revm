use compute::{prelude::GateIndexVec, uint::GarbledUint};
use core::fmt;
use std::vec::Vec;

/// A sequential memory for private data, which uses
/// a `Vec` for internal representation.
/// A [PrivateMemory] instance should always be obtained using
/// the `new` static method to ensure memory safety.
#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PrivateMemory {
    /// The underlying buffer.
    buffer: Vec<GateIndexVec>,
    /// Memory checkpoints for each depth.
    /// Invariant: these are always in bounds of `data`.
    checkpoints: Vec<usize>,
    /// Invariant: equals `self.checkpoints.last()`
    last_checkpoint: usize,
    /// Memory limit. See [`CfgEnv`](wiring::default::CfgEnv).
    #[cfg(feature = "memory_limit")]
    memory_limit: u64,
}

/// Empty private memory.
///
/// Used as placeholder inside Interpreter when it is not running.
pub const EMPTY_PRIVATE_MEMORY: PrivateMemory = PrivateMemory {
    buffer: Vec::new(),
    checkpoints: Vec::new(),
    last_checkpoint: 0,
    #[cfg(feature = "memory_limit")]
    memory_limit: u64::MAX,
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
        Self::with_capacity(4 * 1024)
    }

    /// Creates a new memory instance that can be shared between calls with the given `capacity`.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            checkpoints: Vec::with_capacity(32),
            last_checkpoint: 0,
            #[cfg(feature = "memory_limit")]
            memory_limit: u64::MAX,
        }
    }

    /// Creates a new memory instance that can be shared between calls,
    /// with `memory_limit` as upper bound for allocation size.
    ///
    /// The default initial capacity is 4KiB.
    #[cfg(feature = "memory_limit")]
    #[inline]
    pub fn new_with_memory_limit(memory_limit: u64) -> Self {
        Self {
            memory_limit,
            ..Self::new()
        }
    }

    /// Returns `true` if the `new_size` for the current context memory will
    /// make the shared buffer length exceed the `memory_limit`.
    #[cfg(feature = "memory_limit")]
    #[inline]
    pub fn limit_reached(&self, new_size: usize) -> bool {
        self.last_checkpoint.saturating_add(new_size) as u64 > self.memory_limit
    }

    /// Prepares the private memory for a new context.
    #[inline]
    pub fn new_context(&mut self) {
        let new_checkpoint = self.buffer.len();
        self.checkpoints.push(new_checkpoint);
        self.last_checkpoint = new_checkpoint;
    }

    /// Prepares the private memory for returning to the previous context.
    #[inline]
    pub fn free_context(&mut self) {
        if let Some(old_checkpoint) = self.checkpoints.pop() {
            self.last_checkpoint = self.checkpoints.last().cloned().unwrap_or_default();
            // SAFETY: buffer length is less than or equal `old_checkpoint`
            unsafe { self.buffer.set_len(old_checkpoint) };
        }
    }

    /// Returns the length of the current memory range.
    #[inline]
    pub fn len(&self) -> usize {
        self.buffer.len() - self.last_checkpoint
    }

    /// Returns `true` if the current memory range is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Resizes the memory in-place so that `len` is equal to `new_len`.
    #[inline]
    pub fn resize(&mut self, new_size: usize, circuit_builder: &mut compute::prelude::WRK17CircuitBuilder) {
        let old_size = self.buffer.len();
        // Initialize with empty GateIndexVec for new positions
        for _ in old_size..self.last_checkpoint + new_size {
            let gate_vec: GarbledUint<1> = GarbledUint::from(false);
            let zero_value = circuit_builder.input(&gate_vec);
            self.buffer.push(zero_value);
        }
    }

    /// Returns a reference to a GateIndexVec at the given offset.
    ///
    /// # Panics
    ///
    /// Panics on out of bounds.
    #[inline]
    pub fn get(&self, offset: usize) -> &GateIndexVec {
        let actual_offset = self.last_checkpoint + offset;
        &self.buffer[actual_offset]
    }

    /// Returns a mutable reference to a GateIndexVec at the given offset.
    ///
    /// # Panics
    ///
    /// Panics on out of bounds.
    #[inline]
    pub fn get_mut(&mut self, offset: usize) -> &mut GateIndexVec {
        &mut self.buffer[self.last_checkpoint + offset]
    }

    /// Copies elements from one part of the memory to another part of itself.
    ///
    /// # Panics
    ///
    /// Panics on out of bounds.
    #[inline]
    pub fn copy(&mut self, dst: usize, src: usize, len: usize) {
        let dst_start = self.last_checkpoint + dst;
        let src_start = self.last_checkpoint + src;
        
        // Collect all source values first
        let src_values: Vec<GateIndexVec> = self.buffer[src_start..src_start + len].to_vec();
        
        // Then copy each value to destination
        for (i, value) in src_values.iter().enumerate() {
            self.buffer[dst_start + i] = value.clone();
        }
    }
}
