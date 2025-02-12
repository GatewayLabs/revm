use super::{Account, EvmStorageSlot};
use compute::uint::GarbledUint256;
use primitives::{Address, HashMap, U256};

/// EVM State is a mapping from addresses to accounts.
pub type EvmState = HashMap<Address, Account>;

/// Structure used for EIP-1153 transient storage.
pub type TransientStorage = HashMap<(Address, U256), GarbledUint256>;

/// An account's Storage is a mapping from 256-bit integer keys to [EvmStorageSlot]s.
pub type EvmStorage = HashMap<U256, EvmStorageSlot>;
