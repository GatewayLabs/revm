use crate::{gas, Host, Interpreter};
use primitives::U256;
use specification::hardfork::{Spec, SpecId::*};
use wiring::Block;

/// EIP-1344: ChainID opcode
pub fn chainid<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    check!(interpreter, ISTANBUL);
    gas!(interpreter, gas::BASE);
    push!(interpreter, U256::from(host.env().cfg.chain_id).into());
}

pub fn coinbase<H: Host + ?Sized>(interpreter: &mut Interpreter, host: &mut H) {
    gas!(interpreter, gas::BASE);
    push_b256!(interpreter, host.env().block.coinbase().into_word());
}

pub fn timestamp<H: Host + ?Sized>(interpreter: &mut Interpreter, host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(interpreter, (*host.env().block.timestamp()).into());
}

pub fn block_number<H: Host + ?Sized>(interpreter: &mut Interpreter, host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(interpreter, (*host.env().block.number()).into());
}

pub fn difficulty<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    gas!(interpreter, gas::BASE);
    if SPEC::enabled(MERGE) {
        push_b256!(interpreter, *host.env().block.prevrandao().unwrap());
    } else {
        push!(interpreter, (*host.env().block.difficulty()).into());
    }
}

pub fn gaslimit<H: Host + ?Sized>(interpreter: &mut Interpreter, host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(interpreter, (*host.env().block.gas_limit()).into());
}

/// EIP-3198: BASEFEE opcode
pub fn basefee<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    check!(interpreter, LONDON);
    gas!(interpreter, gas::BASE);
    push!(interpreter, (*host.env().block.basefee()).into());
}

/// EIP-7516: BLOBBASEFEE opcode
pub fn blob_basefee<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    check!(interpreter, CANCUN);
    gas!(interpreter, gas::BASE);
    push!(
        interpreter,
        U256::from(host.env().block.blob_gasprice().unwrap_or_default()).into()
    );
}
