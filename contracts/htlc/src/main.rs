#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

use alloc::vec::Vec;
use ckb_hash::blake2b_256;
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    error::SysError,
    high_level::{load_script, load_transaction, load_witness_args, QueryIter},
};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message,
};

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
// By default, the following heap configuration is used:
// * 16KB fixed heap
// * 1.2MB(rounded up to be 16-byte aligned) dynamic heap
// * Minimal memory block in dynamic heap is 64 bytes
// For more details, please refer to ckb-std's default_alloc macro
// and the buddy-alloc alloc implementation.
ckb_std::default_alloc!(16384, 1258306, 64);

const PUBKEY_HASH_SIZE: usize = 20;
const HASH_SIZE: usize = 32;
const ARGS_SIZE: usize = PUBKEY_HASH_SIZE * 2 + HASH_SIZE * 2 + 8;

const SIGNATURE_SIZE: usize = 65;
const PREIMAGE_SIZE: usize = 32;

const SECP256K1_DATA_HASH: [u8; 32] = [
    0x9b, 0xd7, 0xe0, 0x6f, 0x3e, 0xcf, 0x4b, 0xe0, 0xf2, 0xfc, 0xd2, 0x18, 0x8b, 0x23, 0xf1, 0xb9,
    0xfc, 0xc8, 0x8e, 0x5d, 0x4b, 0x65, 0xa8, 0x63, 0x7b, 0x17, 0x72, 0x3b, 0xbd, 0xa3, 0xcc, 0xe8,
];

#[repr(i8)]
pub enum Error {
    // System errors
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    // Custom errors
    ArgsInvalid,
    WitnessInvalid,
    SinceInvalid,
    PreimageInvalid,
    SignatureInvalid,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        match err {
            SysError::IndexOutOfBound => Self::IndexOutOfBound,
            SysError::ItemMissing => Self::ItemMissing,
            SysError::LengthNotEnough(_) => Self::LengthNotEnough,
            SysError::Encoding => Self::Encoding,
            _ => panic!("unexpected sys error"),
        }
    }
}

enum Action<'a> {
    Claim {
        signature: &'a [u8],
        preimage1: &'a [u8],
        preimage2: &'a [u8],
    },
    Refund {
        signature: &'a [u8],
    },
}

impl<'a> Action<'a> {
    fn from_bytes(witness_lock: &'a [u8]) -> Result<Self, Error> {
        if witness_lock.len() < SIGNATURE_SIZE {
            return Err(Error::WitnessInvalid);
        }

        let signature = &witness_lock[0..SIGNATURE_SIZE];
        if witness_lock.len() == SIGNATURE_SIZE {
            Ok(Action::Refund { signature })
        } else {
            let preimages = &witness_lock[SIGNATURE_SIZE..];
            if preimages.len() != PREIMAGE_SIZE * 2 {
                Err(Error::WitnessInvalid)
            } else {
                let preimage1 = &preimages[0..PREIMAGE_SIZE];
                let preimage2 = &preimages[PREIMAGE_SIZE..PREIMAGE_SIZE * 2];
                Ok(Action::Claim {
                    signature,
                    preimage1,
                    preimage2,
                })
            }
        }
    }
}

struct ScriptArgs<'a> {
    payer_pubkey_hash: &'a [u8],
    payee_pubkey_hash: &'a [u8],
    hash1: &'a [u8],
    hash2: &'a [u8],
    since: u64,
}

impl<'a> ScriptArgs<'a> {
    fn from_bytes(args: &'a [u8]) -> Result<Self, Error> {
        if args.len() != ARGS_SIZE {
            return Err(Error::ArgsInvalid);
        }

        let payer_pubkey_hash = &args[0..PUBKEY_HASH_SIZE];
        let payee_pubkey_hash = &args[PUBKEY_HASH_SIZE..PUBKEY_HASH_SIZE * 2];
        let hash1 = &args[PUBKEY_HASH_SIZE * 2..PUBKEY_HASH_SIZE * 2 + HASH_SIZE];
        let hash2 = &args[PUBKEY_HASH_SIZE * 2 + HASH_SIZE..PUBKEY_HASH_SIZE * 2 + HASH_SIZE * 2];

        let mut since_buf = [0u8; 8];
        since_buf.copy_from_slice(&args[PUBKEY_HASH_SIZE * 2 + HASH_SIZE * 2..]);
        let since = u64::from_le_bytes(since_buf);

        Ok(ScriptArgs {
            payer_pubkey_hash,
            payee_pubkey_hash,
            hash1,
            hash2,
            since,
        })
    }
}

pub fn program_entry() -> i8 {
    match run() {
        Ok(_) => 0,
        Err(e) => e as i8,
    }
}

fn run() -> Result<(), Error> {
    let script = load_script()?;

    let args_bytes: Bytes = script.args().unpack();
    let args = ScriptArgs::from_bytes(&args_bytes)?;

    let witness_args = load_witness_args(0, Source::GroupInput)?;
    let witness_lock: Bytes = witness_args
        .lock()
        .to_opt()
        .ok_or(Error::WitnessInvalid)?
        .unpack();
    let action = Action::from_bytes(&witness_lock)?;

    let tx_since = ckb_std::high_level::load_input_since(0, Source::GroupInput)?;

    match action {
        Action::Claim {
            signature,
            preimage1,
            preimage2,
        } => {
            // Verify since: must be before timeout
            if tx_since != 0 && tx_since >= args.since {
                return Err(Error::SinceInvalid);
            }

            // Verify preimages
            let calculated_hash1 = blake2b_256(preimage1);
            let calculated_hash2 = blake2b_256(preimage2);

            if args.hash1 != calculated_hash1.as_slice()
                || args.hash2 != calculated_hash2.as_slice()
            {
                return Err(Error::PreimageInvalid);
            }

            // Verify payee signature
            verify_signature(args.payee_pubkey_hash, signature)
        }
        Action::Refund { signature } => {
            // Verify since: must be at or after timeout
            if tx_since < args.since {
                return Err(Error::SinceInvalid);
            }

            // Verify payer signature
            verify_signature(args.payer_pubkey_hash, signature)
        }
    }
}

/// Verifies a secp256k1 signature.
///
/// This function reproduces the standard CKB signature verification process.
/// It constructs the message to be signed by hashing the transaction hash
/// with the hashes of all witnesses that share the current lock script.
fn verify_signature(expected_pubkey_hash: &[u8], signature: &[u8]) -> Result<(), Error> {
    if signature.len() != SIGNATURE_SIZE {
        return Err(Error::SignatureInvalid);
    }

    // Load the transaction hash
    let tx = load_transaction()?;
    let tx_hash = tx.calc_tx_hash();

    // Load all witness hashes for the current lock script
    let witness_hashes: Vec<[u8; 32]> = QueryIter::new(load_witness_args, Source::GroupInput)
        .map(|witness| blake2b_256(&witness.as_slice()))
        .collect();

    // Combine the transaction hash and witness hashes to form the message
    let mut message_data = tx_hash.raw_data().to_vec();
    for hash in witness_hashes {
        message_data.extend_from_slice(&hash);
    }
    let message_hash = blake2b_256(&message_data);

    // Create a secp256k1 message
    let message = Message::from_digest(message_hash);

    // Extract recovery ID and signature
    let recovery_id = RecoveryId::from_u8_masked(signature[SIGNATURE_SIZE - 1]);
    let sig = RecoverableSignature::from_compact(&signature[0..64], recovery_id)
        .map_err(|_| Error::SignatureInvalid)?;

    // Recover the public key
    let pubkey = sig.recover(message).map_err(|_| Error::SignatureInvalid)?;

    // Hash the recovered public key and compare with the expected hash
    let pubkey_hash = blake2b_256(&pubkey.serialize()[1..]);
    if pubkey_hash.as_slice() != expected_pubkey_hash {
        return Err(Error::SignatureInvalid);
    }

    Ok(())
}
