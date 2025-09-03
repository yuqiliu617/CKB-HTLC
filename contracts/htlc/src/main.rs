#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

use ckb_hash::blake2b_256;
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    debug,
    error::SysError,
    high_level::{load_script, load_tx_hash, load_witness_args},
};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};

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

#[repr(i8)]
#[derive(Debug, PartialEq)]
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
    WrongSinceFormat,
    ClaimExpired,
    RefundNotReady,
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

#[repr(u8)]
#[derive(PartialEq)]
enum SinceMetric {
    BlockNumber,
    EpochNumber,
    Timestamp,
    Invalid,
}

impl SinceMetric {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => SinceMetric::BlockNumber,
            1 => SinceMetric::EpochNumber,
            2 => SinceMetric::Timestamp,
            _ => SinceMetric::Invalid,
        }
    }
}

#[derive(PartialEq)]
struct Since {
    absolute: bool,
    metric: SinceMetric,
    value: u64,
}

impl Since {
    fn from_u64(since: u64) -> Result<Self, Error> {
        let absolute = (since & (1 << 63)) == 0;
        let metric = SinceMetric::from_u8(((since >> 61) & 0b11) as u8);
        let reserved = ((since >> 56) & 0b0001_1111) as u8;
        let value = since & 0x00FF_FFFF_FFFF_FFFF;

        if metric == SinceMetric::Invalid || reserved != 0 {
            Err(Error::SinceInvalid)
        } else {
            Ok(Since {
                absolute,
                metric,
                value,
            })
        }
    }

    fn comparable(&self) -> bool {
        self.absolute && self.metric != SinceMetric::EpochNumber
    }
}

impl PartialOrd for Since {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        if self.absolute
            && other.absolute
            && self.metric == other.metric
            && self.metric != SinceMetric::EpochNumber
        {
            self.value.partial_cmp(&other.value)
        } else {
            None
        }
    }
}

struct ScriptArgs<'a> {
    payer_pubkey_hash: &'a [u8],
    payee_pubkey_hash: &'a [u8],
    hash1: &'a [u8],
    hash2: &'a [u8],
    since: Since,
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
        let since = Since::from_u64(u64::from_le_bytes(since_buf))?;
        if !since.comparable() {
            return Err(Error::WrongSinceFormat);
        }

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
        Err(e) => {
            debug!("Error: {:?}", e);
            e as i8
        }
    }
}

fn run() -> Result<(), Error> {
    let script = load_script()?;

    // Parse script args
    let args_bytes: Bytes = script.args().unpack();
    let args = ScriptArgs::from_bytes(&args_bytes)?;

    // Parse witness lock
    let witness_args = load_witness_args(0, Source::GroupInput)?;
    let witness_lock: Bytes = witness_args
        .lock()
        .to_opt()
        .ok_or(Error::WitnessInvalid)?
        .unpack();
    let action = Action::from_bytes(&witness_lock)?;

    // Verify tx_since
    let tx_since = Since::from_u64(ckb_std::high_level::load_input_since(
        0,
        Source::GroupInput,
    )?)?;
    if !tx_since.comparable() || tx_since.metric != args.since.metric {
        return Err(Error::WrongSinceFormat);
    }

    match action {
        Action::Claim {
            signature,
            preimage1,
            preimage2,
        } => {
            // Verify since: must be before timeout
            if tx_since >= args.since {
                return Err(Error::ClaimExpired);
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
            verify_signature(signature, args.payee_pubkey_hash)
        }
        Action::Refund { signature } => {
            // Verify since: must be at or after timeout
            if tx_since < args.since {
                return Err(Error::RefundNotReady);
            }

            // Verify payer signature
            verify_signature(signature, args.payer_pubkey_hash)
        }
    }
}

fn verify_signature(signature: &[u8], pubkey_hash: &[u8]) -> Result<(), Error> {
    if signature.len() != SIGNATURE_SIZE {
        return Err(Error::SignatureInvalid);
    }

    // Recover the public key
    let tx_hash = load_tx_hash()?;
    let k256sig =
        K256Signature::from_slice(&signature[0..64]).map_err(|_| Error::SignatureInvalid)?;
    let recovery_id = RecoveryId::from_byte(signature[SIGNATURE_SIZE - 1]).unwrap();
    let pubkey = VerifyingKey::recover_from_prehash(&tx_hash.as_slice(), &k256sig, recovery_id)
        .map_err(|_| Error::SignatureInvalid)?;

    // Verify the public key hash
    let actual_pubkey_hash = blake2b_256(&pubkey.to_encoded_point(false).as_bytes()[1..]);
    if &actual_pubkey_hash[0..PUBKEY_HASH_SIZE] != pubkey_hash {
        return Err(Error::SignatureInvalid);
    }

    Ok(())
}
