use crate::{verify_and_dump_failed_tx, Loader};
use ckb_hash::blake2b_256;
use ckb_testtool::{
    ckb_types::{
        bytes::Bytes,
        core::{TransactionBuilder, TransactionView},
        packed::*,
        prelude::*,
    },
    context::Context,
};
use k256::{
    ecdsa::{signature::Error as SigError, SigningKey},
    elliptic_curve::rand_core::{OsRng, RngCore},
    SecretKey,
};

const PUBKEY_HASH_SIZE: usize = 20;
const HASH_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 65;
const PREIMAGE_SIZE: usize = 32;

struct KeyPair {
    signing_key: SigningKey,
    pubkey_hash: [u8; PUBKEY_HASH_SIZE],
}

impl KeyPair {
    fn new() -> Self {
        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(&secret_key);
        let pubkey = signing_key.verifying_key();
        let pubkey_hash = blake2b_256(&pubkey.to_encoded_point(false).as_bytes()[1..]);

        Self {
            signing_key,
            pubkey_hash: pubkey_hash[0..PUBKEY_HASH_SIZE]
                .try_into()
                .expect("hash size correct"),
        }
    }

    fn sign(&self, prehash: &[u8; 32]) -> Result<[u8; SIGNATURE_SIZE], SigError> {
        let (signature, recovery_id) = self.signing_key.sign_prehash_recoverable(prehash)?;
        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes[0..64].copy_from_slice(&signature.to_bytes());
        sig_bytes[64] = recovery_id.to_byte();
        Ok(sig_bytes)
    }
}

struct PreimageWithHash {
    preimage: [u8; PREIMAGE_SIZE],
    hash: [u8; HASH_SIZE],
}

impl PreimageWithHash {
    fn new() -> Self {
        let mut preimage = [0u8; PREIMAGE_SIZE];
        (&mut OsRng).fill_bytes(&mut preimage);
        let hash = blake2b_256(&preimage);

        Self { preimage, hash }
    }
}

struct ScriptArgs {
    payer: KeyPair,
    payee: KeyPair,
    preimages: (PreimageWithHash, PreimageWithHash),
    since: u64,
}

impl ScriptArgs {
    fn new(since: u64) -> Self {
        let preimage1 = PreimageWithHash::new();
        let preimage2 = PreimageWithHash::new();
        Self {
            payer: KeyPair::new(),
            payee: KeyPair::new(),
            preimages: (preimage1, preimage2),
            since,
        }
    }

    fn build_args(&self) -> Bytes {
        let mut args = Vec::with_capacity(PUBKEY_HASH_SIZE * 2 + HASH_SIZE * 2 + 8);
        args.extend_from_slice(&self.payer.pubkey_hash);
        args.extend_from_slice(&self.payee.pubkey_hash);
        args.extend_from_slice(&self.preimages.0.hash);
        args.extend_from_slice(&self.preimages.1.hash);
        args.extend_from_slice(&self.since.to_le_bytes());
        Bytes::from(args)
    }
}

// Creates witness data for claim (signature + preimages)
fn build_claim_witness(
    signature: &[u8; SIGNATURE_SIZE],
    preimage1: &[u8; PREIMAGE_SIZE],
    preimage2: &[u8; PREIMAGE_SIZE],
) -> Bytes {
    let mut witness_data = Vec::with_capacity(SIGNATURE_SIZE + PREIMAGE_SIZE * 2);
    witness_data.extend_from_slice(signature);
    witness_data.extend_from_slice(preimage1);
    witness_data.extend_from_slice(preimage2);
    Bytes::from(witness_data)
}

fn sign_claim_tx(
    tx: TransactionView,
    context: &mut Context,
    signer: &KeyPair,
    preimages: ([u8; PREIMAGE_SIZE], [u8; PREIMAGE_SIZE]),
) -> Result<TransactionView, SigError> {
    let complete_tx = context.complete_tx(tx);

    let tx_hash = complete_tx.hash();
    let signature = signer.sign(tx_hash.as_slice().try_into().unwrap())?;

    let witness = build_claim_witness(&signature, &preimages.0, &preimages.1);
    let witness_args = WitnessArgs::new_builder()
        .lock(Some(witness).pack())
        .build();
    Ok(complete_tx
        .as_advanced_builder()
        .witness(witness_args.as_bytes().pack())
        .build())
}

fn sign_refund_tx(
    tx: TransactionView,
    context: &mut Context,
    signer: &KeyPair,
) -> Result<TransactionView, SigError> {
    let complete_tx = context.complete_tx(tx);

    let tx_hash = complete_tx.hash();
    let signature = signer.sign(tx_hash.as_slice().try_into().unwrap())?;

    let witness = Bytes::from(signature.to_vec());
    let witness_args = WitnessArgs::new_builder()
        .lock(Some(witness).pack())
        .build();

    Ok(complete_tx
        .as_advanced_builder()
        .witness(witness_args.as_bytes().pack())
        .build())
}

#[test]
fn test_htlc_claim_success() {
    // Setup
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("htlc");
    let out_point = context.deploy_cell(contract_bin);

    let script_args = ScriptArgs::new(1000);
    let args = script_args.build_args();

    // Create script
    let lock_script = context
        .build_script(&out_point, args)
        .expect("build script");

    // Create HTLC cell with funds
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );

    // Setup transaction
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    // Create output cell controlled by payee
    let payee_out_point = context.deploy_cell(Bytes::from(vec![0]));
    let payee_lock_script = context
        .build_script(
            &payee_out_point,
            Bytes::from(script_args.payee.pubkey_hash.to_vec()),
        )
        .expect("payee script");

    let output = CellOutput::new_builder()
        .capacity(990u64.pack()) // Account for transaction fee
        .lock(payee_lock_script)
        .build();

    // Build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(Bytes::new().pack())
        .build();
    let tx = sign_claim_tx(
        tx,
        &mut context,
        &script_args.payee,
        (
            script_args.preimages.0.preimage,
            script_args.preimages.1.preimage,
        ),
    )
    .expect("sign tx");

    // Verify (should pass)
    let cycles = verify_and_dump_failed_tx(&context, &tx, 10_000_000).expect("pass verification");
    println!("Claim success cycles: {}", cycles);
}

#[test]
fn test_htlc_refund_success() {
    // Setup
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("htlc");
    let out_point = context.deploy_cell(contract_bin);

    let script_args = ScriptArgs::new(1000);
    let args = script_args.build_args();

    // Create script
    let lock_script = context
        .build_script(&out_point, args)
        .expect("build script");

    // Create HTLC cell with funds
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );

    // Setup transaction
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .since(script_args.since.pack()) // Set since value to match or exceed the locktime
        .build();

    // Create output cell controlled by payer
    let payer_out_point = context.deploy_cell(Bytes::from(vec![0]));
    let payer_lock_script = context
        .build_script(
            &payer_out_point,
            Bytes::from(script_args.payee.pubkey_hash.to_vec()),
        )
        .expect("payer script");

    let output = CellOutput::new_builder()
        .capacity(990u64.pack()) // Account for transaction fee
        .lock(payer_lock_script)
        .build();

    // Build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(Bytes::new().pack())
        .build();
    let tx = sign_refund_tx(tx, &mut context, &script_args.payer).expect("sign tx");

    // Verify (should pass)
    let cycles = verify_and_dump_failed_tx(&context, &tx, 10_000_000).expect("pass verification");
    println!("Refund success cycles: {}", cycles);
}

#[test]
fn test_htlc_claim_failure_invalid_preimage() {
    // Setup
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("htlc");
    let out_point = context.deploy_cell(contract_bin);

    let script_args = ScriptArgs::new(1000);
    let args = script_args.build_args();

    let invalid_preimage = PreimageWithHash::new(); // Different from what's in the lock

    // Create script
    let lock_script = context
        .build_script(&out_point, args)
        .expect("build script");

    // Create HTLC cell with funds
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );

    // Setup transaction
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    // Create output cell controlled by payee
    let payee_out_point = context.deploy_cell(Bytes::from(vec![0]));
    let payee_lock_script = context
        .build_script(
            &payee_out_point,
            Bytes::from(script_args.payee.pubkey_hash.to_vec()),
        )
        .expect("payee script");

    let output = CellOutput::new_builder()
        .capacity(990u64.pack())
        .lock(payee_lock_script)
        .build();

    // Build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(Bytes::new().pack())
        .build();
    let tx = sign_claim_tx(
        tx,
        &mut context,
        &script_args.payee,
        (
            invalid_preimage.preimage, // Use invalid preimage
            script_args.preimages.1.preimage,
        ),
    )
    .expect("sign tx");

    // Verify (should fail due to invalid preimage)
    let result = verify_and_dump_failed_tx(&context, &tx, 10_000_000);
    assert!(result.is_err(), "Claim with invalid preimage should fail");
}

#[test]
fn test_htlc_refund_failure_before_timeout() {
    // Setup
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("htlc");
    let out_point = context.deploy_cell(contract_bin);

    let script_args = ScriptArgs::new(1000);
    let args = script_args.build_args();

    // Create script
    let lock_script = context
        .build_script(&out_point, args)
        .expect("build script");

    // Create HTLC cell with funds
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );

    // Setup transaction with since value less than the locktime (not expired)
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .since(500u64.pack()) // Less than the since in the contract
        .build();

    // Create output cell controlled by payer
    let payer_out_point = context.deploy_cell(Bytes::from(vec![0]));
    let payer_lock_script = context
        .build_script(
            &payer_out_point,
            Bytes::from(script_args.payee.pubkey_hash.to_vec()),
        )
        .expect("payer script");

    let output = CellOutput::new_builder()
        .capacity(990u64.pack())
        .lock(payer_lock_script)
        .build();

    // Build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(Bytes::new().pack())
        .build();
    let tx = sign_refund_tx(tx, &mut context, &script_args.payer).expect("sign tx");

    // Verify (should fail due to timeout not reached)
    let result = verify_and_dump_failed_tx(&context, &tx, 10_000_000);
    println!("Refund failure before timeout result: {:?}", result);
    assert!(result.is_err(), "Refund before timeout should fail");
}
