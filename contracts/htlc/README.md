# Dual Hash Time Locked Contract (HTLC)

A Nervos CKB implementation of a Hash Time Locked Contract with dual hash locks and timeout functionality.

## Overview

This contract implements a conditional payment system using:
- **Dual Hash Locks**: Requires two different preimages to unlock (e.g., confirmations from two parties)
- **Timeout Mechanism**: Allows the payer to reclaim funds after a specified block height

## Contract Structure

### Cell Structure

The HTLC lock script stores the following information in its args:

| Field                 | Size (bytes) | Description                                              |
| --------------------- | ------------ | -------------------------------------------------------- |
| Payer Public Key Hash | 20           | The payer's public key hash (for refund verification)    |
| Payee Public Key Hash | 20           | The payee's public key hash (for claim verification)     |
| Hash Lock 1           | 32           | The hash of the first preimage                           |
| Hash Lock 2           | 32           | The hash of the second preimage                          |
| Since Value           | 8            | The block height after which the payer can reclaim funds |

Total args size: 112 bytes

### Witness Structure

#### For Claim (by Payee)

| Field      | Size (bytes) | Description           |
| ---------- | ------------ | --------------------- |
| Signature  | 65           | The payee's signature |
| Preimage 1 | 32           | The first preimage    |
| Preimage 2 | 32           | The second preimage   |

Total witness size: 129 bytes

#### For Refund (by Payer)

| Field     | Size (bytes) | Description           |
| --------- | ------------ | --------------------- |
| Signature | 65           | The payer's signature |

Total witness size: 65 bytes

## Usage Flow

### Creating an HTLC Cell

1. Generate two random preimages and their corresponding hashes
2. Prepare the args by concatenating:
   - Payer's public key hash (20 bytes)
   - Payee's public key hash (20 bytes)
   - Hash of preimage 1 (32 bytes)
   - Hash of preimage 2 (32 bytes)
   - Since value as LE bytes (8 bytes)
3. Create a cell with:
   - Lock script pointing to the HTLC binary with the above args
   - Desired capacity

### Claiming Funds (Payee)

The payee can claim funds before the timeout by:

1. Creating a transaction consuming the HTLC cell
2. Providing a witness containing:
   - Valid signature from the payee
   - Both correct preimages
3. Setting the output cell with the payee's desired lock script

### Refunding (Payer)

The payer can reclaim funds after the timeout by:

1. Creating a transaction consuming the HTLC cell
2. Setting the transaction's `since` field to be ≥ the HTLC's since value
3. Providing a witness containing only the payer's signature
4. Setting the output cell with the payer's desired lock script

## Unlock Conditions

- **Before timeout**:
  - Only the payee can unlock by providing both correct preimages and a valid signature
  - The payer cannot reclaim funds yet

- **After timeout**:
  - The payer can reclaim funds by providing a valid signature
  - The payee can still claim if they provide both correct preimages and a valid signature

## Security Considerations

- Preimages should be kept secret until ready to claim
- The `since` value should be chosen carefully based on the use case
- Both parties should verify the correctness of the HTLC cell before proceeding with the protocol
- The hash algorithm used is Blake2b, consistent with CKB's cryptographic primitive
