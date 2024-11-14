// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module sui::attestation;

use sui::clock::{Self, Clock};

/// @param attestation: attesttaion documents bytes data. 
/// @param enclave_pk: The public key created from enclave startup.
/// @param pcr0: Hash of enclave image file.
/// @param pcr1: Hash of linux kernel and bootstrap. 
/// @param pcr2: Hash of application. 
/// @param timestamp: The timestamp ms from clock object.
///
/// See https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html#where
/// If the attestation verifies against the pcrs and against the root of aws trust, also the enclave public key equals to the attestation document's user data, return yes.
public native fun nitro_attestation_verify_inner(
    attestation: &vector<u8>,
    enclave_pk: &vector<u8>,
    pcr0: &vector<u8>,
    pcr1: &vector<u8>,
    pcr2: &vector<u8>,
    timestamp: u64
): bool;

public fun nitro_attestation_verify(
    attestation: &vector<u8>,
    enclave_pk: &vector<u8>,
    pcr0: &vector<u8>,
    pcr1: &vector<u8>,
    pcr2: &vector<u8>,
    clock: &Clock
): bool {
    nitro_attestation_verify_inner(attestation, enclave_pk, pcr0, pcr1, pcr2, clock::timestamp_ms(clock))
}