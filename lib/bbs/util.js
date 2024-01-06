/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {bls12_381} from '@noble/curves/bls12-381.js';
import {bytesToNumberBE as os2ip} from '@noble/curves/abstract/utils.js';
import {CIPHERSUITES} from './ciphersuites.js';
import {mod} from '@noble/curves/abstract/modular.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

/*
FIXME: implement other utils from RFC as needed:

calculate_domain
serialize, signature_to_octets, octets_to_signature, proof_to_octets,
  octets_to_proof and octets_to_pubkey
e (pairing operation).
*/

/**
 * This hashes an arbitrary message (Uint8Array) to a scalar that is in the
 * multiplicative group of integers mod `r` (where `r` is defined by a
 * particular ciphersuite). In other words, it maps an arbitrary string to a
 * number in a particular range via some specific IETF RFC algorithms.
 *
 * @param {object} options - The options to use.
 * @param {Uint8Array} options.msg_octets - The octet string to be hashed.
 * @param {Uint8Array} options.dst - The domain separation tag.
 * @param {string} options.ciphersuite_id - The ID of the ciphersuite to
 *   use to identify hashing parameters.
 *
 * @returns {Uint8Array} - The scalar (hashed result).
 */
export function hash_to_scalar({msg_octets, dst, ciphersuite_id}) {
  _assertUint8Array(msg_octets, 'msg_octets');
  _assertUint8Array(dst, 'dst');

  if(dst.length > 255) {
    throw new Error('"dst.length" must be <= 255.');
  }

  const ciphersuite = CIPHERSUITES[ciphersuite_id];
  if(!ciphersuite) {
    throw new Error(`Unknown ciphersuite ID "${ciphersuite_id}".`);
  }

  // 1. uniform_bytes = expand_message(msg_octets, dst, expand_len)
  // 2. return OS2IP(uniform_bytes) mod r
  // Note: `expand_len` is preset by ciphersuite.
  const uniform_bytes = ciphersuite.expand_message(msg_octets, dst);
  return mod(os2ip(uniform_bytes), ciphersuite.r);
}

export function hash_to_curve_g1({msg_octets, dst}) {
  _assertUint8Array(msg_octets, 'msg_octets');
  _assertUint8Array(dst, 'dst');

  if(dst.length > 255) {
    throw new Error('"dst.length" must be <= 255.');
  }

  // FIXME: probably can't just call this as hash function needs to change
  // based on ciphersuite?
  return bls12_381.G1.hashToCurve(msg_octets, {DST: dst});
}

function _assertUint8Array(value, name) {
  if(!(value instanceof Uint8Array)) {
    throw new TypeError(`"${name}" must be a Uint8Array.`);
  }
}
