/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  bytesToNumberBE as os2ip, concatBytes
} from '@noble/curves/abstract/utils.js';
import {getCiphersuite} from './ciphersuites.js';
import {mod} from '@noble/curves/abstract/modular.js';

const textEncoder = new TextEncoder();

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

/*
FIXME: implement other utils from RFC as needed:

calculate_domain
serialize, signature_to_octets, octets_to_signature, proof_to_octets,
  octets_to_proof and octets_to_pubkey
e (pairing operation).
*/

export function create_generators({count, api_id = '', ciphersuite_id} = {}) {
  _assertType('number', count, 'count');
  _assertType('string', api_id, 'api_id');

  if(!Number.isSafeInteger(count)) {
    throw new Error('"count" must be a safe integer.');
  }

  const ciphersuite = getCiphersuite(ciphersuite_id);

  /* Definitions:

    1. seed_dst, an octet string representing the domain separation tag:
                api_id || "SIG_GENERATOR_SEED_" where "SIG_GENERATOR_SEED_"
                is an ASCII string comprised of 19 bytes.
    2. generator_dst, an octet string representing the domain separation
                      tag: api_id || "SIG_GENERATOR_DST_", where
                      "SIG_GENERATOR_DST_" is an ASCII string comprised of
                      18 bytes.
    3. generator_seed, an octet string representing the domain separation
                      tag: api_id || "MESSAGE_GENERATOR_SEED", where
                      "MESSAGE_GENERATOR_SEED" is an ASCII string comprised
                      of 22 bytes.
  */
  const seed_dst = textEncoder.encode(api_id + 'SIG_GENERATOR_SEED_');
  const generator_dst = textEncoder.encode(api_id + 'SIG_GENERATOR_DST_');
  const generator_seed = textEncoder.encode(api_id + 'MESSAGE_GENERATOR_SEED');

  /* Algorithm:

  1. v = expand_message(generator_seed, seed_dst, expand_len)
  2. for i in (1, 2, ..., count):
  3.    v = expand_message(v || I2OSP(i, 8), seed_dst, expand_len)
  4.    generator_i = hash_to_curve_g1(v, generator_dst)
  5. return (generator_1, ..., generator_count)

  */
  const generators = new Array(count);
  let v = ciphersuite.expand_message(generator_seed, seed_dst);
  for(let i = 1; i <= count; ++i) {
    v = ciphersuite.expand_message(concatBytes(v, i2osp(i, 8)), seed_dst);
    generators[i - 1] = ciphersuite.hash_to_curve_g1(v, generator_dst);
  }
  return generators;
}

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
export function hash_to_scalar({msg_octets, dst, ciphersuite_id} = {}) {
  _assertInstance(Uint8Array, msg_octets, 'msg_octets');
  _assertInstance(Uint8Array, dst, 'dst');

  const ciphersuite = getCiphersuite(ciphersuite_id);

  /* Algorithm:

  1. uniform_bytes = expand_message(msg_octets, dst, expand_len)
  2. return OS2IP(uniform_bytes) mod r

  */
  // Note: `expand_len` is preset by ciphersuite.
  const uniform_bytes = ciphersuite.expand_message(msg_octets, dst);
  return mod(os2ip(uniform_bytes), ciphersuite.r);
}

function i2osp(value, length) {
  value = BigInt(value);
  if(length > 8) {
    throw new Error(`"length" (${length}) must be <= 8.`);
  }
  if(value < 0 || value >= 1 << (8 * length)) {
    throw new Error(`"value" (${value}) not in byte range (0, ${length}).`);
  }
  const bytes = new Uint8Array(length);
  for(let i = length - 1; i >= 0; --i) {
    bytes[i] = value & 0xffn;
    value >>= 8n;
  }
  return bytes;
}

function _assertInstance(type, value, name) {
  if(!(value instanceof type)) {
    throw new TypeError(`"${name}" must be a ${type.name}.`);
  }
}

function _assertType(type, value, name) {
  if(typeof value !== type) {
    throw new TypeError(`"${name}" must be a ${type}.`);
  }
}
