/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  bytesToNumberBE as os2ip, concatBytes
} from '@noble/curves/abstract/utils.js';
import {bls12_381} from '@noble/curves/bls12-381.js';
// FIXME: use in higher-level functions
// const ciphersuite = getCiphersuite(ciphersuite_id);
//import {getCiphersuite} from './ciphersuites.js';
import {mod} from '@noble/curves/abstract/modular.js';

// re-export helpful utilities
export {concatBytes, os2ip};

export const TEXT_ENCODER = new TextEncoder();

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

/*
FIXME: implement other utils from RFC as needed:

signature_to_octets, octets_to_signature, proof_to_octets,
  octets_to_proof and octets_to_pubkey
e (pairing operation).
*/

export function calculate_domain({
  PK, generators, header = new Uint8Array(), api_id = '', ciphersuite
} = {}) {
  _assertInstance(Uint8Array, PK, 'PK');
  _assertArray(generators, 'generators');
  _assertInstance(Uint8Array, header, 'header');
  _assertType('string', api_id, 'api_id');

  /* Definitions:

  1. domain_dst, an octet string representing the domain separation tag:
                 api_id || "H2S_" where "H2S_" is an ASCII string
                 comprised of 4 bytes.
  */
  const domain_dst = TEXT_ENCODER.encode(api_id + 'H2S_');

  /* Algorithm:

  1. dom_array = (L, Q_1, H_1, ..., H_L)
  2. dom_octs = serialize(dom_array) || api_id
  3. dom_input = PK || dom_octs || I2OSP(length(header), 8) || header
  4. return hash_to_scalar(dom_input, domain_dst)

  */
  const {Q_1, H} = generators;
  const L = H.length;
  const dom_array = [L, Q_1, ...H];
  let dom_octs = serialize({input_array: dom_array, ciphersuite});
  if(api_id.length > 0) {
    dom_octs = concatBytes(dom_octs, TEXT_ENCODER.encode(api_id));
  }
  const dom_input = concatBytes(PK, dom_octs, i2osp(header.length, 8), header);
  return hash_to_scalar({msg_octets: dom_input, dst: domain_dst, ciphersuite});
}

export function create_generators({count, api_id = '', ciphersuite} = {}) {
  _assertType('number', count, 'count');
  _assertType('string', api_id, 'api_id');

  if(!Number.isSafeInteger(count)) {
    throw new Error('"count" must be a safe integer.');
  }

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
  const seed_dst = TEXT_ENCODER.encode(api_id + 'SIG_GENERATOR_SEED_');
  const generator_dst = TEXT_ENCODER.encode(api_id + 'SIG_GENERATOR_DST_');
  const generator_seed = TEXT_ENCODER.encode(api_id + 'MESSAGE_GENERATOR_SEED');

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

  // the first point is referred to as `Q_1`
  generators.Q_1 = generators[0];
  // the other points are referred to as `H` or `H_Points`
  generators.H = generators.slice(1);

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
 * @param {object} options.ciphersuite - The ciphersuite to use.
 *
 * @returns {Uint8Array} - The scalar (hashed result).
 */
export function hash_to_scalar({msg_octets, dst, ciphersuite} = {}) {
  _assertInstance(Uint8Array, msg_octets, 'msg_octets');
  _assertInstance(Uint8Array, dst, 'dst');

  /* Algorithm:

  1. uniform_bytes = expand_message(msg_octets, dst, expand_len)
  2. return OS2IP(uniform_bytes) mod r

  */
  // Note: `expand_len` is preset by ciphersuite.
  const uniform_bytes = ciphersuite.expand_message(msg_octets, dst);
  return mod(os2ip(uniform_bytes), ciphersuite.r);
}

export function octets_to_pubkey({PK, ciphersuite} = {}) {
  /* Algorithm:

  1. W = octets_to_point_E2(PK)
  2. if W is INVALID, return INVALID
  3. if subgroup_check_G2(W) is INVALID, return INVALID
  4. if W == Identity_G2, return INVALID
  5. return W

  */
  // conversion handles checking that point is on the curve
  const W = ciphersuite.octets_to_point_E2(PK);
  return W;
}

export function octets_to_signature({signature_octets, ciphersuite} = {}) {
  _assertInstance(Uint8Array, signature_octets, 'signature_octets');

  /* Algorithm:

  1.  expected_len = octet_point_length + octet_scalar_length
  2.  if length(signature_octets) != expected_len, return INVALID
  3.  A_octets = signature_octets[0..(octet_point_length - 1)]
  4.  A = octets_to_point_E1(A_octets)
  5.  if A is INVALID, return INVALID
  6.  if A == Identity_G1, return INVALID
  7.  if subgroup_check_G1(A) returns INVALID, return INVALID
  8.  index = octet_point_length
  9.  end_index = index + octet_scalar_length - 1
  10. e = OS2IP(signature_octets[index..end_index])
  11. if e = 0 or e >= r, return INVALID
  12. return (A, e)

  */
  const {octet_point_length, octet_scalar_length} = ciphersuite;
  const expected_len = octet_point_length + octet_scalar_length;
  if(signature_octets.length !== expected_len) {
    throw new Error(
      `"signature_octets.length" (${signature_octets.length}) ` +
      `must be ${expected_len}.`);
  }

  const A_octets = signature_octets.slice(0, octet_point_length);
  // conversion handles checking that point is on the curve
  const A = ciphersuite.octets_to_point_E1(A_octets);
  const e = os2ip(signature_octets.slice(octet_point_length));
  if(e < 0n || e >= ciphersuite.Fr.ORDER) {
    throw new Error(
      `signature "e" value must be >= 0 and < (${ciphersuite.Fr.ORDER}).`);
  }
  return [A, e];
}

export function serialize({input_array, ciphersuite} = {}) {
  _assertArray(input_array, 'input_array');

  const {G1, G2} = bls12_381;

  /* Algorithm:

  1.  let octets_result be an empty octet string.
  2.  for el in input_array:
  3.      if el is a point of G1: el_octs = point_to_octets_E1(el)
  4.      else if el is a point of G2: el_octs = point_to_octets_E2(el)
  5.      else if el is a scalar: el_octs = I2OSP(el, octet_scalar_length)
  6.      else if el is an integer between 0 and 2^64 - 1:
  7.          el_octs = I2OSP(el, 8)
  8.      else: return INVALID
  9.      octets_result = octets_result || el_octs
  10. return octets_result

  */
  let i = 0;
  const octets_result = new Array(input_array.length);
  for(const el of input_array) {
    let octets;
    if(el instanceof G1.ProjectivePoint) {
      octets = ciphersuite.point_to_octets_E1(el);
    } else if(el instanceof G2.ProjectivePoint) {
      octets = ciphersuite.point_to_octets_E1(el);
    } else if(typeof el === 'bigint') {
      // scalar
      octets = i2osp(el, ciphersuite.octet_scalar_length);
    } else if(typeof el === 'number') {
      // regular integer
      // FIXME: ensure that integers are never BigInts throughout
      octets = i2osp(el, 8);
    } else if(el instanceof Uint8Array) {
      // FIXME: if el instanceof Uint8Array just set it?
      console.trace('element is Uint8Array', el);
      process.exit(1);
      octets = el;
    } else {
      throw new Error(
        `Unknown element "${el}" detected during "serialize()".`);
    }

    octets_result[i++] = octets;
  }

  // return joined octets
  return concatBytes(...octets_result);
}

export function signature_to_octets({signature, ciphersuite} = {}) {
  // signature has `(A, e)` where A is a point in G1 and `e` is a non-zero
  // scalar mod `r`
  /* Algorithm:

  1. (A, e) = signature
  2. return serialize((A, e))

  */
  return serialize({input_array: signature, ciphersuite});
}

function i2osp(value, length) {
  value = BigInt(value);
  if(length > 8) {
    throw new Error(`"length" (${length}) must be <= 8.`);
  }
  if(value < 0 || value >= 1 << (8 * length)) {
    throw new Error(`"value" (${value}) not in byte range (0, ${length}).`);
  }
  const octets = new Uint8Array(length);
  for(let i = length - 1; i >= 0; --i) {
    octets[i] = value & 0xffn;
    value >>= 8n;
  }
  return octets;
}

function _assertArray(value, name) {
  if(!Array.isArray(value)) {
    throw new TypeError(`"${name}" must be an array.`);
  }
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
