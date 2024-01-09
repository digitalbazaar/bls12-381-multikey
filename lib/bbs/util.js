/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  concatBytes, bytesToNumberBE as os2ip
} from '@noble/curves/abstract/utils';
import {bls12_381} from '@noble/curves/bls12-381';
import {mod} from '@noble/curves/abstract/modular';
import {webcrypto} from '../crypto.js';

// re-export helpful utilities
export {concatBytes, os2ip};

export const TEXT_ENCODER = new TextEncoder();

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

export function calculate_B({
  PK, generators, header, messages, api_id, ciphersuite
} = {}) {
  // B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
  const {P1} = ciphersuite;
  const {Q_1, H} = generators;
  const domain = calculate_domain({
    PK, generators, header, api_id, ciphersuite
  });
  let B = P1.add(Q_1.multiply(domain));
  let i = 0;
  for(const message of messages) {
    B = B.add(H[i++].multiply(message));
  }
  return {B, domain};
}

export function calculate_domain({
  PK, generators, header = new Uint8Array(),
  api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Definitions:

  1. domain_dst, an octet string representing the domain separation tag:
                 api_id || "H2S_" where "H2S_" is an ASCII string
                 comprised of 4 bytes.
  */
  const domain_dst = concatBytes(api_id, TEXT_ENCODER.encode('H2S_'));

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
    dom_octs = concatBytes(dom_octs, api_id);
  }
  const dom_input = concatBytes(PK, dom_octs, i2osp(header.length, 8), header);
  return hash_to_scalar({msg_octets: dom_input, dst: domain_dst, ciphersuite});
}

export async function calculate_random_scalars({count, ciphersuite} = {}) {
  if(!(Number.isSafeInteger(count) && count >= 0)) {
    throw new Error('"count" must be a non-negative safe integer.');
  }
  /* Algorithm:

  1. for i in (1, 2, ..., count):
  2.     r_i = OS2IP(get_random(expand_len)) mod r
  3. return (r_1, r_2, ..., r_count)

  */
  // generate random scalars in parallel
  const promises = new Array(count);
  for(let i = 0; i < count; ++i) {
    promises[i] = _generateRandomScalar(ciphersuite);
  }
  return Promise.all(promises);
}

// FIXME: create generator cache for `api_id` + `count` combinations
export function create_generators({
  count, api_id = new Uint8Array(), ciphersuite, compress = false
} = {}) {
  if(!(Number.isSafeInteger(count) && count > 0)) {
    throw new Error('"count" must be a safe integer >= 1.');
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
  const seed_dst = concatBytes(
    api_id, TEXT_ENCODER.encode('SIG_GENERATOR_SEED_'));
  const generator_dst = concatBytes(
    api_id, TEXT_ENCODER.encode('SIG_GENERATOR_DST_'));
  const generator_seed = concatBytes(
    api_id, TEXT_ENCODER.encode('MESSAGE_GENERATOR_SEED'));

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
    let g = ciphersuite.hash_to_curve_g1(v, generator_dst);
    if(compress) {
      g = ciphersuite.octets_to_point_E1(ciphersuite.point_to_octets_E1(g));
    }
    generators[i - 1] = g;
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
 * @returns {bigint} - The scalar (hashed result).
 */
export function hash_to_scalar({msg_octets, dst, ciphersuite} = {}) {
  /* Algorithm:

  1. uniform_bytes = expand_message(msg_octets, dst, expand_len)
  2. return OS2IP(uniform_bytes) mod r

  */
  // Note: `expand_len` is preset by ciphersuite.
  const uniform_bytes = ciphersuite.expand_message(msg_octets, dst);
  return mod(os2ip(uniform_bytes), ciphersuite.r);
}

export function i2osp(value, length) {
  value = BigInt(value);
  if(!(length > 0 && Number.isSafeInteger(length))) {
    throw new Error(`"length" (${length}) must be a positive safe integer.`);
  }
  if(value < 0 || value >= 1n << (8n * BigInt(length))) {
    throw new Error(`"value" (${value}) not in byte range (0, ${length}).`);
  }
  const octets = new Uint8Array(length);
  for(let i = length - 1; i >= 0; --i) {
    octets[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return octets;
}

export function messages_to_scalars({
  messages, api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Definitions:

  1. map_dst, an octet string representing the domain separation tag:
              api_id || "MAP_MSG_TO_SCALAR_AS_HASH_" where
              "MAP_MSG_TO_SCALAR_AS_HASH_" is an ASCII string comprised of
              26 bytes.

  ABORT if:

  1. length(messages) > 2^64 - 1

  */
  const map_dst = concatBytes(
    api_id, TEXT_ENCODER.encode('MAP_MSG_TO_SCALAR_AS_HASH_'));
  if(!(Number.isSafeInteger(messages.length))) {
    throw new Error('"messages.length" must be a safe integer.');
  }

  /* Algorithm:

  1. L =  length(messages)
  2. for i in (1, ..., L):
  3.     msg_scalar_i = hash_to_scalar(messages[i], map_dst)
  4. return (msg_scalar_1, ..., msg_scalar_L)

  */
  return messages.map(
    msg_octets => hash_to_scalar({msg_octets, dst: map_dst, ciphersuite}));
}

export function mocked_calculate_random_scalars({
  count, seed, dst, ciphersuite
} = {}) {
  if(!(Number.isSafeInteger(count) && count >= 0)) {
    throw new Error('"count" must be a non-negative safe integer.');
  }

  /* Algorithm:

  1. out_len = expand_len * count
  2. v = expand_message(SEED, dst, out_len)
  3. if v is INVALID, return INVALID
  4. for i in (1, ..., count):
  5.     start_idx = (i-1) * expand_len
  6.     end_idx = i * expand_len - 1
  7.     r_i = OS2IP(v[start_idx..end_idx]) mod r
  8. return (r_1, ...., r_count)
  */
  const {expand_len, r} = ciphersuite;
  const out_len = expand_len * count;
  const v = ciphersuite.expand_message(seed, dst, out_len);
  const scalars = new Array(count);
  // simplified to use 0-based indexing instead of 1-based from above
  let start_idx = 0;
  for(let i = 0; i < count; ++i) {
    const next_idx = start_idx + expand_len;
    const octets = v.subarray(start_idx, next_idx);
    start_idx = next_idx;
    scalars[i] = mod(os2ip(octets), r);
  }
  return scalars;
}

export function octets_to_proof({proof_octets, ciphersuite} = {}) {
  /* Algorithm (3 parts...):

  1.  proof_len_floor = 3 * octet_point_length + 4 * octet_scalar_length
  2.  if length(proof_octets) < proof_len_floor, return INVALID

  */
  const {r, octet_point_length, octet_scalar_length} = ciphersuite;
  const proof_len_floor = 3 * octet_point_length + 4 * octet_scalar_length;
  if(proof_octets.length < proof_len_floor) {
    throw new Error(
      `"proof_octets.length" (${proof_octets.length}) ` +
      `must be at least ${proof_len_floor}.`);
  }
  // check total proof size is valid here instead of below
  const remainder = proof_octets.length - proof_len_floor;
  if(remainder % octet_scalar_length !== 0) {
    throw new Error('Invalid proof size.');
  }

  /* Algorithm continued:

  // Points (i.e., (Abar, Bbar, D) in ProofGen) de-serialization.
  3.  index = 0
  // FIX to spec: Should say "for i in (0, 2)" to get 3 points, not 2.
  4.  for i in (0, 1):
  5.      end_index = index + octet_point_length - 1
  6.      A_i = octets_to_point_E1(proof_octets[index..end_index])
  7.      if A_i is INVALID or Identity_G1, return INVALID
  8.      if subgroup_check_G1(A_i) returns INVALID, return INVALID
  9.      index += octet_point_length

  */
  let index = 0;
  const A = new Array(3);
  for(let i = 0; i <= 2; ++i) {
    A[i] = ciphersuite.octets_to_point_E1(
      proof_octets.subarray(index, index + octet_point_length));
    if(ciphersuite.E1.eql(A, ciphersuite.E1.ONE)) {
      throw new Error('Invalid point in proof.');
    }
    index += octet_point_length;
  }

  /* Algorithm continued:

  // Scalars (i.e., (e^, r1^, r3^, m^_j1, ..., m^_jU, c) in
  // ProofGen) de-serialization.
  10. j = 0
  11. while index < length(proof_octets):
  12.     end_index = index + octet_scalar_length - 1
  13.     s_j = OS2IP(proof_octets[index..end_index])
  14.     if s_j = 0 or if s_j >= r, return INVALID
  15.     index += octet_scalar_length
  16.     j += 1
  17. if index != length(proof_octets), return INVALID
  18. msg_commitments = ()
  19. if j > 4, set msg_commitments = (s_3, ..., s_(j-2))
  20. return (A_0, A_1, A_2, s_0, s_1, s_2, msg_commitments, s_(j-1))

  */
  // no need to track `s_j` outside of loop, just get all scalars
  const scalars = [];
  while(index < proof_octets.length) {
    const s_j = os2ip(
      proof_octets.subarray(index, index + octet_scalar_length));
    if(s_j === 0 || s_j >= r) {
      throw new Error('Invalid scalar in proof.');
    }
    scalars.push(s_j);
    index += octet_scalar_length;
  }
  // simplified steps 18-20
  return [...A, ...scalars];
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
  // if W == Identity_E2 throw invalid public key error
  if(ciphersuite.E2.eql(W, ciphersuite.E2.ONE)) {
    throw new Error('Invalid public key.');
  }
  return W;
}

export function octets_to_signature({signature_octets, ciphersuite} = {}) {
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

  const A_octets = signature_octets.subarray(0, octet_point_length);
  // conversion handles checking that point is on the curve
  const A = ciphersuite.octets_to_point_E1(A_octets);
  // if A == Identity_G1 throw invalid signature error
  if(ciphersuite.E1.eql(A, ciphersuite.E1.ONE)) {
    throw new Error('Invalid signature.');
  }
  const e = os2ip(signature_octets.subarray(octet_point_length));
  if(e < 0n || e >= ciphersuite.Fr.ORDER) {
    throw new Error(
      `signature "e" value must be >= 0 and < (${ciphersuite.Fr.ORDER}).`);
  }
  return [A, e];
}

export function proof_to_octets({proof, ciphersuite} = {}) {
  // signature has `(A, e)` where A is a point in G1 and `e` is a non-zero
  // scalar mod `r`
  /* Algorithm:

  1. (Abar, Bbar, D, e^, r1^, r3^, (m^_1, ..., m^_U), c) = proof
  2. return serialize((Abar, Bbar, D, e^, r1^, r3^, m^_1, ..., m^_U, c))

  */
  return serialize({input_array: proof, ciphersuite});
}

export function serialize({input_array, ciphersuite} = {}) {
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
      octets = i2osp(el, 8);
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

async function gen_random(expand_len) {
  return webcrypto.getRandomValues(new Uint8Array(expand_len));
}

async function _generateRandomScalar(ciphersuite) {
  const random = await gen_random(ciphersuite.expand_len);
  return mod(os2ip(random), ciphersuite.r);
}
