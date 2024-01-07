/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  calculate_domain, hash_to_scalar,
  serialize, signature_to_octets,
  TEXT_ENCODER
} from './util.js';
import {bls12_381} from '@noble/curves/bls12-381.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

/*
CoreSign
CoreVerify
CoreProofGen
CoreProofVerify
*/

export function CoreSign({
  SK, PK, generators, header = new Uint8Array(), messages = [],
  api_id = '', ciphersuite
} = {}) {
  // FIXME: get assert from `util` or move to assert.js?
  // _assertInstance(Uint8Array, SK, 'SK');
  // _assertInstance(Uint8Array, PK, 'PK');
  // _assertArray(generators, 'generators');
  // _assertInstance(Uint8Array, header, 'header');
  // _assertArray(messages, 'messages');
  // _assertType('string', api_id, 'api_id');

  /* Definitions:

  1. signature_dst, an octet string representing the domain separation
                    tag: api_id || "H2S_" where "H2S_" is an ASCII string
                    comprised of 4 bytes.
  */
  const signature_dst = TEXT_ENCODER.encode(api_id + 'H2S_');

  /* Deserialization:

  1. L = length(messages)
  2. if length(generators) != L + 1, return INVALID
  3. (msg_1, ..., msg_L) = messages
  4. (Q_1, H_1, ..., H_L) = generators

  */
  const L = messages.length;
  if(generators.length !== (L + 1)) {
    throw new Error(
      `"generators.length" (${generators.length}) must equal ` +
      `"messages.length" (${messages.length}) + 1.`);
  }

  /* Algorithm:

  1. domain = calculate_domain(PK, generators, header, api_id)
  2. e = hash_to_scalar(serialize((SK, domain, msg_1, ..., msg_L)),
                        signature_dst)
  3. B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
  4. A = B * (1 / (SK + e))
  5. return signature_to_octets((A, e))

  */
  const {P1} = ciphersuite;
  const {Q_1, H} = generators;
  const domain = calculate_domain({
    PK, generators, header, api_id, ciphersuite
  });
  const e = hash_to_scalar({
    msg_octets: serialize({
      input_array: [SK, domain, ...messages], ciphersuite
    }),
    dst: signature_dst
  });
  // 3. B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
  let B = P1.add(Q_1.multiply(domain));
  let i = 0;
  for(const message of messages) {
    B = B.add(H[i++].multiply(message));
  }
  // 4. A = B * (1 / (SK + e))
  // multiply `B` by the inverse of `SK + e` within the BLS field
  const {fields: {Fr}} = bls12_381;
  const A = B.multiply(Fr.inv(Fr.add(Fr.create(SK), Fr.create(e))));
  // FIXME: just use `serialize()`?
  return signature_to_octets([A, e]);
}
