/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  calculate_domain, hash_to_scalar,
  octets_to_pubkey, octets_to_signature,
  serialize, signature_to_octets,
  TEXT_ENCODER
} from './util.js';

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
  const domain = calculate_domain({
    PK, generators, header, api_id, ciphersuite
  });
  const e = hash_to_scalar({
    msg_octets: serialize({
      input_array: [SK, domain, ...messages], ciphersuite
    }),
    dst: signature_dst
  });
  const B = _calculateB(
    {PK, generators, header, messages, api_id, ciphersuite});
  // 4. A = B * (1 / (SK + e))
  // multiply `B` by the inverse of `SK + e` within the field over `r`
  const {Fr} = ciphersuite;
  const A = B.multiply(Fr.inv(Fr.add(Fr.create(SK), Fr.create(e))));
  // FIXME: just use `serialize()`?
  return signature_to_octets([A, e]);
}

export function CoreVerify({
  PK, signature, generators, header = new Uint8Array(), messages = [],
  api_id = '', ciphersuite
} = {}) {
  // FIXME: get assert from `util` or move to assert.js?
  // _assertInstance(Uint8Array, PK, 'PK');
  // _assertInstance(Uint8Array, signature, 'signature');
  // _assertArray(generators, 'generators');
  // _assertInstance(Uint8Array, header, 'header');
  // _assertArray(messages, 'messages');
  // _assertType('string', api_id, 'api_id');

  /* Deserialization:

  1. signature_result = octets_to_signature(signature)
  2. if signature_result is INVALID, return INVALID
  3. (A, e) = signature_result
  4. W = octets_to_pubkey(PK)
  5. if W is INVALID, return INVALID
  6. L = length(messages)
  7. if length(generators) != L + 1, return INVALID
  8. (msg_1, ..., msg_L) = messages
  9. (Q_1, H_1, ..., H_L) = generators

  */
  // signature_result
  const [A, e] = octets_to_signature(
    {signature_octets: signature, ciphersuite});
  const W = octets_to_pubkey(PK);
  const L = messages.length;
  if(generators.length !== (L + 1)) {
    throw new Error(
      `"generators.length" (${generators.length}) must equal ` +
      `"messages.length" (${messages.length}) + 1.`);
  }

  /* Algorithm:

  1. domain = calculate_domain(PK, generators, header, api_id)
  2. B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
  3. if e(A, W + BP2 * e) * e(B, -BP2) != Identity_GT, return INVALID
  4. return VALID

  */
  const B = _calculateB(
    {PK, generators, header, messages, api_id, ciphersuite});
  // performs step 3 more efficiently by doing
  // e(A, W + BP2 * e) == e(B, BP2)
  // note that BP2 will be negated internally to -BP2 to perform the comparison
  // by multiplying the pairings and checking against Identity_GT as above
  const {BP1, BP2} = ciphersuite;
  const pair1 = [A, W.add(BP1.multiply(e))];
  const pair2 = [B, BP2];
  return ciphersuite.eCompare({pair1, pair2});
}

function _calculateB({PK, generators, header, messages, api_id, ciphersuite}) {
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
  return B;
}
