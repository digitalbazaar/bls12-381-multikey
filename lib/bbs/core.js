/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  calculate_B, calculate_random_scalars, concatBytes,
  hash_to_scalar,
  mocked_calculate_random_scalars,
  octets_to_proof, octets_to_pubkey, octets_to_signature,
  serialize, signature_to_octets,
  TEXT_ENCODER
} from './util.js';
import {
  ProofChallengeCalculate, ProofFinalize, ProofInit, ProofVerifyInit
} from './proof.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

export async function CoreProofGen({
  PK, signature, generators,
  header = new Uint8Array(), ph = new Uint8Array(),
  messages = [], disclosed_indexes = [],
  api_id = new Uint8Array(), ciphersuite, mocked_random_scalars_options
} = {}) {
  /* Deserialization:

  1.  signature_result = octets_to_signature(signature)
  2.  if signature_result is INVALID, return INVALID
  3.  (A, e) = signature_result
  4.  L = length(messages)
  5.  R = length(disclosed_indexes)
  6.  if R > L, return INVALID
  7.  U = L - R
  8.  for i in disclosed_indexes, if i < 0 or i > L - 1, return INVALID
  9.  undisclosed_indexes = (0, 1, ..., L - 1) \ disclosed_indexes
  10. (i1, ..., iR) = disclosed_indexes
  11. (j1, ..., jU) = undisclosed_indexes
  12. disclosed_messages = (messages[i1], ..., messages[iR])
  13. undisclosed_messages = (messages[j1], ..., messages[jU])

  */
  const signature_result = octets_to_signature(
    {signature_octets: signature, ciphersuite});
  const L = messages.length;
  const R = disclosed_indexes.length;
  if(R > L) {
    throw new Error(
      `"disclosed_indexes.length" (${disclosed_indexes.length}) must be ` +
      `less than or equal to "messages.length" (${messages.length}).`);
  }
  const U = L - R;
  if(disclosed_indexes.some(i => isNaN(i) || i < 0 || i >= L)) {
    throw new Error(
      `Every index in "disclosed_indexes" (${disclosed_indexes}) ` +
      `must be a number >= 0 and <= ${L}.`);
  }
  const undisclosed_indexes = [];
  const disclosed_messages = [];
  const undisclosed_messages = [];
  const disclosed_indexes_set = new Set(disclosed_indexes);
  // always generate disclosed messages in the same order as messages
  for(const [i, e] of messages.entries()) {
    if(disclosed_indexes_set.has(i)) {
      disclosed_messages.push(e);
    } else {
      undisclosed_indexes.push(i);
      undisclosed_messages.push(e);
    }
  }

  /* Algorithm:

  1. random_scalars = calculate_random_scalars(5+U)
  2. init_res = ProofInit(PK,
                          signature_result,
                          generators,
                          random_scalars,
                          header,
                          messages,
                          undisclosed_indexes,
                          api_id)
  3. if init_res is INVALID, return INVALID
  4. challenge = ProofChallengeCalculate(init_res, disclosed_indexes,
                                         disclosed_messages, ph)
  5. if challenge is INVALID, return INVALID
  6. proof = ProofFinalize(init_res, challenge, e, random_scalars,
                           undisclosed_messages)
  7. return proof

  */
  const random_scalars = mocked_random_scalars_options === undefined ?
    await calculate_random_scalars({count: 5 + U, ciphersuite}) :
    mocked_calculate_random_scalars({
      count: 5 + U, ...mocked_random_scalars_options, ciphersuite
    });
  const init_res = ProofInit({
    PK, signature_result, generators, random_scalars, header,
    messages, undisclosed_indexes, api_id, ciphersuite
  });
  const challenge = ProofChallengeCalculate({
    init_res, disclosed_indexes, disclosed_messages, ph, api_id, ciphersuite
  });
  const [, e] = signature_result;
  const proof = ProofFinalize({
    init_res, challenge, e_value: e, random_scalars, undisclosed_messages,
    ciphersuite
  });
  return proof;
}

export function CoreProofVerify({
  PK, proof, generators,
  header = new Uint8Array(), ph = new Uint8Array(),
  disclosed_messages = [], disclosed_indexes = [],
  api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Deserialization:

  1. proof_result = octets_to_proof(proof)
  2. if proof_result is INVALID, return INVALID
  3. (Abar, Bbar, D, e^, r1^, r3^, commitments, cp) = proof_result
  4. W = octets_to_pubkey(PK)
  5. if W is INVALID, return INVALID

  */
  const proof_result = octets_to_proof({proof_octets: proof, ciphersuite});
  const [Abar, Bbar] = proof_result;
  const cp = proof_result.at(-1);
  const W = octets_to_pubkey({PK, ciphersuite});

  /* Algorithm:

  1. init_res = ProofVerifyInit(PK, proof_result, generators, header,
                                messages, disclosed_indexes, api_id)
  2. if init_res is INVALID, return INVALID
  3. challenge = ProofChallengeCalculate(init_res, disclosed_indexes,
                                         messages, ph, api_id)
  4. if challenge is INVALID, return INVALID
  5. if cp != challenge, return INVALID
  6. if e(Abar, W) * e(Bbar, -BP2) != Identity_GT, return INVALID
  7. return VALID

  */
  const init_res = ProofVerifyInit({
    PK, proof: proof_result, generators, header,
    disclosed_messages, disclosed_indexes,
    api_id, ciphersuite
  });
  const challenge = ProofChallengeCalculate({
    init_res, disclosed_indexes, disclosed_messages, ph, api_id, ciphersuite
  });
  if(cp !== challenge) {
    // proof challenge does not match
    return false;
  }
  // performs step 6 more efficiently;
  // note that BP2 will be negated internally to -BP2 to perform the comparison
  // by multiplying the pairings and checking against Identity_GT as above
  const {BP2} = ciphersuite;
  const pair1 = [Abar, W];
  const pair2 = [Bbar, BP2];
  return ciphersuite.eCompare({pair1, pair2});
}

export function CoreSign({
  SK, PK, generators, header = new Uint8Array(), messages = [],
  api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Definitions:

  1. signature_dst, an octet string representing the domain separation
                    tag: api_id || "H2S_" where "H2S_" is an ASCII string
                    comprised of 4 bytes.
  */
  const signature_dst = concatBytes(api_id, TEXT_ENCODER.encode('H2S_'));

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
  // calculate `B` and `domain` at once
  const {B, domain} = calculate_B({
    PK, generators, header, messages, api_id, ciphersuite
  });
  const e = hash_to_scalar({
    msg_octets: serialize({
      input_array: [SK, domain, ...messages], ciphersuite
    }),
    dst: signature_dst,
    ciphersuite
  });
  // 4. A = B * (1 / (SK + e))
  // multiply `B` by the inverse of `SK + e` within the field over `r`
  const {Fr} = ciphersuite;
  const A = B.multiply(Fr.inv(Fr.add(SK, e)));
  // if A == Identity_G1 throw invalid signature error
  if(ciphersuite.E1.eql(A, ciphersuite.E1.ONE)) {
    throw new Error('Invalid signature.');
  }
  return signature_to_octets({signature: [A, e], ciphersuite});
}

export function CoreVerify({
  PK, signature, generators, header = new Uint8Array(), messages = [],
  api_id = new Uint8Array(), ciphersuite
} = {}) {
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
  // `signature_result`
  const [A, e] = octets_to_signature(
    {signature_octets: signature, ciphersuite});
  const W = octets_to_pubkey({PK, ciphersuite});
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
  const {B} = calculate_B({
    PK, generators, header, messages, api_id, ciphersuite
  });
  // performs step 3 more efficiently;
  // note that BP2 will be negated internally to -BP2 to perform the comparison
  // by multiplying the pairings and checking against Identity_GT as above
  const {BP2} = ciphersuite;
  const pair1 = [A, W.add(BP2.multiply(e))];
  const pair2 = [B, BP2];
  return ciphersuite.eCompare({pair1, pair2});
}
