/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  calculate_B, calculate_domain,
  concatBytes, hash_to_scalar, i2osp, proof_to_octets, serialize, TEXT_ENCODER
} from './util.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

export function ProofChallengeCalculate({
  init_res,
  disclosed_indexes = [], disclosed_messages = [], ph = new Uint8Array(),
  api_id = new Uint8Array(), ciphersuite
} = {}) {
  /*
  Definitions:

  1. challenge_dst, an octet string representing the domain separation
                    tag: api_id || "H2S_" where "H2S_" is an ASCII string
                    comprised of 4 bytes.
  */
  const challenge_dst = concatBytes(api_id, TEXT_ENCODER.encode('H2S_'));

  /* Deserialization:

  1. R = length(disclosed_indexes)
  2. (i1, ..., iR) = disclosed_indexes
  3. if length(disclosed_messages) != R, return INVALID
  3. (msg_i1, ..., msg_iR) = disclosed_messages
  4. (Abar, Bbar, D, T1, T2, domain) = init_res

  ABORT if:

  1. R > 2^64 - 1
  2. length(ph) > 2^64 - 1

  */
  const R = disclosed_indexes.length;
  const [Abar, Bbar, D, T1, T2, domain] = init_res;
  if(!Number.isSafeInteger(R)) {
    throw new Error(
      `"disclosed_indexes.length" (${R}) must be a safe integer.`);
  }
  if(!Number.isSafeInteger(ph.length)) {
    throw new Error(`"ph.length" (${ph.length}) must be a safe integer.`);
  }

  /* Algorithm:

  1. c_arr = (Abar, Bbar, D, T1, T2, R, i1, ..., iR,
              msg_i1, ..., msg_iR, domain)
  2. c_octs = serialize(c_arr) || I2OSP(length(ph), 8) || ph
  3. return hash_to_scalar(c_octs, challenge_dst)

  */
  const c_arr = [
    Abar, Bbar, D, T1, T2, R,
    ...disclosed_indexes, ...disclosed_messages,
    domain
  ];
  const c_octs = concatBytes(
    serialize({input_array: c_arr, ciphersuite}), i2osp(ph.length, 8), ph);
  return hash_to_scalar({msg_octets: c_octs, dst: challenge_dst, ciphersuite});
}

export function ProofFinalize({
  init_res, challenge, e_value,
  random_scalars, undisclosed_messages = [],
  ciphersuite
} = {}) {
  /* Deserialization:

  1. U = length(undisclosed_messages)
  2. if length(random_scalars) != U + 5, return INVALID
  3. (r1, r2, e~, r1~, r3~, m~_j1, ..., m~_jU) = random_scalars
  4. (undisclosed_1, ..., undisclosed_U) = undisclosed_messages
  5. (Abar, Bbar, D) = (init_res[0], init_res[1], init_res[2])

  */
  const U = undisclosed_messages.length;
  if(random_scalars.length !== (U + 5)) {
    throw new Error(
      `"random_scalars.length" (${random_scalars.length}) must equal ` +
      `"undisclosed_messages.length + 5" (${U + 5}).`);
  }
  // `e~` expressed as `e_` here, `m~_j1` as `m_[0]`, etc. ...
  const [r1, r2, e_, r1_, r3_, ...m_j] = random_scalars;
  const [Abar, Bbar, D] = init_res;

  /* Algorithm:

  1. r3 = r2^-1 (mod r)
  2. e^ = e~ + e_value * challenge
  3. r1^ = r1~ - r1 * challenge
  4. r3^ = r3~ - r3 * challenge
  5. for j in (1, ..., U): m^_j = m~_j + undisclosed_j * challenge (mod r)
  6. proof = (Abar, Bbar, D, e^, r1^, r3^, (m^_j1, ..., m^_jU), challenge)
  7. return proof_to_octets(proof)

  */
  // arithmetic here is with scalars only (not points) so perform in field `Fr`
  const {Fr} = ciphersuite;
  const r3 = Fr.inv(r2);
  // `^` expressed as `Hat`
  const eHat = Fr.add(e_, Fr.mul(e_value, challenge));
  const r1Hat = Fr.sub(r1_, Fr.mul(r1, challenge));
  const r3Hat = Fr.sub(r3_, Fr.mul(r3, challenge));
  // `mHat` constitutes the proof `commitments`
  const mHat = undisclosed_messages.map(
    (undisclosed, j) => Fr.add(m_j[j], Fr.mul(undisclosed, challenge)));
  const proof = [Abar, Bbar, D, eHat, r1Hat, r3Hat, ...mHat, challenge];
  return proof_to_octets({proof, ciphersuite});
}

export function ProofInit({
  PK, signature_result, generators, random_scalars,
  header = new Uint8Array(),
  messages = [], undisclosed_indexes = [],
  api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Deserialization:

  1.  (A, e) = signature_result
  2.  L = length(messages)
  3.  U = length(undisclosed_indexes)
  4.  (j1, ..., jU) = undisclosed_indexes
  5.  if length(random_scalars) != U + 5, return INVALID
  6.  (r1, r2, e~, r1~, r3~, m~_j1, ..., m~_jU) = random_scalars
  7.  (msg_1, ..., msg_L) = messages
  8.  if length(generators) != L + 1, return INVALID
  9.  (Q_1, MsgGenerators) = generators
  10. (H_1, ..., H_L) = MsgGenerators
  11. (H_j1, ..., H_jU) = (MsgGenerators[j1], ..., MsgGenerators[jU])

  */
  const [A, e] = signature_result;
  const {H} = generators;
  const U = undisclosed_indexes.length;
  if(random_scalars.length !== (U + 5)) {
    throw new Error(
      `"random_scalars.length" (${random_scalars.length}) must equal ` +
      `"undisclosed_indexes.length + 5" (${U + 5}).`);
  }

  /* Algorithm:

  1. domain = calculate_domain(PK, Q_1, (H_1, ..., H_L), header, api_id)
  2. B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
  3. D = B * r2
  4. Abar = A * (r1 * r2)
  5. Bbar = D * r1 - Abar * e
  6. T1 = Abar * e~ + D * r1~
  7. T2 = D * r3~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
  8. return (Abar, Bbar, D, T1, T2, domain)

  */
  // calculate `B` and `domain` at once
  const {B, domain} = calculate_B({
    PK, generators, header, messages, api_id, ciphersuite
  });
  // `e~` expressed as `e_` here, `m~_j1` as `m_[0]`, etc. ...
  const [r1, r2, e_, r1_, r3_, ...m_j] = random_scalars;
  const D = B.multiply(r2);
  const Abar = A.multiply(ciphersuite.Fr.mul(r1, r2));
  const Bbar = D.multiply(r1).subtract(Abar.multiply(e));
  const T1 = Abar.multiply(e_).add(D.multiply(r1_));
  let T2 = D.multiply(r3_);
  // for each undisclosed index, add matching generator * ordered random scalar
  for(const [i, j] of undisclosed_indexes.entries()) {
    T2 = T2.add(H[j].multiply(m_j[i]));
  }
  return [Abar, Bbar, D, T1, T2, domain];
}

export function ProofVerifyInit({
  PK, proof, generators, header = new Uint8Array(),
  disclosed_messages = [], disclosed_indexes = [],
  api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Deserialization:

  1.  (Abar, Bbar, D, e^, r1^, r3^, commitments, c) = proof
  2.  U = length(commitments)
  3.  R = length(disclosed_indexes)
  4.  L = R + U
  5.  (i1, ..., iR) = disclosed_indexes
  6.  for i in disclosed_indexes, if i < 0 or i > L - 1, return INVALID
  7.  (j1, ..., jU) = (0, 1, ..., L - 1) \ disclosed_indexes
  8.  if length(disclosed_messages) != R, return INVALID
  9.  (msg_i1, ..., msg_iR) = disclosed_messages
  10. (m^_j1, ...., m^_jU) = commitments
  11. if length(generators) != L + 1, return INVALID
  12. (Q_1, MsgGenerators) = generators
  13. (H_1, ..., H_L) = MsgGenerators
  14. (H_i1, ..., H_iR) = (MsgGenerators[i1], ..., MsgGenerators[iR])
  15. (H_j1, ..., H_jU) = (MsgGenerators[j1], ..., MsgGenerators[jU])

  */
  // `commitments` constitutes `mHat` and `c` is the challenge
  const [Abar, Bbar, D, eHat, r1Hat, r3Hat, ...commitments] = proof;
  const c = commitments.pop();
  const U = commitments.length;
  const R = disclosed_indexes.length;
  const L = R + U;
  if(disclosed_indexes.some(i => isNaN(i) || i < 0 || i > (L - 1))) {
    throw new Error(
      `Every index in "disclosed_indexes" must be a number >= 0 and ` +
      `<= ${L}.`);
  }
  if(generators.length !== (L + 1)) {
    throw new Error(
      `"generators.length" (${generators.length}) must equal the ` +
      `total number of commitments and disclosed indexes + 1 (${L + 1}).`);
  }
  // compute undisclosed indexes
  const {Q_1, H} = generators;
  const disclosed_indexes_set = new Set(disclosed_indexes);
  const undisclosed_indexes = [...H.keys()]
    .filter(i => !disclosed_indexes_set.has(i));

  /* Algorithm:

  1. domain = calculate_domain(PK, Q_1, (H_1, ..., H_L), header, api_id)
  2. T1 = Bbar * c + Abar * e^ + D * r1^
  3. Bv = P1 + Q_1 * domain + H_i1 * msg_i1 + ... + H_iR * msg_iR
  4. T2 = Bv * c + D * r3^ + H_j1 * m^_j1 + ... +  H_jU * m^_jU
  5. return (Abar, Bbar, D, T1, T2, domain)

  */
  const domain = calculate_domain({
    PK, generators, header, api_id, ciphersuite
  });
  const T1 = Bbar.multiply(c).add(Abar.multiply(eHat)).add(D.multiply(r1Hat));
  const {P1} = ciphersuite;
  let Bv = P1.add(Q_1.multiply(domain));
  // for each disclosed message, add matching generator * message
  for(const [i, msg_i] of disclosed_messages.entries()) {
    Bv = Bv.add(H[disclosed_indexes[i]].multiply(msg_i));
  }
  let T2 = Bv.multiply(c).add(D.multiply(r3Hat));
  // for each commitment (each for an undisclosed message),
  // add matching generator * commitment
  for(const [j, mHat_j] of commitments.entries()) {
    T2 = T2.add(H[undisclosed_indexes[j]].multiply(mHat_j));
  }
  return [Abar, Bbar, D, T1, T2, domain];
}
