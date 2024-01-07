/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {calculate_B} from './util.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

export function ProofInit({
  PK, signature_result, generators, random_scalars,
  header = new Uint8Array(),
  messages = [], undisclosed_indexes = [],
  api_id = '', ciphersuite
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
  const Abar = A.multiply(r1.multiply(r2));
  const Bbar = D.multiply(r1).subtract(Abar.multiply(e));
  const T1 = Abar.multiply(e_).add(D.multiply(r1_));
  let T2 = D.multiply(r3_);
  for(let i = 0; i < m_j.length; ++i) {
    T2 = T2.add(H[i].multiply(m_j[i]));
  }
  return [Abar, Bbar, D, T1, T2, domain];
}
