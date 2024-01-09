/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {assertArray, assertInstance, assertType} from './assert.js';
import {CoreProofGen, CoreProofVerify, CoreSign, CoreVerify} from './core.js';
import {
  create_generators,
  messages_to_scalars,
  TEXT_ENCODER
} from './util.js';
import {getCiphersuite} from './ciphersuites.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

export async function ProofGen({
  PK, signature,
  header = new Uint8Array(),
  ph = new Uint8Array(),
  messages = [], disclosed_indexes = [],
  ciphersuite,
  // for test suite only
  mocked_random_scalars_options
} = {}) {
  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, signature, 'signature');
  assertInstance(Uint8Array, header, 'header');
  assertInstance(Uint8Array, ph, 'ph');
  assertArray(messages, 'messages');
  assertArray(disclosed_indexes, 'disclosed_indexes');
  ciphersuite = getCiphersuite(ciphersuite);

  const api_id = _createApiId(ciphersuite.ciphersuite_id);

  /* Algorithm:

  1. message_scalars = messages_to_scalars(messages, api_id)
  2. generators = create_generators(length(messages)+1, api_id)
  3. proof = CoreProofGen(PK, signature, generators, header, ph,
                          message_scalars, disclosed_indexes, api_id)
  4. if proof is INVALID, return INVALID
  5. return proof

  */
  const message_scalars = messages_to_scalars({messages, api_id, ciphersuite});
  const generators = create_generators({
    count: messages.length + 1, api_id, ciphersuite
  });
  const proof = await CoreProofGen({
    PK, signature, generators, header, ph,
    messages: message_scalars, disclosed_indexes, api_id, ciphersuite,
    // for test suite only
    mocked_random_scalars_options
  });
  return proof;
}

export async function ProofVerify({
  PK, proof, header, ph, disclosed_messages, disclosed_indexes, ciphersuite
} = {}) {
  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, proof, 'proof');
  assertInstance(Uint8Array, header, 'header');
  assertInstance(Uint8Array, ph, 'ph');
  assertArray(disclosed_messages, 'disclosed_messages');
  assertArray(disclosed_indexes, 'disclosed_indexes');
  if(disclosed_messages.length !== disclosed_indexes.length) {
    throw new Error(
      `"disclosed_messages.length" (${disclosed_messages.length}) must ` +
      `equal "disclosed_indexes.length" (${disclosed_indexes.length}).`);
  }
  ciphersuite = getCiphersuite(ciphersuite);

  const api_id = _createApiId(ciphersuite.ciphersuite_id);

  /* Deserialization:

  1. proof_len_floor = 2 * octet_point_length + 3 * octet_scalar_length
  2. if length(proof) < proof_len_floor, return INVALID
  3. U = floor((length(proof) - proof_len_floor) / octet_scalar_length)
  4. R = length(disclosed_indexes)

  */
  // note: `proof_len_floor` is checked in `CoreProofVerify`
  const {octet_point_length, octet_scalar_length} = ciphersuite;
  // FIX to spec: Should be 3 * point length and 4 * octet length.
  const proof_len_floor = 3 * octet_point_length + 4 * octet_scalar_length;
  if(proof.length < proof_len_floor) {
    throw new Error(
      `"proof.length" (${proof.length}) ` +
      `must be at least ${proof_len_floor}.`);
  }
  // check total proof size is valid
  const remainder = proof.length - proof_len_floor;
  if(remainder % octet_scalar_length !== 0) {
    throw new Error('Invalid proof size.');
  }
  const U = remainder / octet_scalar_length;
  const R = disclosed_indexes.length;

  /* Algorithm:

  1. message_scalars = messages_to_scalars(disclosed_messages, api_id)
  2. generators = create_generators(U + R + 1, api_id)
  3. result = CoreProofVerify(PK, proof, generators, header, ph,
                              message_scalars, disclosed_indexes, api_id)
  4. return result

  */
  const message_scalars = messages_to_scalars({
    messages: disclosed_messages, api_id, ciphersuite
  });
  const generators = create_generators({count: U + R + 1, api_id, ciphersuite});
  const result = CoreProofVerify({
    PK, proof, generators, header, ph,
    disclosed_messages: message_scalars, disclosed_indexes,
    api_id, ciphersuite
  });
  return result;
}

export async function Sign({
  SK, PK, header = new Uint8Array(), messages = [], ciphersuite
} = {}) {
  assertType('bigint', SK, 'SK');
  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, header, 'header');
  assertArray(messages, 'messages');
  ciphersuite = getCiphersuite(ciphersuite);

  const api_id = _createApiId(ciphersuite.ciphersuite_id);

  /* Algorithm:

  1. message_scalars = messages_to_scalars(messages, api_id)
  2. generators = create_generators(length(messages)+1, api_id)
  3. signature = CoreSign(SK, PK, header, message_scalars, generators, api_id)
  4. if signature is INVALID, return INVALID
  5. return signature

  */
  const message_scalars = messages_to_scalars({messages, api_id, ciphersuite});
  const generators = create_generators({
    count: messages.length + 1, api_id, ciphersuite
  });
  const signature = CoreSign({
    SK, PK, header, messages: message_scalars, generators, api_id, ciphersuite
  });
  return signature;
}

export async function Verify({
  PK, signature, header, messages, ciphersuite
} = {}) {
  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, signature, 'signature');
  assertInstance(Uint8Array, header, 'header');
  assertArray(messages, 'messages');
  ciphersuite = getCiphersuite(ciphersuite);

  const api_id = _createApiId(ciphersuite.ciphersuite_id);

  /* Algorithm:

  1. message_scalars = messages_to_scalars(messages, api_id)
  2. generators = create_generators(length(messages)+1, api_id)
  3. result = CoreVerify(PK, signature, generators, header,
                         message_scalars, api_id)
  4. return result

  */
  const message_scalars = messages_to_scalars({messages, api_id, ciphersuite});
  const generators = create_generators({
    count: messages.length + 1, api_id, ciphersuite
  });
  const result = CoreVerify({
    PK, signature, generators, header, messages: message_scalars,
    api_id, ciphersuite
  });
  return result;
}

function _createApiId(ciphersuite_id) {
  /*
  api_id: the octet string ciphersuite_id || "H2G_HM2S_", where
          ciphersuite_id is defined by the ciphersuite and "H2G_HM2S_"is
          an ASCII string comprised of 9 bytes.
  */
  return TEXT_ENCODER.encode(ciphersuite_id + 'H2G_HM2S_');
}
