/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {assertInstance, assertType} from './assert.js';
import {concatBytes, hash_to_scalar, i2osp, TEXT_ENCODER} from './util.js';
import {getCiphersuite} from './ciphersuites.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

export function KeyGen({
  key_material, key_info = new Uint8Array(), key_dst, ciphersuite
} = {}) {
  assertInstance(Uint8Array, key_material, 'key_material');
  assertInstance(Uint8Array, key_info, 'key_info');
  ciphersuite = getCiphersuite(ciphersuite);
  if(key_dst !== undefined) {
    assertInstance(Uint8Array, key_dst, 'key_dst');
  } else {
    key_dst = TEXT_ENCODER.encode(ciphersuite.ciphersuite_id + 'KEYGEN_DST_');
  }

  /* Algorithm:

  1. if length(key_material) < 32, return INVALID
  2. if length(key_info) > 65535, return INVALID
  3. derive_input = key_material || I2OSP(length(key_info), 2) || key_info
  4. SK = hash_to_scalar(derive_input, key_dst)
  5. if SK is INVALID, return INVALID
  6. return SK

  */
  if(key_material.length < 32) {
    throw new Error(
      `"key_material.length" (${key_material.length}) must be at least 32.`);
  }
  if(key_info.length > 65535) {
    throw new Error(
      `"key_info.length" (${key_info.length}) must be <= 65535.`);
  }
  const derive_input = concatBytes(
    key_material, i2osp(key_info.length, 2), key_info);
  const SK = hash_to_scalar({
    msg_octets: derive_input, dst: key_dst, ciphersuite
  });
  return SK;
}

export function SkToPk({SK, ciphersuite} = {}) {
  assertType('bigint', SK, 'SK');
  ciphersuite = getCiphersuite(ciphersuite);

  /* Algorithm:

  1. W = SK * BP2
  2. return point_to_octets_E2(W)

  */
  const {Fr, BP2} = ciphersuite;
  const W = Fr.multiply(SK, BP2);
  return ciphersuite.point_to_octets_E2(W);
}
