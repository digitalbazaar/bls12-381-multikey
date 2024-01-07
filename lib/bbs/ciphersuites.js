/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  expand_message_xmd, expand_message_xof
} from '@noble/curves/abstract/hash-to-curve.js';
import {bls12_381} from '@noble/curves/bls12-381.js';
import {sha256} from '@noble/hashes/sha256.js';
import {shake256} from '@noble/hashes/sha3.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

// supported BBS cryptosuites
export const CIPHERSUITES = {
  BLS12381_SHAKE256: {
    ciphersuite_id: 'BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_',
    expand_len: 48,
    hash: 'SHAKE-256',
    octet_scalar_length: 32,
    octet_point_length: 48,
    // FIXME: parse point
    p1: '8929dfbc7e6642c4ed9cba0856e493f8b9d7d5fcb0c31ef8fdcd34d50648a5' +
      '6c795e106e9eada6e0bda386b414150755',
    r: bls12_381.fields.Fr.ORDER,
    // hash_to_curve_suite params
    hash_to_curve_g1(msg_octets, dst) {
      if(dst.length > 255) {
        throw new Error('"dst.length" must be <= 255.');
      }
      return bls12_381.G1.hashToCurve(msg_octets, {
        DST: dst,
        expand: 'xof',
        // `k` bits; minimum security, but not used because `dst` <= 255
        k: 256,
        hash: shake256
      });
    },
    expand_message(msg_octets, dst) {
      if(dst.length > 255) {
        throw new Error('"dst.length" must be <= 255.');
      }
      return expand_message_xof(
        msg_octets, dst,
        CIPHERSUITES.BLS12381_SHAKE256.expand_len,
        // `k` bits; minimum security, but not used because `dst` <= 255
        256,
        shake256);
    },
    point_to_octets_E1: _pointToOctets,
    point_to_octets_E2: _pointToOctets
  },
  BLS12381_SHA256: {
    ciphersuite_id: 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_',
    expand_len: 48,
    hash: 'SHA-256',
    octet_scalar_length: 32,
    octet_point_length: 48,
    r: bls12_381.fields.Fr.ORDER,
    // FIXME: parse point
    p1: 'a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd' +
      '225e7c59698588e70d11406d161b4e28c9',
    // hash_to_curve_suite params
    hash_to_curve_g1(msg_octets, dst) {
      if(dst.length > 255) {
        throw new Error('"dst.length" must be <= 255.');
      }
      return bls12_381.G1.hashToCurve(msg_octets, {
        DST: dst,
        expand: 'xmd',
        hash: sha256
      });
    },
    expand_message(msg_octets, dst) {
      if(dst.length > 255) {
        throw new Error('"dst.length" must be <= 255.');
      }
      return expand_message_xmd(
        msg_octets, dst,
        CIPHERSUITES.BLS12381_SHA256.expand_len,
        sha256);
    },
    point_to_octets_E1: _pointToOctets,
    point_to_octets_E2: _pointToOctets
  }
};

export function getCiphersuite(ciphersuite_id) {
  const ciphersuite = CIPHERSUITES[ciphersuite_id];
  if(!ciphersuite) {
    throw new Error(`Unknown ciphersuite ID "${ciphersuite_id}".`);
  }
  return ciphersuite;
}

// `@noble/curves` serializes points in compressed format using `toRawBytes()`
function _pointToOctets(p) {
  return p.toRawBytes();
}
