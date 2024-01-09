/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  expand_message_xmd, expand_message_xof
} from '@noble/curves/abstract/hash-to-curve';
import {assertType} from './assert.js';
import {bls12_381} from '@noble/curves/bls12-381';
import {sha256} from '@noble/hashes/sha256';
import {shake256} from '@noble/hashes/sha3';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

// supported BBS cryptosuites
export const CIPHERSUITES = {
  BLS12381_SHAKE256: {
    ciphersuite_id: 'BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_',
    name: 'BLS12-381-SHAKE-256',
    expand_len: 48,
    hash: 'SHAKE-256',
    octet_scalar_length: 32,
    octet_point_length: 48,
    BP1: bls12_381.G1.ProjectivePoint.BASE,
    BP2: bls12_381.G2.ProjectivePoint.BASE,
    E1: bls12_381.fields.Fp,
    E2: bls12_381.fields.Fp2,
    P1: bls12_381.G1.ProjectivePoint.fromHex(
      '8929dfbc7e6642c4ed9cba0856e493f8b9d7d5fcb0c31ef8fdcd34d50648a5' +
      '6c795e106e9eada6e0bda386b414150755'),
    // field over `r`
    Fr: bls12_381.fields.Fr,
    // `r`
    r: bls12_381.fields.Fr.ORDER,
    // hash_to_curve_suite params
    hash_to_curve_g1(msg_octets, dst) {
      if(dst.length > 255) {
        throw new Error('"dst.length" must be <= 255.');
      }
      return bls12_381.G1.hashToCurve(msg_octets, {
        DST: dst,
        expand: 'xof',
        // `k` bits; security param for the suite
        k: 128,
        hash: shake256
      });
    },
    expand_message(msg_octets, dst, expand_len) {
      if(dst.length > 255) {
        throw new Error('"dst.length" must be <= 255.');
      }
      return expand_message_xof(
        msg_octets, dst,
        expand_len ?? CIPHERSUITES.BLS12381_SHAKE256.expand_len,
        // `k` bits; security param for the suite
        128,
        shake256);
    },
    // instead of just `e()`, this performs `e(pair1) * e(pair2_negation)`
    // and compares against Identity_GT efficiently
    eCompare: _comparePairings,
    octets_to_point_E1: _octetsToG1Point,
    octets_to_point_E2: _octetsToG2Point,
    point_to_octets_E1: _pointToOctets,
    point_to_octets_E2: _pointToOctets
  },
  BLS12381_SHA256: {
    ciphersuite_id: 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_',
    name: 'BLS12-381-SHA-256',
    expand_len: 48,
    hash: 'SHA-256',
    octet_scalar_length: 32,
    octet_point_length: 48,
    // field over `r`
    Fr: bls12_381.fields.Fr,
    // `r`
    r: bls12_381.fields.Fr.ORDER,
    BP1: bls12_381.G1.ProjectivePoint.BASE,
    BP2: bls12_381.G2.ProjectivePoint.BASE,
    E1: bls12_381.fields.Fp,
    E2: bls12_381.fields.Fp2,
    P1: bls12_381.G1.ProjectivePoint.fromHex(
      'a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd' +
      '225e7c59698588e70d11406d161b4e28c9'),
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
    expand_message(msg_octets, dst, expand_len) {
      if(dst.length > 255) {
        throw new Error('"dst.length" must be <= 255.');
      }
      return expand_message_xmd(
        msg_octets, dst,
        expand_len ?? CIPHERSUITES.BLS12381_SHA256.expand_len,
        sha256);
    },
    // instead of just `e()`, this performs `e(pair1) * e(pair2_negation)`
    // and compares against Identity_GT efficiently
    eCompare: _comparePairings,
    octets_to_point_E1: _octetsToG1Point,
    octets_to_point_E2: _octetsToG2Point,
    point_to_octets_E1: _pointToOctets,
    point_to_octets_E2: _pointToOctets
  }
};

const ALL_CIPHERSUITES = [...Object.values(CIPHERSUITES)];

export function getCiphersuite(ciphersuite) {
  if(typeof ciphersuite === 'object') {
    if(!ALL_CIPHERSUITES.includes(ciphersuite)) {
      throw new TypeError(`Unknown ciphersuite "${ciphersuite.name}".`);
    }
    return ciphersuite;
  }

  assertType('string', ciphersuite, 'ciphersuite');
  ciphersuite = CIPHERSUITES[ciphersuite];
  if(!ciphersuite) {
    for(const [, value] of CIPHERSUITES.entries()) {
      if(value.name === ciphersuite || value.ciphersuite_id === ciphersuite) {
        return value;
      }
    }
    throw new Error(`Unknown ciphersuite "${ciphersuite}".`);
  }
  return ciphersuite;
}

// `@noble/curves` serializes points in compressed format using `toRawBytes()`
function _pointToOctets(p) {
  return p.toRawBytes();
}

function _octetsToG1Point(octets) {
  return bls12_381.G1.ProjectivePoint.fromHex(octets);
}

function _octetsToG2Point(octets) {
  return bls12_381.G2.ProjectivePoint.fromHex(octets);
}

// compares two pairings against one another by:
// 1. negating the second element of the the second pair
// 2. implementing "Optimal Ate Pairing" (`e()`) on each pair
// 3. multipling the pairings efficiently with minimal exponentiation
// 4. comparing against the identity element of the GT subgroup
function _comparePairings({pair1, pair2, performNegation = true} = {}) {
  if(performNegation) {
    pair2 = [pair2[0], pair2[1].negate()];
  }
  // do not perform final exponentiation until after multiplication
  const left = bls12_381.pairing(...pair1, false);
  const right = bls12_381.pairing(...pair2, false);
  const {fields: {Fp12}} = bls12_381;
  const Identity_GT = Fp12.ONE;
  const product = Fp12.finalExponentiate(Fp12.mul(left, right));
  return Fp12.eql(product, Identity_GT);
}
