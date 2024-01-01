/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
//import {ALGORITHM, BLS12_381_CURVE, BBS_HASH} from './constants.js';
// FIXME: remove
//import {webcrypto} from './crypto.js';

// exposes sign method
export function createSigner({id, secretKey}) {
  if(!secretKey) {
    throw new Error('"secretKey" is required for signing.');
  }
  // FIXME: consider need for secret key algorithm/other params to determine
  // the generation of a different signing function with only BBS defined
  // thus far; throw if the secret key params do not match what is expected
  // for BBS
  const {namedCurve: curve} = secretKey.algorithm;
  //const algorithm = {name: ALGORITHM, hash: {name: _getBbsHash({curve})}};
  return {
    algorithm: curve,
    id,
    // FIXME: add `multisign` interface that takes a Uint8Array header and
    // Uint8Arrays of messages to be signed
    async multisign({/*header, messages*/} = {}) {
      // Compute the bbsSignature using the Sign procedure of
      // [CFRG-BBS-Signature] with appropriate key material and
      // bbsHeader for the header and bbsMessages for the messages
      // FIXME: implement
    },
    async sign() {
      throw new Error('"sign()" not implemented; use "multisign()".');
    }
  };
}

// exposes verify method
export function createVerifier({id, publicKey}) {
  if(!publicKey) {
    throw new Error('"publicKey" is required for verifying.');
  }
  const {namedCurve: curve} = publicKey.algorithm;
  //const algorithm = {name: ALGORITHM, hash: {name: _getBbsHash({curve})}};
  return {
    algorithm: curve,
    id,
    // FIXME: add `multiverify` interface; `messages` can be sparsely populated
    // to allow for selective disclosure
    async multiverify({/*header, messages, signature*/} = {}) {
      // FIXME: perform `ProofVerify` from BBS spec
      // FIXME: implement
    },
    async verify() {
      throw new Error('"verify()" not implemented; use "multiverify()".');
    }
  };
}

// retrieves name of appropriate BBS hash function
/*
function _getBbsHash({curve}) {
  if(curve === BLS12_381_CURVE.G1) {
    return BBS_HASH.SHA256;
  }
  if(curve === BLS12_381_CURVE.G2) {
    return BBS_HASH.SHA256;
  }
  throw new TypeError(`Unsupported curve "${curve}".`);
}
*/
