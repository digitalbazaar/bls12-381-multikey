/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import {ALGORITHM, BLS12_381_CURVE, BBS_HASH} from './constants.js';
import {webcrypto} from './crypto.js';

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
  const algorithm = {name: ALGORITHM, hash: {name: _getEcdsaHash({curve})}};
  return {
    algorithm: curve,
    id,
    // FIXME: add `multisign` interface that takes a Uint8Array header and
    // Uint8Arrays of messages to be signed
    async multisign({header, messages} = {}) {
      // Compute the bbsSignature using the Sign procedure of
      // [CFRG-BBS-Signature] with appropriate key material and
      // bbsHeader for the header and bbsMessages for the messages
      // FIXME: implement
    },
    async sign({data} = {}) {
      // FIXME: throw an error indicating that `multisign` has to be used
      // instead
      return new Uint8Array(await webcrypto.subtle.sign(
        algorithm, secretKey, data));
    }
  };
}

// exposes verify method
export function createVerifier({id, publicKey}) {
  if(!publicKey) {
    throw new Error('"publicKey" is required for verifying.');
  }
  const {namedCurve: curve} = publicKey.algorithm;
  const algorithm = {name: ALGORITHM, hash: {name: _getEcdsaHash({curve})}};
  return {
    algorithm: curve,
    id,
    async verify({data, signature} = {}) {
      return webcrypto.subtle.verify(algorithm, publicKey, signature, data);
    }
  };
}

// retrieves name of appropriate ECDSA hash function
function _getEcdsaHash({curve}) {
  if(curve === ECDSA_CURVE.P256) {
    return ECDSA_HASH.SHA256;
  }
  if(curve === ECDSA_CURVE.P384) {
    return ECDSA_HASH.SHA384;
  }
  if(curve === ECDSA_CURVE.P521) {
    return ECDSA_HASH.SHA512;
  }
  throw new TypeError(`Unsupported curve "${curve}".`);
}
