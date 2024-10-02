/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import * as bbs from '@digitalbazaar/bbs-signatures';
import {
  ALGORITHMS, BLS12_381_CURVE, MULTIKEY_CONTEXT_V1_URL
} from './constants.js';
import {createBbsSigner, createBbsVerifier} from './factory.js';
import {
  exportKeyPair, importKeyPair,
  jwkToPublicKeyBytes, jwkToPublicKeyMultibase,
  jwkToSecretKeyBytes, jwkToSecretKeyMultibase
} from './serialize.js';

// re-export algorithms
export {ALGORITHMS} from './constants.js';
const ALL_ALGORITHMS = new Set([...Object.values(ALGORITHMS)]);

// generates BLS12-381 key pair for BBS signatures
export async function generateBbsKeyPair({
  id, controller, algorithm, seed
} = {}) {
  if(!ALL_ALGORITHMS.has(algorithm)) {
    throw new Error(`Unknown algorithm "${algorithm}".`);
  }
  const ciphersuite = algorithm.slice('BBS-'.length);
  const keyPair = await bbs.generateKeyPair({seed, ciphersuite});
  const keyPairInterface = await _createKeyPairInterface({
    keyPair: {...keyPair, curve: BLS12_381_CURVE.G2}, options: {algorithm}
  });
  const exportedKeyPair = await keyPairInterface.export({publicKey: true});
  const {publicKeyMultibase} = exportedKeyPair;
  if(controller && !id) {
    id = `${controller}#${publicKeyMultibase}`;
  }
  keyPairInterface.id = id;
  keyPairInterface.controller = controller;
  return keyPairInterface;
}

// imports key pair from JSON Multikey
export async function from(multikeyLike, options = {
  // default algorithm
  algorithm: ALGORITHMS.BBS_BLS12381_SHA256
}) {
  // backwards compatibility
  const multikey = {...multikeyLike};
  if(multikey.type !== 'Multikey') {
    // attempt loading from JWK if `publicKeyJwk` is present
    if(multikey.publicKeyJwk) {
      let id;
      let controller;
      if(multikey.type === 'JsonWebKey' || multikey.type === 'JsonWebKey2020') {
        ({id, controller} = multikey);
      }
      return fromJwk({
        jwk: multikey.publicKeyJwk, secretKey: false, id, controller
      });
    }
  }
  if(!multikey.type) {
    multikey.type = 'Multikey';
  }
  if(!multikey['@context']) {
    multikey['@context'] = MULTIKEY_CONTEXT_V1_URL;
  }
  if(multikey.controller && !multikey.id) {
    multikey.id =
      `${multikeyLike.controller}#${multikeyLike.publicKeyMultibase}`;
  }
  _assertMultikey(multikey);
  return _createKeyPairInterface({keyPair: multikey, options});
}

// imports key pair from JWK
export async function fromJwk({jwk, secretKey = false, id, controller} = {}) {
  const multikey = {
    '@context': MULTIKEY_CONTEXT_V1_URL,
    type: 'Multikey',
    publicKeyMultibase: jwkToPublicKeyMultibase({jwk})
  };
  if(typeof id === 'string') {
    multikey.id = id;
  }
  if(typeof controller === 'string') {
    multikey.controller = controller;
  }
  if(secretKey && jwk.d) {
    multikey.secretKeyMultibase = jwkToSecretKeyMultibase({jwk});
  }
  // default to `BBS-BLS12-381-SHA-256` when coming from JWK
  const algorithm = !jwk.alg || jwk.alg.startsWith('BBS-DRAFT-') ?
    ALGORITHMS.BBS_BLS12381_SHA256 : jwk.alg;
  const options = {algorithm};
  return from(multikey, options);
}

// converts key pair to JWK
export async function toJwk({keyPair, secretKey = false} = {}) {
  const jwk = {
    kty: 'OKP',
    alg: keyPair.algorithm,
    crv: keyPair.curve,
    x: base64url.encode(keyPair.publicKey)
  };
  const useSecretKey = secretKey && !!keyPair.secretKey;
  if(useSecretKey) {
    jwk.d = base64url.encode(keyPair.secretKey);
  }
  return jwk;
}

// raw import from secretKey and publicKey bytes
export async function fromRaw({algorithm, curve, secretKey, publicKey} = {}) {
  if(algorithm) {
    if(!ALL_ALGORITHMS.has(algorithm)) {
      throw new Error(`Unknown algorithm "${algorithm}".`);
    }
    if(curve) {
      if(curve !== BLS12_381_CURVE.G2) {
        throw new Error(`Curve "${curve}" must be "${BLS12_381_CURVE.G2}".`);
      }
    } else {
      curve = BLS12_381_CURVE.G2;
    }
  }
  if(typeof curve !== 'string') {
    throw new TypeError('"curve" must be a string.');
  }
  if(secretKey && !(secretKey instanceof Uint8Array)) {
    throw new TypeError('"secretKey" must be a Uint8Array.');
  }
  if(!(publicKey instanceof Uint8Array)) {
    throw new TypeError('"publicKey" must be a Uint8Array.');
  }
  const jwk = await toJwk({
    keyPair: {
      algorithm: algorithm ?? ALGORITHMS.BBS_BLS12381_SHA256,
      curve,
      publicKey,
      secretKey
    },
    secretKey: !!secretKey
  });
  return fromJwk({jwk, secretKey: !!secretKey});
}

// augments key pair with useful metadata and utilities
async function _createKeyPairInterface({keyPair, options = {}}) {
  if(typeof options?.algorithm !== 'string') {
    throw new TypeError('"options.algorithm" must be a string.');
  }
  const {algorithm} = options;
  if(!ALL_ALGORITHMS.has(algorithm)) {
    throw new Error(`Unknown algorithm "${algorithm}".`);
  }

  // import key pair if `curve`, `publicKey`, or `secretKey` are not set
  if(!(keyPair.curve && keyPair.publicKey && keyPair.secretKey)) {
    keyPair = await importKeyPair(keyPair, {algorithm});
  }
  const exportFn = async ({
    publicKey = true, secretKey = false, includeContext = true, raw = false
  } = {}) => {
    if(raw) {
      const jwk = await toJwk({keyPair, secretKey});
      const result = {curve: keyPair.curve};
      if(publicKey) {
        result.publicKey = jwkToPublicKeyBytes({jwk});
      }
      if(secretKey) {
        result.secretKey = jwkToSecretKeyBytes({jwk});
      }
      return result;
    }
    return exportKeyPair({keyPair, publicKey, secretKey, includeContext});
  };
  const {publicKeyMultibase, secretKeyMultibase} = await exportFn({
    publicKey: true, secretKey: true, includeContext: true
  });
  keyPair = {
    ...keyPair,
    algorithm,
    publicKeyMultibase,
    secretKeyMultibase,
    export: exportFn,
    signer() {
      const {id, secretKey, publicKey} = keyPair;
      return createBbsSigner({id, secretKey, publicKey, algorithm});
    },
    // derives a BBS proof from a BBS signature
    async deriveProof({
      signature, header, messages,
      presentationHeader, disclosedMessageIndexes
    }) {
      const {algorithm, publicKey} = keyPair;
      const ciphersuite = algorithm.slice('BBS-'.length);
      return bbs.deriveProof({
        publicKey, signature, header, messages,
        presentationHeader, disclosedMessageIndexes,
        ciphersuite
      });
    },
    verifier() {
      const {id, publicKey} = keyPair;
      return createBbsVerifier({id, publicKey, algorithm});
    }
  };

  return keyPair;
}

// checks if key pair is in Multikey format
function _assertMultikey(key) {
  if(!(key && typeof key === 'object')) {
    throw new TypeError('"key" must be an object.');
  }
  if(key.type !== 'Multikey') {
    throw new TypeError('"key" must be a Multikey with type "Multikey".');
  }
  if(!(key['@context'] === MULTIKEY_CONTEXT_V1_URL ||
    (Array.isArray(key['@context']) &&
    key['@context'].includes(MULTIKEY_CONTEXT_V1_URL)))) {
    throw new TypeError(
      '"key" must be a Multikey with context ' +
      `"${MULTIKEY_CONTEXT_V1_URL}".`);
  }
}
