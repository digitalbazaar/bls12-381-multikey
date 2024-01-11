/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import * as bbs from '@digitalbazaar/bbs-signatures';
import {createBbsSigner, createBbsVerifier} from './factory.js';
import {
  exportKeyPair, importKeyPair,
  jwkToPublicKeyBytes, jwkToPublicKeyMultibase,
  jwkToSecretKeyBytes, jwkToSecretKeyMultibase
} from './serialize.js';
import {MULTIKEY_CONTEXT_V1_URL} from './constants.js';

// generates BLS12-381 key pair for BBS signatures
export async function generateBbsKeyPair({
  id, controller, ciphersuite, seed
} = {}) {
  const keyPair = await bbs.generateKeyPair({seed, ciphersuite});
  const keyPairInterface = await _createKeyPairInterface({
    keyPair, options: {ciphersuite}
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
export async function from(multikeyLike, options = {}) {
  // backwards compatibility
  const multikey = {...multikeyLike};
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
export async function fromJwk({jwk, secretKey = false} = {}) {
  const multikey = {
    '@context': MULTIKEY_CONTEXT_V1_URL,
    type: 'Multikey',
    publicKeyMultibase: jwkToPublicKeyMultibase({jwk})
  };
  if(secretKey && jwk.d) {
    multikey.secretKeyMultibase = jwkToSecretKeyMultibase({jwk});
  }
  return from(multikey);
}

// converts key pair to JWK
export async function toJwk({keyPair, secretKey = false} = {}) {
  const jwk = {
    kty: 'OKP',
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
export async function fromRaw({curve, secretKey, publicKey} = {}) {
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
      curve,
      publicKey,
      secretKey
    }
  });
  return fromJwk({jwk, secretKey: !!secretKey});
}

// augments key pair with useful metadata and utilities
async function _createKeyPairInterface({keyPair, options = {}}) {
  if(typeof options?.ciphersuite !== 'string') {
    throw new TypeError('"options.ciphersuite" must be a string.');
  }

  // import key pair if `curve` is not set
  if(!keyPair.curve) {
    keyPair = await importKeyPair(keyPair);
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
  const {ciphersuite} = options;
  keyPair = {
    ...keyPair,
    publicKeyMultibase,
    secretKeyMultibase,
    export: exportFn,
    signer() {
      const {id, secretKey} = keyPair;
      return createBbsSigner({id, secretKey, ciphersuite});
    },
    verifier() {
      const {id, publicKey} = keyPair;
      return createBbsVerifier({id, publicKey, ciphersuite});
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
  if(key['@context'] !== MULTIKEY_CONTEXT_V1_URL) {
    throw new TypeError(
      '"key" must be a Multikey with context ' +
      `"${MULTIKEY_CONTEXT_V1_URL}".`);
  }
}
