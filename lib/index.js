/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  ALGORITHM,
  BLS12_381_CURVE,
  EXTRACTABLE,
  MULTIKEY_CONTEXT_V1_URL
} from './constants.js';
import {CryptoKey, webcrypto} from './crypto.js';
import {createSigner, createVerifier} from './factory.js';
import {
  cryptoKeyfromRaw,
  exportKeyPair, importKeyPair,
  toPublicKeyBytes, toSecretKeyBytes,
  toPublicKeyMultibase, toSecretKeyMultibase
} from './serialize.js';

// generates BLS12-381 key pair
export async function generate({
  id, controller, curve, keyAgreement = false
} = {}) {
  if(!curve) {
    throw new TypeError(
      '"curve" must be one of the following values: ' +
      `${Object.values(BLS12_381_CURVE).map(v => `'${v}'`).join(', ')}.`);
  }
  const algorithm = keyAgreement ?
    {name: 'ECDH', namedCurve: curve} : {name: ALGORITHM, namedCurve: curve};
  const usage = keyAgreement ? ['deriveBits'] : ['sign', 'verify'];
  const keyPair = await webcrypto.subtle.generateKey(
    algorithm, EXTRACTABLE, usage);
  keyPair.secretKey = keyPair.privateKey;
  delete keyPair.privateKey;
  const keyPairInterface = await _createKeyPairInterface(
    {keyPair, keyAgreement});
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
export async function from(key) {
  // backwards compatibility
  const multikey = {...key};
  if(!multikey.type) {
    multikey.type = 'Multikey';
  }
  if(!multikey['@context']) {
    multikey['@context'] = MULTIKEY_CONTEXT_V1_URL;
  }
  if(multikey.controller && !multikey.id) {
    multikey.id = `${key.controller}#${key.publicKeyMultibase}`;
  }
  _assertMultikey(multikey);
  return _createKeyPairInterface({keyPair: multikey});
}

// imports key pair from JWK
export async function fromJwk({jwk, secretKey = false} = {}) {
  const multikey = {
    '@context': MULTIKEY_CONTEXT_V1_URL,
    type: 'Multikey',
    publicKeyMultibase: toPublicKeyMultibase({jwk})
  };
  if(secretKey && jwk.d) {
    multikey.secretKeyMultibase = toSecretKeyMultibase({jwk});
  }
  const keyAgreement = !jwk.key_ops || jwk.key_ops.includes('deriveBits');
  return from(multikey, keyAgreement);
}

// converts key pair to JWK
export async function toJwk({keyPair, secretKey = false} = {}) {
  if(!(keyPair?.publicKey instanceof CryptoKey)) {
    keyPair = await importKeyPair(keyPair);
  }
  const useSecretKey = secretKey && !!keyPair.secretKey;
  const cryptoKey = useSecretKey ? keyPair.secretKey : keyPair.publicKey;
  const jwk = await webcrypto.subtle.exportKey('jwk', cryptoKey);
  return jwk;
}

// raw import from secretKey and publicKey bytes
export async function fromRaw({
  curve, secretKey, publicKey, keyAgreement = false
} = {}) {
  if(typeof curve !== 'string') {
    throw new TypeError('"curve" must be a string.');
  }
  if(secretKey && !(secretKey instanceof Uint8Array)) {
    throw new TypeError('"secretKey" must be a Uint8Array.');
  }
  if(!(publicKey instanceof Uint8Array)) {
    throw new TypeError('"publicKey" must be a Uint8Array.');
  }
  const cryptoKey = await cryptoKeyfromRaw(
    {curve, secretKey, publicKey, keyAgreement});
  const jwk = await webcrypto.subtle.exportKey('jwk', cryptoKey);
  return fromJwk({jwk, secretKey: !!secretKey, keyAgreement});
}

// augments key pair with useful metadata and utilities
async function _createKeyPairInterface({keyPair, keyAgreement = false}) {
  if(!(keyPair?.publicKey instanceof CryptoKey)) {
    keyPair = await importKeyPair(keyPair);
  }
  const exportFn = async ({
    publicKey = true, secretKey = false, includeContext = true, raw = false
  } = {}) => {
    if(raw) {
      const jwk = await toJwk({keyPair, secretKey});
      const result = {};
      if(publicKey) {
        result.publicKey = toPublicKeyBytes({jwk});
      }
      if(secretKey) {
        result.secretKey = toSecretKeyBytes({jwk});
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
    publicKeyMultibase,
    secretKeyMultibase,
    keyAgreement,
    export: exportFn,
    signer() {
      const {id, secretKey} = keyPair;
      return createSigner({id, secretKey});
    },
    verifier() {
      const {id, publicKey} = keyPair;
      return createVerifier({id, publicKey});
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
