/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import * as base64url from 'base64url-universal';
import {
  //ALGORITHM,
  //EXTRACTABLE,
  MULTIBASE_BASE58_HEADER,
  MULTIKEY_CONTEXT_V1_URL
} from './constants.js';
import {webcrypto} from './crypto.js';
import {
  //getNamedCurveFromPublicMultikey,
  //getNamedCurveFromSecretMultikey,
  getPublicKeySize,
  getSecretKeySize,
  setPublicKeyHeader,
  setSecretKeyHeader
} from './helpers.js';

// converts key pair to PKCS #8 format
export async function cryptoKeyfromRaw({
  //curve, secretKey, publicKey, keyAgreement
} = {}) {
  // FIXME: implement
  /*
  const algorithm = {
    name: keyAgreement ? 'ECDH' : ALGORITHM,
    namedCurve: curve
  };

  let cryptoKey;
  if(secretKey) {
    const pkcs8 = _rawToPkcs8({curve, secretKey, publicKey});
    const secretUsage = keyAgreement ? ['deriveBits'] : ['sign'];
    cryptoKey = await webcrypto.subtle.importKey(
      'pkcs8', pkcs8, algorithm, EXTRACTABLE, secretUsage);
  } else {
    const spki = _rawToSpki({curve, publicKey});
    // must be empty usage for importing a public key
    const publicUsage = keyAgreement ? [] : ['verify'];
    cryptoKey = await webcrypto.subtle.importKey(
      'spki', spki, algorithm, EXTRACTABLE, publicUsage);
  }
  return cryptoKey;*/
}

// exports key pair
export async function exportKeyPair({
  keyPair, secretKey, publicKey, includeContext
} = {}) {
  if(!(publicKey || secretKey)) {
    throw new TypeError(
      'Export requires specifying either "publicKey" or "secretKey".');
  }

  // get JWK
  const useSecretKey = secretKey && !!keyPair.secretKey;
  const cryptoKey = useSecretKey ? keyPair.secretKey : keyPair.publicKey;
  const jwk = await webcrypto.subtle.exportKey('jwk', cryptoKey);

  // export as Multikey
  const exported = {};
  if(includeContext) {
    exported['@context'] = MULTIKEY_CONTEXT_V1_URL;
  }
  exported.id = keyPair.id;
  exported.type = 'Multikey';
  exported.controller = keyPair.controller;

  if(publicKey) {
    exported.publicKeyMultibase = toPublicKeyMultibase({jwk});
  }

  if(useSecretKey) {
    exported.secretKeyMultibase = toSecretKeyMultibase({jwk});
  }

  return exported;
}

// imports key pair
export async function importKeyPair({
  id, controller, /*secretKeyMultibase,*/
  publicKeyMultibase/*, keyAgreement = false*/
}) {
  if(!publicKeyMultibase) {
    throw new TypeError('The "publicKeyMultibase" property is required.');
  }

  const keyPair = {id, controller};
  // FIXME: implement import
  return keyPair;

  /*

  // import public key
  if(!(publicKeyMultibase && typeof publicKeyMultibase === 'string' &&
    publicKeyMultibase[0] === MULTIBASE_BASE58_HEADER)) {
    throw new TypeError(
      '"publicKeyMultibase" must be a multibase, base58-encoded string.');
  }
  const publicMultikey = base58.decode(publicKeyMultibase.slice(1));

  // set named curved based on multikey header
  const algorithm = {
    name: keyAgreement ? 'ECDH' : ALGORITHM,
    namedCurve: getNamedCurveFromPublicMultikey({publicMultikey})
  };

  // import public key; convert to `spki` format because `jwk` doesn't handle
  // compressed public keys
  const spki = _multikeyToSpki({publicMultikey});
  // must be empty usage for importing a public key
  const publicUsage = keyAgreement ? [] : ['verify'];
  keyPair.publicKey = await webcrypto.subtle.importKey(
    'spki', spki, algorithm, EXTRACTABLE, publicUsage);

  // import secret key if given
  if(secretKeyMultibase) {
    if(!(typeof secretKeyMultibase === 'string' &&
    secretKeyMultibase[0] === MULTIBASE_BASE58_HEADER)) {
      throw new TypeError(
        '"secretKeyMultibase" must be a multibase, base58-encoded string.');
    }
    const secretMultikey = base58.decode(secretKeyMultibase.slice(1));

    // ensure secret key multikey header appropriately matches the
    // public key multikey header
    _ensureMultikeyHeadersMatch({secretMultikey, publicMultikey});

    // convert to `pkcs8` format for import because `jwk` doesn't support
    // compressed keys
    const pkcs8 = _multikeyToPkcs8({secretMultikey, publicMultikey});
    const secretUsage = keyAgreement ? ['deriveBits'] : ['sign'];
    keyPair.secretKey = await webcrypto.subtle.importKey(
      'pkcs8', pkcs8, algorithm, EXTRACTABLE, secretUsage);
  }*/

  return keyPair;
}

export function toPublicKeyBytes({jwk} = {}) {
  if(jwk?.kty !== 'EC') {
    throw new TypeError('"jwk.kty" must be "EC".');
  }
  const {crv: curve} = jwk;
  const publicKeySize = getPublicKeySize({curve});
  // convert `x` coordinate to compressed public key
  const x = base64url.decode(jwk.x);
  const y = base64url.decode(jwk.y);
  const publicKey = new Uint8Array(publicKeySize);
  // use even / odd status of `y` coordinate for compressed header
  const even = y[y.length - 1] % 2 === 0;
  publicKey[0] = even ? 2 : 3;
  // write `x` coordinate at end of multikey buffer to zero-fill it
  publicKey.set(x, publicKey.length - x.length);
  return publicKey;
}

export function toPublicKeyMultibase({jwk} = {}) {
  if(jwk?.kty !== 'EC') {
    throw new TypeError('"jwk.kty" must be "EC".');
  }
  const {crv: curve} = jwk;
  const publicKeySize = getPublicKeySize({curve});
  // convert `x` coordinate to compressed public key
  const x = base64url.decode(jwk.x);
  const y = base64url.decode(jwk.y);
  // leave room for multicodec header (2 bytes)
  const multikey = new Uint8Array(2 + publicKeySize);
  setPublicKeyHeader({curve, buffer: multikey});
  // use even / odd status of `y` coordinate for compressed header
  const even = y[y.length - 1] % 2 === 0;
  multikey[2] = even ? 2 : 3;
  // write `x` coordinate at end of multikey buffer to zero-fill it
  multikey.set(x, multikey.length - x.length);
  const publicKeyMultibase = MULTIBASE_BASE58_HEADER + base58.encode(multikey);
  return publicKeyMultibase;
}

export function toSecretKeyBytes({jwk} = {}) {
  if(jwk?.kty !== 'EC') {
    throw new TypeError('"jwk.kty" must be "EC".');
  }
  const {crv: curve} = jwk;
  const secretKeySize = getSecretKeySize({curve});
  const d = base64url.decode(jwk.d);
  const secretKey = new Uint8Array(secretKeySize);
  // write `d` at end of multikey buffer to zero-fill it
  secretKey.set(d, secretKey.length - d.length);
  return secretKey;
}

export function toSecretKeyMultibase({jwk} = {}) {
  if(jwk?.kty !== 'EC') {
    throw new TypeError('"jwk.kty" must be "EC".');
  }
  const {crv: curve} = jwk;
  const secretKeySize = getSecretKeySize({curve});
  const d = base64url.decode(jwk.d);
  // leave room for multicodec header (2 bytes)
  const multikey = new Uint8Array(2 + secretKeySize);
  setSecretKeyHeader({curve: jwk.crv, buffer: multikey});
  // write `d` at end of multikey buffer to zero-fill it
  multikey.set(d, multikey.length - d.length);
  const secretKeyMultibase = MULTIBASE_BASE58_HEADER + base58.encode(multikey);
  return secretKeyMultibase;
}

// ensures that public key header matches secret key header
/*function _ensureMultikeyHeadersMatch({secretMultikey, publicMultikey}) {
  const publicCurve = getNamedCurveFromPublicMultikey({publicMultikey});
  const secretCurve = getNamedCurveFromSecretMultikey({secretMultikey});
  if(publicCurve !== secretCurve) {
    throw new Error(
      `Public key curve ('${publicCurve}') does not match ` +
      `secret key curve ('${secretCurve}').`);
  }
}
*/
