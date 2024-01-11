/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import * as base64url from 'base64url-universal';
import {
  BLS12_381_CURVE,
  MULTIBASE_BASE58_HEADER,
  MULTIKEY_CONTEXT_V1_URL
} from './constants.js';
import {
  getNamedCurveFromPublicMultikey,
  getNamedCurveFromSecretMultikey,
  getPublicKeySize,
  getSecretKeySize,
  setPublicKeyHeader,
  setSecretKeyHeader
} from './helpers.js';
import {bls12_381} from '@noble/curves/bls12-381';
import {concatBytes} from '@noble/curves/abstract/utils';

const G1Point = bls12_381.G1.ProjectivePoint;
const G2Point = bls12_381.G2.ProjectivePoint;

// exports key pair
export async function exportKeyPair({
  keyPair, secretKey, publicKey, includeContext
} = {}) {
  if(!(publicKey || secretKey)) {
    throw new TypeError(
      'Export requires specifying either "publicKey" or "secretKey".');
  }

  const useSecretKey = secretKey && !!keyPair.secretKey;

  // export as Multikey
  const exported = {};
  if(includeContext) {
    exported['@context'] = MULTIKEY_CONTEXT_V1_URL;
  }
  exported.id = keyPair.id;
  exported.type = 'Multikey';
  exported.controller = keyPair.controller;

  if(publicKey) {
    exported.publicKeyMultibase = rawToPublicKeyMultibase(keyPair);
  }
  if(useSecretKey) {
    exported.secretKeyMultibase = rawToSecretKeyMultibase(keyPair);
  }

  return exported;
}

// imports key pair
export async function importKeyPair({
  id, controller, secretKeyMultibase, publicKeyMultibase
}) {
  if(!publicKeyMultibase) {
    throw new TypeError('The "publicKeyMultibase" property is required.');
  }

  const keyPair = {id, controller};

  // import public key
  if(!(publicKeyMultibase && typeof publicKeyMultibase === 'string' &&
    publicKeyMultibase[0] === MULTIBASE_BASE58_HEADER)) {
    throw new TypeError(
      '"publicKeyMultibase" must be a multibase, base58-encoded string.');
  }
  const publicMultikey = base58.decode(publicKeyMultibase.slice(1));
  // get key pair curve
  keyPair.curve = getNamedCurveFromPublicMultikey({publicMultikey});
  // get raw public key
  keyPair.publicKey = publicMultikey.slice(2);

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

    // get raw secret key
    keyPair.secretKey = secretMultikey.slice(2);
  }

  return keyPair;
}

export function jwkToPublicKeyBytes({jwk} = {}) {
  if(jwk?.kty !== 'OKP') {
    throw new TypeError('"jwk.kty" must be "OKP".');
  }
  const {crv: curve} = jwk;
  const publicKeySize = getPublicKeySize({curve});

  // JWK can have just `x` with the full compressed public key or
  // `x` and `y` (despite using a type of `OKP`), so we handle both
  let publicKey;
  const x = base64url.decode(jwk.x);
  if(jwk.y) {
    // convert coordinates to compressed public key bytes
    const y = base64url.decode(jwk.y);
    publicKey = _coordinatesToPublicKey({curve, x, y});
  } else {
    // `x` has compressed public key bytes
    publicKey = x;
  }
  if(publicKey.length !== publicKeySize) {
    throw new Error(
      `Invalid public key size (${publicKey.length}); ` +
      `expected ${publicKeySize}.`);
  }
  return publicKey;
}

export function jwkToPublicKeyMultibase({jwk} = {}) {
  const {crv: curve} = jwk;
  const publicKey = jwkToPublicKeyBytes({jwk});

  // leave room for multicodec header (2 bytes)
  const multikey = new Uint8Array(2 + publicKey.length);
  setPublicKeyHeader({curve, buffer: multikey});

  // write compressed public key
  multikey.set(publicKey, 2);
  const publicKeyMultibase = MULTIBASE_BASE58_HEADER + base58.encode(multikey);
  return publicKeyMultibase;
}

export function jwkToSecretKeyBytes({jwk} = {}) {
  if(jwk?.kty !== 'OKP') {
    throw new TypeError('"jwk.kty" must be "OKP".');
  }
  const {crv: curve} = jwk;
  const secretKeySize = getSecretKeySize({curve});
  // if `jwk` has `y`, then assume `d` is little endian encoded, otherwise,
  // assume it is big endian encoded (as both of these JWK expressions have
  // been documented)
  const secretKey = base64url.decode(jwk.d);
  if(jwk.y) {
    // little endian encoding
    secretKey.reverse();
  }
  if(secretKey.length !== secretKeySize) {
    throw new Error(
      `Invalid secret key size (${secretKey.length}); ` +
      `expected ${secretKeySize}.`);
  }
  return secretKey;
}

export function jwkToSecretKeyMultibase({jwk} = {}) {
  const secretKey = jwkToSecretKeyBytes({jwk});
  // leave room for multicodec header (2 bytes)
  const multikey = new Uint8Array(2 + secretKey.length);
  setSecretKeyHeader({curve: jwk.crv, buffer: multikey});
  // write `secretKey`
  multikey.set(secretKey, 2);
  const secretKeyMultibase = MULTIBASE_BASE58_HEADER + base58.encode(multikey);
  return secretKeyMultibase;
}

export function rawToPublicKeyMultibase({curve, publicKey} = {}) {
  const publicKeySize = getPublicKeySize({curve});
  if(publicKey.length !== publicKeySize) {
    throw new Error(
      `Invalid public key size (${publicKey.length}); ` +
      `expected ${publicKeySize}.`);
  }
  // leave room for multicodec header (2 bytes)
  const multikey = new Uint8Array(2 + publicKeySize);
  setPublicKeyHeader({curve, buffer: multikey});
  // write `publicKey`
  multikey.set(publicKey, 2);
  const publicKeyMultibase = MULTIBASE_BASE58_HEADER + base58.encode(multikey);
  return publicKeyMultibase;
}

export function rawToSecretKeyMultibase({curve, secretKey} = {}) {
  const secretKeySize = getSecretKeySize({curve});
  if(secretKey.length !== secretKeySize) {
    throw new Error(
      `Invalid secret key size (${secretKey.length}); ` +
      `expected ${secretKeySize}.`);
  }
  // leave room for multicodec header (2 bytes)
  const multikey = new Uint8Array(2 + secretKeySize);
  setSecretKeyHeader({curve, buffer: multikey});
  // write `secretKey`
  multikey.set(secretKey, 2);
  const secretKeyMultibase = MULTIBASE_BASE58_HEADER + base58.encode(multikey);
  return secretKeyMultibase;
}

// convert affine coordinates to compressed public key
function _coordinatesToPublicKey({curve, x, y}) {
  const combined = concatBytes(x, y);
  if(curve === BLS12_381_CURVE.G1) {
    return G1Point.fromHex(combined).toHex(true);
  }
  if(curve === BLS12_381_CURVE.G2) {
    return G2Point.fromHex(combined).toHex(true);
  }
  throw new TypeError(`Unsupported curve "${curve}".`);
}

// ensures that public key header matches secret key header
function _ensureMultikeyHeadersMatch({secretMultikey, publicMultikey}) {
  const publicCurve = getNamedCurveFromPublicMultikey({publicMultikey});
  const secretCurve = getNamedCurveFromSecretMultikey({secretMultikey});
  if(publicCurve !== secretCurve) {
    throw new Error(
      `Public key curve ('${publicCurve}') does not match ` +
      `secret key curve ('${secretCurve}').`);
  }
}
