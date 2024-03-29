/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  BLS12_381_CURVE,
  MULTICODEC_G1_PUBLIC_KEY_HEADER,
  MULTICODEC_G1_SECRET_KEY_HEADER,
  MULTICODEC_G2_PUBLIC_KEY_HEADER,
  MULTICODEC_G2_SECRET_KEY_HEADER
} from './constants.js';

// retrieves name of appropriate BLS12-381 curve from public Multikey
export function getNamedCurveFromPublicMultikey({publicMultikey}) {
  if(publicMultikey[0] === MULTICODEC_G1_PUBLIC_KEY_HEADER[0] &&
    publicMultikey[1] === MULTICODEC_G1_PUBLIC_KEY_HEADER[1]) {
    return BLS12_381_CURVE.G1;
  }
  if(publicMultikey[0] === MULTICODEC_G2_PUBLIC_KEY_HEADER[0] &&
    publicMultikey[1] === MULTICODEC_G2_PUBLIC_KEY_HEADER[1]) {
    return BLS12_381_CURVE.G2;
  }
  throw new TypeError('Unsupported public multikey header.');
}

// retrieves name of appropriate BLS12-381 curve from secret Multikey
export function getNamedCurveFromSecretMultikey({secretMultikey}) {
  if(secretMultikey[0] === MULTICODEC_G1_SECRET_KEY_HEADER[0] &&
    secretMultikey[1] === MULTICODEC_G1_SECRET_KEY_HEADER[1]) {
    return BLS12_381_CURVE.G1;
  }
  if(secretMultikey[0] === MULTICODEC_G2_SECRET_KEY_HEADER[0] &&
    secretMultikey[1] === MULTICODEC_G2_SECRET_KEY_HEADER[1]) {
    return BLS12_381_CURVE.G2;
  }
  throw new TypeError('Unsupported secret multikey header.');
}

export function getPublicKeySize({curve}) {
  if(curve === BLS12_381_CURVE.G1) {
    return 48;
  }
  if(curve === BLS12_381_CURVE.G2) {
    return 96;
  }
  throw new TypeError(`Unsupported curve "${curve}".`);
}

export function getSecretKeySize({curve}) {
  if(curve === BLS12_381_CURVE.G1 || curve === BLS12_381_CURVE.G2) {
    return 32;
  }
  throw new TypeError(`Unsupported curve "${curve}".`);
}

// sets secret key header bytes on key pair
export function setSecretKeyHeader({curve, buffer}) {
  if(curve === BLS12_381_CURVE.G1) {
    buffer[0] = MULTICODEC_G1_SECRET_KEY_HEADER[0];
    buffer[1] = MULTICODEC_G1_SECRET_KEY_HEADER[1];
  } else if(curve === BLS12_381_CURVE.G2) {
    buffer[0] = MULTICODEC_G2_SECRET_KEY_HEADER[0];
    buffer[1] = MULTICODEC_G2_SECRET_KEY_HEADER[1];
  } else {
    throw new TypeError(`Unsupported curve "${curve}".`);
  }
}

// sets public key header bytes on key pair
export function setPublicKeyHeader({curve, buffer}) {
  if(curve === BLS12_381_CURVE.G1) {
    buffer[0] = MULTICODEC_G1_PUBLIC_KEY_HEADER[0];
    buffer[1] = MULTICODEC_G1_PUBLIC_KEY_HEADER[1];
  } else if(curve === BLS12_381_CURVE.G2) {
    buffer[0] = MULTICODEC_G2_PUBLIC_KEY_HEADER[0];
    buffer[1] = MULTICODEC_G2_PUBLIC_KEY_HEADER[1];
  } else {
    throw new TypeError(`Unsupported curve "${curve}".`);
  }
}
