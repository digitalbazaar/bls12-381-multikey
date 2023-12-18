/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
// Name of algorithm
// FIXME: see also: "cryptosuite ID":
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-04.html#name-ciphersuite-id
// FIXME: see also:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-04.html#name-bls12-381-ciphersuites
export const ALGORITHM = 'BBS';
// Determines whether key pair is extractable
export const EXTRACTABLE = true;
// Multikey context v1 URL
export const MULTIKEY_CONTEXT_V1_URL = 'https://w3id.org/security/multikey/v1';
export const MULTIBASE_BASE58_HEADER = 'z';

// Multicodec G1-pub header (0xea as varint = 0xea00)
export const MULTICODEC_G1_PUBLIC_KEY_HEADER = new Uint8Array([0xea, 0x00]);
// Multicodec G2-pub header (0xeb as varint = 0xeb00)
export const MULTICODEC_G2_PUBLIC_KEY_HEADER = new Uint8Array([0xeb, 0x00]);
// Multicodec (G1 + G2)-pub header (0xee as varint = 0xee00)
export const MULTICODEC_G1_G2_PUBLIC_KEY_HEADER = new Uint8Array([0xee, 0x00]);

// Multicodec G1-priv header (0x1309 as varint = 0x8926)
export const MULTICODEC_G1_SECRET_KEY_HEADER = new Uint8Array([0x89, 0x26]);
// Multicodec G2-priv header (0x130a as varint = 0x8a26)
export const MULTICODEC_G2_SECRET_KEY_HEADER = new Uint8Array([0x8a, 0x26]);
// Multicodec (G1 + G2)-priv header (0x130b as varint = 0x8b26)
export const MULTICODEC_G1_G2_SECRET_KEY_HEADER = new Uint8Array([0x8b, 0x26]);

// BLS12-381 curves
export const BLS12_381_CURVE = {
  G1: 'Bls12381G1',
  G2: 'Bls12381G2'
};

// BBS hash functions
export const BBS_HASH = {
  SHA256: 'SHA-256',
  SHAKE256: 'SHAKE-256'
};
