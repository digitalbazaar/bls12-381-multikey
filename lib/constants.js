/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
export const ALGORITHMS = {
  BBS_BLS12381_SHAKE256: 'BBS-BLS12-381-SHAKE-256',
  BBS_BLS12381_SHA256: 'BBS-BLS12-381-SHA-256'
};

// Multikey context v1 URL
export const MULTIKEY_CONTEXT_V1_URL = 'https://w3id.org/security/multikey/v1';
export const MULTIBASE_BASE58_HEADER = 'z';

// Multicodec G1-pub header (0xea as varint = 0xea01)
export const MULTICODEC_G1_PUBLIC_KEY_HEADER = new Uint8Array([0xea, 0x01]);
// Multicodec G2-pub header (0xeb as varint = 0xeb01)
export const MULTICODEC_G2_PUBLIC_KEY_HEADER = new Uint8Array([0xeb, 0x01]);
// unused: Multicodec (G1 + G2)-pub header (0xee as varint = 0xee01)

// Multicodec G1-priv header (0x1309 as varint = 0x8926)
export const MULTICODEC_G1_SECRET_KEY_HEADER = new Uint8Array([0x89, 0x26]);
// Multicodec G2-priv header (0x130a as varint = 0x8a26)
export const MULTICODEC_G2_SECRET_KEY_HEADER = new Uint8Array([0x8a, 0x26]);
// unused: Multicodec (G1 + G2)-priv header (0x130b as varint = 0x8b26)

// BLS12-381 curves
export const BLS12_381_CURVE = {
  G1: 'Bls12381G1',
  G2: 'Bls12381G2'
};
