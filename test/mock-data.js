/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
// note: this multikey has the same key material as `jpaJwk` below
export const mockMultikey = {
  type: 'Multikey',
  controller: 'did:example:1234',
  // eslint-disable-next-line max-len
  publicKeyMultibase: 'zUC7CeW6j5qisFaD8pAoWyvwuqso2E5WYSGeLFYQEmamVdf87AbE2kXakiYkRkDCKD3Z1Ma8qDrCpjNHA1HG93wA6BmrgRRX9ixGqfxGCv4m8FMSmrypZtoiV7UYxD74TQDeMad',
  secretKeyMultibase: 'z488ujFYX3ZK6PS9pPiSdppbeNhbxeBVNZHpChXVRULn5gtb'
};

/* eslint-disable */
// compressed public key (and big endian `d`) from:
// https://www.ietf.org/archive/id/draft-ietf-jose-json-proof-algorithms-02.html
export const jpaJwk = {
  "kty": "OKP",
  "alg": "BBS-DRAFT-3",
  "use": "proof",
  "crv": "Bls12381G2",
  "x": "rMvXj_LibMeRrNh2sqmkBqBH4xKeOWmAYK8inVMX1839y6XeolnbT6vxnxU2PmV9FXJ-rtcz6Txe7v2ij1dFzMHuBT1TyBrtEZWtCSOMTIBXpnVsOMMSdhsTB1iUS9o1",
  "d": "GKvIQj_W51lezMe_U8-k0xd-vedyZK3gHDzONXkXf9I"
};
// uncompressed public key (and little endian `d`) from:
// https://www.ietf.org/archive/id/draft-ietf-cose-bls-key-representations-03.html
export const blsJwk = {
  "kty": "OKP",
  "crv": "Bls12381G2",
  "x": "Ajs8lstTgoTgXMF6QXdyh3m8k2ixxURGYLMaYylVK_x0F8HhE8zk0YWiGV3CHwpQEa2sH4PBZLaYCn8se-1clmCORDsKxbbw3Js_Alu4OmkV9gmbJsy1YF2rt7Vxzs6S",
  "y": "BVkkrVEib-P_FMPHNtqxJymP3pV-H8fCdvPkoWInpFfM9tViyqD8JAmwDf64zU2hBV_vvCQ632ScAooEExXuz1IeQH9D2o-uY_dAjZ37YHuRMEyzh8Tq-90JHQvicOqx",
  "d": "hR6HfxlTwcjMGST5wYnkGiJvuVnpUPbvXSGsvwjJhUM"
};
/* eslint-enable */
