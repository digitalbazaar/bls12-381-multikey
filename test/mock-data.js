/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
// note: this multikey has the same key material as `jpaJwk` below
export const mockMultikey = {
  '@context': 'https://w3id.org/security/multikey/v1',
  type: 'Multikey',
  controller: 'did:example:1234',
  // eslint-disable-next-line max-len
  publicKeyMultibase: 'zUC7GMwWWkA5UMTx7Gg6sabmpchWgq8p1xGhUXwBiDytY8BgD6eq5AmxNgjwDbAz8Rq6VFBLdNjvXR4ydEdwDEN9L4vGFfLkxs8UsU3wQj9HQGjQb7LHWdRNJv3J1kGoA3BvnBv',
  secretKeyMultibase: 'z488vexJQSQ2rF5GrCT8qhzGR7ASSj5rx6CtZjKNFq183woF'
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

/* example of BBS-BLS12-381-SHAKE-256 key in multikey + JWK format
export const mockMultikeyShake256 = {
  '@context': 'https://w3id.org/security/multikey/v1',
  type: 'Multikey',
  controller: 'did:example:1234',
  // eslint-disable-next-line max-len
  publicKeyMultibase: 'zUC76eySqgji6uNDaCrsWnmQnwq8pj1MZUDrRGc2BGRu61baZPKPFB7YpHawussp2YohcEMAeMVGHQ9JtKvjxgGTkYSMN53ZfCH4pZ6TGYLawvzy1wE54dS6PQcut9fxdHH32gi',
  secretKeyMultibase: 'z488x5kHU9aUe1weTqaf2sGFPgQS1HhunREFwB9bFeFwLch5',
};
export const shake256Jwk = {
  kty: 'OKP',
  alg: 'BBS-BLS12-381-SHAKE-256',
  crv: 'Bls12381G2',
  x: 'kJ59sxOk7HYiZOp6yjH4fjgF4lk1ImT7GfDEP1_imjDQo2oE0kw4SIDnvJBMLCVoAUQi5dlxCLmsp35xedaw1C11WvlSFhkVxwCy3AjmqJsvxvFiaj2hQaSjaHkG_0nz',
  d: 'LeFnGNo5fCsCHk6-COdjU7V5n-_k86MSYoAJFLhjOlg'
}
*/
/* eslint-enable */
