/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bbs from '@digitalbazaar/bbs-signatures';

// exposes sign method
export function createBbsSigner({id, secretKey, publicKey, algorithm}) {
  if(!secretKey) {
    throw new Error('"secretKey" is required for signing.');
  }
  const ciphersuite = algorithm.slice('BBS-'.length);
  return {
    algorithm,
    id,
    // include public key in signer interface so it can be included with
    // base proofs for easier selective disclosure
    publicKey,
    async multisign({header, messages} = {}) {
      return bbs.sign({secretKey, publicKey, header, messages, ciphersuite});
    },
    async sign() {
      throw new Error('"sign()" not implemented; use "multisign()".');
    }
  };
}

// exposes verify method
export function createBbsVerifier({id, publicKey, algorithm}) {
  if(!publicKey) {
    throw new Error('"publicKey" is required for verifying.');
  }
  const ciphersuite = algorithm.slice('BBS-'.length);
  return {
    algorithm,
    id,
    async multiverify({proof, header, presentationHeader, messages} = {}) {
      // `messages` can be a sparse array
      const disclosedMessageIndexes = messages
        .map((m, i) => m ? i : undefined)
        .filter(m => m);
      const disclosedMessages = messages.filter(m => m);
      return bbs.verifyProof({
        publicKey, proof, header,
        presentationHeader, disclosedMessages, disclosedMessageIndexes,
        ciphersuite
      });
    },
    async verify() {
      throw new Error('"verify()" not implemented; use "multiverify()".');
    }
  };
}
