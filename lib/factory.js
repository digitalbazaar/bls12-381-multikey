/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bbs from '@digitalbazaar/bbs-signatures';

// exposes sign method
export function createBbsSigner({id, secretKey, ciphersuite}) {
  if(!secretKey) {
    throw new Error('"secretKey" is required for signing.');
  }
  return {
    algorithm: 'BBS-' + ciphersuite,
    id,
    async multisign({header, messages} = {}) {
      return bbs.sign({secretKey, header, messages, ciphersuite});
    },
    async sign() {
      throw new Error('"sign()" not implemented; use "multisign()".');
    }
  };
}

// exposes verify method
export function createBbsVerifier({id, publicKey, ciphersuite}) {
  if(!publicKey) {
    throw new Error('"publicKey" is required for verifying.');
  }
  return {
    algorithm: 'BBS-' + ciphersuite,
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
