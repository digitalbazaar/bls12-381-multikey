/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bbs from '@digitalbazaar/bbs-signatures';
import * as cborg from 'cborg';

// exposes sign method
export function createBbsSigner({id, secretKey, publicKey, algorithm}) {
  if(!secretKey) {
    throw new Error('"secretKey" is required for signing.');
  }
  const ciphersuite = algorithm.slice('BBS-'.length);
  const multisign = async function({header, messages} = {}) {
    return bbs.sign({secretKey, publicKey, header, messages, ciphersuite});
  };
  return {
    algorithm,
    id,
    // include public key in signer interface so it can be included with
    // base proofs for easier selective disclosure
    publicKey,
    multisign,
    async sign({data} = {}) {
      // CBOR-decode data into an array of parameters
      const params = cborg.decode(data);
      if(params.length !== 2) {
        throw new Error(
          'Sign "data" must be a CBOR-encoded array with two parameters: ' +
          'the BBS "header" and BBS "messages".');
      }
      const [header, messages] = params;
      return multisign({header, messages});
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
        .filter(m => m !== undefined);
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
