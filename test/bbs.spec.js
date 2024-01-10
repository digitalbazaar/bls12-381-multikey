/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  create_generators, messages_to_scalars, mocked_calculate_random_scalars
} from '../lib/bbs/util.js';
import {ProofGen, ProofVerify, Sign, Verify} from '../lib/bbs/interface.js';
import chai from 'chai';
import {CIPHERSUITES_TEST_VECTORS} from './bbs-test-vectors.js';
chai.should();

const OPERATIONS = {
  create_generators, messages_to_scalars, mocked_calculate_random_scalars,
  ProofGen, ProofGenAndProofVerify, ProofVerify, Sign, Verify
};

describe.only('BBS test vectors', () => {
  const only = CIPHERSUITES_TEST_VECTORS.filter(tv => {
    return tv.fixtures.some(({only}) => only);
  });
  const testCiphersuites = only.length > 0 ? only : CIPHERSUITES_TEST_VECTORS;
  for(const tv of testCiphersuites) {
    const {ciphersuite, fixtures} = tv;
    describe(ciphersuite.name, () => {
      const only = fixtures.filter(({only}) => only);
      const tests = only.length > 0 ? only : fixtures;
      for(const {name, operation, parameters, output} of tests) {
        const op = OPERATIONS[operation];
        if(!op) {
          throw new Error(`Unknown operation "${operation}".`);
        }
        it(operation + ' - ' + name, async () => {
          const result = await op({...parameters, ciphersuite});
          result.should.deep.eql(output);
        });
      }
    });
  }
});

// runs `ProofGen` and then `ProofVerify` on the result
async function ProofGenAndProofVerify({
  PK, signature,
  header = new Uint8Array(),
  ph = new Uint8Array(),
  messages = [], disclosed_indexes = [],
  ciphersuite, mocked_random_scalars_options
} = {}) {
  const [proof, mocked_proof] = await Promise.all([
    ProofGen({
      PK, signature, header, ph, messages, disclosed_indexes, ciphersuite,
    }),
    ProofGen({
      PK, signature, header, ph, messages, disclosed_indexes, ciphersuite,
      mocked_random_scalars_options
    })
  ]);
  // `proof` must not equal `mocked proof`
  proof.should.not.deep.eql(mocked_proof);
  const disclosed_indexes_set = new Set(disclosed_indexes);
  const disclosed_messages = messages.filter(
    (m, i) => disclosed_indexes_set.has(i));
  return ProofVerify({
    PK, proof, header, ph, disclosed_messages, disclosed_indexes, ciphersuite
  });
}
