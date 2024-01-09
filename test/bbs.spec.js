/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as chai from 'chai';
import {
  create_generators, messages_to_scalars, mocked_calculate_random_scalars
} from '../lib/bbs/util.js';
import {ProofGen, Sign, Verify} from '../lib/bbs/interface.js';
import {CIPHERSUITES_TEST_VECTORS} from './bbs-test-vectors.js';
chai.should();

const OPERATIONS = {
  create_generators, messages_to_scalars, mocked_calculate_random_scalars,
  Sign, ProofGen, Verify
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
