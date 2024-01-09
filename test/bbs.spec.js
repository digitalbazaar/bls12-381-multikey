/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as chai from 'chai';
import {ProofGen, Sign} from '../lib/bbs/interface.js';
import {CIPHERSUITES_TEST_VECTORS} from './bbs-test-vectors.js';
chai.should();

const OPERATIONS = {Sign, ProofGen};

describe.only('BBS test vectors', () => {
  for(const tv of CIPHERSUITES_TEST_VECTORS) {
    const {ciphersuite, fixtures} = tv;
    describe(ciphersuite.name, () => {
      const only = fixtures.filter(({only}) => only);
      const tests = only.length > 0 ? only : fixtures;
      for(const {name, operation, parameters, output} of tests) {
        it(name, async () => {
          const op = OPERATIONS[operation];
          if(!op) {
            throw new Error(`Unknown operation "${operation}".`);
          }
          const result = await op({...parameters, ciphersuite});
          result.should.deep.eql(output);
        });
      }
    });
  }
});
