/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {ProofGen, Sign} from '../lib/bbs/interface.js';
import chai from 'chai';
import {CIPHERSUITES_TEST_VECTORS} from './bbs-test-vectors.js';
chai.should();

const OPERATIONS = {Sign, ProofGen};

describe.only('BBS test vectors', () => {
  for(const tv of CIPHERSUITES_TEST_VECTORS) {
    const {ciphersuite, fixtures} = tv;
    describe(ciphersuite.name, () => {
      for(const {name, operation, parameters, output} of fixtures) {
        it(name, async () => {
          const op = OPERATIONS[operation];
          if(!op) {
            throw new Error(`Unknown operation "${operation}".`);
          }
          const result = await op({...parameters, ciphersuite});
          result.deep.equal(output);
        });
      }
    });
  }
});
