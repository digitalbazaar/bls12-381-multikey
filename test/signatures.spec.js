/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as Bls12381Multikey from '../lib/index.js';
import * as cborg from 'cborg';
import chai from 'chai';
import {mockMultikey} from './mock-data.js';
import {stringToUint8Array} from './text-encoder.js';
chai.should();
const {expect} = chai;

describe('signatures', async () => {
  for(const algorithm of Object.values(Bls12381Multikey.ALGORITHMS)) {
    const keyPair = await Bls12381Multikey.from({
      controller: 'did:example:1234',
      ...mockMultikey
    }, {algorithm});
    const signer = keyPair.signer();
    const verifier = keyPair.verifier();

    describe(algorithm, () => {
      it('has proper signature format', async () => {
        const header = new Uint8Array();
        const messages = [
          stringToUint8Array('first message'),
          stringToUint8Array('second message')
        ];
        const signature = await signer.multisign({header, messages});
        expect(signature).to.be.instanceof(Uint8Array);
      });

      it('can use CBOR-encoded "data" in sign()', async () => {
        const header = new Uint8Array();
        const messages = [
          stringToUint8Array('first message'),
          stringToUint8Array('second message')
        ];
        const data = cborg.encode([header, messages]);
        const signature = await signer.sign({data});
        expect(signature).to.be.instanceof(Uint8Array);
      });

      it('fails with incorrect CBOR-encoded "data" in sign()', async () => {
        const header = new Uint8Array();
        const messages = [
          stringToUint8Array('first message'),
          stringToUint8Array('second message')
        ];
        const data = cborg.encode([header, messages, 'something else']);

        let error;
        try {
          await signer.sign({data});
        } catch(e) {
          error = e;
        }
        expect(error).to.be.an.instanceof(Error);
        expect(error.message).to.equal(
          'Sign "data" must be a CBOR-encoded array with two parameters: ' +
          'the BBS "header" and BBS "messages".');
      });

      it('should sign=>derive=>verify w/full message disclosure', async () => {
        signer.algorithm.should.eql(algorithm);
        signer.should.have.property(
          'id',
          'did:example:1234#' + mockMultikey.publicKeyMultibase);
        verifier.algorithm.should.eql(algorithm);
        verifier.should.have.property(
          'id',
          'did:example:1234#' + mockMultikey.publicKeyMultibase);
        const header = new Uint8Array();
        const messages = [
          stringToUint8Array('first message'),
          stringToUint8Array('second message')
        ];
        const signature = await signer.multisign({header, messages});
        const presentationHeader = new Uint8Array();
        const proof = await keyPair.deriveProof({
          signature, header, messages, presentationHeader,
          disclosedMessageIndexes: [0, 1]
        });
        const result = await verifier.multiverify({
          proof, header, presentationHeader, messages
        });
        result.should.be.true;
      });

      it('should use CBOR-encoded sign()=>derive=>verify', async () => {
        signer.algorithm.should.eql(algorithm);
        signer.should.have.property(
          'id',
          'did:example:1234#' + mockMultikey.publicKeyMultibase);
        verifier.algorithm.should.eql(algorithm);
        verifier.should.have.property(
          'id',
          'did:example:1234#' + mockMultikey.publicKeyMultibase);
        const header = new Uint8Array();
        const messages = [
          stringToUint8Array('first message'),
          stringToUint8Array('second message')
        ];
        const data = cborg.encode([header, messages]);
        const signature = await signer.sign({data});
        const presentationHeader = new Uint8Array();
        const proof = await keyPair.deriveProof({
          signature, header, messages, presentationHeader,
          disclosedMessageIndexes: [0, 1]
        });
        const result = await verifier.multiverify({
          proof, header, presentationHeader, messages
        });
        result.should.be.true;
      });

      it('should sign=>derive=>verify w/message[0] disclosure', async () => {
        signer.algorithm.should.eql(algorithm);
        signer.should.have.property(
          'id',
          'did:example:1234#' + mockMultikey.publicKeyMultibase);
        verifier.algorithm.should.eql(algorithm);
        verifier.should.have.property(
          'id',
          'did:example:1234#' + mockMultikey.publicKeyMultibase);
        const header = new Uint8Array();
        const messages = [
          stringToUint8Array('first message'),
          stringToUint8Array('second message')
        ];
        const signature = await signer.multisign({header, messages});
        const presentationHeader = new Uint8Array();
        const proof = await keyPair.deriveProof({
          signature, header, messages, presentationHeader,
          disclosedMessageIndexes: [0]
        });
        const result = await verifier.multiverify({
          proof, header, presentationHeader, messages: [messages[0]]
        });
        result.should.be.true;
      });

      it('should sign=>derive=>verify w/message[1] disclosure', async () => {
        signer.algorithm.should.eql(algorithm);
        signer.should.have.property(
          'id',
          'did:example:1234#' + mockMultikey.publicKeyMultibase);
        verifier.algorithm.should.eql(algorithm);
        verifier.should.have.property(
          'id',
          'did:example:1234#' + mockMultikey.publicKeyMultibase);
        const header = new Uint8Array();
        const messages = [
          stringToUint8Array('first message'),
          stringToUint8Array('second message')
        ];
        const signature = await signer.multisign({header, messages});
        const presentationHeader = new Uint8Array();
        const proof = await keyPair.deriveProof({
          signature, header, messages, presentationHeader,
          disclosedMessageIndexes: [1]
        });
        const result = await verifier.multiverify({
          proof, header, presentationHeader, messages: [undefined, messages[1]]
        });
        result.should.be.true;
      });

      it('fails if signed data is changed', async () => {
        const header = new Uint8Array();
        const messages = [
          stringToUint8Array('first message'),
          stringToUint8Array('second message')
        ];
        const signature = await signer.multisign({header, messages});
        const presentationHeader = new Uint8Array();
        const proof = await keyPair.deriveProof({
          signature, header, messages, presentationHeader,
          disclosedMessageIndexes: [1]
        });
        const result = await verifier.multiverify({
          proof, header, presentationHeader,
          messages: [undefined, stringToUint8Array('different')]
        });
        result.should.be.false;
      });
    });
  }
});
