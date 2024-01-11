/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as Bls12381Multikey from '../lib/index.js';
import chai from 'chai';
import {mockMultikey} from './mock-data.js';
import {stringToUint8Array} from './text-encoder.js';
chai.should();
const {expect} = chai;

const keyPair = await Bls12381Multikey.from({
  controller: 'did:example:1234',
  ...mockMultikey
});
const signer = keyPair.signer();
const verifier = keyPair.verifier();

describe('signatures', () => {
  it('has proper signature format', async () => {
    const header = new Uint8Array();
    const messages = [
      stringToUint8Array('first message'),
      stringToUint8Array('second message')
    ];
    const signature = await signer.multisign({header, messages});
    expect(signature).to.be.instanceof(Uint8Array);
  });

  it('multisign, deriveBbsProof, and multiverify works properly', async () => {
    signer.should.have.property(
      'id',
      'did:example:1234#' + mockMultikey.publicKeyMultibase);
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
