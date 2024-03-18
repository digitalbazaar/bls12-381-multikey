/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import * as Bls12381Multikey from '../lib/index.js';
import {blsJwk, jpaJwk, mockMultikey} from './mock-data.js';
import chai from 'chai';
import {exportKeyPair} from '../lib/serialize.js';
import {getNamedCurveFromPublicMultikey} from '../lib/helpers.js';
const should = chai.should();
const {expect} = chai;

const {ALGORITHMS} = Bls12381Multikey;

describe('Bls12381Multikey', () => {
  describe('module', () => {
    it('should have proper exports', async () => {
      expect(Bls12381Multikey).to.have.property('ALGORITHMS');
      expect(Bls12381Multikey).to.have.property('generateBbsKeyPair');
      expect(Bls12381Multikey).to.have.property('from');
      expect(Bls12381Multikey).to.have.property('fromJwk');
      expect(Bls12381Multikey).to.have.property('toJwk');
    });
  });

  for(const algorithm of Object.values(ALGORITHMS)) {
    describe(algorithm, () => {
      describe('algorithm', () => {
        it('signer() instance should export proper algorithm', async () => {
          const keyPair = await Bls12381Multikey.from(mockMultikey, {
            algorithm
          });
          const signer = keyPair.signer();
          signer.algorithm.should.equal(algorithm);
          signer.publicKey.should.be.a('Uint8Array');
        });

        it('verifier() instance should export proper algorithm', async () => {
          const keyPair = await Bls12381Multikey.from(mockMultikey, {
            algorithm
          });
          const verifier = keyPair.verifier();
          verifier.algorithm.should.equal(algorithm);
        });
      });

      describe('generateBbsKeyPair', () => {
        it('should generate a BBS key pair', async () => {
          let keyPair;
          let error;
          try {
            keyPair = await Bls12381Multikey.generateBbsKeyPair({
              algorithm
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(error);

          expect(keyPair).to.have.property('publicKeyMultibase');
          expect(keyPair).to.have.property('secretKeyMultibase');
          expect(keyPair).to.have.property('publicKey');
          expect(keyPair.publicKey).to.be.a('Uint8Array');
          expect(keyPair).to.have.property('secretKey');
          expect(keyPair.secretKey).to.be.a('Uint8Array');
          expect(keyPair).to.have.property('export');
          expect(keyPair).to.have.property('signer');
          expect(keyPair).to.have.property('verifier');
          expect(keyPair).to.have.property('algorithm');
          keyPair.algorithm.should.equal(algorithm);
          const secretKeyBytes = base58.decode(
            keyPair.secretKeyMultibase.slice(1));
          const publicKeyBytes = base58.decode(
            keyPair.publicKeyMultibase.slice(1));
          secretKeyBytes.length.should.equal(34);
          publicKeyBytes.length.should.equal(98);
        });
      });

      describe('export', () => {
        it('should export id, type, and key material', async () => {
          const keyPair = await Bls12381Multikey.generateBbsKeyPair({
            id: '4e0db4260c87cc200df3',
            controller: 'did:example:1234',
            algorithm
          });
          const keyPairExported = await keyPair.export({
            publicKey: true, secretKey: true
          });

          const expectedProperties = [
            'id', 'type', 'controller',
            'publicKeyMultibase', 'secretKeyMultibase'
          ];
          for(const property of expectedProperties) {
            expect(keyPairExported).to.have.property(property);
            expect(keyPairExported[property]).to.exist;
          }

          expect(keyPairExported.controller).to.equal('did:example:1234');
          expect(keyPairExported.type).to.equal('Multikey');
          expect(keyPairExported.id).to.equal('4e0db4260c87cc200df3');
        });

        it('should only export public key if specified', async () => {
          const keyPair = await Bls12381Multikey.generateBbsKeyPair({
            id: '4e0db4260c87cc200df3',
            algorithm
          });
          const keyPairExported = await keyPair.export({publicKey: true});

          expect(keyPairExported).not.to.have.property('secretKeyMultibase');
          expect(keyPairExported).to.have.property('publicKeyMultibase');
          expect(keyPairExported).to.have.property(
            'id', '4e0db4260c87cc200df3');
          expect(keyPairExported).to.have.property('type', 'Multikey');
        });

        it('should only export secret key if available', async () => {
          const keyPair = await Bls12381Multikey.generateBbsKeyPair({
            algorithm
          });
          delete keyPair.secretKey;

          const keyPairExported = await exportKeyPair({
            keyPair,
            publicKey: true,
            secretKey: true,
            includeContext: true
          });

          expect(keyPairExported).not.to.have.property('secretKeyMultibase');
        });

        it('should export raw public key', async () => {
          const keyPair = await Bls12381Multikey.generateBbsKeyPair({
            algorithm
          });
          const expectedPublicKey = base58.decode(
            keyPair.publicKeyMultibase.slice(1)).slice(2);
          const {publicKey} = await keyPair.export({
            publicKey: true, raw: true
          });
          expect(expectedPublicKey).to.deep.equal(publicKey);
        });

        it('should export raw secret key', async () => {
          const keyPair = await Bls12381Multikey.generateBbsKeyPair({
            algorithm
          });
          const expectedSecretKey = base58.decode(
            keyPair.secretKeyMultibase.slice(1)).slice(2);
          const {secretKey} = await keyPair.export({
            secretKey: true, raw: true
          });
          expect(expectedSecretKey).to.deep.equal(secretKey);
        });
      });

      describe('from', () => {
        it('should auto-set key.id based on controller', async () => {
          const {publicKeyMultibase} = mockMultikey;
          const keyPair = await Bls12381Multikey.from(mockMultikey);
          _ensurePublicKeyEncoding({keyPair, publicKeyMultibase});
          expect(keyPair.id).to.equal(`did:example:1234#${publicKeyMultibase}`);
        });

        it('should error if "publicKeyMultibase" is missing', async () => {
          let error;
          try {
            await Bls12381Multikey.from({});
          } catch(e) {
            error = e;
          }
          expect(error).to.be.an.instanceof(TypeError);
          expect(error.message).to.equal(
            'Either "publicKeyMultibase" or "secretKeyMultibase" ' +
            'are required.');
        });

        it('should round-trip load exported keys', async () => {
          const keyPair = await Bls12381Multikey.generateBbsKeyPair({
            id: '4e0db4260c87cc200df3',
            algorithm
          });
          const keyPairExported = await keyPair.export({
            publicKey: true, secretKey: true
          });
          const keyPairImported = await Bls12381Multikey.from(keyPairExported);

          expect(await keyPairImported.export({
            publicKey: true, secretKey: true
          })).to.eql(keyPairExported);
        });

        it('should import compressed `publicKeyJwk`', async () => {
          const keyPairImported = await Bls12381Multikey.from({
            publicKeyJwk: jpaJwk
          });
          const jwk = await Bls12381Multikey.toJwk(
            {keyPair: keyPairImported, secretKey: true});
          const expected = {
            kty: 'OKP',
            // algorithm is always SHA-256 here
            alg: ALGORITHMS.BBS_BLS12381_SHA256,
            crv: 'Bls12381G2',
            // eslint-disable-next-line max-len
            x: 'rMvXj_LibMeRrNh2sqmkBqBH4xKeOWmAYK8inVMX1839y6XeolnbT6vxnxU2PmV9FXJ-rtcz6Txe7v2ij1dFzMHuBT1TyBrtEZWtCSOMTIBXpnVsOMMSdhsTB1iUS9o1',
            d: 'GKvIQj_W51lezMe_U8-k0xd-vedyZK3gHDzONXkXf9I'
          };
          expect(jwk).to.eql(expected);
        });

        it('should import uncompressed `publicKeyJwk`', async () => {
          const keyPairImported = await Bls12381Multikey.from({
            publicKeyJwk: blsJwk
          });
          const jwk = await Bls12381Multikey.toJwk(
            {keyPair: keyPairImported, secretKey: true});
          const expected = {
            kty: 'OKP',
            // algorithm is always SHA-256 here
            alg: ALGORITHMS.BBS_BLS12381_SHA256,
            crv: 'Bls12381G2',
            // eslint-disable-next-line max-len
            x: 'gjs8lstTgoTgXMF6QXdyh3m8k2ixxURGYLMaYylVK_x0F8HhE8zk0YWiGV3CHwpQEa2sH4PBZLaYCn8se-1clmCORDsKxbbw3Js_Alu4OmkV9gmbJsy1YF2rt7Vxzs6S',
            d: 'Q4XJCL-sIV3v9lDpWblvIhrkicH5JBnMyMFTGX-HHoU'
          };
          expect(jwk).to.eql(expected);
        });
      });

      describe('fromJwk/toJwk', () => {
        it('should round-trip secret JWKs', async () => {
          const keyPair = await Bls12381Multikey.generateBbsKeyPair({
            id: '4e0db4260c87cc200df3',
            algorithm
          });
          const jwk1 = await Bls12381Multikey.toJwk({keyPair, secretKey: true});
          should.exist(jwk1.d);
          const keyPairImported = await Bls12381Multikey.fromJwk(
            {jwk: jwk1, secretKey: true});
          const jwk2 = await Bls12381Multikey.toJwk(
            {keyPair: keyPairImported, secretKey: true});
          expect(jwk1).to.eql(jwk2);
        });

        it('should round-trip public JWKs', async () => {
          const keyPair = await Bls12381Multikey.generateBbsKeyPair({
            id: '4e0db4260c87cc200df3',
            algorithm
          });
          const jwk1 = await Bls12381Multikey.toJwk({keyPair});
          should.not.exist(jwk1.d);
          const keyPairImported = await Bls12381Multikey.fromJwk({jwk: jwk1});
          const jwk2 = await Bls12381Multikey.toJwk({keyPair: keyPairImported});
          expect(jwk1).to.eql(jwk2);
        });

        it('should multikey-round-trip secret JWKs', async () => {
          const keyPair = await Bls12381Multikey.generateBbsKeyPair({
            id: '4e0db4260c87cc200df3',
            algorithm
          });
          const jwk1 = await Bls12381Multikey.toJwk({keyPair, secretKey: true});
          should.exist(jwk1.d);
          const keyPairImported = await Bls12381Multikey.fromJwk(
            {jwk: jwk1, secretKey: true});
          const multikey = await keyPairImported.export({
            publicKey: true, secretKey: true, includeContext: true
          });
          const multikeyImported = await Bls12381Multikey.from(multikey, {
            algorithm
          });
          const jwk2 = await Bls12381Multikey.toJwk(
            {keyPair: multikeyImported, secretKey: true});
          expect(jwk1).to.eql(jwk2);
        });

        it('should multikey-round-trip public JWKs', async () => {
          const keyPair = await Bls12381Multikey.generateBbsKeyPair({
            id: '4e0db4260c87cc200df3',
            algorithm
          });
          const jwk1 = await Bls12381Multikey.toJwk({keyPair});
          should.not.exist(jwk1.d);
          const keyPairImported = await Bls12381Multikey.fromJwk({jwk: jwk1});
          const multikey = await keyPairImported.export({
            publicKey: true, includeContext: true
          });
          const multikeyImported = await Bls12381Multikey.from(multikey, {
            algorithm
          });
          const jwk2 = await Bls12381Multikey.toJwk({
            keyPair: multikeyImported
          });
          expect(jwk1).to.eql(jwk2);
        });

        it('should import JWK with compressed public key', async () => {
          const keyPairImported = await Bls12381Multikey.fromJwk(
            {jwk: jpaJwk, secretKey: true});
          const jwk = await Bls12381Multikey.toJwk(
            {keyPair: keyPairImported, secretKey: true});
          const expected = {
            kty: 'OKP',
            // algorithm is always SHA-256 here
            alg: ALGORITHMS.BBS_BLS12381_SHA256,
            crv: 'Bls12381G2',
            // eslint-disable-next-line max-len
            x: 'rMvXj_LibMeRrNh2sqmkBqBH4xKeOWmAYK8inVMX1839y6XeolnbT6vxnxU2PmV9FXJ-rtcz6Txe7v2ij1dFzMHuBT1TyBrtEZWtCSOMTIBXpnVsOMMSdhsTB1iUS9o1',
            d: 'GKvIQj_W51lezMe_U8-k0xd-vedyZK3gHDzONXkXf9I'
          };
          expect(jwk).to.eql(expected);
        });

        it('should import JWK with uncompressed public key', async () => {
          const keyPairImported = await Bls12381Multikey.fromJwk(
            {jwk: blsJwk, secretKey: true});
          const jwk = await Bls12381Multikey.toJwk(
            {keyPair: keyPairImported, secretKey: true});
          const expected = {
            kty: 'OKP',
            // algorithm is always SHA-256 here
            alg: ALGORITHMS.BBS_BLS12381_SHA256,
            crv: 'Bls12381G2',
            // eslint-disable-next-line max-len
            x: 'gjs8lstTgoTgXMF6QXdyh3m8k2ixxURGYLMaYylVK_x0F8HhE8zk0YWiGV3CHwpQEa2sH4PBZLaYCn8se-1clmCORDsKxbbw3Js_Alu4OmkV9gmbJsy1YF2rt7Vxzs6S',
            d: 'Q4XJCL-sIV3v9lDpWblvIhrkicH5JBnMyMFTGX-HHoU'
          };
          expect(jwk).to.eql(expected);
        });
      });

      describe('fromRaw', () => {
        it(`should import raw public key`, async () => {
          const keyPair = await Bls12381Multikey.generateBbsKeyPair({
            algorithm
          });

          // first export
          const expectedPublicKey = base58.decode(
            keyPair.publicKeyMultibase.slice(1)).slice(2);
          const {publicKey} = await keyPair.export({
            publicKey: true, raw: true
          });
          expect(expectedPublicKey).to.deep.equal(publicKey);

          // then import
          const imported = await Bls12381Multikey.fromRaw({
            algorithm, publicKey
          });

          // then re-export to confirm
          const {publicKey: publicKey2} = await imported.export(
            {publicKey: true, raw: true});
          expect(expectedPublicKey).to.deep.equal(publicKey2);
        });

        it(`should import raw secret key`, async () => {
          const keyPair = await Bls12381Multikey.generateBbsKeyPair({
            algorithm
          });

          // first export
          const expectedSecretKey = base58.decode(
            keyPair.secretKeyMultibase.slice(1)).slice(2);
          const {secretKey, publicKey} = await keyPair.export(
            {secretKey: true, raw: true});
          expect(expectedSecretKey).to.deep.equal(secretKey);

          // then import
          const imported = await Bls12381Multikey.fromRaw({
            algorithm, secretKey, publicKey
          });

          // then re-export to confirm
          const {secretKey: secretKey2} = await imported.export(
            {secretKey: true, raw: true});
          expect(expectedSecretKey).to.deep.equal(secretKey2);
        });
      });
    });
  }
});

function _ensurePublicKeyEncoding({keyPair, publicKeyMultibase}) {
  keyPair.publicKeyMultibase.startsWith('z').should.be.true;
  publicKeyMultibase.startsWith('z').should.be.true;
  const decodedPubkey = base58.decode(publicKeyMultibase.slice(1));
  const curve = getNamedCurveFromPublicMultikey({
    publicMultikey: decodedPubkey
  });
  curve.should.equal('Bls12381G2');
  const encodedPubkey = 'z' + base58.encode(decodedPubkey);
  encodedPubkey.should.equal(keyPair.publicKeyMultibase);
}
