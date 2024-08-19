# @digitalbazaar/bls12-381-multikey ChangeLog

## 2.0.0 - 2024-08-dd

### Changed
- **BREAKING**: Use `@digitalbazaar/bbs-signatures@3` which is updated
  to the IETF BBS draft 6 spec. This version of the library will produce
  signatures that are incompatible with previous versions (and any previous
  signatures should now be considered obsolete and non-interoperable).

## 1.3.0 - 2024-04-11

### Added
- Enable use of `sign()` with `data` parameter that is a CBOR-encoded
  array of all of the required sign parameters (`header` and `messages`).

## 1.2.0 - 2024-03-17

### Added
- Add conversion from `publicKeyJwk` feature via `from()`.

### Fixed
- Allow `@context` array values in multikeys.

## 1.1.1 - 2024-01-11

### Fixed
- Fix bug with disclosing message with index zero that would cause it
  to not be included in the disclosed indexes array.

## 1.1.0 - 2024-01-11

### Added
- Include `publicKey` in signer interface to enable including it along with
  generated signatures for easier subsequent proof generation.
- Enable loading of keys when only the secret key is present.

## 1.0.0 - 2024-01-10

### Added
- Initial version.
