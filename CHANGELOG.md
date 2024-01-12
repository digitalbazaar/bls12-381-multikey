# @digitalbazaar/bls12-381-multikey ChangeLog

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
