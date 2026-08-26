## x509

Package x509 implements LDAP syntaxes and matching rules derived from [RFC 4523](https://www.rfc-editor.org/rfc/rfc4523.html) and [ITU-T rec. X.509](https://www.itu.int/rec/T-REC-X.509).

This package is designed for use within the [go-directory](https://github.com/go-directory) suite.

## License

The x509 package is released under the terms of the MIT license. See the LICENSE file in the package directory.

### Implemented Standards

LDAP Syntaxes:

  - `1.3.6.1.4.1.1466.115.121.1.8` (Certificate)
  - `1.3.6.1.4.1.1466.115.121.1.9` (Certificate List)
  - `1.3.6.1.4.1.1466.115.121.1.10` (Certificate Pair)
  - `1.3.6.1.4.1.1466.115.121.1.49` (Supported Algorithm)
  - `1.3.6.1.1.15.1` (X.509 Certificate Exact Assertion)
  - `1.3.6.1.1.15.2` (X.509 Certificate Assertion)
  - `1.3.6.1.1.15.3` (X.509 Certificate Pair Exact Assertion))
  - `1.3.6.1.1.15.4` (X.509 Certificate Pair Assertion)
  - `1.3.6.1.1.15.5` (X.509 Certificate List Exact Assertion)
  - `1.3.6.1.1.15.6` (X.509 Certificate List Assertion)
  - `1.3.6.1.1.15.7` (X.509 Algorithm Identifier)

Matching Rules:

  - `2.5.13.34` (`certificateExactMatch`, per syntax `1.3.6.1.1.15.1`)
  - `2.5.13.35` (`certificateMatch`, per syntax `1.3.6.1.1.15.2`)
  - `2.5.13.36` (`certificatePairExactMatch`, per syntax `1.3.6.1.1.15.3`)
  - `2.5.13.37` (`certificatePairMatch`, per syntax `1.3.6.1.1.15.4`)
  - `2.5.13.38` (`certificateListExactMatch`, per syntax `1.3.6.1.1.15.5`)
  - `2.5.13.39` (`certificateListMatch`, per syntax `1.3.6.1.1.15.6`)
  - `2.5.13.40` (`algorithmIdentifierMatch`, per syntax `1.3.6.1.1.15.7`)

