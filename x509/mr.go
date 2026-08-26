package x509

import (
	"bytes"
	goX509 "crypto/x509"
)

func MatchCertificateExact(valueDER, assertionDER []byte) bool {
	return bytes.Equal(valueDER, assertionDER)
}

func MatchCertificatePairExact(valueDER, assertionDER []byte) bool {
	return bytes.Equal(valueDER, assertionDER)
}

func MatchCRLExact(valueDER, assertionDER []byte) bool {
	return bytes.Equal(valueDER, assertionDER)
}

func MatchAlgorithmIdentifier(
	value AlgorithmIdentifier,
	assertion AlgorithmIdentifierAssertion,
) (eq bool) {
	if eq = bytes.Equal(value.OID, assertion.OID); eq {
		eq = bytes.Equal(value.Params, assertion.Params)
	}

	return
}

func MatchCertificateFields(cert *goX509.Certificate, a CertificateAssertion) bool {
	if a.IssuerDER != nil && !bytes.Equal(cert.RawIssuer, a.IssuerDER) {
		return false
	}
	if a.SerialDER != nil && !bytes.Equal(cert.SerialNumber.Bytes(), a.SerialDER) {
		return false
	}
	if a.SubjectDER != nil && !bytes.Equal(cert.RawSubject, a.SubjectDER) {
		return false
	}
	return true
}

func MatchCRLFields(crlDER []byte, a CRLAssertion) bool {
	if a.IssuerDER != nil {
		issuerDER, err := extractCRLIssuerDER(crlDER)
		if err != nil {
			return false
		}
		if !bytes.Equal(issuerDER, a.IssuerDER) {
			return false
		}
	}
	return true
}
