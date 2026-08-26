package x509

import (
	"bytes"
)

type CertificateListAssertion struct {
	IssuerDER []byte
}

func ParseCertificateListAssertion(b []byte) (CertificateListAssertion, error) {
	t, err := ParseDER(b)
	if err != nil {
		return CertificateListAssertion{}, err
	}
	if t.Tag != 0x10 || !t.Constructed {
		return CertificateListAssertion{}, errNotSeq
	}

	var a CertificateListAssertion

	for _, c := range t.Children {
		if c.Class == TagContextSpecific && c.Tag == 0 && !c.Constructed {
			a.IssuerDER = c.Value
		}
	}

	return a, nil
}

func ParseCertificateListExactAssertion(b []byte) ([]byte, error) {
	t, err := ParseDER(b)
	if err != nil {
		return nil, err
	}
	if t.Tag != 0x04 || t.Constructed {
		return nil, errNotOct
	}
	return t.Value, nil
}

func MatchCertificateList(crlDER []byte, a CertificateListAssertion) bool {
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

func MatchCertificateListExact(crlDER, assertionDER []byte) bool {
	return bytes.Equal(crlDER, assertionDER)
}
