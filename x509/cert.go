package x509

import (
	goX509 "crypto/x509"
	"crypto/x509/pkix"
)

func ParseCertificateDER(b []byte) (*goX509.Certificate, error) {
	return goX509.ParseCertificate(b)
}

func ParseCRLDER(b []byte) (*pkix.CertificateList, error) {
	return goX509.ParseCRL(b)
}
