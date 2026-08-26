package x509

import (
	"bytes"
	goX509 "crypto/x509"
	_ "embed"
	"encoding/pem"
	"testing"
)

//go:embed testdata/test_cert.pem
var testCert []byte

//go:embed testdata/test_crl.pem
var testCRL []byte

// SEQUENCE { <content> }
func seq(content ...[]byte) []byte {
	out := []byte{0x30} // SEQUENCE, constructed
	length := 0
	for _, c := range content {
		length += len(c)
	}
	out = append(out, byte(length))
	for _, c := range content {
		out = append(out, c...)
	}
	return out
}

// Context-specific [tag] containing a primitive value
func ctx(tag byte, val []byte) []byte {
	// [tag], primitive
	header := []byte{0x80 | tag, byte(len(val))}
	return append(header, val...)
}

func ctxPrim(tag byte, val []byte) []byte {
	return append([]byte{0x80 | tag, byte(len(val))}, val...)
}

func ctxSeq(tag byte, content ...[]byte) []byte {
	s := seq(content...)
	return append([]byte{0xA0 | tag, byte(len(s))}, s...)
}

// Primitive OID
func oid(bytes ...byte) []byte {
	return append([]byte{0x06, byte(len(bytes))}, bytes...)
}

// Primitive OCTET STRING
func octets(bytes ...byte) []byte {
	return append([]byte{0x04, byte(len(bytes))}, bytes...)
}

func TestParseDER_SimpleSequence(t *testing.T) {
	b := seq(
		octets(0x01, 0x02),
		octets(0x03),
	)

	tlv, err := ParseDER(b)
	if err != nil {
		t.Fatal(err)
	}

	if tlv.Tag != 0x10 || !tlv.Constructed {
		t.Fatalf("expected SEQUENCE")
	}
	if len(tlv.Children) != 2 {
		t.Fatalf("expected 2 children")
	}
}

func TestParseCertificatePair(t *testing.T) {
	forward := octets(0xAA)
	reverse := octets(0xBB)

	b := seq(
		ctxSeq(0, forward),
		ctxSeq(1, reverse),
	)

	cp, err := ParseCertificatePair(b)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(cp.ForwardDER, forward) {
		t.Fatalf("forward mismatch")
	}
	if !bytes.Equal(cp.ReverseDER, reverse) {
		t.Fatalf("reverse mismatch")
	}
}

func TestParseAlgorithmIdentifier(t *testing.T) {
	algOID := oid(0x2A, 0x03) // synthetic OID
	params := octets(0x99)

	b := seq(algOID, params)

	ai, err := ParseAlgorithmIdentifier(b)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(ai.OID, algOID[2:]) {
		t.Fatalf("OID mismatch")
	}
	if !bytes.Equal(ai.Params, params[2:]) {
		t.Fatalf("params mismatch")
	}
}

func TestParseCertificateAssertion(t *testing.T) {
	issuer := octets(0x01)
	serial := octets(0x02)
	subject := octets(0x03)

	b := seq(
		ctxPrim(0, issuer[2:]),
		ctxPrim(1, serial[2:]),
		ctxPrim(2, subject[2:]),
	)

	ca, err := ParseCertificateAssertion(b)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(ca.IssuerDER, issuer[2:]) {
		t.Fatalf("issuer mismatch")
	}
	if !bytes.Equal(ca.SerialDER, serial[2:]) {
		t.Fatalf("serial mismatch")
	}
	if !bytes.Equal(ca.SubjectDER, subject[2:]) {
		t.Fatalf("subject mismatch")
	}
}

func TestParseCRLAssertion(t *testing.T) {
	issuer := octets(0xAB)

	b := seq(
		ctxPrim(0, issuer[2:]),
	)

	ca, err := ParseCRLAssertion(b)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(ca.IssuerDER, issuer[2:]) {
		t.Fatalf("issuer mismatch")
	}
}

func TestMatchCertificateExact(t *testing.T) {
	a := []byte{0x01, 0x02}
	b := []byte{0x01, 0x02}
	c := []byte{0x03}

	if !MatchCertificateExact(a, b) {
		t.Fatalf("expected exact match")
	}
	if MatchCertificateExact(a, c) {
		t.Fatalf("unexpected match")
	}
}

func TestMatchAlgorithmIdentifier(t *testing.T) {
	v := AlgorithmIdentifier{
		OID:    []byte{0x2A},
		Params: []byte{0x99},
	}
	a := AlgorithmIdentifierAssertion{
		OID:    []byte{0x2A},
		Params: []byte{0x99},
	}
	b := AlgorithmIdentifierAssertion{
		OID:    []byte{0x2A},
		Params: []byte{0x01},
	}

	if !MatchAlgorithmIdentifier(v, a) {
		t.Fatalf("expected match")
	}
	if MatchAlgorithmIdentifier(v, b) {
		t.Fatalf("unexpected match")
	}
}

func derFromPEM(pemData []byte) []byte {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil
	}
	return block.Bytes
}

func TestParseCertificateDER(t *testing.T) {
	der := derFromPEM(testCert)
	if der == nil {
		t.Fatal("no cert PEM block")
	}

	cert, err := ParseCertificateDER(der)
	if err != nil {
		t.Fatalf("ParseCertificateDER: %v", err)
	}
	if cert.Raw == nil || len(cert.Raw) == 0 {
		t.Fatalf("empty Raw cert")
	}
}

func TestParseCRLDER(t *testing.T) {
	der := derFromPEM(testCRL)
	if der == nil {
		t.Fatal("no CRL PEM block")
	}

	crl, err := ParseCRLDER(der)
	if err != nil {
		t.Fatalf("ParseCRLDER: %v", err)
	}
	if crl.TBSCertList.Raw == nil || len(crl.TBSCertList.Raw) == 0 {
		t.Fatalf("empty TBSCertList")
	}
}

func TestMatchCertificateFields(t *testing.T) {
	der := derFromPEM(testCert)
	if der == nil {
		t.Fatal("no cert PEM block")
	}

	cert, err := goX509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("crypto/x509.ParseCertificate: %v", err)
	}

	a := CertificateAssertion{
		IssuerDER:  cert.RawIssuer,
		SerialDER:  cert.SerialNumber.Bytes(),
		SubjectDER: cert.RawSubject,
	}

	if !MatchCertificateFields(cert, a) {
		t.Fatalf("expected MatchCertificateFields to succeed")
	}

	a.IssuerDER = []byte{0x00}
	if MatchCertificateFields(cert, a) {
		t.Fatalf("expected issuer mismatch")
	}
}

func TestMatchCRLFields(t *testing.T) {
	der := derFromPEM(testCRL)
	if der == nil {
		t.Fatal("no CRL PEM block")
	}

	issuerDER, err := extractCRLIssuerDER(der)
	if err != nil {
		t.Fatal(err)
	}

	a := CRLAssertion{
		IssuerDER: issuerDER,
	}

	if !MatchCRLFields(der, a) {
		t.Fatalf("expected issuer match")
	}

	a.IssuerDER = []byte{0x00}
	if MatchCRLFields(der, a) {
		t.Fatalf("expected issuer mismatch")
	}
}
