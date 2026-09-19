package syntax

/*
x509.go implements types, syntaxes and matching rules
per RFC 4523.
*/

import (
	"bytes"
	goX509 "crypto/x509"
	"crypto/x509/pkix"
	"errors"

	"github.com/go-directory/encoding/asn1"
)

func parseX509(b []byte) (asn1.TLV, int, error) {
	if len(b) < 2 {
		return asn1.TLV{}, 0, errShortDER
	}

	tagByte := b[0]

	class := int((tagByte & 0xC0) >> 6)
	constructed := (tagByte & 0x20) != 0
	tagNum := int(tagByte & 0x1F)

	if tagNum == 0x1F {
		return asn1.TLV{}, 0, errHighTag
	}

	l := b[1]
	var length int
	var offset int

	if l < 0x80 {
		length = int(l)
		offset = 2
	} else {
		n := int(l & 0x7F)
		if n == 0 || n > 4 {
			return asn1.TLV{}, 0, errTLVLen
		}
		if len(b) < 2+n {
			return asn1.TLV{}, 0, errShortDER
		}
		length = 0
		for i := 0; i < n; i++ {
			length = (length << 8) | int(b[2+i])
		}
		offset = 2 + n
	}

	if len(b) < offset+length {
		return asn1.TLV{}, 0, errShortDER
	}

	val := b[offset : offset+length]
	tlv := asn1.TLV{
		Tag:         byte(tagNum),
		Class:       byte(class),
		Constructed: constructed,
		Length:      length,
		Value:       val,
	}

	if constructed {
		children := []asn1.TLV{}
		consumed := 0
		for consumed < length {
			child, n, err := parseX509(val[consumed:])
			if err != nil {
				return asn1.TLV{}, 0, err
			}
			children = append(children, child)
			consumed += n
		}
		tlv.Children = children
	}

	return tlv, offset + length, nil
}

func extractCRLIssuerDER(crlDER []byte) ([]byte, error) {
	var (
		tlv asn1.TLV
		err error
	)

	if tlv, _, err = parseX509(crlDER); err != nil {
		return nil, err
	}

	// CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }
	if len(tlv.Children) < 1 {
		err = errTBSList
		return nil, err
	}
	tbs := tlv.Children[0]

	// TBSCertList ::= SEQUENCE {
	//   version OPTIONAL,
	//   signature,
	//   issuer,        <- target
	//   thisUpdate,
	//   nextUpdate OPTIONAL,
	//   revokedCertificates OPTIONAL,
	//   ...
	// }
	// issuer is always the 3rd child (index 2)
	if len(tbs.Children) < 3 {
		return nil, errNoIssuer
	}

	issuer := tbs.Children[2]

	// issuer is a SEQUENCE, so issuer.Value is the raw DER of Name
	return issuer.Value, nil
}

type AlgorithmIdentifier struct {
	OID    []byte
	Params []byte
}

func NewAlgorithmIdentifier(b []byte) (AlgorithmIdentifier, error) {
	var (
		alg AlgorithmIdentifier
		err error
		tlv asn1.TLV
	)

	if tlv, _, err = parseX509(b); err != nil {
		return alg, err
	}

	if tlv.Tag != 0x10 || !tlv.Constructed {
		err = errNotSeq
		return alg, err
	}

	if len(tlv.Children) == 0 {
		err = errNoOID
		return alg, err
	}

	alg.OID = tlv.Children[0].Value

	if len(tlv.Children) > 1 {
		alg.Params = tlv.Children[1].Value
	}

	return alg, err
}

type AlgorithmIdentifierAssertion = AlgorithmIdentifier

func NewAlgorithmIdentifierAssertion(b []byte) (AlgorithmIdentifierAssertion, error) {
	return NewAlgorithmIdentifier(b)
}

func algorithmIdentifierAssertion(x any) (result bool, err error) {
	b, ok := x.([]byte)
	if !ok {
		err = errorBadType("Algorithm Identifier Assertion")
		return
	}
	_, err = NewAlgorithmIdentifierAssertion(b)
	result = err == nil
	return
}

func NewCertificateExactAssertion(b []byte) ([]byte, error) {
	var (
		tlv asn1.TLV
		err error
	)

	if tlv, _, err = parseX509(b); err != nil {
		return nil, err
	}
	if tlv.Tag != 0x04 || tlv.Constructed {
		return nil, errNotOct
	}
	return tlv.Value, nil
}

func certificateExactAssertion(x any) (result bool, err error) {
	b, ok := x.([]byte)
	if !ok {
		err = errorBadType("Certificate Exact Assertion")
		return
	}
	_, err = NewCertificateExactAssertion(b)
	result = err == nil
	return
}

type CertificateAssertion struct {
	IssuerDER  []byte
	SerialDER  []byte
	SubjectDER []byte
}

func NewCertificateAssertion(b []byte) (CertificateAssertion, error) {
	var (
		tlv asn1.TLV
		err error
		ca  CertificateAssertion
	)

	if tlv, _, err = parseX509(b); err != nil {
		return ca, err
	}
	if tlv.Tag != 0x10 || !tlv.Constructed {
		return ca, errNotSeq
	}

	if len(tlv.Children) < 3 {
		return ca, errNotSeq
	}

	ca.IssuerDER = tlv.Children[0].Value
	ca.SerialDER = tlv.Children[1].Value
	ca.SubjectDER = tlv.Children[2].Value

	return ca, nil
}

func stripInnerOctet(v []byte) []byte {
	if len(v) >= 2 && v[0] == asn1.TagOctetString {
		p := 0
		_, payload, err := asn1.ReadConstructedTLV(v, &p)
		if err == nil {
			return payload
		}
	}
	return v
}

func certificateAssertion(x any) (result bool, err error) {
	b, ok := x.([]byte)
	if !ok {
		err = errorBadType("Certificate Assertion")
		return
	}
	_, err = NewCertificateAssertion(b)
	result = err == nil
	return
}

type CRLAssertion struct {
	IssuerDER []byte
}

func NewCRLAssertion(b []byte) (CRLAssertion, error) {
	var (
		tlv asn1.TLV
		err error
		ca  CRLAssertion
	)

	if tlv, _, err = parseX509(b); err != nil {
		return ca, err
	}

	if tlv.Tag != 0x10 || !tlv.Constructed {
		return ca, errNotSeq
	}

	ca.IssuerDER = tlv.Children[0].Value

	return ca, nil
}

func cRLAssertion(x any) (result bool, err error) {
	b, ok := x.([]byte)
	if !ok {
		err = errorBadType("CRL Assertion")
		return
	}
	_, err = NewCRLAssertion(b)
	result = err == nil
	return
}

func NewCertificate(b []byte) (*goX509.Certificate, error) {
	return goX509.ParseCertificate(b)
}

func certificate(x any) (result bool, err error) {
	b, ok := x.([]byte)
	if !ok {
		err = errorBadType("Certificate")
		return
	}
	_, err = NewCertificate(b)
	result = err == nil
	return
}

func NewCRL(b []byte) (*pkix.CertificateList, error) {
	return goX509.ParseCRL(b)
}

func certificateList(x any) (result bool, err error) {
	b, ok := x.([]byte)
	if !ok {
		err = errorBadType("Certificate List")
		return
	}
	_, err = NewCRL(b)
	result = err == nil
	return
}

type CertificatePair struct {
	ForwardDER []byte
	ReverseDER []byte
}

func NewCertificatePair(b []byte) (CertificatePair, error) {
	var (
		tlv asn1.TLV
		err error
		cp  CertificatePair
	)

	if tlv, _, err = parseX509(b); err != nil {
		return cp, err
	}

	if tlv.Tag != 0x10 || !tlv.Constructed {
		return cp, errNotSeq
	}

	for _, c := range tlv.Children {
		if c.Class == asn1.ClassContextSpecific && c.Tag == 0 && c.Constructed {
			// [0] -> SEQUENCE -> OCTET STRING
			inner := c.Children[0].Children[0] // Tag=0x4, Length=1, Value={0xaa}
			cp.ForwardDER = append([]byte{inner.Tag, byte(inner.Length)}, inner.Value...)
		}
		if c.Class == asn1.ClassContextSpecific && c.Tag == 1 && c.Constructed {
			inner := c.Children[0].Children[0] // Tag=0x4, Length=1, Value={0xbb}
			cp.ReverseDER = append([]byte{inner.Tag, byte(inner.Length)}, inner.Value...)
		}
	}

	return cp, nil
}

func certificatePair(x any) (result bool, err error) {
	b, ok := x.([]byte)
	if !ok {
		err = errorBadType("Certificate Pair")
		return
	}
	_, err = NewCertificatePair(b)
	result = err == nil
	return
}

type CertificatePairAssertion CertificatePair

func NewCertificatePairAssertion(b []byte) (CertificatePairAssertion, error) {
	var (
		tlv asn1.TLV
		err error
		cpa CertificatePairAssertion
	)

	if tlv, _, err = parseX509(b); err != nil {
		return cpa, err
	}

	if tlv.Tag != 0x10 || !tlv.Constructed {
		err = errNotSeq
		return cpa, err
	}

	for _, c := range tlv.Children {
		if c.Class == asn1.ClassContextSpecific && c.Tag == 0 && !c.Constructed {
			cpa.ForwardDER = c.Value
		}
		if c.Class == asn1.ClassContextSpecific && c.Tag == 1 && !c.Constructed {
			cpa.ReverseDER = c.Value
		}
	}

	return cpa, err
}

func certificatePairAssertion(x any) (result bool, err error) {
	b, ok := x.([]byte)
	if !ok {
		err = errorBadType("Certificate Pair Assertion")
		return
	}
	_, err = NewCertificatePairAssertion(b)
	result = err == nil
	return
}

func NewCertificatePairExactAssertion(b []byte) ([]byte, error) {
	var (
		tlv asn1.TLV
		err error
	)

	if tlv, _, err = parseX509(b); err != nil {
		return nil, err
	}
	if tlv.Tag != 0x04 || tlv.Constructed {
		return nil, errNotOct
	}
	return tlv.Value, nil
}

func certificatePairExactAssertion(x any) (result bool, err error) {
	b, ok := x.([]byte)
	if !ok {
		err = errorBadType("Certificate Pair Exact Assertion")
		return
	}
	_, err = NewCertificateExactAssertion(b)
	result = err == nil
	return
}

type CertificateListAssertion struct {
	IssuerDER []byte
}

func NewCertificateListAssertion(b []byte) (CertificateListAssertion, error) {
	var (
		tlv asn1.TLV
		err error
		a   CertificateListAssertion
	)

	if tlv, _, err = parseX509(b); err != nil {
		return a, err
	}
	if tlv.Tag != 0x10 || !tlv.Constructed {
		err = errNotSeq
		return a, err
	}

	for _, c := range tlv.Children {
		if c.Class == asn1.ClassContextSpecific && c.Tag == 0 && !c.Constructed {
			a.IssuerDER = c.Value
		}
	}

	return a, err
}

func certificateListAssertion(x any) (result bool, err error) {
	b, ok := x.([]byte)
	if !ok {
		err = errorBadType("Certificate List Assertion")
		return
	}
	_, err = NewCertificateListAssertion(b)
	result = err == nil
	return
}

func NewCertificateListExactAssertion(b []byte) ([]byte, error) {
	var (
		tlv asn1.TLV
		err error
	)

	if tlv, _, err = parseX509(b); err != nil {
		return nil, err
	}
	if tlv.Tag != 0x04 || tlv.Constructed {
		return nil, errNotOct
	}
	return tlv.Value, nil
}

func certificateListExactAssertion(x any) (result bool, err error) {
	b, ok := x.([]byte)
	if !ok {
		err = errorBadType("Certificate List Exact Assertion")
		return
	}
	_, err = NewCertificateListExactAssertion(b)
	result = err == nil
	return
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

var (
	errNotSeq   = errors.New("X.509: not a SEQUENCE")
	errNotOct   = errors.New("X.509: not OCTET STRING")
	errNoOID    = errors.New("X.509: missing OID")
	errHighTag  = errors.New("X.509: high-tag-number not supported")
	errShortDER = errors.New("X.509: short or truncated DER payload")
	errTLVLen   = errors.New("X.509: bad TLV length")
	errTBSList  = errors.New("X.509: missing TBSCertList")
	errNoIssuer = errors.New("X.509: missing issuer")
)
