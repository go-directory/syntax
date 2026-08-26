package x509

import (
	"errors"
)

var (
	errNotSeq   = errors.New("not a SEQUENCE")
	errNotOct   = errors.New("not OCTET STRING")
	errNoOID    = errors.New("missing OID")
	errHighTag  = errors.New("high-tag-number not supported")
	errShortDER = errors.New("short or truncated DER payload")
	errTLVLen   = errors.New("bad TLV length")
	errTBSList  = errors.New("missing TBSCertList")
	errNoIssuer = errors.New("missing issuer")
)
