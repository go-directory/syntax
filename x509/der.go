package x509

const (
	TagUniversal       = 0x00
	TagApplication     = 0x40
	TagContextSpecific = 0x80
	TagPrivate         = 0xC0
)

type TLV struct {
	Tag         byte
	Class       byte
	Constructed bool
	Length      int
	Value       []byte
	Children    []TLV
}

func ParseDER(b []byte) (TLV, error) {
	t, _, err := parse(b)
	return t, err
}

func parse(b []byte) (TLV, int, error) {
	if len(b) < 2 {
		return TLV{}, 0, errShortDER
	}

	tag := b[0]
	class := tag & 0xC0
	constructed := (tag & 0x20) != 0
	tagNum := tag & 0x1F

	if tagNum == 0x1F {
		return TLV{}, 0, errHighTag
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
			return TLV{}, 0, errTLVLen
		}
		if len(b) < 2+n {
			return TLV{}, 0, errShortDER
		}
		length = 0
		for i := 0; i < n; i++ {
			length = (length << 8) | int(b[2+i])
		}
		offset = 2 + n
	}

	if len(b) < offset+length {
		return TLV{}, 0, errShortDER
	}

	val := b[offset : offset+length]
	tlv := TLV{
		Tag:         tagNum,
		Class:       class,
		Constructed: constructed,
		Length:      length,
		Value:       val,
	}

	if constructed {
		children := []TLV{}
		consumed := 0
		for consumed < length {
			child, n, err := parse(val[consumed:])
			if err != nil {
				return TLV{}, 0, err
			}
			children = append(children, child)
			consumed += n
		}
		tlv.Children = children
	}

	return tlv, offset + length, nil
}

func extractCRLIssuerDER(crlDER []byte) ([]byte, error) {
	t, err := ParseDER(crlDER)
	if err != nil {
		return nil, err
	}

	// CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }
	if len(t.Children) < 1 {
		return nil, errTBSList
	}
	tbs := t.Children[0]

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
