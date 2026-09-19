package syntax

import (
	"github.com/go-directory/encoding/asn1"
)

/*
Enumerated implements the ASN.1 ENUMERATED type (tag 10), per [§ 20 of
ITU-T Rec. X.680]:

	EnumeratedType ::=
	    ENUMERATED "{" Enumerations "}"

[§ 20 of ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
type Enumerated int

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the receiver instance as an ASN.1 ENUMERATED value.
*/

func (r Enumerated) Encode() ([]byte, error) {
	return asn1.EncodePrimitive(asn1.TagEnumerated, encodeEnum(int(r)))
}

/*
Decode returns an error following an attempt to decode and write
the input enc value to the receiver instance.  The encoding must
not be truncated, and must bear the ENUMERATED tag (0x0A).
*/
func (r *Enumerated) Decode(enc []byte) error {
	if len(enc) < 2 || enc[0] != asn1.TagEnumerated {
		return errEnumDecode
	}
	l, n := asn1.ReadPrimitiveLength(enc[1:])
	if n == 0 || len(enc) < 1+n+l {
		return errEnumDecode
	}
	v := enc[1+n : 1+n+l]
	if len(v) == 0 {
		return errEnumDecode
	}
	x := 0
	for i := 0; i < len(v); i++ {
		x = (x << 8) | int(v[i])
	}
	*r = Enumerated(x)

	return nil
}

func encodeEnum(n int) []byte {
	if n == 0 {
		return []byte{0x00}
	}
	var tmp [8]byte
	i := len(tmp)
	v := n
	for v != 0 && i > 0 {
		i--
		tmp[i] = byte(v)
		v >>= 8
	}
	out := tmp[i:]
	if out[0]&0x80 != 0 {
		out = append([]byte{0x00}, out...)
	}
	return out
}

var errEnumDecode = asn1Error("invalid ENUMERATED encoding")
