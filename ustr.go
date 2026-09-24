package syntax

import (
	"bytes"
	"encoding/binary"
	"unicode/utf8"

	"github.com/go-directory/encoding/asn1"
)

/*
UniversalString implements the Universal Character Set.

	UCS = 0x0000 through 0xFFFF
*/
type UniversalString []byte

/*
UniversalString returns an instance of [UniversalString] alongside an error
following an analysis of x in the context of a UniversalString.
*/
func NewUniversalString(x any) (UniversalString, error) {
	return marshalUniversalString(x)
}

func universalString(x any) (result bool) {
	_, err := marshalUniversalString(x)
	result = err == nil
	return
}

func marshalUniversalString(x any) (us UniversalString, err error) {
	var raw []byte

	switch tv := x.(type) {
	case UniversalString:
		raw = []byte(tv)
	case []byte:
		raw = tv
	case string:
		raw = []byte(tv)
	default:
		err = errorBadType("UniversalString")
		return
	}

	if !utf8.Valid(raw) {
		err = syntaxError("invalid UniversalString: failed UTF8 checks")
		return
	}

	us = UniversalString(raw)

	return
}

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the receiver instance as an ASN.1 UniversalString
value.
*/
func (r UniversalString) Encode() ([]byte, error) {
	L := len(r)
	out := make([]byte, 4*L)
	pos := 0

	for i := 0; i < L; {
		roon, sz := utf8.DecodeRune(r[i:])
		if roon == utf8.RuneError && sz == 1 {
			return nil, syntaxError("UniversalString: invalid UTF-8")
		}
		if err := universalStringCharacterOutOfBounds(roon); err != nil {
			return nil, err
		}
		binary.BigEndian.PutUint32(out[pos:], uint32(roon))
		pos += 4
		i += sz
	}

	return asn1.EncodePrimitive(asn1.TagUniversalString, out[:pos])
}

func universalStringCharacterOutOfBounds(r rune) (err error) {
	if r > 0x10FFFF || (r >= 0xD800 && r <= 0xDFFF) {
		err = syntaxError("UNIVERSAL STRING: invalid code point ",
			string(r), " (", itoa(int(r)), ")")
	}

	return
}

/*
Decode returns an error following an attempt to decode and write
the input enc value to the receiver instance.  The encoding must
not be truncated, and must bear the UniversalString tag (0x1C).
*/
func (r *UniversalString) Decode(enc []byte) error {
	if len(enc) < 3 || enc[0] != asn1.TagUniversalString {
		return errUnivDecode
	}

	l, n := asn1.ReadPrimitiveLength(enc[1:])
	if n == 0 || len(enc) < 1+n+l {
		return errUnivDecode
	}

	v := enc[1+n : 1+n+l]
	if len(v)%4 != 0 {
		return errUnivDecode
	}

	sb := &bytes.Buffer{}
	sb.Grow(len(v))

	for i := 0; i < len(v); i += 4 {
		cp := uint32(v[i])<<24 |
			uint32(v[i+1])<<16 |
			uint32(v[i+2])<<8 |
			uint32(v[i+3])

		if universalStringCharacterOutOfBounds(rune(cp)) != nil {
			return errUnivDecode
		}

		var tmp [4]byte
		n := utf8.EncodeRune(tmp[:], rune(cp))
		sb.Write(tmp[:n])
	}

	*r = UniversalString(sb.Bytes())
	return nil
}

var errUnivDecode = asn1Error("invalid UniversalString encoding")

/*
String returns the string representation of the receiver instance.
*/
func (r UniversalString) String() string { return string(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r UniversalString) IsZero() bool { return len(r) == 0 }
