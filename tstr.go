package syntax

import (
	"github.com/go-directory/encoding/asn1"
)

/*
isT61Single returns a Boolean value indicative of a character match between input
rune r and one of the runes present within the t61NonContiguous global []rune
instance.
*/
func isT61Single(r rune) (is bool) {
	for _, char := range t61NonContiguous {
		if is = r == char; is {
			break
		}
	}

	return is
}

/*
Deprecated: TeletexString implements the Teletex String, per [ITU-T Rec. T.61]

[ITU-T Rec. T.61]: https://www.itu.int/rec/T-REC-T.61
*/
type TeletexString []byte

/*
String returns the string representation of the receiver instance.
*/
func (r TeletexString) String() string { return string(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r TeletexString) IsZero() bool { return len(r) == 0 }

/*
Deprecated: TeletexString returns an instance of [TeletexString] alongside
an error following an analysis of x in the context of a Teletex String, per
[ITU-T Rec. T.61].

[ITU-T Rec. T.61]: https://www.itu.int/rec/T-REC-T.61
*/
func NewTeletexString(x any) (TeletexString, error) {
	return marshalTeletexString(x)
}

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the receiver instance as an ASN.1 T61String value.
*/
func (r TeletexString) Encode() ([]byte, error) {
	return asn1.EncodePrimitive(asn1.TagT61String, r)
}

/*
Decode returns an error following an attempt to decode and write
the input enc value to the receiver instance.  The encoding must
not be truncated, and must bear the T61String tag (0x14).
*/
func (r *TeletexString) Decode(enc []byte) error {
	if len(enc) < 3 || enc[0] != asn1.TagT61String {
		return errT61Decode
	}
	l, n := asn1.ReadPrimitiveLength(enc[1:])
	if n == 0 || len(enc) < 1+n+l {
		return errT61Decode
	}
	*r = TeletexString(enc[1+n : 1+n+l])
	return nil
}

var errT61Decode = asn1Error("invalid T.61 String encoding")

func teletexString(x any) (result bool) {
	_, err := marshalTeletexString(x)
	result = err == nil
	return
}

func marshalTeletexString(x any) (ts TeletexString, err error) {
	badLen := func(l int) (err error) {
		if l == 0 {
			err = errorBadLength("Teletex String", 0)
		}
		return
	}

	var raw []byte
	switch tv := x.(type) {
	case []byte:
		err = badLen(len(tv))
		raw = tv
	case TeletexString:
		err = badLen(len(tv))
		raw = []byte(tv)
	case string:
		err = badLen(len(tv))
		raw = []byte(tv)
	default:
		err = errorBadType("Teletex String")
		return
	}

	for i := 0; i < len(raw) && err == nil; i++ {
		char := rune(raw[i])
		if !(isT61RangedRune(char) || isT61Single(char)) {
			err = syntaxError("Incompatible character for Teletex String: ", string(char))
			break
		}
	}

	if err == nil {
		ts = TeletexString(raw)
	}

	return
}
