package syntax

import (
	"errors"
	"unicode"
)

const TagIA5String byte = 0x16 // 22

/*
IA5String implements [§ 3.2 of RFC 4517]:

	IA5 = 0x0000 through 0x00FF

[§ 3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.2
*/
type IA5String []byte

/*
String returns the string representation of the receiver instance.
*/
func (r IA5String) String() string { return string(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r IA5String) IsZero() bool { return len(r) == 0 }

/*
IA5String returns an instance of [IA5String] alongside an error following
an analysis of x in the context of an IA5 String.
*/
func NewIA5String(x any) (ia5 IA5String, err error) {
	return marshalIA5String(x)
}

func iA5String(x any) (result bool, err error) {
	_, err = marshalIA5String(x)
	result = err == nil
	return
}

func marshalIA5String(x any) (ia5 IA5String, err error) {
	var raw []byte
	switch tv := x.(type) {
	case string:
		raw = []byte(tv)
	case []byte:
		raw = tv
	case IA5String:
		raw = []byte(tv)
	default:
		err = errorBadType("IA5String")
		return
	}

	if err = checkIA5String(raw); err == nil {
		ia5 = IA5String(raw)
	}

	return
}

func checkIA5String[T textLike](raw T) (err error) {
	if len(raw) == 0 {
		err = errors.New("Invalid IA5 String (zero)")
		return
	}

	for i := 0; i < len(raw) && err == nil; i++ {
		char := rune(raw[i])
		if !unicode.Is(iA5Range, char) {
			err = errors.New("Invalid IA5 String character: " + string(char))
		}
	}

	return
}

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the receiver instance as an ASN.1 IA5String value.
*/
func (r IA5String) Encode() ([]byte, error) {
	return encodePrimitive(TagIA5String, r)
}

/*
Decode returns an error following an attempt to decode and write
the input enc value to the receiver instance.  The encoding must
not be truncated, and must bear the IA5String tag (0x16).
*/
func (r *IA5String) Decode(enc []byte) error {
	if len(enc) < 2 || enc[0] != TagIA5String {
		return errIA5Decode
	}
	l, n := readLength(enc[1:])
	if n == 0 || len(enc) < 1+n+l {
		return errIA5Decode
	}
	*r = IA5String(enc[1+n : 1+n+l])
	return nil
}

var errIA5Decode = errors.New("asn1: invalid IA5String")

var iA5Range *unicode.RangeTable

func init() {
	iA5Range = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0000, 0x00FF, 1},
	}}
}
