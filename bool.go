package syntax

import (
	"strconv"

	"github.com/go-directory/encoding/asn1"
)

/*
Boolean implements the ASN.1 BOOLEAN type (tag 1).
*/
type Boolean bool

/*
NewBoolean returns a Boolean value alongside an error following
an analysis of input argument x as a bool.

If x is a bool, it is guaranteed to be valid and is returned as-is.

If x is a string, an underlying call to [strconv.ParseBool] is made.

If x is a byte, only values of 0x00 for false, or 0xFF for true, are
considered valid. Any other byte value is an error.

Any other input type is an error.
*/
func NewBoolean(x any) (b Boolean, err error) {
	switch tv := x.(type) {
	case Boolean:
		b = tv
	case bool:
		b = Boolean(tv)
	case string:
		var _b bool
		_b, err = strconv.ParseBool(tv)
		b = Boolean(_b)
	case byte:
		if _b, found := boolMap[tv]; found {
			b = Boolean(_b)
		} else {
			err = syntaxError("Invalid bool byte; want 0x00 (false) or 0xFF (true)")
		}
	default:
		err = errorBadType("boolean")
	}
	return
}

func boolean(x any) (result bool, err error) {
	_, err = NewBoolean(x)
	result = err == nil
	return
}

func booleanMatch(realValue, assertionValue any) (result bool, err error) {
	var a, b Boolean
	if a, err = NewBoolean(realValue); err == nil {
		if b, err = NewBoolean(assertionValue); err == nil {
			result = a == b
		}
	}

	if err != nil {
		err = syntaxError("UNDEFINED: ", err.Error())
	}

	return
}

func encodeBool(v bool) (enc []byte) {
	enc = []byte{0x00}
	if v {
		enc = []byte{0xFF}
	}
	return
}

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the receiver instance as an ASN.1 BOOLEAN value.
*/

func (r Boolean) Encode() ([]byte, error) {
	return asn1.EncodePrimitive(asn1.TagBoolean, encodeBool(bool(r)))
}

/*
Decode returns an error following an attempt to decode and write
the input enc value to the receiver instance.  The encoding must
not be truncated, and must bear the BOOLEAN tag (0x01).
*/
func (r *Boolean) Decode(enc []byte) error {
	if len(enc) != 3 || enc[0] != asn1.TagBoolean {
		return errBoolDecode
	}
	l, n := asn1.ReadLength(enc[1:])
	if n == 0 || len(enc) < 1+n+l {
		return errBoolDecode
	}

	var err error
	if b, found := boolMap[enc[2]]; found {
		*r = Boolean(b)
	} else {
		err = errBoolDecode
	}

	return err
}

var boolMap = map[byte]bool{
	0x00: false,
	0xFF: true,
}

var errBoolDecode = asn1Error("invalid BOOLEAN encoding")
