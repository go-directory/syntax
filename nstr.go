package syntax

import (
	"strings"
)

/*
NumericString implements [§ 3.3.23 of RFC 4517]:

	NumericString = 1*(DIGIT / SPACE)

[§ 3.3.23 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.23
*/
type NumericString []byte

/*
String returns the string representation of the receiver instance.
*/
func (r NumericString) String() string { return string(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r NumericString) IsZero() bool { return len(r) == 0 }

func numericString(x any) (result bool, err error) {
	_, err = marshalNumericString(x)
	result = err == nil
	return
}

/*
NumericString returns an instance of [NumericString] alongside an error
following an analysis of x in the context of a Numeric String.
*/
func NewNumericString(x any) (NumericString, error) {
	return marshalNumericString(x)
}

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the receiver instance as an ASN.1 NumericString value.
*/
func (r NumericString) Encode() ([]byte, error) {
	return encodeP(tNum, r)
}

/*
Decode returns an error following an attempt to decode and write
the input enc value to the receiver instance.  The encoding must
not be truncated, and must bear the NumericString tag (0x12).
*/
func (r *NumericString) Decode(enc []byte) error {
	if len(enc) < 3 || enc[0] != tNum {
		return errNumericDecode
	}
	l, n := readLen(enc[1:])
	if n == 0 || len(enc) < 1+n+l {
		return errNumericDecode
	}
	*r = NumericString(enc[1+n : 1+n+l])
	return nil
}

var errNumericDecode = asn1Error("invalid NumericString encoding")

func marshalNumericString(x any) (ns NumericString, err error) {
	var raw []byte
	if raw, err = assertNumericString(x); err == nil {
		for _, char := range raw {
			if !(isDigit(rune(char)) || char == ' ') {
				err = syntaxError("Incompatible character for Numeric String: ", string(char))
				break
			}
		}
	}

	if err == nil {
		ns = NumericString(raw)
	}

	return
}

func assertNumericString(x any) (raw []byte, err error) {
	badLen := func(l int) (err error) {
		if l == 0 {
			err = errorBadLength("Numeric String", 0)
		}
		return
	}
	switch tv := x.(type) {
	case int, int8, int16, int32, int64:
		if isNegativeInteger(tv) {
			err = syntaxError("Incompatible sign (-) for Numeric String")
			break
		}
		var cint int64
		if cint, err = castInt64(tv); err == nil {
			raw = []byte(fint(cint, 10))
		}
	case uint, uint8, uint16, uint32, uint64:
		var cuint uint64
		if cuint, err = castUint64(tv); err == nil {
			raw = []byte(fuint(cuint, 10))
		}
	case []byte:
		err = badLen(len(tv))
		raw = tv
	case string:
		err = badLen(len(tv))
		raw = []byte(tv)
	default:
		err = errorBadType("Numeric String")
	}

	return
}

// RFC 4518 § 2.6.2
func prepareNumericStringAssertion(a, b any) (str1, str2 string, err error) {
	if str1, err = assertString(a, 0, "numericString"); err != nil {
		return
	}

	if str2, err = assertString(b, 0, "numericString"); err != nil {
		return
	}

	str1 = strings.ReplaceAll(str1, ` `, ``)
	str2 = strings.ReplaceAll(str2, ` `, ``)

	return
}

func numericStringMatch(a, b any) (result bool, err error) {
	var str1, str2 string
	if str1, str2, err = prepareNumericStringAssertion(a, b); err == nil {
		result = str1 == str2
	}

	return
}

func numericStringOrderingMatch(a any, operator byte, b any) (result bool, err error) {
	var str1, str2 string
	if str1, str2, err = prepareNumericStringAssertion(a, b); err == nil {
		if operator == GreaterOrEqual {
			result = str1 >= str2
		} else {
			result = str1 <= str2
		}
	}

	return
}

func numericStringSubstringsMatch(a, b any) (result bool, err error) {
	var str1, str2 string
	if str1, str2, err = prepareNumericStringAssertion(a, b); err == nil {
		result, err = caseExactSubstringsMatch(str1, str2)
	}

	return
}
