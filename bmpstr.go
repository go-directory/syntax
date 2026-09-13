package syntax

import (
	"unicode/utf8"

	"github.com/go-directory/encoding/asn1"
)

/*
BMPString implements the Basic Multilingual Plane per [ITU-T Rec. X.680].

The structure for instances of this type is as follows:

	T (30, Ox1E) N (NUM. BYTES) P{byte,byte,byte}

Tag T represents ASN.1 BMPString tag integer 30 (0x1E). Number N is an
int-cast byte value that cannot exceed 255. The remaining bytes, which
may be zero (0) or more in number, define payload P. N must equal size
of payload P.

[ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
type BMPString []byte

/*
String returns the string representation of the receiver instance.

This involves unmarshaling the receiver into a string return value.
*/
func (r BMPString) String() string {
	if len(r) < 3 || r[0] != asn1.TagBMPString {
		return ""
	}

	length := int(r[1])
	expectedLength := 2 + length*2
	if len(r) != expectedLength {
		return ""
	}

	var result []rune
	for i := 2; i < expectedLength; i += 2 {
		codePoint := (rune(r[i]) << 8) | rune(r[i+1])
		result = append(result, codePoint)
	}

	return string(result)
}

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the receiver instance as an ASN.1 BMPString value.
*/
func (r BMPString) Encode() ([]byte, error) {
	if len(r)%2 != 0 {
		return nil, errBMPCodec
	}

	chars := len(r) / 2
	var out []byte

	switch {
	case chars < 128:
		out = make([]byte, 2+len(r))
		out[0] = asn1.TagBMPString
		out[1] = byte(chars)
		copy(out[2:], r)
	default:
		n := asn1.LengthBytes(chars)
		out = make([]byte, 1+1+n+len(r))
		out[0] = asn1.TagBMPString
		out[1] = 0x80 | byte(n)
		asn1.WritePrimitiveLength(out[2:2+n], chars)
		copy(out[2+n:], r)
	}

	return out, nil
}

/*
Decode returns an error following an attempt to decode and write
the input enc value to the receiver instance.  The encoding must
not be truncated, and must bear the BMPString tag (0x31).
*/
func (r *BMPString) Decode(enc []byte) error {
	if len(enc) < 2 || enc[0] != asn1.TagBMPString {
		return errBMPCodec
	}
	chars, n := asn1.ReadPrimitiveLength(enc[1:])
	if n == 0 {
		return errBMPCodec
	}
	bytes := chars * 2
	if len(enc) < 1+n+bytes {
		return errBMPCodec
	}
	*r = BMPString(enc[1+n : 1+n+bytes])
	return nil
}

var (
	errBMPCodec = asn1Error("invalid BMPString encoding")
)

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r BMPString) IsZero() bool { return r == nil }

/*
BMPString marshals x into a BMPString (UTF-16) return value, returning
an instance of [BMPString] alongside an error.
*/
func NewBMPString(x any) (BMPString, error) {
	return assertBMPString(x)
}

func assertBMPString(x any) (enc BMPString, err error) {
	var e []byte
	switch tv := x.(type) {
	case []byte:
		e = tv
	case string:
		e = []byte(tv)
	case BMPString:
		if L := len(tv); L == 2 {
			if tv[0] != asn1.TagBMPString || tv[1] != 0x0 {
				err = syntaxError("Invalid ASN.1 tag or length octet for empty string")
				return
			}
			enc = BMPString{asn1.TagBMPString, 0x0}
			return
		} else if L > 0 {
			if tv[0] != asn1.TagBMPString {
				err = syntaxError("Invalid ASN.1 tag")
				return
			} else if int(tv[1]) != len(tv[2:]) {
				err = syntaxError("input string encoded length does not match length octet")
				return
			}
		}
	default:
		err = errorBadType("BMPString")
		return
	}

	if len(e) == 0 {
		// Zero length values are OK
		enc = BMPString{asn1.TagBMPString, 0x0}
		return
	}

	var result []byte
	result = append(result, asn1.TagBMPString) // Add BMPString tag (byte(30))

	// UTF-8 to UTF-16BE
	var utf16be []byte
	if utf16be, err = buildUTF16BE(e); err != nil {
		return
	}

	chars := len(utf16be) / 2
	if chars > 255 {
		err = syntaxError("input string too long for BMPString encoding")
		return
	}

	result = append(result, byte(chars))
	result = append(result, utf16be...)

	enc = BMPString(result)

	return
}

func buildUTF16BE(e []byte) (utf16be []byte, err error) {
	utf16be = make([]byte, 0, len(e)*2)

	for i := 0; i < len(e); {
		roon, sz := utf8.DecodeRune(e[i:])
		if roon == utf8.RuneError && sz == 1 {
			err = syntaxError("invalid UTF-8 in BMPString")
			return
		}
		if roon > 0xFFFF {
			err = syntaxError("BMPString cannot encode code points above U+FFFF")
			return
		}
		utf16be = append(utf16be, byte(roon>>8), byte(roon))
		i += sz
	}

	return
}
