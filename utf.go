package syntax

/*
unicode.go handles rune analysis and unicode ranging.
*/

import (
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/go-directory/encoding/asn1"
)

/*
UTF8String implements the UTF8 String syntax and abstraction.

From [§ 1.4 of RFC 4512]:

	UTF8    = UTF1 / UTFMB
	UTFMB   = UTF2 / UTF3 / UTF4
	UTF0    = %x80-BF
	UTF1    = %x00-7F
	UTF2    = %xC2-DF UTF0
	UTF3    = %xE0 %xA0-BF UTF0 / %xE1-EC 2(UTF0) /
	          %xED %x80-9F UTF0 / %xEE-EF 2(UTF0)
	UTF4    = %xF0 %x90-BF 2(UTF0) / %xF1-F3 3(UTF0) /
	          %xF4 %x80-8F 2(UTF0)

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
type UTF8String []byte

/*
NewUTF8String returns an instance of [UTF8String] alongside an error
following an analysis of x in the context of a UTF8-compliant string.
*/
func NewUTF8String(x any) (UTF8String, error) {
	return assertUTF8String(x)
}

func assertUTF8String(x any) (u UTF8String, err error) {
	var raw []byte

	switch tv := x.(type) {
	case UTF8String:
		raw = []byte(tv)
	case []byte:
		raw = tv
	case string:
		raw = []byte(tv)
	default:
		err = errorBadType("UTF8String")
		return
	}

	u, err = uTF8(raw)
	return
}

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the receiver instance as an ASN.1 UTF8String value.
*/
func (r UTF8String) Encode() ([]byte, error) {
	return asn1.EncodePrimitive(asn1.TagUTF8String, r)
}

/*
Decode returns an error following an attempt to decode and write
the input enc value to the receiver instance.  The encoding must
not be truncated, and must bear the UTF8String tag (0x0c).
*/
func (r *UTF8String) Decode(enc []byte) error {
	if len(enc) < 3 || enc[0] != asn1.TagUTF8String {
		return errUTF8Decode
	}
	l, n := asn1.ReadPrimitiveLength(enc[1:])
	if n == 0 || len(enc) < 1+n+l {
		return errUTF8Decode
	}
	*r = enc[1+n : 1+n+l]
	return nil
}

var errUTF8Decode = asn1Error("invalid OCTET STRING encoding")

/*
String returns the string representation of the receiver instance.
*/
func (r UTF8String) String() string { return string(r) }
func (r UTF8String) IsZero() bool   { return len(r) == 0 }

var (
	runeLen  func(rune) int           = utf8.RuneLen
	decRune  func([]byte) (rune, int) = utf8.DecodeRune
	utf8OK   func([]byte) bool        = utf8.Valid
	utf16Enc func([]rune) []uint16    = utf16.Encode
)

var runeSelf rune = utf8.RuneSelf
var maxASCII rune = unicode.MaxASCII

var (
	asciiRange,
	uTF8SubsetRange,
	utf0Range,
	utf1Range,
	utf2Range,
	utf2aSafeRange,
	utf2bSafeRange,
	utf3aRange,
	utf3SafeRange,
	utf3bRange,
	utf3cRange,
	utf3dRange,
	utf4aRange,
	utf4SafeRange,
	utf4bRange,
	utf4cRange *unicode.RangeTable
)

/*
IsSafeUTF8 returns a Boolean value alongside an error following an
analysis of input argument x as a "Safe UTF8" value.

	UTF8String        = StringValue
	StringValue       = dquote *SafeUTF8Character dquote
	dquote            = %x22 ; " (double quote)
	SafeUTF8Character = %x00-21 / %x23-7F /   ; ASCII minus dquote

	dquote dquote /       ; escaped double quote
	%xC0-DF %x80-BF /     ; 2 byte UTF-8 character
	%xE0-EF 2(%x80-BF) /  ; 3 byte UTF-8 character
	%xF0-F7 3(%x80-BF)    ; 4 byte UTF-8 character
*/
func IsSafeUTF8(x any) (result bool, err error) {
	var raw []rune
	if raw, err = assertRunes(x); err != nil {
		return
	}

	funcs := map[int]func(string) error{
		2: isSafeUTF2,
		3: isSafeUTF3,
		4: isSafeUTF4,
	}

	var last rune
	for i := 0; i < len(raw) && err == nil; i++ {
		r := raw[i]
		switch rL := runeLen(r); rL {
		case 1:
			// ASCII range w/o double-quote
			err = isSafeUTF1(string(r))
			if '"' == r && last != '\u005C' {
				err = syntaxError("Unescaped double-quote; not a UTF8 Safe Character")
			}
			last = r
		case 2, 3, 4:
			// UTF2/3/4
			err = funcs[rL](string(r))
		}
	}

	result = err == nil

	return
}

func isSafeUTF1(x string) (err error) {
	z := rune([]byte(x)[0])
	if !(unicode.Is(asciiRange, z) && z != '"') {
		err = syntaxError("Incompatible char for UTF0 (in ASCII Safe Range):", x)
	}

	return
}

func isSafeUTF2(x string) (err error) {
	z := []byte(string(x))
	ch1 := rune(z[0])
	ch2 := rune(z[1])
	if !(unicode.Is(utf2aSafeRange, ch1) &&
		unicode.Is(utf2bSafeRange, ch2)) {
		err = syntaxError("Incompatible chars for UTF2 (in UTF2 Safe Range): ", x)
	}

	return
}

func isSafeUTF3(x string) (err error) {
	z := []byte(string(x))
	ch1 := rune(z[0])
	ch2 := rune(z[1])
	ch3 := rune(z[2])
	if !(unicode.Is(utf3SafeRange, ch1) &&
		unicode.Is(utf2bSafeRange, ch2) &&
		unicode.Is(utf2bSafeRange, ch3)) {
		err = syntaxError("Incompatible chars for UTF3 (in UTF3 Safe Range): ", x)
	}

	return
}

func isSafeUTF4(x string) (err error) {
	z := []byte(string(x))
	ch1 := rune(z[0])
	ch2 := rune(z[1])
	ch3 := rune(z[2])
	ch4 := rune(z[3])
	if !(unicode.Is(utf4SafeRange, ch1) &&
		unicode.Is(utf2bSafeRange, ch2) &&
		unicode.Is(utf2bSafeRange, ch3) &&
		unicode.Is(utf2bSafeRange, ch4)) {
		err = syntaxError("Incompatible chars for UTF4 (in UTF4 Safe Range): ", x)
	}

	return
}

/*
uTF8 returns an error following an analysis of x in the context of
one (1) or more UTF8 characters.

From [§ 1.4 of RFC 4512]:

	UTF8    = UTF1 / UTFMB
	UTFMB   = UTF2 / UTF3 / UTF4
	UTF0    = %x80-BF
	UTF1    = %x00-7F
	UTF2    = %xC2-DF UTF0
	UTF3    = %xE0 %xA0-BF UTF0 / %xE1-EC 2(UTF0) /
	          %xED %x80-9F UTF0 / %xEE-EF 2(UTF0)
	UTF4    = %xF0 %x90-BF 2(UTF0) / %xF1-F3 3(UTF0) /
	          %xF4 %x80-8F 2(UTF0)

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
func uTF8(x any, zok ...bool) (u UTF8String, err error) {
	var raw []rune
	if raw, err = assertRunes(x, zok...); err != nil {
		return
	}

	for i := 0; i < len(raw) && err == nil; i++ {
		if !unicode.Is(utf1Range, rune(raw[i])) {
			err = uTFMB(rune(raw[i]))
		}
	}

	if err == nil {
		var b string
		for i := 0; i < len(raw); i++ {
			b += string(raw[i])
		}
		u = UTF8String(b)
	}

	return
}

/*
IsUTFMB returns a Boolean value indicative of the input value --
which may be a string, rune, rune slice, byte or byte slice --
being a valid UTFMB value.
*/
func IsUTFMB(x any) bool { return uTFMB(x) == nil }

/*
uTFMB returns an error following an analysis of x in the context of
one (1) or more UTFMB characters.
*/
func uTFMB(x any) (err error) {
	var raw []rune
	if raw, err = assertRunes(x); err == nil {
		for i := 0; i < len(raw) && err == nil; i++ {
			r := rune(raw[i])
			var valid bool
			if valid, err = isUTFMBChar(r); !valid {
				err = syntaxError("Invalid UTFMB char: ", string(r))
				break
			}
		}
	}

	return
}

func isUTF0(b byte) bool {
	return b >= 0x80 && b <= 0xBF
}

func isUTF2(ub []byte) bool {
	return ub[0] >= 0xC2 && ub[0] <= 0xDF && isUTF0(ub[1])
}

func isUTF3(ub []byte) (b bool) {
	switch ub[0] {
	case 0xE0:
		b = unicode.Is(utf3aRange, rune(ub[1])) && isUTF0(ub[2])
	case 0xED:
		b = unicode.Is(utf3cRange, rune(ub[1])) && isUTF0(ub[2])
	case 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xEE, 0xEF:
		b = isUTF0(ub[1]) && isUTF0(ub[2])
	}

	return
}

func isUTF4(ub []byte) (b bool) {
	switch ub[0] {
	case 0xF0:
		b = ub[1] >= 0x90 && ub[1] <= 0xBF && isUTF0(ub[2]) && isUTF0(ub[3])
	case 0xF1, 0xF2, 0xF3:
		b = isUTF0(ub[1]) && isUTF0(ub[2]) && isUTF0(ub[3])
	case 0xF4:
		b = unicode.Is(utf4cRange, rune(ub[1])) && isUTF0(ub[2]) && isUTF0(ub[3])
	}

	return
}

func isUTFMBChar(r rune) (b bool, err error) {
	ub := make([]byte, 4)
	n := utf8.EncodeRune(ub, r)

	switch n {
	case 2:
		b = isUTF2(ub)
	case 3:
		b = isUTF3(ub)
	case 4:
		b = isUTF4(ub)
	}

	if !b {
		err = syntaxError("invalid leading byte for ",
			itoa(n), "-byte sequence, or bad length")
	}

	return
}

func init() {

	uTF8SubsetRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0001, 0x0027, 1},
		{0x002B, 0x005B, 1},
		{0x005D, 0x007F, 1},
	}}

	utf0Range = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0080, 0x00BF, 1},
	}}

	utf1Range = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0000, 0x007F, 1},
	}}
	asciiRange = utf1Range

	utf2Range = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00C2, 0x00DF, 1},
	}}

	utf2aSafeRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00C0, 0x00DF, 1},
	}}

	utf2bSafeRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0080, 0x00BF, 1},
	}}

	utf3aRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00A0, 0x00BF, 1},
	}}

	utf3SafeRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00E0, 0x00EF, 1},
	}}

	utf3bRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00E1, 0x00EC, 1},
	}}

	utf3cRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0080, 0x009F, 1},
	}}

	utf3dRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00EE, 0x00EF, 1},
	}}

	utf4aRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0090, 0x00BF, 1},
	}}

	utf4SafeRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00F0, 0x00F7, 1},
	}}

	utf4bRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00F1, 0x00F3, 1},
	}}

	utf4cRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0080, 0x008F, 1},
	}}
}
