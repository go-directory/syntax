package syntax

/*
substr.go implements the substring assertion type.
*/

import (
	"bytes"
	"unicode"
	"unicode/utf8"
)

const (
	tagSubstringInitial = 0
	tagSubstringAny     = 1
	tagSubstringFinal   = 2
)

/*
Substrings implements the Substring Assertion.

From [§ 3.3.30 of RFC 4517]:

	SubstringAssertion = [ initial ] any [ final ]

	initial  = substring
	any      = ASTERISK *(substring ASTERISK)
	final    = substring
	ASTERISK = %x2A  ; asterisk ("*")

	substring           = 1*substring-character
	substring-character = %x00-29
	                      / (%x5C "2A")  ; escaped "*"
	                      / %x2B-5B
	                      / (%x5C "5C")  ; escaped "\"
	                      / %x5D-7F
	                      / UTFMB

From [§ 2 of RFC 4515]:

	SubstringFilter ::= SEQUENCE {
	    type    AttributeDescription,
	    -- initial and final can occur at most once
	    substrings    SEQUENCE SIZE (1..MAX) OF substring CHOICE {
	     initial        [0] AssertionValue,
	     any            [1] AssertionValue,
	     final          [2] AssertionValue } }

From [§ 3 of RFC 4515]:

	initial = assertionvalue
	any     = ASTERISK *(assertionvalue ASTERISK)
	final   = assertionvalue

This interface type is implemented through [SubstringInitial], [SubstringAny]
and [SubstringFinal] type instances.

Instances of this type are created using the [NewSubstring] constructor.

[§ 2 of RFC 4515]: https://datatracker.ietf.org/doc/html/rfc4515#section-2
[§ 3 of RFC 4515]: https://datatracker.ietf.org/doc/html/rfc4515#section-3
[§ 3.3.30 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.30
*/
type Substring interface {
	//String() string
	Choice() string
	Encode() ([]byte, error)
	IsZero() bool
	Tag() int
	isSubstring()
}

/*
Substrings implements slices of [Substring] instances. An instance of this
type resides within the "Substrings" field of the [FilterSubstrings] type.
*/
type Substrings []Substring

func (r Substrings) Encode() ([]byte, error) {
	var payload []byte
	var err error

	for i := 0; i < len(r) && err == nil; i++ {
		var enc []byte
		switch v := r[i].(type) {
		case SubstringInitial:
			enc, err = v.Encode()
		case SubstringFinal:
			enc, err = v.Encode()
		case SubstringAny:
			enc, err = v.Encode()
		default:
			err = asn1Error("Substring: unknown CHOICE type")
		}
		if err == nil {
			payload = append(payload, enc...)
		}
	}

	var out []byte
	if err == nil {
		out, err = wrapTLV(payload, uSeqTag())
	}

	return out, err
}

func (r *Substrings) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag())
	if err != nil {
		return err
	}

	p2 := 0
	var Init SubstringInitial
	var Final SubstringFinal
	var Any SubstringAny
	for p2 < len(payload) && err == nil {
		var childTag Tag
		var childPayload []byte

		childTag, childPayload, err = readCTLV(payload, &p2)
		if err != nil {
			break
		}

		if first := childPayload[0]; first != tOct {
			err = asn1Error("Substring: unexpected tag ",
				itoa(int(first)))
			break
		}

		var dec OctetString
		switch childTag.Tag {
		case uint32(tagSubstringInitial):
			err = dec.Decode(childPayload)
			Init = SubstringInitial(dec)

		case uint32(tagSubstringAny):
			err = dec.Decode(childPayload)
			Any = append(Any, AssertionValue(dec))

		case uint32(tagSubstringFinal):
			err = dec.Decode(childPayload)
			Final = SubstringFinal(dec)

		default:
			err = asn1Error("Substring: unexpected tag ",
				itoa(int(childTag.Tag)))
		}
	}

	if err == nil {
		if len(Init) > 0 {
			*r = append(*r, Init)
		}
		*r = append(*r, Any)
		if len(Final) > 0 {
			*r = append(*r, Final)
		}
	}

	return err
}

/*
SubstringInitial implements the "initial" CHOICE of an instance of [Substring].
*/
type SubstringInitial AssertionValue

/*
SubstringFinal implements the "final" CHOICE of an instance of [Substring].
*/
type SubstringFinal AssertionValue

/*
SubstringAny implements the "any" CHOICE of an instance of [Substring].
*/
type SubstringAny []AssertionValue

func (r SubstringInitial) IsZero() bool { return len(r) == 0 }
func (r SubstringFinal) IsZero() bool   { return len(r) == 0 }
func (r SubstringAny) IsZero() bool     { return len(r) == 0 }

func (r SubstringAny) Encode() ([]byte, error) {
	payload := make([]byte, 0)

	var err error
	for i := 0; i < len(r) && err == nil; i++ {
		var enc []byte
		enc, err = OctetString(r[i]).Encode()
		payload = append(payload, enc...)
	}

	var out []byte
	if err == nil {
		out, err = wrapTLV(payload, aTag(classC, true, uint32(r.Tag())))
	}

	return out, err
}

func (r *SubstringAny) Decode(enc []byte) error {

	payload, err := unwrapTLV(enc, aTag(classC, true, uint32(r.Tag())))
	if err != nil {
		return err
	}

	p2 := 0
	for p2 < len(payload) && err == nil {
		var childTag Tag
		var childPayload []byte
		if childTag, childPayload, err = readCTLV(payload, &p2); err == nil {
			if childTag.Tag != uint32(tOct) {
				err = asn1Error("Substring.Any Assertion Value: want %d, got %d",
					itoa(int(tOct)),
					itoa(int(childTag.Tag)))
				break
			}
			*r = append(*r, AssertionValue(childPayload))
		}
	}

	return err
}

func (r SubstringInitial) Encode() ([]byte, error) {
	return encodeSubstringInitOrFinal(r)
}

func (r SubstringFinal) Encode() ([]byte, error) {
	return encodeSubstringInitOrFinal(r)
}

func encodeSubstringInitOrFinal(x Substring) (out []byte, err error) {
	var enc []byte
	switch tv := x.(type) {
	case SubstringInitial:
		enc, err = OctetString(tv).Encode()
	case SubstringFinal:
		enc, err = OctetString(tv).Encode()
	}

	if err == nil {
		out, err = wrapTLV(enc, aTag(classC, false, uint32(x.Tag())))
	}
	return out, err
}

func (r *SubstringInitial) Decode(enc []byte) error {
	sub, err := decodeSubstringInitOrFinal(enc)
	if err == nil {
		*r = SubstringInitial(sub.(SubstringInitial))
	}
	return err
}

func (r *SubstringFinal) Decode(enc []byte) error {
	sub, err := decodeSubstringInitOrFinal(enc)
	if err == nil {
		*r = SubstringFinal(sub.(SubstringFinal))
	}
	return err
}

func decodeSubstringInitOrFinal(enc []byte) (sub Substring, err error) {
	p := 0

	var tag Tag
	var payload []byte

	if tag, payload, err = readCTLV(enc, &p); err == nil {
		p2 := 0
		var val []byte
		if _, val, err = readCTLV(payload, &p2); err == nil {
			switch uint32(tag.Tag) {
			case tagSubstringInitial:
				if err == nil {
					sub = SubstringInitial(val)
				}
			case tagSubstringFinal:
				if err == nil {
					sub = SubstringFinal(val)
				}
			default:
				err = asn1Error("Substring: unexpected tag ", itoa(int(tag.Tag)))
			}
		}
	}

	return
}

func (_ SubstringInitial) Tag() int { return tagSubstringInitial }
func (_ SubstringFinal) Tag() int   { return tagSubstringFinal }
func (_ SubstringAny) Tag() int     { return tagSubstringAny }

func (_ SubstringInitial) Choice() string { return "initial" }
func (_ SubstringFinal) Choice() string   { return "final" }
func (_ SubstringAny) Choice() string     { return "any" }

func (_ SubstringInitial) isSubstring() {}
func (_ SubstringFinal) isSubstring()   {}
func (_ SubstringAny) isSubstring()     {}

func (r Substrings) String() string {
	var init AssertionValue
	var fin AssertionValue
	var Any []AssertionValue

	for _, s := range r {
		switch v := s.(type) {
		case SubstringInitial:
			init = AssertionValue(v)
		case SubstringFinal:
			fin = AssertionValue(v)
		case SubstringAny:
			Any = v
		}
	}

	if len(init) == 0 && len(fin) == 0 && len(Any) == 0 {
		return ""
	}

	var b []byte

	if len(init) > 0 {
		b = append(b, init.Escaped()...)
	}

	if len(Any) == 0 {
		b = append(b, '*')
	} else {
		b = append(b, '*')
		for _, a := range Any {
			b = append(b, a.Escaped()...)
			b = append(b, '*')
		}
	}

	if len(fin) > 0 {
		b = append(b, fin.Escaped()...)
	}

	return string(b)
}

func marshalSubstrings(z any) (substrings Substrings, err error) {
	var x []byte
	x, err = assertSubstringAssertion(z)
	if err != nil {
		return
	}

	x = bytes.TrimSpace(x)
	if len(x) == 0 {
		err = errMinAster
		return
	}

	f := x[0] == '*'
	l := x[len(x)-1] == '*'

	hasStar := false
	prevStar := false
	for _, b := range x {
		if b == '*' {
			if prevStar {
				err = syntaxError("SubstringAssertion cannot contain consecutive asterisks")
				return
			}
			hasStar = true
			prevStar = true
		} else {
			prevStar = false
		}
	}

	if !hasStar {
		err = errMinAster
		return
	}

	var parts [][]byte
	start := 0

	for i, b := range x {
		if b == '*' {
			if start < i {
				seg := x[start:i]
				if err = assertionValueBytes(seg); err != nil {
					return
				}
				parts = append(parts, seg)
			}
			start = i + 1
		}
	}

	if start < len(x) {
		seg := x[start:]
		if err = assertionValueBytes(seg); err != nil {
			return
		}
		parts = append(parts, seg)
	}

	if len(parts) == 0 {
		err = errMinAster
		return
	}

	substrings = getSubstringTokens(parts, f, l)

	return
}

func getSubstringTokens(parts [][]byte, f, l bool) (substrings Substrings) {
	var initVal, finalVal AssertionValue
	var anyVals []AssertionValue

	n := len(parts)

	if !f && !l {
		initVal = AssertionValue(parts[0])
		if n > 1 {
			finalVal = AssertionValue(parts[n-1])
		}
		if n > 2 {
			anyVals = make([]AssertionValue, n-2)
			for i := 1; i < n-1; i++ {
				anyVals[i-1] = AssertionValue(parts[i])
			}
		}
	} else if !f && l {
		initVal = AssertionValue(parts[0])
		if n > 1 {
			anyVals = make([]AssertionValue, n-1)
			for i := 1; i < n; i++ {
				anyVals[i-1] = AssertionValue(parts[i])
			}
		}
	} else if f && !l {
		if n > 1 {
			finalVal = AssertionValue(parts[n-1])
			anyVals = make([]AssertionValue, n-1)
			for i := 0; i < n-1; i++ {
				anyVals[i] = AssertionValue(parts[i])
			}
		} else {
			finalVal = AssertionValue(parts[0])
		}
	} else {
		anyVals = make([]AssertionValue, n)
		for i := 0; i < n; i++ {
			anyVals[i] = AssertionValue(parts[i])
		}
	}

	substrings = buildSubstrings(initVal, finalVal, anyVals)
	return
}

func buildSubstrings(
	initVal, finalVal AssertionValue,
	anyVals []AssertionValue,
) (substrings Substrings) {
	substrings = make(Substrings, 0, 3)

	if len(initVal) > 0 {
		substrings = append(substrings, SubstringInitial(initVal))
	}

	substrings = append(substrings, SubstringAny(anyVals))

	if len(finalVal) > 0 {
		substrings = append(substrings, SubstringFinal(finalVal))
	}

	return
}

/*
NewSubstrings returns an instance of [Substrings] alongside an
error following an attempt to marshal x.
*/
func NewSubstrings(x any) (Substrings, error) {
	return marshalSubstrings(x)
}

func substringAssertion(x any) (result bool, err error) {
	_, err = marshalSubstrings(x)
	result = err == nil
	return
}

func assertSubstringAssertion(x any) (value []byte, err error) {
	switch tv := x.(type) {
	case string:
		value = []byte(tv)
	case []byte:
		value = tv
	case Substrings:
		value = []byte(tv.String())
	default:
		err = errorBadType("SubstringAssertion")
	}

	return
}

/*
IsAssertionValue returns a Boolean value indicative of x being
a valid [AssertionValue].

The variadic zeroOK argument (bool) instructs the parser as to
whether or not a zero-length value is acceptable.
*/
func IsAssertionValue(x any, zeroOK ...bool) bool {
	return assertionValueRunes(x, zeroOK...) == nil
}

func assertionValueRunes(x any, zok ...bool) (err error) {
	var raw []rune
	if raw, err = assertRunes(x, zok...); err != nil {
		return
	}

	_err := syntaxError("Invalid assertionvalue characters")
	for i := 0; i < len(raw) && err == nil; i++ {
		if raw[i] == '\\' {
			// Check if there are at least
			// two more characters
			if i+3 > len(raw) {
				err = _err
			} else if !isHex(rune(raw[i+1])) || !isHex(rune(raw[i+2])) {
				// the next two characters are not hex
				err = _err
			}
			// Skip the next two characters, as
			// we've already vetted them
			i += 2
		} else if !unicode.Is(uTF8SubsetRange, rune(raw[i])) {
			err = uTFMB(rune(raw[i]))
		}
	}

	return
}

func assertionValueBytes(raw []byte) (err error) {
	if len(raw) == 0 {
		return syntaxError("Invalid assertionvalue characters")
	}

	for i := 0; i < len(raw); {
		b := raw[i]

		if b < 0x80 {
			if b == '\\' {
				if i+3 > len(raw) {
					return badAssChar
				}
				if !isHex(rune(raw[i+1])) || !isHex(rune(raw[i+2])) {
					return badAssChar
				}
				i += 3
				continue
			}
			// ASCII in allowed ranges is fine; uTF8SubsetRange already excludes '*' and '\'
			i++
			continue
		}

		// UTF-8
		r, size := utf8.DecodeRune(raw[i:])
		if r == utf8.RuneError && size == 1 {
			return badAssChar
		}
		if !unicode.Is(uTF8SubsetRange, r) {
			return uTFMB(r)
		}
		i += size
	}

	return nil
}

/*
AssertionValue implements an OCTET STRING value.
*/
type AssertionValue OctetString

/*
Set assigns x to the receiver instance.
*/
func (r *AssertionValue) Set(x any) {
	var s string
	switch tv := x.(type) {
	case string:
		s = tv
	case []byte:
		s = string(tv)
	default:
		return
	}

	*r = AssertionValue(escapeString(s))
}

/*
String returns the string representation of the receiver instance.
Note that this method is an alias of [AssertionValue.Escaped].
*/
func (r AssertionValue) String() string {
	return r.Escaped()
}

/*
Unescaped returns the unescaped receiver value. For example, "ジェシー"
is returned instead of "\e3\82\b8\e3\82\a7\e3\82\b7\e3\83\bc".
*/
func (r AssertionValue) Unescaped() string {
	var u string
	if len(r) > 0 {
		u = hexDecode(string(r))
	}

	return u
}

func (r AssertionValue) Escaped() (esc string) {
	if len(r) > 0 {
		esc = escapeString(string(r))
	}

	return
}

var badAssChar = syntaxError("Invalid assertionvalue characters")
var errMinAster = syntaxError("SubstringAssertion requires at least one asterisk")
