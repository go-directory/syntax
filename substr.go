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
SubstringAssertion implements the Substring Assertion.

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

[§ 2 of RFC 4515]: https://datatracker.ietf.org/doc/html/rfc4515#section-2
[§ 3 of RFC 4515]: https://datatracker.ietf.org/doc/html/rfc4515#section-3
[§ 3.3.30 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.30
*/
type SubstringAssertion struct {
	Initial AssertionValue `asn1:"tag:0"`
	Any     AssertionValue `asn1:"tag:1"`
	Final   AssertionValue `asn1:"tag:2"`
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r SubstringAssertion) IsZero() bool {
	return len(r.Initial) == 0 &&
		len(r.Any) == 0 &&
		len(r.Final) == 0
}

/*
String returns the string representation of the receiver instance.
*/
func (r SubstringAssertion) String() (s string) {
	Any := func() string {
		if len(r.Any) > 0 {
			return `*` + r.Any.String() + `*`
		}
		return `*`
	}

	if !r.IsZero() {
		bld := &bytes.Buffer{}

		if len(r.Initial) > 0 {
			bld.Write(r.Initial)
			bld.WriteString(Any())
			if len(r.Final) > 0 {
				bld.Write(r.Final)
			}
		} else if len(r.Final) > 0 {
			bld.WriteString(Any())
			bld.Write(r.Final)
		} else {
			// If a star is the only value,
			// don't save anything.
			bld.WriteString(Any())
		}

		s = bld.String()
	}

	return
}

/*
NewSubstringAssertion returns an error following an analysis of x
in the context of a Substring Assertion.
*/
func NewSubstringAssertion(x any) (SubstringAssertion, error) {
	return marshalSubstringAssertion(x)
}

func substringAssertion(x any) (result bool, err error) {
	_, err = marshalSubstringAssertion(x)
	result = err == nil
	return
}

func marshalSubstringAssertion(z any) (ssa SubstringAssertion, err error) {
	var x []byte
	if x, err = assertSubstringAssertion(z); err != nil {
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

	if f && l {
		// Any only
		ssa.Any, err = substrProcess1(x)
	} else if f && !l {
		// Final + Any
		ssa.Any, ssa.Final, err = substrProcess2(x)
	} else if !f && l {
		// Initial + Any
		ssa.Initial, ssa.Any, err = substrProcess3(x)
	} else {
		// Initial + Any + Final
		ssa.Initial, ssa.Any, ssa.Final, err = substrProcess4(x)
	}

	return
}

func substrProcess1(x []byte) (a AssertionValue, err error) {
	if len(x) < 2 {
		err = errMinAster
		return
	}

	z := x[1 : len(x)-1]

	var buf []byte
	start := 0

	for idx := 0; idx < len(z); idx++ {
		if z[idx] == '*' {
			if start < idx {
				buf = append(buf, z[start:idx]...)
			}
			start = idx + 1
		}
	}

	if start < len(z) {
		buf = append(buf, z[start:]...)
	}

	if err = assertionValueBytes(buf); err == nil {
		a = AssertionValue(z)
	}

	return
}

func substrProcess2(x []byte) (a, f AssertionValue, err error) {
	if len(x) < 2 {
		err = errMinAster
		return
	}

	z := x[1:]
	var parts [][]byte
	start := 0

	for i := 0; i < len(z); i++ {
		if z[i] == '*' {
			seg := z[start:i]
			if len(seg) > 0 {
				if err = assertionValueBytes(seg); err != nil {
					return
				}
				parts = append(parts, seg)
				start = i + 1
			}
		}
	}

	if start < len(z) {
		seg := z[start:]
		if err = assertionValueBytes(seg); err != nil {
			return
		}
		parts = append(parts, seg)
	}

	if len(parts) == 0 {
		err = errMinAster
		return
	}

	if len(parts) == 1 {
		f = AssertionValue(parts[0])
	} else {
		var buf bytes.Buffer
		for i := 0; i < len(parts)-1; i++ {
			if i > 0 {
				buf.WriteByte('*')
			}
			buf.Write(parts[i])
		}
		a = AssertionValue(buf.Bytes())
		f = AssertionValue(parts[len(parts)-1])
	}

	return
}

func substrProcess3(x []byte) (i, a AssertionValue, err error) {
	if len(x) < 2 {
		err = errMinAster
		return
	}

	z := x[:len(x)-1]
	var parts [][]byte
	start := 0

	for idx := 0; idx < len(z); idx++ {
		if z[idx] == '*' {
			seg := z[start:idx]
			if len(seg) > 0 {
				if err = assertionValueBytes(seg); err != nil {
					return
				}
				parts = append(parts, seg)
				start = idx + 1
			}
		}
	}

	if start < len(z) {
		seg := z[start:]
		if err = assertionValueBytes(seg); err != nil {
			return
		}
		parts = append(parts, seg)
	}

	if len(parts) == 0 {
		err = errMinAster
		return
	}

	if len(parts) == 1 {
		i = AssertionValue(parts[0])
		return
	}

	i = AssertionValue(parts[0])

	var buf bytes.Buffer
	for idx := 1; idx < len(parts); idx++ {
		if idx > 1 {
			buf.WriteByte('*')
		}
		buf.Write(parts[idx])
	}
	a = AssertionValue(buf.Bytes())

	return
}

func substrProcess4(x []byte) (i, a, f AssertionValue, err error) {
	var parts [][]byte
	start := 0

	for idx := 0; idx < len(x); idx++ {
		if x[idx] == '*' {
			seg := x[start:idx]
			if len(seg) > 0 {
				if err = assertionValueBytes(seg); err != nil {
					return
				}
				parts = append(parts, seg)
				start = idx + 1
			}
		}
	}

	if start < len(x) {
		seg := x[start:]
		if err = assertionValueBytes(seg); err != nil {
			return
		}
		parts = append(parts, seg)
	}

	switch len(parts) {
	case 0, 1:
		err = errMinAster
	case 2:
		i = AssertionValue(parts[0])
		f = AssertionValue(parts[1])
	default:
		i = AssertionValue(parts[0])

		var buf bytes.Buffer
		for idx := 1; idx < len(parts)-1; idx++ {
			if idx > 1 {
				buf.WriteByte('*')
			}
			buf.Write(parts[idx])
		}
		a = AssertionValue(buf.Bytes())
		f = AssertionValue(parts[len(parts)-1])
	}

	return
}

func assertSubstringAssertion(x any) (value []byte, err error) {
	switch tv := x.(type) {
	case string:
		value = []byte(tv)
	case []byte:
		value = tv
	case SubstringAssertion:
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
type AssertionValue []byte

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
