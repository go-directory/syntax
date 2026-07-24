package syntax

/*
substr.go implements the substring assertion type.
*/

import (
	"errors"
	"strings"
	"unicode"
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
		bld := &strings.Builder{}

		if len(r.Initial) > 0 {
			bld.WriteString(r.Initial.String())
			bld.WriteString(Any())
			if len(r.Final) > 0 {
				bld.WriteString(r.Final.String())
			}
		} else if len(r.Final) > 0 {
			bld.WriteString(Any())
			bld.WriteString(r.Final.String())
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
	var x string
	if x, err = assertSubstringAssertion(z); err != nil {
		return
	}

	x = strings.TrimSpace(x)
	f := strings.HasPrefix(x, `*`)
	l := strings.HasSuffix(x, `*`)
	if strings.Contains(x, `**`) {
		err = errors.New("SubstringAssertion cannot contain consecutive asterisks")
		return
	} else if !strings.Contains(x, `*`) {
		err = errors.New("SubstringAssertion requires at least one asterisk")
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
	} else if !f && !l {
		ssa.Initial, ssa.Any, ssa.Final, err = substrProcess4(x)
	}

	return
}

func substrProcess1(x string) (a AssertionValue, err error) {
	z := x[1 : len(x)-1]
	sp := strings.Split(z, `*`)
	asp := strings.Join(sp, ``)
	if err = assertionValueRunes(asp); err == nil {
		a = AssertionValue(z)
	}

	return
}

func substrProcess2(x string) (a, f AssertionValue, err error) {
	z := x[1:]
	sp := strings.Split(z, `*`)
	for idx := 0; idx < len(sp) && err == nil; idx++ {
		err = assertionValueRunes(sp[idx])
	}

	if len(sp) == 1 {
		f = AssertionValue(sp[len(sp)-1])
	} else {
		a = AssertionValue(strings.Join(sp[:len(sp)-1], `*`))
		f = AssertionValue(sp[len(sp)-1])
	}

	return
}

func substrProcess3(x string) (i, a AssertionValue, err error) {
	z := x[:len(x)-1]
	sp := strings.Split(z, `*`)
	for idx := 0; idx < len(sp) && err == nil; idx++ {
		err = assertionValueRunes(sp[idx])
	}

	if len(sp) == 1 {
		i = AssertionValue(sp[0])
	} else {
		i = AssertionValue(sp[0])
		a = AssertionValue(strings.Join(sp[1:], `*`))
	}

	return
}

func substrProcess4(x string) (i, a, f AssertionValue, err error) {
	sp := strings.Split(x, `*`)
	for idx := 0; idx < len(sp) && err == nil; idx++ {
		err = assertionValueRunes(sp[idx])
	}

	switch len(sp) {
	case 0, 1:
		err = errors.New("SubstringAssertion requires at least one asterisk")
	case 2:
		i = AssertionValue(sp[0])
		f = AssertionValue(sp[1])
	default:
		i = AssertionValue(sp[0])
		a = AssertionValue(strings.Join(sp[1:len(sp)-1], `*`))
		f = AssertionValue(sp[len(sp)-1])
	}

	return
}

func assertSubstringAssertion(x any) (value string, err error) {
	switch tv := x.(type) {
	case string:
		value = tv
	case []byte:
		value = string(tv)
	case SubstringAssertion:
		value = tv.String()
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

	_err := errors.New("Invalid assertionvalue characters")
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
