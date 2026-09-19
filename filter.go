package syntax

/*
filter.go contains RFC4515 methods and types.
*/

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
)

/*
NewFilter returns a [Filter] qualifier instance alongside an error.

If the input is nil, [DefaultFilter] ([FilterPresent]) is returned
("(objectClass=*)").

If the input is a []byte or string, an attempt to marshal the value
is made. If the string is zero, this is equivalent to providing nil.

If the input type is an instance of [Refinement], an attempt is made
to create a new equality-focused [Filter] based on the parameters of
that [Refinement].

Any errors found will result in the return of an invalid [Filter] instance.
*/
func NewFilter(x any) (Filter, error) {
	return marshalFilter(x)
}

/*
DefaultFilter implements the official default LDAP Search Filter of
"(objectClass=*)".
*/
var DefaultFilter Filter = FilterPresent{Desc: AttributeDescription(`objectClass`)}

func marshalFilter(x any) (f Filter, err error) {
	var raw []byte
	switch tv := x.(type) {
	case nil:
		// Nil returns the default filter.
		f = DefaultFilter
		return
	case []byte:
		if len(tv) == 0 {
			f = DefaultFilter
			return
		}
		raw = tv
	case Refinement:
		f = refinementToFilter(tv)
		return
	case string:
		if len(tv) == 0 {
			f = DefaultFilter
			return
		}
		raw = []byte(tv)
	default:
		err = errorBadType("Search Filter")
		return
	}

	if f, err = parseSubFilter(raw); f == nil {
		// just to avoid panics in the event
		// the user does not check errors.
		f = invalidFilter{}
		err = invalidFilterErr
	}

	return
}

/*
Filter implements [§ 2] and [§ 3] of RFC4515.

[§ 2]: https://datatracker.ietf.org/doc/html/rfc4515#section-2
[§ 3]: https://datatracker.ietf.org/doc/html/rfc4515#section-3
*/
type Filter interface {
	// Index returns the Nth slice index found within
	// the receiver instance. This is only useful if
	// the receiver is an FilterAnd or FilterOr Filter
	// qualifier type instance.
	Index(int) Filter

	// IsZero returns a Boolean value indicative of
	// a nil receiver state.
	IsZero() bool

	// String returns the string representation of
	// the receiver instance.
	String() string

	// Choice returns the string CHOICE "name" of the
	// receiver instance. Use of this method is merely
	// intended as a convenient alternative to type
	// assertion checks.
	Choice() string

	// Tag returns the integer form of the CHOICE of
	// Filter. This is used for ASN.1 encoding.
	Tag() int

	// Encode returns the ASN.1 encoding for the receiver
	// instance alongside an error.
	Encode() ([]byte, error)

	// Len returns the integer length of the receiver
	// instance. This is only useful if the receiver is
	// an FilterAnd or FilterOr Filter qualifier type
	// instance.
	Len() int

	// Differentiate Filter qualifiers from other
	// unrelated interfaces.
	isFilter()
}

type invalidFilter struct{}

/*
FilterAnd implements the "and" CHOICE of an instance of [Filter].
*/
type FilterAnd []Filter

/*
FilterOr implements the "or" CHOICE of an instance of [Filter].
*/
type FilterOr []Filter

/*
FilterNot implements the "not" CHOICE of an instance of [Filter].
*/
type FilterNot struct {
	Filter
}

/*
FilterEqualityMatch aliases the [AttributeValueAssertion] type to implement
the "equalityMatch" CHOICE of an instance of [Filter].
*/
type FilterEqualityMatch AttributeValueAssertion

/*
FilterGreaterOrEqual aliases the [AttributeValueAssertion] type to implement
the "greaterOrEqual" CHOICE of an instance of [Filter].
*/
type FilterGreaterOrEqual AttributeValueAssertion

/*
FilterLessOrEqual aliases the [AttributeValueAssertion] type to implement
the "lessOrEqual" CHOICE of an instance of [Filter].
*/
type FilterLessOrEqual AttributeValueAssertion

/*
FilterApproximateMatch aliases the [AttributeValueAssertion] type to implement
the "approxMatch" CHOICE of an instance of [Filter].
*/
type FilterApproximateMatch AttributeValueAssertion

/*
AttributeValueAssertion implements the basis for [FilterApproximateMatch],
[FilterGreaterOrEqual], [FilterLessOrEqual] and [FilterEqualityMatch]
instances.

	AttributeValueAssertion ::= SEQUENCE {
	    attributeDesc   AttributeDescription,
	    assertionValue  AssertionValue }
*/
type AttributeValueAssertion struct {
	Desc  AttributeDescription
	Value AssertionValue
}

/*
FilterPresent implements the "present" CHOICE of an instance of [Filter].
*/
type FilterPresent struct {
	Desc AttributeDescription
}

type MatchingRuleID LDAPString

/*
FilterExtensibleMatch aliases the [MatchingRuleAssertion] to implement
the "extensibleMatch" CHOICE of an instance of [Filter].
*/
type FilterExtensibleMatch MatchingRuleAssertion

/*
MatchingRuleAssertion implements the basis of [FilterExtensibleMatch].

	MatchingRuleAssertion ::= SEQUENCE {
	    matchingRule    [1] MatchingRuleId OPTIONAL,
	    type            [2] AttributeDescription OPTIONAL,
	    matchValue      [3] AssertionValue,
	    dnAttributes    [4] BOOLEAN DEFAULT FALSE }
*/
type MatchingRuleAssertion struct {
	MatchingRule MatchingRuleID       `asn1:"tag:1,optional"`
	Type         AttributeDescription `asn1:"tag:2,optional"`
	MatchValue   AssertionValue       `asn1:"tag:3"`
	DNAttributes Boolean              `asn1:"tag:4,default:false"`
}

/*
FilterSubstrings implements the "substrings" CHOICE of an instance of [Filter].
*/
type FilterSubstrings struct {
	Type       AttributeDescription
	Substrings Substrings
}

/*
String returns the string representation of the receiver instance.
*/
func (r MatchingRuleID) String() string { return string(r) }

// differentiate Filter qualifiers from other interfaces.
func (r invalidFilter) isFilter()          {}
func (r FilterAnd) isFilter()              {}
func (r FilterNot) isFilter()              {}
func (r FilterOr) isFilter()               {}
func (r FilterEqualityMatch) isFilter()    {}
func (r FilterPresent) isFilter()          {}
func (r FilterSubstrings) isFilter()       {}
func (r FilterExtensibleMatch) isFilter()  {}
func (r FilterApproximateMatch) isFilter() {}
func (r FilterGreaterOrEqual) isFilter()   {}
func (r FilterLessOrEqual) isFilter()      {}

func (_ invalidFilter) IsZero() bool { return true }
func (_ invalidFilter) Encode() ([]byte, error) {
	return nil, errors.New("Cannot encode invalid Filter")
}
func (_ invalidFilter) Decode(_ []byte) error {
	return errors.New("Cannot decode invalid Filter")
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterAnd) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterOr) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterNot) IsZero() bool { return r.Filter == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterEqualityMatch) IsZero() bool {
	return len(r.Desc) == 0 &&
		r.Value == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterGreaterOrEqual) IsZero() bool {
	return len(r.Desc) == 0 &&
		r.Value == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterLessOrEqual) IsZero() bool {
	return len(r.Desc) == 0 &&
		r.Value == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterApproximateMatch) IsZero() bool {
	return len(r.Desc) == 0 &&
		r.Value == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterPresent) IsZero() bool { return len(r.Desc) == 0 }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterSubstrings) IsZero() bool {
	return len(r.Type) == 0 &&
		len(r.Substrings) == 0
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterExtensibleMatch) IsZero() bool {
	return len(r.MatchingRule) == 0 &&
		len(r.Type) == 0 &&
		len(r.MatchValue) == 0 &&
		!bool(r.DNAttributes)
}

/*
Index returns the Nth [Filter] slice instance from within the receiver.
*/
func (r FilterAnd) Index(idx int) (f Filter) {
	f = invalidFilter{}

	if !r.IsZero() {
		if 0 <= idx && idx < r.Len() {
			f = r[idx]
		}
	}

	return
}

/*
Index returns the Nth [Filter] slice instance from within the receiver.
*/
func (r FilterOr) Index(idx int) (f Filter) {
	f = invalidFilter{}

	if !r.IsZero() {
		if 0 <= idx && idx < r.Len() {
			f = r[idx]
		}
	}

	return
}

/*
Index returns the Nth [Filter] slice instance from within the receiver.
*/
func (r FilterNot) Index(idx int) (f Filter) {
	f = invalidFilter{}

	if !r.IsZero() {
		f = r.Filter.Index(idx)
	}

	return
}

/*
Index returns an invalid [Filter] instance. This method only exists to
satisfy Go's interface signature requirement.
*/
func (r invalidFilter) Index(_ int) Filter {
	return r
}

/*
Index returns the receiver instance of [Filter]. This method only exists
to satisfy Go's interface signature requirement.
*/
func (r FilterGreaterOrEqual) Index(_ int) (f Filter) {
	f = invalidFilter{}

	if !r.IsZero() {
		f = r
	}

	return
}

/*
Index returns the receiver instance of [Filter]. This method only exists
to satisfy Go's interface signature requirement.
*/
func (r FilterLessOrEqual) Index(_ int) (f Filter) {
	f = invalidFilter{}

	if !r.IsZero() {
		f = r
	}

	return
}

/*
Index returns the receiver instance of [Filter]. This method only exists
to satisfy Go's interface signature requirement.
*/
func (r FilterEqualityMatch) Index(_ int) (f Filter) {
	f = invalidFilter{}

	if !r.IsZero() {
		f = r
	}

	return
}

/*
Index returns the receiver instance of [Filter]. This method only exists
to satisfy Go's interface signature requirement.
*/
func (r FilterSubstrings) Index(_ int) (f Filter) {
	f = invalidFilter{}

	if !r.IsZero() {
		f = r
	}

	return
}

/*
Index returns the receiver instance of [Filter]. This method only exists
to satisfy Go's interface signature requirement.
*/
func (r FilterApproximateMatch) Index(_ int) (f Filter) {
	f = invalidFilter{}

	if !r.IsZero() {
		f = r
	}

	return
}

/*
Index returns the receiver instance of [Filter]. This method only exists
to satisfy Go's interface signature requirement.
*/
func (r FilterPresent) Index(_ int) (f Filter) {
	f = invalidFilter{}

	if !r.IsZero() {
		f = r
	}

	return
}

/*
Index returns the receiver instance of [Filter]. This method only exists
to satisfy Go's interface signature requirement.
*/
func (r FilterExtensibleMatch) Index(_ int) (f Filter) {
	f = invalidFilter{}

	if !r.IsZero() {
		f = r
	}

	return
}

/*
String returns a zero string.
*/
func (r invalidFilter) String() string { return `` }

/*
String returns the string representation of the receiver instance.
*/
func (r FilterAnd) String() (s string) {
	if !r.IsZero() {
		var parts []string
		for _, ref := range r {
			parts = append(parts, ref.String())
		}
		bld := &strings.Builder{}
		bld.WriteString("(&")
		bld.WriteString(strings.Join(parts, ""))
		bld.WriteRune(')')
		s = bld.String()
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r FilterOr) String() (s string) {
	if !r.IsZero() {
		var parts []string
		for _, ref := range r {
			parts = append(parts, ref.String())
		}
		bld := &strings.Builder{}
		bld.WriteString("(|")
		bld.WriteString(strings.Join(parts, ""))
		bld.WriteRune(')')
		s = bld.String()
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r FilterNot) String() (s string) {
	if !r.IsZero() {
		bld := &strings.Builder{}
		bld.WriteString("(!")
		bld.WriteString(r.Filter.String())
		bld.WriteRune(')')
		s = bld.String()
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r FilterEqualityMatch) String() (s string) {
	if !r.IsZero() {
		bld := &strings.Builder{}
		bld.WriteRune('(')
		bld.Write(r.Desc)
		bld.WriteRune('=')
		bld.WriteString(r.Value.String())
		bld.WriteRune(')')
		s = bld.String()
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r FilterGreaterOrEqual) String() (s string) {
	if !r.IsZero() {
		bld := &strings.Builder{}
		bld.WriteRune('(')
		bld.Write(r.Desc)
		bld.WriteString(">=")
		bld.WriteString(r.Value.String())
		bld.WriteRune(')')
		s = bld.String()
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r FilterLessOrEqual) String() (s string) {
	if !r.IsZero() {
		bld := &strings.Builder{}
		bld.WriteRune('(')
		bld.Write(r.Desc)
		bld.WriteString("<=")
		bld.WriteString(r.Value.String())
		bld.WriteRune(')')
		s = bld.String()
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r FilterApproximateMatch) String() (s string) {
	if !r.IsZero() {
		bld := &strings.Builder{}
		bld.WriteRune('(')
		bld.Write(r.Desc)
		bld.WriteString("~=")
		bld.WriteString(r.Value.String())
		bld.WriteRune(')')
		s = bld.String()
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r FilterPresent) String() (s string) {
	if !r.IsZero() {
		bld := &strings.Builder{}
		bld.WriteRune('(')
		bld.Write(r.Desc)
		bld.WriteString("=*)")
		s = bld.String()
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r FilterSubstrings) String() (s string) {
	if !r.IsZero() {
		bld := &strings.Builder{}
		bld.WriteRune('(')
		bld.Write(r.Type)
		bld.WriteRune('=')
		bld.WriteString(r.Substrings.String())
		bld.WriteRune(')')
		s = bld.String()
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r FilterExtensibleMatch) String() (s string) {
	if !r.IsZero() {
		if r.MatchValue == nil {
			// always required here.
			return
		}

		value := r.MatchValue.String()
		typ := r.Type
		mr := r.MatchingRule
		dna := r.DNAttributes
		bld := &strings.Builder{}

		if len(typ) > 0 && len(mr) == 0 {
			if dna {
				bld.Write(typ)
				bld.WriteString(`:dn:=`)
				bld.WriteString(value)
			} else {
				bld.Write(typ)
				bld.WriteString(`:=`)
				bld.WriteString(value)
			}
		} else if len(typ) == 0 && len(mr) > 0 {
			if dna {
				bld.WriteString(`:dn:`)
				bld.Write(mr)
				bld.WriteString(`:=`)
				bld.WriteString(value)
			} else {
				bld.WriteRune(':')
				bld.Write(mr)
				bld.WriteString(`:=`)
				bld.WriteString(value)
			}
		} else if len(typ) > 0 && len(mr) > 0 {
			if dna {
				bld.Write(typ)
				bld.WriteString(`:dn:`)
				bld.Write(mr)
				bld.WriteString(`:=`)
				bld.WriteString(value)
			} else {
				bld.Write(typ)
				bld.WriteRune(':')
				bld.Write(mr)
				bld.WriteString(`:=`)
				bld.WriteString(value)
			}
		}

		if bld.Len() > 0 {
			b := &strings.Builder{}
			b.WriteRune('(')
			b.WriteString(bld.String())
			b.WriteRune(')')
			s = b.String()
		}
	}

	return
}

func (r invalidFilter) Choice() string { return "invalid" }

/*
Choice returns the string literal CHOICE "and".
*/
func (r FilterAnd) Choice() string { return "and" }

/*
Choice returns the string literal CHOICE "or".
*/
func (r FilterOr) Choice() string { return "or" }

/*
Choice returns the string literal CHOICE "not".
*/
func (r FilterNot) Choice() string { return "not" }

/*
Choice returns the string literal CHOICE "equalityMatch".
*/
func (r FilterEqualityMatch) Choice() string { return "equalityMatch" }

/*
Choice returns the string literal CHOICE "greaterOrEqual".
*/
func (r FilterGreaterOrEqual) Choice() string { return "greaterOrEqual" }

/*
Choice returns the string literal CHOICE "lessOrEqual".
*/
func (r FilterLessOrEqual) Choice() string { return "lessOrEqual" }

/*
Choice returns the string literal CHOICE "approxMatch".
*/
func (r FilterApproximateMatch) Choice() string { return "approxMatch" }

/*
Choice returns the string literal CHOICE "present".
*/
func (r FilterPresent) Choice() string { return "present" }

/*
Choice returns the string literal CHOICE "substrings".
*/
func (r FilterSubstrings) Choice() string { return "substrings" }

/*
Choice returns the string literal CHOICE "extensibleMatch".
*/
func (r FilterExtensibleMatch) Choice() string { return "extensibleMatch" }

func (r invalidFilter) Len() int { return 0 }

/*
Len returns the integer length of the receiver instance.
*/
func (r FilterAnd) Len() int { return len(r) }

/*
Len returns the integer length of the receiver instance.
*/
func (r FilterOr) Len() int { return len(r) }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r FilterNot) Len() (l int) {
	if !r.IsZero() {
		l = r.Filter.Len()
	}

	return
}

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r FilterEqualityMatch) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r FilterGreaterOrEqual) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r FilterLessOrEqual) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r FilterApproximateMatch) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r FilterPresent) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r FilterSubstrings) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r FilterExtensibleMatch) Len() int { return 1 }

func (_ FilterAnd) Tag() int              { return tagFilterAnd }
func (_ FilterOr) Tag() int               { return tagFilterOr }
func (_ FilterNot) Tag() int              { return tagFilterNot }
func (_ FilterEqualityMatch) Tag() int    { return tagFilterEqualityMatch }
func (_ FilterSubstrings) Tag() int       { return tagFilterSubstrings }
func (_ FilterGreaterOrEqual) Tag() int   { return tagFilterGreaterOrEqual }
func (_ FilterLessOrEqual) Tag() int      { return tagFilterLessOrEqual }
func (_ FilterPresent) Tag() int          { return tagFilterPresent }
func (_ FilterApproximateMatch) Tag() int { return tagFilterApproxMatch }
func (_ FilterExtensibleMatch) Tag() int  { return tagFilterExtensibleMatch }
func (_ invalidFilter) Tag() int          { return tagFilterInvalid }

func (r MatchingRuleAssertion) IsZero() bool {
	return len(r.MatchingRule) == 0 &&
		len(r.Type) == 0 &&
		len(r.MatchValue) == 0 &&
		!bool(r.DNAttributes)
}

func parseSubFilter(input []byte) (f Filter, err error) {
	if input = bytes.TrimSpace(input); len(input) == 0 {
		f = DefaultFilter
		return
	} else if bytes.Contains(input, []byte(`((`)) || !checkParenBalanced(input) {
		err = endOfFilterErr
		f = invalidFilter{}
		return
	}

	switch {
	case bHasPfx(input, []byte("(&")):
		f, err = parseFilterAnd(input)
	case bHasPfx(input, []byte("(|")):
		f, err = parseFilterOr(input)
	case bHasPfx(input, []byte("(!")):
		f, err = parseFilterNot(input)
	default:
		f, err = parseItemFilter(input)
	}

	return
}

func parseFilterAnd(input []byte) (Filter, error) {
	return parseComplexFilter(input[2:len(input)-1], "&")
}

func parseFilterOr(input []byte) (Filter, error) {
	return parseComplexFilter(input[2:len(input)-1], "|")
}

func parseFilterNot(input []byte) (f Filter, err error) {
	f = invalidFilter{}
	if len(input) < 8 {
		err = invalidFilterErr
		return
	}

	var subRef Filter
	if subRef, err = parseSubFilter(input[2 : len(input)-1]); err == nil {
		f = FilterNot{subRef}
	}

	return
}

func parseComplexFilter(input []byte, prefix string) (Filter, error) {
	var refs []Filter
	parts := splitFilterParts(input)
	for _, part := range parts {
		subRef, err := parseSubFilter(part)
		if err != nil {
			return nil, err
		}
		refs = append(refs, subRef)
	}
	if prefix == "&" {
		return FilterAnd(refs), nil
	}
	return FilterOr(refs), nil
}

func parseItemFilter(input []byte) (f Filter, err error) {
	f = invalidFilter{}
	idx := bytes.Index(input, []byte("="))
	if idx == -1 {
		err = invalidFilterErr
		return
	}

	var cerr error // assertionValue character set errors

	pre, after := input[:idx], input[idx+1:]

	// Verify parenthetical encapsulation is balanced
	if err = checkParenEncaps(pre, after); err != nil {
		return
	}

	checkAssnValue := func(x []byte) (err error) {
		if !IsAssertionValue(string(x), true) {
			err = errors.New("Invalid assertion value: " + string(x))
		}
		return
	}

	// Now that we've verified them, parenthetical
	// encapsulators will just get in the way, so
	// let's strip them off. They will reappear
	// during string representation.
	pre = bRepAll(pre, []byte(`(`), []byte(``))
	after = bRepAll(after, []byte(`)`), []byte(``))

	if beq(after, []byte(`*`)) {
		err = checkFilterOIDs(pre, []byte(``))
		f = FilterPresent{
			Desc: AttributeDescription(pre)}
	} else if bHasSfx(pre, []byte(`>`)) {
		err = checkFilterOIDs(pre[:len(pre)-1], []byte(``))
		cerr = checkAssnValue(after)
		f = FilterGreaterOrEqual{
			AttributeDescription(pre[:len(pre)-1]),
			AssertionValue(after)}
	} else if bHasSfx(pre, []byte(`<`)) {
		err = checkFilterOIDs(pre[:len(pre)-1], []byte(``))
		cerr = checkAssnValue(after)
		f = FilterLessOrEqual{
			AttributeDescription(pre[:len(pre)-1]),
			AssertionValue(after)}
	} else if bHasSfx(pre, []byte(`~`)) {
		err = checkFilterOIDs(pre[:len(pre)-1], []byte(``))
		cerr = checkAssnValue(after)
		f = FilterApproximateMatch{
			AttributeDescription(pre[:len(pre)-1]),
			AssertionValue(after)}
	} else if bytes.Contains(after, []byte("*")) {
		var ssa Substrings
		if ssa, err = NewSubstrings(after); err == nil {
			err = checkFilterOIDs(pre, []byte(``))
			f = FilterSubstrings{
				Type:       AttributeDescription(pre),
				Substrings: ssa}
		}
	} else if bytes.Contains(pre, []byte(":")) {
		f, err = parseExtensibleMatch(pre, after)
		cerr = checkAssnValue(after)
	} else {
		err = checkFilterOIDs(pre, []byte(``))
		cerr = checkAssnValue(after)
		f = FilterEqualityMatch{
			Desc:  AttributeDescription(pre),
			Value: AssertionValue(after)}
	}

	if err != nil || cerr != nil {
		f = invalidFilter{}
	}

	return
}

func parseExtensibleMatch(a, b []byte) (f Filter, err error) {
	scol := bHasPfx(a, []byte(`:`))
	sdn := bHasPfx(a, lDN) || bHasPfx(a, uDN)

	val := AssertionValue(b)
	_f := FilterExtensibleMatch{}

	if !scol {
		if !valueIsDNAttrs(a) {
			if idx := bytes.IndexRune(a, ':'); idx != -1 {
				mr := bytes.Trim(a[idx+1:], `:`)
				err = checkFilterOIDs(a[:idx], mr)
				_f.Type = AttributeDescription(a[:idx])
				_f.MatchingRule = MatchingRuleID(mr)
			}
		} else {
			_f.DNAttributes = true
			if c := dnAttrSplit(a); len(c) == 2 {
				mr := bytes.Trim(c[1], `:`)
				err = checkFilterOIDs(c[0], mr)
				if len(c[0]) > 0 && len(c[1]) > 0 {
					_f.Type = AttributeDescription(c[0])
					_f.MatchingRule = MatchingRuleID(mr)
				} else if len(c[0]) > 0 {
					_f.Type = AttributeDescription(c[0])
					//} else if mr != "" {
					//_f.MatchingRule = mr
				}
			}
		}
		_f.MatchValue = val
	} else if scol {
		if sdn {
			_f.DNAttributes = true
			_f.MatchingRule = MatchingRuleID(a[4 : len(a)-1])
		} else {
			_f.MatchingRule = MatchingRuleID(a[1 : len(a)-1])
		}
		err = checkFilterOIDs([]byte(``), _f.MatchingRule)
		_f.MatchValue = val
	}

	if err == nil && !_f.IsZero() {
		f = _f
	}

	return
}

// Verify parenthetical encapsulation is balanced
func checkParenEncaps(a, b []byte) (err error) {
	lencap := bHasPfx(a, []byte(`(`))
	rencap := bHasSfx(b, []byte(`)`))
	if lencap && !rencap {
		err = endOfFilterErr
	} else if !lencap && rencap {
		err = endOfFilterErr
	}

	return
}

func checkParenBalanced(x []byte) bool {
	return bytes.Count(x, []byte(`(`)) == bytes.Count(x, []byte(`)`))
}

func checkFilterOIDs(t, m []byte) (err error) {
	if len(t) > 0 {
		tsp := bytes.Split(t, []byte(`;`)) // disregard tags for OID resolution
		if !isOIDOrDescr(tsp[0]) {
			err = syntaxError("Filter: invalid OID or descriptor: '", string(t), "'")
			return
		}
	}
	if len(m) > 0 {
		if !isOIDOrDescr(m) {
			err = syntaxError("Filter: invalid OID or descriptor: '", string(m), "'")
		}
	}

	return
}

func isOIDOrDescr(x []byte) bool {
	if len(x) == 0 {
		return false
	}
	first := rune(x[0])
	if ('a' <= first && first <= 'z') || ('A' <= first && first <= 'Z') {
		return descrSyntaxCheck(x)
	} else if '0' <= first && first <= '9' {
		return oIDSyntaxCheck(x)
	}

	return false
}

func descrSyntaxCheck(x []byte) bool {
	alnum := func(r rune) bool {
		return ('a' <= r && r <= 'z') ||
			('A' <= r && r <= 'Z') ||
			('0' <= r && r <= '9')
	}

	// can only end in alnum.
	if !alnum(rune(x[len(x)-1])) {
		return false
	}

	// watch hyphens to avoid contiguous use
	var lastHyphen bool

	// iterate all characters in x, checking
	// each one for "descr" validity.
	for i := 0; i < len(x); i++ {
		ch := rune(x[i])
		switch {
		case alnum(ch):
			lastHyphen = false
		case ch == '-':
			if lastHyphen {
				// cannot use consecutive hyphens
				return false
			}
			lastHyphen = true
		default:
			return false
		}
	}

	return true
}

func isValidArc(arc []byte) bool {
	if bHasPfx(arc, []byte(`-`)) {
		// can't be negative
		return false
	}
	if len(arc) > 1 && arc[0] == '0' {
		// base10 only
		return false
	}
	for i := 0; i < len(arc); i++ {
		if !('0' <= rune(arc[i]) && rune(arc[i]) <= '9') {
			return false
		}
	}
	return true
}

func oIDSyntaxCheck(o []byte) bool {
	O := splitOnByte(o, 0x2E) // "."
	if len(O) < 2 {
		return false
	}

	switch rune(O[0][0]) {
	case '0', '1':
		if i, err := strconv.Atoi(string(O[1])); err != nil {
			return false
		} else if !(0 <= i && i <= 39) {
			return false
		}
	case '2':
	default:
		return false
	}

	var res bool = true
	for i := 1; i < len(O[1:]) && res; i++ {
		res = isValidArc(O[i])
	}

	return res
}

func splitFilterParts(input []byte) [][]byte {
	var parts [][]byte
	currentPart := &bytes.Buffer{}
	depth := 0

	for _, char := range input {
		switch char {
		case '(':
			if depth == 0 && currentPart.Len() > 0 {
				b := currentPart.Bytes()
				part := make([]byte, len(b))
				copy(part, b)
				parts = append(parts, part)
				currentPart.Reset()
			}
			depth++
		case ')':
			depth--
		}
		currentPart.WriteByte(char)
	}

	if currentPart.Len() > 0 {
		b := currentPart.Bytes()
		part := make([]byte, len(b))
		copy(part, b)
		parts = append(parts, part)
	}

	return parts
}

func valueIsDNAttrs(x []byte) bool {
	return bytes.Contains(x, lDN) ||
		bytes.Contains(x, uDN)
}

var (
	lDN = []byte(":dn:")
	uDN = []byte(":DN:")
)

func dnAttrSplit(x []byte) (slice [][]byte) {
	lo := bytes.Contains(x, lDN)
	hi := bytes.Contains(x, uDN)
	if lo && !hi {
		slice = bytes.Split(x, lDN)
	} else if !lo && hi {
		slice = bytes.Split(x, uDN)
	}

	return
}

/*
func assertString(x any, min int, name string) (str string, err error) {
	switch tv := x.(type) {
	case []byte:
		str, err = assertString(string(tv), min, name)
	case string:
		if len(tv) < min && min != 0 {
			err = errorBadLength(name, 0)
			break
		}
		str = tv
	default:
		err = errorBadType(name)
	}

	return
}
*/

/*
refinementToFilter returns an EQUALITY-focused instance of Filter
based on the contents of the input Refinement instance.
*/
func refinementToFilter(r Refinement) (f Filter) {
	if r == nil {
		f = DefaultFilter
		return
	}

	switch tv := r.(type) {
	case RefinementAnd:
		_f := FilterAnd{}
		for i := 0; i < tv.Len(); i++ {
			_f = append(_f, refinementToFilter(tv[i]))
		}
		f = _f
	case RefinementOr:
		_f := FilterOr{}
		for i := 0; i < tv.Len(); i++ {
			_f = append(_f, refinementToFilter(tv[i]))
		}
		f = _f
	case RefinementNot:
		f = FilterNot{
			Filter: refinementToFilter(tv.Refinement),
		}
	case RefinementItem:
		f = FilterEqualityMatch{Desc: []byte(`objectClass`), Value: []uint8(tv)}
	}

	return
}

const (
	tagMatchingRuleAssertionMatchingRule = 1
	tagMatchingRuleAssertionType         = 2
	tagMatchingRuleAssertionMatchValue   = 3
	tagMatchingRuleAssertionDnAttributes = 4
)

/*
Context tags per § 2 of RFC 4515:

	Filter ::= CHOICE {
	    and                [0] SET SIZE (1..MAX) OF filter Filter,
	    or                 [1] SET SIZE (1..MAX) OF filter Filter,
	    not                [2] Filter,
	    equalityMatch      [3] AttributeValueAssertion,
	    substrings         [4] SubstringFilter,
	    greaterOrEqual     [5] AttributeValueAssertion,
	    lessOrEqual        [6] AttributeValueAssertion,
	    present            [7] AttributeDescription,
	    approxMatch        [8] AttributeValueAssertion,
	    extensibleMatch    [9] MatchingRuleAssertion }
*/
const (
	tagFilterAnd             = iota // 0
	tagFilterOr                     // 1
	tagFilterNot                    // 2
	tagFilterEqualityMatch          // 3
	tagFilterSubstrings             // 4
	tagFilterGreaterOrEqual         // 5
	tagFilterLessOrEqual            // 6
	tagFilterPresent                // 7
	tagFilterApproxMatch            // 8
	tagFilterExtensibleMatch        // 9
)
const tagFilterInvalid = -1

var (
	endOfFilterErr    error = errors.New("Unexpected end of filter")
	invalidFilterErr  error = errors.New("Invalid or malformed filter")
	emptyFilterSetErr error = errors.New("Zero or invalid filter SET")
)
