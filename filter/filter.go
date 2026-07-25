package filter

/*
filter.go contains RFC4515 methods and types.
*/

import (
	"errors"
	"strconv"
	"strings"

	"github.com/go-directory/syntax"
)

/*
New returns a [Filter] qualifier instance alongside an error.

If the input is nil, the default [FilterPresent] (e.g.: "(objectClass=*)")
is returned.

If the input is a string, an attempt to marshal the value is made. If
the string is zero, this is equivalent to providing nil.

Any errors found will result in the return of an invalid [Filter] instance.
*/
func New(x any) (Filter, error) {
	return marshalFilter(x)
}

func marshalFilter(x any) (f Filter, err error) {
	switch tv := x.(type) {
	case nil:
		// Nil returns the default filter.
		f, err = marshalFilter(``)
		return
	case string:
		// try to handle a zero length string
		// filter (default return).
		if len(tv) == 0 {
			f = FilterPresent{
				Desc: AttributeDescription(`objectClass`),
			}
			return
		}
	}

	if f, err = parseSubFilter(x); f == nil {
		// just to avoid panics in the event
		// the user does not check errors.
		f = invalidFilter{}
		err = invalidFilterErr
	}

	return
}

/*
Filter implements [Section 2] and [Section 3] of RFC4515.

[Section 2]: https://datatracker.ietf.org/doc/html/rfc4515#section-2
[Section 3]: https://datatracker.ietf.org/doc/html/rfc4515#section-3
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
	Value syntax.AssertionValue
}

/*
AttributeDescription implements [Section 2.5 of RFC4512].

[Section 2.5 of RFC4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-2.5
*/
type AttributeDescription string

/*
FilterPresent implements the "present" CHOICE of an instance of [Filter].
*/
type FilterPresent struct {
	Desc AttributeDescription
}

type MatchingRuleID string

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
	MatchingRule MatchingRuleID        `asn1:"tag:1,optional"`
	Type         AttributeDescription  `asn1:"tag:2,optional"`
	MatchValue   syntax.AssertionValue `asn1:"tag:3"`
	DNAttributes bool                  `asn1:"tag:4,default:false"`
}

/*
FilterSubstrings implements the "substrings" CHOICE of an instance of [Filter].
*/
type FilterSubstrings struct {
	Type       AttributeDescription
	Substrings syntax.SubstringAssertion
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

func (r invalidFilter) IsZero() bool { return true }

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
	return r.Desc.String() == "" &&
		r.Value == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterGreaterOrEqual) IsZero() bool {
	return r.Desc.String() == "" &&
		r.Value == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterLessOrEqual) IsZero() bool {
	return r.Desc.String() == "" &&
		r.Value == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterApproximateMatch) IsZero() bool {
	return r.Desc.String() == "" &&
		r.Value == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterPresent) IsZero() bool { return r.Desc.String() == "" }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterSubstrings) IsZero() bool {
	return r.Type.String() == "" &&
		r.Substrings.IsZero()
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterExtensibleMatch) IsZero() bool {
	return r.MatchingRule.String() == "" &&
		r.Type.String() == "" &&
		r.MatchValue == nil &&
		!r.DNAttributes
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
func (r invalidFilter) Index(_ int) (f Filter) {
	f = invalidFilter{}
	return
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
func (r AttributeDescription) String() string {
	return string(r)
}

/*
Type returns only the "descr" string value of the receiver instance.
*/
func (r AttributeDescription) Type() string {
	return r.String()
}

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
		bld.WriteString(")")
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
		bld.WriteString(")")
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
		bld.WriteString(")")
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
		bld.WriteString("(")
		bld.WriteString(r.Desc.String())
		bld.WriteString("=")
		bld.WriteString(r.Value.String())
		bld.WriteString(")")
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
		bld.WriteString("(")
		bld.WriteString(r.Desc.String())
		bld.WriteString(">=")
		bld.WriteString(r.Value.String())
		bld.WriteString(")")
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
		bld.WriteString("(")
		bld.WriteString(r.Desc.String())
		bld.WriteString("<=")
		bld.WriteString(r.Value.String())
		bld.WriteString(")")
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
		bld.WriteString("(")
		bld.WriteString(r.Desc.String())
		bld.WriteString("~=")
		bld.WriteString(r.Value.String())
		bld.WriteString(")")
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
		bld.WriteString("(")
		bld.WriteString(r.Desc.String())
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
		bld.WriteString("(")
		bld.WriteString(string(r.Type))
		bld.WriteString("=")
		bld.WriteString(r.Substrings.String())
		bld.WriteString(")")
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
		typ := r.Type.String()
		mr := r.MatchingRule.String()
		dna := r.DNAttributes
		bld := &strings.Builder{}

		if typ != "" && mr == "" {
			if dna {
				bld.WriteString(typ)
				bld.WriteString(`:dn:=`)
				bld.WriteString(value)
			} else {
				bld.WriteString(typ)
				bld.WriteString(`:=`)
				bld.WriteString(value)
			}
		} else if typ == "" && mr != "" {
			if dna {
				bld.WriteString(`:dn:`)
				bld.WriteString(mr)
				bld.WriteString(`:=`)
				bld.WriteString(value)
			} else {
				bld.WriteRune(':')
				bld.WriteString(mr)
				bld.WriteString(`:=`)
				bld.WriteString(value)
			}
		} else if typ != "" && mr != "" {
			if dna {
				bld.WriteString(typ)
				bld.WriteString(`:dn:`)
				bld.WriteString(mr)
				bld.WriteString(`:=`)
				bld.WriteString(value)
			} else {
				bld.WriteString(typ)
				bld.WriteRune(':')
				bld.WriteString(mr)
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

func (r MatchingRuleAssertion) IsZero() bool {
	return r.MatchingRule == "" &&
		len(r.Type) == 0 &&
		len(r.MatchValue) == 0 &&
		!r.DNAttributes
}

func parseSubFilter(x any) (f Filter, err error) {
	var input string
	if input, err = assertString(x, 1, "Search Filter"); err != nil {
		return
	}

	if input = strings.TrimSpace(input); input == "" {
		f = FilterPresent{Desc: AttributeDescription("objectClass")}
		return
	} else if strings.Contains(input, `((`) || !checkParenBalanced(input) {
		err = endOfFilterErr
		f = invalidFilter{}
		return
	}

	switch {
	case strings.HasPrefix(input, "(&"):
		f, err = parseFilterAnd(input)
	case strings.HasPrefix(input, "(|"):
		f, err = parseFilterOr(input)
	case strings.HasPrefix(input, "(!"):
		f, err = parseFilterNot(input)
	default:
		f, err = parseItemFilter(input)
	}

	return
}

func parseFilterAnd(input string) (Filter, error) {
	return parseComplexFilter(input[2:len(input)-1], "&")
}

func parseFilterOr(input string) (Filter, error) {
	return parseComplexFilter(input[2:len(input)-1], "|")
}

func parseFilterNot(input string) (f Filter, err error) {
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

func parseComplexFilter(input, prefix string) (Filter, error) {
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

func parseItemFilter(input string) (f Filter, err error) {
	f = invalidFilter{}
	idx := strings.Index(input, "=")
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

	checkAssnValue := func(x string) (err error) {
		if !syntax.IsAssertionValue(x, true) {
			err = errors.New("Invalid assertion value: " + x)
		}
		return
	}

	// Now that we've verified them, parenthetical
	// encapsulators will just get in the way, so
	// let's strip them off. They will reappear
	// during string representation.
	pre = strings.ReplaceAll(pre, `(`, ``)
	after = strings.ReplaceAll(after, `)`, ``)

	if after == `*` {
		err = checkFilterOIDs(pre, ``)
		f = FilterPresent{
			Desc: AttributeDescription(pre)}
	} else if strings.HasSuffix(pre, `>`) {
		err = checkFilterOIDs(pre[:len(pre)-1], ``)
		cerr = checkAssnValue(after)
		f = FilterGreaterOrEqual{
			AttributeDescription(pre[:len(pre)-1]),
			syntax.AssertionValue(after)}
	} else if strings.HasSuffix(pre, `<`) {
		err = checkFilterOIDs(pre[:len(pre)-1], ``)
		cerr = checkAssnValue(after)
		f = FilterLessOrEqual{
			AttributeDescription(pre[:len(pre)-1]),
			syntax.AssertionValue(after)}
	} else if strings.HasSuffix(pre, `~`) {
		err = checkFilterOIDs(pre[:len(pre)-1], ``)
		cerr = checkAssnValue(after)
		f = FilterApproximateMatch{
			AttributeDescription(pre[:len(pre)-1]),
			syntax.AssertionValue(after)}
	} else if strings.Contains(after, "*") {
		var ssa syntax.SubstringAssertion
		if ssa, err = syntax.NewSubstringAssertion(after); err == nil {
			err = checkFilterOIDs(pre, ``)
			f = FilterSubstrings{
				Type:       AttributeDescription(pre),
				Substrings: ssa}
		}
	} else if strings.Contains(pre, ":") {
		f, err = parseExtensibleMatch(pre, after)
		cerr = checkAssnValue(after)
	} else {
		err = checkFilterOIDs(pre, ``)
		cerr = checkAssnValue(after)
		f = FilterEqualityMatch{
			Desc:  AttributeDescription(pre),
			Value: syntax.AssertionValue(after)}
	}

	if err != nil || cerr != nil {
		f = invalidFilter{}
	}

	return
}

func parseExtensibleMatch(a, b string) (f Filter, err error) {
	scol := strings.HasPrefix(a, `:`)
	sdn := strings.HasPrefix(a, `:dn:`) || strings.HasPrefix(a, `:DN:`)

	val := syntax.AssertionValue(b)
	_f := FilterExtensibleMatch{}

	if !scol {
		if !valueIsDNAttrs(a) {
			if idx := strings.IndexRune(a, ':'); idx != -1 {
				mr := strings.Trim(a[idx+1:], `:`)
				err = checkFilterOIDs(a[:idx], mr)
				_f.Type = AttributeDescription(a[:idx])
				_f.MatchingRule = MatchingRuleID(mr)
			}
		} else {
			_f.DNAttributes = true
			if c := dnAttrSplit(a); len(c) == 2 {
				mr := strings.Trim(c[1], `:`)
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
		err = checkFilterOIDs(``, _f.MatchingRule.String())
		_f.MatchValue = val
	}

	if err == nil && !_f.IsZero() {
		f = _f
	}

	return
}

// Verify parenthetical encapsulation is balanced
func checkParenEncaps(a, b string) (err error) {
	lencap := strings.HasPrefix(a, `(`)
	rencap := strings.HasSuffix(b, `)`)
	if lencap && !rencap {
		err = endOfFilterErr
	} else if !lencap && rencap {
		err = endOfFilterErr
	}

	return
}

func checkParenBalanced(x string) bool {
	return strings.Count(x, `(`) == strings.Count(x, `)`)
}

func checkFilterOIDs(t, m string) (err error) {
	if len(t) > 0 {
		if strings.Contains(t, `;`) {
			err = errors.New("Invalid OID or descriptor (tags are prohibited): " + t)
			return
		} else if !isOIDOrDescr(t) {
			err = errors.New("Invalid OID or descriptor: " + t)
			return
		}
	}
	if len(m) > 0 {
		if !isOIDOrDescr(m) {
			err = errors.New("Invalid OID or descriptor: " + m)
		}
	}

	return
}

func isOIDOrDescr(x string) bool {
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

func descrSyntaxCheck(x string) bool {
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

func isValidArc(arc string) bool {
	if strings.HasPrefix(arc, `-`) {
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

func oIDSyntaxCheck(o string) bool {
	O := strings.Split(o, `.`)
	if len(O) < 2 {
		return false
	}

	switch string(O[0]) {
	case "0", "1":
		if i, err := strconv.Atoi(string(O[1])); err != nil {
			return false
		} else if !(0 <= i && i <= 39) {
			return false
		}
	case "2":
	default:
		return false
	}

	var res bool = true
	for i := 1; i < len(O[1:]) && res; i++ {
		res = isValidArc(O[i])
	}

	return res
}

func splitFilterParts(input string) []string {
	var parts []string
	currentPart := &strings.Builder{}
	depth := 0
	for _, char := range input {
		switch char {
		case '(':
			if depth == 0 && currentPart.Len() > 0 {
				parts = append(parts, currentPart.String())
				currentPart.Reset()
			}
			depth++
		case ')':
			depth--
		}
		currentPart.WriteRune(char)
	}
	if currentPart.Len() > 0 {
		parts = append(parts, currentPart.String())
	}
	return parts
}

func valueIsDNAttrs(x string) bool {
	return strings.Contains(x, `:dn:`) || strings.Contains(x, `:DN:`)
}

func dnAttrSplit(x string) (slice []string) {
	lo := strings.Contains(x, `:dn:`)
	hi := strings.Contains(x, `:DN:`)
	if lo && !hi {
		slice = strings.Split(x, `:dn:`)
	} else if !lo && hi {
		slice = strings.Split(x, `:DN:`)
	}

	return
}

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

const (
	tagMatchingRuleAssertionMatchingRule = 1
	tagMatchingRuleAssertionType         = 2
	tagMatchingRuleAssertionMatchValue   = 3
	tagMatchingRuleAssertionDnAttributes = 4
)

var (
	endOfFilterErr    error = errors.New("Unexpected end of filter")
	invalidFilterErr  error = errors.New("Invalid or malformed filter")
	emptyFilterSetErr error = errors.New("Zero or invalid filter SET")
)

func errorBadLength(name string, length int) error {
	return errors.New(`Invalid length '` + strconv.FormatInt(int64(length), 10) + `' for ` + name)
}

func errorBadType(name string) error {
	return errors.New(`Incompatible input type for ` + name)
}
