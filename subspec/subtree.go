package subspec

/*
subtree.go implements the RFC3672 SubtreeSpecification.
*/

/*
SubtreeSpecification implements the Subtree Specification construct.

It can be ASN.1 DER encoded and decoded using the provided asn1
package subdirectory.

A zero instance of this type is equal to "{}" when represented as a
string value, which is a valid default value when populated for an
entry's "[subtreeSpecification]" attribute type instance within a DIT.

From [§ 2.1 of RFC 3672]:

	SubtreeSpecification ::= SEQUENCE {
	    base                [0] LocalName DEFAULT { },
	                            COMPONENTS OF ChopSpecification,
	    specificationFilter [4] Refinement OPTIONAL }

	LocalName ::= RDNSequence

	ChopSpecification ::= SEQUENCE {
	    specificExclusions  [1] SET OF CHOICE {
	                            chopBefore [0] LocalName,
	                            chopAfter [1] LocalName } OPTIONAL,
	    minimum             [2] BaseDistance DEFAULT 0,
	    maximum             [3] BaseDistance OPTIONAL }

	BaseDistance ::= INTEGER (0 .. MAX)

	Refinement ::= CHOICE {
	    item                [0] OBJECT-CLASS.&id,
	    and                 [1] SET OF Refinement,
	    or                  [2] SET OF Refinement,
	    not                 [3] Refinement }

From [Appendix A of RFC 3672]:

	SubtreeSpecification = "{" [ sp ss-base ]
	                           [ sep sp ss-specificExclusions ]
	                           [ sep sp ss-minimum ]
	                           [ sep sp ss-maximum ]
	                           [ sep sp ss-specificationFilter ]
	                                sp "}"

	ss-base                = id-base                msp LocalName
	ss-specificExclusions  = id-specificExclusions  msp SpecificExclusions
	ss-minimum             = id-minimum             msp BaseDistance
	ss-maximum             = id-maximum             msp BaseDistance
	ss-specificationFilter = id-specificationFilter msp Refinement

	BaseDistance = INTEGER-0-MAX

From [§ 6 of RFC 3642]:

	LocalName         = RDNSequence
	RDNSequence       = dquote *SafeUTF8Character dquote

	INTEGER-0-MAX   = "0" / positive-number
	positive-number = non-zero-digit *decimal-digit

	sp  =  *%x20  ; zero, one or more space characters
	msp = 1*%x20  ; one or more space characters
	sep = [ "," ]

	OBJECT-IDENTIFIER = numeric-oid / descr
	numeric-oid       = oid-component 1*( "." oid-component )
	oid-component     = "0" / positive-number

[Appendix A of RFC 3672]: https://datatracker.ietf.org/doc/html/rfc3672#appendix-A
[subtreeSpecification]: https://datatracker.ietf.org/doc/html/rfc3672#section-2.3
[§ 2.1 of RFC 3672]: https://datatracker.ietf.org/doc/html/rfc3672#section-2.1
[§ 6 of RFC 3642]: https://datatracker.ietf.org/doc/html/rfc3642#section-6
*/
type SubtreeSpecification struct {
	Base LocalName `asn1:"tag:0,default:"`

	// COMPONENTS OF chopSpecification
	ChopSpecification

	SpecificationFilter Refinement `asn1:"tag:4,optional"`
}

/*
SubtreeSpecification returns an instance of [SubtreeSpecification]
alongside an error.

If the input is nil, the default [SubtreeSpecification] (e.g.: "{}")
is returned.

If the input is a string, an attempt to marshal the value is made. If
the string is zero, this is equivalent to providing nil.

Any errors found will result in the return of an invalid [Filter] instance.
*/
func New(x any) (ss SubtreeSpecification, err error) {

	var raw string
	switch x.(type) {
	case nil:
		return
	default:
		if raw, err = assertString(x, 0, "Subtree Specification"); err != nil {
			return
		} else if raw == "" {
			return // no error
		}
	}

	if err = checkSubtreeEncaps(raw); err != nil {
		return
	}
	raw = trimS(raw[1 : len(raw)-1])

	var ranges map[string][]int = make(map[string][]int, 0)

	for _, err = range []error{
		ss.marshalBase(raw, ranges),
		ss.marshalExclusions(raw, ranges),
		ss.marshalMinimum(raw, ranges),
		ss.marshalMaximum(raw, ranges),
		ss.marshalSpecFilter(raw, ranges),
	} {
		if err != nil {
			break
		}
	}

	return
}

func (r *SubtreeSpecification) marshalBase(raw string, ranges map[string][]int) (err error) {
	if begin := stridx(raw, `base `); begin != -1 {
		var end int
		begin += 5
		if r.Base, end, err = subtreeBase(raw[begin:]); err == nil {
			end += begin + 1
			ranges[`base`] = []int{begin, end}
		}
	}

	return
}

func (r *SubtreeSpecification) marshalExclusions(raw string, ranges map[string][]int) (err error) {
	if begin := stridx(raw, `specificExclusions `); begin != -1 {
		var end int
		begin += 19
		if r.ChopSpecification.Exclusions, end, err = subtreeExclusions(raw, begin); err == nil {
			end = begin + end
			ranges[`specificExclusions`] = []int{begin, end}
		}
	}

	return
}

func (r *SubtreeSpecification) marshalMinimum(raw string, ranges map[string][]int) (err error) {
	if begin := stridx(raw, `minimum `); begin != -1 {
		var end int
		begin += 8
		if r.ChopSpecification.Minimum, end, err = subtreeMinMax(raw, begin); err == nil {
			end = begin + end
			ranges[`minimum`] = []int{begin, end}
		}
	}

	return
}

func (r *SubtreeSpecification) marshalMaximum(raw string, ranges map[string][]int) (err error) {
	if begin := stridx(raw, `maximum `); begin != -1 {
		var end int
		begin += 8
		if r.ChopSpecification.Maximum, end, err = subtreeMinMax(raw, begin); err == nil {
			end = begin + end
			ranges[`maximum`] = []int{begin, end}
		}
	}

	return
}

func (r *SubtreeSpecification) marshalSpecFilter(raw string, ranges map[string][]int) (err error) {
	if begin := stridx(raw, `specificationFilter `); begin != -1 {
		begin += 20
		var err error
		if r.SpecificationFilter, err = subtreeRefinement(raw, begin); err == nil {
			ranges[`specificationFilter`] = []int{begin, begin + len(raw) - begin}
		}
	}

	return
}

func checkSubtreeEncaps(raw string) (err error) {
	if raw[0] != '{' || raw[len(raw)-1] != '}' {
		err = mkerr("SubtreeSpecification {} encapsulation error")
	}
	return
}

/*
SpecificExclusions implements the chopSpecification specificExclusions ASN.1
SET OF CHOICE component.

From [Appendix A of RFC 3672]:

	SpecificExclusions = "{" [ sp SpecificExclusion *( "," sp SpecificExclusion ) ] sp "}"

[Appendix A of RFC 3672]: https://datatracker.ietf.org/doc/html/rfc3672#appendix-A
*/
type SpecificExclusions []SpecificExclusion

func (r SpecificExclusions) Len() int {
	return len(r)
}

/*
SpecificExclusion implements the chopSpecification specificExclusion component.

From [§ 2.1 of RFC 3672]:

	LocalName ::= RDNSequence
	SET OF CHOICE {
	   chopBefore [0] LocalName,
	   chopAfter  [1] LocalName }

From [Appendix A of RFC 3672]:

	SpecificExclusion  = chopBefore / chopAfter
	chopBefore         = id-chopBefore ":" LocalName
	chopAfter          = id-chopAfter  ":" LocalName
	id-chopBefore      = %x63.68.6F.70.42.65.66.6F.72.65 ; "chopBefore"
	id-chopAfter       = %x63.68.6F.70.41.66.74.65.72    ; "chopAfter"

[Appendix A of RFC 3672]: https://datatracker.ietf.org/doc/html/rfc3672#appendix-A
[§ 2.1 of RFC 3672]: https://datatracker.ietf.org/doc/html/rfc3672#section-2.1
*/
type SpecificExclusion struct {
	ChopBefore LocalName `asn1:"tag:0"`
	ChopAfter  LocalName `asn1:"tag:1"`
}

/*
ChopSpecification implements the chopSpecification component of an
instance of [SubtreeSpecification].
*/
type ChopSpecification struct {
	Exclusions SpecificExclusions `asn1:"tag:1,optional"`
	Minimum    BaseDistance       `asn1:"tag:2,default:0"`
	Maximum    BaseDistance       `asn1:"tag:3,optional"`
}

func (r ChopSpecification) IsZero() bool {
	return len(r.Exclusions) == 0 &&
		r.Minimum == 0 &&
		r.Maximum == 0
}

/*
BaseDistance implements the integer value of a minimum and/or maximum
[SubtreeSpecification] depth refinement parameter. An instance of this
type for either use case indicates the subordinate entry depth "range"
whose contents are subject to the influence of the [SubtreeSpecification]
bearing a non-zero value.

A zero instance of this type, unsurprisingly, is zero (0) and indicates
no depth refinement is in force for the respective administrative area.
*/
type BaseDistance int

/*
LocalName implements an "RDNSequence" per [§ 6 of RFC 3642].

Instances of this type may be found within the "base" of a [SubtreeSpecification]
instance, as well as the "name" of a [SpecificExclusion], and are used to describe
an indicated entry set present at, or within, a given administrative area.

A zero instance of this type is equivalent to a null DN, which normally indicates
that the given administrative area is defined by the current subentry.

[§ 6 of RFC 3642]: https://datatracker.ietf.org/doc/html/rfc3642#section-6
*/
type LocalName string

/*
String returns the string representation of the receiver instance.
*/
func (r LocalName) String() string {
	return string(r)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r LocalName) IsZero() bool {
	return r == ``
}

func (r SpecificExclusions) IsZero() bool {
	return len(r) == 0
}

/*
String returns the string representation of the receiver instance.
*/
func (r SpecificExclusions) String() string {
	if len(r) == 0 {
		return `{ }`
	}

	var _s []string
	for i := 0; i < len(r); i++ {
		_s = append(_s, r[i].String())
	}

	return `{ ` + join(_s, `, `) + ` }`
}

func (r SpecificExclusion) IsZero() bool {
	return &r == nil
}

/*
String returns the string literal "before" or "after" as the selected
ASN.1 CHOICE. The determination is made based upon non-zeroness of the
respective [LocalName] value. A zero string is returned if the instance
is invalid.
*/
func (r SpecificExclusion) Choice() (se string) {
	if chopB := r.ChopBefore.String(); chopB != "" {
		se = `before`
	} else if chopA := r.ChopAfter.String(); chopA != "" {
		se = `after`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r SpecificExclusion) String() (s string) {
	choice := r.Choice()
	if choice == "before" {
		s = `chopBefore ` + `"` + r.ChopBefore.String() + `"`
	} else if choice == "after" {
		s = `chopAfter ` + `"` + r.ChopAfter.String() + `"`
	}

	return
}

func findMatchingBrace(s string, startIdx int) int {
	depth := 0
	for i := startIdx; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func subtreeExclusions(raw string, begin int) (excl SpecificExclusions, end int, err error) {
	// find the actual '{' (skip spaces)
	for begin < len(raw) && raw[begin] == ' ' {
		begin++
	}
	if begin >= len(raw) || raw[begin] != '{' {
		err = mkerr("Bad exclusion encapsulation")
		return
	}

	// find matching closing brace
	match := findMatchingBrace(raw, begin)
	if match == -1 {
		err = mkerr("Unmatched brace in specificExclusions")
		return
	}

	// content inside braces
	content := raw[begin+1 : match]
	// split into top-level parts like: `chopBefore "ou=Payroll"` etc.
	parts := splitRefinementParts(content)

	for _, p := range parts {
		p = trimS(p)
		if p == "" {
			continue
		}

		// split into key and value. value may contain spaces/commas so split only once.
		kv := splitN(p, " ", 2)
		if len(kv) != 2 {
			err = mkerr("Malformed specificExclusions part: ", p)
			return
		}
		key := trimS(kv[0])
		val := trimS(kv[1])
		val = trim(val, `"`) // remove surrounding quotes if present

		if key != "chopBefore" && key != "chopAfter" {
			err = mkerr("Unexpected key '", key, "'")
			return
		}

		ex := SpecificExclusion{}
		if key == "chopBefore" {
			ex.ChopBefore = LocalName(val)
		} else {
			ex.ChopAfter = LocalName(val)
		}
		excl = append(excl, ex)
	}

	// end is number of bytes consumed from begin
	end = match - begin + 1
	return
}

func subtreeMinMax(raw string, begin int) (minmax BaseDistance, end int, err error) {
	end = -1

	var (
		max string
		m   int
	)

	for i := 0; i < len(raw[begin:]); i++ {
		if isDigit(rune(raw[begin+i])) {
			max += string(raw[begin+i])
			continue
		}
		break
	}

	if m, err = atoi(max); err == nil {
		minmax = BaseDistance(m)
		end = len(max)
	}

	return
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r SubtreeSpecification) IsZero() bool {
	return r.Base == "" &&
		r.ChopSpecification.IsZero() &&
		r.SpecificationFilter == nil
}

/*
String returns the string representation of the receiver instance.
*/
func (r SubtreeSpecification) String() (s string) {
	if r.IsZero() {
		s = `{}`
		return
	}

	var _s []string
	if len(r.Base) > 0 {
		_s = append(_s, `base `+`"`+string(r.Base)+`"`)
	}

	if x := r.ChopSpecification.Exclusions; len(x) > 0 {
		_s = append(_s, `specificExclusions `+x.String())
	}

	if r.ChopSpecification.Minimum > 0 {
		_s = append(_s, `minimum `+itoa(int(r.ChopSpecification.Minimum)))

	}

	if r.ChopSpecification.Maximum > 0 {
		_s = append(_s, `maximum `+itoa(int(r.ChopSpecification.Maximum)))

	}

	if r.SpecificationFilter != nil {
		x := r.SpecificationFilter.String()
		_s = append(_s, `specificationFilter `+x)
	}

	s = `{` + join(_s, `, `) + `}`

	return
}

/*
Refinement implements [Appendix A of RFC 3672], and serves as the
"SpecificationFilter" optionally found within a Subtree Specification.
It is qualified through instances of:

  - [RefinementItem]
  - [RefinementAnd]
  - [RefinementOr]
  - [RefinementNot]

From [Appendix A of RFC 3672]:

	Refinement  = item / and / or / not
	item        = id-item ":" OBJECT-IDENTIFIER
	and         = id-and  ":" Refinements
	or          = id-or   ":" Refinements
	not         = id-not  ":" Refinement

	Refinements = "{" [ sp Refinement *( "," sp Refinement ) ] sp "}"
	id-item     = %x69.74.65.6D ; "item"
	id-and      = %x61.6E.64    ; "and"
	id-or       = %x6F.72       ; "or"
	id-not      = %x6E.6F.74    ; "not"

From [ITU-T Rec. X.501 clause 12.3.5]:

	Refinement ::= CHOICE {
		item [0] OBJECT-CLASS.&id,
		and  [1] SET SIZE (1..MAX) OF Refinement,
		or   [2] SET SIZE (1..MAX) OF Refinement,
		not  [3] Refinement,
		... }

[ITU-T Rec. X.501 clause 12.3.5]: https://www.itu.int/rec/T-REC-X.501
[Appendix A of RFC 3672]: https://datatracker.ietf.org/doc/html/rfc3672#appendix-A
*/
type Refinement interface {
	// Index returns the Nth slice index found within
	// the receiver instance. This is only useful if
	// the receiver is an RefinementAnd or RefinementOr
	// Refinement qualifier type instance.
	Index(int) Refinement

	// IsZero returns a Boolean value indicative of
	// a nil receiver state.
	IsZero() bool

	// String returns the string representation of
	// the receiver instance.
	String() string

	// Verify returns an error following an attempt to
	// resolve all RefinementItem OID instances that are
	// encountered within the receiver instance.
	Verify() error

	// Choice returns the string CHOICE "name" of the
	// receiver instance. Use of this method is merely
	// intended as a convenient alternative to type
	// assertion checks.
	Choice() string

	// Len returns the integer length of the receiver
	// instance. This is only useful if the receiver is
	// an RefinementAnd or RefinementOr Refinement
	// qualifier type instance.
	Len() int

	// differentiate Refinement from other interfaces
	isRefinement()
}

/*
RefinementAnd implements slices of [Refinement], all of which are expected to
evaluate as true during processing.

Instances of this type qualify the [Refinement] interface type.
*/
type RefinementAnd []Refinement

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r RefinementAnd) IsZero() bool {
	return &r == nil
}

/*
Push appends zero (0) or more instances of string or [Refinement] to
the receiver instance.
*/
func (r *RefinementAnd) Push(x ...any) {
	for i := 0; i < len(x); i++ {
		switch tv := x[i].(type) {
		case string:
			if ref, err := subtreeRefinement(tv, 0); err == nil {
				*r = append(*r, ref)
			}
		case Refinement:
			*r = append(*r, tv)
		}
	}
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r RefinementOr) IsZero() bool {
	return &r == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r RefinementNot) IsZero() bool {
	return r.Refinement == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r RefinementItem) IsZero() bool {
	return string(r) == ""
}

/*
String returns the string representation of the receiver instance.
*/
func (r RefinementAnd) String() (s string) {
	if !r.IsZero() {
		var parts []string
		for _, ref := range r {
			parts = append(parts, ref.String())
		}
		s = "and:{" + join(parts, ",") + "}"
	}

	return
}

/*
Verify returns an error following an attempt to resolve any enclosed
[RefinementItem] objectClass OIDs.
*/
func (r RefinementAnd) Verify() (err error) {
	L := r.Len()
	if L == 0 {
		err = mkerr("RefinementAnd: zero length")
		return
	}

	for i := 0; i < L && err == nil; i++ {
		err = r.Index(i).Verify()
	}

	return
}

/*
Type returns the string literal "and" as the ASN.1 CHOICE.
*/
func (r RefinementAnd) Choice() string {
	return "and"
}

/*
Len returns the integer length of the receiver instance.
*/
func (r RefinementAnd) Len() int {
	return len(r)
}

/*
Index returns the Nth slice index found within the receiver instance.
*/
func (r RefinementAnd) Index(idx int) (x Refinement) {
	rl := r.Len()
	x = invalidRefinement{}
	if 0 <= idx && idx < rl {
		x = r[idx]
	}

	return
}

/*
RefinementOr implements slices of [Refinement], at least one of which is
expected to evaluate as true during processing.

Instances of this type qualify the [Refinement] interface type.
*/
type RefinementOr []Refinement

/*
Push appends zero (0) or more instances of string or [Refinement] to
the receiver instance.
*/
func (r *RefinementOr) Push(x ...any) {
	for i := 0; i < len(x); i++ {
		switch tv := x[i].(type) {
		case string:
			if ref, err := subtreeRefinement(tv, 0); err == nil {
				*r = append(*r, ref)
			}
		case Refinement:
			*r = append(*r, tv)
		}
	}
}

/*
String returns the string representation of the receiver instance.
*/
func (r RefinementOr) String() (s string) {
	if !r.IsZero() {
		var parts []string
		for _, ref := range r {
			parts = append(parts, ref.String())
		}
		s = "or:{" + join(parts, ",") + "}"
	}

	return
}

/*
Verify returns an error following an attempt to resolve any enclosed
[RefinementItem] objectClass OIDs.
*/
func (r RefinementOr) Verify() (err error) {
	L := r.Len()
	if L == 0 {
		err = mkerr("RefinementAnd: Or length")
		return
	}

	for i := 0; i < L && err == nil; i++ {
		err = r.Index(i).Verify()
	}

	return
}

/*
Type returns the string literal "or" as the ASN.1 CHOICE.
*/
func (r RefinementOr) Choice() string {
	return "or"
}

/*
Len returns the integer length of the receiver instance.
*/
func (r RefinementOr) Len() int {
	return len(r)
}

/*
Index returns the Nth slice index found within the receiver instance.
*/
func (r RefinementOr) Index(idx int) (x Refinement) {
	rl := r.Len()
	x = invalidRefinement{}
	if 0 <= idx && idx < rl {
		x = r[idx]
	}

	return
}

/*
RefinementNot implements a negated, recursive instance of [Refinement].
Normally during processing, instances of this type are processed first
when present among other qualifiers as siblings (slices), such as with
[RefinementAnd] and [RefinementOr] instances.

Instances of this type qualify the [Refinement] interface type.
*/
type RefinementNot struct {
	Refinement
}

/*
String returns the string representation of the receiver instance.
*/
func (r RefinementNot) String() string {
	if r.IsZero() {
		return ``
	}

	return "not:" + r.Refinement.String()
}

/*
Verify returns an error following an attempt to resolve any enclosed
[RefinementItem] objectClass OIDs.
*/
func (r RefinementNot) Verify() (err error) {
	if r.IsZero() {
		err = mkerr("RefinementNot: nil instance")
		return
	}

	err = r.Refinement.Verify()
	return
}

/*
Type returns the string literal "not" as the ASN.1 CHOICE.
*/
func (r RefinementNot) Choice() string {
	return "not"
}

/*
Len returns the integer length of the receiver instance.
*/
func (r RefinementNot) Len() (l int) {
	if !r.IsZero() {
		l = r.Refinement.Len()
	}

	return
}

/*
Index returns the Nth slice index found within the receiver instance.
*/
func (r RefinementNot) Index(idx int) (x Refinement) {
	x = invalidRefinement{}

	if !r.IsZero() {
		x = r.Refinement.Index(idx)
	}

	return
}

func (r RefinementOr) isRefinement()   {}
func (r RefinementAnd) isRefinement()  {}
func (r RefinementNot) isRefinement()  {}
func (r RefinementItem) isRefinement() {}

type invalidRefinement struct{}

func (r invalidRefinement) isRefinement()          {}
func (r invalidRefinement) String() string         { return `` }
func (r invalidRefinement) IsZero() bool           { return false }
func (r invalidRefinement) Len() int               { return 0 }
func (r invalidRefinement) Index(_ int) Refinement { return invalidRefinement{} }
func (r invalidRefinement) Verify() error          { return mkerr("Invalid Refinement") }
func (r invalidRefinement) Choice() string         { return `invalid` }

/*
RefinementItem implements the core ("atom") value type to be used in
[Refinement] statements, and appears in [RefinementAnd], [RefinementOr]
and [RefinementNot] [Refinement] qualifier type instances.

This is the only "tangible" type in the "specificationFilter" formula,
as all other types simply act as contextual "envelopes" meant to,
ultimately, store instances of this type.

Instances of this type qualify the [Refinement] interface type.
*/
type RefinementItem string

/*
String returns the string representation of the receiver instance.
*/
func (r RefinementItem) String() (s string) {
	if !r.IsZero() {
		s = `item:` + string(r)
	}

	return
}

/*
Verify returns an error following an attempt to resolve any enclosed
[RefinementItem] objectClass OIDs.
*/
func (r RefinementItem) Verify() (err error) {
	_, err = Resolve(string(r))
	return
}

/*
Type returns the string literal "item" as the ASN.1 CHOICE.
*/
func (r RefinementItem) Choice() string {
	return "item"
}

/*
Len always returns the integer 1 (one).  This method only exists to satisfy
Go's interface signature requirement with respect to [Refinement].
*/
func (r RefinementItem) Len() int { return 1 }

/*
Index always returns the receiver instance as-is.  This method only exists to satisfy
Go's interface signature requirement with respect to [Refinement].
*/
func (r RefinementItem) Index(_ int) Refinement { return r }

func subtreeBase(x any) (base LocalName, end int, err error) {
	end = -1
	var raw string
	if raw, err = assertString(x, 1, "Subtree Base"); err != nil {
		return
	}

	// FIXME - extend spec to allow single quotes?
	if raw[0] != '"' {
		err = mkerr("Missing encapsulation (\") for LocalName")
		return
	}

	for i := 1; i < len(raw) && end == -1; i++ {
		switch char := rune(raw[i]); char {
		case '"':
			end = i
			break
		}
	}

	if err = isSafeUTF8(raw[1:end]); err == nil {
		base = LocalName(raw[1:end])
	}

	return
}

func subtreeRefinement(x any, begin ...int) (ref Refinement, err error) {
	var input string
	if input, err = assertString(x, 1, "Specification Filter"); err != nil {
		return
	}
	if len(begin) > 0 {
		input = trimS(input[begin[0]:])
	} else {
		input = trimS(input)
	}

	if hasPfx(input, "item:") {
		ref, err = parseItem(input)
	} else if hasPfx(input, "and:") {
		ref, err = parseAnd(input)
	} else if hasPfx(input, "or:") {
		ref, err = parseOr(input)
	} else if hasPfx(input, "not:") {
		ref, err = parseNot(input)
	} else {
		err = mkerr("invalid refinement: ", input)
	}

	return
}

func parseItem(input string) (Refinement, error) {
	var ref Refinement = invalidRefinement{}
	parts := splitN(input, ":", 2)
	if len(parts) != 2 {
		return ref, mkerr("invalid item: ", input)
	}

	res, err := Resolve(parts[1])
	if err == nil {
		ref = RefinementItem(res)
	}
	return ref, err
}

func parseAnd(input string) (Refinement, error) {
	return parseComplexRefinement(input, "and:")
}

func parseOr(input string) (Refinement, error) {
	return parseComplexRefinement(input, "or:")
}

func parseNot(input string) (Refinement, error) {
	input = trimPfx(input, "not:")
	subRef, err := subtreeRefinement(input)
	if err != nil {
		return nil, err
	}
	return RefinementNot{subRef}, nil
}

func parseComplexRefinement(input, prefix string) (Refinement, error) {
	input = trimPfx(input, prefix)
	input = trimS(input)
	input = trimPfx(input, "{")
	input = trimSfx(input, "}")

	var refs []Refinement
	parts := splitRefinementParts(input)
	for _, part := range parts {
		subRef, err := subtreeRefinement(part)
		if err != nil {
			return nil, err
		}
		refs = append(refs, subRef)
	}

	if prefix == "and:" {
		return RefinementAnd(refs), nil
	}
	return RefinementOr(refs), nil
}

// splitRefinementParts splits input on top-level commas while respecting nested braces
// and quoted strings. It returns trimmed parts (but does not remove surrounding quotes).
func splitRefinementParts(input string) []string {
	var parts []string
	var sb = newStrBuilder()
	depth := 0
	inQuote := false
	escape := false

	for _, r := range input {
		if escape {
			// previous char was backslash, include this char verbatim
			sb.WriteRune(r)
			escape = false
			continue
		}

		if r == '\\' && inQuote {
			escape = true
			sb.WriteRune(r)
			continue
		}

		if r == '"' {
			inQuote = !inQuote
			sb.WriteRune(r)
			continue
		}

		if !inQuote {
			if r == '{' {
				depth++
			} else if r == '}' {
				if depth > 0 {
					depth--
				}
			}
		}

		if r == ',' && depth == 0 && !inQuote {
			part := trimS(sb.String())
			if part != "" {
				parts = append(parts, part)
			}
			sb.Reset()
			continue
		}

		sb.WriteRune(r)
	}

	if s := trimS(sb.String()); s != "" {
		parts = append(parts, s)
	}

	return parts
}

/*
RegisterOID assigns the provided numeric OID o and its descriptor(s)
d to a forward and reverse map, e.g.:

	OIDFwdMap[<descr>] = <numeric oid> (string to string)
	OIDFwdMap[<numeric oid>] = [<descr(s)>...] (string to []string)

OIDs represent LDAP Object Classes in either form, whether they're
expressed as a descriptor or numeric OID.

If the [OIDRevMap] contains at least one (1) entry, subsequent
[RefinementItem] parsing routines will attempt to resolve numeric
OIDs encountered (e.g.: "2.5.6.6") to the principal descriptor.
If a given numeric OID is unregistered, an error is raised.

If the [OIDFwdMap] contains at least one (1) entry, subsequent
[RefinementItem] parsing routines will attempt to verify the
specified descriptor (e.g.: "person") is a known objectClass:
that is, it has been associated with a numeric OID. If a given
descriptor is unregistered, an error is raised.

Use of this function will initialize the two respective maps
if not already initialized.
*/
func RegisterOID(o string, d ...string) (err error) {
	if OIDFwdMap == nil {
		OIDFwdMap = make(map[string]string)
	}
	if OIDRevMap == nil {
		OIDRevMap = make(map[string][]string)
	}

	dl := len(d)

	if dl == 0 {
		err = mkerr("Cannot register OID without at least one descriptor")
		return
	} else if o == "" {
		err = mkerr("Cannot register zero length numeric OID")
		return
	}

	// this is an all-or-nothing approach.
	// all descriptors must be non zero.
	var tempD []string
	for i := 0; i < dl && err == nil; i++ {
		if d[i] == "" {
			err = mkerr("Cannot register zero-length descriptor")
		}
	}

	if err == nil {
		OIDRevMap[o] = tempD
		for i := 0; i < dl; i++ {
			OIDFwdMap[d[i]] = o
		}
	}

	return
}

func useRevMap() bool { return OIDRevMap != nil && len(OIDRevMap) > 0 }
func useFwdMap() bool { return OIDFwdMap != nil && len(OIDFwdMap) > 0 }

/*
Resolve returns a string descr alongside an error following an attempt
to resolve the input argument id to a known LDAP Object Class descriptor.
This method is called during [RefinementItem] parsing.

If a numeric OID is input, and is resolved, the resolved descr is returned.

If a descr OID is input, and is resolved, the original descr is returned.

If neither of the above cases produced a known descriptor, an error is
returned.

If OID resolution is not in use -- that is, neither [OIDFwdMap] nor [OIDRevMap]
are initialized, each with at least one entry -- this function silently returns
the original id input argument with no error.
*/
func Resolve(id string) (descr string, err error) {
	if !(useRevMap() || useFwdMap()) {
		descr = id // return id as-is, no resolver in use.
		return
	}

	if len(id) == 0 {
		err = mkerr("Bad Refinement Item; must be an objectClass numeric/descr OID")
		return
	}

	if isDigit(rune(id[0])) {
		var ok bool
		if descr, ok = resolveO2D(id); !ok {
			err = mkerr("Bad Refinement Item: unregistered objectClass numeric OID ", id)
		}
	} else if isAlpha(rune(id[0])) {
		var ok bool
		if _, ok = resolveD2O(id); !ok {
			err = mkerr("Bad Refinement Item: unregistered objectClass descr OID ", id)
			return
		}
		descr = id // resolved ok, return id as-is
	} else {
		err = mkerr("Bad Refinement Item; must be an objectClass numeric/descr OID")
	}

	return
}

func resolveO2D(o string) (d string, ok bool) {
	if useRevMap() && o != "" {
		var res []string
		if res, ok = OIDRevMap[lc(o)]; !ok {
			// return the original input
			d = o
		} else {
			if len(res) > 0 && res[0] != "" {
				d = res[0]
			} else {
				// return the original input
				d = o
			}
		}
	}

	return
}

func resolveD2O(d string) (o string, ok bool) {
	if OIDFwdMap != nil && len(OIDFwdMap) > 0 && d != "" {
		if o, ok = OIDFwdMap[lc(d)]; !ok {
			// return the original input
			o = d
		}
	}

	return
}

var (
	OIDFwdMap = make(map[string]string)   // 1-to-1  (descr -> oid)
	OIDRevMap = make(map[string][]string) // 1-to-1+ (oid -> descr(s))
)
