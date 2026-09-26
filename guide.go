package syntax

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/go-directory/encoding/asn1"
)

/*
EnhancedGuide implements the Enhanced Guide type.

From [§ 3.3.10 of RFC 4517]:

	EnhancedGuide = object-class SHARP WSP criteria WSP
	                   SHARP WSP subset
	object-class  = WSP oid WSP
	subset        = "baseObject" / "oneLevel" / "wholeSubtree"

From [§ 9.2.11 of ITU-T Rec. X.520]:

	EnhancedGuide ::= SEQUENCE {
		objectClass	[0] OBJECT-CLASS.&id,
		criteria	[1] Criteria,
		subset		[2] INTEGER {
			baseObject      (0),
			oneLevel        (1),
			wholeSubtree    (2)} DEFAULT oneLevel,
	... }

[§ 3.3.10 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.10
[§ 9.2.11 of ITU-T Rec. X.520]: https://www.itu.int/rec/T-REC-X.520
*/
type EnhancedGuide struct {
	ObjectClass ObjectIdentifier `asn1:"tag:0"`
	Criteria    Criteria         `asn1:"tag:1"`
	Subset      Integer          `asn1:"tag:2,default:1"`
}

/*
NewEnhancedGuide returns an instance of [EnhancedGuide] alongside an error
following an attempt to parse x under the terms of the "Enhanced Guide" ABNF,
per [§ 3.3.10 of RFC 4517].

[§ 3.3.10 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.10
*/
func NewEnhancedGuide(x any) (EnhancedGuide, error) {
	return marshalEnhancedGuide(x)
}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the receiver instance as a UNIVERSAL SEQUENCE.
*/
func (r EnhancedGuide) Encode() ([]byte, error) {
	enc := make([]byte, 0)
	val, err := r.ObjectClass.Encode() // OBJECT IDENTIFIER
	if err == nil {
		val, _ = wrapTLV(val, aTag(classC, false, uint32(0))) // [0]
		enc = append(enc, val...)
		if val, err = r.Criteria.Encode(); err == nil { // CHOICE:CRITERIA
			val, _ = wrapTLV(val, aTag(classC, true, uint32(1))) // [1]
			enc = append(enc, val...)
			if val, err = r.Subset.Encode(); err == nil { // INTEGER
				val, _ = wrapTLV(val, aTag(classC, false, uint32(2))) // [2]
				enc = append(enc, val...)
				enc, err = wrapTLV(enc, uSeqTag()) // SEQUENCE
			}
		}
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the input
encoding to the receiver instance. The encoding must not be truncated and
must bear the UNIVERSAL SEQUENCE tag (0x30).
*/
func (r *EnhancedGuide) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag())
	if err == nil {
		p := 0
		var val []byte
		val, err = readEPTLV(payload, &p, classC, 0)
		if err == nil {
			if err = r.ObjectClass.Decode(val); err == nil {
				val, err = readECTLV(payload, &p, classC, 1, true)
				if err == nil {
					tag, _ := readTag(val)
					r.Criteria, err = decodeCriteriaByTag(tag.Tag, val)
					if err == nil {
						val, err = readEPTLV(payload, &p, classC, 2)
						if err == nil {
							err = r.Subset.Decode(val)
							r.Subset.ok = err == nil // TODO fix this
						}
					}
				}
			}
		}
	}

	return err
}

func enhancedGuide(x any) (result bool, err error) {
	_, err = marshalEnhancedGuide(x)
	result = err == nil
	return
}

func marshalEnhancedGuide(x any) (g EnhancedGuide, err error) {
	var raw []byte
	if raw, err = assertBytes(x, 5, "Enhanced Guide"); err != nil {
		return
	}

	raws := splitUnescapedBytes(raw, tSharp, tBSlash)
	if len(raws) != 3 {
		err = syntaxError("Enhanced Guide: bad syntax")
		return
	}

	oc := bytes.TrimSpace(raws[0])
	g.ObjectClass, err = NewObjectIdentifier(oc)
	if err != nil {
		return
	}

	cp := newCriteriaParser(raws[1])
	g.Criteria = cp.tokenizeCriteria()
	if err = g.Criteria.Valid(); err != nil {
		err = syntaxError("Enhanced Guide: invalid Criteria: ",
			err.Error(), " -- ", b2s(raws[1]))
		return
	}

	if g.Subset = subsetToInt(raws[2]); g.Subset.Native() == -1 {
		err = syntaxError("Enhanced Guide: incompatible subset: ",
			b2s(raws[2]))
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r EnhancedGuide) String() (s string) {
	if &r != nil && r.Criteria != nil {
		s = r.ObjectClass.String() + `#` +
			r.Criteria.String() + `#` +
			intToSubset(r.Subset)
	}

	return
}

func subsetToInt(x []byte) (i Integer) {
	i = Integer{ok: true, native: -1}
	switch b2s(lc(bytes.TrimSpace(x))) {
	case `baseobject`:
		i = Integer{ok: true}
	case `onelevel`:
		i = Integer{ok: true, native: 1}
	case `wholesubtree`:
		i = Integer{ok: true, native: 2}
	}

	return
}

func intToSubset(x Integer) (s string) {
	s = `oneLevel`
	switch x.Native() {
	case 0:
		s = `baseObject`
	case 2:
		s = `wholeSubtree`
	}

	return
}

/*
Deprecated: Guide is OBSOLETE and is provided for historical support only;
use [EnhancedGuide] instead.

From [§ 3.3.14 of RFC 4517]:

	Guide = [ object-class SHARP ] criteria

	object-class  = WSP oid WSP
	criteria   = and-term *( BAR and-term )
	and-term   = term *( AMPERSAND term )
	term       = EXCLAIM term /
	             attributetype DOLLAR match-type /
	             LPAREN criteria RPAREN /
	             true /
	             false
	match-type = "EQ" / "SUBSTR" / "GE" / "LE" / "APPROX"
	true       = "?true"
	false      = "?false"
	BAR        = %x7C  ; vertical bar ("|")
	AMPERSAND  = %x26  ; ampersand ("&")
	EXCLAIM    = %x21  ; exclamation mark ("!")

[§ 3.3.14 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.14
*/
type Guide struct {
	ObjectClass ObjectIdentifier `asn1:"tag:0,optional"`
	Criteria    Criteria         `asn1:"tag:1"`
}

func NewGuide(x any) (Guide, error) {
	return marshalGuide(x)
}

func guide(x any) (result bool, err error) {
	_, err = marshalGuide(x)
	result = err == nil
	return
}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the receiver instance as a UNIVERSAL SEQUENCE.
*/
func (r Guide) Encode() ([]byte, error) {
	enc := make([]byte, 0)
	val, err := r.ObjectClass.Encode() // OBJECT IDENTIFIER
	if err == nil {
		val, _ = wrapTLV(val, aTag(classC, false, uint32(0))) // [0]
		enc = append(enc, val...)
		if val, err = r.Criteria.Encode(); err == nil { // CHOICE:CRITERIA
			val, _ = wrapTLV(val, aTag(classC, true, uint32(1))) // [1]
			enc = append(enc, val...)
			enc, err = wrapTLV(enc, uSeqTag()) // SEQUENCE
		}
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the input
encoding to the receiver instance. The encoding must not be truncated and
must bear the UNIVERSAL SEQUENCE tag (0x30).
*/
func (r *Guide) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag())
	if err == nil {
		p := 0
		var val []byte
		val, err = readEPTLV(payload, &p, classC, 0)
		if err == nil {
			if err = r.ObjectClass.Decode(val); err == nil {
				val, err = readECTLV(payload, &p, classC, 1, true)
				if err == nil {
					tag, _ := readTag(val)
					r.Criteria, err = decodeCriteriaByTag(tag.Tag, val)
				}
			}
		}
	}

	return err
}

func marshalGuide(x any) (g Guide, err error) {
	var raw []byte
	if raw, err = assertBytes(x, 5, "Guide"); err != nil {
		return
	}

	raws := splitUnescapedBytes(raw, tSharp, tBSlash)

	switch l := len(raws); l {
	case 1:
		cp := newCriteriaParser(raws[0])
		g.Criteria = cp.tokenizeCriteria()
	case 2:
		oc := bytes.TrimSpace(raws[0])
		if g.ObjectClass, err = NewObjectIdentifier(oc); err == nil {
			cp := newCriteriaParser(raws[1])
			g.Criteria = cp.tokenizeCriteria()
		}
	default:
		err = syntaxError("Guide: unexpected component length; want 2, got ",
			strconv.FormatInt(int64(l), 10))
	}

	if err == nil {
		err = g.Criteria.Valid()
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r Guide) String() (s string) {
	if &r != nil && r.Criteria != nil {
		if r.ObjectClass != nil {
			s += r.ObjectClass.String() + `#`
		}
		s += r.Criteria.String()
	}

	return
}

/*
CriteriaItem implements the CriteriaItem ASN.1 CHOICE definition, per
[§ 6.5.2 of ITU-T rec. X.520]:

	CriteriaItem ::= CHOICE {
	  equality         [0] AttributeType,
	  substrings       [1] AttributeType,
	  greaterOrEqual   [2] AttributeType,
	  lessOrEqual      [3] AttributeType,
	  approximateMatch [4] AttributeType,
	  ... }

This interface is implemented through instances of the following types:

  - [CriteriaItemEquality]
  - [CriteriaItemSubstrings]
  - [CriteriaItemGreaterOrEqual]
  - [CriteriaItemLessOrEqual]
  - [CriteriaItemApproximateMatch]

Note that the [Criteria] interface is a superset of this interface.

As a whole, instances of this type represent the "type" ASN.1 CHOICE
component of a [Criteria] implementation. Therefore, when encoded by
itself, an instance of this type shall only bear the CONTEXT-SPECIFIC
tags shown in the above definition. But when encoded in a bonafide
[Criteria] context, the encoding is wrapped in an additional UNIVERSAL [0]
context.

[§ 6.5.2 of ITU-T rec. X.520]: https://www.itu.int/rec/T-REC-X.520
*/
type CriteriaItem interface {
	Tag() int
	Choice() string
	String() string
	Encode() ([]byte, error)
	Len() int
	Index(int) Criteria
	Valid() error

	// CriteriaItem spans two interfaces: Criteria
	// and CritieriaItem.
	isCriteria()
	isCriteriaItem()
}

type invalidCriteriaItem struct{}

/*
CriteriaItemEquality implements the "equality" [AttributeType]
CHOICE type for a [CriteriaItem].
*/
type CriteriaItemEquality AttributeType

/*
CriteriaItemSubstrings implements the "substrings" [AttributeType]
CHOICE type for a [CriteriaItem].
*/
type CriteriaItemSubstrings AttributeType

/*
CriteriaItemGreaterOrEqual implements the "greaterOrEqual" [AttributeType]
CHOICE type for a [CriteriaItem].
*/
type CriteriaItemGreaterOrEqual AttributeType

/*
CriteriaItemLessOrEqual implements the "lessOrEqual" [AttributeType]
CHOICE type for a [CriteriaItem].
*/
type CriteriaItemLessOrEqual AttributeType

/*
CriteriaItemApproximateMatch implements the "approximateMatch" [AttributeType]
CHOICE type for a [CriteriaItem].
*/
type CriteriaItemApproximateMatch AttributeType

func (_ invalidCriteriaItem) Encode() ([]byte, error) {
	return nil, errInvalidCritItem
}

func (r CriteriaItemEquality) Encode() ([]byte, error) {
	return criteriaItemEncode(r, r.Tag())
}

func (r CriteriaItemSubstrings) Encode() ([]byte, error) {
	return criteriaItemEncode(r, r.Tag())
}

func (r CriteriaItemGreaterOrEqual) Encode() ([]byte, error) {
	return criteriaItemEncode(r, r.Tag())
}

func (r CriteriaItemLessOrEqual) Encode() ([]byte, error) {
	return criteriaItemEncode(r, r.Tag())
}

func (r CriteriaItemApproximateMatch) Encode() ([]byte, error) {
	return criteriaItemEncode(r, r.Tag())
}

func criteriaItemEncode(raw []byte, tag int) (outer []byte, err error) {
	var payload []byte
	if payload, err = OctetString(raw).Encode(); err == nil {
		outer, err = wrapTLV(payload,
			aTag(asn1.ClassContextSpecific,
				false, uint32(tag)))
	}
	return outer, err
}

func (_ invalidCriteriaItem) Tag() int { return -1 }

/*
Tag returns the integer form of the [0] context tag for a [CriteriaItem] ASN.1 CHOICE.
*/
func (_ CriteriaItemEquality) Tag() int { return 0 }

/*
Tag returns the integer form of the [1] context tag for a [CriteriaItem] ASN.1 CHOICE.
*/
func (_ CriteriaItemSubstrings) Tag() int { return 1 }

/*
Tag returns the integer form of the [2] context tag for a [CriteriaItem] ASN.1 CHOICE.
*/
func (_ CriteriaItemGreaterOrEqual) Tag() int { return 2 }

/*
Tag returns the integer form of the [3] context tag for a [CriteriaItem] ASN.1 CHOICE.
*/
func (_ CriteriaItemLessOrEqual) Tag() int { return 3 }

/*
Tag returns the integer form of the [4] context tag for a [CriteriaItem] ASN.1 CHOICE.
*/
func (_ CriteriaItemApproximateMatch) Tag() int { return 4 }

func (r invalidCriteriaItem) Index(_ int) Criteria { return r }

/*
Index returns the receiver instance. This method exists solely to satisfy Go's interface
signature requirements with respect to the [Criteria] and [CriteriaItem] types.
*/
func (r CriteriaItemEquality) Index(_ int) Criteria { return r }

/*
Index returns the receiver instance. This method exists solely to satisfy Go's interface
signature requirements with respect to the [Criteria] and [CriteriaItem] types.
*/
func (r CriteriaItemSubstrings) Index(_ int) Criteria { return r }

/*
Index returns the receiver instance. This method exists solely to satisfy Go's interface
signature requirements with respect to the [Criteria] and [CriteriaItem] types.
*/
func (r CriteriaItemGreaterOrEqual) Index(_ int) Criteria { return r }

/*
Index returns the receiver instance. This method exists solely to satisfy Go's interface
signature requirements with respect to the [Criteria] and [CriteriaItem] types.
*/
func (r CriteriaItemLessOrEqual) Index(_ int) Criteria { return r }

/*
Index returns the receiver instance. This method exists solely to satisfy Go's interface
signature requirements with respect to the [Criteria] and [CriteriaItem] types.
*/
func (r CriteriaItemApproximateMatch) Index(_ int) Criteria { return r }

func (_ invalidCriteriaItem) Choice() string { return `invalid` }

/*
Choice returns the string literal "equality", representing the ASN.1 CHOICE
component name.
*/
func (_ CriteriaItemEquality) Choice() string { return "equality" }

/*
Choice returns the string literal "substrings", representing the ASN.1 CHOICE
component name.
*/
func (_ CriteriaItemSubstrings) Choice() string { return "substrings" }

/*
Choice returns the string literal "greaterOrEqual", representing the ASN.1 CHOICE
component name.
*/
func (_ CriteriaItemGreaterOrEqual) Choice() string { return "greaterOrEqual" }

/*
Choice returns the string literal "lessOrEqual", representing the ASN.1 CHOICE
component name.
*/
func (_ CriteriaItemLessOrEqual) Choice() string { return "lessOrEqual" }

/*
Choice returns the string literal "approximateMatch", representing the ASN.1 CHOICE
component name.
*/
func (_ CriteriaItemApproximateMatch) Choice() string { return "approximateMatch" }

func (_ invalidCriteriaItem) Len() int { return 1 }

/*
Len returns a fixed integer value of 1. This method exists solely to satisfy Go's
interface signature requirements with respect to the [Criteria] and [CriteriaItem]
types.
*/
func (_ CriteriaItemEquality) Len() int { return 1 }

/*
Len returns a fixed integer value of 1. This method exists solely to satisfy Go's
interface signature requirements with respect to the [Criteria] and [CriteriaItem]
types.
*/
func (_ CriteriaItemSubstrings) Len() int { return 1 }

/*
Len returns a fixed integer value of 1. This method exists solely to satisfy Go's
interface signature requirements with respect to the [Criteria] and [CriteriaItem]
types.
*/
func (_ CriteriaItemGreaterOrEqual) Len() int { return 1 }

/*
Len returns a fixed integer value of 1. This method exists solely to satisfy Go's
interface signature requirements with respect to the [Criteria] and [CriteriaItem]
types.
*/
func (_ CriteriaItemLessOrEqual) Len() int { return 1 }

/*
Len returns a fixed integer value of 1. This method exists solely to satisfy Go's
interface signature requirements with respect to the [Criteria] and [CriteriaItem]
types.
*/
func (_ CriteriaItemApproximateMatch) Len() int { return 1 }

func (_ invalidCriteriaItem) String() string { return `` }

/*
String returns the string representation of the receiver instance.
*/
func (r CriteriaItemEquality) String() string { return b2s(r) + "$EQ" }

/*
String returns the string representation of the receiver instance.
*/
func (r CriteriaItemSubstrings) String() string { return b2s(r) + "$SUBSTR" }

/*
String returns the string representation of the receiver instance.
*/
func (r CriteriaItemGreaterOrEqual) String() string { return b2s(r) + "$GE" }

/*
String returns the string representation of the receiver instance.
*/
func (r CriteriaItemLessOrEqual) String() string { return b2s(r) + "$LE" }

/*
String returns the string representation of the receiver instance.
*/
func (r CriteriaItemApproximateMatch) String() string { return b2s(r) + "$APPROX" }

func (_ invalidCriteriaItem) Valid() (err error) {
	err = errInvalidCritItem
	return
}

/*
Valid returns an error following an OID syntax check upon the receiver instance.
*/
func (r CriteriaItemEquality) Valid() (err error) {
	if _, err = oID(r); err != nil {
		err = syntaxError("Invalid attributeType for equality: ", err.Error())
	}
	return
}

/*
Valid returns an error following an OID syntax check upon the receiver instance.
*/
func (r CriteriaItemSubstrings) Valid() (err error) {
	if _, err = oID(r); err != nil {
		err = syntaxError("Invalid attributeType for substrings: ", err.Error())
	}
	return
}

/*
Valid returns an error following an OID syntax check upon the receiver instance.
*/
func (r CriteriaItemGreaterOrEqual) Valid() (err error) {
	if _, err = oID(r); err != nil {
		err = syntaxError("Invalid attributeType for greaterOrEqual: ", err.Error())
	}
	return
}

/*
Valid returns an error following an OID syntax check upon the receiver instance.
*/
func (r CriteriaItemLessOrEqual) Valid() (err error) {
	if _, err = oID(r); err != nil {
		err = syntaxError("Invalid attributeType for lessOrEqual: ", err.Error())
	}
	return
}

/*
Valid returns an error following an OID syntax check upon the receiver instance.
*/
func (r CriteriaItemApproximateMatch) Valid() (err error) {
	if _, err = oID(r); err != nil {
		err = syntaxError("Invalid attributeType for approximateMatch: ", err.Error())
	}
	return
}

func (_ CriteriaItemEquality) isCriteria()         {}
func (_ CriteriaItemSubstrings) isCriteria()       {}
func (_ CriteriaItemGreaterOrEqual) isCriteria()   {}
func (_ CriteriaItemLessOrEqual) isCriteria()      {}
func (_ CriteriaItemApproximateMatch) isCriteria() {}
func (_ invalidCriteriaItem) isCriteria()          {}

func (_ CriteriaItemEquality) isCriteriaItem()         {}
func (_ CriteriaItemSubstrings) isCriteriaItem()       {}
func (_ CriteriaItemGreaterOrEqual) isCriteriaItem()   {}
func (_ CriteriaItemLessOrEqual) isCriteriaItem()      {}
func (_ CriteriaItemApproximateMatch) isCriteriaItem() {}
func (_ invalidCriteriaItem) isCriteriaItem()          {}

/*
Criteria implements the Criteria ASN.1 definition defined in
[§ 6.5.2 of ITU-T rec. X.520]:

	Criteria ::= CHOICE {
	        type [0] CriteriaItem
	        and  [1] SET OF Criteria,
	        or   [2] SET OF Criteria,
	        not  [3] Criteria,
	... }

The ABNF defined in [§ 3.3.10 of RFC 4517] describes the LDAP specific
encoding of values of this type:

	criteria   = and-term *( BAR and-term )
	and-term   = term *( AMPERSAND term )
	term       = EXCLAIM term /
	             attributetype DOLLAR match-type /
	             LPAREN criteria RPAREN /
	             true /
	             false
	match-type = "EQ" / "SUBSTR" / "GE" / "LE" / "APPROX"
	true       = "?true"
	false      = "?false"
	BAR        = %x7C  ; vertical bar ("|")
	AMPERSAND  = %x26  ; ampersand ("&")
	EXCLAIM    = %x21  ; exclamation mark ("!")

Use of the true/false (?true/?false) terms will result in the assignment of
a zero length [CriteriaAnd]/[CriteriaOr] instance respectively.

This interface is implemented through instances of the following types:

  - [CriteriaAnd]
  - [CriteriaOr]
  - [CriteriaNot]
  - All [CriteriaItem] types ([CriteriaItem] is a subset of this interface)

[§ 3.3.10 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.10
[§ 6.5.2 of ITU-T rec. X.520]: https://www.itu.int/rec/T-REC-X.520
*/
type Criteria interface {
	Tag() int
	Choice() string
	String() string
	Len() int
	Encode() ([]byte, error)
	Index(int) Criteria
	Valid() error
	isCriteria()
}

type invalidCriteria struct{}

/*
CriteriaAnd implements the [Criteria] "and" ASN.1 CHOICE.
*/
type CriteriaAnd []Criteria

/*
CriteriaOr implements the [Criteria] "or" ASN.1 CHOICE.
*/
type CriteriaOr []Criteria

/*
CriteriaOr implements the [Criteria] "not" ASN.1 CHOICE.
*/
type CriteriaNot struct {
	Criteria
}

func (_ invalidCriteria) Tag() int { return -1 }

/*
Tag returns the integer form of the [1] context tag for a [Criteria] ASN.1 CHOICE.
*/
func (_ CriteriaAnd) Tag() int { return 1 }

/*
Tag returns the integer form of the [2] context tag for a [Criteria] ASN.1 CHOICE.
*/
func (_ CriteriaOr) Tag() int { return 2 }

/*
Tag returns the integer form of the [3] context tag for a [Criteria] ASN.1 CHOICE.
*/
func (_ CriteriaNot) Tag() int { return 3 }

func (_ invalidCriteria) Choice() string { return "invalid" }

/*
Choice returns the string literal "and", representing the ASN.1 CHOICE
component name.
*/
func (_ CriteriaAnd) Choice() string { return "and" }

/*
Choice returns the string literal "or", representing the ASN.1 CHOICE
component name.
*/
func (_ CriteriaOr) Choice() string { return "or" }

/*
Choice returns the string literal "not", representing the ASN.1 CHOICE
component name.
*/
func (_ CriteriaNot) Choice() string { return "not" }

func (_ invalidCriteria) Encode() ([]byte, error) {
	return nil, errInvalidCrit
}

func (r CriteriaAnd) Encode() ([]byte, error) {
	return encodeCriteriaSet(uint32(r.Tag()), r)
}

func (r CriteriaOr) Encode() ([]byte, error) {
	return encodeCriteriaSet(uint32(r.Tag()), r)
}

func (r *CriteriaAnd) Decode(enc []byte) error {
	var f []Criteria
	var err error
	f, err = decodeCriteriaSet(uint32(r.Tag()), enc)
	if err == nil {
		*r = CriteriaAnd(f)
	}
	return err
}

func (r *CriteriaOr) Decode(enc []byte) error {
	var f []Criteria
	var err error
	f, err = decodeCriteriaSet(uint32(r.Tag()), enc)
	if err == nil {
		*r = CriteriaOr(f)
	}

	return err
}

func (r CriteriaNot) Encode() ([]byte, error) {
	enc, err := r.Criteria.Encode()
	var out []byte
	if err == nil {
		out, err = wrapTLV(enc,
			aTag(classC,
				true, uint32(r.Tag())))
	}

	return out, err
}

func (r *CriteriaNot) Decode(enc []byte) error {
	p := 0

	payload, err := readECTLV(enc, &p, classC, uint32(r.Tag()))

	if err == nil {

		p2 := 0
		start := p2

		var childTag Tag
		if childTag, _, err = readCTLV(payload, &p2); err == nil {
			var f Criteria
			if f, err = decodeCriteriaByTag(childTag.Tag, payload[start:p2]); err == nil {
				r.Criteria = f
			}
		}
	}

	return err
}

/*
String returns the string representation of the receiver instance.
*/
func (r CriteriaAnd) String() string {
	L := len(r)
	if L == 0 {
		return "?true"
	}
	var terms []string
	for _, c := range r {
		terms = append(terms, c.String())
	}
	s := strings.Join(terms, "&")
	if L > 1 {
		s = "(" + s + ")"
	}
	return s
}

/*
String returns the string representation of the receiver instance.
*/
func (r CriteriaOr) String() string {
	L := len(r)
	if L == 0 {
		return "?false"
	}
	var terms []string
	for _, c := range r {
		terms = append(terms, c.String())
	}
	s := strings.Join(terms, "|")
	if L > 1 {
		s = "(" + s + ")"
	}
	return s
}

/*
String returns the string representation of the receiver instance.
*/
func (r CriteriaNot) String() string {
	if r.Criteria == nil {
		return ""
	}
	s := r.Criteria.String()
	if _, ok := r.Criteria.(CriteriaAnd); ok && r.Criteria.Len() > 1 {
		return "!" + s
	}
	if _, ok := r.Criteria.(CriteriaOr); ok && r.Criteria.Len() > 1 {
		return "!" + s
	}
	return "!" + s
}

func (_ invalidCriteria) String() string { return `` }

/*
Len returns the integer length of the receiver instance.
*/
func (r CriteriaAnd) Len() int { return len(r) }

/*
Len returns the integer length of the receiver instance.
*/
func (r CriteriaOr) Len() int { return len(r) }

/*
Len returns a fixed integer value of 1. This method exists solely to satisfy Go's
interface signature requirements with respect to the [Criteria] type.
*/
func (_ CriteriaNot) Len() int { return 1 }

func (_ invalidCriteria) Len() int { return -1 }

/*
Index returns the Nth slice member residing within the receiver instance.
*/
func (r CriteriaAnd) Index(idx int) (c Criteria) {
	if 0 <= idx && idx < len(r) {
		c = r[idx]
	}
	return
}

/*
Index returns the Nth slice member residing within the receiver instance.
*/
func (r CriteriaOr) Index(idx int) (c Criteria) {
	if 0 <= idx && idx < len(r) {
		c = r[idx]
	}
	return
}

/*
Index returns the receiver instance. This method exists solely to satisfy Go's interface
signature requirements with respect to the [Criteria] type.
*/
func (r CriteriaNot) Index(_ int) Criteria {
	var c Criteria = invalidCriteria{}
	if r.Criteria != nil {
		c = r
	}
	return c
}

func (r invalidCriteria) Index(_ int) Criteria { return r }

/*
Valid returns an error following a validity check conducted upon all slice members.

Note that a zero-length receiver is considered valid.
*/
func (r CriteriaAnd) Valid() (err error) {
	for i := 0; i < len(r) && err == nil; i++ {
		if r[i] == nil {
			err = syntaxError("CriteriaAnd: nil child")
		} else {
			err = r[i].Valid()
		}
	}
	return
}

/*
Valid returns an error following a validity check conducted upon all slice members.

Note that a zero-length receiver is considered valid.
*/
func (r CriteriaOr) Valid() (err error) {
	for i := 0; i < len(r) && err == nil; i++ {
		if r[i] == nil {
			err = syntaxError("CriteriaOr: nil child")
		} else {
			err = r[i].Valid()
		}
	}
	return
}

/*
Valid returns an error following a validity check conducted upon the underlying
[Criteria] instance.
*/
func (r CriteriaNot) Valid() (err error) {
	if r.Criteria == nil {
		err = syntaxError("CriteriaNot: nil instance")
	} else {
		err = r.Criteria.Valid()
	}
	return
}

func encodeCriteriaSet(tag uint32, fs []Criteria) ([]byte, error) {
	var payload []byte
	var err error

	for i := 0; i < len(fs) && err == nil; i++ {
		var enc []byte
		enc, err = fs[i].Encode()
		if err == nil {
			payload = append(payload, enc...)
		}
	}

	var out []byte
	if err == nil {
		out, err = wrapTLV(payload,
			aTag(classU, true, uint32(tSet)),
			aTag(classC, true, tag))
	}

	return out, err
}

func decodeCriteriaSet(tag uint32, enc []byte) ([]Criteria, error) {

	payload, err := unwrapTLV(enc,
		aTag(classC, true, tag),
		aTag(classU, true, uint32(tSet)))

	var out []Criteria
	if err == nil {
		p := 0
		for p < len(payload) && err == nil {
			start := p

			var childTag Tag
			if childTag, _, err = readCTLV(payload, &p); err == nil {
				var f Criteria
				f, err = decodeCriteriaByTag(childTag.Tag, payload[start:p])
				if err == nil {
					out = append(out, f)
				}
			}
		}
	}

	return out, err
}

func decodeCriteriaByTag(tag uint32, payload []byte) (f Criteria, err error) {
	switch tag {
	case 0:
		subtag, _ := readTag(payload)

		var val []byte
		val, err = unwrapTLV(payload, aTag(classC, false, subtag.Tag))
		if err == nil {
			var x OctetString
			if err = x.Decode(val); err == nil {
				switch subtag.Tag {
				case 0:
					f = CriteriaItemEquality(x)
				case 1:
					f = CriteriaItemSubstrings(x)
				case 2:
					f = CriteriaItemGreaterOrEqual(x)
				case 3:
					f = CriteriaItemLessOrEqual(x)
				case 4:
					f = CriteriaItemApproximateMatch(x)
				default:
					err = asn1Error("unexpected CriteriaItem tag ", itoa(int(subtag.Tag)))
				}
			}
		}
	case 1:
		var x CriteriaAnd
		err = x.Decode(payload)
		f = x
	case 2:
		var x CriteriaOr
		err = x.Decode(payload)
		f = x
	case 3:
		var x CriteriaNot
		err = x.Decode(payload)
		f = x
	default:
		err = asn1Error("unexpected Criteria tag ", itoa(int(tag)))
	}

	return
}

func (_ invalidCriteria) Valid() (err error) {
	return syntaxError("Criteria: invalid instance")
}

func (_ invalidCriteria) isCriteria() {}
func (_ CriteriaAnd) isCriteria()     {}
func (_ CriteriaOr) isCriteria()      {}
func (_ CriteriaNot) isCriteria()     {}

type criteriaParser struct {
	input []byte
	pos   int
}

func newCriteriaParser(input []byte) *criteriaParser {
	return &criteriaParser{input: bytes.TrimSpace(input), pos: 0}
}

func (t *criteriaParser) next() byte {
	if t.pos >= len(t.input) {
		return 0
	}
	ch := t.input[t.pos]
	t.pos++
	return ch
}

func (t *criteriaParser) peek() byte {
	if t.pos >= len(t.input) {
		return 0
	}
	return t.input[t.pos]
}

func (t *criteriaParser) tokenizeCriteria() Criteria {
	var ors CriteriaOr
	ors = append(ors, t.tokenizeAndTerm())
	for t.peek() == '|' {
		t.next()
		ors = append(ors, t.tokenizeAndTerm())
	}

	L := len(ors)
	// NOTE: zero length is OK! // bool term==false
	if L == 1 {
		return ors[0]
	}
	return ors
}

func (t *criteriaParser) tokenizeAndTerm() Criteria {
	var and CriteriaAnd
	and = append(and, t.tokenizeTerm())
	for t.peek() == '&' {
		t.next()
		and = append(and, t.tokenizeTerm())
	}

	L := len(and)
	// NOTE: zero length is OK! // bool term==true
	if L == 1 {
		return and[0]
	}

	return and
}

func (t *criteriaParser) tokenizeTerm() Criteria {
	switch t.peek() {
	case '!':
		t.next()
		return CriteriaNot{Criteria: t.tokenizeTerm()}
	case '(':
		t.next()
		c := t.tokenizeCriteria()
		t.next()
		return c
	case '?':
		t.next()
		if bHasPfx(t.input[t.pos:], tTrue) {
			t.pos += 4
			return CriteriaAnd{}
		} else if bHasPfx(t.input[t.pos:], tFalse) {
			t.pos += 5
			return CriteriaOr{}
		}
	}

	attrType := t.tokenizeUntil('$')
	t.next()
	matchType := t.tokenizeMatchType()
	var item CriteriaItem
	switch strings.ToUpper(b2s(matchType)) {
	case "EQ":
		item = CriteriaItemEquality(attrType)
	case "SUBSTR":
		item = CriteriaItemSubstrings(attrType)
	case "GE":
		item = CriteriaItemGreaterOrEqual(attrType)
	case "LE":
		item = CriteriaItemLessOrEqual(attrType)
	case "APPROX":
		item = CriteriaItemApproximateMatch(attrType)
	default:
		return invalidCriteriaItem{}
	}
	return item
}

func (t *criteriaParser) tokenizeUntil(delims ...byte) []byte {
	start := t.pos
	for {
		if t.pos >= len(t.input) {
			break
		}
		ch := t.input[t.pos]
		for _, d := range delims {
			if ch == d {
				return t.input[start:t.pos]
			}
		}
		t.pos++
	}
	return t.input[start:t.pos]
}

func (t *criteriaParser) tokenizeMatchType() (s []byte) {
	switch t.peek() {
	case 'E':
		if bHasPfx(t.input[t.pos:], tItemEQ) {
			t.pos += 2
			s = tItemEQ
		}
	case 'S':
		if bHasPfx(t.input[t.pos:], tItemSUB) {
			t.pos += 6
			s = tItemSUB
		}
	case 'G':
		if bHasPfx(t.input[t.pos:], tItemGE) {
			t.pos += 2
			s = tItemGE
		}
	case 'L':
		if bHasPfx(t.input[t.pos:], tItemLE) {
			t.pos += 2
			s = tItemLE
		}
	case 'A':
		if bHasPfx(t.input[t.pos:], tItemAPX) {
			t.pos += 6
			s = tItemAPX
		}
	}

	return
}

var (
	errInvalidCritItem = syntaxError("Criteria Item: invalid instance")
	errInvalidCrit     = syntaxError("Criteria: invalid instance")
)
