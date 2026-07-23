package aci

/*
aci.go implements types and methods pertaining to the Netscape
Access Control Instruction Version 3.0 (ACIv3) syntax.
*/

import (
	"encoding/binary"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/JesseCoretta/go-ldapfilter"
	"github.com/JesseCoretta/go-shifty"
)

/*
Instruction is the high-level composite type for Netscape's ACIv3
instruction construct.

Field T contains an [TargetRule], which is always optional.

Field A contains a string intended for a helpful "label" which differentiates the
statement from other instructions -- a requirement of most directory implementations
which honor the ACIv3 syntax. This is known as the "ACL", or "Access Control Label".

Field PB contains an instance of [PermissionBindRule], which MUST contain at
least one (1) [PermissionBindRuleItem].
*/
type Instruction struct {
	T  TargetRule         // *0 TargetRuleItem
	A  string             //  1 ACL
	PB PermissionBindRule // *1 PermissionBindRuleItem
}

/*
OID returns the official Netscape ACIv3 object identifier string literal "2.16.840.1.113730.3.1.55".
*/
func (r Instruction) OID() string {
	return `2.16.840.1.113730.3.1.55`
}

/*
NewInstruction returns an instance of [Instruction] alongside an error following an attempt
to parse or marshal x.
*/
func NewInstruction(x ...any) (Instruction, error) {
	var (
		i Instruction = Instruction{
			T:  TargetRule{&aCITargetRule{}},
			PB: badACIv3PBR,
		}
		err error
	)

	switch len(x) {
	case 0:
	case 1:
		if str, ok := x[0].(string); ok {
			err = i.parse(str)
		} else {
			err = badACIv3InstructionErr
		}
	case 2:
		err = i.parseLen2(x[0], x[1])
	case 3:
		err = i.parseLen3(x[0], x[1], x[2])
	default:
		err = badACIv3InstructionErr
	}

	return i, err
}

/*
String returns the string representation of the receiver instance.
*/
func (r Instruction) String() string {
	return r.T.String() + "(version 3.0; acl \"" +
		r.A + "\"; " + r.PB.String() + ")"
}

func (r *Instruction) parse(x string) (err error) {
	x = strings.TrimSpace(x)

	tidx := strings.Index(x, "version 3.0;")
	if tidx == -1 || tidx == 0 {
		err = badACIv3InstructionErr
		return
	}

	if t := strings.TrimRight(strings.TrimSpace(x[:tidx-1]), `(`); len(t) > 0 {
		err = r.T.parse(t)
	}

	if err == nil {
		n := strings.TrimSpace(x[tidx+12:])
		if aidx := strings.IndexRune(n, '"'); aidx == -1 {
			err = badACIv3InstructionErr
		} else {
			// Read the quoted ACL string (excluding
			// quotes that are not escaped).
			a := n[aidx+1:]
			e := 0
			for i := 0; i < len(a); i++ {
				if a[i] == '"' && a[i-1] != '\\' {
					e = i + 1
					break
				}
				r.A += string(a[i])
			}

			if pb := strings.TrimSpace(a[e:]); len(pb) < 18 {
				err = badACIv3PBRErr
			} else if pb[0] != ';' || pb[len(pb)-1] != ')' {
				err = badACIv3InstructionErr
			} else {
				err = r.PB.parse(strings.TrimSpace(pb[1 : len(pb)-1]))
			}
		}
	}

	return
}

func (r *Instruction) parseLen2(a, b any) (err error) {
	var ok bool
	if r.A, ok = a.(string); !ok || len(r.A) == 0 {
		err = badACIv3InstructionErr
	} else {
		switch tv := b.(type) {
		case string:
			err = r.PB.parse(tv)
		case PermissionBindRule:
			if err = tv.Valid(); err == nil {
				r.PB = tv
			}
		default:
			err = badACIv3InstructionErr
		}
	}

	return
}

func (r *Instruction) parseLen3(a, b, c any) (err error) {
	switch tv := a.(type) {
	case string:
		err = r.T.parse(tv)
	case TargetRule:
		if err = tv.Valid(); err == nil {
			r.T = tv
		}
	default:
		err = badACIv3InstructionErr
	}

	if err == nil {
		var ok bool
		if r.A, ok = b.(string); !ok || len(r.A) == 0 {
			err = badACIv3InstructionErr
		} else {
			switch tv := c.(type) {
			case string:
				err = r.PB.parse(tv)
			case PermissionBindRule:
				if err = tv.Valid(); err == nil {
					r.PB = tv
				}
			default:
				err = badACIv3InstructionErr
			}
		}
	}

	return
}

/*
Keyword describes the effective "type" within the context of a given [BindRule] or [TargetRuleItem].

The available Keyword instances vary based on the rule type in which a given Keyword resides.

See the Keyword constants defined in this package for a complete list.
*/
type Keyword interface {
	String() string
	Kind() string

	isACIv3Keyword()
}

/*
Operator implements a simple comparison operator
for [BindRule] and [TargetRuleItem] statements.
*/
type Operator uint8

// private keyword maps exist only to keep cyclomatics down.
var (
	aCIBTMap                    map[BindType]string
	aCIOperatorMap              map[string]Operator
	aCIBindKeywordMap           map[Keyword]string
	aCITargetKeywordMap         map[Keyword]string
	aCIPermittedTargetOperators map[Keyword][]Operator
	aCIPermittedBindOperators   map[Keyword][]Operator
	aCILevelMap                 map[int]InheritanceLevel    = make(map[int]InheritanceLevel, 0)
	aCILevelNumbers             map[string]InheritanceLevel = make(map[string]InheritanceLevel, 0)
	aCIRightsMap                map[Right]string
	aCIRightsNames              map[string]Right
)

var (
	badACIv3Attribute      Attribute
	badAttributeValue      AttributeValue
	badACIv3BindRule       BindRule
	badACIv3BindKeyword    BindKeyword
	badACIv3TargetKeyword  TargetKeyword
	badACIv3Inheritance    Inheritance
	badACIv3TargetRule     TargetRule
	badACIv3TargetRuleItem TargetRuleItem
	badACIv3Permission     Permission
	badACIv3AM             AuthenticationMethod
	badACIv3OID            ObjectIdentifier
	badACIv3PBR            PermissionBindRule
	badACIv3PBRItem        PermissionBindRuleItem
	badACIv3Scope          Scope
	badACIv3FQDN           FQDN
	badACIv3IPAddress      IPAddress
)

// Level bit constraint - we don't use all of uint16 for
// inheritance level bit shifting, thus there is little
// sense in iterating the whole thing.
var aCILevelBitIter int = bitSize(uint16(0)) - 4

/*
AttributeTypeDescription contains the string representation of the Netscape
ACIv3 "aci" attribute type schema definition, formatted in the standard RFC 4512
Attribute Type Description syntax.

Directory systems which implement and honor the Netscape ACIv3 syntax for access
control purposes SHOULD register and advertise this type in the directory schema.

This constant is defined merely for reference. It is not necessary, and likely
impossible, to add this manually to a directory schema.

Facts:

  - OID: 2.16.840.1.113730.3.1.55 (descr: "aci")
  - Directory String SYNTAX
  - NO matching rules of any kind
  - directoryOperation USAGE
  - X-ORIGIN credits Netscape and Sun Java for development of the ACIv3 syntax
*/
const AttributeTypeDescription = `( 2.16.840.1.113730.3.1.55 NAME 'aci' DESC 'Netscape defined access control information attribute type' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE directoryOperation X-ORIGIN 'Netscape/Sun Java Directory Servers' )`

/*
[Right] constants are discrete left-shifted privilege aggregates that can be
used in an additive (or subtractive) manner to form a complete [Permission]
statement.
*/
const (
	ReadAccess      Right = 1 << iota // 1
	WriteAccess                       // 2
	AddAccess                         // 4
	DeleteAccess                      // 8
	SearchAccess                      // 16
	CompareAccess                     // 32
	SelfWriteAccess                   // 64
	ProxyAccess                       // 128
	ImportAccess                      // 256
	ExportAccess                      // 512

	NoAccess  Right = 0
	AllAccess Right = 895 // DOES NOT INCLUDE "proxy"
)

/*
BindType keyword constants are used in value matching definitions that utilizes either the [BindUAT] (userattr) or [BindGAT] (groupattr) [BindKeyword] constant within an [BindRule] instance.
*/
const (
	invalidACIv3BindType BindType = iota // <invalid_bind_type>
	BindTypeUSERDN
	BindTypeGROUPDN
	BindTypeROLEDN
	BindTypeSELFDN
	BindTypeLDAPURL
)

/*
BindKeyword constants are intended for singular use within an [BindRule] instance.
*/
const (
	invalidACIv3BindKeyword BindKeyword = iota // <invalid_bind_keyword>
	BindUDN                                    // `userdn`
	BindRDN                                    // `roledn`
	BindGDN                                    // `groupdn`
	BindUAT                                    // `userattr`
	BindGAT                                    // `groupattr`
	BindIP                                     // `ip`
	BindDNS                                    // `dns`
	BindDoW                                    // `dayofweek`
	BindToD                                    // `timeofday`
	BindAM                                     // `authmethod`
	BindSSF                                    // `ssf`
)

/*
TargetKeyword constants are intended for singular use within an [TargetRuleItem] instance.
*/
const (
	invalidACIv3TargetKeyword TargetKeyword = iota // <invalid_target_keyword>
	Target                                         // 0x1, target
	TargetTo                                       // 0x2, target_to
	TargetAttr                                     // 0x3, targetattr
	TargetCtrl                                     // 0x4, targetcontrol
	TargetFrom                                     // 0x5, target_from
	TargetScope                                    // 0x6, targetscope
	TargetFilter                                   // 0x7, targetfilter
	TargetAttrFilters                              // 0x8, targattrfilters (yes, "targ". As in "wild Klingon boars").
	TargetExtOp                                    // 0x9, extop
)

/*
Level uint16 constants are left-shifted to define a range of vertical (depth) [BindRule] statements.
*/
const (
	invalidACIv3InheritanceLevel InheritanceLevel = 0         //   0 - <no levels>
	Level0                       InheritanceLevel = 1 << iota //   1 - base  (0) (current Object)
	Level1                                                    //   2 - one   (1) level below baseObject
	Level2                                                    //   4 - two   (2) levels below baseObject
	Level3                                                    //   8 - three (3) levels below baseObject
	Level4                                                    //  16 - four  (4) levels below baseObject
	Level5                                                    //  32 - five  (5) levels below baseObject
	Level6                                                    //  64 - six   (6) levels below baseObject
	Level7                                                    // 128 - seven (7) levels below baseObject
	Level8                                                    // 256 - eight (8) levels below baseObject
	Level9                                                    // 512 - nine  (9) levels below baseObject

	AllLevels InheritanceLevel = InheritanceLevel(2046) // ALL levels; one (1) through nine (9)
)

const (
	invalidCop Operator = 0x0

	Eq Operator = 0x1 // "Equal To"
	Ne Operator = 0x2 // "Not Equal To"     !! USE WITH CAUTION !!
	Lt Operator = 0x3 // "Less Than"
	Gt Operator = 0x4 // "Greater Than"
	Le Operator = 0x5 // "Less Than Or Equal"
	Ge Operator = 0x6 // "Greater Than Or Equal"
)

/*
[AttributeOperation] constants are used to initialize and return [AttributeFilter] instances based on one (1) of the possible two (2) constants defined below.
*/
const (
	noAOp AttributeOperation = iota
	AddOp                    // add=
	DelOp                    // delete=
)

const (
	brAnd aCIBindRuleTokenType = iota
	brOr
	brNot
	brParenOpen
	brParenClose
	brValue
	brOperator
)

const (
	trParenOpen aCITargetRuleTokenType = iota
	trParenClose
	trKeyword
	trOperator
	trValue
	trDelim
)

const (
	badATStr          = `<invalid_attribute_type>`
	badAVStr          = `<invalid_attribute_value>`
	badACIv3TRStr     = `<invalid_target_rule>`
	badACIv3BRStr     = `<invalid_bind_rule>`
	badACIv3BTStr     = `<invalid_bind_type>`
	badACIv3BKWStr    = `<invalid_bind_keyword>`
	badACIv3TKWStr    = `<invalid_target_keyword>`
	badACIv3InhStr    = `<invalid_inheritance>`
	badACIv3PermStr   = `<invalid_permission>`
	badDobrNotStr     = `<invalid_object_identifier>`
	badPBRStr         = `<invalid_permission_bind_rule>`
	badDoWStr         = `<invalid_days>`
	badToDStr         = `<invalid_timeofday>`
	badCopStr         = `<invalid_comparison_operator>`
	badACIv3IPAddrStr = `<invalid_address_list>`
	badACIv3FQDNStr   = `<invalid_fqdn_or_label>`
)

const (
	aCIBindRuleIDStr   = `bindRule`
	aCITargetRuleIDStr = `targetRule`
	pbrRuleIDStr       = `permissionBindRule`
	pbrRuleItemIDStr   = `permissionBindRuleItem`
)

const (
	fqdnMax  = 253
	labelMax = 63
)

/*
Day constants can be shifted into an instance of [DayOfWeek], allowing effective expressions such as [Sunday],[Tuesday]. See the [DayOfWeek.Shift] and [DayOfWeek.Unshift] methods.
*/
const (
	noDay     Day = 0         // 0 <invalid_day>
	Sunday    Day = 1 << iota // 1
	Monday                    // 2
	Tuesday                   // 4
	Wednesday                 // 8
	Thursday                  // 16
	Friday                    // 32
	Saturday                  // 64
)

var (
	authMap   map[int]AuthenticationMethod
	authNames map[string]AuthenticationMethod
)

/*
AuthenticationMethodLowerCase allows control over the case folding of AuthenticationMethod string representation.

A value of true shall force lowercase normalization, while a value of false (default) forces uppercase normalization.
*/
var AuthenticationMethodLowerCase bool

/*
AuthenticationMethod constants define all of the available LDAP authentication mechanisms recognized within the ACIv3 syntax honored by the package.

Please note that supported SASL mechanisms vary per implementation.
*/
const (
	noAuth    AuthenticationMethod = iota // invalid
	Anonymous                             // 0
	Simple                                // 1
	SSL                                   // 2
	SASL                                  // 3
	EXTERNAL                              // 4
	DIGESTMD5                             // 5
	GSSAPI                                // 6
)

type aCIBindRuleTokenType int

func (r aCIBindRuleTokenType) isBooleanOperator() bool {
	return r == brAnd || r == brOr || r == brNot
}

type aCITargetRuleTokenType int

/*
BindKeyword contains the value describing a particular [Keyword] to be used within an [BindRule].
*/
type BindKeyword uint8

/*
TargetKeyword contains the value describing a particular [Keyword] to be used within an [TargetRuleItem].
*/
type TargetKeyword uint8

/*
BindType describes one (1) of five (5) possible contexts used in certain [BindRule] instances:

  - [BindTypeUSERDN]
  - [BindTypeGROUPDN]
  - [BindTypeROLEDN]
  - [BindTypeSELFDN]
  - [BindTypeLDAPURL]
*/
type BindType uint8

/*
String returns the string representation of the receiver instance of [BindType].
*/
func (r BindType) String() (b string) {
	b = badACIv3BTStr
	if kw, found := aCIBTMap[r]; found {
		b = kw
	}
	return
}

/*
Kind returns the static string literal `bindRule` identifying the instance as a [BindKeyword].
*/
func (r BindKeyword) Kind() string {
	return aCIBindRuleIDStr
}

func (r BindKeyword) isACIv3Keyword() {}

func aCIKeywordIn(kw Keyword, kws ...Keyword) (in bool) {
	for _, k := range kws {
		if in = k.String() == kw.String(); in {
			break
		}
	}

	return
}

/*
Kind returns the static string literal `targetRule` identifying the instance as a [TargetKeyword].
*/
func (r TargetKeyword) Kind() string {
	return aCITargetRuleIDStr
}

func (r TargetKeyword) isACIv3Keyword() {}

/*
String returns the string representation of the receiver instance of [BindKeyword].
*/
func (r BindKeyword) String() (k string) {
	k = badACIv3BKWStr
	if kw, found := aCIBindKeywordMap[r]; found {
		k = kw
	}
	return
}

/*
String returns the string representation of the receiver instance of [TargetKeyword].
*/
func (r TargetKeyword) String() (k string) {
	k = badACIv3TKWStr
	if kw, found := aCITargetKeywordMap[r]; found {
		k = kw
	}
	return
}

func assertATBTVBindKeyword(bkw ...any) (kw BindKeyword) {
	if kw = BindUAT; len(bkw) > 0 {
		switch tv := bkw[0].(type) {
		case BindKeyword:
			if tv == BindGAT {
				kw = tv
			}
		}
	}

	return
}

/*
matchTKW will return the matching TargetKeyword constant for the input kw string value.
*/
func matchTKW(kw any) (k TargetKeyword) {
	k = invalidACIv3TargetKeyword

	var keyword string
	switch tv := kw.(type) {
	case string:
		keyword = tv
	case TargetKeyword:
		keyword = tv.String()
	default:
		return
	}

	for n, v := range aCITargetKeywordMap {
		if strings.EqualFold(keyword, v) {
			k = n.(TargetKeyword)
			break
		}
	}

	return
}

/*
matchBKW will return the matching BindKeyword constant for the input kw string value.
*/
func matchBKW(kw any) (k BindKeyword) {
	k = invalidACIv3BindKeyword

	var keyword string
	switch tv := kw.(type) {
	case string:
		keyword = tv
	case BindKeyword:
		keyword = tv.String()
	default:
		return
	}

	for n, v := range aCIBindKeywordMap {
		if strings.EqualFold(keyword, v) {
			k = n.(BindKeyword)
			break
		}
	}

	return
}

/*
matchBT will return the matching BindType constant for the input kw string value.
*/
func matchBT(kw string) BindType {
	for k, v := range aCIBTMap {
		if strings.EqualFold(kw, v) {
			return k
		}
	}

	return BindType(0x0)
}

/*
String returns the string representation of the receiver instance.
*/
func (r Operator) String() (cop string) {
	cop = badCopStr
	switch r {
	case Eq:
		cop = `=`
	case Ne:
		cop = `!=`
	case Ge:
		cop = `>=`
	case Gt:
		cop = `>`
	case Le:
		cop = `<=`
	case Lt:
		cop = `<`
	}

	return
}

/*
Description returns the string description for the receiver instance:

  - "Equal To"
  - "Not Equal To"
  - "Less Than"
  - "Greater Than"
  - "Less Than Or Equal"
  - "Greater Than Or Equal"

This method is largely for convenience, and many individuals may feel it only has any practical
applications in the areas of documentation, diagram creation or some other similar activity.

However, a prudent cybersecurity expert may argue that this method can be used to aid in the
(critical) area of proofreading newly-devised or modified access control statements. A person
could very easily mistake >= and <=, certainly if they're overworked or not paying attention.
One such mistake could spell disaster.

Additionally, use of this method as a means to auto-generate [Instruction] comments (for LDIF
configurations, or similar) can greatly help an admin more easily READ and UNDERSTAND the statements
in question.

See the [Operator] const definitions for details.
*/
func (r Operator) Description() (desc string) {
	desc = badCopStr
	switch r {
	case Eq:
		desc = `Equal To`
	case Ne:
		desc = `Not Equal To`
	case Ge:
		desc = `Greater Than Or Equal`
	case Gt:
		desc = `Greater Than`
	case Le:
		desc = `Less Than Or Equal`
	case Lt:
		desc = `Less Than`
	}

	return
}

/*
Context returns the contextual string name of the receiver instance:

  - "Eq"
  - "Ne"
  - "Lt"
  - "Gt"
  - "Le"
  - "Ge"
*/
func (r Operator) Context() (ctx string) {
	ctx = badCopStr
	switch r {
	case Eq:
		ctx = `Eq`
	case Ne:
		ctx = `Ne`
	case Ge:
		ctx = `Ge`
	case Gt:
		ctx = `Gt`
	case Le:
		ctx = `Le`
	case Lt:
		ctx = `Lt`
	}

	return
}

/*
Valid returns an error instance following the process of verifying the receiver to be a known [Operator] instance.  This does NOT, however, imply feasibility of use with any particular type in the creation of [BindRule] or [TargetRuleItem] instances.
*/
func (r Operator) Valid() (err error) {
	if !isValidCopNumeral(int(r)) {
		err = badACIv3CopErr
	}

	return
}

/*
Compare shall resolve the input [Operator] candidate (cop) and, if successful, shall perform an equality assertion between it and the receiver instance. The assertion result is returned as a bool instance.

In the case of the string representation of a given candidate input value, case-folding is not a significant factor.
*/
func (r Operator) Compare(cop any) bool {
	switch tv := cop.(type) {
	case Operator:
		return tv == r
	case int:
		return int(tv) == int(r)
	case string:
		return strInSlice(tv, []string{
			r.Description(),
			r.Context(),
			r.String(),
		})
	}

	return false
}

/*
isValidCopNumeral merely returns the Boolean evaluation result of a check to see whether integer x falls within a numerical range of one (1) through six (6).

This range represents the absolute minimum and maximum numerical values for any valid instance of the Operator type (and, by necessity, the go-aci [Operator] alias type as well).
*/
func isValidCopNumeral(x int) bool {
	return (1 <= x && x <= 6)
}

/*
keywordAllowsACIv3Operator returns a Boolean value indicative of whether Keyword input value kw allows [Operator] op for use in T/B rule instances.

Certain keywords, such as [TargetScope], allow only certain operators, while others, such as [BindSSF], allow the use of ALL operators.
*/
func keywordAllowsACIv3Operator(kw, op any) (allowed bool) {
	// identify the comparison operator,
	// save as cop var.
	var cop Operator
	switch tv := op.(type) {
	case string:
		cop = matchACIv3Cop(tv)
	case Operator:
		cop = tv
	case int:
		cop = Operator(tv)
	default:
		return
	}

	// identify the keyword, and pass it onto
	// the appropriate map search function.
	switch tv := kw.(type) {
	case string:
		if bkw := matchBKW(tv); bkw != BindKeyword(0x0) {
			allowed = operatorAllowedPerKeyword(bkw, cop, aCIPermittedBindOperators)
		} else if tkw := matchTKW(tv); tkw != TargetKeyword(0x0) {
			allowed = operatorAllowedPerKeyword(tkw, cop, aCIPermittedTargetOperators)
		}
	case BindKeyword:
		allowed = operatorAllowedPerKeyword(tv, cop, aCIPermittedBindOperators)
	case TargetKeyword:
		allowed = operatorAllowedPerKeyword(tv, cop, aCIPermittedTargetOperators)
	}

	return
}

/*
matchACIv3Cop reads the *string representation* of a Operator instance and returns the appropriate Operator constant.

A bogus Operator (badCop, 0x0) shall be returned if a match was not made.
*/
func matchACIv3Cop(op string) (cop Operator) {
	for _, v := range aCIOperatorMap {
		if strInSlice(op, []string{
			v.String(),
			v.Context(),
			v.Description(),
		}) {
			cop = v
			break
		}
	}

	return
}

func operatorAllowedPerKeyword(key Keyword, cop Operator, table map[Keyword][]Operator) (allowed bool) {
	// look-up the keyword within the permitted cop
	// map; if found, obtain slices of cops allowed
	// by said keyword.
	if cops, found := table[key]; found {
		// iterate the cops slice, attempting to perform
		// a match of the input cop candidate value and
		// the current cops slice [i].
		for i := 0; i < len(cops) && !allowed; i++ {
			if cop == cops[i] {
				allowed = true
			}
		}
	}

	return
}

//// BIND

/*
BindRuleItem is a qualifier of the [BindRule] interface type,
and represents the core "atom" of any Bind Rule statement.

An instance of this type contains three (3) user-assigned
components, all of which are required:

  - A [BindKeyword]; assigned via the [BindRuleItem.SetKeyword] method
  - A [Operator]; assigned via the [BindRuleItem.SetOperator] method
  - An expression (value of any); assigned via the [BindRuleItem.SetExpression] method
*/
type BindRuleItem struct {
	*aCIBindRuleItem
}

/*
aCIBindRuleItem is the private embedded type found within,
viable instances of [BindRuleItem].
*/
type aCIBindRuleItem struct {
	Keyword    BindKeyword
	Operator   Operator
	Expression any

	paren bool // leading/trailing parentheticals
	pad   bool // leading/trailing space char (inner parens)
	mvq   bool // multi-val quote scheme
}

/*
SetQuotationStyle allows the election of a particular multivalued quotation style offered by the various adopters of the ACIv3 syntax. In the context of a [BindRule], this will only have a meaningful impact if the keyword for the receiver is one (1) of the following:

  - [BindUDN]     (userdn)
  - [BindRDN]     (roledn)
  - [BindGDN]     (groupdn)

Additionally, the underlying type set as the expression value within the receiver MUST be a [BindDistinguishedNames] instance with two (2) or more distinguished names within.

See the const definitions for [MultivalOuterQuotes] (default) and [MultivalSliceQuotes] for details.
*/
func (r BindRuleItem) SetQuotationStyle(style int) BindRule {
	if !r.IsZero() {
		switch r.Expression().(type) {
		case BindDistinguishedName:
			switch r.Keyword() {
			case BindUDN, BindGDN, BindRDN:
				r.aCIBindRuleItem.mvq = style == 0
			}
		}
	}

	return r
}

/*
SetQuotationStyle performs no useful task, as the concept of setting a quotation
style applies only to instances of *[BindRuleItem]. This method exists solely
to satisfy Go's interface signature requirements.
*/
func (r BindRuleOr) SetQuotationStyle(_ int) BindRule { return r }

/*
SetQuotationStyle performs no useful task, as the concept of setting a quotation
style applies only to instances of *[BindRuleItem]. This method exists solely
to satisfy Go's interface signature requirements.
*/
func (r BindRuleAnd) SetQuotationStyle(_ int) BindRule { return r }

/*
SetQuotationStyle performs no useful task, as the concept of setting a quotation
style applies only to instances of *[BindRuleItem]. This method exists solely
to satisfy Go's interface signature requirements.
*/
func (r BindRuleNot) SetQuotationStyle(_ int) BindRule { return r }

/*
SetPaddingStyle controls whitespace padding during the string representation process.

A value of 0 disables padding, while any other positive value enables padding.
*/
func (r BindRuleItem) SetPaddingStyle(style int) BindRule {
	if !r.IsZero() {
		r.aCIBindRuleItem.pad = style > 0
	}

	return r
}

/*
SetPaddingStyle controls whitespace padding during the string representation process.

A value of 0 disables padding, while any other positive value enables padding.
*/
func (r BindRuleAnd) SetPaddingStyle(style int) BindRule {
	if !r.IsZero() {
		r.aCIBindRuleSlice.pad = style > 0
	}

	return r
}

/*
SetPaddingStyle controls whitespace padding during the string representation process.

A value of 0 disables padding, while any other positive value enables padding.
*/
func (r BindRuleOr) SetPaddingStyle(style int) BindRule {
	if !r.IsZero() {
		r.aCIBindRuleSlice.pad = style > 0
	}

	return r
}

/*
SetPaddingStyle controls whitespace padding during the string representation process.

A value of 0 disables padding, while any other positive value enables padding.
*/
func (r BindRuleNot) SetPaddingStyle(style int) BindRule {
	if !r.IsZero() {
		r.BindRule.SetPaddingStyle(style)
	}

	return r
}

/*
Kind returns the string literal "bindRuleItem".
*/
func (r BindRuleItem) Kind() string {
	return `bindRuleItem`
}

/*
Kind returns the string literal "bindRuleAnd".
*/
func (r BindRuleAnd) Kind() string {
	return `bindRuleAnd`
}

/*
Kind returns the string literal "bindRuleOr".
*/
func (r BindRuleOr) Kind() string {
	return `bindRuleOr`
}

/*
Kind returns the string literal "bindRuleNot".
*/
func (r BindRuleNot) Kind() string {
	return `bindRuleNot`
}

/*
Push performs no useful action, as this method exists solely
to satisfy Go's interface signature requirements.
*/
func (r BindRuleItem) Push(_ ...any) BindRule {
	return r
}

func (r BindRuleItem) isBindRule() {} // differentiate from other interfaces
func (r BindRuleAnd) isBindRule()  {} // differentiate from other interfaces
func (r BindRuleOr) isBindRule()   {} // differentiate from other interfaces
func (r BindRuleNot) isBindRule()  {} // differentiate from other interfaces

/*
BindRuleAnd qualifies the [BindRule] interface type and implements
a "BOOLEAN AND" multi-valued slice type in which ALL conditions must
evaluate as true to be considered a match.
*/
type BindRuleAnd struct {
	*aCIBindRuleSlice
}

/*
aCIBindRuleSlice is the private embedded type found within instances
of [BindRuleAnd] and [BindRuleOr].
*/
type aCIBindRuleSlice struct {
	slice []BindRule
	paren bool
	kind  string
	pad   bool
}

/*
BindRuleOr qualifies the [BindRule] interface type and implements
a "BOOLEAN OR" multi-valued slice type in which ONE (1) OR MORE
conditions must evaluate as true to be considered a match.
*/
type BindRuleOr struct {
	*aCIBindRuleSlice
}

/*
BindRuleNot qualifies the [BindRule] interface type and implements
a "BOOLEAN NOT" (negated) type in which NONE of the conditions must
evaluate as true to be considered a match.
*/
type BindRuleNot struct {
	*aCIBindRuleNot
}

type aCIBindRuleNot struct {
	BindRule
}

/*
Push appends the input instance(s) of [BindRule] to the receiver instance.
*/
func (r BindRuleAnd) Push(x ...any) BindRule {
	if r.IsZero() {
		r = BindRuleAnd{&aCIBindRuleSlice{}}
	}

	var err error
	for i := 0; i < len(x) && err == nil; i++ {
		switch tv := x[i].(type) {
		case string:
			var tkz []aCIBindRuleToken
			if tkz, err = tokenizeACIv3BindRule(tv); err == nil {
				var br BindRule
				if br, err = parseACIv3BindRuleTokens(tkz); err == nil {
					r.aCIBindRuleSlice.slice = append(r.aCIBindRuleSlice.slice, br)
				}
			}
		case BindRule:
			if err = tv.Valid(); err == nil {
				r.aCIBindRuleSlice.slice = append(r.aCIBindRuleSlice.slice, tv)
			}
		}
	}

	return r
}

/*
Push appends the input instance(s) of [BindRule] to the receiver instance.
*/
func (r BindRuleOr) Push(x ...any) BindRule {
	if r.IsZero() {
		r = BindRuleOr{&aCIBindRuleSlice{}}
	}

	var err error
	for i := 0; i < len(x) && err == nil; i++ {
		switch tv := x[i].(type) {
		case string:
			var tkz []aCIBindRuleToken
			if tkz, err = tokenizeACIv3BindRule(tv); err == nil {
				var br BindRule
				if br, err = parseACIv3BindRuleTokens(tkz); err == nil {
					r.aCIBindRuleSlice.slice = append(r.aCIBindRuleSlice.slice, br)
				}
			}
		case BindRule:
			if err = tv.Valid(); err == nil {
				r.aCIBindRuleSlice.slice = append(r.aCIBindRuleSlice.slice, tv)
			}
		}
	}

	return r
}

/*
Push assigns the input instance of [BindRule] to the receiver
instance. Unlike other Push methods, this does not append.
*/
func (r BindRuleNot) Push(x ...any) BindRule {
	if r.aCIBindRuleNot == nil {
		r.aCIBindRuleNot = &aCIBindRuleNot{}
	}

	if len(x) > 0 {
		var err error
		switch tv := x[0].(type) {
		case string:
			var iter int
			var tkz []aCIBindRuleToken
			if tkz, err = tokenizeACIv3BindRule(tv); err == nil {
				var br BindRule
				if br, err = parseACIv3BindRuleGroup(tkz, &iter); err == nil {
					r.aCIBindRuleNot.BindRule = br
				}
			}
		case BindRule:
			k := tv.Kind()
			err = tv.Valid()
			if err == nil && strInSlice(k, []string{`bindRuleAnd`, `bindRuleOr`, `bindRuleItem`}) {
				r.aCIBindRuleNot.BindRule = tv
			}
		}
	}

	return r
}

/*
String returns the string representation of the receiver instance.
*/
func (r BindRuleItem) String() (s string) {
	s = badACIv3BRStr
	if r.IsZero() {
		return s
	}

	// Try to coax a string out of the value.
	var raw string
	switch tv := r.Expression().(type) {
	case BindDistinguishedName:
		raw = tv.string(r.aCIBindRuleItem.mvq, r.aCIBindRuleItem.pad)
	default:
		if meth := getStringer(tv); meth != nil {
			raw = meth()
		} else {
			return s
		}
	}

	if !(strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`)) {
		raw = `"` + raw + `"`
	}

	var pad string
	if r.pad {
		pad = ` `
	}

	s = r.Keyword().String() + pad +
		r.Operator().String() + pad + raw

	if r.paren {
		s = `(` + pad + s + pad + `)`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r BindRuleAnd) String() string {
	return r.aCIBindRuleSlice.aCIBindRuleSliceString("AND")
}

/*
String returns the string representation of the receiver instance.
*/
func (r BindRuleOr) String() string {
	return r.aCIBindRuleSlice.aCIBindRuleSliceString("OR")
}

func (r *aCIBindRuleSlice) aCIBindRuleSliceString(k string) (s string) {
	s = `invalidBindRule` + k
	if r == nil {
		return
	}

	if len(r.slice) > 0 {
		var _s []string
		for i := 0; i < len(r.slice); i++ {
			_s = append(_s, r.slice[i].String())
		}

		var bop string = ` ` + k + ` `
		var pad string
		if r.pad {
			pad = ` `
		}

		s = strings.Join(_s, bop)

		if r.paren {
			s = `(` + pad + s + pad + `)`
		}
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r BindRuleNot) String() (s string) {
	s = `invalidBindRuleNot`
	if r.BindRule != nil {
		s = `NOT ` + r.BindRule.String()
	}

	return
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r BindRuleItem) IsZero() bool {
	return r.aCIBindRuleItem == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r BindRuleAnd) IsZero() bool {
	return r.aCIBindRuleSlice == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r BindRuleOr) IsZero() bool {
	return r.aCIBindRuleSlice == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r BindRuleNot) IsZero() bool {
	return r.aCIBindRuleNot == nil
}

/*
Len returns an integer length of one (1) if the instance has
been initialized, and an integer length of zero (0) if not
initialized.

This method exists solely to satisfy Go's interface signature
requirements and is not necessary to use upon instances of this
type.
*/
func (r BindRuleItem) Len() int {
	var l int
	if &r != nil {
		l++
	}

	return l
}

/*
Len returns the integer length of the receiver instance.
*/
func (r BindRuleAnd) Len() int {
	var l int
	if !r.IsZero() {
		l = len(r.aCIBindRuleSlice.slice)
	}

	return l
}

/*
Len returns the integer length of the receiver instance.
*/
func (r BindRuleOr) Len() int {
	var l int
	if !r.IsZero() {
		l = len(r.aCIBindRuleSlice.slice)
	}

	return l
}

/*
Len returns the integer length of the receiver instance.
*/
func (r BindRuleNot) Len() int {
	var l int
	if r.BindRule != nil {
		l = r.BindRule.Len()
	}

	return l
}

/*
Index returns the Nth underlying slice index, if present.

This type exports this method solely to satisfy Go's interface
signature requirements and is not necessary to use upon instances
of this type. If executed, this method returns the receiver
instance.
*/
func (r BindRuleItem) Index(_ int) BindRule { return r }

/*
Index returns the Nth underlying [BindRule] slice index, if present.
*/
func (r BindRuleAnd) Index(idx int) BindRule {
	var br BindRule = badACIv3BindRule
	if 0 <= idx && idx < r.Len() {
		br = r.aCIBindRuleSlice.slice[idx]
	}

	return br
}

/*
Index returns the Nth underlying [BindRule] slice index, if present.
*/
func (r BindRuleOr) Index(idx int) BindRule {
	var br BindRule = badACIv3BindRule
	if 0 <= idx && idx < r.Len() {
		br = r.aCIBindRuleSlice.slice[idx]
	}

	return br
}

/*
Index returns the Nth underlying [BindRule] slice index, if present.

Note that, in the case of instances of this type, this method is only
meaningful if the underlying [BindRule] qualifier type is an instance
of [BindRuleAnd] or [BindRuleOr].
*/
func (r BindRuleNot) Index(idx int) BindRule {
	var br BindRule = badACIv3BindRule
	if r.BindRule != nil {
		k := r.BindRule.Kind()
		if k == `bindRuleAnd` || k == `bindRuleOr` {
			if 0 <= idx && idx < r.BindRule.Len() {
				br = r.BindRule.Index(idx)
			}
		}
	}

	return br
}

/*
Valid returns an error instance which, when non-nil,
will indicate a logical flaw, such a missing component
of a [BindRuleItem] qualifier, or some other issue.
*/
func (r BindRuleItem) Valid() (err error) {
	if r.IsZero() {
		err = errors.New("Invalid bind rule (ITEM): is zero")
		return
	}

	for _, ok := range []bool{
		r.Keyword() != invalidACIv3BindKeyword,
		r.Operator() != 0x0,

		// TODO:expand on this logic to limit validity
		// to high-level interface qualifiers only, or
		// raw string values.
		r.Expression() != nil,
	} {
		if !ok {
			err = errors.New("Invalid bind rule (ITEM): Missing bindRule keyword, operator or the expr value is bogus")
			break
		}
	}

	return
}

/*
Valid returns an error instance which, when non-nil, will
indicate a flaw in an instance residing at a particular
slice index.
*/
func (r BindRuleAnd) Valid() (err error) {
	if r.IsZero() {
		err = errors.New("Invalid bind rule (AND): is zero")
	} else {
		err = r.aCIBindRuleSlice.Valid()
	}

	return
}

/*
Valid returns an error instance which, when non-nil, will
indicate a flaw in an instance residing at a particular
slice index.
*/
func (r BindRuleOr) Valid() (err error) {
	if r.IsZero() {
		err = errors.New("Invalid bind rule (OR): is zero")
	} else {
		err = r.aCIBindRuleSlice.Valid()
	}

	return
}

/*
Valid returns an error instance which, when non-nil, will
indicate a logical flaw, such as a nil or zero length
[BindRule] instance, a missing component of a [BindRuleItem]
qualifier, or some other issue.
*/
func (r BindRuleNot) Valid() (err error) {
	if r.IsZero() {
		err = errors.New("Invalid bind rule (NOT): is zero")
	} else {
		err = r.BindRule.Valid()
	}

	return
}

/*
Valid is a private method executed by the [BindRuleAnd.Valid]
and [BindRuleOr.Valid] methods.
*/
func (r *aCIBindRuleSlice) Valid() (err error) {
	if len(r.slice) == 0 {
		err = errors.New("slice rule is zero length")
		return
	}
	for idx, rule := range r.slice {
		if err = rule.Valid(); err != nil {
			// Reveal the bogus slice
			// index to the user...
			err = errors.New(err.Error() + " at or nested within bindRule index " +
				strconv.Itoa(idx))
			break
		}
	}

	return
}

/*
BindRule implements an interface qualifier type for instances
of any of the following types:

  - [BindRuleItem]
  - [BindRuleAnd]
  - [BindRuleOr]
  - [BindRuleNot]
*/
type BindRule interface {
	// Kind returns the string literal "bindRuleItem",
	// "bindRuleAnd", "bindRuleOr" or "bindRuleNot"
	// depending on the underlying qualifier type.
	Kind() string

	// String returns the string representation
	// of the receiver instance.
	String() string

	// Len returns the integer length of the receiver
	// instance.

	// Note that if the underlying qualifier type is an
	// instance of [BindRuleItem], an value or zero (0)
	// or one (1) shall always be returned, depending on
	// whether or not the instance is nil.
	Len() int

	// IsZero returns a Boolean value indicative of a
	// nil underlying qualifier type instance.
	IsZero() bool

	// Push appends one (1) or more qualifier type
	// instances of [BindRule] to the receiver instance.
	//
	// Note this only has any meaningful effect if the
	// underlying qualifier type is an instance of
	// [BindRuleAnd] or [BindRuleOr].
	Push(...any) BindRule

	// Index returns the Nth underlying slice value found
	// within the underlying qualifier type instance.
	//
	// Note this only has any meaningful effect if the
	// underlying qualifier type is an instance of
	// [BindRuleAnd] or [BindRuleOr].
	Index(int) BindRule

	// SetParen assigns the input Boolean value to the
	// receiver instance.  A value of true shall serve
	// to encapsulate subsequent string representations
	// in parenthesis characters, namely "(" and ")".
	// A value of false performs no such encapsulation
	// and is the default value.
	SetParen(bool) BindRule

	// SetQuotationStyle controls whether multivalued
	// values of specific types will be individually
	// quoted during string representation. A value of
	// zero (0) results in individually quoted values,
	// while any other value encapsulates all values
	// in a single pair of quotes. Note that this shall
	// only have an effect if there are two (2) or more
	// values present.
	SetQuotationStyle(int) BindRule

	// SetPaddingStyle controls whether whitespace
	// padding is used during string representation. A
	// value of zero (0) disables padding, while any
	// other positive value enables padding.
	SetPaddingStyle(int) BindRule

	// IsParen returns a Boolean value indicative of
	// whether the underlying qualifier type instance
	// is configured to encapsulate subsequent string
	// representations within parenthetical characters.
	IsParen() bool

	// Valid returns an error instance which, when non-nil,
	// will indicate a logical flaw, such as a nil or zero
	// length [BindRule] instance, a missing component of
	// a [BindRuleItem] qualifier, or some other issue.
	Valid() error

	// differentiate from other interface types of a
	// similar design.
	isBindRule()
}

/*
BindRuleMethods contains one (1) or more instances of [BindRuleMethod], representing a particular [BindRule] "builder" method for execution by the caller.

See the Operators method extended through all eligible types for further details.
*/
type BindRuleMethods struct {
	*aCIBindRuleFuncMap
}

/*
newACIv3BindRuleMethods populates an instance of *aCIBindRuleFuncMap, which
is embedded within the return instance of BindRuleMethods.
*/
func newACIv3BindRuleMethods(m aCIBindRuleFuncMap) BindRuleMethods {
	M := make(aCIBindRuleFuncMap, len(m))
	for k, v := range m {
		M[k] = v
	}

	return BindRuleMethods{&M}
}

/*
IsParen returns a Boolean value indicative of the receiver
instance being in a parenthetical state.
*/
func (r BindRuleItem) IsParen() (is bool) {
	if !r.IsZero() {
		is = r.aCIBindRuleItem.paren
	}

	return
}

/*
IsParen returns a Boolean value indicative of the receiver
instance being in a parenthetical state.
*/
func (r BindRuleAnd) IsParen() (is bool) {
	if !r.IsZero() {
		is = r.aCIBindRuleSlice.paren
	}

	return
}

/*
IsParen returns a Boolean value indicative of the receiver
instance being in a parenthetical state.
*/
func (r BindRuleOr) IsParen() (is bool) {
	if !r.IsZero() {
		is = r.aCIBindRuleSlice.paren
	}

	return
}

/*
IsParen returns a Boolean value indicative of the receiver
instance being in a parenthetical state.
*/
func (r BindRuleNot) IsParen() (is bool) {
	if !r.IsZero() {
		is = r.aCIBindRuleNot.BindRule.IsParen()
	}

	return
}

/*
SetParen declares whether the receiver instance is parenthetical.

A value of true engages parenthetical encapsulation during the
string representation process.
*/
func (r BindRuleItem) SetParen(p bool) BindRule {
	if !r.IsZero() {
		r.aCIBindRuleItem.paren = p
	}

	return r
}

/*
SetParen declares whether the receiver instance is parenthetical.

A value of true engages parenthetical encapsulation during the
string representation process.
*/
func (r BindRuleAnd) SetParen(p bool) BindRule {
	if !r.IsZero() {
		r.aCIBindRuleSlice.paren = p
	}

	return r
}

/*
SetParen declares whether the receiver instance is parenthetical.

A value of true engages parenthetical encapsulation during the
string representation process.
*/
func (r BindRuleOr) SetParen(p bool) BindRule {
	if !r.IsZero() {
		r.aCIBindRuleSlice.paren = p
	}

	return r
}

/*
SetParen declares whether the receiver instance is parenthetical.

A value of true engages parenthetical encapsulation during the
string representation process.
*/
func (r BindRuleNot) SetParen(p bool) BindRule {
	if !r.IsZero() {
		r.aCIBindRuleNot.BindRule.IsParen()
	}

	return r
}

/*
Index calls the input index (idx) within the internal structure of the receiver instance. If found, an instance of [Operator] and its accompanying [BindRuleMethod] instance are returned.

Valid input index types are integer (int), [Operator] constant or string identifier. In the case of a string identifier, valid values are as follows:

  - For [Eq] (1): `=`, `Eq`, `Equal To`
  - For [Ne] (2): `!=`, `Ne`, `Not Equal To`
  - For [Lt] (3): `>`, `Lt`, `Less Than`
  - For [Le] (4): `>=`, `Le`, `Less Than Or Equal`
  - For [Gt] (5): `<`, `Gt`, `Greater Than`
  - For [Ge] (6): `<=`, `Ge`, `Greater Than Or Equal`

Case is not significant in the string matching process.

Please note that use of this method by way of integer or [Operator] values utilizes fewer resources than a string lookup.

See the [Operator.Context], [Operator.String] and [Operator.Description] methods for accessing the above string values easily.

If the index was not matched, an invalid [Operator] is returned alongside a nil [BindRuleMethod]. This will also apply to situations in which the type instance which crafted the receiver is uninitialized, or is in an otherwise aberrant state.
*/
func (r BindRuleMethods) Index(idx any) (Operator, BindRuleMethod) {
	return r.index(idx)
}

/*
index is a private method called by BindRuleMethods.Index.
*/
func (r BindRuleMethods) index(idx any) (cop Operator, meth BindRuleMethod) {
	if r.IsZero() {
		return
	}
	cop = invalidCop

	// perform a type switch upon the input
	// index type
	switch tv := idx.(type) {

	case Operator:
		// cast cop as an int, and make recursive
		// call to this function.
		return r.Index(int(tv))

	case int:
		var found bool
		if meth, found = (*r.aCIBindRuleFuncMap)[Operator(tv)]; found {
			cop = Operator(tv)
			return
		}

	case string:
		cop, meth = rangeBindRuleFuncMap(tv, r.aCIBindRuleFuncMap)
	}

	return
}

func rangeBindRuleFuncMap(candidate string, fm *aCIBindRuleFuncMap) (cop Operator, meth BindRuleMethod) {
	// iterate all map entries, and see if
	// input string value matches the value
	// returned by these three (3) methods:
	for k, v := range *fm {
		if strInSlice(candidate, []string{
			k.String(),      // e.g.: "="
			k.Context(),     // e.g.: "Eq"
			k.Description(), // e.g.: "Equal To"
		}) {
			cop = k
			meth = v
			break
		}
	}

	return
}

/*
NewBindDistinguishedName returns an instance of [BindDistinguishedName] alongside an error
following an attempt to marshal the input arguments.

If no arguments are provided, a bogus instance is returned.

The first argument must be a single [BindKeyword], which MUST be one of [BindUDN],
[BindGDN] or [BindRDN].

All subsequent arguments must be string-based DNs, which may or may not include wildcard or
substring patterns

The ACIv3-required prefix of "ldap:///" need not be specified.
*/
func NewBindDistinguishedName(x ...any) (BindDistinguishedName, error) {
	return marshalACIv3BindDistinguishedName(x...)
}

func marshalACIv3BindDistinguishedName(x ...any) (bdn BindDistinguishedName, err error) {
	var bkw BindKeyword

	kwOK := func(bkw BindKeyword) error {
		var err error
		if !aCIKeywordIn(bkw, BindUDN, BindGDN, BindRDN) {
			err = badACIv3KWErr
		}
		return err
	}

	switch len(x) {
	case 0:
	default:
		switch tv := x[0].(type) {
		case string:
			bkw = matchBKW(tv)
		case BindKeyword:
			bkw = tv
		}

		if err = kwOK(bkw); err == nil {
			bdn.BindKeyword = bkw
			bdn.aCIDistinguishedName = &aCIDistinguishedName{}
			if len(x) > 1 {
				err = bdn.aCIDistinguishedName.push(x[1:]...)
			}
		}
	}

	return bdn, err
}

/*
NewTargetDistinguishedName returns an instance of [TargetDistinguishedName] alongside an error
following an attempt to marshal the input arguments.

If no arguments are provided, a bogus instance is returned.

The first argument must be a single [TargetKeyword] or its string equivalent, which MUST be
one of [Target], [TargetTo] or [TargetFrom].

All subsequent arguments must be string-based DNs, which may or may not include wildcard or
substring patterns.

The ACIv3-required prefix of "ldap:///" need not be specified.
*/
func NewTargetDistinguishedName(x ...any) (TargetDistinguishedName, error) {
	return marshalACIv3TargetDistinguishedName(x...)
}

func marshalACIv3TargetDistinguishedName(x ...any) (tdn TargetDistinguishedName, err error) {
	var tkw TargetKeyword

	kwOK := func(tkw TargetKeyword) (err error) {
		if !aCIKeywordIn(tkw, Target, TargetTo, TargetFrom) {
			err = badACIv3KWErr
		}
		return err
	}

	switch len(x) {
	case 0:
	default:
		switch tv := x[0].(type) {
		case string:
			tkw = matchTKW(tv)
		case TargetKeyword:
			tkw = tv
		}

		if err = kwOK(tkw); err == nil {
			tdn.TargetKeyword = tkw
			tdn.aCIDistinguishedName = &aCIDistinguishedName{}
			if len(x) > 1 {
				err = tdn.aCIDistinguishedName.push(x[1:]...)
			}
		}
	}

	return tdn, err
}

/*
NewAttribute returns an instance of [Attribute] alongside an error following an
attempt to parse x into one (1) or more attribute type OIDs, whether as numeric or
descriptor values.
*/
func NewAttribute(x ...any) (Attribute, error) {
	return marshalACIv3Attribute(x...)
}

func marshalACIv3Attribute(x ...any) (Attribute, error) {
	var at Attribute = Attribute{&aCIAttribute{}}
	err := at.push(x...)
	return at, err
}

/*
NewBindRuleAnd returns an instance of [BindRule], qualified via an underlying
[BindRuleAnd] instance.

Zero (0) or more [BindRule] qualifier type instances may be input
for immediate addition to the return value.
*/
func NewBindRuleAnd(x ...any) (BindRule, error) {
	br := BindRuleAnd{&aCIBindRuleSlice{}}
	return br.Push(x...), nil
}

/*
NewBindRuleOr returns an instance of [BindRule], qualified via an underlying
[BindRuleOr] instance.

Zero (0) or more [BindRule] qualifier type instances may be input
for immediate addition to the return value.
*/
func NewBindRuleOr(x ...any) (BindRule, error) {
	br := BindRuleOr{&aCIBindRuleSlice{}}
	return br.Push(x...), nil
}

/*
NewBindRuleNot returns a negated instance of [BindRule], qualified via an
underlying [BindRuleNot] instance.

Note that up to one (1) [BindRule] qualifier type instance may be set
within instances of this type. An instance of [BindRuleNot] is ineligible
for assignment.
*/
func NewBindRuleNot(x ...any) (BindRule, error) {
	return BindRuleNot{newACIv3BindRuleNot(x...)}, nil
}

func newACIv3BindRuleNot(x ...any) (r *aCIBindRuleNot) {
	r = &aCIBindRuleNot{}

	if len(x) > 0 {
		switch tv := x[0].(type) {
		case string:
			if tkz, err := tokenizeACIv3BindRule(tv); err == nil {
				var z BindRule
				z, err = parseACIv3BindRuleTokens(tkz)
				if err == nil && z.Kind() != `bindRuleNot` {
					r.BindRule = z
				}
			}
		case BindRule:
			if tv.Kind() != `bindRuleNot` {
				r.BindRule = tv
			}
		}
	}

	return
}

/*
NewBindRuleItem initialized, populates and returns an instance of [BindRule],
qualified by an underlying *[BindRuleItem] instance.
*/
func NewBindRuleItem(x ...any) (BindRule, error) {
	var (
		bri BindRuleItem = BindRuleItem{&aCIBindRuleItem{}}
		err error
	)

	if len(x) > 0 {
		switch tv := x[0].(type) {
		case string:
			err = bri.parse(tv)
		case BindKeyword:
			if matchBKW(tv) != 0x0 {
				if len(x) == 3 {
					if _, ok := x[1].(Operator); !ok {
						err = badACIv3BRErr
					} else {
						return newACIv3BindRuleItem(x[0], x[1], x[2]), err
					}
				}
			}
		default:
			err = badACIv3TRErr
		}
	}

	return bri, err
}

func (r *BindRuleItem) parse(x string) (err error) {
	var tkz []aCIBindRuleToken
	if tkz, err = tokenizeACIv3BindRule(x); len(tkz) >= 3 && err == nil {
		var b BindRule
		if b, err = parseACIv3BindRuleTokens(tkz); err == nil {
			*r, _ = b.(BindRuleItem)
		}
	}

	return err
}

func initACIv3BindRuleItem() BindRuleItem {
	return BindRuleItem{&aCIBindRuleItem{
		Keyword:  invalidACIv3BindKeyword,
		Operator: invalidCop,
	}}
}

func newACIv3BindRuleItem(kw, op any, ex ...any) BindRuleItem {
	return initACIv3BindRuleItem().
		SetKeyword(kw).(BindRuleItem).
		SetOperator(op).(BindRuleItem).
		SetExpression(ex...).(BindRuleItem)
}

/*
SetKeyword assigns [Keyword] kw to the receiver instance.
*/
func (r BindRuleItem) SetKeyword(kw any) BindRule {
	if r.aCIBindRuleItem == nil {
		r.aCIBindRuleItem = initACIv3BindRuleItem().aCIBindRuleItem
	}

	switch tv := kw.(type) {
	case string:
		r.aCIBindRuleItem.Keyword = matchBKW(tv)
	case BindKeyword:
		r.aCIBindRuleItem.Keyword = tv
	}

	return r
}

/*
SetOperator assigns [Operator] op to the receiver
instance.
*/
func (r BindRuleItem) SetOperator(op any) BindRule {
	if r.aCIBindRuleItem == nil {
		r.aCIBindRuleItem = initACIv3BindRuleItem().aCIBindRuleItem
	}

	// assert underlying comparison operator.
	var cop Operator
	switch tv := op.(type) {
	case string:
		cop = matchACIv3Cop(tv)
	case Operator:
		cop = tv
	}

	// For security reasons, only assign comparison
	// operator if it is Eq or Ne.
	if 0x0 < cop && cop <= 0x6 {
		r.aCIBindRuleItem.Operator = cop
	}

	return r
}

/*
SetExpression assigns value expr to the receiver instance.
*/
func (r BindRuleItem) SetExpression(expr ...any) BindRule {
	if r.aCIBindRuleItem == nil {
		r.aCIBindRuleItem = initACIv3BindRuleItem().aCIBindRuleItem
	}

	// Constrain to specific value types per keyword
	if value, err := assertBindValueByKeyword(r.aCIBindRuleItem.Keyword, expr...); err == nil {
		r.aCIBindRuleItem.Expression = value
	}

	return r
}

/*
Contains returns a Boolean value indicative of whether the specified [Operator], which may be expressed as a string, int or native [Operator], is allowed for use by the type instance that created the receiver instance. This method offers a convenient alternative to the use of the Index method combined with an assertion value (such as Eq, Ne, "=", "Greater Than", et al).

In other words, if one uses the [FQDN]'s BRM method to create an instance of [BindRuleMethods], feeding Gt (Greater Than) to this method shall return false, as mathematical comparison does not apply to instances of the [FQDN] type.
*/
func (r BindRuleMethods) Contains(cop any) bool {
	c, _ := r.index(cop)
	return c.Valid() == nil
}

/*
IsZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r BindRuleMethods) IsZero() bool {
	return r.aCIBindRuleFuncMap == nil
}

/*
Valid returns the first encountered error returned as a result of execution of the first available [BindRuleMethod] instance. This is useful in cases where a user wants to see if the desired instance(s) of [BindRuleMethod] will produce a usable result.
*/
func (r BindRuleMethods) Valid() (err error) {
	if r.IsZero() {
		err = nilInstanceErr
		return
	}

	// Eq is always available for all eligible
	// types, so let's use that unconditionally.
	// If any one method works, then all of them
	// will work.
	_, meth := r.Index(Eq)
	err = meth().Valid()
	return
}

/*
Len returns the integer length of the receiver. Note that the return value will NEVER be less than zero (0) nor greater than six (6).
*/
func (r BindRuleMethods) Len() int {
	var l int
	if !r.IsZero() {
		l = len((*r.aCIBindRuleFuncMap))
	}

	return l
}

/*
BindRuleMethod is the closure signature for methods used to build new instances of [BindRule].

The signature is qualified by methods extended through all eligible types defined in this package.

Note that certain types only support a subset of the above list. Very few types support all of the above.
*/
type BindRuleMethod func() BindRule

/*
aCIBindRuleFuncMap is a private type intended to be used within instances of [BindRuleMethods].
*/
type aCIBindRuleFuncMap map[Operator]BindRuleMethod

/*
Keyword returns the [ACIv3BindKeyword] value currently set within the receiver instance.
*/
func (r BindRuleItem) Keyword() BindKeyword {
	var bkw BindKeyword = invalidACIv3BindKeyword
	if &r != nil {
		bkw = r.aCIBindRuleItem.Keyword
	}

	return bkw
}

/*
Operator returns the [Operator] value currently set within the receiver instance.
*/
func (r BindRuleItem) Operator() Operator {
	var cop Operator = invalidCop
	if &r != nil {
		cop = r.aCIBindRuleItem.Operator
	}

	return cop
}

/*
Expression returns the underlying expression value currently set within the receiver instance.
*/
func (r BindRuleItem) Expression() any {
	var val any
	if r.aCIBindRuleItem != nil {
		val = r.aCIBindRuleItem.Expression
	}

	return val
}

/*
NewBindRule returns an instance of [BindRule] alongside an error following an attempt to
parse string x as a qualifying instance of [BindRuleItem], [BindRuleAnd], [BindRuleOr]
or [BindRuleNot].
*/
func NewBindRule(x ...any) (BindRule, error) {
	var (
		br  BindRule
		err error
	)

	if len(x) > 0 {
		switch tv := x[0].(type) {
		case string:
			var tkz []aCIBindRuleToken
			if tkz, err = tokenizeACIv3BindRule(tv); err == nil {
				br, err = parseACIv3BindRuleExpression(tkz)
			}
		}
	}

	return br, err
}

type aCIBindRuleToken struct {
	Type  aCIBindRuleTokenType
	Value string
}

type aCITargetRuleToken struct {
	Type  aCITargetRuleTokenType
	Value string
}

func tokenizeACIv3BindRuleBooleanOperator(input string, tkz []aCIBindRuleToken) []aCIBindRuleToken {
	switch strings.ToUpper(input) {
	case "AND":
		tkz = append(tkz, aCIBindRuleToken{Type: brAnd, Value: input})
	case "OR":
		tkz = append(tkz, aCIBindRuleToken{Type: brOr, Value: input})
	case "NOT":
		tkz = append(tkz, aCIBindRuleToken{Type: brNot, Value: input})
	default:
		tkz = append(tkz, aCIBindRuleToken{Type: brValue, Value: input})
	}

	return tkz
}

/*
tokenizeACIv3BindRule tokenizes input into slices of aCIBindRuleToken.
*/
func tokenizeACIv3BindRule(input string) (tkz []aCIBindRuleToken, err error) {
	var tokens []aCIBindRuleToken
	bld := &strings.Builder{}

	flush := func() {
		if bld.Len() > 0 {
			tokens = append(tokens, tokenizeACIv3BindRuleBooleanOperator(bld.String(), tkz)...)
			bld.Reset()
		}
	}

	for i := 0; i < len(input); i++ {
		ch := input[i]
		switch ch {
		case '"':
			flush() // finish any pending token
			i++     // skip the starting quote
			for ; i < len(input) && input[i] != '"'; i++ {
				bld.WriteByte(input[i])
			}
			tokens = append(tokens, aCIBindRuleToken{Type: brValue, Value: bld.String()})
			bld.Reset()
		case '(':
			flush()
			tokens = append(tokens, aCIBindRuleToken{Type: brParenOpen, Value: "("})
		case ')':
			flush()
			tokens = append(tokens, aCIBindRuleToken{Type: brParenClose, Value: ")"})
		default:
			if isWHSP(rune(ch)) {
				flush()
			} else if ch == '=' {
				flush()
				bld.WriteByte(ch)
			} else if runeInSlice(rune(ch), []rune{'>', '<', '!'}) {
				flush()
				bld.WriteByte(ch)
				// If the next character is '=' then include it.
				if i+1 < len(input) && input[i+1] == '=' {
					bld.WriteByte(input[i+1])
					i++
				}
			} else {
				bld.WriteByte(ch)
			}
		}
	}
	flush()

	tkz, err = combineACIv3BindRuleTokens(tokens)

	return
}

func combineACIv3BindRuleTokens(tokens []aCIBindRuleToken) (combined []aCIBindRuleToken, err error) {
	// Combine "AND" immediately followed by "NOT" into a single operator token.
	for i := 0; i < len(tokens); {
		if tokens[i].Type == brAnd && i+1 < len(tokens) && tokens[i+1].Type == brNot {
			combined = append(combined, aCIBindRuleToken{Type: brNot, Value: "AND NOT"})
			i += 2 // 1 extra for "NOT"
		} else {
			combined = append(combined, tokens[i])
			i++
		}
	}

	// Ensure none of the tokens are empty, which would
	// almost certainly indicate a tokenization error of
	// bogus input.
	for _, tk := range combined {
		if tk.Value == "" {
			err = badACIv3BRTokenErr
			break
		}
	}

	return combined, err
}

/*
NewTargetRule returns an instance of [TargetRule] alongside an error following an attempt to
parse raw as one (1) or more instance of [TargetRuleItem].
*/
func NewTargetRule(x ...any) (TargetRule, error) {
	var (
		tr  TargetRule = TargetRule{&aCITargetRule{}}
		err error
	)

	if len(x) > 0 {
		tr.Push(x...)
	}

	return tr, err
}

func (r *TargetRule) parse(x string) (err error) {

	var tkz []aCITargetRuleToken
	if tkz, err = tokenizeACIv3TargetRule(x); err != nil {
		return
	} else if len(tkz) < 5 {
		err = errors.New("unexpected number of tokens; any number of targetRuleItem tokens MUST ALWAYS be 5 <=")
		return
	}

	// Iterate targetRuleItem instances in token
	// groups of five (5):
	//
	// 1 - Open Paren "("
	// 2 - Keyword
	// 3 - Operator
	// 4 - Value(s)
	// 5 - Closing Paren ")"
	for len(tkz) >= 5 && err == nil {
		if tkz[0].Type == trParenOpen &&
			tkz[1].Type == trKeyword &&
			tkz[2].Type == trOperator {
			var ex []any
			var i int
			for i = 3; i < len(tkz); i++ {
				if typ := tkz[i].Type; typ != trParenClose {
					if typ == trValue {
						ex = append(ex, tkz[i].Value)
					}
				} else {
					break
				}
			}
			var item TargetRuleItem
			if item, err = newACIv3TargetRuleItem(tkz[1].Value, tkz[2].Value, ex...); err == nil {
				tkz = tkz[i+1:]
				r.Push(item)
			}
		}
	}

	return err
}

func processACIv3TargetRuleItem(tkz []aCITargetRuleToken) (r TargetRuleItem, err error) {
	r = badACIv3TargetRuleItem
	if l := len(tkz); l < 5 {
		err = errors.New("unexpected number of tokens; want 5 or more, got " + strconv.Itoa(l))
		return
	}

	if tkz[0].Value != "(" || tkz[4].Value != ")" {
		err = errors.New("Missing targetRuleItem parenthesis")
		return
	}

	kw := matchTKW(tkz[1].Value)
	if kw == 0x0 {
		err = badACIv3KWErr
		return
	}

	op := matchACIv3Cop(tkz[2].Value)
	if !(0 < op && op <= 2) {
		err = badACIv3CopErr
		return
	}

	// TODO: check types per keyword
	if r, err = newACIv3TargetRuleItem(kw, op, tkz[3].Value); err == nil {
		err = r.Valid()
	}

	return
}

func tokenizeACIv3TargetRule(input string) (tkz []aCITargetRuleToken, err error) {
	i := 0
	length := len(input)
	if length == 0 {
		err = badACIv3TRErr
		return
	}

	for i < length && err == nil {
		// Skip any whitespace (spaces, tabs, etc.). These are insignificant.
		for i < length && unicode.IsSpace(rune(input[i])) {
			i++
		}

		ch := input[i]
		switch ch {
		case '(':
			tkz = append(tkz, aCITargetRuleToken{Type: trParenOpen, Value: "("})
			i++
		case ')':
			tkz = append(tkz, aCITargetRuleToken{Type: trParenClose, Value: ")"})
			i++
		case '=':
			tkz = append(tkz, aCITargetRuleToken{Type: trOperator, Value: "="})
			i++
		case '!':
			// For "!=" operator, the '!' must be immediately followed by '='.
			if i+1 < length && input[i+1] == '=' {
				tkz = append(tkz, aCITargetRuleToken{Type: trOperator, Value: "!="})
				i += 2
			} else {
				err = errors.New("targetRule unexpected token '!' without '=' following")
			}
		case '"':
			// Parse a quoted string literal.
			tkz, i, err = tokenizeTargetRuleQuotedValue(i, length, input, tkz)
		case '|':
			// Process the keyword, which is never quoted, and purely lower alphabetical
			tkz, i, err = tokenizeACIv3TargetRuleMultival(i, length, input, tkz)
		default:
			// Process the keyword, which is never quoted, and purely lower alphabetical
			tkz, i, err = tokenizeACIv3TargetRuleKeyword(ch, i, length, input, tkz)
		}
	}

	return tkz, nil
}

func tokenizeACIv3TargetRuleMultival(i, l int, input string, tkz []aCITargetRuleToken) ([]aCITargetRuleToken, int, error) {
	var err error
	if i+1 < l && input[i+1] == '|' {
		tkz = append(tkz, aCITargetRuleToken{Type: trDelim, Value: "||"})
		i += 2
	} else {
		err = errors.New("targetRule expected '||' for value delimiter, got single '|'")
	}

	return tkz, i, err
}

func tokenizeACIv3TargetRuleKeyword(ch byte, i, l int, input string, tkz []aCITargetRuleToken) ([]aCITargetRuleToken, int, error) {
	// Process the key, which is never quoted, and purely alphabetical
	var err error
	if isAlpha(rune(ch)) {
		start := i
		for i < l && isAlpha(rune(input[i])) {
			i++
		}
		identifier := input[start:i]
		tkz = append(tkz, aCITargetRuleToken{Type: trKeyword, Value: identifier})
	} else {
		err = errors.New("targetRule unexpected character '" + string(ch) +
			"' at position " + strconv.Itoa(i))
	}

	return tkz, i, err
}

func tokenizeTargetRuleQuotedValue(i, l int, input string, tkz []aCITargetRuleToken) ([]aCITargetRuleToken, int, error) {
	i++ // skip the opening quote
	sb := &strings.Builder{}
	var err error
	for i < l {
		if input[i] == '"' {
			// Found the closing quote.
			i++ // consume the closing quote and break.
			break
		}
		sb.WriteByte(input[i])
		i++
	}
	tkz = append(tkz, aCITargetRuleToken{Type: trValue, Value: sb.String()})
	return tkz, i, err
}

func processACIv3BindRule(tokens []aCIBindRuleToken, pos *int) (BindRule, error) {
	if *pos >= len(tokens) {
		return nil, errors.New("unexpected end of tokens")
	}

	// If a parenthesized group is encountered, defer to the group parser.
	if tokens[*pos].Type == brParenOpen {
		return parseACIv3BindRuleGroup(tokens, pos)
	}

	// Otherwise, join all adjacent value tokens.
	var parts []string
	for *pos < len(tokens) && tokens[*pos].Type == brValue {
		parts = append(parts, tokens[*pos].Value)
		*pos++
	}
	joined := strings.Join(parts, " ")
	operators := []string{"<=", ">=", "!=", "=", "<", ">"}
	for _, op := range operators {
		if idx := strings.Index(joined, op); idx != -1 {
			bkw := matchBKW(strings.TrimSpace(joined[:idx]))
			cop := matchACIv3Cop(strings.TrimSpace(joined[idx : idx+len(op)]))
			valueStr := strings.TrimSpace(joined[idx+len(op):])
			if val, err := assertBindValueByKeyword(bkw, valueStr); err == nil {
				rule := newACIv3BindRuleItem(bkw, cop, val)
				return rule.SetParen(false), rule.Valid()
			} else {
				return nil, err
			}
		}
	}
	return badACIv3BindRule, nil
}

func assertBindValueByKeyword(bkw BindKeyword, raw ...any) (value any, err error) {
	if len(raw) == 0 {
		err = badACIv3BRExprErr
		return
	}

	switch bkw {
	case BindUDN, BindGDN, BindRDN:
		arg := append([]any{bkw}, raw...)
		value, err = marshalACIv3BindDistinguishedName(arg...)
	case BindUAT, BindGAT:
		value, err = assertBindAT(bkw, raw...)
	case BindDNS:
		value, err = marshalACIv3FQDN(raw...)
	case BindDoW:
		value, err = marshalACIv3DayOfWeek(raw...)
	case BindToD:
		value, err = marshalACIv3TimeOfDay(raw...)
	case BindSSF:
		value, err = marshalACIv3SecurityStrengthFactor(raw...)
	case BindAM:
		value, err = marshalACIv3AuthenticationMethod(raw...)
	case BindIP:
		value, err = marshalACIv3IPAddress(raw...)
	}

	if err == nil && value == nil {
		err = nilInstanceErr
	}

	return
}

func assertBindAT(bkw BindKeyword, raw ...any) (value any, err error) {
	switch tv := raw[0].(type) {
	case string:
		if strings.Contains(tv, `[`) {
			value, err = marshalACIv3Inheritance(raw...)
		} else {
			value, err = marshalACIv3AttributeBindTypeOrValue(append([]any{bkw}, raw...)...)
		}
	case Inheritance:
		value = tv
		err = tv.Valid()
	case AttributeBindTypeOrValue:
		value = tv
		err = tv.Valid()
	}

	return
}

func assertTargetValueByKeyword(tkw TargetKeyword, raw ...any) (value any, err error) {
	if len(raw) == 0 {
		err = nilInputErr
		return
	}

	switch tkw {
	case Target, TargetTo, TargetFrom:
		arg := append([]any{tkw}, raw...)
		value, err = marshalACIv3TargetDistinguishedName(arg...)
	case TargetCtrl, TargetExtOp:
		//arg := append([]any{tkw}, raw...)
		value, err = marshalACIv3ObjectIdentifier(tkw, raw...)
	case TargetAttr:
		value, err = assertTargetRuleAttribute(raw...)
	case TargetAttrFilters:
		switch raw[0].(type) {
		case AttributeFilterOperation:
			value, err = marshalACIv3AttributeFilterOperation(raw...)
		case AttributeFilterOperationItem:
			value, err = marshalACIv3AttributeFilterOperationItem(raw...)
		}
	case TargetFilter:
		if len(raw) > 0 {
			value, err = filter.New(raw[0])
		}
	case TargetScope:
		value, err = marshalACIv3SearchScope(raw...)
	}

	if err == nil && value == nil {
		err = nilInstanceErr
	}

	return
}

func assertTargetRuleAttribute(raw ...any) (value any, err error) {
	switch tv := raw[0].(type) {
	case string:
		if strings.Contains(tv, `#`) {
			value, err = marshalACIv3AttributeBindTypeOrValue(raw...)
		} else {
			value, err = marshalACIv3Attribute(raw...)
		}
	case Attribute:
		value = tv
		err = tv.Valid()
	case AttributeBindTypeOrValue:
		value = tv
		err = tv.Valid()
	}

	return
}

func parseACIv3BindRuleGroup(tokens []aCIBindRuleToken, pos *int) (BindRule, error) {
	if tokens[*pos].Type != brParenOpen {
		return nil, errors.New("expected '(' but got " + tokens[*pos].Value)
	}
	*pos++ // skip '('

	// Process the first operand.
	operand, err := processACIv3BindRule(tokens, pos)
	if err != nil {
		return nil, err
	}
	operands := []BindRule{operand}
	var operators []aCIBindRuleTokenType

	// Parse remaining tokens until a closing parenthesis is reached.
	for *pos < len(tokens) && tokens[*pos].Type != brParenClose {
		if !tokens[*pos].Type.isBooleanOperator() {
			return nil, errors.New("expected boolean operator but got " + tokens[*pos].Value)
		}
		operators = append(operators, tokens[*pos].Type)
		*pos++
		nextOperand, err := processACIv3BindRule(tokens, pos)
		if err != nil {
			return nil, err
		}
		operands = append(operands, nextOperand)
	}
	if *pos >= len(tokens) || tokens[*pos].Type != brParenClose {
		return nil, errors.New("expected closing parenthesis")
	}
	*pos++ // skip closing parenthesis

	// Decide which kind of boolean grouping to use.
	if len(operators) == 0 {
		return operands[0].SetParen(true), nil
	}

	var allAnd, allOr bool
	var r BindRule

	if allAnd, allOr, err = getAndOrBool(operators); allOr {
		r = BindRuleOr{&aCIBindRuleSlice{slice: operands, paren: true}}
	} else if allAnd {
		// In an AND group, any brNot wraps the corresponding operand.
		var newOperands []BindRule
		newOperands = append(newOperands, operands[0])
		for idx, op := range operators {
			if op == brNot {
				not := BindRuleNot{newACIv3BindRuleNot(operands[idx+1])}
				newOperands = append(newOperands, not)
			} else {
				newOperands = append(newOperands, operands[idx+1])
			}
		}
		r = BindRuleAnd{&aCIBindRuleSlice{slice: newOperands, paren: true}}
	}

	return r, err
}

func parseACIv3BindRuleExpression(tokens []aCIBindRuleToken) (BindRule, error) {
	pos := 0
	// We require at least three (3) tokens
	if len(tokens) < 3 {
		return nil, errors.New("incomplete bind rule expression")
	}
	left, err := processACIv3BindRule(tokens, &pos)
	if err != nil {
		return nil, err
	}
	operands := []BindRule{left}
	var operators []aCIBindRuleTokenType

	// Process top-level operator-operand pairs.
	for pos < len(tokens) {
		if !tokens[pos].Type.isBooleanOperator() {
			return nil, errors.New("unexpected token encountered at top level: " + tokens[pos].Value)
		}
		operators = append(operators, tokens[pos].Type)
		pos++
		nextOperand, err := processACIv3BindRule(tokens, &pos)
		if err != nil {
			return nil, err
		}
		operands = append(operands, nextOperand)
	}

	var allAnd, allOr bool
	var r BindRule

	if allAnd, allOr, err = getAndOrBool(operators); allOr {
		r = BindRuleOr{&aCIBindRuleSlice{slice: operands}}
	} else if allAnd {
		// In an AND group, any brNot wraps the corresponding operand.
		var newOperands []BindRule
		newOperands = append(newOperands, operands[0])
		for idx, op := range operators {
			if op == brNot {
				not := BindRuleNot{newACIv3BindRuleNot(operands[idx+1])}
				newOperands = append(newOperands, not)
			} else {
				newOperands = append(newOperands, operands[idx+1])
			}
		}
		r = BindRuleAnd{&aCIBindRuleSlice{slice: newOperands}}
	}

	return r, err
}

func getAndOrBool(operators []aCIBindRuleTokenType) (allAnd, allOr bool, err error) {
	allOr, allAnd = true, true
	for _, op := range operators {
		if op != brOr {
			allOr = false
		}
		if op != brAnd && op != brNot {
			allAnd = false
		}
	}

	if !allAnd && !allOr {
		err = errors.New("mixed operators at top level are not supported")
	}

	return
}

func parseACIv3BindRuleTokens(tokens []aCIBindRuleToken) (rule BindRule, err error) {
	pos := 0
	rule, err = processACIv3BindRule(tokens, &pos)
	if pos != len(tokens) {
		err = errors.New("extra tokens remain after parsing")
	}

	return
}

func newDoW() DayOfWeek {
	return DayOfWeek(shifty.New(shifty.Uint8))
}

func newLvls() *aCILevels {
	l := aCILevels(shifty.New(shifty.Uint16))
	return &l
}

func newRights() *aCIRights {
	r := aCIRights(shifty.New(shifty.Uint16))
	return &r
}

func (r DayOfWeek) cast() shifty.BitValue {
	return shifty.BitValue(r)
}

func (r aCILevels) cast() shifty.BitValue {
	return shifty.BitValue(r)
}

func (r aCIRights) cast() shifty.BitValue {
	return shifty.BitValue(r)
}

type (
	// [DayOfWeek] is a type alias of [shifty.BitValue], and is used
	// to construct a dayofweek [BindRule].
	DayOfWeek shifty.BitValue // 8-bit

	// rights is a private type alias of shifty.BitValue, and is
	// used in the construction of an instance of [Permission].
	aCIRights shifty.BitValue // 16-bit

	// levels is a private type alias of shifty.BitValue, and is
	// used in the construction of an inheritance-based userattr
	// or groupattr BindRule by embedding.
	aCILevels shifty.BitValue // 16-bit

)

/*
Inheritance describes an inherited [BindRule] syntax, allowing access control over child entry enumeration below the specified parent.
*/
type Inheritance struct {
	AttributeBindTypeOrValue
	*aCILevels
}

/*
NewInheritance creates a new instance of [Inheritance] bearing the provided [AttributeBindTypeOrValue] instance, as well as zero (0) or more [Level] instances for shifting.
*/
func NewInheritance(x ...any) (Inheritance, error) {
	return marshalACIv3Inheritance(x...)
}

func marshalACIv3Inheritance(x ...any) (r Inheritance, err error) {
	switch len(x) {
	case 0:
		err = nilInstanceErr
	case 1:
		switch tv := x[0].(type) {
		case string:
			err = r.parse(tv)
		case Inheritance:
			if err = tv.Valid(); err == nil {
				r = tv
			}
		default:
			err = badACIv3InhErr
		}
	default:
		switch tv := x[0].(type) {
		case string:
			var atb AttributeBindTypeOrValue
			atb, err = marshalACIv3AttributeBindTypeOrValue(tv)
			if err == nil {
				r.AttributeBindTypeOrValue = atb
				r.aCILevels = newLvls()
				r.Shift(x[1:]...)
			}
		case AttributeBindTypeOrValue:
			if err = tv.Valid(); err == nil {
				r.AttributeBindTypeOrValue = tv
				r.aCILevels = newLvls()
				r.Shift(x[1:]...)
			}
		default:
			err = badACIv3InhErr
		}
	}

	return
}

/*
InheritanceLevel describes a discrete numerical abstract of a single subordinate level. [InheritanceLevel] describes any single [InheritanceLevel] definition. [InheritanceLevel] constants are intended for "storage" within an instance of [Inheritance].

Valid [InheritanceLevel] constants are level zero (0) through level nine (9), though the supported range will vary across directory implementations.
*/
type InheritanceLevel uint16

/*
IsZero returns a Boolean value indicative of whether the receiver instance is nil, or unset.
*/
func (r Inheritance) IsZero() bool {
	return r.AttributeBindTypeOrValue.IsZero() && r.aCILevels == nil
}

/*
Valid returns an error indicative of whether the receiver is in an aberrant state.
*/
func (r Inheritance) Valid() (err error) {
	if r.IsZero() {
		err = nilInstanceErr
	} else if r.AttributeBindTypeOrValue.IsZero() || r.Len() > 10 {
		err = badACIv3InheritanceLevelErr
	}

	return
}

/*
BRM returns an instance of [BindRuleMethods].

Each of the return instance's key values represent a single instance of the [Operator] type that is allowed for use in the creation of [BindRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [BindRuleMethod] instance for OPTIONAL use in the creation of a [BindRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [BindRule] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r Inheritance) BRM() BindRuleMethods {
	return newACIv3BindRuleMethods(aCIBindRuleFuncMap{
		Eq: r.Eq,
		Ne: r.Ne,
	})
}

/*
Eq initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Equal-To the [BindUAT] or [BindGAT] [BindKeyword] contexts.
*/
func (r Inheritance) Eq() (b BindRule) {
	if err := r.Valid(); err == nil {
		b = newACIv3BindRuleItem(r.AttributeBindTypeOrValue.
			BindKeyword, Eq, r)
	}
	return
}

/*
Ne initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Not-Equal-To the [BindUAT] or [BindGAT] [BindKeyword] contexts.

Negated equality [BindRule] instances should be used with caution.
*/
func (r Inheritance) Ne() (b BindRule) {
	if err := r.Valid(); err == nil {
		b = newACIv3BindRuleItem(r.AttributeBindTypeOrValue.
			BindKeyword, Ne, r)
	}
	return
}

/*
parseACIv3Inheritance is a private function that reads the input string (inh) and attempts to marshal its contents into an instance of Inheritance (I), which is returned alongside an error (err).

This function is called during the bind rule parsing phase if and when an inheritance-related userattr/groupattr rule is encountered.
*/
func (r *Inheritance) parse(inh string) (err error) {
	// Bail out immediately if the prefix is
	// non conformant.
	if !strings.HasPrefix(strings.ToLower(inh), `parent[`) {
		err = badACIv3InhErr
		return
	}

	// chop off the 'parent[' prefix; we don't need
	// to preserve it following the presence check.
	raw := inh[7:]

	// Grab the sequence of level identifiers up to
	// and NOT including the right (closing) bracket.
	// The integer index (idx) marks the boundary of
	// the identifier sequence.
	idx := strings.IndexRune(raw, ']')
	if idx == -1 {
		err = badACIv3InhErr
		return
	}

	// make sure the dot delimiter
	// comes immediately after the
	// closing square bracket.
	if raw[idx+1] != '.' {
		err = badACIv3InhErr
		return
	}

	// Initialize our return instance, as we're about
	// to begin storing things in it.
	r.aCILevels = newLvls()

	// Iterate the split sequence of level identifiers.
	// Also, obliterate any ASCII #32 (SPACE) chars
	// (e.g.: ', ' -> ',').
	X := strings.Split(strings.ReplaceAll(raw[:idx], ` `, ``), `,`)
	for _, s := range X {
		r.Shift(s)
	}

	// Bail if nothing was found (do not fall
	// back to default when parsing).
	if r.aCILevels.cast().Int() == 0 {
		// bogus or unsupported identifiers?
		err = missingACIv3LvlsErr
		return
	}

	// Call our AttributeBindTypeOrValue parser
	// and marshal a new instance to finish up.
	// At this phase, we begin value parsing
	// one (1) character after the identifier
	// boundary (see above).
	var abv AttributeBindTypeOrValue

	if abv, err = parseATBTV(raw[idx+2:]); err == nil {
		r.AttributeBindTypeOrValue = abv
	}

	return
}

/*
Len returns the abstract integer length of the receiver, quantifying the number of [InheritanceLevel] instances currently being expressed.

For example, if the receiver instance has its [Level1] and [Level5] bits enabled, this would represent an abstract length of two (2).
*/
func (r Inheritance) Len() int {
	var D int
	for i := 0; i < aCILevelBitIter; i++ {
		if d := InheritanceLevel(1 << i); r.Positive(d) {
			D++
		}
	}

	return D
}

/*
Keyword returns the [BindKeyword] associated with the receiver instance enveloped as a [Keyword]. In the context of this type instance, the [BindKeyword] returned will be either [BindUAT] or [BindGAT].
*/
func (r Inheritance) Keyword() (kw Keyword) {
	if err := r.Valid(); err != nil {
		return nil
	}

	k := r.AttributeBindTypeOrValue.BindKeyword
	switch k {
	case BindGAT, BindUAT:
		kw = k
	}

	return
}

/*
String returns the string name value for receiver instance.

The return value(s) are enclosed within square-brackets, followed by comma delimitation and are prefixed with "parent" before being returned.
*/
func (r Inheritance) String() (s string) {
	s = badACIv3InhStr
	if err := r.Valid(); err == nil {
		lvls := r.aCILevels.string()
		s = "parent[" + lvls + "]." + r.AttributeBindTypeOrValue.String()
	}
	return
}

/*
String is a string method that returns the string representation of the receiver instance.
*/
func (r aCILevels) string() string {
	var levels []string
	if r.cast().Int() > 0 {
		for i := 0; i < aCILevelBitIter; i++ {
			if shift := InheritanceLevel(1 << i); r.cast().Positive(shift) {
				levels = append(levels, shift.String())
			}
		}
	}

	return strings.Join(levels, `,`)
}

/*
String returns a single string name value for receiver instance of [Level].
*/
func (r InheritanceLevel) String() (lvl string) {
	for k, v := range aCILevelNumbers {
		if r == v {
			lvl = k
			break
		}
	}

	return
}

/*
Shift wraps the [shifty.BitValue.Shift] method.
*/
func (r Inheritance) Shift(x ...any) Inheritance {
	if r.aCILevels == nil {
		r.aCILevels = newLvls()
	}

	for i := 0; i < len(x); i++ {
		var lvl InheritanceLevel
		switch tv := x[i].(type) {
		case InheritanceLevel:
			lvl = tv
		case int:
			lvl = assertIntInheritance(tv)
		case string:
			lvl = assertStrInheritance(tv)
		}
		r.aCILevels.cast().Shift(lvl)
	}

	return r
}

/*
assertStrInheritance returns the appropriate [Level] instance logically associated with the string value (x) input by the user. Valid levels are zero (0) through four (4), else invalidACIv3InheritanceLevel is returned.
*/
func assertStrInheritance(x string) (lvl InheritanceLevel) {
	for k, v := range aCILevelNumbers {
		if x == k {
			lvl = v
			break
		}
	}

	return
}

/*
assertIntInheritance returns the appropriate Level instance logically associated with the integer value (x) input by the user. Valid levels are zero (0) through four (4), else invalidACIv3InheritanceLevel is returned.
*/
func assertIntInheritance(x int) (lvl InheritanceLevel) {
	if L, found := aCILevelMap[x]; found {
		lvl = L
	}

	return
}

/*
Positive wraps the [shifty.BitValue.Positive] method.
*/
func (r Inheritance) Positive(x any) (posi bool) {
	if !r.IsZero() {
		var lvl InheritanceLevel

		switch tv := x.(type) {
		case InheritanceLevel:
			lvl = tv
		case int:
			lvl = assertIntInheritance(tv)
		case string:
			lvl = assertStrInheritance(tv)
		}
		posi = r.aCILevels.cast().Positive(lvl)
	}

	return
}

/*
Unshift wraps the [shifty.BitValue.Unshift] method.
*/
func (r Inheritance) Unshift(x ...any) Inheritance {
	if !r.IsZero() {
		for i := 0; i < len(x); i++ {
			var lvl InheritanceLevel
			switch tv := x[i].(type) {
			case InheritanceLevel:
				lvl = tv
			case int:
				lvl = assertIntInheritance(tv)
			case string:
				lvl = assertStrInheritance(tv)
			}
			r.aCILevels.cast().Unshift(lvl)
		}
	}

	return r
}

//// DN

type BindDistinguishedName struct {
	BindKeyword
	*aCIDistinguishedName
}

type TargetDistinguishedName struct {
	TargetKeyword
	*aCIDistinguishedName
}

type aCIDistinguishedName struct {
	slice []string // use string instead of proper DN type, as ACIv3 allows wildcard DNs
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r BindDistinguishedName) IsZero() bool {
	return r.aCIDistinguishedName == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r TargetDistinguishedName) IsZero() bool {
	return r.aCIDistinguishedName == nil
}

/*
Len returns the integer length of the receiver instance.
*/
func (r BindDistinguishedName) Len() int {
	var l int
	if !r.IsZero() {
		l = r.aCIDistinguishedName.len()
	}

	return l
}

/*
Len returns the integer length of the receiver instance.
*/
func (r TargetDistinguishedName) Len() int {
	var l int
	if !r.IsZero() {
		l = r.aCIDistinguishedName.len()
	}

	return l
}

func (r *aCIDistinguishedName) len() int {
	var l int
	if r != nil {
		l = len(r.slice)
	}

	return l
}

/*
Push appends zero (0) or more values to the receiver. Each value
MUST be a string DN.
*/
func (r BindDistinguishedName) Push(x ...any) BindDistinguishedName {
	if !r.IsZero() {
		_ = r.aCIDistinguishedName.push(x...)
	}

	return r
}

/*
Eq returns an instance of [BindRuleItem], enveloped as an [BindRule],
bearing the associated [BindKeyword] in equality form.
*/
func (r BindDistinguishedName) Eq() BindRule {
	var br BindRule = badACIv3BindRule
	if r.Len() > 0 {
		br = newACIv3BindRuleItem(r.BindKeyword, Eq, r)
	}

	return br
}

/*
Ne returns an instance of [BindRuleItem], enveloped as an [BindRule],
bearing the associated [BindKeyword] in negated equality form.

Negated equalient [BindRule] instances should be used with caution.
*/
func (r BindDistinguishedName) Ne() BindRule {
	var br BindRule = badACIv3BindRule
	if r.Len() > 0 {
		br = newACIv3BindRuleItem(r.BindKeyword, Ne, r)
	}

	return br
}

/*
Push appends zero (0) or more values to the receiver. Each value
MUST be a string DN.
*/
func (r TargetDistinguishedName) Push(x ...any) TargetDistinguishedName {
	if !r.IsZero() {
		_ = r.aCIDistinguishedName.push(x...)
	}

	return r
}

/*
Eq returns an instance of [TargetRuleItem] bearing the associated
[TargetKeyword] in equality form.
*/
func (r TargetDistinguishedName) Eq() TargetRuleItem {
	var tr TargetRuleItem = badACIv3TargetRuleItem
	if r.Len() > 0 {
		_tr, err := newACIv3TargetRuleItem(r.TargetKeyword, Eq, r)
		if err == nil {
			tr = _tr
		}
	}

	return tr
}

/*
Ne returns an instance of [BindRuleItem], enveloped as an [BindRule],
bearing the associated [BindKeyword] in equality form.

Negated equalient [TargetRuleItem] instances should be used with caution.
*/
func (r TargetDistinguishedName) Ne() TargetRuleItem {
	var tr TargetRuleItem = badACIv3TargetRuleItem
	if r.Len() > 0 {
		_tr, err := newACIv3TargetRuleItem(r.TargetKeyword, Ne, r)
		if err == nil {
			tr = _tr
		}
	}

	return tr
}

func isACIv3SpecialDN(x string) bool {
	return strInSlice(strings.ToLower(x), []string{
		"ldap:///anyone",
		"ldap:///all",
		"ldap:///self",
		"ldap:///parent",
	})
}

func (r *aCIDistinguishedName) push(x ...any) (err error) {
	for i := 0; i < len(x) && err == nil; i++ {
		switch tv := x[i].(type) {
		case string:
			if len(strings.Split(tv, `=`)) >= 2 || isACIv3SpecialDN(tv) {
				if !strings.HasPrefix(tv, "ldap:///") {
					tv = "ldap:///" + tv
				}
				if !r.contains(tv) {
					r.slice = append(r.slice, tv)
				}
			} else {
				err = badACIv3PushErr
			}
			//case DistinguishedName:
			//	dn := tv.String()
			//	if _, err = marshalDistinguishedName(dn); err == nil && !r.contains(dn) {
			//		r.slice = append(r.slice, "ldap:///"+dn)
			//	}
		case BindDistinguishedName:
			// In case the user wants to "merge" multiple DNs into one
			// single statement ...
			for i := 0; i < len(tv.aCIDistinguishedName.slice); i++ {
				r.push(tv.aCIDistinguishedName.slice[i])
			}
		case TargetDistinguishedName:
			// same
			for i := 0; i < len(tv.aCIDistinguishedName.slice); i++ {
				r.push(tv.aCIDistinguishedName.slice[i])
			}
		}
	}

	return
}

func (r aCIDistinguishedName) string(mvq, pad bool) string {
	var s string
	if L := r.len(); L > 0 {
		var _s []string
		if mvq {
			for i := 0; i < L; i++ {
				_s = append(_s, `"`+r.slice[i]+`"`)
			}
		} else {
			for i := 0; i < L; i++ {
				_s = append(_s, r.slice[i])
			}
		}

		var delim string = `||`
		if pad {
			delim = ` || `
		}

		if s = strings.Join(_s, delim); !mvq {
			s = `"` + s + `"`
		}
	}

	return s
}

/*
Index returns the Nth string present within the receiver instance.
*/
func (r BindDistinguishedName) Index(idx int) string {
	var s string
	if !r.IsZero() {
		s = r.aCIDistinguishedName.index(idx)
	}

	return s
}

/*
Index returns the Nth string present within the receiver instance.
*/
func (r TargetDistinguishedName) Index(idx int) string {
	var s string
	if !r.IsZero() {
		s = r.aCIDistinguishedName.index(idx)
	}

	return s
}

func (r aCIDistinguishedName) index(idx int) string {
	var dn string

	if 0 <= idx && idx < r.len() {
		dn = r.slice[idx]
	}

	return dn
}

/*
Contains returns a Boolean value indicative of a match between x
and a slice value in the receiver instance.

x MUST be a string DN.
*/
func (r BindDistinguishedName) Contains(x any) bool {
	var c bool
	if !r.IsZero() {
		c = r.aCIDistinguishedName.contains(x)
	}

	return c
}

/*
Contains returns a Boolean value indicative of a match between x
and a slice value in the receiver instance.

x MUST be a string DN.
*/
func (r TargetDistinguishedName) Contains(x any) bool {
	var c bool
	if !r.IsZero() {
		c = r.aCIDistinguishedName.contains(x)
	}

	return c
}

func (r aCIDistinguishedName) contains(x any) bool {
	var term string
	switch tv := x.(type) {
	case string:
		term = tv
	default:
		return false
	}

	return strInSlice(term, r.slice)
}

//// ATTRS

/*
AttributeBindTypeOrValue contains a statement of the following syntax:

	<AttributeName>#<BindType -OR- AttributeValue>

Instances of this type are used in certain [BindRule] instances, particularly
those that involve user-attribute or group-attribute [BindKeyword] instances.
*/
type AttributeBindTypeOrValue struct {
	BindKeyword // Constraint: BindUAT or BindGAT keywords only!
	*atbtv      // Embedded PTR
}

/*
atbtv is the embedded (BY POINTER!) type found within instances of AttributeBindTypeOrValue.

Slices are as follows:
  - 0: <atoid> (Attribute)
  - 1: <atv>   (BindType -OR- AttributeValue)
*/
type atbtv [2]any

/*
IsZero returns a Boolean value indicative of whether the receiver is nil,
or unset.
*/
func (r AttributeBindTypeOrValue) IsZero() bool {
	if r.atbtv == nil {
		return true
	}

	return r.BindKeyword == 0x0
}

/*
NewAttributeBindTypeOrValue will return a new instance of [AttributeBindTypeOrValue]. The
required [BindKeyword] must be either [BindUAT] or [BindGAT]. The optional input values
(x), if provided, will be used to set the instance.
*/
func NewAttributeBindTypeOrValue(x ...any) (AttributeBindTypeOrValue, error) {
	return marshalACIv3AttributeBindTypeOrValue(x...)
}

func marshalACIv3AttributeBindTypeOrValue(x ...any) (AttributeBindTypeOrValue, error) {
	var a AttributeBindTypeOrValue
	var err error

	if l := len(x); l > 0 {
		switch l {
		case 1:
			switch tv := x[0].(type) {
			case string:
				a, err = parseATBTV(tv)
			case AttributeBindTypeOrValue:
				a = tv
			}
		case 2:
			var bkw BindKeyword

			switch tv := x[0].(type) {
			case string:
				bkw = matchBKW(tv)
			case BindKeyword:
				bkw = tv
			}

			switch tv := x[1].(type) {
			case string:
				a, err = parseATBTV(tv)
			case AttributeBindTypeOrValue:
				a = tv
				a.BindKeyword = bkw
			}
		default:
			a = aCIUserOrGroupAttr(x[0], x[1:]...)
		}
	}

	if err == nil {
		err = a.Valid()
	}

	return a, err
}

/*
aCIUserOrGroupAttr is a private package level function called by either the GroupAttr or UserAttr function. This function is the base initializer for the [AttributeBindTypeOrValue] instance returned by said functions.
*/
func aCIUserOrGroupAttr(kw any, x ...any) (A AttributeBindTypeOrValue) {
	var keyword BindKeyword

	switch tv := kw.(type) {
	case string:
		keyword = matchBKW(kw)
	case BindKeyword:
		if tv == BindUAT || tv == BindGAT {
			keyword = tv
		}
	}

	A = AttributeBindTypeOrValue{
		keyword, new(atbtv),
	}

	if len(x) != 0 {
		A.atbtv.set(x...)
	}

	return
}

/*
Set assigns value(s) x to the receiver. The value(s) must be [Attribute] and/or [AttributeValue] instances, created via the package-level [AT] and [AV] functions respectively.
*/
func (r AttributeBindTypeOrValue) Set(x ...any) AttributeBindTypeOrValue {
	if r.IsZero() {
		r.atbtv = new(atbtv)
	}
	r.atbtv.set(x...)
	return r
}

/*
Eq initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Equal-To a [BindUAT] or [BindGAT] [BindKeyword] context.
*/
func (r AttributeBindTypeOrValue) Eq() (b BindRule) {
	if !r.atbtv.isZero() {
		b = newACIv3BindRuleItem(r.BindKeyword, Eq, r)
	}
	return
}

/*
Ne initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Not-Equal-To a [BindUAT] or [BindGAT] [BindKeyword] context.

Negated equality [BindRule] instances should be used with caution.
*/
func (r AttributeBindTypeOrValue) Ne() (b BindRule) {
	if !r.atbtv.isZero() {
		b = newACIv3BindRuleItem(r.BindKeyword, Ne, r)
	}
	return
}

/*
BRM returns an instance of [BindRuleMethods].

Each of the return instance's key values represent a single instance of the [Operator] type that is allowed for use in the creation of [BindRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [BindRuleMethod] instance for OPTIONAL use in the creation of a [BindRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [BindRule] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r AttributeBindTypeOrValue) BRM() BindRuleMethods {
	return newACIv3BindRuleMethods(aCIBindRuleFuncMap{
		Eq: r.Eq,
		Ne: r.Ne,
	})
}

/*
Keyword returns the [BindKeyword] associated with the receiver instance, enveloped as a [Keyword]. In the context of this type instance, the [BindKeyword] returned will always be one (1) of [BindUAT] or [BindGAT].
*/
func (r AttributeBindTypeOrValue) Keyword() Keyword {
	var kw Keyword = r.BindKeyword
	switch kw {
	case BindGAT:
		return BindGAT
	}

	return BindUAT
}

/*
isZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r *atbtv) isZero() bool {
	var z bool = true
	if r != nil {
		z = (r[0] == nil && r[1] == nil)
	}
	return z
}

/*
String returns the string representation of the receiver.
*/
func (r atbtv) String() (s string) {
	// Only one (1) of the following
	// vars will be used.
	var bt BindType
	var av AttributeValue

	if r.isZero() {
		return
	}

	// Assert the attributeType value or bail out.
	if at, assert := r[0].(Attribute); assert {
		// First see if the value is a BindType
		// keyword, as those are few and easily
		// identified.
		if bt, assert = r[1].(BindType); !assert || bt == BindType(0x0) {
			// If not a BindType kw, see if it
			// appears to be an AttributeValue.
			if av, assert = r[1].(AttributeValue); !assert || len(*av.string) == 0 {
				// value is neither an AttributeValue
				// nor BindType kw; bail out.
				return
			}

			// AttributeValue wins
			s = at.Index(0) + `#` + av.String()
			return
		}

		// BindType wins
		s = at.Index(0) + `#` + av.String()
	}

	return
}

/*
set assigns one (1) or more values (x) to the receiver. Only [Attribute], [AttributeValue] and [BindType] instances shall be assigned.

Note that if a string value is detected, it will be cast as the appropriate type and assigned to the appropriate slice in the receiver, but ONLY if said slice is nil.
*/
func (r *atbtv) set(x ...any) {
	for i := 0; i < len(x); i++ {
		switch tv := x[i].(type) {
		case Attribute:
			if r[0] == nil {
				r[0] = tv
			}
		case AttributeValue, BindType:
			r[1] = tv
		case string:
			if bt := matchBT(tv); bt != BindType(0x0) {
				r[1] = bt
			} else {
				r[1] = AttributeValue{&tv}
			}
		}
	}
}

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeBindTypeOrValue) String() string {
	var s string = badAVStr
	if r.atbtv != nil {
		if at, ok := r.atbtv[0].(Attribute); ok {
			switch tv := r.atbtv[1].(type) {
			case AttributeValue:
				s = at.Index(0) + `#` + (*tv.string)
			case BindType:
				s = at.Index(0) + `#` + tv.String()
			}
		}
	}
	return s
}

/*
Parse reads the input string (raw) in an attempt to marshal its contents into the receiver instance (r). An error is returned at the end of the process.

If no suitable [BindKeyword] is provided (bkw), the default is [BindUAT]. Valid options are [BindUAT] and [BindGAT].
*/
func (r *AttributeBindTypeOrValue) parse(raw string, bkw ...any) (err error) {
	var _r AttributeBindTypeOrValue
	if _r, err = parseATBTV(raw, bkw); err == nil {
		*r = _r
	}

	return
}

/*
Valid returns an error indicative of whether the receiver is in an aberrant state.
*/
func (r AttributeBindTypeOrValue) Valid() (err error) {
	if !r.IsZero() {
		if r.atbtv[0] == nil || r.atbtv[1] == nil {
			err = badACIv3ATBTVErr
		}
	} else {
		err = nilInstanceErr
	}

	return
}

/*
parseATBTV parses the input string (x) in an attempt to marshal its contents
into an instance of [AttributeBindTypeOrValue] (A), which is returned alongside
an error (err).

The optional BindKeyword argument (bkw) allows the [BindGAT] (groupattr) Bind
Rule keyword to be set, else the default of [BindUAT] (userattr) will take
precedence.
*/
func parseATBTV(x string, bkw ...any) (A AttributeBindTypeOrValue, err error) {
	// Obtain the index number for ASCII #35 (NUMBER SIGN).
	// If minus one (-1), input value x is totally bogus.
	idx := strings.IndexRune(x, '#')
	if idx == -1 {
		err = badACIv3AttributeBindTypeOrValueErr
		return
	} else if len(x[idx+1:]) == 0 {
		err = badACIv3AttributeBindTypeOrValueErr
		return
	}

	// Set the groupattr keyword if requested, else
	// use the default of userattr.
	kw := assertATBTVBindKeyword(bkw...)

	at, _ := marshalACIv3Attribute(x[:idx])
	v := x[idx+1:]
	av := AttributeValue{&v}

	if at.Index(0) == badATStr {
		err = badACIv3AttributeBindTypeOrValueErr
		return
	}

	// If the remaining portion of the value is, in
	// fact, a known BIND TYPE keyword, pack it up
	// and ship it out.
	if bt := matchBT(x[idx+1:]); bt != BindType(0x0) {
		A = aCIUserOrGroupAttr(kw, at, bt)
	} else {
		A = aCIUserOrGroupAttr(kw, at, av)
	}

	return
}

/*
Attribute facilitates the storage of one (1) or more attribute OIDs, typically used in the
context of [TargetRuleItem] attributes.
*/
type Attribute struct {
	*aCIAttribute
}

type aCIAttribute struct {
	slice []string
	all   bool // "*"; mutex for len(slice)>0
}

/*
String returns the string representation of the receiver instance.
*/
func (r Attribute) String() string {
	var s string = badATStr

	if !r.IsZero() {
		if r.aCIAttribute.all {
			s = `*`
		} else if r.Len() > 0 {
			s = strings.Join(r.aCIAttribute.slice, `||`)
		}
	}

	return s
}

/*
Eq initializes and returns a new [TargetRuleItem] instance configured to express the evaluation of the receiver value as Equal-To a [TargetAttr] [TargetKeyword] context.
*/
func (r Attribute) Eq() TargetRuleItem {
	var tr TargetRuleItem = badACIv3TargetRuleItem
	if !r.IsZero() {
		t, err := newACIv3TargetRuleItem(TargetAttr, Eq, r)
		if err == nil {
			tr = t
		}
	}

	return tr
}

/*
Ne initializes and returns a new [TargetRuleItem] instance configured to express the evaluation of the receiver value as Not-Equal-To a [TargetAttr] [TargetKeyword] context.

Negated equality [TargetRuleItem] instances should be used with caution.
*/
func (r Attribute) Ne() (t TargetRuleItem) {
	var tr TargetRuleItem = badACIv3TargetRuleItem
	if !r.IsZero() {
		t, err := newACIv3TargetRuleItem(TargetAttr, Ne, r)
		if err == nil {
			tr = t
		}
	}

	return tr
}

/*
Kind performs no useful task, as the receiver instance has no concept of a keyword, which is the typical value source for Kind calls. This method exists solely to satisfy Go's interface signature requirements and will return a zero string if executed.
*/
func (r Attribute) Kind() string { return `` }

/*
Keyword performs no useful task, as the receiver instance has no concept of a keyword. This method exists solely to satisfy Go's interface signature requirements and will return nil if executed.
*/
func (r Attribute) Keyword() Keyword { return nil }

/*
TRM returns an instance of [TargetRuleMethods].

Each of the return instance's key values represent a single instance of the [Operator] type that is allowed for use in the creation of [TargetRuleItem] instances which bear the receiver instance as an expression value. The value for each key is the actual [TargetRuleMethod] instance for OPTIONAL use in the creation of a [TargetRuleItem] instance.

This is merely a convenient alternative to maintaining knowledge of which [Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [TargetRuleItem] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly initialized, populated and prepared for such activity.
*/
func (r Attribute) TRM() TargetRuleMethods {
	return newACIv3TargetRuleMethods(aCITargetRuleFuncMap{
		Eq: r.Eq,
		Ne: r.Ne,
	})
}

/*
Valid returns an error following an analysis of the receiver instance.
*/
func (r Attribute) Valid() (err error) {
	if r.IsZero() || r.Len() == 0 {
		err = nilInstanceErr
	}

	return
}

/*
Push appends zero (0) or more attributes to the receiver instance.
*/
func (r Attribute) Push(x ...any) Attribute {
	_ = r.push(x...)
	return r
}

func (r Attribute) push(x ...any) (err error) {
	for i := 0; i < len(x) && !r.aCIAttribute.all && err == nil; i++ {
		switch tv := x[i].(type) {
		case []string:
			for j := 0; j < len(tv) && err == nil; j++ {
				err = r.push(strings.TrimSpace(tv[j]))
			}
		case string:
			if tv == `*` {
				r.aCIAttribute.slice = nil
				r.aCIAttribute.all = true
				break
			}
			sp := strings.Split(tv, `||`)
			for j := 0; j < len(sp) && err == nil; j++ {
				if at := strings.TrimSpace(sp[j]); isAttribute(at) {
					r.aCIAttribute.slice = append(r.aCIAttribute.slice, at)
				} else {
					err = badACIv3AttributeErr
				}
			}
		}
	}

	return err
}

func (r Attribute) Len() int {
	var l int
	if r.aCIAttribute != nil {
		l = len(r.aCIAttribute.slice)
	}

	return l
}

func (r Attribute) Index(idx int) string {
	var a string = badATStr
	if r.aCIAttribute != nil {
		if 0 <= idx && idx < r.Len() {
			a = r.aCIAttribute.slice[idx]
		}
	}

	return a
}

func (r Attribute) IsZero() bool {
	return r.aCIAttribute == nil
}

/*
String returns the string representation of the underlying value within the receiver. The return value shall reflect an LDAP descriptor, such as `manager` or `cn`.
*/
func (r aCIAttribute) string(mvq, pad bool) (s string) {
	if r.all {
		s = `"*"`
	} else {
		var _s []string
		if mvq {
			for i := 0; i < len(r.slice); i++ {
				_s = append(_s, `"`+r.slice[i]+`"`)
			}
		} else {
			for i := 0; i < len(r.slice); i++ {
				_s = append(_s, r.slice[i])
			}
		}
		var delim string = `||`
		if pad {
			delim = ` || `
		}

		if s = strings.Join(_s, delim); !mvq {
			s = `"` + s + `"`
		}
	}

	return
}

/*
AttributeValue embeds a pointer value that reflects an attribute value.
*/
type AttributeValue struct {
	*string
}

/*
String returns the string representation of the underlying value within the receiver. The return value should be either an attributeType assertion value, or one (1) of the five (5) possible [BindType] identifiers (e.g.: [BindTypeUSERDN]).
*/
func (r AttributeValue) String() (s string) {
	s = badAVStr
	if r.string != nil {
		s = (*r.string)
	}

	return
}

//// TARGET

/*
TargetRuleItem implements the base slice type for instances of [TargetRuleItem].

Instances of this type shall contain a minimum of zero (0) and a maximum of nine (9)
valid [TargetRuleItem] instances.

During the [TargetRule.Push] (append) process, individual slices are checked for
uniqueness based on [TargetKeyword] use. As such, no single [TargetKeyword]
shall ever appear in more than one [TargetRuleItem] instance found within instances
of this type.
*/
type TargetRule struct {
	*aCITargetRule
}

type aCITargetRule struct {
	slice []TargetRuleItem
}

func (r TargetRule) IsZero() bool {
	return r.aCITargetRule == nil
}

/*
Len returns the integer length of the receiver instance.
*/
func (r TargetRule) Len() int {
	var l int
	if !r.IsZero() {
		l = len(r.aCITargetRule.slice)
	}

	return l
}

/*
Index returns the Nth instance of [TargetRuleItem] present
within the receiver instance.
*/
func (r TargetRule) Index(idx int) TargetRuleItem {
	var tr TargetRuleItem = badACIv3TargetRuleItem
	if !r.IsZero() {
		if 0 <= idx && idx < r.Len() {
			tr = r.aCITargetRule.slice[idx]
		}
	}

	return tr
}

/*
Contains returns a Boolean value indicative of the presence an instance
of [TargetRuleItem] bearing the specified [TargetKeyword] within
the receiver instance.
*/
func (r TargetRule) Contains(kw any) bool {
	var (
		c bool
		k TargetKeyword = matchTKW(kw)
	)

	if !r.IsZero() {
		for i := 0; i < r.Len() && !c; i++ {
			c = r.aCITargetRule.slice[i].Keyword() == k
		}
	}

	return c
}

/*
Push appends zero (0) or more valid [TargetRuleItem] instances to the
receiver instance.

If the specified [TargetRuleItem] input instances bear [TargetKeyword]s
already in use within the receiver instance, they are silently ignored.

Up to nine (9) possible [TargetRuleItem] instances shall appear within
any instance of this type.
*/
func (r TargetRule) Push(x ...any) TargetRule {
	if !r.IsZero() {
		for i := 0; i < len(x) && r.Len() < 9; i++ {
			switch tv := x[i].(type) {
			case string:
				r.parse(tv)
			case TargetRuleItem:
				if tv.Valid() == nil && !r.Contains(tv.Keyword()) {
					r.aCITargetRule.slice = append(r.aCITargetRule.slice, tv)
				}
			}

		}
	}

	return r
}

/*
Valid returns an error following an analysis of the receiver instance.
*/
func (r TargetRule) Valid() (err error) {
	for i := 0; i < r.Len() && err == nil; i++ {
		err = r.Index(i).Valid()
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r TargetRule) String() string {
	var s string
	if r.Len() == 0 {
		// TargetRules are always OPTIONAL in any ACIv3, thus
		// we need not return an "invalid placeholder" value,
		// just a zero string.
		return ``
	}

	for i := 0; i < r.Len(); i++ {
		s += r.Index(i).String()
	}

	return s
}

/*
TargetRuleItem implements the (optional) ACIv3 Target Rule slice value type.
Instances of this type are intended for storage within an instance of [TargetRule].
*/
type TargetRuleItem struct {
	*aCITargetRuleItem
}

type aCITargetRuleItem struct {
	Keyword    TargetKeyword
	Operator   Operator
	Expression any
	mvq        bool
	pad        bool
}

/*
TargetRuleMethods contains one (1) or more instances of [TargetRuleMethod], representing a particular [TargetRuleItem] "builder" method for execution by the caller.

See the Operators method extended through all eligible types for further details.
*/
type TargetRuleMethods struct {
	*aCITargetRuleFuncMap
}

/*
newTargetRuleMethods populates an instance of *targetRuleFuncMap, which is embedded within the return instance of TargetRuleMethods.
*/
func newACIv3TargetRuleMethods(m aCITargetRuleFuncMap) TargetRuleMethods {
	if len(m) == 0 {
		return TargetRuleMethods{nil}
	}

	M := make(aCITargetRuleFuncMap, len(m))
	for k, v := range m {
		M[k] = v
	}

	return TargetRuleMethods{&M}
}

/*
Index calls the input index (idx) within the internal structure of the receiver instance. If found, an instance of [Operator] and its accompanying [TargetRuleMethod] instance are returned.

Valid input index types are integer (int), [Operator] constant or string identifier. In the case of a string identifier, valid values are as follows:

  - For Eq (1): `=`, `Eq`, `Equal To`
  - For Ne (2): `=`, `Ne`, `Not Equal To`
  - For Lt (3): `=`, `Lt`, `Less Than`
  - For Le (4): `=`, `Le`, `Less Than Or Equal`
  - For Gt (5): `=`, `Gt`, `Greater Than`
  - For Ge (6): `=`, `Ge`, `Greater Than Or Equal`

Case is not significant in the string matching process.

Please note that use of this method by way of integer or [Operator] values utilizes fewer resources than a string lookup.

See the [Operator.Context], [Operator.String] and [Operator.Description] methods for accessing the above string values easily.

If the index was not matched, an invalid [Operator] is returned alongside a nil [TargetRuleMethod]. This will also apply to situations in which the type instance which crafted the receiver is uninitialized, or is in an otherwise aberrant state.
*/
func (r TargetRuleMethods) Index(idx any) (cop Operator, meth TargetRuleMethod) {
	if r.IsZero() {
		return
	}
	cop = invalidCop

	// perform a type switch upon the input
	// index type
	switch tv := idx.(type) {

	case Operator:
		// cast cop as an int, and make recursive
		// call to this function.
		return r.Index(int(tv))

	case int:
		// there are only six (6) valid
		// operators, numbered one (1)
		// through six (6).
		if !(1 <= tv && tv <= 6) {
			return
		}

		var found bool
		if meth, found = (*r.aCITargetRuleFuncMap)[Operator(tv)]; found {
			cop = Operator(tv)
		}

	case string:
		cop, meth = rangeTargetRuleFuncMap(tv, r.aCITargetRuleFuncMap)
	}

	return
}

func rangeTargetRuleFuncMap(candidate string, fm *aCITargetRuleFuncMap) (cop Operator, meth TargetRuleMethod) {
	// iterate all map entries, and see if
	// input string value matches the value
	// returned by these three (3) methods:
	for k, v := range *fm {
		if strInSlice(candidate, []string{
			k.String(),      // e.g.: "="
			k.Context(),     // e.g.: "Eq"
			k.Description(), // e.g.: "Equal To"
		}) {
			cop = k
			meth = v
			break
		}
	}

	return
}

/*
Contains returns a Boolean value indicative of whether the specified [Operator], which may be expressed as a string, int or native [Operator], is allowed for use by the type instance that created the receiver instance. This method offers a convenient alternative to the use of the Index method combined with an assertion value (such as [Eq], [Ne], "=", "Greater Than", et al).

In other words, if one uses the [TargetDistinguishedName]'s TRM method to create an instance of [TargetRuleMethods], feeding [Gt] (Greater Than) to this method shall return false, as no [TargetRuleItem] context allows mathematical comparison.
*/
func (r TargetRuleMethods) Contains(cop any) bool {
	c, _ := r.Index(cop)
	return c.Valid() == nil
}

/*
IsZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r TargetRuleMethods) IsZero() bool {
	return r.aCITargetRuleFuncMap == nil
}

/*
Valid returns the first encountered error returned as a result of execution of the first available [TargetRuleMethod] instance. This is useful in cases where a user wants to see if the desired instance(s) of [TargetRuleMethod] will produce a usable result.
*/
func (r TargetRuleMethods) Valid() (err error) {
	if r.IsZero() {
		err = nilInstanceErr
		return
	}

	// Eq is always available for all eligible
	// types, so let's use that unconditionally.
	// If any one method works, then all of them
	// will work.
	_, meth := r.Index(Eq)
	err = meth().Valid()
	return
}

/*
Len returns the integer length of the receiver. Note that the return value will NEVER be less than zero (0) nor greater than six (6).
*/
func (r TargetRuleMethods) Len() int {
	if r.IsZero() {
		return 0
	}

	return len((*r.aCITargetRuleFuncMap))
}

/*
TargetRuleMethod is the closure signature for methods used to build new instances of [TargetRuleItem].

The signature is qualified by the following methods extended through all eligible types defined in this package:

  - [Eq]
  - [Ne]

Note that [TargetRuleItem] instances only support a very limited subset of these methods when compared to [BindRule] instances. In fact, some [TargetRuleItem] instances only support ONE such method: Eq.
*/
type TargetRuleMethod func() TargetRuleItem

/*
aCITargetRuleFuncMap is a private type intended to be used within instances of TargetRuleMethods.
*/
type aCITargetRuleFuncMap map[Operator]TargetRuleMethod

/*
Keyword returns the [TargetKeyword] value currently set within the receiver instance.
*/
func (r TargetRuleItem) Keyword() TargetKeyword {
	var bkw TargetKeyword = invalidACIv3TargetKeyword
	if &r != nil {
		bkw = r.aCITargetRuleItem.Keyword
	}

	return bkw
}

/*
Operator returns the [Operator] value currently set within the receiver instance.
*/
func (r TargetRuleItem) Operator() Operator {
	var cop Operator = invalidCop
	if &r != nil {
		cop = r.aCITargetRuleItem.Operator
	}

	return cop
}

/*
Expression returns the underlying expression value currently set within the receiver instance.
*/
func (r TargetRuleItem) Expression() any {
	var val any
	if &r != nil {
		val = r.aCITargetRuleItem.Expression
	}

	return val
}

/*
NewTargetRuleItem initializes, populates and returns a new instance of [TargetRuleItem].
*/
func NewTargetRuleItem(x ...any) (TargetRuleItem, error) {
	var (
		tri TargetRuleItem = TargetRuleItem{&aCITargetRuleItem{}}
		err error
	)

	if len(x) > 0 {
		switch tv := x[0].(type) {
		case string:
			err = tri.parse(tv)
		case TargetKeyword:
			if matchTKW(tv) != 0x0 {
				if len(x) == 3 {
					if _, ok := x[1].(Operator); !ok {
						err = badACIv3TRErr
					} else {
						tri, err = newACIv3TargetRuleItem(x[0], x[1], x[2])
					}
				} else {
					err = badACIv3TRErr
				}
			} else {
				err = badACIv3TRErr
			}
		default:
			err = badACIv3TRErr
		}
	}

	return tri, err

}

func initACIv3TargetRuleItem() TargetRuleItem {
	return TargetRuleItem{&aCITargetRuleItem{
		Keyword:  invalidACIv3TargetKeyword,
		Operator: invalidCop,
	}}
}

func newACIv3TargetRuleItem(kw, op any, ex ...any) (tr TargetRuleItem, err error) {
	tr = initACIv3TargetRuleItem().
		SetKeyword(kw).
		SetOperator(op)

	var value any
	if value, err = assertTargetValueByKeyword(tr.Keyword(), ex...); err == nil {
		tr.SetExpression(value)
	}

	if err == nil {
		err = tr.Valid()
	}

	return
}

/*
SetKeyword assigns [Keyword] kw to the receiver instance.
*/
func (r TargetRuleItem) SetKeyword(kw any) TargetRuleItem {
	if r.IsZero() {
		r.aCITargetRuleItem = initACIv3TargetRuleItem().aCITargetRuleItem
	}
	switch tv := kw.(type) {
	case string:
		r.aCITargetRuleItem.Keyword = matchTKW(tv)
	case TargetKeyword:
		r.aCITargetRuleItem.Keyword = tv
	}

	return r
}

/*
SetOperator assigns [Operator] op to the receiver
instance.
*/
func (r TargetRuleItem) SetOperator(op any) TargetRuleItem {
	if r.IsZero() {
		r.aCITargetRuleItem = initACIv3TargetRuleItem().aCITargetRuleItem
	}

	// assert underlying comparison operator.
	var cop Operator
	switch tv := op.(type) {
	case string:
		cop = matchACIv3Cop(tv)
	case Operator:
		cop = tv
	}

	// For security reasons, only assign comparison
	// operator if it is Eq or Ne.
	if 0x0 < cop && cop <= 0x2 {
		r.aCITargetRuleItem.Operator = cop
	}

	return r
}

/*
SetExpression assigns value expr to the receiver instance.
*/
func (r TargetRuleItem) SetExpression(expr any) TargetRuleItem {
	if r.IsZero() {
		r.aCITargetRuleItem = initACIv3TargetRuleItem().aCITargetRuleItem
	}
	// TODO: constrain to specific types
	r.aCITargetRuleItem.Expression = expr

	return r
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r TargetRuleItem) IsZero() bool {
	return r.aCITargetRuleItem == nil
}

/*
Kind returns the string literal `targetRule`.
*/
func (r TargetRuleItem) Kind() string {
	return `targetRule`
}

/*
Valid returns an error instance which, when non-nil, will indicate a logical
flaw, such a missing component of a [TargetRuleItem] qualifier, or some
other issue.
*/
func (r TargetRuleItem) Valid() (err error) {
	if r.IsZero() {
		err = errors.New("Invalid target rule item: is zero")
		return
	}

	for _, ok := range []bool{
		r.Keyword() != invalidACIv3TargetKeyword,
		r.Operator() != 0x0,

		// TODO:expand on this logic to limit validity
		// to high-level interface qualifiers only, or
		// raw string values.
		r.Expression() != nil,
	} {
		if !ok {
			err = errors.New("Invalid target rule (ITEM): Missing bindRule keyword, operator or the expr value is bogus")
			break
		}
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r TargetRuleItem) String() (s string) {
	s = badACIv3TRStr
	if r.IsZero() {
		return s
	}

	// Try to coax a string out of the value.
	var raw string
	switch tv := r.Expression().(type) {
	case TargetDistinguishedName:
		raw = tv.string(r.aCITargetRuleItem.mvq, r.aCITargetRuleItem.pad)
	case ObjectIdentifier:
		raw = tv.string(r.aCITargetRuleItem.mvq, r.aCITargetRuleItem.pad)
	default:
		// For all other types, as a last resort, see
		// if the instance has its own Stringer, and
		// (if so) use it.
		if meth := getStringer(tv); meth != nil {
			raw = meth()
		} else {
			return s
		}
	}

	if !(strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`)) {
		raw = `"` + raw + `"`
	}

	var pad string
	if r.pad {
		pad = ` `
	}

	s = `(` + pad + r.Keyword().String() + pad +
		r.Operator().String() + pad + raw + pad + `)`

	return
}

func (r *TargetRuleItem) parse(x string) (err error) {
	var tkz []aCITargetRuleToken
	if tkz, err = tokenizeACIv3TargetRule(x); err == nil {
		*r, err = processACIv3TargetRuleItem(tkz)
	}

	return err
}

//// RIGHTS

/*
Right contains the specific bit value of a single user privilege. Constants of this type are intended for submission to the [Permission.Shift], [Permission.Unshift] and [Permission.Positive] methods.
*/
type Right uint16

/*
Permission defines a level of access bestowed (or withheld) by a [PermissionBindRule].
*/
type Permission struct {
	*aCIPermission
}

type aCIPermission struct {
	*bool
	*aCIRights
}

/*
NewPermission returns an instance of [Permission] alongside an error following an attempt to marshal x.

If only a single value is provided, it is assumed to be the string representation of an [Permission], e.g.:

	allow(read,search,compare)

If more than one values are provided, it is assumed the first argument is a disposition Boolean. A value of true
results in a granting [Permission] ("allow"), while false results in a withholding [Permission] ("deny").
All subsequent arguments are assumed to be individual [Right] instances or their equivalent forms as integers
or strings.
*/
func NewPermission(x ...any) (Permission, error) {
	return marshalACIv3Permission(x...)
}

func marshalACIv3Permission(x ...any) (Permission, error) {
	var (
		p   *aCIPermission
		err error
	)

	switch len(x) {
	case 0:
		err = badACIv3PermErr
		return badACIv3Permission, err
	case 1:
		if raw, ok := x[0].(string); !ok || len(raw) == 0 {
			err = badACIv3PermErr
			return badACIv3Permission, err
		} else {
			p, err = parseACIv3Permission(raw)
		}
	default:
		if disp, ok := x[0].(bool); !ok {
			err = badACIv3PermErr
			return badACIv3Permission, err
		} else {
			p, err = newACIv3Permission(disp, x[1:]...)
		}
	}

	return Permission{p}, err
}

/*
newACIv3Permission returns a newly initialized instance of *permission bearing the provided disposition and [Right] instance(s).
*/
func newACIv3Permission(disp bool, x ...any) (p *aCIPermission, err error) {
	p = new(aCIPermission)
	p.bool = &disp
	p.aCIRights = newRights()
	p.shift(x...)
	return
}

func parseACIv3Permission(raw string) (p *aCIPermission, err error) {
	var offset int
	var disp bool // disposition (allow[true] vs. deny[false])

	if len(raw) < 9 {
		// shortest possible statement is 9 chars ("deny(all)"),
		// so bail out if we're smaller than that.
		err = badACIv3PermErr
		return
	} else if raw[len(raw)-1] != ')' {
		// must end in a closing paren
		err = badACIv3PermErr
		return
	}
	raw = removeWHSP(raw)

	if strings.HasPrefix(raw, "allow(") {
		offset = 6
		disp = true
	} else if strings.HasPrefix(raw, "deny(") {
		offset = 5
		disp = false
	} else {
		err = badACIv3PermErr
		return
	}

	raw = raw[offset:]     // chop disposition prefix
	raw = raw[:len(raw)-1] // chop closing paren

	// split the remaining text by comma delimiters.
	// shift the remainder, which should be one (1) or
	// more string-based "right" names (i.e.: "read").
	p, err = newACIv3Permission(disp, strings.Split(raw, ","))

	return
}

func (r *aCIPermission) shift(x ...any) {
	if !r.isZero() {
		// iterate through the sequence of "anys"
		// and assert to an Right (or the abstraction
		// of a Right).
		for i := 0; i < len(x); i++ {
			switch tv := x[i].(type) {
			case int, Right:
				r.aCIRights.cast().Shift(tv)
			case []int:
				for j := 0; j < len(tv); j++ {
					r.aCIRights.cast().Shift(tv[j])
				}
			case string:
				if priv, found := aCIRightsNames[strings.ToLower(tv)]; found {
					r.aCIRights.cast().Shift(priv)
				}
			case []string:
				for j := 0; j < len(tv); j++ {
					if priv, found := aCIRightsNames[strings.ToLower(tv[j])]; found {
						r.aCIRights.cast().Shift(priv)
					}
				}
			}
		}
	}
}

func (r *aCIPermission) unshift(x ...any) {
	if !r.isZero() {
		// iterate through the sequence of "anys"
		// and assert to a Right (or the abstraction
		// of an Right).
		for i := 0; i < len(x); i++ {
			switch tv := x[i].(type) {
			case int, Right:
				r.aCIRights.cast().Unshift(tv)
			case []int:
				for j := 0; j < len(tv); j++ {
					r.aCIRights.cast().Unshift(tv[j])
				}
			case string:
				if priv, found := aCIRightsNames[strings.ToLower(tv)]; found {
					r.aCIRights.cast().Unshift(priv)
				}
			case []string:
				for j := 0; j < len(tv); j++ {
					if priv, found := aCIRightsNames[strings.ToLower(tv[j])]; found {
						r.aCIRights.cast().Unshift(priv)
					}
				}
			}
		}
	}
}

func (r *aCIPermission) positive(x any) (posi bool) {
	if !r.isZero() {
		switch tv := x.(type) {
		case int:
			if posi = tv == 0 && r.aCIRights.cast().Int() == tv; posi {
				break
			}
			posi = r.aCIRights.cast().Positive(tv)

		case string:
			if priv, found := aCIRightsNames[strings.ToLower(tv)]; found {
				posi = r.positive(priv)
			}

		case Right:
			posi = r.positive(int(tv))
		}
	}
	return
}

/*
String returns a single string name value for receiver instance.
*/
func (r Right) String() (p string) {
	switch r {
	case NoAccess:
		return aCIRightsMap[0]
	case AllAccess:
		return aCIRightsMap[895]
	}

	if kw, found := aCIRightsMap[r]; found {
		p = kw
	}
	return
}

/*
Len returns the abstract integer length of the receiver, quantifying the number of [Right] instances currently being expressed. For example, if the receiver instance has its [ReadAccess] and [DeleteAccess] [Right] bits enabled, this would represent an abstract length of two (2).
*/
func (r Permission) Len() (l int) {
	if !r.IsZero() {
		l = r.aCIPermission.len()
	}
	return
}

func (r aCIPermission) len() int {
	var D int
	for i := 0; i < r.aCIRights.cast().Size(); i++ {
		if d := Right(1 << i); r.aCIRights.cast().Positive(d) {
			D++
		}
	}

	return D
}

/*
String returns the string representation of the receiver instance.
*/
func (r Permission) String() string {
	if r.IsZero() {
		return badACIv3PermStr
	}

	pint := r.aCIPermission.aCIRights.cast().Int()
	dispStr := func(rights []string) string {
		return r.Disposition() + `(` + strings.Join(rights, `,`) + `)`
	}

	var rights []string
	if Right(pint) == AllAccess {
		rights = append(rights, AllAccess.String())
		return dispStr(rights)
	} else if pint == 1023 {
		rights = append(rights, AllAccess.String())
		rights = append(rights, ProxyAccess.String())
		return dispStr(rights)
	} else if Right(pint) == NoAccess {
		rights = append(rights, NoAccess.String())
		return dispStr(rights)
	}

	size := r.aCIPermission.aCIRights.cast().Size()
	for i := 0; i < size; i++ {
		if right := Right(1 << i); r.Positive(right) {
			rights = append(rights, right.String())
		}
	}

	return dispStr(rights)
}

/*
Disposition returns the string disposition `allow` or 'deny', depending on the state of the receiver.
*/
func (r Permission) Disposition() string {
	if r.aCIPermission == nil {
		return `<unknown_disposition>`
	}
	return r.aCIPermission.disposition()
}

func (r aCIPermission) disposition() (disp string) {
	disp = `<unknown_disposition>`
	if *r.bool {
		disp = `allow`
	} else if !*r.bool {
		disp = `deny`
	}
	return
}

/*
Positive returns a Boolean value indicative of whether a particular bit is positive (is set). Negation implies negative, or unset.
*/
func (r Permission) Positive(x any) (posi bool) {
	if err := r.Valid(); err == nil {
		posi = r.aCIPermission.positive(x)
	}
	return
}

/*
Shift left-shifts the receiver instance to include [Right] x, if not already present.
*/
func (r Permission) Shift(x ...any) Permission {
	if err := r.Valid(); err == nil {
		for i := 0; i < len(x); i++ {
			r.aCIPermission.shift(x[i]) //rights.cast().Shift(x[i])
		}
	}
	return r
}

/*
Unshift right-shifts the receiver instance to remove [Right] x, if present.
*/
func (r Permission) Unshift(x ...any) Permission {
	if err := r.Valid(); err == nil {
		for i := 0; i < len(x); i++ {
			r.aCIPermission.unshift(x[i]) //rights.cast().Unshift(x[i])
		}
	}
	return r
}

/*
IsZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r Permission) IsZero() bool {
	return r.aCIPermission.isZero()
}

func (r *aCIPermission) isZero() bool {
	if r == nil {
		return true
	}

	return r.bool == nil && r.aCIRights == nil
}

/*
Valid returns a non-error instance if the receiver fails to pass basic validity checks.
*/
func (r Permission) Valid() (err error) {
	if !r.IsZero() {
		if r.aCIPermission.bool == nil {
			err = errors.New("Permission: missing disposition")
		}
	} else {
		err = nilInstanceErr
	}

	return
}

//// OID

/*
ObjectIdentifier implements a storage type for slices of string OID instances.

Instances of this type are only used in [TargetRuleItem] instances which bear either the
[TargetCtrl] or [TargetExtOp] keywords.
*/
type ObjectIdentifier struct {
	TargetKeyword
	*aCIObjectIdentifier
}

type aCIObjectIdentifier struct {
	slice []string
}

func (r aCIObjectIdentifier) string(mvq, pad bool) string {
	var s string
	if L := len(r.slice); L > 0 {
		var _s []string
		if mvq {
			for i := 0; i < L; i++ {
				_s = append(_s, `"`+r.slice[i]+`"`)
			}
		} else {
			for i := 0; i < L; i++ {
				_s = append(_s, r.slice[i])
			}
		}

		var delim string = `||`
		if pad {
			delim = ` || `
		}

		if s = strings.Join(_s, delim); !mvq {
			s = `"` + s + `"`
		}
	}

	return s
}

func (r aCIObjectIdentifier) contains(x any) bool {
	var contains bool
	var term string
	switch tv := x.(type) {
	case string:
		term = tv
	default:
		return false
	}

	for i := 0; i < len(r.slice) && !contains; i++ {
		contains = r.slice[i] == term
	}

	return contains
}

/*
TRM returns an instance of [TargetRuleMethods].

Each of the return instance's key values represent a single [Operator] that is allowed for use in the creation of [TargetRuleItem] instances which bear the receiver instance as an expression value. The value for each key is the actual instance method to -- optionally -- use for the creation of the [TargetRuleItem].

This is merely a convenient alternative to maintaining knowledge of which [Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [TargetRuleItem] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r ObjectIdentifier) TRM() TargetRuleMethods {
	return newACIv3TargetRuleMethods(aCITargetRuleFuncMap{
		Eq: r.Eq,
		Ne: r.Ne,
	})
}

/*
NewLDAPControlOIDs initializes a new instance of [ObjectIdentifier].

Instances of this design are used in the creation of [TargetRuleItem] instances that bear the [TargetCtrl] [TargetKeyword] context.

OIDs produced as a result of this function are expected to be LDAP Control Object Identifiers. Input instances must be string.
*/
func NewLDAPControlOIDs(x ...any) (ObjectIdentifier, error) {
	return marshalACIv3ObjectIdentifier(TargetCtrl, x...)
}

/*
NewLDAPExtendedOperationOIDs initializes a new instance of [ObjectIdentifier].

Instances of this design are used in the creation of [TargetRuleItem] instances that bear the [TargetExtOp] [TargetKeyword] context.

OIDs produced as a result of this function are expected to be LDAP Extended Operation Object Identifiers. Input instances must be string.
*/
func NewLDAPExtendedOperationOIDs(x ...any) (ObjectIdentifier, error) {
	return marshalACIv3ObjectIdentifier(TargetExtOp, x...)
}

func marshalACIv3ObjectIdentifier(kw TargetKeyword, x ...any) (r ObjectIdentifier, err error) {
	r = ObjectIdentifier{
		kw, // constrained by caller
		&aCIObjectIdentifier{},
	}

	for i := 0; i < len(x) && err == nil; i++ {
		_, err = r.push(x[i])
	}

	return
}

/*
IsZero returns the integer length of the receiver instance.
*/
func (r ObjectIdentifier) IsZero() bool {
	return r.aCIObjectIdentifier == nil
}

/*
Push appends one (1) or more unique numeric OID (string) values to the receiver instance.
*/
func (r ObjectIdentifier) Push(x ...any) ObjectIdentifier {
	oid, _ := r.push(x...)
	return oid
}

func (r ObjectIdentifier) push(x ...any) (ObjectIdentifier, error) {
	var err error
	if !r.IsZero() {
		for i := 0; i < len(x) && err == nil; i++ {
			switch tv := x[i].(type) {
			case string:
				if isObjectIdentifier(tv) && !r.aCIObjectIdentifier.contains(tv) {
					r.aCIObjectIdentifier.slice = append(r.aCIObjectIdentifier.slice, tv)
				}
			case ObjectIdentifier:
				if len(tv.aCIObjectIdentifier.slice) > 0 {
					r.aCIObjectIdentifier.slice = append(r.aCIObjectIdentifier.slice,
						tv.aCIObjectIdentifier.slice...)
				}
			}
		}
	}

	return r, err
}

/*
Len returns the integer length of the receiver instance.
*/
func (r ObjectIdentifier) Len() int {
	var i int
	if !r.IsZero() {
		i = len(r.aCIObjectIdentifier.slice)
	}

	return i
}

/*
Valid returns a Boolean value indicative of a valid receiver instance.
*/
func (r ObjectIdentifier) Valid() error {
	var err error
	if r.TargetKeyword == 0x0 || r.Len() == 0 {
		err = badACIv3OIDErr
	}

	return err
}

/*
Index returns the Nth instance of a string OID present within the receiver instance.
*/
func (r ObjectIdentifier) Index(idx int) string {
	var oid string
	if !r.IsZero() {
		if 0 <= idx && idx < r.Len() {
			oid = r.aCIObjectIdentifier.slice[idx]
		}
	}

	return oid
}

/*
Eq returns an instance of [TargetRuleItem] which represents a keyword-based equality
rule containing one (1) or more string OID instances.
*/
func (r ObjectIdentifier) Eq() TargetRuleItem {
	return r.newTR(Eq)
}

/*
Ne returns an instance of [TargetRuleItem] which represents a keyword-based negated
equality rule containing one (1) or more string OID instances.

Negated equality [TargetRuleItem] instances should be used with caution.
*/
func (r ObjectIdentifier) Ne() TargetRuleItem {
	return r.newTR(Ne)
}

func (r ObjectIdentifier) newTR(op Operator) TargetRuleItem {
	var tr TargetRuleItem = badACIv3TargetRuleItem
	t, err := newACIv3TargetRuleItem(r.TargetKeyword, op, r)
	if err == nil {
		tr = t
	}

	return tr
}

/*
Keyword returns the [TargetKeyword] associated with the receiver instance enveloped as a [TargetKeyword]. In the context of this type instance, the [TargetKeyword] returned is always [TargetExtOp] or [TargetCtrl].
*/
func (r ObjectIdentifier) Keyword() TargetKeyword {
	var kw TargetKeyword
	if !r.IsZero() {
		kw = r.TargetKeyword
	}

	return kw
}

/*
Contains returns a Boolean value indicative of whether value x, if a string instance already resides within the receiver instance.

Case is not significant in the matching process.
*/
func (r ObjectIdentifier) Contains(x any) bool {
	var contains bool
	if !r.IsZero() {
		contains = r.aCIObjectIdentifier.contains(x)
	}

	return contains
}

/*
SetQuotationStyle performs the iterative equivalent to the [TargetRuleItem.SetQuotationStyle] method, activating
the specified quotation style upon all such instances present within the receiver instance.
*/
func (r TargetRule) SetQuotationStyle(style int) TargetRule {
	if !r.IsZero() {
		for i := 0; i < r.Len(); i++ {
			r.Index(i).SetQuotationStyle(style)
		}
	}

	return r
}

/*
SetQuotationStyle allows the election of a particular multivalued quotation style offered by the various adopters of the ACIv3 syntax. In the context of a [TargetRuleItem], this will only have a meaningful impact if the keyword for the receiver is one (1) of the following:

  - [TargetCtrl]  (targetcontrol)
  - [TargetExtOp] (extop)
  - [Target]      (target)
  - [TargetTo]    (target_to)
  - [TargetFrom]  (target_from)
  - [TargetAttr]  (targetattr)

Additionally, the underlying type set as the expression value within the receiver MUST be a [TargetDistinguishedName], [Attribute] or [ObjectIdentifier] instance with two (2) or more values present.
*/
func (r TargetRuleItem) SetQuotationStyle(style int) TargetRuleItem {
	if !r.IsZero() {
		switch r.Expression().(type) {
		case TargetDistinguishedName, Attribute, ObjectIdentifier:
			switch r.Keyword() {
			case Target, TargetTo, TargetFrom, TargetAttr,
				TargetCtrl, TargetExtOp:
				r.aCITargetRuleItem.mvq = style == 0
			}
		}
	}

	return r
}

//// PERMISSION/BIND

/*
PermissionBindRule contains one (1) or more [PermissionBindRuleItem] instances.
*/
type PermissionBindRule struct {
	*aCIPermissionBindRule
}

type aCIPermissionBindRule struct {
	slice []PermissionBindRuleItem
}

func (r PermissionBindRule) Len() int {
	var l int
	if !r.IsZero() {
		l = len(r.aCIPermissionBindRule.slice)
	}

	return l
}

/*
Index returns the Nth [PermissionBindRuleItem] slice within the receiver instance.
*/
func (r PermissionBindRule) Index(idx int) PermissionBindRuleItem {
	var p PermissionBindRuleItem = badACIv3PBRItem
	if 0 <= idx && idx < r.Len() {
		p = r.aCIPermissionBindRule.slice[idx]
	}

	return p
}

/*
PermissionBindRuleItem contains one (1) [Permission] instance and one (1) [BindRule]
instance. Instances of this type are used within an [PermissionBindRule] instance.
*/
type PermissionBindRuleItem struct {
	*aCIPermissionBindRuleItem
}

type aCIPermissionBindRuleItem struct {
	Permission
	BindRule
}

/*
NewPermissionBindRule returns an instance of [PermissionBindRule] alongside an error following
an attempt to marshal x, which must be zero (0) or more instances of [PermissionBindRuleItem]
or equivalent string values.
*/
func NewPermissionBindRule(x ...any) (PermissionBindRule, error) {
	var (
		pbr PermissionBindRule = PermissionBindRule{&aCIPermissionBindRule{}}
		err error
	)

	if len(x) > 0 {
		pbr.Push(x...)
	}

	return pbr, err
}

/*
Push appends zero (0) or more valid instances of [PermissionBindRuleItem], or
string equivalents.
*/
func (r PermissionBindRule) Push(x ...any) PermissionBindRule {
	if !r.IsZero() {
		for i := 0; i < len(x); i++ {
			switch tv := x[i].(type) {
			case string:
				r.parse(tv)
			case PermissionBindRuleItem:
				if err := tv.Valid(); err == nil {
					r.aCIPermissionBindRule.slice =
						append(r.aCIPermissionBindRule.slice, tv)
				}
			}

		}
	}

	return r
}

/*
NewPermissionBindRuleItem returns an instance of [PermissionBindRuleItem], bearing the [Permission] P and the [BindRule]
B. The values P and B shall undergo validity checks per the conditions of the [PermissionBindRuleItem] Valid method
automatically. A bogus [PermissionBindRuleItem] is returned if such checks fail.

Instances of this kind are intended for append via the [PermissionBindRule.Push] method
*/
func NewPermissionBindRuleItem(x ...any) (PermissionBindRuleItem, error) {
	var (
		pbr PermissionBindRuleItem = PermissionBindRuleItem{&aCIPermissionBindRuleItem{}}
		err error
	)

	if len(x) == 0 {
		return pbr, err
	}

	switch tv := x[0].(type) {
	case string:
		err = pbr.parse(tv)
	case Permission:
		if err = tv.Valid(); err == nil {
			if len(x) == 2 {
				b, ok := x[1].(BindRule)
				if !ok {
					err = badACIv3PBRErr
				} else if err = b.Valid(); err == nil {
					pbr.aCIPermissionBindRuleItem.Permission = tv
					pbr.aCIPermissionBindRuleItem.BindRule = b
				}
			}
		}
	default:
		err = badACIv3PBRErr
	}

	return pbr, err
}

func (r *PermissionBindRule) parse(x string) (err error) {
	if r.IsZero() {
		r.aCIPermissionBindRule = &aCIPermissionBindRule{}
	}

	if idx := strings.IndexRune(x, ';'); idx == -1 {
		err = badACIv3PBRErr
	} else {
		sp := strings.Split(x, ";")
		for i := 0; i < len(sp) && err == nil; i++ {
			var pb PermissionBindRuleItem = PermissionBindRuleItem{
				&aCIPermissionBindRuleItem{},
			}
			if len(sp[i]) > 0 {
				if err = pb.parse(strings.TrimSpace(sp[i]) + ";"); err == nil {
					r.Push(pb)
				}
			}
		}
	}

	return err
}

func (r *PermissionBindRuleItem) parse(x string) (err error) {
	idx := strings.IndexRune(x, ')')
	if idx == -1 {
		err = badACIv3PBRErr
		return
	}

	p, err := marshalACIv3Permission(x[:idx+1])
	if err == nil {
		idx2 := strings.IndexRune(x, ';')
		if idx2 == -1 {
			err = badACIv3PBRErr
			return
		}

		var b BindRule
		var tkz []aCIBindRuleToken
		if tkz, err = tokenizeACIv3BindRule(x[idx+2 : idx2]); err == nil {
			if b, err = parseACIv3BindRuleTokens(tkz); err == nil {
				r.aCIPermissionBindRuleItem = &aCIPermissionBindRuleItem{
					Permission: p,
					BindRule:   b,
				}
				err = r.Valid()
			}
		}
	}

	return
}

/*
IsZero returns a Boolean value indicative of whether the receiver instance is nil, or unset.
*/
func (r PermissionBindRule) IsZero() bool {
	return r.aCIPermissionBindRule == nil
}

/*
IsZero returns a Boolean value indicative of whether the receiver instance is nil, or unset.
*/
func (r PermissionBindRuleItem) IsZero() bool {
	return r.aCIPermissionBindRuleItem == nil
}

/*
Permission returns the underlying [Permission] instance present within the receiver instance.
*/
func (r PermissionBindRuleItem) Permission() Permission {
	var p Permission = badACIv3Permission
	if !r.IsZero() {
		p = r.aCIPermissionBindRuleItem.Permission
	}

	return p
}

/*
BindRule returns the underlying [BindRule] instance present within the receiver instance.
*/
func (r PermissionBindRuleItem) BindRule() BindRule {
	var p BindRule = badACIv3BindRule
	if !r.IsZero() {
		p = r.aCIPermissionBindRuleItem.BindRule
	}

	return p
}

/*
Kind returns the string literal `permissionBindRule`.
*/
func (r PermissionBindRule) Kind() string {
	return pbrRuleIDStr
}

/*
Kind returns the string literal `permissionBindRuleItem`.
*/
func (r PermissionBindRuleItem) Kind() string {
	return pbrRuleItemIDStr
}

/*
Valid returns an error instance should any of the following conditions evaluate as true:

  - Valid returns an error for P
  - Valid returns an error for B
  - Len returns zero (0) for B
*/
func (r PermissionBindRule) Valid() (err error) {
	if r.IsZero() {
		err = nilInstanceErr
	}

	return
}

/*
Valid returns an error following a validity scan of the receiver instance.
*/
func (r PermissionBindRuleItem) Valid() (err error) {
	if r.IsZero() {
		err = nilInstanceErr
	} else {
		if err = r.aCIPermissionBindRuleItem.Permission.Valid(); err == nil {
			err = r.aCIPermissionBindRuleItem.BindRule.Valid()
		}
	}

	return
}

/*
String returns the string representation of the receiver.
*/
func (r PermissionBindRule) String() string {
	var s []string
	if !r.IsZero() {
		for i := 0; i < r.Len(); i++ {
			pbr := r.aCIPermissionBindRule.slice[i]
			s = append(s, pbr.String())
		}
	}

	return strings.Join(s, " ")
}

/*
String returns the string representation of the receiver.
*/
func (r PermissionBindRuleItem) String() string {
	var s string
	if !r.IsZero() {
		p := r.aCIPermissionBindRuleItem.Permission
		b := r.aCIPermissionBindRuleItem.BindRule
		if !p.IsZero() && !b.IsZero() {
			s += p.String() + " " + b.String() + ";"
		}
	}

	return s
}

//// TIME / DAY

/*
Day represents the numerical abstraction of a single day of the week, such as Sunday (1).
*/
type Day uint8

func marshalACIv3DayOfWeek(x ...any) (r DayOfWeek, err error) {
	r = newDoW()

	switch len(x) {
	case 0:
		return
	case 1:
		switch tv := x[0].(type) {
		case string:
			r.Shift(tv)
		case Day:
			r.Shift(tv)
		case DayOfWeek:
			r = tv
		}
	default:
		r.Shift(x...)
	}

	err = r.Valid()

	return
}

/*
parse will iterate a comma-delimited list and verify each slice as a day of the week and return a [DayOfWeek] instance alongside a Boolean value indicative of success.
*/
func (r DayOfWeek) parse(dow string) (err error) {
	r = newDoW()
	X := strings.Split(strings.ReplaceAll(dow, ` `, ``), `,`)
	for i := 0; i < len(X); i++ {
		dw := matchStrDoW(X[i])
		if dw == noDay {
			err = badACIv3DoWErr
			return
		}
		r.Shift(dw)
	}

	err = r.Valid()
	return
}

func matchDoW(d any) (D Day) {
	D = noDay
	switch tv := d.(type) {
	case int:
		D = matchIntDoW(tv)
	case string:
		D = matchStrDoW(tv)
	case Day:
		D = tv
	}

	return
}

func matchStrDoW(d string) (D Day) {
	D = noDay
	switch strings.ToLower(d) {
	case `sun`, `sunday`, `1`:
		D = Sunday
	case `mon`, `monday`, `2`:
		D = Monday
	case `tues`, `tuesday`, `3`:
		D = Tuesday
	case `wed`, `wednesday`, `4`:
		D = Wednesday
	case `thur`, `thurs`, `thursday`, `5`:
		D = Thursday
	case `fri`, `friday`, `6`:
		D = Friday
	case `sat`, `saturday`, `7`:
		D = Saturday
	}

	return
}

func matchIntDoW(d int) (D Day) {
	D = noDay
	switch d {
	case 1:
		D = Sunday
	case 2:
		D = Monday
	case 3:
		D = Tuesday
	case 4:
		D = Wednesday
	case 5:
		D = Thursday
	case 6:
		D = Friday
	case 7:
		D = Saturday
	}

	return
}

/*
NewDayOfWeek initializes, shifts and returns a new instance of [DayOfWeek] in one shot.
*/
func NewDayOfWeek(x ...any) (DayOfWeek, error) {
	return newDoW().Shift(x...), nil
}

/*
Keyword returns the [BindToD] [BindKeyword].
*/
func (r DayOfWeek) Keyword() Keyword {
	return BindDoW
}

/*
Len returns the abstract integer length of the receiver, quantifying the number of [Day] instances currently being expressed.

For example, if the receiver instance has its [Monday] and [Friday] [Day] bits enabled, this would represent an abstract length of two (2).
*/
func (r DayOfWeek) Len() int {
	var D int
	for i := 0; i < r.cast().Size(); i++ {
		if d := Day(1 << i); r.cast().Positive(d) {
			D++
		}
	}

	return D
}

/*
NewWeekdaysBindRule is a convenient prefabricator function that returns an instance of [BindRule] automatically assembled to express a sequence of weekdays. The sequence "[Monday] through [Friday]" can also be expressed via the bit-shifted value of sixty-two (62). See the [Day] constants for the specific numerals used for summation in this manner.

Supplying an invalid or nonapplicable [Operator] to this method shall return a bogus [BindRule] instance.
*/
func NewWeekdaysBindRule(cop any) (b BindRule) {
	if c, meth := newDoW().Shift(Monday, Tuesday, Wednesday,
		Thursday, Friday).BRM().index(cop); c.Valid() == nil {
		b = meth()
	}
	return
}

/*
NewWeekendBindRule is a convenient prefabricator function that returns an instance of [BindRule] automatically assembled to express a sequence of [Sunday] and [Saturday] [Day] instances. This sequence can also be expressed via the bit-shifted value of sixty-five (65). See the [Day] constants for the specific numerals used for summation in this manner.

Supplying an invalid or nonapplicable [Operator] to this method shall return a bogus [BindRule] instance.
*/
func NewWeekendBindRule(cop any) (b BindRule) {
	if c, meth := newDoW().Shift(Sunday, Saturday).BRM().index(cop); c.Valid() == nil {
		b = meth()
	}
	return
}

/*
Shift wraps [shifty.BitValue.Shift] method to allow for bit-shifting of the receiver (r) instance using various representations of any number of days (string, int or [Day]).
*/
func (r DayOfWeek) Shift(x ...any) DayOfWeek {
	// initialize receiver r if zero.
	if r.IsZero() {
		r = newDoW()
	}

	// assert each dow's type and analyze.
	// If deemed a valid dow, left-shift
	// into d.
	for i := 0; i < len(x); i++ {
		switch tv := x[i].(type) {
		case int, string:
			if dw := matchDoW(tv); dw != noDay {
				r.cast().Shift(dw)
			}
		case Day:
			r.cast().Shift(tv)
		}
	}

	return r
}

/*
Positive wraps the [shifty.BitValue.Positive] method.
*/
func (r DayOfWeek) Positive(x Day) (posi bool) {
	if !r.IsZero() {
		posi = r.cast().Positive(x)
	}
	return
}

/*
Unshift wraps [shifty.BitValue.Unshift] method to allow for bit-unshifting of the receiver (r) instance using various representations of any number of days (string, int or [Day]).
*/
func (r DayOfWeek) Unshift(x ...any) DayOfWeek {
	// can't unshift from nothing
	if r.IsZero() {
		return r
	}

	// assert each dow's type and analyze.
	// If deemed a valid dow, right-shift
	// out of d.
	for i := 0; i < len(x); i++ {
		switch tv := x[i].(type) {
		case int, string:
			if dw := matchDoW(tv); dw != noDay {
				r.cast().Unshift(dw)
			}
		case Day:
			r.cast().Unshift(tv)
		}
	}

	return r
}

/*
IsZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r DayOfWeek) IsZero() bool {
	return r.cast().Kind() == 0x0
}

/*
String returns the string representation of the receiver instance. At least one [Day] should register as positive in order for a valid string return to ensue.
*/
func (r DayOfWeek) String() (s string) {
	s = badDoWStr

	var dows []string
	for i := 0; i < r.cast().Size(); i++ {
		if day := Day(1 << i); r.Positive(day) {
			dows = append(dows, day.String())
		}
	}

	if len(dows) > 0 {
		s = strings.Join(dows, `,`)
	}

	return
}

/*
Valid returns a Boolean value indicative of whether the receiver contains one or more valid bits representing known [Day] values.

At least one [Day] must be positive within the receiver.
*/
func (r DayOfWeek) Valid() (err error) {
	if r.IsZero() {
		err = nilInstanceErr
	} else if r.String() == badDoWStr {
		err = badACIv3DoWErr
	}

	return
}

/*
Eq initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Equal-To the [BindDoW] [BindKeyword] context.
*/
func (r DayOfWeek) Eq() (b BindRule) {
	if err := r.Valid(); err == nil {
		b = newACIv3BindRuleItem(BindDoW, Eq, r)
	}
	return
}

/*
Ne initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Not-Equal-To the [BindDoW] [BindKeyword] context.

Negated equality [BindRule] instances should be used with caution.
*/
func (r DayOfWeek) Ne() (b BindRule) {
	if err := r.Valid(); err == nil {
		b = newACIv3BindRuleItem(BindDoW, Ne, r)
	}
	return
}

/*
BRM returns an instance of [BindRuleMethods].

Each of the return instance's key values represent a single instance of the [Operator]
type that is allowed for use in the creation of [BindRule] instances which bear the
receiver instance as an expression value. The value for each key is the actual [BindRuleMethod]
instance for OPTIONAL use in the creation of a [BindRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [Operator] instances
apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the
execution of ANY of the return instance's value methods will return bogus [BindRule] instances.
While this is useful in unit testing, the end user must only execute this method IF and WHEN the
receiver has been properly populated and prepared for such activity.
*/
func (r DayOfWeek) BRM() BindRuleMethods {
	return newACIv3BindRuleMethods(aCIBindRuleFuncMap{
		Eq: r.Eq,
		Ne: r.Ne,
	})
}

/*
String returns a single string name value for receiver instance of [Day].
*/
func (r Day) String() (day string) {
	day = badDoWStr
	switch r {
	case Sunday:
		day = `Sun`
	case Monday:
		day = `Mon`
	case Tuesday:
		day = `Tues`
	case Wednesday:
		day = `Wed`
	case Thursday:
		day = `Thur`
	case Friday:
		day = `Fri`
	case Saturday:
		day = `Sat`
	}

	return
}

/*
TimeOfDay is a [2]byte type used to represent a specific point in 24-hour time
using hours and minutes (such as 1215 for 12:15 PM, or 1945 for 7:45 PM). Instances
of this type contain a big endian unsigned 16-bit integer value, one that utilizes
the first and second slices. The value is used within [BindToD]-based [BindRule]
statements.
*/
type TimeOfDay struct {
	*aCITimeOfDay
}

/*
NewTimeOfDay initializes, sets and returns a new instance of [TimeOfDay] in one shot.
*/
func NewTimeOfDay(x ...any) (TimeOfDay, error) {
	return marshalACIv3TimeOfDay(x...)
}

func marshalACIv3TimeOfDay(x ...any) (r TimeOfDay, err error) {
	r.aCITimeOfDay = new(aCITimeOfDay)
	switch len(x) {
	case 0:
	default:
		switch tv := x[0].(type) {
		case string:
			r.Set(x[0])
		case TimeOfDay:
			r.Set(tv.String())
		}
	}

	err = r.Valid()

	return
}

type aCITimeOfDay [2]byte

/*
NewTimeframeBindRule is a convenience function that returns a [BindRule] instance for the purpose of expressing a timeframe during which access may (or may not) be granted. This is achieved by combining the two (2) [TimeOfDay] input values in a Boolean "AND stack".

The notBefore input value defines the so-called "start" of the timeframe. It should be chronologically earlier than notAfter. This value will be used to craft a Greater-Than-Or-Equal (Ge) [BindRule] expressive statement.

The notAfter input value defines the so-called "end" of the timeframe. It should be chronologically later than notBefore. This value will be used to craft a Less-Than (Lt) [BindRule] expressive statement.
*/
func NewTimeframeBindRule(notBefore, notAfter TimeOfDay) BindRule {
	return BindRuleAnd{&aCIBindRuleSlice{
		slice: []BindRule{notBefore.Ge(), notAfter.Lt()},
	}}
}

/*
Keyword returns the [BindToD] keyword instance.
*/
func (r TimeOfDay) Keyword() Keyword {
	return BindToD
}

/*
Eq initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Equal-To the [BindToD] [BindKeyword] context.
*/
func (r TimeOfDay) Eq() BindRule {
	br := badACIv3BindRule
	if err := r.Valid(); err == nil {
		br = newACIv3BindRuleItem(BindToD, Eq, r)
	}
	return br
}

/*
Ne initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Not-Equal-To the [BindToD] [BindKeyword] context.

Negated equality [BindRule] instances should be used with caution.
*/
func (r TimeOfDay) Ne() BindRule {
	br := badACIv3BindRule
	if err := r.Valid(); err == nil {
		br = newACIv3BindRuleItem(BindToD, Ne, r)
	}
	return br
}

/*
Lt initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Less-Than the [BindToD] [BindKeyword] context.
*/
func (r TimeOfDay) Lt() BindRule {
	br := badACIv3BindRule
	if err := r.Valid(); err == nil {
		br = newACIv3BindRuleItem(BindToD, Lt, r)
	}
	return br
}

/*
Le initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Less-Than-Or-Equal to the [BindToD] [BindKeyword] context.
*/
func (r TimeOfDay) Le() BindRule {
	br := badACIv3BindRule
	if err := r.Valid(); err == nil {
		br = newACIv3BindRuleItem(BindToD, Le, r)
	}
	return br
}

/*
Gt initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Greater-Than the [BindToD] [BindKeyword] context.
*/
func (r TimeOfDay) Gt() BindRule {
	br := badACIv3BindRule
	if err := r.Valid(); err == nil {
		br = newACIv3BindRuleItem(BindToD, Gt, r)
	}
	return br
}

/*
Ge initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Greater-Than-Or-Equal to the [BindToD] [BindKeyword] context.
*/
func (r TimeOfDay) Ge() BindRule {
	br := badACIv3BindRule
	if err := r.Valid(); err == nil {
		br = newACIv3BindRuleItem(BindToD, Ge, r)
	}

	return br
}

/*
BRM returns an instance of [BindRuleMethods].

Each of the return instance's key values represent a single instance of the [Operator] type that is allowed for use in the creation of [BindRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [BindRuleMethod] instance for OPTIONAL use in the creation of a [BindRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [BindRule] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r TimeOfDay) BRM() BindRuleMethods {
	return newACIv3BindRuleMethods(aCIBindRuleFuncMap{
		Eq: r.Eq,
		Ne: r.Ne,
		Lt: r.Lt,
		Le: r.Le,
		Gt: r.Gt,
		Ge: r.Ge,
	})
}

/*
String returns the string representation of the receiver instance.
*/
func (r TimeOfDay) String() string {
	s := badToDStr
	if !r.IsZero() {
		s = strconv.Itoa(int(binary.BigEndian.Uint16([]byte{r.aCITimeOfDay[0],
			r.aCITimeOfDay[1]})))
		for len(s) < 4 {
			s = "0" + s
		}
	}

	return s
}

/*
Valid returns a Boolean value indicative of whether the receiver is believed to be in a valid state.
*/
func (r TimeOfDay) Valid() (err error) {
	if r.IsZero() {
		err = nilInstanceErr
	}
	return
}

/*
IsZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r TimeOfDay) IsZero() bool {
	return r.aCITimeOfDay == nil
}

/*
Set encodes the specified 24-hour (a.k.a.: military) time value into the receiver instance.

Valid input types are string and [time.Time]. The effective hour and minute values, when combined, should ALWAYS fall within the valid clock range of 0000 up to and including 2400.  Bogus values within said range, such as 0477, will return an error.
*/
func (r TimeOfDay) Set(t any) TimeOfDay {
	r.aCITimeOfDay.set(t)
	return r
}

func (r *aCITimeOfDay) set(t any) {
	assertToD(r, t)
}

/*
assertToD is called by timeOfDay.set for the purpose of handling a potential clock time value for use in a [BindRule] statement.
*/
func assertToD(r *aCITimeOfDay, t any) {
	if r == nil {
		r = new(aCITimeOfDay)
	}
	switch tv := t.(type) {
	case time.Time:
		// time.Time input results in a recursive
		// run of this method.
		if !tv.IsZero() {
			h := strconv.Itoa(tv.Hour())
			m := strconv.Itoa(tv.Minute())
			if len(h) > 1 {
				h = "0" + h
			}
			if len(m) > 1 {
				m = "0" + m
			}
			r.set(h + m)
		}
	case string:
		// Handle discrepancy between ACIv3 time, which ends
		// at 2400, and Golang Time, which ends at 2359.
		var offset int
		if tv == `2400` {
			tv = `2359` // so time.Parse doesn't flip
			offset = 41 // so we can use it as intended per ACIv3 time syntax.
		}

		if _, err := time.Parse(`1504`, tv); err == nil {
			if n, err := strconv.Atoi(tv); err == nil {
				x := make([]byte, 2)
				binary.BigEndian.PutUint16(x, uint16(n+offset))
				for i := 0; i < 2; i++ {
					(*r)[i] = x[i]
				}
			}
		}
	}
}

//// SCOPE

/*
Scope extends the standard RFC4511 search scope to accommodate an additional scope,
"subordinate", for use in ACIv3-specific [URL]s, as well as for [TargetRuleItem]
composition where the [TargetScope] keyword is in use.
*/
type Scope uint8

/*
SearchScope constants define four (4) known LDAP Search Scopes permitted for use per
the ACIv3 syntax specification honored by this package.
*/
const (
	noScope          Scope = iota // 0x0 <unspecified_scope>
	ScopeBaseObject               // 0x1, `base`
	ScopeSingleLevel              // 0x2, `one` or `onelevel`
	ScopeSubtree                  // 0x3, `sub` or `subtree`
	ScopeSubordinate              // 0x4  `subordinate`
)

/*
NewSearchScope initializes, sets and returns an instance of [Scope] in one shot. Valid
input types are as follows:

  - Standard scope names as string values (e.g.: `base`, `onelevel`, `subtree` and `subordinate`)
  - Integer representations of scopes (see the predefined [Scope] constants for details)

This function may only be needed in certain situations where a scope needs to be
parsed from values with different representations. Usually the predefined [Scope]
constants are sufficient.
*/
func NewSearchScope(x ...any) (s Scope, err error) {
	return marshalACIv3SearchScope(x...)
}

func marshalACIv3SearchScope(x ...any) (s Scope, err error) {
	s = badACIv3Scope
	if len(x) > 0 {
		switch tv := x[0].(type) {
		case string:
			s = aCIStrToScope(tv)
		case int:
			s = aCIIntToScope(tv)
		default:
			err = badACIv3ScopeErr
		}
	} else {
		err = badACIv3ScopeErr
	}

	return
}

/*
Eq initializes and returns a new [TargetRuleItem] instance configured to express the
evaluation of the receiver value as Equal-To an [TargetScope] [TargetKeyword]
context.
*/
func (r Scope) Eq() TargetRuleItem {
	var tr TargetRuleItem = badACIv3TargetRuleItem

	if r != badACIv3Scope {
		tr, _ = newACIv3TargetRuleItem(TargetScope, Eq, r)
	}

	return tr
}

/*
Ne performs no useful task, as negated equality comparison does not apply to
[TargetRuleItem] instances that bear the [TargetScope] [TargetKeyword].

This method exists solely to satisfy Go's interface signature requirements.

This method SHALL NOT appear within instances of [TargetRuleMethods] that
were crafted through execution of the [Scope.TRM] method.
*/
func (r Scope) Ne() TargetRuleItem { return badACIv3TargetRuleItem }

/*
Keyword returns the [Keyword] associated with the receiver instance enveloped
as a [Keyword]. In the context of this type instance, the [TargetKeyword]
returned is always [TargetScope].
*/
func (r Scope) Keyword() Keyword {
	return TargetScope
}

/*
TRM returns an instance of [TargetRuleMethods].

Each of the return instance's key values represent a single [Operator] that
is allowed for use in the creation of [TargetRuleItem] instances which bear the
receiver instance as an expression value. The value for each key is the actual
instance method to -- optionally -- use for the creation of the [TargetRuleItem].

This is merely a convenient alternative to maintaining knowledge of which
[Operator] instances apply to which types. Instances of this type are also
used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet
been initialized, the execution of ANY of the return instance's value methods
will return bogus [TargetRuleItem] instances. While this is useful in unit testing,
the end user must only execute this method IF and WHEN the receiver has been properly
populated and prepared for such activity.
*/
func (r Scope) TRM() TargetRuleMethods {
	return newACIv3TargetRuleMethods(aCITargetRuleFuncMap{Eq: r.Eq})
}

/*
String returns the string representation of the receiver instance.
*/
func (r Scope) String() string {
	s := `<invalid_search_scope>`

	switch r {
	case ScopeBaseObject:
		s = `base`
	case ScopeSingleLevel:
		s = `onelevel`
	case ScopeSubtree:
		s = `subtree`
	case ScopeSubordinate:
		s = `subordinate` // seems to be an OUD thing.
	}

	return s
}

/*
strToScope returns an [Scope] constant based on the string input. If a match does not occur, [ScopeBaseObject] (default)
is returned.
*/
func aCIStrToScope(x string) (s Scope) {
	s = ScopeBaseObject
	switch strings.ToLower(x) {
	case `one`, `onelevel`:
		s = ScopeSingleLevel
	case `sub`, `subtree`:
		s = ScopeSubtree
	case `children`, `subordinate`:
		s = ScopeSubordinate
	}

	return
}

/*
intToScope returns an [Scope] constant based on the integer input. If a match does not occur, [ScopeBaseObject] (default)
is returned.
*/
func aCIIntToScope(x int) (s Scope) {
	s = ScopeBaseObject //default
	switch x {
	case 2:
		s = ScopeSingleLevel
	case 3:
		s = ScopeSubtree
	case 4:
		s = ScopeSubordinate
	}

	return
}

//// ATTRIBUTE+FILTER

/*
AttributeFilter is a struct type that embeds an [Attribute] and filter-style [TargetRule].
*/
type AttributeFilter struct {
	*aCIAttributeFilter
}

/*
aCIAttributeFilter is the embedded type (as a pointer!) within instances of AttributeFilter.
*/
type aCIAttributeFilter struct {
	Attribute     // single LDAP AttributeType
	filter.Filter // single LDAP Search Filter
}

type AttributeFilterOperationItem struct {
	*aCIAttributeFilterOperationItem
}

type aCIAttributeFilterOperationItem struct {
	AttributeOperation                   // add= or delete=
	slice              []AttributeFilter // 1* AttributeFilter; "&&" delim
}

/*
AttributeFilterOperation is the high-level composite type for use in creating [TargetRule]
instances which bear the [TargetAttrFilters] [Keyword].

Instances of this type require one (1) [AddOp]-based [AttributeFilterOperationItem] instance
and/or one (1) [DelOp]-based [AttributeFilterOperationItem] instance.
*/
type AttributeFilterOperation struct {
	*aCIAttributeFilterOperation
}

type aCIAttributeFilterOperation struct {
	add  AttributeFilterOperationItem
	del  AttributeFilterOperationItem
	semi bool // when true, override default comma (",") delimiter with semicolon (";")
}

/*
AttributeOperation defines either an Add Operation or a Delete Operation.

Constants of this type are used in [AttributeFilterOperation] instances.
*/
type AttributeOperation uint8

/*
NewAttributeFilter initializes, optionally sets and returns a new instance of [AttributeFilter], which is a critical component of the [TargetAttrFilters] Target Rule.

Input values must be either a [filter.Filter] or an [Attribute].
*/
func NewAttributeFilter(x ...any) (AttributeFilter, error) {
	var (
		af  AttributeFilter
		err error
	)

	switch len(x) {
	case 0:
		return af, err
	case 1:
		switch tv := x[0].(type) {
		case string:
			err = af.parse(tv)
		default:
			err = badACIv3AFOpItemErr
		}
	case 2:
		af.aCIAttributeFilter = &aCIAttributeFilter{}
		switch tv := x[0].(type) {
		case string:
			if isAttribute(tv) {
				af.aCIAttributeFilter.Attribute, err = marshalACIv3Attribute(tv)

				switch tv2 := x[1].(type) {
				case filter.Filter:
					af.aCIAttributeFilter.Filter = tv2
				case string:
					af.aCIAttributeFilter.Filter, err = filter.New(tv2)
				default:
					err = badACIv3AFOpItemErr
				}
			}
		case Attribute:
			if err = tv.Valid(); err == nil {
				af.aCIAttributeFilter.Attribute = tv

				switch tv2 := x[1].(type) {
				case filter.Filter:
					af.aCIAttributeFilter.Filter = tv2
				case string:
					af.aCIAttributeFilter.Filter, err = filter.New(tv2)
				default:
					err = badACIv3AFOpItemErr
				}
			}
		default:
			err = badACIv3AFOpItemErr
		}
	default:
		err = badACIv3AFOpItemErr
	}

	if err == nil {
		err = af.Valid()
	}

	return af, err

}

func NewAttributeFilterOperationItem(x ...any) (AttributeFilterOperationItem, error) {
	return marshalACIv3AttributeFilterOperationItem(x...)
}

func marshalACIv3AttributeFilterOperationItem(x ...any) (AttributeFilterOperationItem, error) {
	afoi := AttributeFilterOperationItem{&aCIAttributeFilterOperationItem{}}
	var err error

	switch len(x) {
	case 0:
		return afoi, err
	case 1:
		switch tv := x[0].(type) {
		case string:
			err = afoi.parse(tv)
		case AttributeFilterOperationItem:
			err = tv.Valid()
			afoi = tv
		default:
			err = badACIv3AFOpItemErr
		}
	case 2:
		switch tv := x[0].(type) {
		case AttributeOperation:
			switch tv2 := x[1].(type) {
			case AttributeFilter:
				afoi.aCIAttributeFilterOperationItem.AttributeOperation = tv
				afoi.aCIAttributeFilterOperationItem.slice = []AttributeFilter{tv2}
			default:
				err = badACIv3AFOpItemErr
			}
		default:
			err = badACIv3AFOpItemErr
		}
	default:
		err = badACIv3AFOpItemErr
	}

	if err == nil {
		err = afoi.Valid()
	}

	return afoi, err
}

func NewAttributeFilterOperation(x ...any) (AttributeFilterOperation, error) {
	return marshalACIv3AttributeFilterOperation(x...)
}

func marshalACIv3AttributeFilterOperation(x ...any) (AttributeFilterOperation, error) {
	afo := AttributeFilterOperation{&aCIAttributeFilterOperation{}}
	var err error

	switch len(x) {
	case 0:
		return afo, err
	case 1:
		switch tv := x[0].(type) {
		case string:
			var addPart, delPart string
			var semi bool
			addPart, delPart, semi, err = splitACIv3AttributeFilterOperation(tv)
			afo.aCIAttributeFilterOperation.semi = semi
			if addPart != "" {
				var add AttributeFilterOperationItem
				add, err = marshalACIv3AttributeFilterOperationItem(addPart)
				afo.aCIAttributeFilterOperation.add = add
			}
			if delPart != "" {
				var del AttributeFilterOperationItem
				del, err = marshalACIv3AttributeFilterOperationItem(delPart)
				afo.aCIAttributeFilterOperation.del = del
			}
		case AttributeFilterOperation:
			afo = tv
			err = tv.Valid()
		default:
			err = badACIv3AFOpItemErr
		}
	case 2:
		switch x[0].(type) {
		case AttributeOperation:
			switch tv2 := x[1].(type) {
			case AttributeFilterOperationItem:
				if tv2.Operation() == AddOp {
					afo.aCIAttributeFilterOperation.add = tv2
				} else if tv2.Operation() == DelOp {
					afo.aCIAttributeFilterOperation.del = tv2
				}
			default:
				err = badACIv3AFOpItemErr
			}
		default:
			err = badACIv3AFOpItemErr
		}
	default:
		err = badACIv3AFOpItemErr
	}

	if err == nil {
		err = afo.Valid()
	}

	return afo, err
}

/*
Set assigns the provided address component to the receiver and returns the receiver instance in fluent-form.

Multiple values can be provided in variadic form, or piecemeal.
*/
func (r *AttributeFilter) Set(x ...any) *AttributeFilter {
	if r.IsZero() {
		r.aCIAttributeFilter = new(aCIAttributeFilter)
	}

	r.aCIAttributeFilter.set(x...)
	return r
}

/*
AttributeType returns the underlying instance of [Attribute], or a bogus [Attribute] if unset.
*/
func (r AttributeFilter) Attribute() Attribute {
	var a Attribute = badACIv3Attribute
	if !r.IsZero() {
		a = r.aCIAttributeFilter.Attribute
	}

	return a
}

/*
Filter returns the underlying instance of [filter.Filter], or a bogus [filter.Filter] if unset.
*/
func (r AttributeFilter) Filter() filter.Filter {
	f := bogusFilter
	if !r.IsZero() {
		f = r.aCIAttributeFilter.Filter
	}

	return f
}

/*
set is a private method called by AttributeFilter.Set.
*/
func (r *aCIAttributeFilter) set(x ...any) {
	for i := 0; i < len(x); i++ {
		switch tv := x[i].(type) {
		case string:
			if isAttribute(tv) {
				r.Attribute, _ = marshalACIv3Attribute(tv)
			} else {
				r.Filter, _ = filter.New(tv)
			}
		case Attribute:
			r.Attribute = tv
		case filter.Filter:
			r.Filter = tv
		}
	}
}

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeFilter) String() string {
	var s string
	if err := r.Valid(); err == nil {
		s = r.aCIAttributeFilter.Attribute.Index(0) + ":" + r.aCIAttributeFilter.Filter.String()
	}

	return s
}

/*
Keyword returns the [TargetKeyword] associated with the receiver instance enveloped as a [Keyword]. In the context of this type instance, the [TargetKeyword] returned is always [TargetFilter].
*/
func (r AttributeFilter) Keyword() Keyword {
	return TargetAttrFilters
}

/*
Valid returns an error indicative of whether the receiver is in an aberrant state.
*/
func (r AttributeFilter) Valid() (err error) {
	if r.IsZero() {
		err = nilInstanceErr
	} else if r.aCIAttributeFilter.Filter == nil {
		err = endOfFilterErr
	} else if r.aCIAttributeFilter.Attribute.IsZero() {
		err = badACIv3AttributeErr
	}

	return
}

/*
IsZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r AttributeFilter) IsZero() bool {
	if r.aCIAttributeFilter == nil {
		return true
	}
	return r.aCIAttributeFilter.Filter == nil &&
		r.aCIAttributeFilter.Attribute.IsZero()
}

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeOperation) String() string {
	var o string = `add`
	if r == DelOp {
		o = `delete`
	}

	return o
}

/*
Keyword returns the [TargetKeyword] associated with the receiver instance. In the context of this type instance, the [TargetKeyword] returned is always [TargetAttrFilters].
*/
func (r AttributeFilterOperation) Keyword() Keyword {
	return TargetAttrFilters
}

/*
SetDelimiter controls the delimitation scheme employed by the receiver. A value of one (1) overrides the default
comma (",") delimiter with a semicolon (";").
*/
func (r AttributeFilterOperation) SetDelimiter(i ...int) AttributeFilterOperation {
	if !r.IsZero() {
		if len(i) == 0 {
			r.aCIAttributeFilterOperation.semi = false
		} else {
			r.aCIAttributeFilterOperation.semi = i[0] == 1
		}
	}

	return r
}

/*
Len returns the integer length of the receiver instance. The maximum length for instances of this
kind is two (2).
*/
func (r AttributeFilterOperation) Len() int {
	var l int
	if !r.IsZero() {
		if !r.aCIAttributeFilterOperation.add.IsZero() {
			l++
		}
		if !r.aCIAttributeFilterOperation.del.IsZero() {
			l++
		}
	}

	return l
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r AttributeFilterOperation) IsZero() bool {
	var z bool = true
	if r.aCIAttributeFilterOperation != nil {
		z = r.aCIAttributeFilterOperation.add.IsZero() &&
			r.aCIAttributeFilterOperation.del.IsZero()
	}

	return z
}

/*
Valid returns an error following a validity check.
*/
func (r AttributeFilterOperation) Valid() error {
	var err error
	if r.IsZero() {
		err = nilInstanceErr
	}

	return err
}

/*
Kind returns the categorical label assigned to the receiver.
*/
func (r AttributeFilterOperation) Kind() string {
	return TargetAttrFilters.String()
}

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeFilterOperation) String() string {
	var s string
	if !r.IsZero() {
		var sl []string
		if !r.aCIAttributeFilterOperation.add.IsZero() {
			sl = append(sl, r.aCIAttributeFilterOperation.add.String())
		}
		if !r.aCIAttributeFilterOperation.del.IsZero() {
			sl = append(sl, r.aCIAttributeFilterOperation.del.String())
		}

		var d string = ","
		if r.aCIAttributeFilterOperation.semi {
			d = ";"
		}
		s = strings.Join(sl, d)
	}

	return s
}

/*
Eq initializes and returns a new [TargetRule] instance configured to express the evaluation of the receiver value as Equal-To a [TargetAttrFilters] [TargetKeyword] context.
*/
func (r AttributeFilterOperation) Eq() TargetRuleItem {
	var tr TargetRuleItem = badACIv3TargetRuleItem
	t, err := newACIv3TargetRuleItem(TargetAttrFilters, Eq, r)
	if err == nil {
		tr = t
	}

	return tr
}

/*
Ne performs no useful task, as negated equality comparison does not apply to [TargetRule] instances that bear the [TargetAttrFilters] [TargetKeyword] context.

This method exists solely to convey this message and conform to Go's interface qualifying signature. When executed, this method will return a bogus [TargetRule].

Negated equality [TargetRule] instances should be used with caution.
*/
func (r AttributeFilterOperation) Ne() TargetRuleItem { return badACIv3TargetRuleItem }

/*
TRM returns an instance of [TargetRuleMethods].

Each of the return instance's key values represent a single instance of the [Operator] type that is allowed for use in the creation of [TargetRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [TargetRuleMethod] instance for  OPTIONAL use in the creation of a [TargetRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [Operator] instances apply to which types. Instances of this type  are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [TargetRule] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r AttributeFilterOperation) TRM() TargetRuleMethods {
	return newACIv3TargetRuleMethods(aCITargetRuleFuncMap{
		Eq: r.Eq,
		Ne: r.Ne,
	})
}

func (r AttributeFilterOperationItem) Push(x ...any) AttributeFilterOperationItem {
	for i := 0; i < len(x); i++ {
		switch tv := x[i].(type) {
		case string:
			_ = r.parse(tv)
		case AttributeFilter:
			if tv.Valid() == nil {
				r.aCIAttributeFilterOperationItem.slice =
					append(r.aCIAttributeFilterOperationItem.slice, tv)
			}
		}
	}

	return r
}

/*
Keyword returns the [TargetKeyword] associated with the receiver instance enveloped as a [Keyword]. In the context of this type instance, the [TargetAttrFilters] [TargetKeyword] context is always returned.
*/
func (r AttributeFilterOperationItem) Keyword() Keyword {
	return TargetAttrFilters
}

/*
Len returns the integer length of the receiver instance.
*/
func (r AttributeFilterOperationItem) Len() int {
	var l int
	if !r.IsZero() {
		l = len(r.aCIAttributeFilterOperationItem.slice)
	}

	return l
}

/*
Index returns the Nth instance of [AttributeFilter] present within the receiver instance.
*/
func (r AttributeFilterOperationItem) Index(idx int) AttributeFilter {
	var af AttributeFilter
	if !r.IsZero() {
		if 0 <= idx && idx < r.Len() {
			af = r.aCIAttributeFilterOperationItem.slice[idx]
		}
	}

	return af
}

/*
Contains returns a Boolean value indicative of whether the type and its value were located within the receiver.

Valid input types are [AttributeFilter] or a valid string equivalent.

Case is significant in the matching process.
*/
func (r AttributeFilterOperationItem) Contains(x any) bool {
	var found bool
	if r.Len() == 0 {
		return found
	}

	var candidate string

	switch tv := x.(type) {
	case string:
		candidate = tv
	case AttributeFilter:
		candidate = tv.String()
	default:
		return found
	}

	for i := 0; i < r.Len() && !found; i++ {
		// case is significant here.
		found = r.Index(i).String() == candidate
	}

	return found
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r AttributeFilterOperationItem) IsZero() bool {
	return r.aCIAttributeFilterOperationItem == nil
}

/*
Valid returns an error following an analysis of the receiver instance.
*/
func (r AttributeFilterOperationItem) Valid() error {
	var err error

	if !r.IsZero() {
		if r.aCIAttributeFilterOperationItem.AttributeOperation == 0 ||
			len(r.aCIAttributeFilterOperationItem.slice) == 0 {
			err = badACIv3AFOpItemErr
		}
	}

	return err
}

/*
Kind returns the kind of receiver instance.
*/
func (r AttributeFilterOperationItem) Kind() string {
	return TargetAttrFilters.String()
}

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeFilterOperationItem) String() string {
	var s string
	if !r.IsZero() {
		s = r.Operation().String() + `=`
		var f []string
		for i := 0; i < r.Len(); i++ {
			f = append(f, r.Index(i).String())
		}
		s += strings.Join(f, ` && `)
	}

	return s
}

/*
Eq initializes and returns a new [TargetRule] instance configured to express the evaluation of the receiver value as Equal-To a [TargetAttrFilters] [TargetKeyword] context.
*/
func (r AttributeFilterOperationItem) Eq() TargetRuleItem {
	var tr TargetRuleItem = badACIv3TargetRuleItem
	t, err := newACIv3TargetRuleItem(TargetAttrFilters, Eq, r)
	if err == nil {
		tr = t
	}

	return tr
}

/*
Ne performs no useful task, as negated equality comparison does not apply to [TargetRule] instances that bear the [TargetAttrFilters] [TargetKeyword] context.

This method exists solely to convey this message and conform to Go's interface qualifying signature. When executed, this method will return a bogus [TargetRule].

Negated equality [TargetRule] instances should be used with caution.
*/
func (r AttributeFilterOperationItem) Ne() TargetRuleItem { return badACIv3TargetRuleItem }

/*
TRM returns an instance of [TargetRuleMethods].

Each of the return instance's key values represent a single instance of the [Operator] type that is allowed for use in the creation of [TargetRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [TargetRuleMethod] instance for OPTIONAL use in the creation of a [TargetRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [TargetRule] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r AttributeFilterOperationItem) TRM() TargetRuleMethods {
	return newACIv3TargetRuleMethods(aCITargetRuleFuncMap{
		Eq: r.Eq,
		Ne: r.Ne,
	})
}

/*
Operation returns [AddOp], [DelOp] or an invalid operation if unspecified.
*/
func (r AttributeFilterOperationItem) Operation() AttributeOperation {
	var o AttributeOperation
	if !r.IsZero() {
		o = r.aCIAttributeFilterOperationItem.AttributeOperation
	}

	return o
}

// countACIv3AFOSubstr returns how many times substr occurs in s.
func countACIv3AFOSubstr(s, substr string) int {
	count := 0
	for {
		i := strings.Index(s, substr)
		if i == -1 {
			break
		}
		count++
		s = s[i+len(substr):]
	}
	return count
}

func splitACIv3AttributeFilterOperation(x string) (part1, part2 string, semi bool, err error) {
	// Trim the entire input first.
	s := strings.TrimSpace(x)

	// Find the delimiter (comma or semicolon) in the string.
	idx := strings.IndexAny(s, ",;")
	if idx == -1 {
		// No delimiter; only one value.
		part1 = s
	} else {
		semi = rune(s[idx]) == ';'

		// Split the string into two parts. We use TrimSpace
		// to allow optional spaces after the delimiter.
		part1 = strings.TrimSpace(s[:idx])
		part2 = strings.TrimSpace(s[idx+1:])
		if len(part2) == 0 {
			err = errors.New("empty second value after delimiter")
			return
		}
	}

	// Scan final result for conflicts
	err = checkACIv3AFOSubstr(part1, part2)
	return
}

func checkACIv3AFOSubstr(part1, part2 string) (err error) {
	// Each part must start with "add=" or "delete=".
	if !strings.HasPrefix(part1, "add=") && !strings.HasPrefix(part1, "delete=") {
		err = errors.New("first part must start with 'add=' or 'delete='")
	} else if part2 != "" && !strings.HasPrefix(part2, "add=") && !strings.HasPrefix(part2, "delete=") {
		err = errors.New("second part must start with 'add=' or 'delete='")
	} else if countACIv3AFOSubstr(part1, "add=") > 1 || countACIv3AFOSubstr(part1, "delete=") > 1 ||
		countACIv3AFOSubstr(part2, "add=") > 1 || countACIv3AFOSubstr(part2, "delete=") > 1 {
		err = errors.New("prefix appears more than once in one of the parts")
	} else if part2 != "" {
		if (strings.HasPrefix(part1, "add=") && strings.HasPrefix(part2, "add=")) ||
			(strings.HasPrefix(part1, "delete=") && strings.HasPrefix(part2, "delete=")) {
			err = errors.New("duplicate prefix in both parts")
		}
	}

	return
}

/*
parseACIv3AttributeFilterOperationItem parses the string input value (raw) and attempts to marshal its contents into an instance of AttributeFilterOperation (afo). An error is returned alongside afo upon completion of the attempt.
*/
func (r *AttributeFilterOperationItem) parse(raw string) error {
	r.aCIAttributeFilterOperationItem = &aCIAttributeFilterOperationItem{}

	aop, val, err := parseACIv3AttrFilterOperPreamble(raw)
	if err == nil {
		r.aCIAttributeFilterOperationItem.AttributeOperation = aop
		sp := strings.Split(val, `&&`)
		for i := 0; i < len(sp); i++ {
			var af AttributeFilter
			if err = af.parse(strings.TrimSpace(sp[i])); err == nil {
				r.Push(af)
			}

		}
	}

	return err
}

/*
parseACIv3AttributeFilterOperationItem parses the string input value (raw) and attempts to marshal its contents into an instance of AttributeFilter (af). An error is returned alongside af upon completion of the attempt.
*/
func (r *AttributeFilter) parse(raw string) (err error) {
	idx := strings.IndexRune(raw, ':')
	if idx == -1 {
		err = badACIv3AFErr
		return
	}

	var at Attribute
	if at, err = marshalACIv3Attribute(raw[:idx]); err != nil {
		return
	}

	var f filter.Filter
	if f, err = filter.New(raw[idx+1:]); err == nil {
		r.Set(at, f)
	}

	return
}

/*
parseACIv3AttributeFilterOperPreamble parses the string input value (raw) and attempts to  identify the prefix as a known instance of AttributeOperation. The inferred operation identifier, which shall be either 'add=' or 'delete=' is returned as value. An error is returned alongside aop and value upon completion of the attempt.
*/
func parseACIv3AttrFilterOperPreamble(raw string) (aop AttributeOperation, value string, err error) {
	switch {

	case strings.HasPrefix(raw, `add=`):
		aop = AddOp
		value = raw[4:]

	case strings.HasPrefix(raw, `delete=`):
		aop = DelOp
		value = raw[7:]

	default:
		err = badACIv3AFOpErr
	}

	return
}

//// NET

/*
IPAddress embeds slices of address values, allowing simple composition of flexible IP-based [BindRule] instances.
*/
type IPAddress struct {
	*aCIIPAddresses
}

/*
NewIPAddress initializes, sets and returns a new instance of [IPAddr] in one shot.
*/
func NewIPAddress(addr ...any) (IPAddress, error) {
	return marshalACIv3IPAddress(addr...)
}

func marshalACIv3IPAddress(x ...any) (r IPAddress, err error) {
	ip := new(aCIIPAddresses)
	for i := 0; i < len(x); i++ {
		switch tv := x[i].(type) {
		case string:
			ip.set(tv)
		case IPAddress:
			sp := strings.Split(tv.String(), `,`)
			ip.set(sp...)
		}
	}
	return IPAddress{ip}, nil
}

type aCIIPAddresses []aCIIPAddress
type aCIIPAddress string

/*
Keyword returns the [BindKeyword] instance assigned to the receiver instance as a [Keyword]. This shall be the [BindKeyword] that appears in a [BindRule] containing the receiver instance as the expression value.
*/
func (r FQDN) Keyword() Keyword {
	return BindDNS
}

/*
Eq initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Equal-To the [BindIP] [BindKeyword] context.
*/
func (r IPAddress) Eq() BindRule {
	var b BindRule = badACIv3BindRule
	if r.Valid() == nil {
		b = newACIv3BindRuleItem(BindIP, Eq, r)
	}

	return b
}

/*
Ne initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Not-Equal-To the [BindIP] [BindKeyword] context.

Negated equality [BindRule] instances should be used with caution.
*/
func (r IPAddress) Ne() BindRule {
	var b BindRule = badACIv3BindRule
	if r.Valid() == nil {
		b = newACIv3BindRuleItem(BindIP, Ne, r)
	}

	return b
}

/*
BRM returns an instance of [BindRuleMethods].

Each of the return instance's key values represent a single instance of the [Operator] type that is allowed for use in the creation of [BindRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [BindRuleMethod] instance for OPTIONAL use in the creation of a [BindRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus BindRule instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r IPAddress) BRM() BindRuleMethods {
	return newACIv3BindRuleMethods(aCIBindRuleFuncMap{
		Eq: r.Eq,
		Ne: r.Ne,
	})
}

/*
Len returns the integer length of the receiver instance.
*/
func (r IPAddress) Len() int {
	var l int
	if r.aCIIPAddresses != nil {
		l = len(*r.aCIIPAddresses)
	}

	return l
}

/*
Keyword returns the [BindKeyword] assigned to the receiver instance. This shall be the keyword that appears in a [BindRule] containing the receiver instance as the expression value.
*/
func (r IPAddress) Keyword() Keyword {
	return BindIP
}

/*
Kind returns the string representation of the receiver's kind.
*/
func (r IPAddress) Kind() string {
	return BindIP.String()
}

/*
Set assigns the provided address component to the receiver and returns the receiver instance in fluent-form.

Multiple values can be provided in variadic form, or piecemeal.
*/
func (r *IPAddress) Set(addr ...string) *IPAddress {
	if r.aCIIPAddresses == nil {
		r.aCIIPAddresses = new(aCIIPAddresses)
	}

	r.aCIIPAddresses.set(addr...)
	return r
}

func (r *aCIIPAddresses) set(addr ...string) {
	for i := 0; i < len(addr); i++ {
		if isValidIP(addr[i]) && r.unique(addr[i]) {
			*r = append(*r, aCIIPAddress(addr[i]))
		}
	}
}

func isValidIP(x string) bool {
	return isV4(x) || isV6(x)
}

func isV4(x string) bool {
	if len(x) <= 1 {
		return false
	}

	for c := 0; c < len(x); c++ {
		char := rune(byte(strings.ToLower(string(x[c]))[0]))
		if !isValidV4Char(char) {
			return false
		}
	}

	return true
}

func isValidV4Char(char rune) bool {
	return ('0' <= char && char <= '9') || char == '.' || char == '*' || char == '/'
}

func isV6(x string) bool {
	if len(x) <= 1 {
		return false
	}

	for c := 0; c < len(x); c++ {
		char := rune(byte(strings.ToLower(string(x[c]))[0]))
		if !isValidV6Char(char) {
			return false
		}
	}

	return true
}

func isValidV6Char(char rune) bool {
	return ('0' <= char && char <= '9') || ('a' <= char && char <= 'f') || char == ':' || char == '*' || char == '/'
}

/*
IsZero returns a Boolean value indicative of whether the receiver is considered nil, or unset.
*/
func (r IPAddress) IsZero() bool {
	if r.aCIIPAddresses == nil {
		return true
	}

	return r.aCIIPAddresses.isZero()
}

/*
Valid returns an error indicative of whether the receiver is in an aberrant state.
*/
func (r IPAddress) Valid() error {
	var err error
	if r.Len() == 0 {
		err = nilInstanceErr
	}

	return err
}

func (r *aCIIPAddresses) isZero() bool {
	return r == nil
}

/*
unique scans the receiver to verify whether the addr input value is not already present within the receiver.
*/
func (r IPAddress) unique(addr string) bool {
	var b bool = true
	if !r.IsZero() {
		b = r.aCIIPAddresses.unique(addr)
	}

	return b
}

func (r aCIIPAddresses) unique(addr string) bool {
	var addrs []string
	for i := 0; i < len(r); i++ {
		addrs = append(addrs, string(r[i]))
	}

	return !strInSlice(addr, addrs)
}

/*
String returns the string representation of an IP address.
*/
func (r IPAddress) String() string {
	var s string = badACIv3IPAddrStr
	if !r.isZero() {
		var str []string
		for i := 0; i < len(*r.aCIIPAddresses); i++ {
			str = append(str, string((*r.aCIIPAddresses)[i]))
		}
		s = strings.Join(str, `,`)
	}

	return s
}

//////////////////////////////////////////////////////////////////////////////////
// Begin DNS/FQDN
//////////////////////////////////////////////////////////////////////////////////

/*
domainLabel represents a single component within a fully-qualified domain name. Multiple occurrences of ordered instances of this type represent a complete FQDN, which may include wildcards (*), to be used in DNS-based ACIs.
*/
type domainLabel []byte
type aCIFQDNLabels []domainLabel

/*
FQDN contains ordered domain labels that form a fully-qualified domain name.
*/
type FQDN struct {
	*aCIFQDNLabels
}

/*
NewFQDN initializes, sets and returns a new instance of [FQDN] in one shot.
*/
func NewFQDN(x ...any) (FQDN, error) {
	return marshalACIv3FQDN(x...)
}

func marshalACIv3FQDN(x ...any) (r FQDN, err error) {
	dns := new(aCIFQDNLabels)
	for i := 0; i < len(x); i++ {
		switch tv := x[i].(type) {
		case string:
			dns.set(tv)
		case FQDN:
			sp := strings.Split(tv.String(), `,`)
			dns.set(sp...)
		}
	}

	r = FQDN{dns}
	if len(x) > 0 {
		err = r.Valid()
	}

	return
}

/*
Len returns the abstract integer length of the receiver. The value returned represents the number of valid DNS labels within a given instance of [FQDN]. For example, `www.example.com` has three (3) such labels.
*/
func (r FQDN) Len() int {
	var l int
	if r.aCIFQDNLabels != nil {
		l = len(*r.aCIFQDNLabels)
	}

	return l
}

/*
Set appends one or more domain labels to the receiver. The total character length of a single label CANNOT exceed sixty-three (63) characters.  When added up, all domain label instances present within the receiver SHALL NOT collectively exceed two hundred fifty-three (253) characters.

Valid characters within labels:

  - a-z
  - A-Z
  - 0-9
  - Hyphen ('-', limited to [1:length-1] slice range)
  - Asterisk ('*', use with care for wildcard DNS-based ACI [BindRule] expressions)
  - Full Stop ('.', see below for remarks on this character)

Users need not enter full stops (.) manually, given this method supports the use of variadic expressions, i.e.:

	Set(`www`,`example`,`com`)

However, should full stops (.) be used within input values:

	Set(`www.example.com`)

... the parser shall split the input into label components and add them to the receiver piecemeal in the intended order.

Please note that it is not necessary to include a NULL terminating full stop character (.) at the end (TLD?) of the intended [FQDN].
*/
func (r *FQDN) Set(x ...any) *FQDN {
	if r.IsZero() {
		r.aCIFQDNLabels = new(aCIFQDNLabels)
	}

	for i := 0; i < len(x); i++ {
		if str, ok := x[i].(string); ok {
			r.aCIFQDNLabels.set(str)
		}
	}

	return r
}

func (r *aCIFQDNLabels) set(label ...string) {
	if len(label) == 0 {
		return
	}

	dl, c, ok := processLabel(label...)
	if !ok {
		return
	}

	// Only update the receiver if
	// we haven't breached the high
	// water mark ...
	if len(*r)+c <= fqdnMax {
		for l := 0; l < len(dl); l++ {
			*r = append(*r, dl[l])
		}
	}

	return
}

func processLabel(label ...string) (dl aCIFQDNLabels, c int, ok bool) {
	for i := 0; i < len(label); i++ {
		if idx := strings.IndexRune(label[i], '.'); idx != -1 {
			sp := strings.Split(label[i], `.`)
			for j := 0; j < len(sp); j++ {
				// null label doesn't
				// need to stop the
				// show.
				if !validLabel(sp[j]) {
					return
				}
				c += len(sp[j])
				dl = append(dl, domainLabel(sp[j]))
			}
		} else {
			if !validLabel(label[i]) {
				return
			}
			c += len(label[i])
			dl = append(dl, domainLabel(label[i]))
		}
	}

	ok = c > 0 && len(dl) > 0
	return
}

/*
String returns the string representation of a fully-qualified domain name.
*/
func (r FQDN) String() string {
	var s string = badACIv3FQDNStr

	if err := r.Valid(); err == nil {
		var str []string

		for i := 0; i < len(*r.aCIFQDNLabels); i++ {
			str = append(str, string((*r.aCIFQDNLabels)[i]))
		}

		s = strings.Join(str, `.`)
	}

	return s
}

/*
Eq initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Equal-To the [BindDNS] [BindKeyword] context.
*/
func (r FQDN) Eq() BindRule {
	if err := r.Valid(); err != nil {
		return badACIv3BindRule
	}
	return newACIv3BindRuleItem(BindDNS, Eq, r)
}

/*
Ne initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Not-Equal-To the [BindDNS] [BindKeyword] context.

Negated equality [BindRule] instances should be used with caution.
*/
func (r FQDN) Ne() BindRule {
	if err := r.Valid(); err != nil {
		return badACIv3BindRule
	}
	return newACIv3BindRuleItem(BindDNS, Ne, r)
}

/*
BRM returns an instance of [BindRuleMethods].

Each of the return instance's key values represent a single instance of the [Operator] type that is allowed for use in the creation of [BindRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [BindRuleMethod] instance for OPTIONAL use in the creation of a [BindRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [BindRule] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r FQDN) BRM() BindRuleMethods {
	return newACIv3BindRuleMethods(aCIBindRuleFuncMap{
		Eq: r.Eq,
		Ne: r.Ne,
	})
}

/*
IsZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r FQDN) IsZero() bool {
	return r.aCIFQDNLabels.isZero()
}

func (r *aCIFQDNLabels) isZero() bool {
	return r == nil
}

/*
Valid returns a Boolean value indicative of whether the receiver contents represent a legal fully-qualified domain name value.
*/
func (r FQDN) Valid() (err error) {
	L := r.len()

	if !(0 < L && L <= fqdnMax) || len(*r.aCIFQDNLabels) < 2 {
		err = badACIv3FQDNErr
	}

	// seems legit
	return
}

/*
Len returns the integer length of the receiver in terms of character count.
*/
func (r FQDN) len() int {
	if r.aCIFQDNLabels == nil {
		return 0
	}

	var c int
	for i := 0; i < len(*r.aCIFQDNLabels); i++ {
		for j := 0; j < len(*r.aCIFQDNLabels); j++ {
			c++
		}
	}

	return c
}

/*
validLabel returns a Boolean value indicative of whether the input value (label) represents a valid label component for use within a fully-qualified domain.
*/
func validLabel(label string) bool {
	// Cannot exceed maximum component lengths!
	if !(0 < len(label) && len(label) <= labelMax) {
		return false
	}

	for i := 0; i < len(label); i++ {
		if ok := labelCharsOK(rune(label[i]), i, len(label)-1); !ok {
			return ok
		}
	}

	// seems legit
	return true
}

func labelCharsOK(c rune, i, l int) (ok bool) {
	// Cannot contain unsupported characters!
	if !isDigit(c) && !isAlpha(c) &&
		c != '.' && c != '*' && c != '-' {
		return
	}

	// Cannot begin or end with hyphen!
	if c == '-' && (i == 0 || i == l) {
		return
	}

	ok = true
	return
}

//// SECURITY

/*
NewAuthenticationMethod is a uint8 type that manifests through predefined package constants, each describing a supported means of LDAP authentication.
*/
type AuthenticationMethod uint8

func NewAuthenticationMethod(x ...any) (AuthenticationMethod, error) {
	return marshalACIv3AuthenticationMethod(x...)
}

/*
marshalACIv3AuthenticationMethod resolves a given authentication method based
on an integer or string input (x). If no match, an error is returned
*/
func marshalACIv3AuthenticationMethod(x ...any) (r AuthenticationMethod, err error) {
	switch len(x) {
	case 0:
		err = badACIv3AMErr
	default:
		switch tv := x[0].(type) {
		case int:
			for k, v := range authMap {
				if k == tv {
					r = v
					break
				}
			}
		case string:
			for k, v := range authNames {
				if strings.EqualFold(k, tv) {
					r = v
					break
				}
			}
		case AuthenticationMethod:
			if err = tv.Valid(); err == nil {
				r = tv
			}
		}
	}

	return
}

/*
BRM returns an instance of [BindRuleMethods].

Each of the return instance's key values represent a single instance of the [Operator] type that is allowed for use in the creation of [BindRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [BindRuleMethod] instance for OPTIONAL use in the creation of a [BindRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [BindRule] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r AuthenticationMethod) BRM() BindRuleMethods {
	return newACIv3BindRuleMethods(aCIBindRuleFuncMap{
		Eq: r.Eq,
		Ne: r.Ne,
	})
}

/*
Eq initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Equal-To the [BindAM] [BindKeyword] context.
*/
func (r AuthenticationMethod) Eq() BindRule {
	if r == noAuth {
		return badACIv3BindRule
	}
	return newACIv3BindRuleItem(BindAM, Eq, r)
}

/*
Ne initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Not-Equal-To the [BindAM] [BindKeyword] context.

Negated equality [BindRule] instances should be used with caution.
*/
func (r AuthenticationMethod) Ne() BindRule {
	if r == noAuth {
		return badACIv3BindRule
	}
	return newACIv3BindRuleItem(BindAM, Ne, r)
}

func (r AuthenticationMethod) Valid() (err error) {
	var found bool
	for k := range authNames {
		if strings.EqualFold(k, r.String()) {
			found = true
			break
		}
	}

	if !found {
		err = badACIv3AMErr
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r AuthenticationMethod) String() (am string) {
	for k, v := range authNames {
		if v == r {
			am = foldACIv3AuthenticationMethod(k)
			break
		}
	}

	return
}

/*
SecurityStrengthFactor embeds a pointer to uint8. A nil uint8 value indicates an effective security strength factor of zero (0). A non-nil uint8 value expresses uint8 + 1, thereby allowing a range of 0-256 "within" a uint8 instance.
*/
type SecurityStrengthFactor struct {
	*ssf
}

type ssf struct {
	*uint8
}

/*
NewSecurityStrengthFactor initializes, sets and returns a new instance of [SecurityStrengthFactor] in one shot.
*/
func NewSecurityStrengthFactor(x ...any) (SecurityStrengthFactor, error) {
	return marshalACIv3SecurityStrengthFactor(x...)
}

func marshalACIv3SecurityStrengthFactor(x ...any) (r SecurityStrengthFactor, err error) {
	r = SecurityStrengthFactor{new(ssf)}
	switch len(x) {
	case 0:
		return
	default:
		switch tv := x[0].(type) {
		case string, int:
			r.ssf.set(tv)
		case SecurityStrengthFactor:
			r.ssf.set(tv.String())
		}
	}

	err = r.Valid()

	return
}

/*
Keyword returns the BindKeyword assigned to the receiver instance enveloped as a [Keyword]. This shall be the keyword that appears in a [BindRule] containing the receiver instance as the expression value.
*/
func (r SecurityStrengthFactor) Keyword() Keyword {
	return BindSSF
}

/*
IsZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r SecurityStrengthFactor) IsZero() bool {
	if r.ssf == nil {
		return true
	}

	return r.uint8 == nil
}

/*
Eq initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Equal-To the [BindSSF] [BindKeyword] context.
*/
func (r SecurityStrengthFactor) Eq() BindRule {
	return newACIv3BindRuleItem(BindSSF, Eq, r)
}

/*
Ne initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Not-Equal-To the [BindSSF] [BindKeyword] context.

Negated equality [BindRule] instances should be used with caution.
*/
func (r SecurityStrengthFactor) Ne() BindRule {
	return newACIv3BindRuleItem(BindSSF, Ne, r)
}

/*
Lt initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Less-Than the [BindSSF] [BindKeyword] context.
*/
func (r SecurityStrengthFactor) Lt() BindRule {
	return newACIv3BindRuleItem(BindSSF, Lt, r)
}

/*
Le initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Less-Than-Or-Equal to the [BindSSF] [BindKeyword] context.
*/
func (r SecurityStrengthFactor) Le() BindRule {
	return newACIv3BindRuleItem(BindSSF, Le, r)
}

/*
Gt initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Greater-Than the [BindSSF] [BindKeyword] context.
*/
func (r SecurityStrengthFactor) Gt() BindRule {
	return newACIv3BindRuleItem(BindSSF, Gt, r)
}

/*
Ge initializes and returns a new [BindRule] instance configured to express the evaluation of the receiver value as Greater-Than-Or-Equal to the [BindSSF] [BindKeyword] context.
*/
func (r SecurityStrengthFactor) Ge() BindRule {
	return newACIv3BindRuleItem(BindSSF, Ge, r)
}

/*
BRM returns an instance of [BindRuleMethods].

Each of the return instance's key values represent a single instance of the [Operator] type that is allowed for use in the creation of [BindRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [BindRuleMethod] instance for OPTIONAL use in the creation of a [BindRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [BindRule] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r SecurityStrengthFactor) BRM() BindRuleMethods {
	return newACIv3BindRuleMethods(aCIBindRuleFuncMap{
		Eq: r.Eq,
		Ne: r.Ne,
		Lt: r.Lt,
		Le: r.Le,
		Gt: r.Gt,
		Ge: r.Ge,
	})
}

/*
String returns the string representation of the receiver instance.
*/
func (r SecurityStrengthFactor) String() string {
	var s string = `0`
	if !r.IsZero() {
		s = strconv.Itoa(int((*r.ssf.uint8)) + 1)
	}

	return s
}

/*
Valid returns nil and, at present, does nothing else. Based on the efficient design of the receiver type, there is no possible state that is technically invalid at ALL times. A nil instance may, in fact, be correct in particular situations.

Thus as there is no room for unforeseen errors with regards to this type specifically, this method has been gutted but remains present merely for the purpose of signature consistency throughout the package.
*/
func (r SecurityStrengthFactor) Valid() error { return nil }

func (r SecurityStrengthFactor) clear() {
	if !r.IsZero() {
		r.ssf.clear()
	}
}

func (r *ssf) clear() {
	if r != nil {
		r.uint8 = nil
	}
}

/*
Set modifies the receiver to reflect the desired security strength factor (SSF), which can represent any numerical value between 0 (off) and 256 (max).

Valid input types are int, string and nil.

A value of nil wipes out any previous value, making the SSF effectively zero (0).

A string value of `full` or `max` sets the SSF to its maximum value. A value of `none` or `off` has the same effect as when providing a nil value. A numerical string value is cast as int and (if valid) will be resubmitted silently. Case is not significant during the string matching process.

An int value less than or equal to zero (0) has the same effect as when providing a nil value. A value between 1 and 256 is acceptable and will be used. A value greater than 256 will be silently reduced back to the maximum.
*/
func (r *SecurityStrengthFactor) Set(factor any) SecurityStrengthFactor {
	if r.ssf == nil {
		r.ssf = new(ssf)
		r.ssf.uint8 = new(uint8)
	}
	r.ssf.set(factor)
	return *r
}

/*
set is called by [SecurityStrengthFactor.Set] to modify the underlying uint8 pointer in order to represent a security strength factor value.
*/
func (r *ssf) set(factor any) {
	switch tv := factor.(type) {
	case nil:
		r.clear()
	case string:
		i := stringToIntSSF(tv)
		if i == 0 {
			r.clear()
			return
		}
		r.set(i)
	case int:
		if tv > 256 {
			tv = 256
		} else if tv <= 0 {
			r.clear()
			return
		}

		v := uint8(tv - 1)
		r.uint8 = &v
	}

	return
}

func stringToIntSSF(x string) (i int) {
	switch strings.ToLower(x) {
	case `full`, `max`:
		i = 256
	case `none`, `off`:
		i = 0
	default:
		i, _ = strconv.Atoi(x)
	}

	return
}

/*
foldACIv3AuthenticationMethod executes the string representation case-folding, per whatever value is assigned to the global ACIv3AuthenticationMethodLowerCase variable.
*/
func foldACIv3AuthenticationMethod(x string) string {
	if AuthenticationMethodLowerCase {
		return strings.ToLower(x)
	}
	return strings.ToUpper(x)
}

/*
strInSlice returns a Boolean value indicative of the presence of
r within the input slice value.  The optional variadic input value
cEM indicates whether the matching process should recognize exact
case folding.

By default, case is not significant in the matching process.
*/
func strInSlice(r any, slice []string, cEM ...bool) (match bool) {
	// assume caseIgnoreMatch by default
	funk := strings.EqualFold
	if len(cEM) > 0 {
		if cEM[0] {
			// use caseExactMatch
			funk = streq
		}
	}

	switch tv := r.(type) {
	case string:
		for i := 0; i < len(slice) && !match; i++ {
			match = funk(tv, slice[i])
		}
	case []string:
		for i := 0; i < len(tv) && !match; i++ {
			for j := 0; j < len(slice) && !match; j++ {
				match = funk(tv[i], slice[j])
			}
		}
	}

	return
}

func streq(a, b string) bool {
	return a == b
}

func isAlnum(r rune) bool {
	return isAlpha(r) || isDigit(r)
}

func isAlpha(r rune) bool {
	return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z'
}

func isDigit(r rune) bool {
	return '0' <= r && r <= '9'
}

func isWHSP(ch rune) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

func removeWHSP(a string) string {
	return strings.ReplaceAll(a, ` `, ``)
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

func isObjectIdentifier(o string) bool {
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

	var res bool = true // true by default
	for i := 1; i < len(O[1:]) && res; i++ {
		res = isValidArc(O[i])
	}

	return res
}

/*
isAttribute returns a boolean value indicative of whether val
describes a numeric OID or RFC 4512 descriptor ("descr").

This is used, specifically, it identify an schema definition's
"NAME" or specify any number of values for an ACIAttribute.
*/
func isAttribute(val string) (is bool) {
	if is = isObjectIdentifier(val); !is {
		is = isAttributeDescriptor(val)
	}

	return
}

func runeInSlice(r rune, slice []rune) bool {
	for i := 0; i < len(slice); i++ {
		if r == slice[i] {
			return true
		}
	}

	return false
}

/*
isIUint returns a Boolean value of true if x represents a member of
the integer / unsigned integer "family". Any size is allowed, so
long as it is a built-in primitive.

If a (valid) member is a pointer reference, it is dereferenced and
examined just the same.

Floats and complexes are ineligible and will return false as they
are not used in this package. Additionally, non-numerical types
shall return false. This would include structs, strings, maps, etc.
*/
func isIUint(x any) (is bool) {
	// create a reflect.Type abstract
	// instance using raw input x.
	X := reflect.TypeOf(x)

	// disenvelop the instance if
	// it is a pointer reference.
	if isPtr(x) {
		X = X.Elem()
	}

	// perform a reflect.Kind switch upon
	// reflect.Type instance X ...
	switch k := X.Kind(); k {

	// allow only the following "kinds":
	case reflect.Int, reflect.Uint,
		reflect.Int8, reflect.Uint8,
		reflect.Int16, reflect.Uint16,
		reflect.Int32, reflect.Uint32,
		reflect.Int64, reflect.Uint64,
		reflect.Uintptr:
		is = true
	}

	return
}

/*
getBitSize returns the max bit length capacity
for a given type.

Note this will only return a meaningful value if
x represents a numerical type, such as Day, Right
or Level (all of which are subject to bit shifts).
Passing inappropriate type instances, such as a
struct, string, etc., will return zero (0).

This function uses the reflect.Size method (and
thus unsafe.Sizeof) to obtain a uintptr, which
will be cast as an int, multiplied by eight (8)
and finally returned.
*/
func bitSize(x any) (bits int) {
	if x == nil {
		return
	}

	// create a reflect.Type abstract
	// instance using raw input x.
	X := reflect.TypeOf(x)

	// disenvelop the instance if
	// it is a pointer reference.
	if isPtr(x) {
		X = X.Elem()
	}

	// see if the instance is an int
	// or uint (or a variant of same)
	if isIUint(x) {
		bits = int(X.Size()) * 8
	}

	return
}

/*
isAttributeDescriptor scans the input string val and judges
whether it appears to qualify as a valid RFC 4512 descriptor
(or "descr"), in that:

  - it begins with an alpha
  - it ends with an alpha or digit
  - it contains only alphas, digits, hyphens or semicolons
  - it contains no consecutive hyphens or semicolons
*/
func isAttributeDescriptor(val string) bool {
	if len(val) == 0 {
		return false
	}

	// must begin with an alpha.
	if !isAlpha(rune(val[0])) {
		return false
	}

	// can only end in alnum.
	if !isAlnum(rune(val[len(val)-1])) {
		return false
	}

	for i := 0; i < len(val); i++ {
		ch := rune(val[i])
		switch {
		case isAlnum(ch):
			// ok
		case ch == ';', ch == '-':
			// ok
		default:
			return false
		}
	}

	return true
}

/*
isPtr returns a Boolean value indicative of whether kind
reflection revealed the presence of a pointer type.
*/
func isPtr(x any) bool {
	return reflect.TypeOf(x).Kind() == reflect.Ptr
}

/*
getStringer uses reflect to obtain and return a given
type instance's String ("stringer") method, if present.
If not, nil is returned.
*/
func getStringer(x any) (meth func() string) {
	if x != nil {
		if v := reflect.ValueOf(x); !v.IsZero() {
			if method := v.MethodByName(`String`); method.Kind() != reflect.Invalid {
				if _meth, ok := method.Interface().(func() string); ok {
					meth = _meth
				}
			}
		}
	}

	return
}

var bogusFilter filter.Filter

var (
	nilInstanceErr error = errors.New("Nil instance error")
	nilInputErr    error = errors.New("Nil input error")
	endOfFilterErr error = errors.New("Unexpected end of filter")
)

// ACI-specific errror
var (
	badACIv3ValAssignmentErr            error = errors.New("Unsupported ACI value assignment per keyword")
	badACIv3InheritanceLevelErr         error = errors.New("Invalid ACI inheritance level")
	badACIv3AttributeBindTypeOrValueErr error = errors.New("Invalid ACI AttributeBindTypeOrValue")
	badACIv3AttributeErr                error = errors.New("Invalid ACI attribute")
	badACIv3ATBTVErr                    error = errors.New("Invalid ACI attribute bind type or value")
	badACIv3InstructionErr              error = errors.New("Invalid ACI Instruction")
	badACIv3ScopeErr                    error = errors.New("Invalid ACI search scope")
	badACIv3FilterErr                   error = errors.New("Invalid ACI filter")
	badACIv3AFErr                       error = errors.New("Invalid ACI Attribute Filter")
	badACIv3AFOpErr                     error = errors.New("Invalid ACI Attribute Filter Operation")
	badACIv3AFOpItemErr                 error = errors.New("Invalid ACI Attribute Filter Operation Item")
	badACIv3AMErr                       error = errors.New("Invalid ACI authentication method")
	badACIv3KWErr                       error = errors.New("Invalid ACI keyword")
	badACIv3CopErr                      error = errors.New("Invalid ACI comparison operator")
	badACIv3InhErr                      error = errors.New("Invalid ACI inheritance statement")
	badACIv3DoWErr                      error = errors.New("Invalid ACI day of week value")
	badACIv3ToDErr                      error = errors.New("Invalid ACI time of day value")
	badACIv3FQDNErr                     error = errors.New("Invalid ACI FQDN")
	badACIv3OIDErr                      error = errors.New("Invalid ACI Object Identifier")
	badACIv3PermErr                     error = errors.New("Invalid ACI permission statement")
	badACIv3TRErr                       error = errors.New("Invalid ACI target rule statement")
	badACIv3BRErr                       error = errors.New("Invalid ACI bind rule statement")
	badACIv3PBRErr                      error = errors.New("Invalid ACI permission+bind rule statement")
	badACIv3BRExprErr                   error = errors.New("Invalid ACI bind rule expression")
	badACIv3BRTokenErr                  error = errors.New("Empty ACI bind rule token value")
	badACIv3BDNErr                      error = errors.New("Invalid ACI bind distinguished name")
	badACIv3TDNErr                      error = errors.New("Invalid ACI target distinguished name")
	badACIv3PushErr                     error = errors.New("Invalid ACI slice element")
	missingACIv3LvlsErr                 error = errors.New("Missing or invlaid ACI inheritance level(s)")
)

func init() {
	bogusFilter, _ = filter.New(`bogus`)

	aCIRightsMap = map[Right]string{
		NoAccess:        `none`,
		ReadAccess:      `read`,
		WriteAccess:     `write`,
		AddAccess:       `add`,
		DeleteAccess:    `delete`,
		SearchAccess:    `search`,
		CompareAccess:   `compare`,
		SelfWriteAccess: `selfwrite`,
		AllAccess:       `all`,
		ProxyAccess:     `proxy`,
		ImportAccess:    `import`,
		ExportAccess:    `export`,
	}

	// we want to resolve the *name*
	// of an Right into an actual
	// Right instance.
	aCIRightsNames = make(map[string]Right, 0)
	for k, v := range aCIRightsMap {
		aCIRightsNames[v] = k
	}

	aCILevelMap = map[int]InheritanceLevel{
		0: Level0,
		1: Level1,
		2: Level2,
		3: Level3,
		4: Level4,
		5: Level5,
		6: Level6,
		7: Level7,
		8: Level8,
		9: Level9,
	}

	aCILevelNumbers = map[string]InheritanceLevel{
		`0`: Level0,
		`1`: Level1,
		`2`: Level2,
		`3`: Level3,
		`4`: Level4,
		`5`: Level5,
		`6`: Level6,
		`7`: Level7,
		`8`: Level8,
		`9`: Level9,
	}

	aCIOperatorMap = map[string]Operator{
		Eq.String(): Eq,
		Ne.String(): Ne,
		Lt.String(): Lt,
		Le.String(): Le,
		Gt.String(): Gt,
		Ge.String(): Ge,
	}

	// populate the allowed comparison operator map per each
	// possible TargetRule keyword
	aCIPermittedTargetOperators = map[Keyword][]Operator{
		Target:            {Eq, Ne},
		TargetTo:          {Eq, Ne},
		TargetFrom:        {Eq, Ne},
		TargetCtrl:        {Eq, Ne},
		TargetAttr:        {Eq, Ne},
		TargetExtOp:       {Eq, Ne},
		TargetScope:       {Eq},
		TargetFilter:      {Eq, Ne},
		TargetAttrFilters: {Eq},
	}

	// populate the allowed comparison operator map per each
	// possible BindRule keyword
	aCIPermittedBindOperators = map[Keyword][]Operator{
		BindUDN: {Eq, Ne},
		BindRDN: {Eq, Ne},
		BindGDN: {Eq, Ne},
		BindIP:  {Eq, Ne},
		BindAM:  {Eq, Ne},
		BindDNS: {Eq, Ne},
		BindUAT: {Eq, Ne},
		BindGAT: {Eq, Ne},
		BindDoW: {Eq, Ne},
		BindSSF: {Eq, Ne, Lt, Le, Gt, Ge},
		BindToD: {Eq, Ne, Lt, Le, Gt, Ge},
	}

	// bindkeyword map
	aCIBindKeywordMap = map[Keyword]string{
		BindUDN: `userdn`,
		BindRDN: `roledn`,
		BindGDN: `groupdn`,
		BindUAT: `userattr`,
		BindGAT: `groupattr`,
		BindIP:  `ip`,
		BindDNS: `dns`,
		BindDoW: `dayofweek`,
		BindToD: `timeofday`,
		BindAM:  `authmethod`,
		BindSSF: `ssf`,
	}

	// targetkeyword map
	aCITargetKeywordMap = map[Keyword]string{
		Target:            `target`,
		TargetTo:          `target_to`,
		TargetAttr:        `targetattr`,
		TargetCtrl:        `targetcontrol`,
		TargetFrom:        `target_from`,
		TargetScope:       `targetscope`,
		TargetFilter:      `targetfilter`,
		TargetAttrFilters: `targattrfilters`,
		TargetExtOp:       `extop`,
	}

	// bindtype map
	aCIBTMap = map[BindType]string{
		BindTypeUSERDN:  `USERDN`,
		BindTypeROLEDN:  `ROLEDN`,
		BindTypeSELFDN:  `SELFDN`,
		BindTypeGROUPDN: `GROUPDN`,
		BindTypeLDAPURL: `LDAPURL`,
	}

	// authMap facilitates lookups of AuthenticationMethod
	// instances using their underlying numerical const
	// value; this is mostly used internally.
	authMap = map[int]AuthenticationMethod{
		0: Anonymous,
		1: Simple,
		2: SSL,
		3: SASL,
		4: DIGESTMD5,
		5: EXTERNAL,
		6: GSSAPI,
	}

	// authNames facilitates lookups of AuthenticationMethod
	// instances using their string representation. as the
	// lookup key.
	//
	// NOTE: case is not significant during string
	// *matching* (resolution); this is regardless
	// of the state of AuthenticationMethodLowerCase.
	authNames = map[string]AuthenticationMethod{
		`none`:   Anonymous, // anonymous is ALWAYS default
		`simple`: Simple,    // simple auth (DN + Password); no confidentiality is implied
		`ssl`:    SSL,       // authentication w/ confidentiality; SSL (LDAPS) and TLS (LDAP + STARTTLS)

		// NOTE: Supported SASL methods vary per impl.
		`sasl`:            SASL,      // *any* SASL mechanism
		`sasl EXTERNAL`:   EXTERNAL,  // only SASL/EXTERNAL mechanism, e.g.: TLS Client Auth w/ personal cert
		`sasl DIGEST-MD5`: DIGESTMD5, // only SASL/DIGEST-MD5 mechanism, e.g.: password encipherment
		`sasl GSSAPI`:     GSSAPI,    // only SASL/GSSAPI mechanism, e.g.: Kerberos Single Sign-On
	}
}
