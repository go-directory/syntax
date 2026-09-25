package syntax

/*
dn.go is a modified copy of "go-ldap/ldap/v3/dn.go", optimized for use
in the Go Directory suite.

See the LICENSE.go-ldap-DN file in the repository root.
*/

import (
	"bytes"
	"sort"
	"strings"
)

/*
DistinguishedName implements an RFC 4514 distinguished name. This
type is a modified version of the [go-ldap/DN] type. The purpose
of these modifications is to enhance performance of certain DN
related operations, particularly in cases where calls to a backend
database are made, or where DIT Structure Rule processing of a new
or renamed entry is underway.

The "RDNs" field is identical to that of the original implementation,
except that the [][RelativeDistinguishedName] slice type is replaced
by the formal [RDNSequence] type per RFC 4511 and no longer uses pointer
instances as slice members.

A "preproc" value of true will result in the fields mentioned below
being populated following successful parsing of the input distinguished
name.

The "Normal" and "Case" fields store the string representation of
the distinguished name value in lowercase-normalized and original
case forms respectively.

The "Attributes" field stores a map[string][]int instance which is
used to both inventory all used attributes uniquely, and to foster
interrogation of those elements. The []int values contain the slice
indices of the associated values residing within the "Values" field
instance.

The "Values" field stores unique [AttributeValue] slices of the values
present within the distinguished name.

The "Boundary" field serves to define the boundary of a sequence of
RDNs. For instance, in an environment which uses the "flattened"
root context of "dc=example,dc=com", it may be desirable to set the
"Boundary" to one (1). This means that RDN truncation should cease
when there is only one (1) comma delimiter remaining between two RDNs,
thus not leaving the caller with "dc=com", which may be bogus by
itself. A value of zero (0) -- the default -- means that truncation
will continue until there is only a single RDN remaining.

[go-ldap/DN]: https://github.com/go-ldap/ldap/v3
*/
type DistinguishedName struct {
	RDNs       RDNSequence
	Normal     LDAPDN
	Case       LDAPDN
	Attributes map[string][]int
	Values     []AttributeValue
	Boundary   uint
}

func (r DistinguishedName) Encode() ([]byte, error)  { return nil, nil }
func (r *DistinguishedName) Decode(enc []byte) error { return nil }

/*
LDAPDN implements the LDAPString representation of a distinguished name.
*/
type LDAPDN LDAPString

func NewLDAPDN(x []byte) (LDAPDN, error) {
	var dn LDAPDN
	d, err := parseDN(b2s(x))
	if err == nil {
		dn = []byte(d.String())
	}

	return dn, err
}

/*
String returns the string representation of the receiver instance.
*/
func (r LDAPDN) String() string { return b2s(r) }

/*
RDN returns only the [RelativeLDAPDN] component of the receiver instance.
*/
func (r LDAPDN) RDN() RelativeLDAPDN {
	var rdn RelativeLDAPDN
	sp := splitUnescapedBytes(r, tComma, tBSlash)
	if len(sp) > 0 && len(sp[0]) > 0 {
		rdn = RelativeLDAPDN(sp[0])
	}

	return rdn
}

/*
Superior combines a truncates the leading [RelativeLDAPDN] component, returning
the parent [LDAPDN].
*/
func (r LDAPDN) Superior() LDAPDN {
	var sup LDAPDN
	sp := splitUnescapedBytes(r, tComma, tBSlash)
	if len(sp) > 1 {
		sup = LDAPDN(bytes.Join(sp[1:], tComma))
	}

	return sup
}

/*
Subordinate combines a [RelativeLDAPDN] with the receiver instance
to assemble a new child [LDAPDN].
*/
func (r LDAPDN) Subordinate(child RelativeLDAPDN) LDAPDN {
	rdn := LDAPDN(append(child, tComma...))
	return append(rdn, r...)
}

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the receiver instance as an OCTET STRING.
*/
func (r LDAPDN) Encode() ([]byte, error) {
	_, err := parseDN(b2s(r))
	var out []byte
	if err == nil {
		out, err = OctetString(r).Encode()
	}

	return out, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated and must bear the OCTET STRING tag (0x04).
*/
func (r *LDAPDN) Decode(enc []byte) error {
	var o OctetString
	var err error
	if err = o.Decode(enc); err == nil {
		*r = LDAPDN(o)
	}

	return err
}

/*
RelativeLDAPDN implements the [LDAPString] representation of a relative
distinguished name.
*/
type RelativeLDAPDN LDAPString

func NewRelativeLDAPDN(x []byte) (RelativeLDAPDN, error) {
	var rdn RelativeLDAPDN
	d, err := parseDN(b2s(x))
	if err == nil {
		temp := DistinguishedName{RDNs: []RelativeDistinguishedName{d.RDNs[0]}}
		rdn = []byte(temp.String())
	}

	return rdn, err
}

/*
String returns the string representation of the receiver instance.
*/
func (r RelativeLDAPDN) String() string { return b2s(r) }

func (r RelativeLDAPDN) Encode() ([]byte, error) {
	return OctetString(r).Encode()
}

func (r *RelativeLDAPDN) Decode(enc []byte) error {
	var o OctetString
	var err error
	if err = o.Decode(enc); err == nil {
		*r = RelativeLDAPDN(o)
	}

	return err
}

/*
NewDistinguishedName returns an instance of [DistinguishedName] alongside
an error following an attempt to marshal x.

The preproc Boolean argument, when true, will perform pre-processing on
the [DistinguishedName], namely:

  - String representation capture
  - Case-folding
  - Type-to-Value(s) Indices mapping
*/
func NewDistinguishedName(x []byte, preproc bool) (DistinguishedName, error) {
	dn, err := parseDN(b2s(x))
	if err == nil && preproc {
		dn.preprocess()
	}

	return dn, err
}

func (r *DistinguishedName) preprocess() {
	str := r.String()
	r.Normal = []byte(strings.ToLower(str))
	r.Case = []byte(str)
	r.Attributes = make(map[string][]int)
	r.Values = make([]AttributeValue, 0)
	for i := 0; i < len(r.RDNs); i++ {
		for j := 0; j < len(r.RDNs[i].Attributes); j++ {
			atv := r.RDNs[i].Attributes[j]
			at := atv.Type.String()
			av := atv.Value
			if _, found := r.Attributes[at]; !found {
				r.Attributes[at] = []int{}
			}
			r.Attributes[at] = append(r.Attributes[at], len(r.Values))
			r.Values = append(r.Values, av)
		}
	}
}

/*
Depth returns the logical depth from leaf to root.

Under ordinary circumstances, in which the "Boundary" of the receiver
is the default of zero (0), this method simply returns the length of
the underlying "RDNs" slice.

However if a non-zero "Boundary" is set, it is subtracted from the
return value.
*/
func (r DistinguishedName) Depth() int {
	L := len(r.RDNs)
	if r.Boundary > 0 && uint(L) > r.Boundary {
		L = L - int(r.Boundary)
	}
	return L
}

/*
Root returns the root [DistinguishedName] alongside an error following
an attempt to truncate the receiver instance to the minimum number of
permitted [RelativeDistinguishedName] instances with respect to the
configured boundary.
*/
func (r DistinguishedName) Root() (root DistinguishedName, err error) {
	if L := uint(len(r.RDNs)); L > 0 {
		B := r.Boundary
		switch {
		case B == 0 || B > L:
			// No boundary is set, or boundary is bogus
			root.RDNs = append(root.RDNs, r.RDNs[len(r.RDNs)-1])
		default:
			root.RDNs = r.RDNs[r.Depth()-1:]
		}
		if len(r.Normal) > 0 {
			root.preprocess()
		}
	}

	return
}

/*
Superior returns a new instance of [DistinguishedName] alongside
an error following an attempt to read and process the immediate
superior naming context of the receiver instance.
*/
func (r DistinguishedName) Superior() (sup DistinguishedName, err error) {
	L := len(r.RDNs)
	if L-1 <= 0 {
		sup = r // we're at the root, just return it
		return
	} else if uint(L-1) < r.Boundary {
		sup = r // same as above, but with a boundary error
		err = syntaxError("DistinguishedName: boundary exceeded")
		return
	}

	sup = DistinguishedName{
		RDNs: r.RDNs[1:],
	}
	if len(r.Normal) > 0 {
		sup.preprocess()
	}

	return
}

/*
Subordinate returns a new instance of [DistinguishedName] alongside
an error follwing an attempt to create a direct descendant of the
receiver instance.

The input rdn value must be the string representation of a legal
[RelativeDistinguishedName].
*/
func (r DistinguishedName) Subordinate(rdn string) (sub DistinguishedName, err error) {
	var rDN DistinguishedName
	if rDN, err = parseDN(rdn); err == nil {
		sub.RDNs = append([]RelativeDistinguishedName{rDN.RDNs[0]}, r.RDNs...)
		if len(r.Normal) > 0 {
			sub.preprocess()
		}
	}

	return
}

func dN(x any) (ok bool, err error) {
	switch tv := x.(type) {
	case DistinguishedName:
		if len(tv.RDNs) == 0 {
			err = syntaxError("DistinguishedName: invalid instance")
		}
	case string:
		_, err = parseDN(tv)
	default:
		err = errorBadType("DistinguishedName")

	}
	return err == nil, err
}

/*
NameAndOptionalUID returns an error following an analysis of x in the
context of a Name and Optional UID.

From [§ 3.3.21 of RFC 4517]:

	NameAndOptionalUID = distinguishedName [ SHARP BitString ]

From [§ 3.3.2 of RFC 4517]:

	BitString    = SQUOTE *binary-digit SQUOTE "B"
	binary-digit = "0" / "1"

From [§ 1.4 of RFC 4512]:

	SHARP  = %x23   ; octothorpe (or sharp sign) ("#")
	SQUOTE = %x27   ; single quote ("'")

[§ 3.3.21 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.21
[§ 3.3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.2
[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
type NameAndOptionalUID struct {
	DN  DistinguishedName
	UID BitString `asn1:"optional"`
}

func nameAndOptionalUID(x any) (result bool, err error) {
	_, err = marshalNameAndOptionalUID(x)
	result = err == nil
	return
}

func marshalNameAndOptionalUID(x any) (nou NameAndOptionalUID, err error) {
	var raw string
	switch tv := x.(type) {
	case NameAndOptionalUID:
		nou = tv
		return
	case DistinguishedName:
		nou.DN = tv
		return
	default:
		if raw, err = assertString(x, 1, "Name and Optional UID"); err != nil {
			return
		}
	}

	var rev string
	for i := 0; i < len(raw); i++ {
		rev += string(raw[len(raw)-i-1])
	}

	var _l int = len(raw)
	if strings.HasPrefix(rev, `B'`) {
		var bitstring string = `'`

		for i := len(raw) - 2; i > 0; i-- {

			if raw[i-1] == '\'' || isDigit(rune(raw[i-1])) {
				bitstring += string(raw[i-1])
				continue
			}
			break
		}

		bitstring += `B`

		_l = _l - len(bitstring) - 1
		if delim := raw[_l]; delim != '#' {
			err = syntaxError("DistinguishedName: missing '#' delimiter for Name/UID pair; found ",
				string(delim))
			return
		}

		if nou.UID, err = marshalBitString(bitstring); err != nil {
			return
		}
	}

	var dn DistinguishedName
	if dn, err = parseDN(raw[:_l]); err == nil {
		nou.DN = dn
	}

	return
}

func distinguishedNameMatch(a, b any) (result bool, err error) {
	mkDN := func(x any) (dn DistinguishedName, err error) {
		switch tv := a.(type) {
		case []byte:
			dn, err = parseDN(b2s(tv))
		case DistinguishedName:
			if len(tv.RDNs) == 0 {
				err = syntaxError("DistinguishedName: nil instance")
				break
			}
			dn = tv
		case string:
			dn, err = parseDN(tv)
		default:
			err = errorBadType("DistinguishedName")
		}
		return
	}

	var dn1, dn2 DistinguishedName
	if dn1, err = mkDN(a); err == nil {
		if dn2, err = mkDN(b); err == nil {
			result = dn1.EqualFold(dn2)
		}
	}
	return
}

func uniqueMemberMatch(a, b any) (result bool, err error) {
	var nou1, nou2 NameAndOptionalUID
	if nou1, err = marshalNameAndOptionalUID(a); err != nil {
		return
	}

	if nou2, err = marshalNameAndOptionalUID(b); err != nil {
		return
	}

	if result, err = distinguishedNameMatch(nou1.DN, nou2.DN); err != nil || result {
		return
	}

	if len(nou1.UID.Bytes) == 0 && len(nou2.UID.Bytes) == 0 {
		result = true
	} else if len(nou1.UID.Bytes) != 0 && len(nou2.UID.Bytes) != 0 {
		result, err = bitStringMatch(nou1.UID, nou2.UID)
	}

	return
}

/*
RDNSequence implements the "RDNSequence" ASN.1 type per RFC 4514.
*/
type RDNSequence []RelativeDistinguishedName

func (r RDNSequence) Encode() ([]byte, error)  { return nil, nil }
func (r *RDNSequence) Decode(enc []byte) error { return nil }

/*
RelativeDistinguishedName implements the slice type of an instance of [RDNSequence], per
[§ 2 of RFC4514].

[§ 2 of RFC4514]: https://datatracker.ietf.org/doc/html/rfc4514#section-2
*/
type RelativeDistinguishedName struct {
	Attributes []AttributeTypeAndValue
}

/*
String returns the string representation of the receiver instance.
*/
func (r RelativeDistinguishedName) String() string {
	attrs := make([]string, len(r.Attributes))
	for i := range r.Attributes {
		attrs[i] = r.Attributes[i].String()
	}
	sort.Strings(attrs)
	return strings.Join(attrs, "+")
}

/*
String returns the string representation of the receiver instance.
*/
func (r DistinguishedName) String() string {
	var s string
	if s = b2s(r.Case); len(s) == 0 {
		rdns := make([]string, len(r.RDNs))
		for i := range r.RDNs {
			rdns[i] = r.RDNs[i].String()
		}
		s = strings.Join(rdns, ",")
	}

	return s
}

var dNDelimChars = map[byte]struct{}{
	0x2B: {}, // "+"
	0x2C: {}, // ","
	0x3B: {}, // ";"
}

// parseDN returns a distinguishedName or an error.
// The function respects https://tools.ietf.org/html/rfc4514
func parseDN(str string) (DistinguishedName, error) {
	var dn = DistinguishedName{RDNs: make([]RelativeDistinguishedName, 0)}
	if strings.TrimSpace(str) == "" {
		return dn, nil
	}

	var (
		rdn                   = RelativeDistinguishedName{}
		attr                  = AttributeTypeAndValue{}
		escaping              bool
		startPos              int
		appendAttributesToRDN = func(end bool) {
			rdn.Attributes = append(rdn.Attributes, attr)
			attr = AttributeTypeAndValue{}
			if end {
				dn.RDNs = append(dn.RDNs, rdn)
				rdn = RelativeDistinguishedName{}
			}
		}
	)

	// Loop through each character in the string and
	// build up the attribute type and value pairs.
	// We only check for ascii characters here, which
	// allows us to iterate over the string byte by byte.
	for i := 0; i < len(str); i++ {
		char := str[i]
		_, isDelim := dNDelimChars[char]
		switch {
		case escaping:
			escaping = false
		case char == '\\':
			escaping = true
		case char == '=' && len(attr.Type) == 0:
			if err := attr.setType(str[startPos:i]); err != nil {
				return DistinguishedName{}, err
			}
			startPos = i + 1
		case isDelim:
			if len(attr.Type) == 0 {
				return dn, syntaxError("DistinguishedName: incomplete type, value pair")
			}
			if err := attr.setValue(str[startPos:i]); err != nil {
				return DistinguishedName{}, err
			}

			startPos = i + 1
			last := char == ',' || char == ';'
			appendAttributesToRDN(last)
		}
	}

	if len(attr.Type) == 0 {
		return dn, syntaxError("DistinguishedName: ended with incomplete type, value pair")
	}

	err := attr.setValue(str[startPos:])
	if err == nil {
		appendAttributesToRDN(true)
	}

	return dn, err
}

/*
Equal returns true if the [DistinguishedName] instances are equal as defined by [§ 4.2.15 of RFC4517]
(distinguishedNameMatch).

Distinguished names are the same if and only if they have the same number of [AttributeTypeAndValue]
instances, and each attribute of the first RDN is the same as the attribute of the second RDN with
the same [AttributeType].

The order of attributes is not significant. Case-folding of the underlying [AttributeType] instances
is not significant, however case-folding of the underlying [AttributeValue] instances is.

See also [DistinguishedName.EqualFold].

[§ 4.2.15 of RFC4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.15
*/
func (r DistinguishedName) Equal(other DistinguishedName) bool {
	var is bool
	if is = len(r.RDNs) == len(other.RDNs); is {
		for i := 0; i < len(r.RDNs) && is; i++ {
			is = r.RDNs[i].Equal(other.RDNs[i])
		}
	}
	return is
}

/*
EqualFold returns true if the [DistinguishedName] instances are equal as defined by [§ 4.2.15 of RFC4517].
The sematics of this method are identical to those of [DistinguishedName.Equal], except that case-folding
is not significant for the underlying [AttributeValue] instance.

[§ 4.2.15 of RFC4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.15
*/
func (r DistinguishedName) EqualFold(other DistinguishedName) bool {
	var is bool
	if is = len(r.RDNs) == len(other.RDNs); is {
		for i := 0; i < len(r.RDNs) && is; i++ {
			is = r.RDNs[i].EqualFold(other.RDNs[i])
		}
	}
	return is
}

/*
Equal returns true if the [RelativeDistinguishedName] instances are equal as defined by [§ 4.2.15 of RFC4517]
(distinguishedNameMatch).

Relative distinguished names are the same if and only if they have the same number of [AttributeTypeAndValue]
instances, and each attribute of the first RDN is the same as the attribute of the second RDN with the same
[AttributeType].

The order of attributes is not significant. Case-folding of the underlying [AttributeType] instances
is not significant, however case-folding of the underlying [AttributeValue] instances is.

See also [RelativeDistinguishedName.EqualFold].

[§ 4.2.15 of RFC4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.15
*/
func (r RelativeDistinguishedName) Equal(other RelativeDistinguishedName) bool {
	var eq bool
	if len(r.Attributes) == len(other.Attributes) {
		eq = r.hasAllAttributes(other.Attributes) && other.hasAllAttributes(r.Attributes)
	}
	return eq
}

/*
EqualFold returns true if the [RelativeDistinguishedName] instances are equal as defined by [§ 4.2.15 of RFC4517].
The sematics of this method are identical to those of [RelativeDistinguishedName.Equal], except that case-folding
is not significant for the underlying [AttributeValue] instances.

[§ 4.2.15 of RFC4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.15
*/
func (r RelativeDistinguishedName) EqualFold(other RelativeDistinguishedName) bool {
	var eq bool
	if len(r.Attributes) == len(other.Attributes) {
		eq = r.hasAllAttributesFold(other.Attributes) && other.hasAllAttributesFold(r.Attributes)
	}
	return eq
}

/*
AncestorOf returns true if the other [DistinguishedName] consists of at least one
[RelativeDistinguishedName] followed by all the [RDNSequence] slices of the current
[DistinguishedName].

Case-folding of the underlying [AttributeType] instances is not significant, however
case-folding of the underlying [AttributeValue] instances is.

Examples:

  - "ou=widgets,o=acme.com" is an ancestor of "ou=sprockets,ou=widgets,o=acme.com"
  - "ou=widgets,o=acme.com" is not an ancestor of "ou=sprockets,ou=widgets,o=foo.com"
  - "ou=widgets,o=acme.com" is not an ancestor of "ou=widgets,o=acme.com"

See also [DistinguishedName.AncestorOfFold].
*/
func (r DistinguishedName) AncestorOf(other DistinguishedName) bool {
	if len(r.RDNs) >= len(other.RDNs) {
		return false
	}
	// Take the last `len(d.RDNs)` RDNs from the other DN to compare against
	otherRDNs := other.RDNs[len(other.RDNs)-len(r.RDNs):]
	for i := range r.RDNs {
		if !r.RDNs[i].Equal(otherRDNs[i]) {
			return false
		}
	}
	return true
}

/*
AncestorOf returns true if the other [DistinguishedName] consists of at least one
[RelativeDistinguishedName] followed by all the [RDNSequence] slices of the current
[DistinguishedName].

The sematics of this method are identical to those of [DistinguishedName.AncestorOf],
except that case-folding is not significant for the underlying [AttributeValue] instances.
*/
func (r DistinguishedName) AncestorOfFold(other DistinguishedName) bool {
	if len(r.RDNs) >= len(other.RDNs) {
		return false
	}
	// Take the last `len(d.RDNs)` RDNs from the other DN to compare against
	otherRDNs := other.RDNs[len(other.RDNs)-len(r.RDNs):]
	for i := range r.RDNs {
		if !r.RDNs[i].EqualFold(otherRDNs[i]) {
			return false
		}
	}
	return true
}

func (r RelativeDistinguishedName) hasAllAttributes(attrs []AttributeTypeAndValue) bool {
	// Each candidate attribute must match a distinct attribute of the receiver.
	// Without consuming matches this is a set containment test, so a multi-valued
	// RDN that repeats an attributeTypeAndValue would compare equal to one that
	// repeats a different pair the same number of times.
	matched := make([]bool, len(r.Attributes))
	for _, attr := range attrs {
		found := false
		for i, myattr := range r.Attributes {
			if matched[i] {
				continue
			}
			if myattr.Equal(attr) {
				matched[i] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (r RelativeDistinguishedName) hasAllAttributesFold(attrs []AttributeTypeAndValue) bool {
	// See hasAllAttributes: matches are consumed so multiplicity is respected.
	matched := make([]bool, len(r.Attributes))
	for _, attr := range attrs {
		found := false
		for i, myattr := range r.Attributes {
			if matched[i] {
				continue
			}
			if myattr.EqualFold(attr) {
				matched[i] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
