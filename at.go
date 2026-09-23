package syntax

/*
at.go contains Attribute related types and methods.
*/

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/go-directory/encoding/asn1"
)

type PartialAttributeList []PartialAttribute

func (r PartialAttributeList) Encode() ([]byte, error) {
	payload := make([]byte, 0)

	for _, pa := range r {
		enc, err := pa.Encode()
		if err != nil {
			return nil, err
		}
		payload = append(payload, enc...)
	}

	return asn1.WrapTLV(payload, uSeqTag())
}

func (r *PartialAttributeList) Decode(enc []byte) error {
	p := 0

	payload, err := asn1.ReadExpectedConstructedTLV(enc, &p,
		asn1.ClassUniversal, uint32(asn1.TagSequence))

	if err != nil {
		return err
	}

	*r = (*r)[:0]
	p2 := 0

	for p2 < len(payload) && err == nil {
		var childPayload []byte
		if childPayload, err = asn1.ReadExpectedConstructedTLV(payload, &p2,
			asn1.ClassUniversal, uint32(asn1.TagSequence)); err == nil {
			var pa PartialAttribute
			if err = pa.Decode(childPayload); err == nil {
				*r = append(*r, pa)
			}
		}
	}

	return err
}

type AttributeList []Attribute

func (r AttributeList) Encode() ([]byte, error) {
	// Encode each PartialAttribute
	payload := make([]byte, 0)

	for _, pa := range r {
		enc, err := pa.Encode()
		if err != nil {
			return nil, err
		}
		payload = append(payload, enc...)
	}

	// Wrap in SEQUENCE OF
	return asn1.WrapTLV(payload, uSeqTag())
}

func (r *AttributeList) Decode(enc []byte) error {
	p := 0

	// Read outer SEQUENCE OF or fail
	payload, err := asn1.ReadExpectedConstructedTLV(enc, &p,
		asn1.ClassUniversal, uint32(asn1.TagSequence))

	if err != nil {
		return err
	}

	// Decode children
	*r = (*r)[:0]
	p2 := 0

	for p2 < len(payload) && err == nil {
		// Each child is a PartialAttribute (SEQUENCE)
		var pa PartialAttribute

		// Read the child TLV
		var childPayload []byte
		if childPayload, err = asn1.ReadExpectedConstructedTLV(payload, &p2,
			asn1.ClassUniversal, uint32(asn1.TagSequence)); err == nil {
			if err = pa.Decode(childPayload); err == nil {
				*r = append(*r, pa)
			}
		}
	}

	return err
}

/*
PartialAttribute implements the partialAttribute type, per [§ 4.1.7 of RFC4511].

[§ 4.1.7 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.7
*/
type PartialAttribute struct {
	Type AttributeDescription
	Vals []AttributeValue
}

func (r PartialAttribute) Encode() ([]byte, error) {
	// Encode type
	typeEnc, err := r.Type.Encode()
	if err != nil {
		return nil, err
	}

	// Encode vals (SET OF)
	valsPayload := make([]byte, 0)
	for _, v := range r.Vals {
		enc, err := v.Encode()
		if err != nil {
			return nil, err
		}
		valsPayload = append(valsPayload, enc...)
	}

	valsEnc := asn1.WriteConstructedTLV(
		nil,
		asn1.ClassUniversal,
		true,
		uint32(asn1.TagSet),
		valsPayload,
	)

	// Build SEQUENCE payload
	seqPayload := make([]byte, 0)
	seqPayload = append(seqPayload, typeEnc...)
	seqPayload = append(seqPayload, valsEnc...)

	// Wrap in SEQUENCE
	final := asn1.WriteConstructedTLV(
		nil,
		asn1.ClassUniversal,
		true,
		uint32(asn1.TagSequence),
		seqPayload,
	)

	return final, nil
}

func (r *PartialAttribute) Decode(enc []byte) error {
	p := 0

	// If enc starts with SEQUENCE 0x30 (0x10 & constructed),
	// we will strip it as a first measure.
	if len(enc) > 0 && enc[0] == 0x30 {
		payload, err := asn1.ReadExpectedConstructedTLV(enc, &p,
			asn1.ClassUniversal, uint32(asn1.TagSequence))

		if err != nil {
			return err
		}
		enc = payload
		p = 0
	}

	if p+2 > len(enc) {
		return asn1Error("PartialAttribute.Decode: short type TLV")
	}
	if enc[p] != asn1.TagOctetString {
		return asn1Error("PartialAttribute.Decode: expected OCTET STRING, got ",
			strconv.Itoa(int(enc[p])))
	}
	typeLen := int(enc[p+1])
	if p+2+typeLen > len(enc) {
		return asn1Error("PartialAttribute.Decode: short type payload")
	}

	typePayload := enc[p+2 : p+2+typeLen]
	p += 2 + typeLen

	r.Type = AttributeDescription(typePayload)

	var valsPayload []byte
	var err error

	if valsPayload, err = asn1.ReadExpectedConstructedTLV(enc, &p,
		asn1.ClassUniversal, uint32(asn1.TagSet)); err == nil {

		r.Vals = r.Vals[:0]
		p2 := 0

		for p2 < len(valsPayload) {
			if p2+2 > len(valsPayload) {
				err = asn1Error("PartialAttribute.Decode: short value TLV")
				break
			}

			if valsPayload[p2] != asn1.TagOctetString {
				err = asn1Error("PartialAttribute.Decode: expected OCTET STRING, got ",
					strconv.Itoa(int(valsPayload[p2])))
				break
			}

			vLen := int(valsPayload[p2+1])
			if p2+2+vLen > len(valsPayload) {
				err = asn1Error("PartialAttribute.Decode: short value payload")
				break
			}

			vPayload := valsPayload[p2+2 : p2+2+vLen]
			p2 += 2 + vLen

			r.Vals = append(r.Vals, AttributeValue(vPayload))
		}
	}

	return err
}

/*
	AttributeSelection ::= SEQUENCE OF selector LDAPString

AttributeSelection implements [§ 4.5.1.8 of RFC 4511] to serve as a slice
type of [LDAPString] instances. Normally, instances of this type are used
by a client to control which attribute types are to be sent over the wire.

Note that the [LDAPString] is constrained to "attributeSelector" per [§
4.5.1.8 of RFC 4511].

[§ 4.5.1.8 of RFC 4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1.8
*/
type AttributeSelection []LDAPString

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the receiver instance as a SEQUENCE OF [LDAPString].
*/
func (r AttributeSelection) Encode() ([]byte, error) {
	payload := make([]byte, 0)

	for _, ls := range r {
		// LDAPString is encoded as OctetString, and
		// is constrained to UTF-8.
		if !utf8OK(ls) {
			err := encodingError("AttributeSelection: LDAPString is not valid UTF-8")
			return nil, err
		}

		enc, err := OctetString(ls).Encode()
		if err != nil {
			return nil, err
		}

		payload = append(payload, enc...)
	}

	return asn1.WrapTLV(payload, uSeqTag())
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding MUST NOT be
truncated, and must bear the ASN.1 UNIVERSAL SEQUENCE tag (0x30).
*/
func (r *AttributeSelection) Decode(enc []byte) error {
	p := 0

	var err error

	L := len(enc)
	if L < 2 {
		err = asn1Error("AttributeSelection.Decode: truncated encoding")
		return err
	}

	if enc[0] != 0x30 {
		err = asn1Error("AttributeSelection.Decode: expected 0x30 class/tag")
		return err
	}

	var payload []byte
	payload, err = asn1.ReadExpectedConstructedTLV(enc, &p,
		asn1.ClassUniversal, uint32(asn1.TagSequence))

	if err == nil {
		L = len(payload) // update length following class/tag truncation
		enc = payload
		p = 0

		for p < L {
			if p+2 > L {
				err = asn1Error("AttributeSelection.Decode: short value TLV")
				break
			}

			if enc[p] != asn1.TagOctetString {
				err = asn1Error("AttributeSelection.Decode: expected OCTET STRING (4), got ",
					strconv.Itoa(int(enc[p])))
				break
			}

			vLen := int(enc[p+1])
			if p+2+vLen > L {
				err = asn1Error("AttributeSelection.Decode: short value payload")
				break
			}

			vPayload := enc[p+2 : p+2+vLen]
			p += 2 + vLen

			*r = append(*r, LDAPString(vPayload))
		}
	}

	return err
}

/*
Process returns a de-duplicated instance of [AttributeSelection]
(clean) alongside a map of [AttributeDescription] (numeric OID)
to [AttributeDescription] (descriptor) associations (oid2descr)
and two Boolean values (allUA and allOP).

The input resolver closure instance SHOULD be the OID resolver
for attribute types, found in the [go-directory/schema] package.
A custom resolver, for testing reasons perhaps, MAY be supplied
if necessary.

The return value clean contains resolved OIDs, not the original
descriptors. For example, an [AttributeDescription] of `cn` would
be "replaced" by `2.5.4.3`. The clean instance will preserve the
original ordering of the receiver instance. The de-duplication
process will catch and silently discard duplicate instances --
regardless of whether they were originally expressed as a numeric
OID or descriptor.

The oid2descr map return value contains a transaction log of sorts.
Each numeric OID map index is associated with its own principal
descriptor (for instance, "2.5.4.3": AttributeDescriptor("cn")).
A given entry being present within this return instance basically
means it was recognized and added to the clean return instance.

The return allUA and allOP values indicate whether '*' and '+'
are present in the receiver instance respectively. These special
values are not preserved within the return instance of clean,
however their presence is indicated (and, thus, preserved) via
these Boolean values.

If '*' was detected, NO [AttributeDescription] instances will be
present within the return values if they bear the "userApplications"
USAGE.

Similarly, if '+' was detected, NO [AttributeDescription] instances
will be present in the return values if they bear anything other
than the "userApplications" USAGE -- namely "directoryOperations",
"distributedOperation" or "dSAOperation".

If the receiver instance contains zero (0) [AttributeDescription]
instances, this method imposes the default of `*` (allUA=true).

[go-directory/schema]: https://github.com/go-directory/schema
*/
func (r AttributeSelection) Process(
	resolver func(string) (string, string, []string, int),
) (
	clean AttributeSelection,
	oid2descr map[string]AttributeDescription,
	allUA, allOP bool,
) {
	L := len(r)
	allUA = L == 0 // default

	seen := make(map[string]struct{})
	oid2descr = make(map[string]AttributeDescription)

	for i := 0; i < L; i++ {
		if string(r[i]) == `*` {
			allUA = true
			continue
		} else if string(r[i]) == `+` {
			allOP = true
			continue
		}

		noid, princ, _, _ := resolver(string(r[i]))
		if noid == "" {
			// silently ignore nonexistent attribute types
			continue
		}

		aoid := string(AttributeDescription(noid))
		if _, found := seen[aoid]; found {
			// silently ignore duplicative attribute types
			continue
		}

		seen[aoid] = struct{}{}
		oid2descr[aoid] = AttributeDescription(princ)
		clean = append(clean, LDAPString(noid))
	}

	return
}

/*
Attribute is a direct alias of [PartialAttribute]. It has no methods of its
own.
*/
type Attribute = PartialAttribute

/*
AttributeDescription implements [§ 2.5 of RFC4512] and is based on the [LDAPString]
(OCTET STRING) derivative type:

	attributedescription = attributetype options
	attributetype = oid
	options = *( SEMI option )
	option = 1*keychar

The "oid" ABNF allows for a numeric OID or descriptor ("short name").

Examples:

  - 2.5.4.3
  - givenName
  - cn;lang-sl

See also [AttributeType] and [AttributeOption].

[§ 2.5 of RFC4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-2.5
*/
type AttributeDescription LDAPString

/*
AttributeType implements a numeric OID or descriptor ("short name") type, per
[§ 2.5 of RFC4512]. A value of this type serves as the primary component of
an instance of [AttributeDescription].

Examples:

  - 2.5.4.3
  - l
  - objectClass

[§ 2.5 of RFC4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-2.5
*/
type AttributeType LDAPString

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeType) String() string { return string(r) }

/*
AttributeOption implements [§ 2.5 of RFC4512]. At present, the only
recognized implementation of instances of this is an [AttributeTag].

[§ 2.5 of RFC4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-2.5
*/
type AttributeOption interface {
	Kind() string
	String() string
	isAttributeOption()
}

/*
AttributeTag implements [§ 2.5.2 of RFC4512].

[§ 2.5.2 of RFC4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-2.5.2
*/
type AttributeTag LDAPString

/*
Kind returns the string literal "tag" to describe the kind of [AttributeOption]
represented by the receiver instance.
*/
func (r AttributeTag) Kind() string { return `tag` }

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeTag) String() string { return string(r) }

// differentiate Filter qualifiers from other interfaces.
func (r AttributeTag) isAttributeOption() {}

/*
String returns the string representation of the receiver instance.
Note that this will include any [AttributeOption] parameters, such
as [AttributeTag] instances, that are present in the receiver instance.

See also [AttributeDescription.Type] for a means of obtaining only
the underlying [AttributeType].
*/
func (r AttributeDescription) String() string { return string(r) }

/*
Type returns only the descriptor ("short name") component of the
receiver instance.

Specifically, this will ensure that elements such as [AttributeOption]
instances -- such as language tags -- are not included in the return
[AttributeType] value.
*/
func (r AttributeDescription) Type() AttributeType {
	oid := r
	if idx := bytes.Index(oid, []byte(`;`)); idx != -1 {
		oid = oid[:idx]
	}

	return AttributeType(oid)
}

/*
Options returns slices of [AttributeOption] qualifier types based upon
the contents of the receiver instance. For example attribute tags such
as ";lang-sl", ";binary", et al, are among the possible returns.
*/
func (r AttributeDescription) Options() []AttributeOption {
	var options []AttributeOption
	tsp := bytes.Split(r, []byte(`;`))
	for i := 0; i < len(tsp); i++ {
		// checkFilterOIDs enforces "keychar" ABNF.
		if err := checkFilterOIDs(tsp[i], []byte(``)); err == nil && i != 0 {
			options = append(options, AttributeTag(tsp[i]))
		}
	}

	return options
}

/*
Encode returns a []byte instance alongside an error following an attempt
to encode the receiver instance as an ASN.1 OCTET STRING.

Instances of this type are constrained to the character ranges defined
in [§ 1.4 of RFC4512] and [§ 2.5 of RFC4512]. An error is returned if
illegal characters are detected.

[§ 1.4 of RFC4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 2.5 of RFC4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-2.5
*/
func (r AttributeDescription) Encode() ([]byte, error) {
	var enc []byte
	_, err := isDescr(string(r))
	if err == nil {
		// Cast to underlying OctetString
		enc, err = OctetString(r).Encode()
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding MUST NOT be
truncated, and must bear the ASN.1 OCTET STRING tag (0x04).
*/
func (r *AttributeDescription) Decode(enc []byte) error {
	var o OctetString
	var err error
	if err = o.Decode(enc); err == nil {
		*r = AttributeDescription(o)
	}
	return err
}

/*
AttributeValue implements an ASN.1 OCTET STRING derivative type
for use in various assertion and encapsulation use cases.
*/
type AttributeValue OctetString

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeValue) String() string { return string(r) }

func (r AttributeValue) Encode() ([]byte, error) {
	// Cast to underlying OctetString
	return OctetString(r).Encode()
}

func (r *AttributeValue) Decode(enc []byte) error {
	var o OctetString
	var err error
	if err = o.Decode(enc); err == nil {
		*r = AttributeValue(o)
	}
	return err
}

/*
AttributeTypeAndValue implements the attributeTypeAndValue type, as defined
in [§ 2 of RFC4514]. Instances of this type serve as slice members in an
instance of [RelativeDistinguishedName].

[§ 2 of RFC4514]: https://datatracker.ietf.org/doc/html/rfc4514#section-2
*/
type AttributeTypeAndValue struct {
	Type  AttributeType
	Value AttributeValue
}

func (r AttributeTypeAndValue) Encode() ([]byte, error) {
	// Encode type
	typeEnc, err := OctetString(r.Type).Encode()
	if err != nil {
		return nil, err
	}

	var valEnc, outer []byte
	if valEnc, err = OctetString(r.Value).Encode(); err == nil {

		// Build SEQUENCE payload
		seqPayload := make([]byte, 0)
		seqPayload = append(seqPayload, typeEnc...)
		seqPayload = append(seqPayload, valEnc...)

		// Wrap in SEQUENCE
		outer, err = asn1.WrapTLV(seqPayload, uSeqTag())
	}

	return outer, err
}

func (r *AttributeTypeAndValue) Decode(enc []byte) error {
	p := 0

	// If enc starts with SEQUENCE 0x30 (0x10 & constructed),
	// we will strip it as a first measure.
	if len(enc) > 0 && enc[0] == 0x30 {
		payload, err := asn1.ReadExpectedConstructedTLV(enc, &p,
			asn1.ClassUniversal, uint32(asn1.TagSequence))

		if err != nil {
			return err
		}
		enc = payload
		p = 0
	}

	if p+2 > len(enc) {
		return asn1Error("AttributeTypeAndValue.Decode: short type TLV")
	}
	if enc[p] != asn1.TagOctetString {
		return asn1Error("AttributeTypeAndValue.Decode: expected OCTET STRING, got ",
			strconv.Itoa(int(enc[p])))
	}
	typeLen := int(enc[p+1])
	if p+2+typeLen > len(enc) {
		return asn1Error("AttributeTypeAndValue.Decode: short type payload")
	}

	typePayload := enc[p+2 : p+2+typeLen]
	p += 2 + typeLen

	r.Type = typePayload

	_, valsPayload, err := asn1.ReadConstructedTLV(enc, &p)
	if err == nil {
		r.Value = valsPayload
	}

	return err
}

func (r *AttributeTypeAndValue) setType(str string) error {
	result, err := r.decodeString(str)
	if err == nil {
		r.Type = AttributeType(result)
	}

	return err
}

func (r *AttributeTypeAndValue) setValue(s string) error {
	// https://www.ietf.org/rfc/rfc4514.html#section-2.4
	// If the AttributeType is of the dotted-decimal form, the
	// AttributeValue is represented by an number sign ('#' U+0023)
	// character followed by the hexadecimal encoding of each of the octets
	// of the BER encoding of the X.500 AttributeValue.
	if len(s) > 0 && s[0] == '#' {
		decodedString, err := r.decodeEncodedString(s[1:])
		if err == nil {
			r.Value = AttributeValue(decodedString)
		}
		return err
	}

	decodedString, err := r.decodeString(s)
	if err == nil {
		r.Value = AttributeValue(decodedString)
	}
	return err
}

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeTypeAndValue) String() string {
	typ := encodeATV(lc(r.Type), false)
	val := encodeATV(r.Value, true)
	typ = append(typ, []byte(`=`)...)
	typ = append(typ, val...)
	return string(typ)
}

/*
Equal returns true if the [AttributeTypeAndValue] instance is equivalent to the other
[AttributeTypeAndValue].

Case-folding of the underlying [AttributeType] instance is not significant, however
case-folding of the underlying [AttributeValue] is.
*/
func (r AttributeTypeAndValue) Equal(other AttributeTypeAndValue) bool {
	return beqf(r.Type, other.Type) && beq(r.Value, other.Value)
}

/*
EqualFold returns true if the [AttributeTypeAndValue] instance is equivalent to the other
[AttributeTypeAndValue].

Case of the underlying [AttributeType] and [AttributeValue] instances is not significant.
*/
func (r AttributeTypeAndValue) EqualFold(other AttributeTypeAndValue) bool {
	return beqf(r.Type, other.Type) && beqf(r.Value, other.Value)
}

// old go-ldap/v3/dn.go ATV code

func (r AttributeTypeAndValue) decodeEncodedString(str string) (string, error) {
	b, err := hex.DecodeString(str)
	if err != nil {
		return "", err
	}

	p := 0
	tag, val, err := asn1.ReadConstructedTLV(b, &p)
	if err == nil {
		if p != len(b) {
			return "", asn1Error("DistinguishedName: trailing bytes after value")
		}
		err = tag.Expect(asn1.ClassUniversal, false, uint32(asn1.TagOctetString))
	}

	return string(val), err
}

// Remove leading and trailing spaces from the attribute type and value
// and unescape any escaped characters in these fields
//
// decodeString is based on https://github.com/inteon/cert-manager/blob/ed280d28cd02b262c5db46054d88e70ab518299c/pkg/util/pki/internal/dn.go#L170
func (r AttributeTypeAndValue) decodeString(str string) (string, error) {
	s := []rune(stripLeadingAndTrailingSpaces(str))

	bld := bytes.Buffer{}
	for i := 0; i < len(s); i++ {
		char := s[i]

		// If the character is not an escape character, just add it to the
		// builder and continue
		if char != '\\' {
			// § 2.4 of RFC 4514: these characters must appear escaped
			// (either as "\X" or as "\XX" hex) when present in an AttributeValue.
			// Reject the raw form here so that callers don't silently accept
			// input that violates the grammar.
			switch char {
			case '"', ';', '<', '>':
				return "", syntaxError("DistinguishedName: unescaped character: '",
					string(char), "'")
			case 0:
				return "", syntaxError("DistinguishedName: unescaped NULL character")
			}
			bld.WriteRune(char)
			continue
		}

		// If the escape character is the last character, it's a corrupted
		// escaped character
		if i+1 >= len(s) {
			return "", syntaxError("DistinguishedName: corrupted escaped character: '",
				string(s), "'")
		}

		// If the escaped character is a special character, just add it to
		// the builder and continue
		switch s[i+1] {
		case ' ', '"', '#', '+', ',', ';', '<', '=', '>', '\\':
			bld.WriteRune(s[i+1])
			i++
			continue
		}

		// If the escaped character is not a special character, it should
		// be a hex-encoded character of the form \XX if it's not at least
		// two characters long, it's a corrupted escaped character
		if i+2 >= len(s) {
			return "", syntaxError("DistinguishedName: failed to decode escaped character: encoding/hex: invalid byte: ", string(s[i+1]))
		}

		// Get the runes for the two characters after the escape character
		// and convert them to a byte slice
		xx := []byte(string(s[i+1 : i+3]))

		// If the two runes are not hex characters and result in more than
		// two bytes when converted to a byte slice, it's a corrupted
		// escaped character
		if len(xx) != 2 {
			return "", syntaxError("DistinguishedName: failed to decode escaped character: invalid byte: ", string(xx))
		}

		// Decode the hex-encoded character and add it to the builder
		dst := []byte{0}
		if n, err := hex.Decode(dst, xx); err != nil {
			return "", syntaxError("DistinguishedName: failed to decode escaped character: ", err.Error())
		} else if n != 1 {
			return "", syntaxError("DistinguishedName: failed to decode escaped character: encoding/hex: expected 1 byte when un-escaping, got ",
				strconv.Itoa(n))
		}

		bld.WriteByte(dst[0])
		i += 2
	}

	return bld.String(), nil
}

// Escape a string according to RFC 4514
func encodeATV(value []byte, isValue bool) []byte {
	bld := bytes.Buffer{}

	escapeChar := func(c byte) {
		bld.WriteByte('\\')
		bld.WriteByte(c)
	}

	escapeHex := func(c byte) {
		bld.WriteByte('\\')
		bld.WriteString(hex.EncodeToString([]byte{c}))
	}

	// Loop through each byte and escape as necessary.
	// Runes that take up more than one byte are escaped
	// byte by byte (since both bytes are non-ASCII).
	for i := 0; i < len(value); i++ {
		char := value[i]
		if i == 0 && (char == ' ' || char == '#') {
			// Special case leading space or number sign.
			escapeChar(char)
			continue
		}
		if i == len(value)-1 && char == ' ' {
			// Special case trailing space.
			escapeChar(char)
			continue
		}

		switch char {
		case '"', '+', ',', ';', '<', '>', '\\':
			// Each of these special characters must be escaped.
			escapeChar(char)
			continue
		}

		if !isValue && char == '=' {
			// Equal signs have to be escaped only in the type part of
			// the attribute type and value pair.
			escapeChar(char)
			continue
		}

		if char < ' ' || char > '~' {
			// All special character escapes are handled first
			// above. All bytes less than ASCII SPACE and all bytes
			// greater than ASCII TILDE must be hex-escaped.
			escapeHex(char)
			continue
		}

		// Any other character does not require escaping.
		bld.WriteByte(char)
	}

	return bld.Bytes()
}

func stripLeadingAndTrailingSpaces(inVal string) string {
	noSpaces := strings.Trim(inVal, " ")

	// Re-add the trailing space only if it was escaped. A trailing space is
	// escaped when it is preceded by an odd number of backslashes; an even
	// number leaves the space unescaped (each "\\" is a literal backslash), so
	// the space is insignificant and stays stripped. Counting only the final
	// backslash treated "\\ " (a literal backslash plus an insignificant
	// space) as an escaped space, keeping a spurious trailing space in the
	// decoded value.
	if len(noSpaces) > 0 && inVal[len(inVal)-1] == ' ' {
		backslashes := 0
		for i := len(noSpaces) - 1; i >= 0 && noSpaces[i] == '\\'; i-- {
			backslashes++
		}
		if backslashes%2 == 1 {
			noSpaces = noSpaces + " "
		}
	}

	return noSpaces
}

func isAttribute(in []byte) (is bool) {
	if len(in) == 0 {
		return false
	}

	switch {
	case isAlpha(rune(in[0])):
		is, _ = isDescr(string(in))
	case isDigit(rune(in[0])):
		_, err := marshalLDAPOID(in)
		is = err == nil
	}

	return
}
