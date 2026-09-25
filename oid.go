package syntax

/*
oid.go contains all types and methods pertaining to the ASN.1
OBJECT IDENTIFIER type.
*/

import (
	"bytes"
	"math"
	"math/big"
	"strings"

	"github.com/go-directory/encoding/vlq"
)

/*
LDAPOID is the ASN.1 OCTET STRING form of a numeric OID, defined in [§ 4.1.2
of RFC4511].

Complete values of instances of this type are constrained for basic X.680 number
form sanity (i.e.: no non-base 10 arcs, no negative arcs), as well as ensure the
"first and second arc combinations" are legal.

Characters in values of this type are constrained to those defined for ["numericoid",
per § 1.4 of RFC4512].

Use of this instances of this type instead of [ObjectIdentifier] is generally
preferred in cases where performance is the top concern, or where an OID is to be
sent over the wire via a directory protocol.

[§ 4.1.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.2
["numericoid", per § 1.4 of RFC4512]: https://datatracker.ietf.org/doc/html/rfc4511#section-1.4
*/
type LDAPOID OctetString

/*
NewLDAPOID returns an instance of [LDAPOID] alongside an error following an
attempt to parse the input value as a UTF-8 encoded OCTET STRING containing
a numeric OID.
*/
func NewLDAPOID(x any) (LDAPOID, error) { return marshalLDAPOID(x) }

func marshalLDAPOID(x any) (loid LDAPOID, err error) {
	var b []byte
	if b, err = assertBytes(x, 3, "LDAPOID"); err == nil {
		parts := bytes.Split(b, []byte("."))
		L := len(parts)
		if L < 2 {
			return nil, errorOIDMinLen
		}
		if err = checkFirstArcs(parts[0], parts[1]); err == nil {
			if L > 2 {
				// We've already processed the first two, so start
				// at slice 3 and only evaluate string numbers as
				// being both unsigned and strictly base 10.
				for i := 2; i < L && err == nil; i++ {
					if AL := len(parts[i]); AL == 0 {
						err = syntaxError("LDAPOID: encountered zero length arc")
					} else if !isDigits(parts[i]) {
						err = syntaxError("LDAPOID: arcs must be numerical and not negative")
					} else if AL > 1 && bHasPfx(parts[i], []byte(`0`)) {
						err = syntaxError("LDAPOID: arcs must be base10")
					}
				}
			}
			loid = b
		}
	}

	return
}

// ensures first two arcs are not in an illegal state.
func checkFirstArcs(a1, a2 []byte) (err error) {
	var arc1, arc2 int
	first := string(a1)
	second := string(a2)
	if arc1, err = atoi(first); err == nil {
		if arc2, err = atoi(second); err == nil {
			notNeg := arc1 >= 0 && arc2 >= 0
			badArc2 := false
			switch arc1 {
			case 0, 1:
				badArc2 = arc2 > 39
			case 2:
			default:
				err = syntaxError("LDAPOID: illegal root arc '", first, "'")
				return
			}
			if !notNeg {
				err = syntaxError("LDAPOID: negative arc(s) detected")
			} else if badArc2 {
				err = syntaxError("LDAPOID: illegal second arc (>39)")
			}
		}
	}
	return
}

func isNumericOID(x any) bool {
	_, err := marshalLDAPOID(x)
	return err == nil
}

func (r LDAPOID) Equal(o LDAPOID) bool { return beq(r,o) }

func (r LDAPOID) String() string { return string(r) }

func (r LDAPOID) Encode() ([]byte, error) {
	return OctetString(r).Encode()
}

func (r *LDAPOID) Decode(enc []byte) error {
	var dec OctetString
	err := dec.Decode(enc)
	if err == nil {
		*r = LDAPOID(dec)
	}
	return err
}

/*
ObjectIdentifier implements an unbounded ASN.1 OBJECT IDENTIFIER (tag 6),
which is convertible to both the [encoding/asn1.ObjectIdentifier] and
[crypto/x509.OID] types.

See the [ObjectIdentifier.IntSlice] and [ObjectIdentifier.Uint64Slice]
methods for details.
*/
type ObjectIdentifier []numberForm

/*
String returns the string representation of the receiver instance.
*/
func (r ObjectIdentifier) String() (s string) {
	if r.Valid() {
		var x []string = make([]string, len(r))
		for i := 0; i < len(r); i++ {
			x[i] = r[i].String()
		}

		s = strings.Join(x, `.`)
	}
	return
}

/*
Eq returns a Boolean value indicative of an equality match between
the receiver and input [ObjectIdentifier] instances.
*/
func (r ObjectIdentifier) Eq(o ObjectIdentifier) bool {
	var ok bool
	if ok = r.Len() == o.Len(); ok {
		// compare each numberForm slice
		for i := 0; i < r.Len() && ok; i++ {
			ok = r[i].eq(o[i])
		}
	}

	return ok
}

/*
Len returns the integer length of the receiver instance.
*/
func (r ObjectIdentifier) Len() int { return len(r) }

/*
IsZero returns a Boolean value indicative of a nil or zero length receiver state.
*/
func (r ObjectIdentifier) IsZero() (is bool) {
	if is = &r == nil; !is {
		is = r.Len() == 0
	}
	return
}

/*
oID returns a Boolean value alongside an error following an attempt
to verify valid numeric OID or descriptor syntax of input argument x.
*/
func oID(x any) (result bool, err error) {
	switch tv := x.(type) {
	case []byte:
		result, err = oID(string(tv))
	case string:
		if len(tv) == 0 {
			err = syntaxError("Invalid ObjectIdentifier syntax")
			break
		}
		switch {
		case isDigit(rune(tv[0])):
			_, err = marshalLDAPOID(tv)
		case isAlpha(rune(tv[0])):
			_, err = isDescr(tv)
		}
		result = err == nil
	case ObjectIdentifier:
		if result = tv.Valid(); !result {
			err = syntaxError("Invalid ObjectIdentifier syntax")
		}
	}

	return
}

/*
isDescr returns a Boolean value indicative of the val string
input value being a legal OID descriptor (a.k.a.: name form),
in that:

  - The name is at least one character long, and ...
  - The first character is a letter, and ...
  - All subsequent characters are alphanumeric or hyphens, and ...
  - Any hyphens present are NOT contiguous (e.g.: "--")
*/
func isDescr(val string) (result bool, err error) {
	if len(val) == 0 {
		err = syntaxError("zero length OID descriptor")
		return
	}

	if !isAlpha(rune(val[0])) {
		err = syntaxError("OID descriptor must begin with an alpha, got ", string(val[0]))
		return
	}

	L := len(val) - 1
	if !isAlnum(rune(val[L])) {
		err = syntaxError("OID descriptor must end with an alphanumeric")
		return
	}

	// watch hyphens to avoid contiguous use.
	// A value of true at any point means the
	// PREVIOUS char was a hyphen.
	var lastHyphen bool

	// iterate all characters in val (except for the
	// first and final chars already checked above),
	// checking each one for "descr" validity.
	for i := 1; i < L && err == nil; i++ {
		ch := rune(val[i])
		switch {
		case isAlnum(ch):
			lastHyphen = false
		case ch == '-':
			if lastHyphen {
				// cannot use consecutive hyphens
				err = syntaxError("OID descriptor cannot contain consecutive hyphens")
				break
			}
			lastHyphen = true
		default:
			err = syntaxError("OID descriptor contains invalid character: want [a-zA-Z0-9\\-], got ", string(ch))
		}
	}

	result = err == nil
	return
}

func assertObjectIdentifier(id any) (A ObjectIdentifier) {
	switch tv := id.(type) {
	case string:
		A, _ = NewObjectIdentifier(tv)
	case ObjectIdentifier:
		if tv.Len() >= 0 {
			A = tv
		}
	}

	return
}

/*
NewObjectIdentifier returns an instance of [ObjectIdentifier] alongside
an error following an attempt to marshal the variadic x inputs as an ASN.1
OBJECT IDENTIFIER.

Variadic input allows for slice mixtures of all of the following types,
with each treated as an individual number form instance:

  - *[big.Int]
  - string
  - uint64
  - int64
  - int32
  - int

If a string primitive is the only input option, it will be treated as a
complete [ObjectIdentifier] (e.g.: "1.3.6.1"). A single input value that
is NOT a string returns an error, as [ObjectIdentifier] instances MUST
have two (2) or more number form arcs at any given time.

If an [ObjectIdentifier] is the only input option, it is checked for
validity and returned without further processing.
*/
func NewObjectIdentifier(x ...any) (r ObjectIdentifier, err error) {
	var _d ObjectIdentifier = make(ObjectIdentifier, 0)

	if len(x) == 1 {
		if slice, ok := x[0].(string); ok {
			// single string input
			r, err = newObjectIdentifierStr(slice)
			return
		} else if slice, ok := x[0].([]byte); ok {
			// single string input
			r, err = newObjectIdentifierStr(string(slice))
			return
		} else if slice2, ok := x[0].(ObjectIdentifier); ok {
			// check OID as valid
			if !slice2.Valid() {
				err = errorOIDNil
			} else {
				r = slice2
			}
			return
		} else {
			err = errorOIDMinLen
			return
		}
	}

	for i := 0; i < len(x) && err == nil; i++ {
		var nf numberForm
		switch tv := x[i].(type) {
		case *big.Int, numberForm, []byte, string, int32, int64, uint64, int:
			nf, err = newNumberForm(tv)
		default:
			err = errorOIDBadType
		}

		_d = append(_d, nf)
		if _d.Len() == 2 {
			// run validity check for first two
			// arcs before proceeding any further.
			if !_d.Valid() {
				err = errorOIDBadFirstArcs
			}
		}
	}

	if err == nil {
		r = _d
	}

	return
}

func newObjectIdentifierStr(s string) (ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, errorOIDMinLen
	}

	args := make([]any, len(parts))
	for i, p := range parts {
		args[i] = p
	}

	o, err := NewObjectIdentifier(args...)
	if !o.Valid() {
		err = errorOIDNil
	}
	return o, err
}

/*
IntSlice returns slices of integer values and an error. The integer values are based
upon the contents of the receiver. Note that if any single arc number overflows int,
a zero slice is returned.

Successful output can be cast as an instance of [encoding/asn1.ObjectIdentifier], if
desired.
*/
func (r ObjectIdentifier) IntSlice() (slice []int, err error) {
	if r.IsZero() {
		err = errorOIDNil
		return
	} else if r.Len() < 2 {
		err = errorOIDMinLen
		return
	}

	var t []int
	for i := 0; i < len(r) && err == nil; i++ {
		var n int
		if n, err = atoi(r[i].String()); err == nil {
			t = append(t, n)
		}
	}

	if len(t) > 0 && err == nil {
		slice = t[:]
	}

	return
}

/*
Uint64Slice returns slices of uint64 values and an error. The uint64
values are based upon the contents of the receiver.

Note that if any single arc number overflows uint64, a zero slice is
returned alongside an error.

Successful output can be cast as an instance of [crypto/x509.OID], if
desired.
*/
func (r ObjectIdentifier) Uint64Slice() (slice []uint64, err error) {
	if r.IsZero() {
		err = errorOIDNil
		return
	} else if r.Len() < 2 {
		err = errorOIDMinLen
		return
	}

	var t []uint64
	for i := 0; i < len(r) && err == nil; i++ {
		var n uint64
		if n, err = puint(r[i].String(), 10, 64); err == nil {
			t = append(t, n)
		}
	}

	if len(t) > 0 && err == nil {
		slice = t[:]
	}

	return
}

/*
Valid returns a Boolean value indicative of the following:

  - Receiver's length is greater than or equal to two (2) slice members, and ...
  - The first slice in the receiver contains an unsigned decimal value that is less than three (3), and ...
  - If root arc is 0 or 1, the second arc must be no greater than thirty nine (39)
*/
func (r ObjectIdentifier) Valid() (is bool) {
	if L := r.Len(); L > 0 {
		if is = r[0].lt(3) && L >= 2; is {
			for i := 1; i < L && is; i++ {
				if i == 1 && r[0].lt(2) {
					if is = r[1].lt(40); !is {
						break
					}
				}
				is = r[i].ok
			}
		}
	}

	return
}

func (r ObjectIdentifier) matchOID(oiv ObjectIdentifier, off int) (matched bool) {
	L := r.Len()
	ct := 0
	for i := 0; i < L; i++ {
		if x := r[i]; x.eq(oiv[i]) {
			ct++
		} else if off == -1 && L-1 == i {
			// sibling check should end in
			// a FAILED match for the final
			// arcs.
			ct++
		}
	}

	return ct == L
}

/*
Encode returns byte slices alongside an error following an attempt to
encode the receiver instance.
*/
func (r ObjectIdentifier) Encode() ([]byte, error) {
	if !r.Valid() {
		return nil, errorOIDNil
	}

	first := r[0]
	second := r[1]

	// First-two-arc compression: (first * 40) + second
	var wire []byte

	if !second.big {
		// first is ALWAYS native, second is native here
		wire = vlq.Encode[uint64](first.native*40 + second.native)
	} else {
		// second is big, so we must use big.Int math
		tmp := newBigInt(0).Mul(newBigInt(0).SetUint64(first.native), newBigInt(40))
		tmp.Add(tmp, second.bigInt)
		wire = vlq.Encode[*big.Int](tmp)
	}

	// Encode remaining arcs
	for i := 2; i < r.Len(); i++ {
		if r[i].big {
			wire = append(wire, vlq.Encode[*big.Int](r[i].bigInt)...)
		} else {
			wire = append(wire, vlq.Encode[uint64](r[i].native)...)
		}
	}

	return wire, nil
}

/*
Decode returns an error following an attempt to decode the input enc bytes
into the receiver instance. Any data present in the receiver instance will
be destroyed.
*/
func (r *ObjectIdentifier) Decode(enc []byte) error {
	if len(enc) < 1 {
		return errorOIDBadEnc
	}

	var (
		dec  any
		p    int
		bigi bool
		err  error
	)

	// Decode combined first+second arc as native or big
	if bigi = len(enc) > 10; bigi {
		dec, err = vlq.Decode[*big.Int](enc, &p)
	} else {
		dec, err = vlq.Decode[uint64](enc, &p)
	}

	if err != nil {
		return err
	}

	var firstNF, secondNF numberForm

	if !bigi {
		// Native path
		v := dec.(uint64)
		if v >= 120 && v < 160 {
			// Reject combined values 120..159 (these
			// correspond to illegal root 3.x)
			return errorOIDBadFirstArcs
		}

		switch {
		case v < 40:
			// 0.x
			firstNF = numberForm{ok: true, native: 0}
			secondNF = numberForm{ok: true, native: v}
		case v < 80:
			// 1.(v-40)
			firstNF = numberForm{ok: true, native: 1}
			secondNF = numberForm{ok: true, native: v - 40}
		default:
			// 2.(v-80)
			firstNF = numberForm{ok: true, native: 2}
			secondNF = numberForm{ok: true, native: v - 80}
		}
	} else {
		// Big path: combined is big.Int
		// For big combined, it must be >= 80: first = 2, second = combined - 80
		tmp := newBigInt(0).Set(dec.(*big.Int))
		tmp.Sub(tmp, newBigInt(80))

		firstNF = numberForm{ok: true, native: 2}
		secondNF = numberForm{ok: true, big: true, bigInt: tmp}
	}

	arcs := make(ObjectIdentifier, 0, 4)
	arcs = append(arcs, firstNF, secondNF)

	// Remaining arcs
	L := len(enc)
	for p < L && err == nil {
		var n any
		if L-p > 10 {
			n, err = vlq.Decode[*big.Int](enc, &p)
			arcs = append(arcs, numberForm{
				big:    true,
				ok:     true,
				bigInt: n.(*big.Int),
			})
		} else {
			n, err = vlq.Decode[uint64](enc, &p)
			arcs = append(arcs, numberForm{
				ok:     true,
				native: n.(uint64),
			})
		}
	}

	if err == nil {
		*r = arcs
	}

	return err
}

var newBigInt func(int64) *big.Int = big.NewInt

/*
numberForm implements the unbounded ASN.1 INTEGER for ObjectIdentifier type
instances.

Note that *[big.Int] is used internally ONLY if the number overflows uint64.
*/
type numberForm struct {
	big, ok bool
	native  uint64   // Stores native unsigned integer values when possible
	bigInt  *big.Int // Stores big.Int values only when necessary
}

/*
newNumberForm returns an instance of number form alongside an error
following an attempt to marshal x as an X.680 number form.

Input types may be int, int32, int64, uint64, string, []byte or
*[big.Int]. In the case of []byte, the value is expected to
be the Big Endian representation of the desired number form.

Any unsigned magnitude is permitted. Number forms which overflow
uint64 are stored as *[big.Int].

When the input value is NOT a string and when NO constraints are
utilized, it is safe to shadow the return error.
*/
func newNumberForm[T any](x T) (i numberForm, err error) {
	i, err = assertNumberForm(x)
	return
}

func assertNumberForm[T any](v T) (i numberForm, err error) {
	if err = checkNegativeNF(any(v)); err != nil {
		return
	}

	switch value := any(v).(type) {
	case int:
		i = numberForm{native: uint64(value)}
	case int64:
		i = numberForm{native: uint64(value)}
	case uint64:
		i = uint64ToNumberForm(value)
	case *big.Int:
		i = bigToNumberForm(value)
	case int32:
		i = numberForm{native: uint64(value)}
	case string:
		i, err = strToNumberForm(value)
	case []byte:
		i, err = strToNumberForm(string(value))
	case numberForm:
		if !value.ok {
			err = errorNFNil
		}
		i = value
	default:
		err = errorNFBadType
	}

	if err == nil {
		i.ok = true
	}

	return
}

func checkNegativeNF(v any) (err error) {
	switch value := v.(type) {
	case int:
		if value < 0 {
			err = errorNFNegative
		}
	case int32:
		if value < 0 {
			err = errorNFNegative
		}
	case int64:
		if value < 0 {
			err = errorNFNegative
		}
	case *big.Int:
		if value.Cmp(newBigInt(0)) == -1 {
			err = errorNFNegative
		}
	}

	return
}

func (r numberForm) String() string {
	var s string
	if r.big {
		s = r.bigInt.String()
	} else {
		s = fuint(r.native, 10)
	}

	return s
}

func (r numberForm) IsZero() bool   { return &r == nil }
func (r numberForm) IsBig() bool    { return r.big }
func (r numberForm) Native() uint64 { return r.native }
func (r numberForm) Valid() bool    { return r.ok }

/*
Big returns the *[big.Int] form of the receiver instance.

Note that use of this method constructs an entirely new instance of
*[big.Int] if the underlying value is an int64.  Thus, this method
should only usually be needed if a call to [numberForm.IsBig] returns
true. In that case, the preexisting *[big.Int] value is returned, as
opposed to being generated on the fly.

When [numberForm.IsBig] returns false, the return instance of *[big.Int]
is entirely independent of the receiver and does not replace the
underlying value. This can be useful, though potentially costly, in
cases where methods extended by *[big.Int] that are not wrapped in
this package directly need to be accessed for some reason.
*/
func (r numberForm) Big() (i *big.Int) {
	if r.big {
		i = r.bigInt
	} else {
		i = newBigInt(0).SetUint64(r.native)
	}

	return
}

func (r numberForm) eq(x any) bool { return r.cmpAny(x) == 0 }
func (r numberForm) lt(x any) bool { return r.cmpAny(x) < 0 }

func (r numberForm) cmpAny(x any) (result int) {
	switch t := x.(type) {
	case numberForm:
		result = cmpNumberForm(r, t)

	case int:
		result = r.cmpInt64(int64(t))

	case int32:
		result = r.cmpInt64(int64(t))

	case int64:
		result = r.cmpInt64(t)

	case uint64:
		result = r.cmpUint64(t)

	case string:
		result = r.cmpNumberFormStr(t)

	case *big.Int:
		result = r.cmpBig(t)

	default:
		panic("NumberForm: unsupported type for comparison")
	}

	return
}

func (r numberForm) cmpNumberFormStr(v string) int {
	nf, err := newNumberForm(v)
	if err != nil {
		panic(err)
	}
	return cmpNumberForm(r, nf)
}

func cmpNumberForm(a, b numberForm) int {
	if !a.big && !b.big {
		switch {
		case a.native < b.native:
			return -1
		case a.native > b.native:
			return +1
		default:
			return 0
		}
	}
	return a.Big().Cmp(b.Big())
}

func (r numberForm) cmpInt64(v int64) int {
	if !r.big {
		switch {
		case r.native < uint64(v):
			return -1
		case r.native > uint64(v):
			return +1
		default:
			return 0
		}
	}
	return r.Big().Cmp(big.NewInt(v))
}

func (r numberForm) cmpUint64(u uint64) int {
	if !r.big && u <= math.MaxInt64 {
		return r.cmpInt64(int64(u))
	}
	b := newBigInt(0).SetUint64(u)
	return r.Big().Cmp(b)
}

func (r numberForm) cmpBig(b *big.Int) int {
	if !r.big {
		return newBigInt(0).SetUint64(r.native).Cmp(b)
	}
	return r.bigInt.Cmp(b)
}

/*
isNumberForm returns a Boolean value indicative of the nf string
input value representing a valid [NumberForm], in that:

  - The number is one (1) or more valid digits, and ...
  - The number is base10 (e.g.: not octal), and ...
  - The number is not negative

Assuming the above requirements are satisfied, any unsigned magnitude
is considered valid.
*/
func isNumberForm(nf string) bool {
	return numberFormCheck(nf) == nil
}

func numberFormCheck(num string) (err error) {
	if len(num) == 0 {
		err = errorNFNoInput
		return
	}

	if num[0] == '-' {
		err = errorNFNegative
		return
	} else if len(num) > 1 && num[0] == '0' {
		err = errorNFOctal
		return
	}

	for i := 0; i < len(num); i++ {
		if ch := num[i]; !('0' <= ch && ch <= '9') {
			err = errorNFNaN
			break
		}
	}

	return
}

func strToNumberForm(num string) (i numberForm, err error) {
	if err = numberFormCheck(num); err != nil {
		return
	}

	_i, _ := newBigInt(0).SetString(num, 10)
	if _i.IsUint64() {
		i = numberForm{native: _i.Uint64()}
	} else {
		i = numberForm{big: true, bigInt: _i}
	}

	return
}

func bigToNumberForm(num *big.Int) (i numberForm) {
	if i.big = !num.IsUint64(); i.big {
		i.bigInt = num
	} else {
		i.native = num.Uint64()
	}

	return
}

func uint64ToNumberForm(num uint64) (i numberForm) {
	if i.big = num > uint64(math.MaxInt64); i.big {
		i.bigInt = newBigInt(0).SetUint64(num)
	} else {
		i.native = num
	}

	return
}

func objectIdentifierMatch(a, b any) (result bool, err error) {
	var (
		oid1, oid2 ObjectIdentifier
		err1, err2 error
	)

	oid1, err1 = NewObjectIdentifier(a)
	oid2, err2 = NewObjectIdentifier(b)

	if err1 == nil && err2 == nil {
		result = oid1.Eq(oid2)
		return
	}

	if OIDMap == nil || len(OIDMap) == 0 {
		// no resolution available. Try a
		// simple cmp as string values.
		str1, _ := assertString(a, 1, "string")
		str2, _ := assertString(b, 1, "string")
		return str1 == str2, nil
	}

	if err1 != nil {
		oid1, err = resolveDescrToOID(a)
	}

	if err2 != nil {
		oid2, err = resolveDescrToOID(b)
	}

	result = oid1.Eq(oid2) && err == nil

	return
}

func objectIdentifierFirstComponentMatch(sequence, assertionValue any) (result bool, err error) {

	// Use reflection to handle the sequence (a), which must
	// only be one of the following struct types:
	//
	//   - Attribute Type Description
	//   - LDAP Syntax Description
	//   - Matching Rule Description
	//   - Matching Rule Use Description
	//   - Object Class Description
	//   - DIT Content Rule Description
	//   - Name Form Description
	//
	// The first component is extracted as componentValue,
	// which must only be an object identifier in order for
	// the objectIdentifierMatch call (below) to be successful.
	componentValue := assertFirstStructField(sequence)
	if componentValue == nil {
		err = syntaxError("not a valid sequence, or sequence has no fields")
		return
	}

	result, err = objectIdentifierMatch(componentValue, assertionValue)

	return
}

func resolveDescrToOID(a any) (o ObjectIdentifier, err error) {
	str, ok := a.(string)
	if !ok {
		err = errorUnknownOIDDescr
		return
	}

	for k, v := range OIDMap {
		if strInSlice(str, v) {
			o, err = NewObjectIdentifier(k)
			break
		}
	}

	if err != nil {
		err = errorUnknownOIDDescr
	} else if o == nil {
		err = syntaxError("OID resolution error: unregistered descriptor ", str)
	}

	return
}

/*
Encode returns a byte slice alongside an error following an attempt to
encode the receiver instance as Big Endian bytes.
*/
func (r numberForm) Encode() ([]byte, error) {
	if !r.ok {
		return nil, errorNFNil
	}

	var enc []byte
	if r.big {
		enc = vlq.Encode[*big.Int](r.bigInt)
	} else {
		enc = vlq.Encode[uint64](r.native)
	}

	return enc, nil
}

/*
Decode returns an error following an attempt to decode the input enc bytes
into the receiver instance. Any data present in the receiver instance will
be destroyed.
*/
func (r *numberForm) Decode(enc []byte) error {
	p := 0

	var err error
	var n any

	if len(enc) > 10 {
		n, err = vlq.Decode[*big.Int](enc, &p)
		r.bigInt = n.(*big.Int)
		r.big = true
		r.ok = true
	} else {
		n, err = vlq.Decode[uint64](enc, &p)
		r.native = n.(uint64)
		r.ok = true
	}

	return err
}

func bEToUint64(b []byte) uint64 {
	n := len(b)
	if n > 8 {
		panic("bigEndianToUint64: buffer length must be ≤ 8")
	}

	var u uint64
	for i := 0; i < 8-n; i++ {
		u = (u << 8) | 0x00
	}
	for _, by := range b {
		u = (u << 8) | uint64(by)
	}
	return u
}

func uint64ToBE(n uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(n & 0xff)
		n >>= 8
	}
	return b
}

func bEFitsUint64(b []byte) bool {
	n := len(b)
	if n > 8 {
		for i := 0; i < n-8; i++ {
			if b[i] != 0x00 {
				return false
			}
		}
	}
	return true
}

func bEToNumberForm(b []byte) (i numberForm) {
	if i.big = !bEFitsUint64(b); i.big {
		i.bigInt = newBigInt(0).SetBytes(b)
	} else {
		i.native = bEToUint64(b)
	}

	return
}

/*
OIDMap contains a user-populated numeric OID to descriptor slices map.

The purpose of this map is to facilitate objectIdentifierMatch equality
checks in conformance with [§ 4.2.25 of RFC 4517] and [§ 4.2.26 of RFC 4517],
particularly where descr values -- as opposed to dotted decimal OIDs -- are
encountered.

Set this variable to nil to disable OID resolution.

[§ 4.2.25 of RFC 4517]: https://www.rfc-editor.org/rfc/rfc4517.html#section-4.2.25
[§ 4.2.26 of RFC 4517]: https://www.rfc-editor.org/rfc/rfc4517.html#section-4.2.26
*/
var OIDMap map[string][]string

var (
	errorNFNegative = syntaxError("NUMBER FORM: negative numbers prohibited")
	errorNFNil      = syntaxError("NUMBER FORM: nil or bogus instance")
	errorNFBadType  = syntaxError("NUMBER FORM: unsupported input type")
	errorNFNoInput  = syntaxError("NUMBER FORM: nil or zero input")
	errorNFOctal    = syntaxError("NUMBER FORM: leading zeroes (octal numbers) prohibited")
	errorNFBadVLQ   = syntaxError("NUMBER FORM: truncated VLQ")
	errorNFBadBE    = syntaxError("NUMBER FORM: invalid BE input bytes")
	errorNFNaN      = syntaxError("NUMBER FORM: non numeric character found")

	errorOIDMinLen         = syntaxError("OBJECT IDENTIFIER: two (2) or more arcs required")
	errorOIDNil            = syntaxError("OBJECT IDENTIFIER: nil or bogus instance")
	errorOIDBadType        = syntaxError("OBJECT IDENTIFIER: unsupported input type")
	errorOIDBadFirstArcs   = syntaxError("OBJECT IDENTIFIER: illegal first and/or second level arcs")
	errorOIDBadEnc         = syntaxError("OBJECT IDENTIFIER: bad encoding")
	errorOIDOIVBadNames    = syntaxError("OBJECT IDENTIFIER: no nameForms at input for OIV init")
	errorOIDOIVBadNamesLen = syntaxError("OBJECT IDENTIFIER: nameForm ct MUST be equal length for OIV init")

	errorUnknownOIDDescr = syntaxError("Undefined: unknown descr for OID")
)

func init() {
	OIDMap = make(map[string][]string)
	for _, slices := range [][]string{
		{`0.9.2342.19200300.100.1.1`, `uid`, `userId`},
		{`0.9.2342.19200300.100.1.25`, `dc`, `domainComponent`},
		{`2.5.4.3`, `cn`, `commonName`},
		{`2.5.4.6`, `c`, `countryName`},
		{`2.5.4.7`, `l`, `localityName`},
		{`2.5.4.9`, `street`, `streetAddress`},
		{`2.5.4.10`, `o`, `organizationName`},
		{`2.5.4.11`, `ou`, `organizationUnitName`},
		{`2.5.4.33`, `st`, `stateOrProvinceName`},
		{`2.5.4.41`, `name`},
		{`2.5.4.49`, `distinguishedName`},
	} {
		OIDMap[slices[0]] = slices[1:]
	}
}
