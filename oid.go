package syntax

/*
oid.go contains all types and methods pertaining to the ASN.1
OBJECT IDENTIFIER type.
*/

import (
	"errors"
	"math"
	"math/big"
	"strconv"
	"strings"
)

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
	case string:
		// try descriptor first
		if _, err = isDescr(tv); err != nil {
			// fallback to numeric oid
			_, err = NewObjectIdentifier(tv)
		}
		result = err == nil
	case ObjectIdentifier:
		if result = tv.Valid(); !result {
			err = errors.New("Invalid ObjectIdentifier syntax")
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
		err = errors.New("zero length OID descriptor")
		return
	}

	if !isAlpha(rune(val[0])) {
		err = errors.New("OID descriptor must begin with an alpha, got " + string(val[0]))
		return
	}

	L := len(val) - 1
	if rune(val[L]) == '-' {
		err = errors.New("OID descriptor cannot end in a hyphen")
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
				err = errors.New("OID descriptor cannot contain consecutive hyphens")
				break
			}
			lastHyphen = true
		default:
			err = errors.New("invalid character for OID descriptor: (none of [a-zA-Z0-9\\-])")
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
		case *big.Int, numberForm, string, int32, int64, uint64, int:
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

Successful output can be cast as an instance of [encoding/asn1.ObjectIdentifier], if desired.
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
		if n, err = strconv.Atoi(r[i].String()); err == nil {
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
		if n, err = strconv.ParseUint(r[i].String(), 10, 64); err == nil {
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
		s = strconv.FormatUint(r.native, 10)
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
		err = errors.New("not a valid sequence, or sequence has no fields")
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
		err = errors.New("OID resolution error: unregistered descriptor " + str)
	}

	return
}

/*
OIDMap contains a user-populated numeric OID to descriptor slices map.

The purpose of this map is to facilitate objectIdentifierMatch equality
checks in conformance with [§ 4.2.25 of RFC 4517] and [§ 4.2.26 of RFC 4517],
particularly where descr values -- as opposed to dotted decimal OIDs -- are
encountered.

[§ 4.2.25 of RFC 4517]: https://www.rfc-editor.org/rfc/rfc4517.html#section-4.2.25
[§ 4.2.26 of RFC 4517]: https://www.rfc-editor.org/rfc/rfc4517.html#section-4.2.26
*/
var OIDMap map[string][]string

var (
	errorNFNegative = errors.New("NUMBER FORM: negative numbers prohibited")
	errorNFNil      = errors.New("NUMBER FORM: nil or bogus instance")
	errorNFBadType  = errors.New("NUMBER FORM: unsupported input type")
	errorNFNoInput  = errors.New("NUMBER FORM: nil or zero input")
	errorNFOctal    = errors.New("NUMBER FORM: leading zeroes (octal numbers) prohibited")
	errorNFBadVLQ   = errors.New("NUMBER FORM: truncated VLQ")
	errorNFBadBE    = errors.New("NUMBER FORM: invalid BE input bytes")
	errorNFNaN      = errors.New("NUMBER FORM: non numeric character found")

	errorOIDMinLen         = errors.New("OBJECT IDENTIFIER: two (2) or more arcs required")
	errorOIDNil            = errors.New("OBJECT IDENTIFIER: nil or bogus instance")
	errorOIDBadType        = errors.New("OBJECT IDENTIFIER: unsupported input type")
	errorOIDBadFirstArcs   = errors.New("OBJECT IDENTIFIER: illegal first and/or second level arcs")
	errorOIDBadEnc         = errors.New("OBJECT IDENTIFIER: bad encoding")
	errorOIDOIVBadNames    = errors.New("OBJECT IDENTIFIER: no nameForms at input for OIV init")
	errorOIDOIVBadNamesLen = errors.New("OBJECT IDENTIFIER: nameForm ct MUST be equal length for OIV init")

	errorUnknownOIDDescr = errors.New("Undefined: unknown descr for OID")
)

func init() {
	OIDMap = make(map[string][]string)
	for _, slices := range [][]string{
		{`2.5.4.3`, `cn`, `commonName`},
		{`2.5.4.6`, `c`, `countryName`},
		{`2.5.4.10`, `o`, `organizationName`},
		{`2.5.4.11`, `ou`, `organizationUnitName`},
		{`2.5.4.33`, `st`, `stateOrProvinceName`},
		{`2.5.4.41`, `name`},
		{`2.5.4.49`, `distinguishedName`},
	} {
		OIDMap[slices[0]] = slices[1:]
	}
}
