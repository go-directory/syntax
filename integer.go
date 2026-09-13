package syntax

/*
integer.go contains methods and types related to the ASN.1 INTEGER type.
*/

import (
	"math"
	"math/big"
	"strconv"

	"github.com/go-directory/encoding/asn1"
)

/*
Integer implements the unbounded ASN.1 INTEGER type (tag 2).

Note that *[big.Int] is used internally ONLY if the number overflows uint64.

For safety reasons (with respect to ambiguity of default values), a zero
instance of this type is bogus. Users MUST use the [NewInteger] constructor
to obtain valid instances of this type.
*/
type Integer struct {
	big, ok bool
	native  int64    // Stores native signed integer values when possible
	bigInt  *big.Int // Stores big.Int values only when necessary
}

/*
NewInteger returns an instance of [Integer] alongside an error
following an attempt to marshal x as an unbounded ASN.1 integer.

Input types may be int, int32, int64, uint64, string or *[big.Int].

Any signed magnitude is permitted. Values which underflow or overflow
int64 are stored as *[big.Int].
*/
func NewInteger[T any](x T) (i Integer, err error) {
	i, err = assertInteger(x)
	return
}

func assertInteger[T any](v T) (i Integer, err error) {
	switch value := any(v).(type) {
	case int:
		i = Integer{native: int64(value)}
	case int64:
		i = Integer{native: value}
	case uint64:
		i = uint64ToInteger(value)
	case *big.Int:
		i = bigToInteger(value)
	case int32:
		i = Integer{native: int64(value)}
	case string:
		i, err = strToInteger(value)
	case Integer:
		if !value.ok {
			err = errorIntNil
		}
		i = value
	default:
		err = errorIntBadType
	}

	if err == nil {
		i.ok = true
	}

	return
}

func integer(x any) (result bool, err error) {
	_, err = NewInteger(x)
	result = err == nil
	return
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r Integer) IsZero() bool { return &r == nil }

/*
String returns the string representation of the receiver instance.
*/
func (r Integer) String() string {
	var s string
	if r.big {
		s = r.bigInt.String()
	} else {
		s = strconv.FormatInt(r.native, 10)
	}

	return s
}

func encodeIntegerValue(n int64) []byte {
	if n == 0 {
		return []byte{0x00}
	}

	var tmp [8]byte
	v := uint64(n)
	i := len(tmp)

	for v != 0 && i > 0 {
		i--
		tmp[i] = byte(v)
		v >>= 8
	}

	out := tmp[i:]

	// Positive: ensure MSB = 0
	if n > 0 && out[0]&0x80 != 0 {
		out = append([]byte{0x00}, out...)
	}

	// Negative: ensure MSB = 1
	if n < 0 && out[0]&0x80 == 0 {
		out = append([]byte{0xFF}, out...)
	}

	return out
}

func decodeIntegerValue(b []byte) int64 {
	var n int64
	for i := 0; i < len(b); i++ {
		n = (n << 8) | int64(b[i])
	}
	// Sign extend
	shift := 64 - uint(len(b))*8
	n = (n << shift) >> shift
	return n
}

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the receiver instance as an ASN.1 INTEGER value.
*/
func (r Integer) Encode() ([]byte, error) {
	if !r.ok {
		return nil, errIntCodec
	}

	var enc []byte
	if r.big {
		enc = asn1.EncodeInteger[*big.Int](r.bigInt)
	} else {
		enc = asn1.EncodeInteger[int64](r.native)
	}

	return enc, nil
}

/*
Decode returns an error following an attempt to decode and write
the input enc value to the receiver instance.  The encoding must
not be truncated, and must bear the INTEGER tag (0x02).
*/
func (r *Integer) Decode(enc []byte) error {
	L := len(enc)
	if L < 2 || enc[0] != asn1.TagInteger {
		return errIntCodec
	}

	var err error
	if L > 10 {
		r.bigInt, err = asn1.DecodeInteger[*big.Int](enc)
	} else {
		r.native, err = asn1.DecodeInteger[int64](enc)
	}

	return err
}

/*
IsBig returns a Boolean value indicative of the underlying value
overflowing uint64.
*/
func (r Integer) IsBig() bool { return r.big }

/*
Native returns the underlying int64 value found within the receiver
instance. Note that this method should not be used unless a call of
[Integer.IsBig] beforehand returns false.
*/
func (r Integer) Native() int64 { return r.native }

/*
Valid returns a Boolean value indicative of the receiver instance
being properly initialized via the [NewInteger] or [MustNewInteger]
constructor with an unambiguous (non-default) value.
*/
func (r Integer) Valid() bool { return r.ok }

/*
Big returns the *[big.Int] form of the receiver instance.

Note that use of this method constructs an entirely new instance of
*[big.Int] if the underlying value is an int64.  Thus, this method
should only usually be needed if a call to [Integer.IsBig] returns
true. In that case, the preexisting *[big.Int] value is returned, as
opposed to being generated on the fly.

When [Integer.IsBig] returns false, the return instance of *[big.Int]
is entirely independent of the receiver and does not replace the
underlying value. This can be useful, though potentially costly, in
cases where methods extended by *[big.Int] that are not wrapped in
this package directly need to be accessed for some reason.
*/
func (r Integer) Big() (i *big.Int) {
	if r.big {
		i = r.bigInt
	} else {
		i = newBigInt(0).SetInt64(r.native)
	}

	return
}

/*
Eq returns a bool indicative of an equality match between the
receiver instance and x.
*/
func (r Integer) Eq(x any) bool { return r.cmpAny(x) == 0 }

/*
Ne returns a bool indicative of a negative equality match between
the receiver instance and x.
*/
func (r Integer) Ne(x any) bool { return r.cmpAny(x) != 0 }

/*
Gt returns a bool indicative of r being greater than x.
*/
func (r Integer) Gt(x any) bool { return r.cmpAny(x) > 0 }

/*
Ge returns a bool indicative of r being greater than or equal to x.
*/
func (r Integer) Ge(x any) bool { return r.cmpAny(x) >= 0 }

/*
Lt returns a bool indicative of r being less than x.
*/
func (r Integer) Lt(x any) bool { return r.cmpAny(x) < 0 }

/*
Le returns a bool indicative of r being less than or equal to x.
*/
func (r Integer) Le(x any) bool { return r.cmpAny(x) <= 0 }

func (r Integer) cmpAny(x any) (result int) {
	switch t := x.(type) {
	case Integer:
		result = cmpInteger(r, t)

	case int:
		result = r.cmpInt64(int64(t))

	case int32:
		result = r.cmpInt64(int64(t))

	case int64:
		result = r.cmpInt64(t)

	case uint64:
		result = r.cmpUint64(t)

	case string:
		result = r.cmpIntegerStr(t)

	case *big.Int:
		result = r.cmpBig(t)

	default:
		panic("Integer: unsupported type for comparison")
	}

	return
}

func (r Integer) cmpIntegerStr(v string) int {
	nf, err := NewInteger(v)
	if err != nil {
		panic(err)
	}
	return cmpInteger(r, nf)
}

func cmpInteger(a, b Integer) int {
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

func (r Integer) cmpInt64(v int64) int {
	if !r.big {
		switch {
		case r.native < v:
			return -1
		case r.native > v:
			return +1
		default:
			return 0
		}
	}
	return r.Big().Cmp(big.NewInt(v))
}

func (r Integer) cmpUint64(u uint64) int {
	if !r.big && u <= math.MaxInt64 {
		return r.cmpInt64(int64(u))
	}
	b := newBigInt(0).SetUint64(u)
	return r.Big().Cmp(b)
}

func (r Integer) cmpBig(b *big.Int) int {
	if !r.big {
		return newBigInt(0).SetInt64(r.native).Cmp(b)
	}
	return r.bigInt.Cmp(b)
}

func integerStrCheck(num string) (err error) {
	if len(num) == 0 {
		err = errorIntNoInput
		return
	}

	if num[0] == '-' {
		num = num[1:]
	}

	if len(num) > 1 && num[0] == '0' {
		err = errorIntOctal
		return
	}

	for i := 0; i < len(num); i++ {
		if ch := num[i]; !('0' <= ch && ch <= '9') {
			err = errorIntNaN
			break
		}
	}

	return
}

func strToInteger(num string) (i Integer, err error) {
	if err = integerStrCheck(num); err != nil {
		return
	}

	if _i, _ := newBigInt(0).SetString(num, 10); _i.IsInt64() {
		i = Integer{native: _i.Int64()}
	} else {
		i = Integer{big: true, bigInt: _i}
	}

	return
}

func bigToInteger(num *big.Int) (i Integer) {
	if i.big = !num.IsInt64(); i.big {
		i.bigInt = num
	} else {
		i.native = num.Int64()
	}

	return
}

func uint64ToInteger(num uint64) (i Integer) {
	if i.big = num > uint64(math.MaxInt64); i.big {
		i.bigInt = newBigInt(0).SetUint64(num)
	} else {
		i.native = int64(num)
	}

	return
}

/*
integerMatch implements [§ 4.2.19 of RFC 4517].

OID: 2.5.13.14

[§ 4.2.19 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.19
*/
func integerMatch(a, b any) (bool, error) {
	return integerMatchingRule(a, b)
}

/*
integerOrderingMatch implements [§ 4.2.20 of RFC 4517].

OID: 2.5.13.15

[§ 4.2.20 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.20
*/
func integerOrderingMatch(a any, operator byte, b any) (bool, error) {
	return integerMatchingRule(a, b, operator)
}

/*
integerFirstComponentMatch implements [§ 4.2.18 of RFC 4517].

OID: 2.5.13.29

[§ 4.2.18 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.18
*/
func integerFirstComponentMatch(a, b any) (result bool, err error) {

	// Use reflection to handle the attribute value.
	// This value MUST be a struct (SEQUENCE) with
	// field 0 being a compatible integer type.
	realValue := assertFirstStructField(a)
	if realValue == nil {
		return
	}

	// field is the integer derived from realValue, and
	// should represent a compatible integer type.
	var field Integer
	if field, err = assertInteger(realValue); err == nil {
		if assertionValue := assertFirstStructField(b); assertionValue == nil {
			// b is presumably a compatible integer
			// type, so assert the value as one.
			var i Integer
			i, err = assertInteger(b)
			result = field.Eq(i) && err == nil
		} else {
			// b is a struct, so assert the derived
			// value from field 0 as a compatible
			// integer type.
			var i Integer
			i, err = assertInteger(assertionValue)
			result = field.Eq(i) && err == nil
		}
	}

	return
}

func integerMatchingRule(a any, b any, operator ...byte) (result bool, err error) {
	var i1, i2 Integer
	if i1, err = assertInteger(a); err == nil {
		if i2, err = assertInteger(b); err == nil {
			if len(operator) > 0 {
				if operator[0] == GreaterOrEqual {
					result = i1.Ge(i2)
				} else {
					result = i1.Le(i2)
				}
			} else {
				result = i1.Eq(i2)
			}
		}
	}

	return
}

var (
	errorIntNil     = syntaxError("INTEGER: nil or bogus instance")
	errorIntBadType = syntaxError("INTEGER: unsupported input type")
	errorIntNoInput = syntaxError("INTEGER: nil or zero input")
	errorIntOctal   = syntaxError("INTEGER: leading zeroes (octal numbers) prohibited")
	errorIntNaN     = syntaxError("INTEGER: non numeric character found")
	errIntCodec     = syntaxError("INTEGER: invalid ASN.1 encoding")
)
