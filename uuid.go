package syntax

import (
	"bytes"
	"uuid"
)

/*
UUID wraps [uuid.UUID] to implement RFC 4530.
*/
type UUID uuid.UUID

/*
UUID returns an instance of [UUID] alongside an error.

If no argument is provided, a new [uuid.UUID] is generated and
returned. If an argument is provided, it is parsed as a UUID.

Valid input types are string or []byte.
*/
func NewUUID(x ...any) (UUID, error) {
	return marshalUUID(x...)
}

/*
NewZeroUUID returns a [UUID] of [16]byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}.
*/
func NewZeroUUID() UUID { return UUID(uuid.Nil()) }

/*
Parse returns an error following a call to [uuid.Parse]. If the
call is successful, the receiver is overwritten with the new
[UUID] instance.

Valid input types may be []byte or string.
*/
func (r *UUID) Parse(u any) error {
	str, err := assertString(u, 32, "UUID")
	if err == nil {
		var U uuid.UUID
		U, err = uuid.Parse(str)
		if err == nil {
			*r = UUID(U)
		}
	}

	return err
}

/*
NewSeqUUID returns an instance of [UUID] alongsie an error following
an attempt to create a predictable, sequential instance.

The input uint64 seq value is encoded as big endian and will overwrite
the last eight (8) bytes of the return value.

The variadic input prefix allows for a UUID to be used as the prefix
(the first eight (8) bytes). If not provided, a default UUID value of
"00000000-0000-4000-8000-000000000000" is assumed.

To offer an example, calling this function with a sequence uint64 of
748 and a UUID prefix of "f81d4fae-7dec-11d0-a765-00a0c91e6bf6", the
return value would be "f81d4fae-7dec-11d0-0000-000000000310".
*/
func NewSeqUUID(seq uint64, prefix ...any) (UUID, error) {
	var (
		err error
		def = UUID(uuid.Nil()) // [16]byte{0x0,0x0,...}
	)

	if len(prefix) > 0 {
		var u UUID
		switch tv := prefix[0].(type) {
		case []byte, string:
			err = u.Parse(tv)
		case uuid.UUID:
			u = UUID(tv)
		case UUID:
			u = tv
		default:
			err = errorBadType("UUID")
		}

		if err == nil {
			def = u
			putBE(def[8:], seq)
		}
	} else {
		// RFC 9562 V4/Variant
		def[6] = (def[6] & 0x0f) | 0x40
		def[8] = (def[8] & 0x3f) | 0x80
		putBE(def[8:], seq)
	}

	return def, err
}

/*
uUID returns a [Boolean] value indicative of a valid input
value (x) per UUID syntax (RFC 4530).
*/
func uUID(x any) (result bool, err error) {
	_, err = marshalUUID(x)
	result = err == nil
	return
}

/*
uuidMatch compares UUIDs a and b to gauge their equality.
*/
func uuidMatch(a, b any) (result bool, err error) {
	var au, bu UUID
	if au, err = marshalUUID(a); err == nil {
		if bu, err = marshalUUID(b); err == nil {
			result = bytes.Compare(au[:], bu[:]) == 0
		}
	}
	return
}

func uuidOrderingMatch(a any, operator byte, b any) (result bool, err error) {
	var au, bu UUID
	if au, err = marshalUUID(a); err == nil {
		if bu, err = marshalUUID(b); err == nil {
			if operator == GreaterOrEqual {
				result = bytes.Compare(au[:], bu[:]) > 0
			} else {
				result = bytes.Compare(au[:], bu[:]) < 0
			}
		}
	}

	return
}

/*
marshalUUID returns an instance of [UUID] alongside an error
following an attempt to marshal x as an RFC 4530 UUID.
*/
func marshalUUID(x ...any) (u UUID, err error) {
	if len(x) == 0 {
		u = UUID(uuid.New())
		return
	}

	var raw []byte

	switch tv := x[0].(type) {
	case string:
		raw = []byte(tv)
	case []byte:
		raw = tv
	case UUID:
		u = tv
		return
	default:
		err = errorBadType("UUID")
		return
	}

	var _u uuid.UUID
	if err = _u.UnmarshalText(raw); err == nil {
		u = UUID(_u)
	}

	return
}

/*
Cast unwraps and returns the underlying instance of [uuid.UUID].
*/
func (r UUID) Cast() uuid.UUID {
	return uuid.UUID(r)
}

/*
String returns the string representation of the receiver instance.
*/
func (r UUID) String() string {
	return r.Cast().String()
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r UUID) IsZero() bool {
	return len(r) == 0
}

/*
Integer returns the [Integer] representation of the receiver instance.
*/
/*
func (r UUID) Integer() (i Integer) {
	if !r.IsZero() {
		_i, _ := assertNumber(0)
		_i.SetBytes(r[:])
		i = Integer(*_i)
	}

	return
}
*/
