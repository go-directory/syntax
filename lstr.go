package syntax

/*
lstr.go contains LDAPString types and methods.
*/

import (
	"unicode/utf8"
)

/*
LDAPString aliases [OctetString] to implement [§ 4.1.2 of RFC 4511].
Instances of this type are constrained to UTF-8.

[§ 4.1.2 of RFC 4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.2
*/
type LDAPString OctetString

/*
LDAPString returns an instance of [LDAPString] alongside an error.
*/
func NewLDAPString(x ...any) (LDAPString, error) {
	return marshalLDAPString(x...)
}

func marshalLDAPString(x ...any) (ls LDAPString, err error) {

	marsh := func(b []byte) (o OctetString, err error) {
		if !utf8.Valid(b) {
			err = encodingError("LDAPString: not valid UTF-8")
		} else {
			o, err = marshalOctetString(b)
		}
		return
	}

	if len(x) > 0 {
		var o OctetString
		switch tv := x[0].(type) {
		case OctetString:
			o, err = marsh(tv)
			ls = LDAPString(o)
		case []byte:
			o, err = marsh(tv)
			ls = LDAPString(o)
		case string:
			o, err = marsh([]byte(tv))
			ls = LDAPString(o)
		default:
			err = errorBadType("LDAPString")
		}
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r LDAPString) String() string { return string(r) }
