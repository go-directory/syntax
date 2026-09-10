package syntax

import (
	"errors"
	"unicode"
)

const TagPrintableString byte = 0x13

/*
PrintableString implements [§ 3.3.29 of RFC 4517]:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter

From [§ 1.4 of RFC 4512]:

	ALPHA   = %x41-5A / %x61-7A    ; "A"-"Z" / "a"-"z"
	DIGIT   = %x30 / LDIGIT        ; "0"-"9"
	SQUOTE  = %x27                 ; single quote ("'")
	SPACE   = %x20                 ; space (" ")
	LPAREN  = %x28                 ; left paren ("(")
	RPAREN  = %x29                 ; right paren (")")
	PLUS    = %x2B                 ; plus sign ("+")
	COMMA   = %x2C                 ; comma (",")
	HYPHEN  = %x2D                 ; hyphen ("-")
	DOT     = %x2E                 ; period (".")
	EQUALS  = %x3D                 ; equals sign ("=")

From [§ 3.2 of RFC 4517]:

	SLASH     = %x2F               ; forward slash ("/")
	COLON     = %x3A               ; colon (":")
	QUESTION  = %x3F               ; question mark ("?")

[§ 3.3.29 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.29
[§ 3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.2
[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
type PrintableString []byte

/*
String returns the string representation of the receiver instance.
*/
func (r PrintableString) String() string {
	return string(r)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r PrintableString) IsZero() bool { return len(r) == 0 }

func printableString(x any) (result bool, err error) {
	_, err = marshalPrintableString(x)
	result = err == nil
	return
}

/*
PrintableString returns an error following an analysis of x in the context
of a [PrintableString].
*/
func NewPrintableString(x any) (PrintableString, error) {
	return marshalPrintableString(x)
}

func marshalPrintableString(x any) (ps PrintableString, err error) {
	var raw []byte

	badLen := func(l int) (err error) {
		if l == 0 {
			err = errorBadLength("Printable String", 0)
		}
		return
	}

	switch tv := x.(type) {
	case PrintableString:
		err = badLen(len(tv))
		raw = []byte(tv)
	case string:
		err = badLen(len(tv))
		raw = []byte(tv)
	case []byte:
		err = badLen(len(tv))
		raw = tv
	default:
		err = errorBadType("Printable String")
	}

	for i := 0; i < len(raw) && err == nil; i++ {
		char := rune(raw[i])
		if !unicode.In(char, digits, lAlphas, uAlphas, prsRange) {
			err = errorBadType("Invalid printable string character: " + string(char))
		}
	}

	if err == nil {
		ps = PrintableString(raw)
	}

	return
}

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the receiver instance as an ASN.1 PrintableString.
value.
*/
func (r PrintableString) Encode() ([]byte, error) {
	return encodePrimitive(TagPrintableString, r)
}

/*
Decode returns an error following an attempt to decode and write
the input enc value to the receiver instance.  The encoding must
not be truncated, and must bear the PrintableString tag (0x13).
*/
func (r *PrintableString) Decode(enc []byte) error {
	if len(enc) < 2 || enc[0] != TagPrintableString {
		return errPrintableDecode
	}
	l, n := readLength(enc[1:])
	if n == 0 || len(enc) < 1+n+l {
		return errPrintableDecode
	}
	*r = enc[1+n : 1+n+l]
	return nil
}

var errPrintableDecode = errors.New("asn1: invalid PrintableString")
