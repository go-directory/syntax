package syntax

import (
	"errors"
)

/*
CountryString implements [§ 3.3.4 of RFC 4517]:

	CountryString  = 2(PrintableCharacter)

From [§ 1.4 of RFC 4512]:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.3.4 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.4
*/
type CountryString []byte

/*
String returns the string representation of the receiver instance.
*/
func (r CountryString) String() string { return string(r) }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r CountryString) IsZero() bool { return len(r) == 0 }

func countryString(x any) (result bool, err error) {
	_, err = marshalCountryString(x)
	result = err == nil
	return
}

/*
CountryString returns an error following an analysis of x in the context of
an [ISO 3166] country code. Note that specific codes -- though syntactically
valid -- should be verified periodically in lieu of significant world events.

[ISO 3166]: https://www.iso.org/iso-3166-country-codes.html
*/
func NewCountryString(x any) (CountryString, error) {
	return marshalCountryString(x)
}

func marshalCountryString(x any) (cs CountryString, err error) {
	var raw []byte

	badLen := func(l int) (err error) {
		if l != 2 {
			err = errorBadLength("Country String", 0)
		}

		return
	}

	switch tv := x.(type) {
	case string:
		err = badLen(len(tv))
		raw = []byte(tv)
	case []byte:
		err = badLen(len(tv))
		raw = tv
	default:
		err = errorBadType("Country String")
		return
	}

	if err == nil {
		if !isUAlpha(rune(raw[0])) || !isUAlpha(rune(raw[1])) {
			err = errors.New("Incompatible characters for Country String: " +
				string(raw[0]) + "/" + string(raw[0]))
			return
		}
		cs = CountryString(raw)
	}

	return
}
