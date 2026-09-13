package syntax

/*
postal.go contains implementations for various postal and mail constructs.
*/

import (
	"bytes"
	"unicode"
	"unicode/utf8"
)

/*
DeliveryMethod implements [§ 3.3.5 of RFC 4517]:

	DeliveryMethod = pdm *( WSP DOLLAR WSP pdm )
	pdm = "any" / "mhs" / "physical" / "telex" / "teletex" /
	      "g3fax" / "g4fax" / "ia5" / "videotex" / "telephone"

From [§ 1.4 of RFC 4512]:

	DOLLAR  = %x24	  ; dollar sign ("$")
	WSP     = 0*SPACE ; zero or more " "

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.3.5 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.5
*/
type DeliveryMethod [][]byte

/*
String returns the string representation of the receiver instance.
*/
func (r DeliveryMethod) String() string {
	return string(bytes.Join(r, []byte(` $ `)))
}

func deliveryMethod(x any) (result bool, err error) {
	_, err = marshalDeliveryMethod(x)
	result = err == nil
	return
}

/*
DeliveryMethod returns an error following an analysis of x in the context
of a [DeliveryMethod].
*/
func NewDeliveryMethod(x any) (DeliveryMethod, error) {
	return marshalDeliveryMethod(x)
}

var postalDeliveryMethods = map[string]struct{}{
	// Method	ASN.1 Type Integer [X.520]
	`any`:       {}, // 0
	`mhs`:       {}, // 1
	`physical`:  {}, // 2
	`telex`:     {}, // 3
	`teletex`:   {}, // 4
	`g3fax`:     {}, // 5
	`g4fax`:     {}, // 6
	`ia5`:       {}, // 7
	`videotex`:  {}, // 8
	`telephone`: {}, // 9
}

func marshalDeliveryMethod(x any) (dm DeliveryMethod, err error) {
	var raw []byte
	var dms DeliveryMethod
	switch tv := x.(type) {
	case []byte:
		raw = tv
	case string:
		raw = []byte(tv)
	default:
		err = errorBadType("Delivery Method")
		return
	}

	raws := splitOnByte(bRepAll(raw, []byte(` `), []byte(``)), 0x24)
	for i := 0; i < len(raws) && err == nil; i++ {
		if _, found := postalDeliveryMethods[string(raws[i])]; !found {
			err = syntaxError("Invalid PDM type for Delivery Method: ", string(raws[i]))
		} else {
			dms = append(dms, raws[i])
		}
	}

	if err == nil {
		dm = dms
	}

	return
}

/*
PostalAddress implements the PostalAddress definition per [§ 3.3.28 of
RFC 4517]:

	PostalAddress = line *( DOLLAR line )
	line          = 1*line-char
	line-char     = %x00-23
	                / (%x5C "24")  ; escaped "$"
	                / %x25-5B
	                / (%x5C "5C")  ; escaped "\"
	                / %x5D-7F
	                / UTFMB

From [§ 1.4 of RFC 4512]:

	DOLLAR  = %x24	  ; dollar sign ("$")
	UTFMB   = UTF2 / UTF3 / UTF4
	UTF0    = %x80-BF
	UTF1    = %x00-7F
	UTF2    = %xC2-DF UTF0
	UTF3    = %xE0 %xA0-BF UTF0 / %xE1-EC 2(UTF0) /
	          %xED %x80-9F UTF0 / %xEE-EF 2(UTF0)
	UTF4    = %xF0 %x90-BF 2(UTF0) / %xF1-F3 3(UTF0) /
	          %xF4 %x80-8F 2(UTF0)

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.3.28 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.28
*/
type PostalAddress [][]byte

/*
String returns the string representation of the receiver instance.
*/
func (r PostalAddress) String() string {
	return string(bytes.Join(r, []byte(`$`)))
}

func postalAddress(x any) (result bool, err error) {
	_, err = marshalPostalAddress(x)
	result = err == nil
	return
}

/*
PostalAddress returns an error following an analysis of x in the context
of a [PostalAddress].
*/
func NewPostalAddress(x any) (PostalAddress, error) {
	return marshalPostalAddress(x)
}

func marshalPostalAddress(x any) (pa PostalAddress, err error) {
	badLen := func(l int) (err error) {
		if l < 1 {
			err = errorBadLength("Postal Address", 1)
		}
		return
	}

	var raw []byte
	switch tv := x.(type) {
	case []byte:
		raw = tv
		err = badLen(len(tv))
	case string:
		raw = []byte(tv)
		err = badLen(len(tv))
	default:
		err = errorBadType("Postal Address")
	}

	if err == nil {
		var lcs [][]byte
		if lcs, err = lineChar(raw); err == nil {
			pa = PostalAddress(lcs)
		}
	}

	return
}

/*
OtherMailbox implements [§ 3.3.27 of RFC 4517]:

	OtherMailbox = mailbox-type DOLLAR mailbox
	mailbox-type = PrintableString
	mailbox      = IA5String
	IA5String    = *(%x00-7F)

From [§ 1.4 of RFC 4512]:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter

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
	DOLLAR  = %x24	               ; dollar sign ("$")

From [§ 3.2 of RFC 4517]:

	IA5String          = *(%x00-7F)

[§ 3.3.27 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.27
[§ 3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.2
[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
type OtherMailbox [2][]byte

func otherMailbox(x any) (result bool, err error) {
	_, err = marshalOtherMailbox(x)
	result = err == nil
	return
}

/*
OtherMailbox returns an error following an analysis of x in the context
of an [OtherMailbox].
*/
func NewOtherMailbox(x any) (OtherMailbox, error) {
	return marshalOtherMailbox(x)
}

func marshalOtherMailbox(x any) (om [2][]byte, err error) {
	var raw []byte

	badLen := func(l int) (err error) {
		if l < 1 {
			err = errorBadLength("Other Mailbox", 1)
		}
		return
	}

	switch tv := x.(type) {
	case []byte:
		err = badLen(len(tv))
		raw = tv
	case string:
		err = badLen(len(tv))
		raw = []byte(tv)
	default:
		err = errorBadType("Other Mailbox")
	}

	if err != nil {
		return
	}

	parts := splitUnescapedBytes(raw, []byte(`$`), []byte(`\`))
	if len(parts) != 2 {
		err = syntaxError("Invalid Other Mailbox value")
		return
	}

	if _, err = marshalPrintableString(parts[0]); err == nil {
		if _, err = marshalIA5String(parts[1]); err == nil {
			om[0] = append([]byte(nil), parts[0]...)
			om[1] = append([]byte(nil), parts[1]...)
		}
	}
	return
}

func lineChar(raw []byte) (lineChars [][]byte, err error) {
	var last rune
	value := &bytes.Buffer{}

	for i := 0; i < len(raw) && err == nil; {
		r, size := utf8.DecodeRune(raw[i:])
		if r == utf8.RuneError && size == 1 {
			err = syntaxError("invalid UTF-8")
			break
		}

		if r == '\\' {
			last = r
			i += size
			continue
		}

		if r == '$' {
			if last == r {
				err = syntaxError("Contiguous '$' runes; invalid line-char sequence")
				break
			} else if last == '\\' {
				value.WriteByte('\\')
				value.WriteByte('$')
				last = rune(0)
			} else {
				lineChars = append(lineChars, append([]byte(nil), value.Bytes()...))
				value.Reset()
				last = '$'
			}
			i += size
			continue
		}

		last = r
		if err = uTFMB(r); err == nil || unicode.Is(lineCharRange, r) {
			value.Write(raw[i : i+size])
			err = nil
		}

		i += size
	}

	if value.Len() > 0 && err == nil {
		lineChars = append(lineChars, append([]byte(nil), value.Bytes()...))
	}

	return
}
