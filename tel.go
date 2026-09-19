package syntax

import (
	"bytes"
	"strconv"
	"unicode"
)

var (
	ftnPRM map[string]uint
	ttxs   map[string]uint8
)

const (
	UBTelephoneNumber   int = 32   // X.520: ub-telephone-number INTEGER ::= 32
	UBTeletexTerminalID int = 1024 // X.520: ub-teletex-terminal-id INTEGER ::= 1024
	UBTeletexPrivateUse int = 128  // X.411: ub-teletex-private-use-length INTEGER ::= 128
)

/*
FacsimileTelephoneNumber implements [§ 3.3.11 of RFC 4517] and [§ 6.7.4 of ITU-T Rec.
X.520].

From [§ 3.3.11 of RFC 4517]:

	fax-number       = telephone-number *( DOLLAR fax-parameter )
	telephone-number = PrintableString
	fax-parameter    = "twoDimensional" /
	                   "fineResolution" /
	                   "unlimitedLength" /
	                   "b4Length" /
	                   "a3Width" /
	                   "b4Width" /
	                   "uncompressed"

ASN.1 definitions:

	FacsimileTelephoneNumber ::= SEQUENCE {
		telephoneNumber     PrintableString (SIZE(1.. ub-telephone-number)),
		parameters          G3FacsimileNonBasicParameters  OPTIONAL}

	G3FacsimileNonBasicParameters ::= BIT STRING {
		two-dimensional	     (8),
		fine-resolution	     (9),
		unlimited-length     (20),
		b4-length            (21),
		a3-width             (22),
		b4-width             (23),
		uncompressed         (30) }

[§ 3.3.11 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.11
[§ 6.7.4 of ITU-T Rec. X.520]: https://www.itu.int/rec/T-REC-X.520
*/
type FacsimileTelephoneNumber struct {
	TelephoneNumber               PrintableString `asn1:"printable"`
	G3FacsimileNonBasicParameters BitString       `asn1:"optional"`
}

/*
String returns the string representation of the receiver instance.
*/
func (r FacsimileTelephoneNumber) String() string {
	var s string
	if len(r.TelephoneNumber) == 0 {
		return s
	}

	var prms [][]byte
	for name, bit := range ftnPRM {
		if r.isSet(bit) {
			prms = append(prms, []byte(name))
		}
	}

	if ftn := r.TelephoneNumber.String(); len(prms) > 0 {
		buf := &bytes.Buffer{}
		buf.WriteString(ftn)
		buf.WriteRune('$')
		buf.Write(bytes.Join(prms, []byte(`$`)))
		s = buf.String()
	}

	return s
}

func (r FacsimileTelephoneNumber) isSet(bit uint) bool {
	if bit > 31 || len(r.G3FacsimileNonBasicParameters.Bytes) == 0 {
		return false
	}

	index := bit / 8
	pos := bit % 8
	return r.G3FacsimileNonBasicParameters.Bytes[index]&(1<<pos) != 0
}

func (r *FacsimileTelephoneNumber) IsZero() bool { return &r == nil }

func (r *FacsimileTelephoneNumber) set(bit uint) {
	if bit > 31 || r.IsZero() {
		return
	}

	index := bit / 8
	pos := bit % 8
	r.G3FacsimileNonBasicParameters.Bytes[index] |= 1 << pos
}

/*
FacsimileTelephoneNumber returns an instance of [FacsimileTelephoneNumber]
alongside an error.

From [§ 3.3.11 of RFC 4517]:

	fax-number       = telephone-number *( DOLLAR fax-parameter )
	telephone-number = PrintableString
	fax-parameter    = "twoDimensional" /
	                   "fineResolution" /
	                   "unlimitedLength" /
	                   "b4Length" /
	                   "a3Width" /
	                   "b4Width" /
	                   "uncompressed"

From [§ 1.4 of RFC 4512]:

	DOLLAR  = %x24 ; dollar sign ("$")

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.3.11 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.11
*/
func NewFacsimileTelephoneNumber(x any) (FacsimileTelephoneNumber, error) {
	return marshalFacsimileTelephoneNumber(x)
}

func facsimileTelephoneNumber(x any) (result bool, err error) {
	_, err = marshalFacsimileTelephoneNumber(x)
	result = err == nil
	return
}

func marshalFacsimileTelephoneNumber(x any) (ftn FacsimileTelephoneNumber, err error) {
	var raw []byte

	switch tv := x.(type) {
	case []byte:
		raw = tv
	case string:
		raw = []byte(tv)
	default:
		err = errorBadType("Facsimile Telephone Number")
		return
	}

	raws := splitUnescapedBytes(raw, []byte(`$`), []byte(`\`))

	if len(raws) <= 1 {
		err = syntaxError("Invalid Facsimile Telephone Number")
		return
	} else if ftn.TelephoneNumber, err = marshalPrintableString(raws[0]); err != nil || len(raws) == 1 {
		return
	}

	ftn.G3FacsimileNonBasicParameters = BitString{
		Bytes:     make([]byte, 4),
		BitLength: 32,
	}

	raws = raws[1:]

	for _, slice := range raws {
		bit, found := ftnPRM[string(slice)]
		if !found {
			err = syntaxError("Unknown Facsimile Telephone Number PRM value: ", string(slice))
			break
		} else if ftn.isSet(bit) {
			err = syntaxError("Duplicate Facsimile Telephone Number PRM value: ",
				string(slice), " at bit ", strconv.FormatInt(int64(bit), 10))
			break
		}
		ftn.set(bit)
	}

	return
}

/*
TelephoneNumber implements [§ 3.3.31 of RFC 4517] and [§ 6.7.1 of ITU-T Rec. X.520]:

	PrintableString (SIZE(1..ub-telephone-number))

[§ 6.7.1 of ITU-T Rec. X.520]: https://www.itu.int/rec/T-REC-X.520
[§ 3.3.31 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.31
*/
type TelephoneNumber PrintableString

/*
String returns the string representation of the receiver instance.
*/
func (r TelephoneNumber) String() string { return `+` + string(r) }

/*
TelephoneNumber returns an instance of [TelephoneNumber] alongside an error
following an analysis of x in the context of a Telephone Number.
*/
func NewTelephoneNumber(x any) (TelephoneNumber, error) {
	return marshalTelephoneNumber(x)
}

func telephoneNumber(x any) (result bool, err error) {
	_, err = marshalTelephoneNumber(x)
	result = err == nil
	return
}

func marshalTelephoneNumber(x any) (tn TelephoneNumber, err error) {
	badLen := func(tv []byte) (err error) {
		l := len(tv)
		if !(1 <= l && l <= UBTelephoneNumber) {
			err = errorBadLength("Telephone Number", l)
		} else if tv[0] != '+' {
			err = syntaxError("Telephone Number has invalid prefix: ", string(tv[0]))
		}
		return
	}

	var raw []byte
	switch tv := x.(type) {
	case []byte:
		raw = tv
	case string:
		raw = []byte(tv)
	default:
		err = errorBadType("Telephone Number")
		return
	}

	if err = badLen(raw); err == nil {
		raw = raw[1:]

		// TODO: conform more closely to E.123.
		for _, ch := range raw {
			char := rune(ch)
			if !unicode.In(char, digits, lAlphas, uAlphas, prsRange, telRange) {
				err = errorBadType("Invalid Telephone Number character: " + string(char))
				return
			}
		}

		if _, err = marshalPrintableString(raw); err == nil {
			tn = TelephoneNumber(raw)
		}
	}

	return
}

/*
TelexNumber implements TelexNumber per [§ 3.3.33 of RFC 4517]:

	telex-number  = actual-number DOLLAR country-code DOLLAR answerback
	actual-number = PrintableString
	country-code  = PrintableString
	answerback    = PrintableString

From [§ 3.2 of RFC 4517]:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter

From [§ 1.4 of RFC 4512]:

	DOLLAR  = %x24 ; dollar sign ("$")

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.2
[§ 3.3.33 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.33
*/
type TelexNumber [3][]byte

/*
TelexNumber returns an error following an analysis of x in the context
of a Telex Number.
*/
func NewTelexNumber(x any) (TelexNumber, error) {
	return marshalTelexNumber(x)
}

func telexNumber(x any) (result bool, err error) {
	_, err = marshalTelexNumber(x)
	result = err == nil
	return
}

func marshalTelexNumber(x any) (tn TelexNumber, err error) {
	var raw []byte

	switch tv := x.(type) {
	case []byte:
		raw = tv
	case string:
		raw = []byte(tv)
	default:
		return tn, errorBadType("Telex Number")
	}

	parts := splitUnescapedBytes(raw, []byte("$"), []byte("\\"))

	if len(parts) != 3 {
		return tn, syntaxError("Invalid Telex Number value")
	}

	for i := 0; i < 3; i++ {
		if _, err = marshalPrintableString(parts[i]); err != nil {
			return tn, err
		}
		tn[i] = append([]byte(nil), parts[i]...)
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r TelexNumber) String() string {
	var s string
	if r[0] != nil && r[1] != nil && r[2] != nil {
		buf := &bytes.Buffer{}
		buf.Write(r[0])
		buf.WriteRune('$')
		buf.Write(r[1])
		buf.WriteRune('$')
		buf.Write(r[2])
		s = buf.String()
	}

	return s
}

/*
TeletexTerminalIdentifier implements [§ 3.3.32 of RFC 4517] and

	teletex-id = ttx-term *(DOLLAR ttx-param)
	ttx-term   = PrintableString          ; terminal identifier
	ttx-param  = ttx-key COLON ttx-value  ; parameter
	ttx-key    = "graphic" / "control" / "misc" / "page" / "private"
	ttx-value  = *ttx-value-octet

	ttx-value-octet = %x00-23
	                  / (%x5C "24")  ; escaped "$"
	                  / %x25-5B
	                  / (%x5C "5C")  ; escaped "\"
	                  / %x5D-FF

ASN.1 definition, per [ITU-T Rec. X.520]:

	TeletexTerminalIdentifier ::= SEQUENCE {
		teletexTerminal PrintableString (SIZE(1..ub-teletex-terminal-id)),
		parameters	TeletexNonBasicParameters OPTIONAL
	}

	ub-teletex-terminal-id INTEGER ::= 1024

From [§ 3.2 of RFC 4517]:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter
	COLON              = %x3A  ; colon (":")

From [§ 1.4 of RFC 4512]:

	DOLLAR  = %x24 ; dollar sign ("$")

[ITU-T Rec. X.520]: https://www.itu.int/rec/T-REC-X.520
[§ 3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.2
[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.3.32 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.32
*/
type TeletexTerminalIdentifier struct {
	TeletexTerminal []byte                    `asn1:"printable"` // (SIZE(1..ub-teletex-terminal-id)),
	Parameters      TeletexNonBasicParameters `asn1:"set,optional"`
}

/*
TeletexNonBasicParameters is defined in [ITU-T Rec. X.420].

[ITU-T Rec. X.420]: https://www.itu.int/rec/T-REC-X.420
*/
type TeletexNonBasicParameters struct {
	GraphicCharacterSets     TeletexString `asn1:"tag:0,optional"` // TeletexString OPTIONAL
	CtrlCharacterSets        TeletexString `asn1:"tag:1,optional"` // TeletexString OPTIONAL
	PageFormats              OctetString   `asn1:"tag:2,optional"` // OCTET STRING OPTIONAL
	MiscTerminalCapabilities TeletexString `asn1:"tag:3,optional"` // TeletexString OPTIONAL
	PrivateUse               OctetString   `asn1:"tag:4,optional"` // OCTET STRING OPTIONAL
}

func (r TeletexTerminalIdentifier) String() string {
	var s string
	buf := &bytes.Buffer{}
	buf.Write(r.TeletexTerminal)
	if bt := r.Parameters.bytes(); len(bt) > 0 {
		buf.WriteRune('$')
		buf.Write(bt)
	}
	s = buf.String()

	return s
}

func (r TeletexNonBasicParameters) bytes() (nbp []byte) {
	var slice [][]byte
	if len(r.GraphicCharacterSets) > 0 {
		slice = append(slice, []byte(r.GraphicCharacterSets))
	}
	if len(r.CtrlCharacterSets) > 0 {
		slice = append(slice, []byte(r.CtrlCharacterSets))
	}
	if len(r.PageFormats) > 0 {
		slice = append(slice, []byte(r.PageFormats))
	}
	if len(r.MiscTerminalCapabilities) > 0 {
		slice = append(slice, []byte(r.MiscTerminalCapabilities))
	}
	if len(r.PrivateUse) > 0 {
		slice = append(slice, []byte(r.PrivateUse))
	}

	if len(slice) > 0 {
		nbp = bytes.Join(slice, []byte(`$`))
	}

	return nbp
}

/*
TeletexTerminalIdentifier returns an error following an analysis of x in
the context of a Teletex Terminal Identifier.
*/
func NewTeletexTerminalIdentifier(x any) (TeletexTerminalIdentifier, error) {
	return marshalTeletexTerminalIdentifier(x)
}

func teletexTerminalIdentifier(x any) (result bool, err error) {
	_, err = marshalTeletexTerminalIdentifier(x)
	result = err == nil
	return
}

func marshalTeletexTerminalIdentifier(x any) (tti TeletexTerminalIdentifier, err error) {
	var (
		raw []byte
		raws,
		vals [][]byte
	)

	switch tv := x.(type) {
	case []byte:
		raw = tv
	case string:
		raw = []byte(tv)
	default:
		err = errorBadType("Teletex Terminal Identifier")
		return
	}

	_raws := splitUnescapedBytes(raw, []byte(`$`), []byte(`\`))
	if raws, vals, err = marshalTeletex(_raws[1:]); err != nil {
		return
	} else if _, err = marshalPrintableString(_raws[0]); err != nil {
		return
	}

	tti.TeletexTerminal = _raws[0]

	var ct uint8
	for idx, slice := range raws {
		sl := string(slice)
		bit, found := ttxs[sl]
		if !found {
			err = syntaxError("Unknown Teletex Terminal Identifier TTXPRM value: ", sl)
			break
		} else if ct&bit > 0 {
			err = syntaxError("Duplicate Teletex Terminal Identifier TTXPRM value: ", sl)
			break
		}
		ct |= bit

		if idx < len(vals) {
			value := vals[idx]

			switch sl {
			case `graphic`:
				tti.Parameters.GraphicCharacterSets = TeletexString(value)
			case `control`:
				tti.Parameters.CtrlCharacterSets = TeletexString(value)
			case `private`:
				tti.Parameters.PrivateUse = OctetString(value)
			case `misc`:
				tti.Parameters.MiscTerminalCapabilities = TeletexString(value)
			case `page`:
				tti.Parameters.PageFormats = OctetString(value)
			}
		}
	}

	return
}

func marshalTeletex(_raws [][]byte) (raws, vals [][]byte, err error) {
	var cfound bool
	for i := 0; i < len(_raws); i++ {
		if idx := bytes.IndexRune(_raws[i], ':'); idx != -1 {
			cfound = true
			raw := _raws[i][:idx]
			aft := _raws[i][idx+1:]
			raws = append(raws, raw)

			ll := append(raw, []byte(`:`)...)
			if len(aft) > 0 {
				if err = teletexSuffixValue(aft); err != nil {
					return
				}
				ll = append(ll, aft...)
				vals = append(vals, ll)
			} else {
				vals = append(vals, ll)
			}
		} else {
			err = syntaxError("Teletex Terminal Identifier missing ttx-value")
			return
		}
	}

	if !(0 < len(raws) && len(raws) < UBTeletexTerminalID) {
		err = syntaxError("Missing Teletex Terminal Identifier value, or length out of bounds")
	}

	if !cfound {
		err = syntaxError("Teletex Terminal Identifier missing ':' token")
	}

	return
}

// RFC 4518 § 2.6.3
func prepareTelephoneNumberAssertion(a, b any) (bts1, bts2 []byte, err error) {
	switch tv := a.(type) {
	case []byte:
		bts1 = tv
	case string:
		bts1 = []byte(tv)
	default:
		err = errorBadType("NumericString")
		return
	}

	switch tv := b.(type) {
	case []byte:
		bts2 = tv
	case string:
		bts2 = []byte(tv)
	default:
		err = errorBadType("NumericString")
		return
	}

	for _, roon := range []rune{
		'\u002d', '\u058a', '\u2010', '\u2011',
		'\u2212', '\ufe63', '\uff0d', '\u0020',
	} {
		bts1 = bytes.ReplaceAll(bts1, []byte(string(roon)), []byte(``))
		bts2 = bytes.ReplaceAll(bts2, []byte(string(roon)), []byte(``))
	}

	return
}

func teletexSuffixValue(x []byte) (err error) {
	var last rune
	for _, ch := range x {
		if ch == '$' && last != '\\' {
			err = syntaxError("Unescaped '$' character found in TTID suffix")
			break
		} else if !(unicode.Is(ttxRange, rune(ch)) || ch == '\\') {
			err = syntaxError("Incompatible char for UTF0 (in UTFMB): ", string(ch))
			break
		}
		last = rune(ch)
	}

	return
}

func telephoneNumberSubstringsMatch(a, b any) (result bool, err error) {
	var str1, str2 []byte
	if str1, str2, err = prepareTelephoneNumberAssertion(a, b); err == nil {
		result, err = caseIgnoreSubstringsMatch(str1, str2)
	}

	return
}

func telephoneNumberMatch(a, b any) (result bool, err error) {
	var str1, str2 []byte
	if str1, str2, err = prepareTelephoneNumberAssertion(a, b); err == nil {
		result = bytes.EqualFold(str1, str2)
	}

	return
}

func init() {
	ttxs = map[string]uint8{
		`graphic`: uint8(1),
		`control`: uint8(2),
		`page`:    uint8(4),
		`misc`:    uint8(8),
		`private`: uint8(16),
	}

	ftnPRM = map[string]uint{
		`twoDimensional`:  uint(8),
		`fineResolution`:  uint(9),
		`unlimitedLength`: uint(20),
		`b4Length`:        uint(21),
		`a3Width`:         uint(22),
		`b4Width`:         uint(23),
		`uncompressed`:    uint(30),
	}
}
