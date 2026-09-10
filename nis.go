package syntax

import (
	"errors"
	"strings"
)

/*
NetgroupTriple implements the NIS Netgroup Triple type.  Instances of
this type are produced following a successful execution of the
[RFC2307.NetgroupTriple] function.

A zero instance of this type is equal to:

	("-","-","-")

From [§ 2.4 of RFC 2307]:

	nisnetgrouptriple = "(" hostname "," username "," domainname ")"
	hostname          = "" / "-" / keystring
	username          = "" / "-" / keystring
	domainname        = "" / "-" / keystring

ASN.1 definition:

	nisNetgroupTripleSyntax ::= SEQUENCE {
	        hostname   [0] IA5String OPTIONAL,
	        username   [1] IA5String OPTIONAL,
	        domainname [2] IA5String OPTIONAL
	}

From [§ 1.4 of RFC 4512]:

	keystring = leadkeychar *keychar
	leadkeychar = ALPHA
	keychar = ALPHA / DIGIT / HYPHEN

	ALPHA   = %x41-5A / %x61-7A     ; "A"-"Z" / "a"-"z"
	DIGIT   = %x30 / LDIGIT         ; "0"-"9"
	LDIGIT  = %x31-39               ; "1"-"9"
	HYPHEN  = %x2D                  ; hyphen ("-")

From [§ 3.2 of RFC 4517]:

	IA5String          = *(%x00-7F)

[§ 2.4 of RFC 2307]: https://datatracker.ietf.org/doc/html/rfc2307#section-2.4
[§ 3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.2
[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
type NetgroupTriple struct {
	Hostname IA5String `asn1:"tag:0,optional"`
	Username IA5String `asn1:"tag:1,optional"`
	Domain   IA5String `asn1:"tag:2,optional"`
}

/*
String returns the string representation of the receiver instance.
*/
func (r NetgroupTriple) String() string {
	var trips []string
	for _, ia5 := range []IA5String{
		r.Hostname,
		r.Username,
		r.Domain,
	} {
		if len(ia5) == 0 {
			// Use a hyphen for null, because it
			// Just Looks Better™.
			trips = append(trips, `-`)
		} else {
			trips = append(trips, ia5.String())
		}
	}

	return `(` + strings.Join(trips, `,`) + `)`
}

/*
NISNetgroupTriple returns an instance of [NetgroupTriple] alongside an error.

The input value type must be a string, such as `("laptop","jesse","example.com")`
or `("-","-","-")`.
*/
func NewNetgroupTriple(x any) (trip NetgroupTriple, err error) {
	var raw string
	if raw, err = assertString(x, 4, "NIS Netgroup Triple"); err != nil {
		return
	}

	if err = validTripleEncap(raw); err != nil {
		return
	}

	value := raw[1 : len(raw)-1]
	ngt := splitUnescaped(value, `,`, `\`)

	if len(ngt) != 3 {
		err = errors.New("NIS Netgroup Triple does not contain exactly three (3) keystring/hyphen/null values")
		return
	}

	var _trip NetgroupTriple

	for i := 0; i < len(ngt) && err == nil; i++ {
		var ia5 IA5String
		ia5, err = marshalIA5String(ngt[i])
		_trip.setNetgroupTripleFieldByIndex(i, ia5)
	}

	if err == nil {
		trip = _trip
	}

	return
}

func validTripleEncap(raw string) (err error) {
	if !(raw[0] == '(' && raw[len(raw)-1] == ')') {
		err = errors.New("NIS Netgroup Triple encapsulation error")
	}

	return
}

func (r *NetgroupTriple) setNetgroupTripleFieldByIndex(idx int, val any) {
	var ia5 IA5String

	switch tv := val.(type) {
	case string:
		if tv == "" {
			tv = "-"
		}
		ia5 = IA5String(tv)
	case IA5String:
		ia5 = tv
	default:
		return
	}

	switch idx {
	case 0:
		r.Hostname = ia5
	case 1:
		r.Username = ia5
	case 2:
		r.Domain = ia5
	}

	return
}

/*
BootParameter implements the NIS BootParameter type.  Instances of this type
are produced following a successful execution of the [RFC2307.BootParameter]
function.

From [§ 2.4 of RFC 2307]:

	bootparameter     = key "=" server ":" path
	key               = keystring
	server            = keystring
	path              = keystring

ASN.1 definition:

	bootParameterSyntax ::= SEQUENCE {
		key     IA5String,
		server  IA5String,
		path    IA5String
	}

From [§ 1.4 of RFC 4512]:

	keystring = leadkeychar *keychar
	leadkeychar = ALPHA
	keychar = ALPHA / DIGIT / HYPHEN

	ALPHA   = %x41-5A / %x61-7A   ; "A"-"Z" / "a"-"z"
	DIGIT   = %x30 / LDIGIT       ; "0"-"9"
	LDIGIT  = %x31-39             ; "1"-"9"
	HYPHEN  = %x2D ; hyphen ("-")

From [§ 3.2 of RFC 4517]:

	IA5String          = *(%x00-7F)

[§ 2.4 of RFC 2307]: https://datatracker.ietf.org/doc/html/rfc2307#section-2.4
[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.2
*/
type BootParameter struct {
	Key    IA5String
	Server IA5String
	Path   IA5String
}

/*
String returns the string representation of the receiver instance.
*/
func (r BootParameter) String() (bp string) {
	boots := []IA5String{
		r.Key,
		r.Server,
		r.Path,
	}

	for i := 0; i < len(boots); i++ {
		if len(boots[i]) == 0 {
			return
		}
	}

	bp = boots[0].String() + `=` + boots[1].String() + `:` + boots[2].String()

	return
}

/*
BootParameter returns an error following an analysis of x in the context
of a NIS Boot Parameter.
*/
func NewBootParameter(x any) (bp BootParameter, err error) {
	var raw string

	switch tv := x.(type) {
	case string:
		if len(tv) < 5 {
			err = errors.New("Boot Parameter: insufficient length")
			return
		}
		raw = tv
	default:
		err = errors.New("Boot Parameter")
		return
	}

	idx := strings.IndexRune(raw, '=')
	if idx == -1 {
		err = errors.New("Missing '=' delimiter for NIS Boot Parameter")
		return
	}

	idx2 := strings.IndexRune(raw, ':')
	if idx2 == -1 {
		err = errors.New("Missing ':' delimiter for NIS Boot Parameter")
		return
	}

	var bps [3]string

	for iidx, slice := range []string{
		raw[:idx],         // key
		raw[idx+1 : idx2], // server
		raw[idx2+1:],      // path
	} {
		if _, err = marshalIA5String(slice); err != nil {
			break
		}
		bps[iidx] = slice
	}

	if err == nil {
		bp.Key = IA5String(bps[0])
		bp.Server = IA5String(bps[1])
		bp.Path = IA5String(bps[2])
	}

	return
}

// TODO - not sure if we need this
func isKeystring(x string) bool {
	if len(x) == 0 {
		return false
	}

	if !isAlpha(rune(x[0])) || rune(x[len(x)-1]) == '-' {
		return false
	}

	var last rune
	for i := 1; i < len(x); i++ {
		if last == '-' && rune(x[i]) == last {
			return false
		} else if !isXString(rune(x[i])) {
			return false
		}
		last = rune(x[i])
	}

	return true
}

func isXString(r rune) bool {
	return isAlpha(r) || isDigit(r) || r == '-'
}

/*
splitUnescaped returns an instance of []string based upon an attempt
to split the input str value on separator characters which are NOT
escaped. Escaped separator values are ignored.

For example, this allows a string to be split on comma (,) while
ignoring escaped commas (\,).
*/
func splitUnescaped(str, sep, esc string) (slice []string) {
	slice = strings.Split(str, sep)
	for i := len(slice) - 2; i >= 0; i-- {
		if strings.HasSuffix(slice[i], esc) {
			slice[i] = slice[i][:len(slice[i])-len(esc)] + sep + slice[i+1]
			slice = append(slice[:i+1], slice[i+2:]...)
		}
	}

	return
}
