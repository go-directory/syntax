package syntax

import (
	"strings"
)

/*
NetgroupTriple implements the NIS Netgroup Triple type.  Instances of
this type are produced following a successful execution of the
[NewNetgroupTriple] function.

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
	var raw []byte
	if raw, err = assertBytes(x, 4, "NIS Netgroup Triple"); err == nil {
		if err = validTripleEncap(raw); err == nil {
			value := raw[1 : len(raw)-1]
			ngt := splitUnescapedBytes(value, tComma, tBSlash)

			if len(ngt) != 3 {
				err = syntaxError("NIS Netgroup Triple does not contain exactly three (3) keystring/hyphen/null values")
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
		}
	}

	return
}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the receiver instance as a UNIVERSAL SEQUENCE.
*/
func (r NetgroupTriple) Encode() ([]byte, error) {
	var payload []byte
	var err error
	var out []byte
	for idx, component := range []IA5String{
		r.Hostname,
		r.Username,
		r.Domain,
	} {
		if len(component) > 0 {
			var enc []byte
			if enc, err = component.Encode(); err != nil {
				break
			}

			// wrap it in a context tag
			var wrap []byte
			wrap, err = wrapTLV(enc,
				aTag(classC, false, uint32(idx)))
			if err != nil {
				break
			}
			payload = append(payload, wrap...)
		}
	}

	if err == nil {
		out, err = wrapTLV(payload, uSeqTag())
	}

	return out, err
}

func (r *NetgroupTriple) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag())
	if err == nil {
		p := 0
		for i := 0; i < 3 && err == nil; i++ {
			var tlv []byte
			tlv, err = readEPTLV(
				payload,
				&p,
				classC,
				uint32(i))

			if err == nil {
				var ia5 IA5String
				if err = ia5.Decode(tlv); err == nil {
					switch i {
					case 0:
						r.Hostname = ia5
					case 1:
						r.Username = ia5
					case 2:
						r.Domain = ia5
					default:
						err = asn1Error("NetgroupTriple: extra data found during decode")
					}
				}
			}
		}
	}

	return err
}

func validTripleEncap(raw []byte) (err error) {
	if !(raw[0] == '(' && raw[len(raw)-1] == ')') {
		err = syntaxError("NIS Netgroup Triple encapsulation error")
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
are produced following a successful execution of the [NewBootParameter]
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
			err = syntaxError("Boot Parameter: insufficient length")
			return
		}
		raw = tv
	default:
		err = syntaxError("Boot Parameter")
		return
	}

	idx := strings.IndexRune(raw, '=')
	if idx == -1 {
		err = syntaxError("Missing '=' delimiter for NIS Boot Parameter")
		return
	}

	idx2 := strings.IndexRune(raw, ':')
	if idx2 == -1 {
		err = syntaxError("Missing ':' delimiter for NIS Boot Parameter")
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

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the receiver instance as a UNIVERSAL SEQUENCE.
*/
func (r BootParameter) Encode() ([]byte, error) {
	var payload []byte
	var err error

	for _, component := range []IA5String{
		r.Key,
		r.Server,
		r.Path,
	} {
		if len(component) == 0 {
			continue
		}

		var enc []byte
		enc, err = component.Encode() // IA5 TLV: 16 LL VALUE
		if err != nil {
			return nil, err
		}

		payload = append(payload, enc...)
	}

	return wrapTLV(payload, uSeqTag())
}

func (r *BootParameter) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag())
	if err != nil {
		return err
	}

	p := 0
	for i := 0; i < 3; i++ {
		if p >= len(payload) {
			return asn1Error("BootParameter: truncated IA5String")
		}

		// Expect IA5 tag
		if payload[p] != tIA5 {
			return errIA5Decode
		}

		// Read IA5 length
		l, n := readLen(payload[p+1:])
		if n == 0 || len(payload) < p+1+n+l {
			return errIA5Decode
		}

		// Full IA5 TLV slice
		tlv := payload[p : p+1+n+l]

		var ia5 IA5String
		if err = ia5.Decode(tlv); err == nil {
			switch i {
			case 0:
				r.Key = ia5
			case 1:
				r.Server = ia5
			case 2:
				r.Path = ia5
			}

			p += 1 + n + l
		}
	}

	return nil
}
