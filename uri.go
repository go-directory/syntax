package syntax

/*
url.go contains the RFC4511 URI type; implements RFC4516 URL logic.
*/

import (
	"bytes"

	"github.com/go-directory/encoding/percent"
)

/*
URI implements [§ 4.1.10 of RFC4511] and [§ 2 of RFC4516].

This type is merely an [LDAPString] (OCTET STRING) meant to store an LDAP
URI description that has already undergone parsing.

[§ 4.1.10 of RFC4511] defines the ASN.1 URI definition:

	URI ::= LDAPString

[§ 2 of RFC4516] defines the following ABNF, which dictates how the
[LDAPString] representation of a URI should manifest:

	ldapurl     = scheme COLON SLASH SLASH [host [COLON port]]
	                 [SLASH dn [QUESTION [attributes]
	                 [QUESTION [scope] [QUESTION [filter]
	                 [QUESTION extensions]]]]]
	                                ; <host> and <port> are defined
	                                ;   in Sections 3.2.2 and 3.2.3
	                                ;   of [RFC3986].
	                                ; <filter> is from Section 3 of
	                                ;   [RFC4515], subject to the
	                                ;   provisions of the
	                                ;   "Percent-Encoding" section
	                                ;   below.
	scheme      = "ldap"
	dn          = distinguishedName ; From Section 3 of [RFC4514],
	                                ; subject to the provisions of
	                                ; the "Percent-Encoding"
	                                ; section below.
	attributes  = attrdesc *(COMMA attrdesc)
	attrdesc    = selector *(COMMA selector)
	selector    = attributeSelector ; From Section 4.5.1 of
	                                ; [RFC4511], subject to the
	                                ; provisions of the
	                                ; "Percent-Encoding" section
	                                ; below.
	scope       = "base" / "one" / "sub"
	extensions  = extension *(COMMA extension)
	extension   = [EXCLAMATION] extype [EQUALS exvalue]
	extype      = oid               ; From section 1.4 of [RFC4512].
	exvalue     = LDAPString        ; From section 4.1.2 of
	                                ; [RFC4511], subject to the
	                                ; provisions of the
	                                ; "Percent-Encoding" section
	                                ; below.
	EXCLAMATION = %x21              ; exclamation mark ("!")
	SLASH       = %x2F              ; forward slash ("/")
	COLON       = %x3A              ; colon (":")
	QUESTION    = %x3F              ; question mark ("?")

[§ 4.1.10 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4516#section-4.1.10
[§ 2 of RFC4516]: https://datatracker.ietf.org/doc/html/rfc4516#section-2
*/
type URI LDAPString

/*
NewURI returns an instance of [URI] alongside an error
following an attempt to parse the input value.
*/
func NewURI(x any) (URI, error) {
	var u URI
	b, err := assertBytes(x, 8, "URI")
	if err == nil {
		u, err = marshalURI(b)
	}
	return u, err
}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the receiver as an ASN.1 OCTET STRING.
*/
func (r URI) Encode() ([]byte, error) {
	return OctetString(r).Encode()
}

/*
Decode returns an error following an attempt to decode and write the
input encoding value into the receiver. The encoding must not be
truncated, and must bear the ASN.1 OCTET STRING tag (0x4).
*/
func (r *URI) Decode(enc []byte) error {
	var dec OctetString
	err := dec.Decode(enc)
	if err == nil {
		*r = URI(dec)
	}
	return err
}

/*
String returns the string representation of the receiver instance.
*/
func (r URI) String() string { return string(r) }

// uriBuilder is a temporary storage type for URI parsing routines.
type uriBuilder struct {
	Scheme     LDAPString
	Host       LDAPString
	Port       LDAPString
	DN         LDAPDN
	Attributes AttributeSelection
	Scope      *Enumerated
	Filter     Filter
	Extensions []LDAPOID
}

var uriScopes = map[Enumerated][]byte{
	0: scopeBase,
	1: scopeOne,
	2: scopeSub,
}

var uriScopeNames = map[string]Enumerated{
	"base": 0,
	"one":  1,
	"sub":  2,
}

func (r *uriBuilder) setHostPort(input, pfxtype []byte) (rest []byte, err error) {
	var hostPort []byte
	slashIdx := indexByte(input, '/')
	if slashIdx != -1 {
		hostPort = input[:slashIdx]
		rest = input[slashIdx+1:]
	} else {
		hostPort = input
		rest = nil
	}

	if len(hostPort) > 0 {
		colonIdx := indexByte(hostPort, ':')
		if colonIdx != -1 {
			r.Host = hostPort[:colonIdx]
			portBytes := hostPort[colonIdx+1:]
			if len(portBytes) == 0 {
				err = syntaxError("URI: service port must be numeric")
				return
			}
			n, aerr := atoi(b2s(portBytes))
			if aerr != nil {
				err = syntaxError("URI: service port must be numeric")
				return
			}
			if n < 1 || n > 65535 {
				err = syntaxError("URI: service port number must be unsigned and no greater than 65535")
				return
			}
			r.Port = portBytes
		} else {
			r.Host = hostPort
		}
	}

	return
}

func (r *uriBuilder) setDN(parts [][]byte) (err error) {
	if len(parts) > 0 && len(parts[0]) > 0 {
		dec, derr := percent.Decode(parts[0])
		if derr != nil {
			err = encodingError("URI: error decoding DN '",
				b2s(parts[0]), "': ", derr.Error())
			return
		}
		r.DN, err = NewLDAPDN(dec)
	}
	return
}

func (r *uriBuilder) setAttributes(parts [][]byte) (err error) {
	if len(parts) > 1 && len(parts[1]) > 0 {
		var dec [][]byte
		if indexByte(parts[1], '%') != -1 {
			d, derr := percent.Decode(parts[1])
			if derr != nil {
				err = derr
				return
			}
			dec = splitAndTrim(d, tComma)
		} else {
			dec = splitAndTrim(parts[1], tComma)
		}
		for i := 0; i < len(dec); i++ {
			if !isAttribute(dec[i]) {
				err = syntaxError("URI: malformed attribute '",
					b2s(dec[i]), "'")
				break
			}
			r.Attributes = append(r.Attributes, dec[i])
		}
	}
	return
}

func (r *uriBuilder) setScope(parts [][]byte) (err error) {
	if len(parts) > 2 && len(parts[2]) > 0 {
		lc := lc(parts[2])
		slc := b2s(lc)
		switch slc {
		case "base", "one", "sub":
			enum := uriScopeNames[slc]
			r.Scope = &enum
		default:
			err = syntaxError("URI: scope must be one of 'base', 'one', or 'sub'")
		}
	}
	return
}

func (r *uriBuilder) setFilter(parts [][]byte) (err error) {
	if len(parts) > 3 && len(parts[3]) > 0 {
		dec, derr := percent.Decode(parts[3])
		if derr != nil {
			err = encodingError("URI: error decoding filter: ", derr.Error())
			return
		}
		r.Filter, err = NewFilter(dec)
		if err != nil {
			err = syntaxError("URI: error parsing filter: ", err.Error())
			return
		}
	} else {
		r.Filter = invalidFilter{}
	}
	return
}

func (r *uriBuilder) setExtensions(parts [][]byte) (err error) {
	if len(parts) > 4 && len(parts[4]) > 0 {
		rawExts := splitAndTrim(parts[4], tComma)
		for i := 0; i < len(rawExts); i++ {
			dec, derr := percent.Decode(rawExts[i])
			if derr != nil {
				err = encodingError("URI: error decoding extension \": ",
					b2s(rawExts[i]), "\": ", derr.Error())
				return
			}
			r.Extensions = append(r.Extensions, dec)
		}
	}
	return
}

func marshalURI(input []byte) (r URI, err error) {

	// Determine kind of scheme and its text length.
	pfxlen, pfxtype := selectURIPrefix(input)
	if pfxlen == -1 {
		err = syntaxError("URI: invalid scheme: must begin with ldap://, ldaps:// or ldapi:///")
		return
	}

	// Remove the scheme prefix.
	remainder := input[pfxlen:]
	def := uriBuilder{Scheme: pfxtype}

	// If the URI is simply "scheme:///", this is fine.
	if bHasSfx(input, tTripleSlash) {
		r = URI(input)
		return
	}

	var rest []byte
	if rest, err = def.setHostPort(remainder, pfxtype); err != nil {
		return
	}

	parts := bytes.Split(rest, tQMark)

	if len(parts) > 5 {
		err = syntaxError("URI: read error: unsupported trailing content found: ",
			b2s(bytes.Join(parts[5:], tSpace)))
		return
	}

	// Throw an error if any trailing content is found
	if len(parts) > 5 {
		err = syntaxError("URI: read error: unsupported trailing content found: ",
			b2s(bytes.Join(parts[5:], tSpace)))
		return
	}

	for _, err = range []error{
		def.setDN(parts),
		def.setAttributes(parts),
		def.setScope(parts),
		def.setFilter(parts),
		def.setExtensions(parts),
	} {
		if err != nil {
			break
		}
	}

	if err == nil {
		r = URI(def.String())
	}

	return
}

func (r uriBuilder) printScheme() []byte {
	out := make([]byte, 0, 128)

	switch b2s(r.Scheme) {
	case "ldap", "ldaps":
		out = append(out, r.Scheme...)
		out = append(out, tColonDoubleSlash...)
		if len(r.Host) > 0 {
			out = append(out, r.Host...)
			if len(r.Port) > 0 {
				out = append(out, tColon...)
				out = append(out, r.Port...)
			}
		}
	case "ldapi":
		out = append(out, uriLDAPI...)
	}

	return out
}

func (r uriBuilder) String() string {
	chop := func(b []byte) []byte {
		b = bytes.TrimRight(b, "/")
		b = bytes.TrimRight(b, "?")
		return b
	}

	out := r.printScheme()
	if len(out) == 0 {
		return ``
	}

	out = append(out, tSlash...)

	if len(r.DN) > 0 {
		out = append(out, r.DN...)
	}

	if !(len(r.Attributes) > 0 ||
		r.Scope != nil ||
		r.Filter != nil ||
		len(r.Extensions) > 0) {

		out = chop(out)
		out = append(out, tTripleSlash...)
		return b2s(out)
	}

	out = append(out, tQMark...)

	if len(r.Attributes) > 0 {
		for i := 0; i < len(r.Attributes); i++ {
			if i > 0 {
				out = append(out, tComma...)
			}
			out = append(out, []byte(r.Attributes[i])...)
		}
	}

	out = append(out, tQMark...)
	if r.Scope != nil {
		out = append(out, uriScopes[*r.Scope]...)
	}

	out = append(out, tQMark...)
	if !r.Filter.IsZero() {
		out = append(out, s2b(r.Filter.String())...)
	}

	if len(r.Extensions) > 0 {
		out = append(out, tQMark...)
		for i := 0; i < len(r.Extensions); i++ {
			if i > 0 {
				out = append(out, tComma...)
			}
			out = append(out, r.Extensions[i]...)
		}
	}

	return string(chop(out))
}

func selectURIPrefix(input []byte) (l int, typ []byte) {
	low := lc(input)

	if bHasPfx(low, uriLDAP) {
		return len(uriLDAP), []byte("ldap")
	}
	if bHasPfx(low, uriLDAPS) {
		return len(uriLDAPS), []byte("ldaps")
	}
	if bHasPfx(low, uriLDAPI) {
		return len(uriLDAPI), []byte("ldapi")
	}

	return -1, nil
}

func splitAndTrim(s, sep []byte) [][]byte {
	// sep is always 1 byte in your code
	c := sep[0]

	var parts [][]byte
	start := 0

	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == c {
			if i > start {
				p := bytes.TrimSpace(s[start:i])
				if len(p) > 0 {
					parts = append(parts, p)
				}
			}
			start = i + 1
		}
	}
	return parts
}

func indexByte(b []byte, c byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func trimRightByte(b []byte, c byte) []byte {
	i := len(b) - 1
	for i >= 0 && b[i] == c {
		i--
	}
	return b[:i+1]
}

func trimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\t' || b[start] == '\n' || b[start] == '\r') {
		start++
	}
	end := len(b) - 1
	for end >= start && (b[end] == ' ' || b[end] == '\t' || b[end] == '\n' || b[end] == '\r') {
		end--
	}
	return b[start : end+1]
}
