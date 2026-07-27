package syntax

import (
	"errors"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func NewDistinguishedName(x string) (*ldap.DN, error) {
	return ldap.ParseDN(x)
}

func dN(x any) (ok bool, err error) {
	switch tv := x.(type) {
	case string:
		_, err = ldap.ParseDN(tv)
	default:
		err = errorBadType("ldap.DN")

	}
	return err == nil, err
}

/*
NameAndOptionalUID returns an error following an analysis of x in the
context of a Name and Optional UID.

From [§ 3.3.21 of RFC 4517]:

	NameAndOptionalUID = distinguishedName [ SHARP BitString ]

From [§ 3.3.2 of RFC 4517]:

	BitString    = SQUOTE *binary-digit SQUOTE "B"
	binary-digit = "0" / "1"

From [§ 1.4 of RFC 4512]:

	SHARP  = %x23   ; octothorpe (or sharp sign) ("#")
	SQUOTE = %x27   ; single quote ("'")

[§ 3.3.21 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.21
[§ 3.3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.2
[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
type NameAndOptionalUID struct {
	DN  *ldap.DN
	UID BitString `asn1:"optional"`
}

func nameAndOptionalUID(x any) (result bool, err error) {
	_, err = marshalNameAndOptionalUID(x)
	result = err == nil
	return
}

func marshalNameAndOptionalUID(x any) (nou NameAndOptionalUID, err error) {
	var raw string
	switch tv := x.(type) {
	case NameAndOptionalUID:
		nou = tv
		return
	case *ldap.DN:
		nou.DN = tv
		return
	default:
		if raw, err = assertString(x, 1, "Name and Optional UID"); err != nil {
			return
		}
	}

	var rev string
	for i := 0; i < len(raw); i++ {
		rev += string(raw[len(raw)-i-1])
	}

	var _l int = len(raw)
	if strings.HasPrefix(rev, `B'`) {
		var bitstring string = `'`

		for i := len(raw) - 2; i > 0; i-- {

			if raw[i-1] == '\'' || isDigit(rune(raw[i-1])) {
				bitstring += string(raw[i-1])
				continue
			}
			break
		}

		bitstring += `B`

		_l = _l - len(bitstring) - 1
		if delim := raw[_l]; delim != '#' {
			err = errors.New("Missing '#' delimiter for Name/UID pair; found " + string(delim))
			return
		}

		if nou.UID, err = marshalBitString(bitstring); err != nil {
			return
		}
	}

	var dn *ldap.DN
	if dn, err = ldap.ParseDN(raw[:_l]); err == nil {
		nou.DN = dn
	}

	return
}

func distinguishedNameMatch(a, b any) (result bool, err error) {
	mkDN := func(x any) (dn *ldap.DN, err error) {
		switch tv := a.(type) {
		case string:
			dn, err = ldap.ParseDN(tv)
		case *ldap.DN:
			dn = tv
		default:
			err = errorBadType("ldap.DN")
		}
		return
	}

	var dn1, dn2 *ldap.DN
	if dn1, err = mkDN(a); err != nil {
		return
	}

	if dn2, err = mkDN(b); err != nil {
		return
	}

	if len(dn1.RDNs) != len(dn2.RDNs) {
		return
	}

	for i := range dn1.RDNs {
		if !dn1.RDNs[i].Equal(dn2.RDNs[i]) {
			return
		}
	}

	result = true
	return
}

func uniqueMemberMatch(a, b any) (result bool, err error) {
	var nou1, nou2 NameAndOptionalUID
	if nou1, err = marshalNameAndOptionalUID(a); err != nil {
		return
	}

	if nou2, err = marshalNameAndOptionalUID(b); err != nil {
		return
	}

	if result, err = distinguishedNameMatch(nou1.DN, nou2.DN); err != nil || result {
		return
	}

	if len(nou1.UID.Bytes) == 0 && len(nou2.UID.Bytes) == 0 {
		result = true
	} else if len(nou1.UID.Bytes) != 0 && len(nou2.UID.Bytes) != 0 {
		result, err = bitStringMatch(nou1.UID, nou2.UID)
	}

	return
}
