package syntax

import (
	"errors"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type DistinguishedName struct {
	DN         *ldap.DN
	Normal     []byte
	Case       []byte
	Attributes [][]byte
	Values     [][]byte
}

func NewDistinguishedName(x []byte, preproc bool) (DistinguishedName, error) {
	var dn DistinguishedName
	_dn, err := ldap.ParseDN(string(x))
	if err == nil {
		dn = DistinguishedName{DN: _dn}
		if preproc {
			str := _dn.String()
			dn.Normal = []byte(strings.ToLower(str))
			dn.Case = []byte(str)
			dn.Attributes = make([][]byte, 0)
			dn.Values = make([][]byte, 0)

			atSeen := make(map[string]struct{})
			for i := 0; i < len(_dn.RDNs); i++ {
				for j := 0; j < len(_dn.RDNs[i].Attributes); j++ {
					at := _dn.RDNs[i].Attributes[j]
					if _, found := atSeen[at.Type]; !found {
						atSeen[at.Type] = struct{}{}
						dn.Attributes = append(dn.Attributes, []byte(at.Type))
					}
					dn.Values = append(dn.Values, []byte(at.Value))
				}
			}
		}
	}

	return dn, err
}

func dN(x any) (ok bool, err error) {
	switch tv := x.(type) {
	case DistinguishedName:
		if tv.DN == nil {
			err = errors.New("Invalid *ldap.DN instance")
		}
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
	DN  DistinguishedName
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
	case DistinguishedName:
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

	var dn DistinguishedName
	if dn.DN, err = ldap.ParseDN(raw[:_l]); err == nil {
		nou.DN = dn
	}

	return
}

func distinguishedNameMatch(a, b any) (result bool, err error) {
	mkDN := func(x any) (dn DistinguishedName, err error) {
		switch tv := a.(type) {
		case DistinguishedName:
			if tv.DN == nil {
				err = errors.New("Nil *ldap.DN")
				break
			}
			dn = tv
		case string:
			dn.DN, err = ldap.ParseDN(tv)
		default:
			err = errorBadType("ldap.DN")
		}
		return
	}

	var dn1, dn2 DistinguishedName
	if dn1, err = mkDN(a); err != nil {
		return
	}

	if dn2, err = mkDN(b); err != nil {
		return
	}

	result = dn1.DN.EqualFold(dn2.DN)
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
