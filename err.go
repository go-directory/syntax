package syntax

import (
	"errors"

	"github.com/go-directory/common"
)

type commonErr = common.Error

func errorBadLength(name string, length int) error {
	return errors.New(`Invalid length '` + fint(int64(length), 10) + `' for ` + name)
}

func errorBadType(name string) error {
	return errors.New(`Incompatible input type for ` + name)
}

func syntaxError(msg ...string) error {
	return common.LDAPResultInvalidAttributeSyntax.New(msg...)
}

// non-asn1 encoding errors
func encodingError(msg ...string) (err commonErr) {
	err = common.LDAPResultOther.New(msg...)
	err.SetHeader("encoding:")
	return
}

func asn1Error(msg ...string) (err commonErr) {
	err = common.ErrorASN1.New(msg...)
	err.SetHeader("ASN.1:")
	return
}

