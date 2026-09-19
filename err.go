package syntax

import (
	"errors"
	"strconv"

	"github.com/go-directory/common"
)

func errorBadLength(name string, length int) error {
	return errors.New(`Invalid length '` + strconv.FormatInt(int64(length), 10) + `' for ` + name)
}

func errorBadType(name string) error {
	return errors.New(`Incompatible input type for ` + name)
}

func syntaxError(msg ...string) error {
	return common.LDAPResultInvalidAttributeSyntax.New(msg...)
}

// non-asn1 encoding errors
func encodingError(msg ...string) error {
	return common.LDAPResultOther.New(msg...)
}

func asn1Error(msg ...string) error {
	m := append([]string{"ASN.1 "}, msg...)
	return common.ErrorASN1.New(m...)
}

func zeroE(err error) bool { return common.ZeroError(err) }

func setDiag(err error, msg ...string) error {
	if is, ok := err.(common.Error); ok {
		is.SetDiag(msg...)
		err = is
	}

	return err
}
