package subspec

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
)

var (
	lc      func(string) string                    = strings.ToLower
	fmtInt  func(int64, int) string                = strconv.FormatInt
	atoi    func(string) (int, error)              = strconv.Atoi
	itoa    func(int) string                       = strconv.Itoa
	fields  func(string) []string                  = strings.Fields
	trimS   func(string) string                    = strings.TrimSpace
	trimL   func(string, string) string            = strings.TrimLeft
	trimR   func(string, string) string            = strings.TrimRight
	trimPfx func(string, string) string            = strings.TrimPrefix
	trimSfx func(string, string) string            = strings.TrimSuffix
	hasPfx  func(string, string) bool              = strings.HasPrefix
	hasSfx  func(string, string) bool              = strings.HasSuffix
	join    func([]string, string) string          = strings.Join
	split   func(string, string) []string          = strings.Split
	splitN  func(string, string, int) []string     = strings.SplitN
	stridx  func(string, string) int               = strings.Index
	idxr    func(string, rune) int                 = strings.IndexRune
	repAll  func(string, string, string) string    = strings.ReplaceAll
	puint   func(string, int, int) (uint64, error) = strconv.ParseUint
	fuint   func(uint64, int) string               = strconv.FormatUint
	streqf  func(string, string) bool              = strings.EqualFold
	trim    func(string, string) string            = strings.Trim
	valOf   func(any) reflect.Value                = reflect.ValueOf
	typeOf  func(any) reflect.Type                 = reflect.TypeOf
)

/*
isPtr returns a Boolean value indicative of whether kind
reflection revealed the presence of a pointer type.
*/
func isPtr(x any) bool {
	return typeOf(x).Kind() == reflect.Ptr
}

func mkerr(msgs ...string) error {
	if len(msgs) == 0 {
		return nil
	} else if len(msgs) == 1 {
		return errors.New(msgs[0])
	}

	e := &strings.Builder{}
	for _, msg := range msgs {
		e.WriteString(msg)
	}

	return errors.New(e.String())
}

func errorBadLength(name string, length int) error {
	return mkerr(`Invalid length '` + fmtInt(int64(length), 10) + `' for ` + name)
}

func errorBadType(name string) error {
	return mkerr(`Incompatible input type for ` + name)
}

func removeWHSP(a string) string {
	return repAll(a, ` `, ``)
}

func streq(a, b string) bool {
	return a == b
}

/*
isAttribute returns a boolean value indicative of whether val
describes a numeric OID or RFC 4512 descriptor ("descr").

This is used, specifically, it identify an schema definition's
"NAME" or specify any number of values for an ACIAttribute.
*/
func isAttribute(val string) (is bool) {
	// TODO: proper oid check
	if is = len(val) > 0 && isDigit(rune(val[0])); !is {
		is = isAttributeDescriptor(val)
	}

	return
}

/*
isAttributeDescriptor scans the input string val and judges
whether it appears to qualify as a valid RFC 4512 descriptor
(or "descr"), in that:

  - it begins with an alpha
  - it ends with an alpha or digit
  - it contains only alphas, digits, hyphens or semicolons
  - it contains no consecutive hyphens or semicolons
*/
func isAttributeDescriptor(val string) bool {
	if len(val) == 0 {
		return false
	}

	// must begin with an alpha.
	if !isAlpha(rune(val[0])) {
		return false
	}

	// can only end in alnum.
	if !isAlnum(rune(val[len(val)-1])) {
		return false
	}

	for i := 0; i < len(val); i++ {
		ch := rune(val[i])
		switch {
		case isAlnum(ch):
			// ok
		case ch == ';', ch == '-':
			// ok
		default:
			return false
		}
	}

	return true
}

/*
newStrBuilder is a private function which returns an
instance of strings.Builder. This is merely a convenience
wrapper which avoids the need for multiple import calls
of the bytes package.
*/
func newStrBuilder() strings.Builder {
	return strings.Builder{}
}

/*
strInSlice returns a Boolean value indicative of the presence of
r within the input slice value.  The optional variadic input value
cEM indicates whether the matching process should recognize exact
case folding.

By default, case is not significant in the matching process.
*/
func strInSlice(r any, slice []string, cEM ...bool) (match bool) {
	// assume caseIgnoreMatch by default
	funk := streqf
	if len(cEM) > 0 {
		if cEM[0] {
			// use caseExactMatch
			funk = streq
		}
	}

	switch tv := r.(type) {
	case string:
		for i := 0; i < len(slice) && !match; i++ {
			match = funk(tv, slice[i])
		}
	case []string:
		for i := 0; i < len(tv) && !match; i++ {
			for j := 0; j < len(slice) && !match; j++ {
				match = funk(tv[i], slice[j])
			}
		}
	}

	return
}

func assertString(x any, min int, name string) (str string, err error) {
	switch tv := x.(type) {
	case []byte:
		str, err = assertString(string(tv), min, name)
	case string:
		if len(tv) < min && min != 0 {
			err = errorBadLength(name, 0)
			break
		}
		str = tv
	default:
		err = errorBadType(name)
	}

	return
}
