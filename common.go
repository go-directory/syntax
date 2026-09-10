package syntax

import (
	"reflect"
	"strings"
)

type textLike interface{ ~string | ~[]byte }

/*
assertFirstStructField is a private function used for
firstComponent EQUALITY matching, in which the first
struct (ASN.1 SEQUENCE) field is matched.
*/
func assertFirstStructField(x any) (first any) {
	if isStruct(x) {
		if typ := reflect.TypeOf(x); typ.NumField() > 0 {
			first = reflect.ValueOf(x).Field(0).Interface()
		}
	}

	return
}

/*
isStruct is a private function which returns a Boolean
value indicative of whether kind reflection revealed
the presence of a struct type.
*/
func isStruct(x any) (is bool) {
	if x != nil {
		is = reflect.TypeOf(x).Kind() == reflect.Struct
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

func isNegativeInteger(x any) (is bool) {
	switch tv := x.(type) {
	case int:
		is = tv < 0
	case int8:
		is = tv < 0
	case int16:
		is = tv < 0
	case int32:
		is = tv < 0
	case int64:
		is = tv < 0
	}

	return
}

func castInt64(x any) (i int64, err error) {
	switch tv := x.(type) {
	case int:
		i = int64(tv)
	case int8:
		i = int64(tv)
	case int16:
		i = int64(tv)
	case int32:
		i = int64(tv)
	case int64:
		i = tv
	default:
		err = errorBadType("castInt64")
	}

	return
}

func castUint64(x any) (i uint64, err error) {
	switch tv := x.(type) {
	case uint:
		i = uint64(tv)
	case uint8:
		i = uint64(tv)
	case uint16:
		i = uint64(tv)
	case uint32:
		i = uint64(tv)
	case uint64:
		i = tv
	default:
		err = errorBadType("castUint64")
	}

	return
}

func strInSlice(r any, slice []string, cEM ...bool) (match bool) {
	// assume caseIgnoreMatch by default
	funk := strings.EqualFold
	if len(cEM) > 0 {
		if cEM[0] {
			// use caseExactMatch
			funk = func(a, b string) bool {
				return a == b
			}
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

/*
ber encoder for OctetString, PrintableString, et al.
*/
func encodePrimitive(tag byte, v []byte) ([]byte, error) {
	l := len(v)
	var out []byte

	switch {
	case l < 128:
		out = make([]byte, 2+l)
		out[0] = tag
		out[1] = byte(l)
		copy(out[2:], v)
	default:
		n := lengthBytes(l)
		out = make([]byte, 1+1+n+l)
		out[0] = tag
		out[1] = 0x80 | byte(n)
		writeLength(out[2:2+n], l)
		copy(out[2+n:], v)
	}

	return out, nil
}

func lengthBytes(l int) int {
	switch {
	case l < 256:
		return 1
	case l < 65536:
		return 2
	case l < 16777216:
		return 3
	default:
		return 4
	}
}

func writeLength(dst []byte, l int) {
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = byte(l)
		l >>= 8
	}
}

func readLength(b []byte) (int, int) {
	if len(b) == 0 {
		return 0, 0
	}
	if b[0] < 128 {
		return int(b[0]), 1
	}
	n := int(b[0] & 0x7F)
	if len(b) < 1+n {
		return 0, 0
	}
	l := 0
	for i := 0; i < n; i++ {
		l = (l << 8) | int(b[1+i])
	}
	return l, 1 + n
}
