package syntax

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-directory/encoding/asn1"
)

func aTag(class byte, constr bool, tag uint32) asn1.Tag {
	return asn1.Tag{
		Class:       class,
		Constructed: constr,
		Tag:         uint32(tag),
	}
}

func uSeqTag() asn1.Tag { return aTag(0, true, 16) }

type textLike interface{ ~string | ~[]byte }

var itoa = strconv.Itoa
var atoi = strconv.Atoi
var puint = strconv.ParseUint
var fuint = strconv.FormatUint
var fint = strconv.FormatInt

func b2s(b []byte) string { return string(b) }
func s2b(b string) []byte { return []byte(b) }

func beq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func beqf(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		aa := a[i]
		bb := b[i]
		if aa >= 'A' && aa <= 'Z' {
			aa += 'a' - 'A'
		}
		if bb >= 'A' && bb <= 'Z' {
			bb += 'a' - 'A'
		}
		if aa != bb {
			return false
		}
	}
	return true
}

func lc(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

func bHasPfx(s, prefix []byte) bool {
	if len(prefix) > len(s) {
		return false
	}
	for i := range prefix {
		if s[i] != prefix[i] {
			return false
		}
	}
	return true
}

func bHasSfx(s, suffix []byte) bool {
	if len(suffix) > len(s) {
		return false
	}
	offset := len(s) - len(suffix)
	for i := range suffix {
		if s[offset+i] != suffix[i] {
			return false
		}
	}
	return true
}

func bytesIndex(s, substr []byte) int {
	n := len(substr)
	if n == 0 {
		return 0
	}
	if n > len(s) {
		return -1
	}
	for i := 0; i <= len(s)-n; i++ {
		match := true
		for j := 0; j < n; j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func splitOnByte(s []byte, sep byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func trimStars(b []byte) []byte {
	start := 0
	end := len(b)

	for start < end && b[start] == '*' {
		start++
	}
	for end > start && b[end-1] == '*' {
		end--
	}

	return b[start:end]
}

func bRepAll(s, old, new []byte) []byte {
	if len(old) == 0 {
		return s
	}
	var out []byte
	i := 0
	for i <= len(s)-len(old) {
		match := true
		for j := 0; j < len(old); j++ {
			if s[i+j] != old[j] {
				match = false
				break
			}
		}
		if match {
			out = append(out, new...)
			i += len(old)
		} else {
			out = append(out, s[i])
			i++
		}
	}
	out = append(out, s[i:]...)
	return out
}

func bytesCompare(a, b []byte) int {
	min := len(a)
	if len(b) < min {
		min = len(b)
	}
	for i := 0; i < min; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
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

/*
splitUnescaped returns an instance of [][]byte based upon an attempt
to split the input str value on separator characters which are NOT
escaped. Escaped separator values are ignored.

For example, this allows a string to be split on comma (,) while
ignoring escaped commas (\,).
*/
func splitUnescapedBytes(str, sep, esc []byte) [][]byte {
	var out [][]byte
	var buf bytes.Buffer

	var s byte
	var e byte

	if len(sep) > 0 {
		s = sep[0]
	}
	if len(esc) > 0 {
		e = esc[0]
	}

	escaped := false

	for _, b := range str {
		if escaped {
			buf.WriteByte(b)
			escaped = false
			continue
		}

		if b == e {
			escaped = true
			continue
		}

		if b == s {
			out = append(out, append([]byte(nil), buf.Bytes()...))
			buf.Reset()
			continue
		}

		buf.WriteByte(b)
	}

	out = append(out, append([]byte(nil), buf.Bytes()...))
	return out
}

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

func assertBytes(x any, minimum int, name string) (val []byte, err error) {
	badLen := func(l int) (err error) {
		if l < minimum && minimum != 0 {
			err = errorBadLength(name, 0)
		}
		return
	}

	switch tv := x.(type) {
	case []byte:
		err = badLen(len(tv))
		val = tv
	case string:
		err = badLen(len(tv))
		val = []byte(tv)
	default:
		err = errorBadType(name)
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

func escapeString(x string) (esc string) {
	if len(x) > 0 {
		bld := &strings.Builder{}
		for _, z := range x {
			if z > maxASCII {
				for _, c := range []byte(string(z)) {
					bld.WriteString(`\`)
					bld.WriteString(strconv.FormatUint(uint64(c), 16))
				}
			} else {
				bld.WriteRune(z)
			}
		}

		esc = bld.String()
	}

	return
}

func hexDecode(x any) string {
	var r string
	switch tv := x.(type) {
	case string:
		r = tv
	case []byte:
		r = string(tv)
	default:
		return ``
	}

	d := &strings.Builder{}
	length := len(r)

	for i := 0; i < length; i++ {
		if r[i] == '\\' && i+3 <= length {
			b, err := hex.DecodeString(r[i+1 : i+3])
			if err != nil || !(isHex(rune(r[i+1])) || isHex(rune(r[i+2]))) {
				return ``
			}
			d.Write(b)
			i += 2
		} else {
			d.WriteString(string(r[i]))
		}
	}

	return d.String()
}

// TODO: kill me
func strInSlice(r any, slice []string, cEM ...bool) (match bool) {
	// assume caseIgnoreMatch by default
	funk := strings.EqualFold
	if len(cEM) > 0 && cEM[0] {
		// use caseExactMatch
		funk = func(a, b string) bool { return a == b }
	}

	loop := func(a string) (match bool) {
		for i := 0; i < len(slice) && !match; i++ {
			match = funk(a, slice[i])
		}
		return
	}

	switch tv := r.(type) {
	case string:
		match = loop(tv)
	case []string:
		for i := 0; i < len(tv) && !match; i++ {
			match = loop(tv[i])
		}
	}

	return
}

// foldString returns a folded string such that foldString(x) == foldString(y)
// is identical to bytes.EqualFold(x, y).
// based on https://go.dev/src/encoding/json/fold.go
func foldString(s string) string {
	builder := strings.Builder{}
	for _, char := range s {
		// Handle single-byte ASCII.
		if char < runeSelf {
			if 'A' <= char && char <= 'Z' {
				char += 'a' - 'A'
			}
			builder.WriteRune(char)
			continue
		}

		builder.WriteRune(foldRune(char))
	}
	return builder.String()
}
