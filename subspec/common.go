package subspec

import (
	"errors"
	"strconv"
	"strings"
)

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
	return mkerr(`Invalid length '`, strconv.FormatInt(int64(length), 10), `' for `, name)
}

func errorBadType(name string) error {
	return mkerr(`Incompatible input type for ` + name)
}

func streq(a, b string) bool {
	return a == b
}

func lc(in string) string {
	bld := &strings.Builder{}
	for i := 0; i < len(in); i++ {
		if c := rune(in[i]); isUAlpha(c) {
			c = rune(in[i]) + 32
			bld.WriteRune(c)
		} else {
			bld.WriteRune(c)
		}
	}

	return bld.String()
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
