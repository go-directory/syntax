package syntax

import (
	"bytes"
	"errors"
)

func caseIgnoreMatch(a, b any) (result bool, err error) {
	result, err = caseBasedMatch(a, b, false)
	return
}

func caseExactMatch(a, b any) (result bool, err error) {
	result, err = caseBasedMatch(a, b, true)
	return
}

func caseBasedMatch(a, b any, caseExact bool) (result bool, err error) {
	var b1, b2 []byte
	if b1, err = assertBytes(a, 1, "string"); err != nil {
		return
	}
	if b2, err = assertBytes(b, 1, "string"); err != nil {
		return
	}

	if caseExact {
		result = beq(b1, b2)
	} else {
		result = beqf(b1, b2)
	}

	return
}

func caseIgnoreOrderingMatch(a any, operator byte, b any) (bool, error) {
	return caseBasedOrderingMatch(a, b, false, operator)
}

func caseExactOrderingMatch(a any, operator byte, b any) (bool, error) {
	return caseBasedOrderingMatch(a, b, true, operator)
}

func caseBasedOrderingMatch(a, b any, caseExact bool, operator byte) (result bool, err error) {
	var b1, b2 []byte
	if b1, b2, err = prepareNumericBytesAssertion(a, b); err == nil {
		if caseExact {
			if operator == GreaterOrEqual {
				result = bytesCompare(b1, b2) >= 0
			} else {
				result = bytesCompare(b1, b2) <= 0
			}
		} else {
			l1 := lc(b1)
			l2 := lc(b2)
			if operator == GreaterOrEqual {
				result = bytesCompare(l1, l2) >= 0
			} else {
				result = bytesCompare(l1, l2) <= 0
			}
		}
	}

	return
}

/*
caseIgnoreSubstringsMatch implements [§ 4.2.13 of RFC 4517].

OID: 2.5.13.4.
*/
func caseIgnoreSubstringsMatch(a, b any) (result bool, err error) {
	result, err = substringsMatch(a, b, true)
	return
}

/*
caseExactSubstringsMatch implements [§ 4.2.6 of RFC 4517].

OID: 2.5.13.7.
*/
func caseExactSubstringsMatch(a, b any) (result bool, err error) {
	result, err = substringsMatch(a, b, false)
	return
}

func substringsMatch(a, b any, caseIgnore ...bool) (result bool, err error) {
	var value []byte
	value, err = assertBytes(a, 1, "actual value")
	if err != nil {
		return
	}

	var subs Substrings
	subs, err = marshalSubstrings(b)
	if err != nil {
		return
	}

	caseHandler := func(v []byte) []byte { return v }
	if len(caseIgnore) > 0 && caseIgnore[0] {
		caseHandler = lc
	}

	value = caseHandler(value)

	var init, fin []byte
	var Any []AssertionValue

	if init, fin, Any, err = substringsSplit(subs, caseHandler); err == nil {
		if len(init) > 0 {
			if !bHasPfx(value, init) {
				return
			}
			value = value[len(init):]
		}

		for _, seg := range Any {
			if len(seg) == 0 {
				continue
			}
			idx := bytes.Index(value, seg)
			if idx < 0 {
				return
			}
			value = value[idx+len(seg):]
		}

		if len(fin) > 0 {
			result = bHasSfx(value, fin)
			return
		}

		result = true
	}

	return
}

func substringsSplit(subs Substrings, caseHandler func([]byte) []byte) (init, fin []byte, Any []AssertionValue, err error) {
	var inits, fins int
	for _, s := range subs {
		switch v := s.(type) {
		case SubstringInitial:
			init = caseHandler([]byte(v))
			inits++
		case SubstringFinal:
			fin = caseHandler([]byte(v))
			fins++
		case SubstringAny:
			_Any := make([]AssertionValue, len(v))
			for i := range v {
				_Any[i] = AssertionValue(caseHandler([]byte(v[i])))
			}
			Any = append(Any, _Any...)
		}
	}

	if len(Any) == 0 {
		err = errorBadType("Substrings: at least one \"any\" AssertionValue is required")
	} else if inits > 1 {
		err = errors.New("Substrings: \"init\" AssertionValue can appear only once")
	} else if fins > 1 {
		err = errors.New("Substrings: \"final\" AssertionValue can appear only once")
	}

	return
}

func prepareStringListAssertion(a, b any) (b1, b2 []byte, err error) {
	assertSubstringsList := func(x any) (list []byte, err error) {
		slices, ok := x.([][]byte)
		if !ok {
			err = errorBadType("substringslist")
			return
		}

		var buf []byte
		for _, s := range slices {
			buf = append(buf, s...)
		}

		// remove escaped backslashes and dollars
		buf = bRepAll(buf, []byte(`\\`), nil)
		buf = bRepAll(buf, []byte(`$`), nil)

		list = buf
		return
	}

	if b1, err = assertSubstringsList(a); err == nil {
		b2, err = assertSubstringsList(b)
	}

	return
}

func caseIgnoreListSubstringsMatch(a, b any) (result bool, err error) {
	var b1, b2 []byte
	if b1, b2, err = prepareStringListAssertion(a, b); err == nil {
		result, err = caseIgnoreSubstringsMatch(b1, b2)
	}
	return
}

func caseIgnoreListMatch(a, b any) (result bool, err error) {
	var l1, l2 [][]byte
	if l1, l2, err = assertByteLists(a, b); err != nil {
		return
	}

	if len(l1) != len(l2) {
		return
	}

	for idx, slice := range l1 {
		if len(slice) == 0 || !beqf(slice, l2[idx]) {
			return
		}
	}

	result = true
	return
}

func assertByteLists(a, b any) (l1, l2 [][]byte, err error) {
	var ok bool

	if l1, ok = a.([][]byte); !ok {
		err = errorBadType("list")
		return
	}

	if l2, ok = b.([][]byte); !ok {
		err = errorBadType("list")
	}

	return
}

func caseExactIA5Match(a, b any) (bool, error) {
	return caseBasedIA5Match(a, b, true)
}

func caseIgnoreIA5Match(a, b any) (bool, error) {
	return caseBasedIA5Match(a, b, false)
}

func caseBasedIA5Match(a, b any, caseExact bool) (result bool, err error) {
	var b1, b2 []byte
	if b1, err = assertBytes(a, 1, "ia5String"); err != nil {
		return
	}
	if b2, err = assertBytes(b, 1, "ia5String"); err != nil {
		return
	}

	if _, err = marshalIA5String(b1); err == nil {
		if _, err = marshalIA5String(b2); err == nil {
			if caseExact {
				result = beq(b1, b2)
			} else {
				result = beqf(b1, b2)
			}
		}
	}

	return
}

func prepareIA5StringAssertion(a, b any) (b1, b2 []byte, err error) {
	assertIA5 := func(x any) (i []byte, err error) {
		var raw []byte
		if raw, err = assertBytes(x, 1, "IA5String"); err == nil {
			if _, err = marshalIA5String(raw); err == nil {
				i = raw
			}
		}
		return
	}

	if b1, err = assertIA5(a); err == nil {
		b2, err = assertIA5(b)
	}

	return
}

func caseIgnoreIA5SubstringsMatch(a, b any) (result bool, err error) {
	var b1, b2 []byte
	if b1, b2, err = prepareIA5StringAssertion(a, b); err == nil {
		result, err = caseIgnoreSubstringsMatch(b1, b2)
	}
	return
}

func prepareNumericBytesAssertion(a, b any) (b1, b2 []byte, err error) {
	var s1, s2 []byte
	if s1, err = assertBytes(a, 1, "string"); err != nil {
		return
	}
	if s2, err = assertBytes(b, 1, "string"); err != nil {
		return
	}
	b1 = s1
	b2 = s2
	return
}
