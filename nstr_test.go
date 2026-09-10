package syntax

import (
	"fmt"
	"testing"
)

func ExampleNumericString_roundTripBER() {
	i, err := NewNumericString(1478231)
	if err != nil {
		fmt.Println(err)
		return
	}

	var enc []byte
	if enc, err = i.Encode(); err != nil {
		fmt.Println(err)
		return
	}

	var dec NumericString
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(dec)
	// Output: 1478231
}

func TestNumericString(t *testing.T) {
	for _, raw := range []any{
		`01 37 3748`,
		483982,
		`483982`,
		0,
		`00 00 00000000000000`,
	} {
		if ns, err := NewNumericString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else {
			_ = ns.String()
			if b, _ := numericString(raw); !b {
				t.Errorf("%s failed: failed to parse numericString", t.Name())
			}
		}
	}

	marshalNumericString(`ABC`)
}

func TestNumericString_SubstringsMatch(t *testing.T) {
	result, err := numericStringSubstringsMatch(`48 129 647`, `48*12* 6*7`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result {
		t.Errorf("%s failed:\nwant: %s\ngot:  %t", t.Name(), `TRUE`, result)
	}
}

func TestNumericString_NumericStringMatch(t *testing.T) {
	result, err := numericStringMatch(`01 37 47`, `013747`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result {
		t.Errorf("%s failed:\nwant: TRUE\ngot:  %t", t.Name(), result)
	}
}

func TestNumericString_OrderingMatch(t *testing.T) {
	result, err := numericStringOrderingMatch(`01 47 47`, LessOrEqual, `01 37 47`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if result {
		t.Errorf("%s failed:\nwant: FALSE\ngot:  %t", t.Name(), result)
		return
	}

	result, err = numericStringOrderingMatch(`01 47 47`, GreaterOrEqual, `01 37 47`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if !result {
		t.Errorf("%s failed:\n\twant: TRUE\n\tgot:  %t", t.Name(), result)
		return
	}
}

func TestNumericString_codecov(t *testing.T) {
	_, _, _ = prepareNumericStringAssertion(struct{}{}, `ok`)
	_, _, _ = prepareNumericStringAssertion(`ok`, struct{}{})
}
