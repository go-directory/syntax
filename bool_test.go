package syntax

import (
	"fmt"
	"testing"
)

func ExampleBoolean_roundTripBER() {
	var b Boolean = true
	enc, err := b.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}
	var dec Boolean
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(dec)
	// Output: true
}

func TestNewBoolean(t *testing.T) {
	for _, b := range []any{
		true, false,
		`true`, `TRUE`, `false`, `FALSE`, `True`, `False`,
		byte(0x00), byte(0xFF),
	} {
		if _, err := NewBoolean(b); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}

	// coverage
	_, _ = NewBoolean(struct{}{})
	_, _ = boolean(true)
	_, _ = boolean(`falsch`)
	_, _ = boolean(nil)
	_, _ = boolean(byte(0x02))
	_, _ = boolean(-2)

	_, _ = booleanMatch(struct{}{}, true)
	_, _ = booleanMatch(true, struct{}{})
	_, _ = booleanMatch(false, true)
	_, _ = booleanMatch(nil, true)

	if result, err := booleanMatch(`TRUE`, false); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if result {
		t.Errorf("%s failed:\nwant: %t\ngot:  %t", t.Name(), false, result)
		return
	}
}
