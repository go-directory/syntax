package syntax

import (
	"fmt"
	"testing"
)

func TestPrintableString(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`WAT`),
		[]byte(`This is a printable string.`),
	} {
		if _, err := NewPrintableString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}

	_, _ = marshalPrintableString(`&1.555.123.4567`)
	_, _ = marshalPrintableString(`&1.555👩123.4567`)

}

func ExamplePrintableString_roundTripBER() {
	ps := PrintableString("JERRY. HELLO.")
	enc, err := ps.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}
	var dec PrintableString
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", dec)
	// Output: JERRY. HELLO.

}
