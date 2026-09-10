package syntax

import (
	"fmt"
	"testing"
)

func ExampleTeletexString_roundTripBER() {
	t61, err := NewTeletexString("Hello T.61")
	if err != nil {
		fmt.Println(err)
		return
	}

	var enc []byte
	if enc, err = t61.Encode(); err != nil {
		fmt.Println(err)
		return
	}

	var dec TeletexString
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(dec)
	// Output: Hello T.61
}

func ExampleTeletexString_IsZero() {
	var tel TeletexString
	fmt.Println(tel.IsZero())
	// Output: true
}

func TestTeletexString_codecov(t *testing.T) {
	teletexString(`X`)
	teletexString(``)
	marshalTeletexString([]byte{0x1E, 0x3, 0x2, 0x3, 0x5})
}
