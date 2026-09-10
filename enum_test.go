package syntax

import (
	"fmt"
)

func ExampleEnumerated_roundTripBER() {
	var enum Enumerated = 134758
	enc, err := enum.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec Enumerated
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(dec)
	// Output: 134758
}
