package syntax

import (
	"fmt"
)

func ExampleNull_roundTripBER() {
	var null Null
	enc, err := null.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec Null
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}
	// Output:
}
