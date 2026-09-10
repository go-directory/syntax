package syntax

import (
	"fmt"
)

func ExampleUTF8String_roundTripBER() {
	u := UTF8String("I am a UTF-8 string")
	enc, err := u.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec UTF8String
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s", dec)
	// Output: I am a UTF-8 string
}
