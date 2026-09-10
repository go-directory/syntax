package syntax

import (
	"fmt"
	"testing"
)

func ExampleUniversalString_roundTripBER() {
	text := `This is a UniversalString.`
	u, err := NewUniversalString(text)
	if err != nil {
		fmt.Println(err)
		return
	}

	var enc []byte
	if enc, err = u.Encode(); err != nil {
		fmt.Println(err)
		return
	}

	var dec UniversalString
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(dec)
	// Output: This is a UniversalString.
}

func TestUniversalString(t *testing.T) {
	for _, raw := range []string{
		`平仮名`,
		`This is a UniversalString.`,
		`This is@~@@~~~ not UniversalString ﺝﺦﺕﺣﺛ^\^\rOH WAIT yes it is`,
	} {
		if _, err := NewUniversalString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestUniversalString_codecov(t *testing.T) {
	_ = universalString(`This is@~@@~~~ not UniversalString ﺝﺦﺕﺣﺛ^\^\rOH WAIT yes it is`)
}
