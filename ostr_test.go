package syntax

import (
	"fmt"
	"testing"
)

func ExampleOctetString_IsZero() {
	var oct OctetString
	fmt.Println(oct.IsZero())
	// Output: true
}

func ExampleOctetString_roundTripBER() {
	oct := OctetString("JERRY. HELLO.")
	enc, err := oct.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}
	var dec OctetString
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", dec)
	// Output: JERRY. HELLO.
}

func TestOctetString(t *testing.T) {
	for _, raw := range []string{
		``,
		`This is an OctetString.`,
	} {
		if oct, err := NewOctetString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := oct.String(); raw != got {
			t.Errorf("%s failed:\nwant: %s\ngot:  %s",
				t.Name(), raw, got)
		}
	}

	octet1 := OctetString{0x01, 0x02, 0x02}
	octet2 := OctetString{0x01, 0x02, 0x02}
	result, err := octetStringMatch(octet1, octet2)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result {
		t.Errorf("%s failed:\nwant: TRUE\ngot:  %t", t.Name(), result)
	}

	octet1 = OctetString{0x01, 0x02, 0x03}
	_ = octet1.Len()
	result, err = octetStringMatch(octet1, octet2)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if result {
		t.Errorf("%s failed:\nwant: TRUE\ngot:  %t", t.Name(), result)
		return
	}

	result, err = octetStringOrderingMatch(octet1, GreaterOrEqual, octet2)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result {
		t.Errorf("%s failed:\nwant: TRUE\ngot:  %t", t.Name(), result)
	}

	_, _ = marshalOctetString("界界界界")
	_, _ = octetStringMatch([]byte{}, []byte{})
	_, _ = octetStringMatch([]byte{}, struct{}{})
	_, _ = octetStringMatch(struct{}{}, []byte{})
	_, _ = octetStringMatch([]byte{}, []byte{0x0})
	_, _ = octetStringMatch([]byte{0x0}, []byte{})

	_, _ = octetStringOrderingMatch([]byte{0x01}, LessOrEqual, []byte{0x01, 0x02})
	_, _ = octetStringOrderingMatch([]byte{0x01}, GreaterOrEqual, []byte{0x01, 0x02})
	_, _ = octetStringOrderingMatch([]byte{0x01, 0x03}, LessOrEqual, []byte{0x01, 0x02})
	_, _ = octetStringOrderingMatch([]byte{0x01, 0x02}, LessOrEqual, []byte{0x02})
	_, _ = octetStringOrderingMatch([]byte{0x01, 0x02}, GreaterOrEqual, []byte{0x02})
	_, _ = octetStringOrderingMatch([]byte{0x01, 0x03}, GreaterOrEqual, []byte{0x02, 0x01})
	_, _ = octetStringOrderingMatch([]byte{}, LessOrEqual, []byte{})
	_, _ = octetStringOrderingMatch([]byte{}, LessOrEqual, struct{}{})
	_, _ = octetStringOrderingMatch(struct{}{}, LessOrEqual, []byte{})
	_, _ = octetStringOrderingMatch([]byte{0x0}, LessOrEqual, []byte{0x1, 0x2})
	_, _ = octetStringOrderingMatch([]byte{0x1}, LessOrEqual, []byte{})

	_, _ = octetString([]byte{})
	_, _ = octetString([]byte{0x0, 0x1, 0x2})
}
