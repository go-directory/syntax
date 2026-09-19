package syntax

import (
	"fmt"
	"testing"
)

func ExampleBitString_bitManipulation() {
	/*
	   // § 6.7.4 of ITU-T Rec. X.520
	   G3FacsimileNonBasicParameters ::= BIT STRING {
	       two-dimensional      (8),
	       fine-resolution      (9),
	       unlimited-length     (20),
	       b4-length            (21),
	       a3-width             (22),
	       b4-width             (23),
	       uncompressed         (30) }

	*/
	var bs BitString

	fmt.Printf("bit 8 is set:  %t\n", bs.Has(8))
	fmt.Printf("bit 20 is set: %t\n", bs.Has(20))

	bs.Set(8)  // two-dimensional
	bs.Set(20) // unlimited-length
	bs.Set(21) // b4-length

	fmt.Printf("bit 8 is set:  %t\n", bs.Has(8))
	fmt.Printf("bit 20 is set: %t\n", bs.Has(20))
	fmt.Printf("bit 21 is set: %t\n", bs.Has(21))
	bs.Unset(21) // I changed my mind :S
	fmt.Printf("bit 21 is set: %t\n", bs.Has(21))
	// Output:
	// bit 8 is set:  false
	// bit 20 is set: false
	// bit 8 is set:  true
	// bit 20 is set: true
	// bit 21 is set: true
	// bit 21 is set: false
}

func ExampleBitString_roundTripDER() {
	bs, err := NewBitString(`'010101110101'B`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var enc []byte
	if enc, err = bs.Encode(); err != nil {
		fmt.Println(err)
		return
	}

	var dec BitString
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(dec)
	// Output: '010101110101'B
}

func TestBitString(t *testing.T) {
	var raw string = `'10100101'B`
	if result, _ := bitString(raw); !result {
		t.Errorf("%s failed:\nwant: %t\ngot:  %t",
			t.Name(), true, result)
		return
	}

	bs, err := NewBitString(raw)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if bs.IsZero() {
		t.Errorf("%s failed: instance is zero", t.Name())
	} else if got := bs.String(); raw != got {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s",
			t.Name(), raw, got)
	}

	// coverage
	bs.At(-1)
	bs.At(1)
	bs.RightAlign()
}

func TestBitString_codecov(t *testing.T) {
	_, _ = assertBitString([]byte{})
	_, _ = assertBitString(struct{}{})
	_, _ = bitString([]byte{})
	_, _ = bitString(struct{}{})

	_, _ = bitStringMatch([]byte{}, struct{}{})
	_, _ = bitStringMatch([]byte(`'010110'B`), struct{}{})
	_, _ = bitStringMatch([]byte{}, []byte{})
	_, _ = bitStringMatch(struct{}{}, struct{}{})
	_, _ = bitStringMatch([]byte(`'010110'B`), []byte(`'01'B`))

	b, err := bitStringMatch(`'1010100'B`, `'1010000'B`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if b {
		t.Errorf("%s failed:\nwant: %t\ngot:  %t",
			t.Name(), false, b)
		return
	}

	b, err = bitStringMatch(`'1010100'B`, `'1010100'B`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if !b {
		t.Errorf("%s failed:\nwant: %t\ngot:  %t",
			t.Name(), true, b)
		return
	}

	_, _ = bitStringMatch(`'1010100'B`, `'10101'B`)
	//_ = stripTrailingZeros([]byte{0x1, 0x2, 0x0, 0x0}, 2)
	//_ = stripTrailingZeros([]byte{0x1, 0x2, 0x0, 0x0}, 4)
	//_ = stripTrailingZeros([]byte{}, 0)

}
