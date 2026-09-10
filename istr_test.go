package syntax

import (
	"fmt"
	"testing"
)

func ExampleIA5String_roundTripBER() {
	ia5 := IA5String("Testing")
	enc, err := ia5.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}
	var dec IA5String
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", dec)
	// Output: Testing
}

func TestIA5String(t *testing.T) {

	var raw string = `Jerry. Hello.`
	if ia, err := NewIA5String(raw); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if got := ia.String(); raw != got {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s",
			t.Name(), raw, got)
	}

	//var chars []rune = []rune{0xEA4F, 'こ','ん','に','ち','は','、','世','界','🌍'}
	//if err := checkIA5String(string(chars)); err == nil {
	//	t.Errorf("%s failed: expected error, got nil", t.Name())
	//	return
	//}
}

func TestIA5String_SubstringsMatch(t *testing.T) {
	result, err := caseIgnoreIA5SubstringsMatch(`JERRY. HELLO.`, `JERR*.*HELL*.`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result {
		t.Errorf("%s failed:\nwant: %s\ngot:  %t", t.Name(), `TRUE`, result)
	}
}

func TestIA5String_CaseMatch(t *testing.T) {
	result, err := caseExactIA5Match(`This`, `This`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result {
		t.Errorf("%s failed:\nwant: %s\ngot:  %t",
			t.Name(), `TRUE`, result)
	}

	result, err = caseIgnoreIA5Match(`This`, `THIS`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result {
		t.Errorf("%s failed:\nwant: %s\ngot:  %t",
			t.Name(), `TRUE`, result)
	}
}

func TestIA5String_codecov(t *testing.T) {
	_, _ = iA5String("HELLO.")
	_, _ = iA5String("jesse.coretta@icloud.com")
	if err := checkIA5String([]byte(`jesse.coretta@icloud.com`)); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	_, _ = caseBasedIA5Match(struct{}{}, `werd`, true)
	_, _ = caseBasedIA5Match(`werd`, struct{}{}, false)

	runes := []rune{rune(0xFFFF), 'ñ'}
	_, _ = marshalIA5String(string(runes))
}
