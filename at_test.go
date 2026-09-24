package syntax

import (
	"fmt"
	"testing"
)

func TestIsAttribute(t *testing.T) {
	for idx, good := range [][]byte{
		[]byte(`2.5.4.3`),
		[]byte(`l`),
		[]byte(`DC`),
		[]byte(`a9`),
		[]byte(`a-b`),
		[]byte(`owner`),
		[]byte(`objectClass`),
	} {
		if !isAttribute(good) {
			t.Errorf("%s[%d] failed: %q; want nil, got error", t.Name(), idx, good)
		}
	}

	for idx, bad := range [][]byte{
		[]byte(`2.5..4.3`),
		[]byte(``),
		[]byte(`719`),
		[]byte(`9a`),
		[]byte(`_DC`),
		[]byte(`-t`),
		{0x8},
		[]byte(`t-`),
		[]byte(`t--t`),
		[]byte(`owner#`),
		[]byte(`object Class`),
	} {
		if isAttribute(bad) {
			t.Errorf("%s[%d] failed: %q; want error, got nil", t.Name(), idx, bad)
		}
	}

	ad := AttributeDescription(`cn;lang-sl`)
	if !ad.Type().Valid() {
		t.Fatalf("%s failed: valid attribute %q flagged as invalid", t.Name(), ad)
	}

	ad = AttributeDescription(`givenName`)
	ad2 := AttributeDescription(`givenname`)
	_ = ad.EqualFold(ad2)
	_ = ad.Equal(ad2)
}

func ExampleAttributeTypeAndValue_roundTripDER() {
	atv := AttributeTypeAndValue{
		Type:  AttributeType("cn"),
		Value: AttributeValue("Jesse Coretta"),
	}

	enc, err := atv.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec AttributeTypeAndValue
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(dec)
	// Output: cn=Jesse Coretta
}

func ExampleAttributeSelection_roundTripDER() {
	sel := AttributeSelection{
		LDAPString("2.5.4.3"), // numeric OIDs will always be supported ...
		LDAPString("sn"),      // ... but descriptors ("names") are usually preferred
		LDAPString("givenName"),
		LDAPString("l"),
	}

	enc, err := sel.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec AttributeSelection
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", dec)
	// Output: [2.5.4.3 sn givenName l]
}

func ExamplePartialAttribute_Encode() {
	pa := PartialAttribute{
		Type: AttributeDescription("cn"),
		Vals: []AttributeValue{AttributeValue("Jesse Coretta")},
	}

	enc, err := pa.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	// Peek at the first byte to see if it is correct
	class := enc[0] >> 6
	isC := (enc[0] & 0x20) != 0
	tag := uint32(enc[0] & 0x1F)

	fmt.Printf("class: %d / isConstructed: %t / tag: %d", class, isC, tag)
	// Output: class: 0 / isConstructed: true / tag: 16
}

func ExamplePartialAttribute_roundTripDER() {
	pa := PartialAttribute{
		Type: AttributeDescription("cn"),
		Vals: []AttributeValue{AttributeValue("Jesse Coretta")},
	}

	enc, err := pa.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec PartialAttribute
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s: %s", dec.Type, dec.Vals[0])
	// Output: cn: Jesse Coretta
}

func ExampleAttributeList_roundTripDER() {
	pas := AttributeList{
		PartialAttribute{
			Type: AttributeDescription("cn"),
			Vals: []AttributeValue{AttributeValue("Jesse Coretta")},
		},
	}

	enc, err := pas.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec AttributeList
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s: %s", dec[0].Type, dec[0].Vals[0])
	// Output: cn: Jesse Coretta
}

func ExamplePartialAttributeList_roundTripDER() {
	pas := PartialAttributeList{
		PartialAttribute{
			Type: AttributeDescription("cn"),
			Vals: []AttributeValue{AttributeValue("Jesse Coretta")},
		},
	}

	enc, err := pas.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec PartialAttributeList
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s: %s", dec[0].Type, dec[0].Vals[0])
	// Output: cn: Jesse Coretta
}
