package syntax

import (
	"testing"
)

func TestDirectoryString_FirstComponentMatch(t *testing.T) {
	type Sequence struct {
		Value DirectoryString
	}

	var txt string = `Printable123`
	instance := Sequence{Value: PrintableString(txt)}
	var testValue DirectoryString = PrintableString(txt)

	// Try a non Sequence instance
	result, err := directoryStringFirstComponentMatch(instance, testValue)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if !result {
		t.Errorf("%s failed:\nwant: %s\ngot:  %t",
			t.Name(), `TRUE`, result)
		return
	}

	// Try a Sequence instance
	result, err = directoryStringFirstComponentMatch(instance, instance)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if !result {
		t.Errorf("%s failed:\nwant: %s\ngot:  %t",
			t.Name(), `TRUE`, result)
		return
	}
}

func TestDirectoryString_codecov(t *testing.T) {

	for _, ds := range []DirectoryString{
		BMPString{0x1E, 0x02, 0x03, 0xA3},
		BMPString{0x1E, 0x06, 0x00, 0x41, 0x00, 0x42, 0x00, 0x43},
		BMPString{0x1E, 0x0a, 0x00, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F},
		BMPString{0x1E, 0x08, 0x00, 0x54, 0x00, 0x65, 0x00, 0x78, 0x00, 0x74},
		BMPString{},
		PrintableString(" "),
		PrintableString("Printable123"),
		PrintableString("Yes."),
		UniversalString("こんにちは世界！"),
		UniversalString("This is a universal string 😊"),
		UTF8String(""),
		UTF8String(`ZFKJ345325^&*$`),
		UTF8String("Hola! こんにちは"),
		UTF8String("Hello, 世界!"),
		UTF8String("Zǹǹêrī!"),
		TeletexString(`maybe`),
		TeletexString("Hello"),
		TeletexString("Teletex123!"),
	} {
		_ = ds.String()
		ds.Choice()
		ds.isDirectoryString()
	}

	var cs CountryString
	cs.IsZero()
	_ = cs.String()

	isT61Single('\u009B')

	NewCountryString(``)
	NewCountryString(`#@`)

	NewDirectoryString('\u0071')

	raw := `8392810954`

	_, _ = NewUniversalString(nil)
	_, _ = NewIA5String(nil)
	_, _ = NewUTF8String(raw)
	_, _ = NewUTF8String(nil)
	_, _ = NewUniversalString(raw)
	_, _ = NewBMPString(raw)
	_, _ = NewBMPString(`12`)
	_, _ = NewBMPString(nil)
	_, _ = NewBMPString(BMPString([]byte{0x1E, 0x00}))
	_, _ = NewBMPString(BMPString([]byte{0x00, 0x1E}))

	var bigBMP []byte = []byte{0x1E, 0xFF}
	for i := 0; i < 256; i++ {
		bigBMP = append(bigBMP, byte(i))
	}
	_, _ = NewBMPString(bigBMP)
	_, _ = NewUniversalString(``)
	_, _ = NewUniversalString(UniversalString(`XYZ`))
	_, _ = NewUniversalString([]byte{})
	_, _ = NewOctetString([]byte{})
	_, _ = NewOctetString(``)
	_, _ = NewOctetString(nil)
	_, _ = NewTeletexString(``)
	_, _ = NewPrintableString(``)
	_, _ = NewTeletexString(`A`)
	_, _ = NewPrintableString(struct{}{})
	_, _ = NewPrintableString(`A`)
	_, _ = NewTeletexString([]byte(`A`))
	_, _ = NewTeletexString(nil)
	_, _ = NewPrintableString([]byte(`A`))

	var tel TeletexString
	_ = tel.String()
	tel.IsZero()

	var prs PrintableString
	prs.IsZero()
	_ = prs.String()

	_, _ = assertNumericString(`X`)
	_, _ = assertNumericString(``)
	_, _ = assertNumericString(nil)
	_, _ = assertNumericString(uint(0))
	_, _ = assertNumericString(int32(-1))
	_, _ = assertNumericString(uint16(0))

	var ns NumericString
	_ = ns.String()
	ns.IsZero()

	var us UniversalString
	_ = us.String()
	us.IsZero()

	directoryString(`XABC`)

	for _, str := range []DirectoryString{
		BMPString{0x1E, 0x01, 0xDC, 0x00},                               // bad
		BMPString{0x00, 0x00, 0xD8, 0x00},                               // bad
		BMPString{0x4E, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x6D, 0x00, 0xE9}, // bad
		BMPString{0x00, 0x00, 0x00},                                     // bad
		BMPString{0xFF},                                                 // bad
		PrintableString("Invalid@Chars"),                                // bad
		PrintableString("Test@PRINTABLE#"),                              // bad
		PrintableString(""),                                             // bad
		UniversalString("\x00\x00\x00\x20\x00\xDC\x00\x00"),             // bad
		UniversalString("\x00\x00\xD8\x00\x00\x00\xDF\xFF"),             // bad
		UTF8String("\xC3\x28"),                                          // bad
		UTF8String("\xF0\x28\x8C\xBC"),                                  // bad
		UTF8String("\xF0"),                                              // bad
		UTF8String("\xF0\x82\x82\xAC"),                                  // bad
		UTF8String("\xE2\x28\xA1"),                                      // bad
		TeletexString("\x80\x81\x82"),                                   // bad
		TeletexString("\xC0\xC1"),                                       // bad
		TeletexString("\xF1\xF2\xF3"),                                   // bad
	} {
		_, _ = marshalDirectoryString(str)
	}

	type FirstComponent struct {
		Field DirectoryString
	}
	type BadFirstComponent struct {
		Field float32
	}

	fc, _ := marshalDirectoryString(`directoryString`)
	bc := BadFirstComponent{float32(1)}
	directoryStringFirstComponentMatch(nil, fc)
	directoryStringFirstComponentMatch(bc, fc)
	directoryStringFirstComponentMatch(fc, nil)
	directoryStringFirstComponentMatch(fc, 1)
	directoryStringFirstComponentMatch(fc, struct{}{})
	directoryStringFirstComponentMatch(fc, `directoryString`)
	directoryStringFirstComponentMatch(fc, fc)
	directoryStringFirstComponentMatch(struct{}{}, fc)
	directoryStringFirstComponentMatch(struct{}{}, 1)
}
