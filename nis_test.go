package syntax

import (
	"fmt"
	"testing"
)

func ExampleNetgroupTriple_roundTripDER() {
	ngt := NetgroupTriple{
		Hostname: IA5String("localhost"),
		Username: IA5String("jesse"),
		Domain:   IA5String("example.com"),
	}

	enc, err := ngt.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec NetgroupTriple
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(dec)
	// Output: (localhost,jesse,example.com)
}

func ExampleBootParameter_roundTripDER() {
	bp := BootParameter{
		Key:    IA5String("abc123"),
		Server: IA5String("localhost"),
		Path:   IA5String("/path/to/something"),
	}

	enc, err := bp.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec BootParameter
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(dec)
	// Output: abc123=localhost:/path/to/something
}

func TestNetgroupTriple(t *testing.T) {
	for idx, raw := range []string{
		`(console,jc,example.com)`,
		`(-,-,-)`,
		`(-,jc,-)`,
	} {
		if trip, err := NewNetgroupTriple(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else if got := trip.String(); got != raw {
			t.Errorf("%s[%d] failed:\nwant: %s\ngot:  %s",
				t.Name(), idx, raw, got)
		}
	}

	ngt := NetgroupTriple{}
	_ = ngt.String()
	ngt.setNetgroupTripleFieldByIndex(0, nil)
	ngt.setNetgroupTripleFieldByIndex(0, ``)
	ngt.setNetgroupTripleFieldByIndex(0, `this`)
	ngt.setNetgroupTripleFieldByIndex(1, `isOnly`)
	ngt.setNetgroupTripleFieldByIndex(2, `aTest`)
	_ = ngt.String()

	NewNetgroupTriple(`(?,?,?,?)`)
	NewNetgroupTriple(`??`)
	NewNetgroupTriple(`(??`)
	NewNetgroupTriple(nil)
	NewNetgroupTriple(`ÃÃ"","","",""`)
	NewNetgroupTriple(`@,\,"","Ã"`)
}

func TestBootParameter(t *testing.T) {
	for idx, raw := range []string{
		`test=thing:path`,
	} {
		if btp, err := NewBootParameter(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else if got := btp.String(); got != raw {
			t.Errorf("%s[%d] failed:\nwant: %s\ngot:  %s",
				t.Name(), idx, raw, got)
		}
	}

	NewBootParameter(`test=`)
	NewBootParameter(`test=;:`)
	NewBootParameter(`test:`)
	NewBootParameter(``)
	NewBootParameter(nil)

	var bp BootParameter
	_ = bp.String()
}

func TestNIS_codecov(t *testing.T) {
	isKeystring(`c--l`)
	isKeystring(`-`)
	isKeystring(``)
	isKeystring(`c界j`)
	isKeystring(`A`)
	isKeystring(`abc`)
}
