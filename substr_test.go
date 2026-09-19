package syntax

import (
	"fmt"
	"testing"
)

func ExampleSubstrings_roundTripBER() {
	sub, err := NewSubstrings(`substring*substring*substring`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var enc []byte
	if enc, err = sub.Encode(); err != nil {
		fmt.Println(err)
		return
	}

	var dec Substrings
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%v\n", dec)
	// Output: substring*substring*substring
}

func ExampleSubstringAny_roundTripBER() {
	Any := SubstringAny{
		AssertionValue{0x73, 0x75, 0x62, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67},
		AssertionValue{0x73, 0x75, 0x62, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67},
	}

	enc, err := Any.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec SubstringAny
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s\n", dec)
	// Output: [substring substring]
}

func ExampleSubstringInitial_roundTripBER() {
	Sub := SubstringInitial{0x73, 0x75, 0x62, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67}

	enc, err := Sub.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec SubstringInitial
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s\n", dec)
	// Output: substring
}

func TestSubstrings(t *testing.T) {
	for idx, raw := range []string{
		`substring*substring`,
		`substri*ng*thing`,
		`*substring*substring*`,
		`*substr*ing*end`,
		`substring*substring*substring`,
		`subst*`,
		`*ubstr`,
	} {
		if ssa, err := NewSubstrings(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else if got := ssa.String(); got != raw {
			t.Errorf("%s[%d] failed:\n\twant:%s\n\tgot: %s\n",
				t.Name(), idx, raw, got)
		}
	}
}

func BenchmarkNewSubstrings(b *testing.B) {
	b.StopTimer()
	assn := [][]byte{
		[]byte(`+1*555*134`),
		[]byte(`substring*substring`),
		[]byte(`substri*ng*thing`),
		[]byte(`*substring*substring*`),
		[]byte(`*substr*ing*end`),
		[]byte(`substring*substring*substring`),
		[]byte(`subst*`),
		[]byte(`*ubstr`),
	}

	maxIdx := len(assn)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, _ = NewSubstrings(assn[i%maxIdx])
	}
}
func BenchmarkSubstringMatch(b *testing.B) {
	match := []byte(`substring`)
	b.StopTimer()
	assn := [][]byte{
		[]byte(`+1*555*134`),
		[]byte(`substring*substring`),
		[]byte(`substri*ng*thing`),
		[]byte(`*substring*substring*`),
		[]byte(`*substr*ing*end`),
		[]byte(`substring*substring*substring`),
		[]byte(`subst*`),
		[]byte(`*ubstr`),
	}

	maxIdx := len(assn)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, _ = substringsMatch(match, assn[i%maxIdx])
	}
}
