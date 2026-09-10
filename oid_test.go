package syntax

import (
	"fmt"
	"testing"
)

func ExampleObjectIdentifier_roundTripBER() {
	o, err := NewObjectIdentifier(`1.3.6.1.4.1`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var enc []byte
	if enc, err = o.Encode(); err != nil {
		fmt.Println(err)
		return
	}

	var dec ObjectIdentifier
	if err := dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(dec.String())
	// Output: 1.3.6.1.4.1
}

func ExampleObjectIdentifier_Decode_bogus() {
	// pre-encoded OID bytes for (illegal) 3.3.6.1.4.1
	enc := []byte{0x7B, 0x6, 0x1, 0x4, 0x1}

	var dest ObjectIdentifier
	fmt.Println(dest.Decode(enc))
	// Output: OBJECT IDENTIFIER: illegal first and/or second level arcs
}

func TestObjectIdentifier_oID(t *testing.T) {
	for _, val := range []string{
		`cn`,
		`2.5.4.3`,
		`account`,
		`l`,
		`0.0`,
		`2.1`,
	} {
		if res, err := oID(val); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if !res {
			t.Errorf("%s failed:\n\twant: %t\n\tgot:  %t", t.Name(), true, res)
		}
	}
}

func ExampleObjectIdentifier_IntSlice() {
	id := `1.3.6.1.4.1.56521.999`
	o, err := NewObjectIdentifier(id)
	if err != nil {
		fmt.Println(err)
		return
	}

	var slice []int
	if slice, err = o.IntSlice(); err == nil {
		fmt.Println(slice)
	}
	// Output: [1 3 6 1 4 1 56521 999]
}

func ExampleObjectIdentifier_Uint64Slice() {
	id := `1.3.6.1.4.1.56521.999`
	o, err := NewObjectIdentifier(id)
	if err != nil {
		fmt.Println(err)
		return
	}

	var slice []uint64
	if slice, err = o.Uint64Slice(); err == nil {
		fmt.Println(slice)
	}
	// Output: [1 3 6 1 4 1 56521 999]
}

func ExampleObjectIdentifier_Eq() {
	one, err := NewObjectIdentifier(`1.3.6.1.5.1`)
	if err != nil {
		fmt.Println(err)
		return
	}
	two, err := NewObjectIdentifier(`1.3.6.1.5.2`)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("OIDs match: %t", one.Eq(two))
	// Output: OIDs match: false
}

func TestObjectIdentifier(t *testing.T) {
	for _, oid := range []string{
		`1.3.6.1.4.1`,
		`2.5`,
		`0.0.4`,
	} {
		if _, err := NewObjectIdentifier(oid); err != nil {
			t.Errorf("%s failed: genuine OID flagged as bogus (%s)", t.Name(), oid)
			return
		}
	}

	for _, bad := range []string{
		`2`,
		``,
		`$.3`,
		`1.2.3..4.5`,
		`1.2.3.4.5.`,
		`4.2.3.t.5`,
		`3.1`,
		`_`,
		`1.50`,
		`1.S0`,
		`.1.3`,
		`1.3.`,
	} {
		if _, err := NewObjectIdentifier(bad); err == nil {
			t.Errorf("%s failed: bogus OID flagged as genuine (%s)", t.Name(), bad)
			return
		}
	}
}

func TestObjectIdentifier_basicAny(t *testing.T) {
	bigPen := newBigInt(int64(56521))
	nfPen := numberForm{
		ok:     true,
		native: uint64(56521),
	}

	for idx, this := range [][]any{
		{0, 0},                              // ITU-T Recommendation
		{1, 3, int64(6)},                    // DoD
		{1, 3, 6, 1, 4, 1, int32(56521)},    // My PEN OID
		{1, 3, 6, 1, 4, 1, bigPen},          // "" (big.Int)
		{1, 3, 6, 1, 4, 1, nfPen},           // "" (numberForm)
		{1, 3, 6, 1, 4, 1, `56521`},         // "" (string)
		{1, 3, 6, 1, 5, uint64(5), 7, 3, 1}, // TLS ServerAuth
	} {
		if _, err := NewObjectIdentifier(this...); err != nil {
			t.Errorf("%s [%d] failed: %v", t.Name(), idx, err)
		}
	}
}

func TestObjectIdentifier_basicString(t *testing.T) {
	for _, want := range []string{
		`0.0`,               // ITU-T recommendation
		`1.3.6`,             // DoD
		`1.3.6.1.4.1.56521`, // My PEN OID
		`1.3.6.1.5.5.7.3.1`, // TLS ServerAuth
	} {
		oid, err := NewObjectIdentifier(want)
		if err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}

		if got := oid.String(); got != want {
			t.Errorf("%s compare failed: want %s, got %s", t.Name(), want, got)
		}
	}
}

func TestObjectIdentifier_bigString(t *testing.T) {
	for _, want := range []string{
		`2.25.987895962269883002155146617097157934`,
		`2.25.923487482374589327592759723372975730`,
		`2.999999999999999999999999999999999999`, // not a real OID, but valid
	} {
		if oid, err := NewObjectIdentifier(want); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := oid.String(); got != want {
			t.Errorf("%s compare failed: want %s, got %s", t.Name(), want, got)
		}
	}
}

func TestObjectIdentifier_codecov(t *testing.T) {
	var o ObjectIdentifier
	_, _ = o.Uint64Slice()
	_, _ = o.IntSlice()
	_ = o.IsZero()
	_ = o.IsZero()
	_ = o.Len()
	assertObjectIdentifier(struct{}{})
	assertObjectIdentifier(``)
	assertObjectIdentifier(o)
	_, _ = NewObjectIdentifier()
	_, _ = NewObjectIdentifier(struct{}{})
	_, _ = NewObjectIdentifier(struct{}{}, struct{}{})
	_, _ = NewObjectIdentifier(o)
	_, _ = NewObjectIdentifier(ObjectIdentifier{numberForm{}})
	newObjectIdentifierStr(`1.3.6._.4.1`)
	b := ObjectIdentifier{numberForm{}}
	_, _ = b.Uint64Slice()
	_, _ = b.IntSlice()
}
