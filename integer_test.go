package syntax

import (
	"fmt"
	"testing"
)

func BenchmarkIntegerASN1(b *testing.B) {
	o, _ := NewInteger(327597823)
	b.StopTimer()

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		enc, _ := o.Encode()
		var dec Integer
		_ = dec.Decode(enc)
	}
}

func ExampleInteger_roundTripBER() {
	i, err := NewInteger(1478231)
	if err != nil {
		fmt.Println(err)
		return
	}

	var enc []byte
	if enc, err = i.Encode(); err != nil {
		fmt.Println(err)
		return
	}

	var dec Integer
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(dec.Native())
	// Output: 1478231
}

func TestInteger_valid(t *testing.T) {
	for idx, in := range []any{
		0, 1, 2, -3, int64(-3729837392),
		int32(0), int32(-1), int32(2),
		int64(0), int64(1), int64(2),
		uint64(0), uint64(1), uint64(2),
		`58742589373894573475934758934758934759347534789`,
		`-58742589373894573475934758934758934759347534789`,
	} {
		i, err := NewInteger(in)
		if err != nil {
			t.Errorf("%s [%d] failed: %v", t.Name(), idx, err)
		}
		_ = i.IsBig()
		_ = i.Native()
		_ = i.Big()
		_ = i.Eq(1)
		_ = i.Ne(1)
		_ = i.Le(1)
		_ = i.Ge(1)
		_ = i.Lt(1)
		_ = i.Gt(1)
		_ = i.cmpAny(`1`)
		_ = i.cmpAny(1)
		_ = i.cmpAny(int32(1))
		_ = i.cmpAny(int64(1))
		_ = i.cmpAny(uint64(1))
		_ = i.cmpAny(Integer{ok: true, native: 1})
	}
}

func TestInteger_panicCmp(t *testing.T) {
	var i Integer
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s failed: %v", t.Name(), "expected panic")
		}
	}()
	_ = i.cmpAny(struct{}{})
}

func TestInteger_panicStr(t *testing.T) {
	var i Integer
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s failed: %v", t.Name(), "expected panic")
		}
	}()
	_ = i.cmpIntegerStr(`-`)
}
