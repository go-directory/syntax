package syntax

import (
	"fmt"
	"testing"
)

func TestEnhancedGuide(t *testing.T) {
	for idx, raw := range []string{
		`0.9.2342.19200300.100.4.5#(!(?true&?false&2.5.4.0$EQ)|?true)#wholeSubtree`,
		`2.5.6.6#((2.5.4.3$GE&!2.5.4.3$SUBSTR)|?false)#oneLevel`,
	} {
		if g, err := NewEnhancedGuide(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else if got := g.String(); raw != got {
			t.Errorf("%s[%d] failed:\nwant: %s\ngot:  %s", t.Name(), idx, raw, got)
		}
	}

	if _, err := NewEnhancedGuide(`account#!(?true&?false&2.5.4.0$EQ)|?true#wholeSybtree`); err == nil {
		t.Errorf("%s failed: expected error, got nil", t.Name())
	}
}

func ExampleEnhancedGuide_roundTripBER() {
	eg, _ := NewEnhancedGuide(`0.9.2342.19200300.100.4.5#(!(?true&?false&2.5.4.0$EQ)|?true)#wholeSubtree`)

	enc, err := eg.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec EnhancedGuide
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s\n", dec)
	// Output: 0.9.2342.19200300.100.4.5#(!(?true&?false&2.5.4.0$EQ)|?true)#wholeSubtree
}

func ExampleGuide_roundTripBER() {
	og, _ := NewGuide(`0.9.2342.19200300.100.4.5#(!(?true&?false&2.5.4.0$EQ)|?true)`)

	enc, err := og.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec Guide
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s\n", dec)
	// Output: 0.9.2342.19200300.100.4.5#(!(?true&?false&2.5.4.0$EQ)|?true)
}

func TestGuide(t *testing.T) {
	for idx, raw := range []string{
		`0.9.2342.19200300.100.4.5#(!(?true&?false)|?true)`,
		`((2.5.4.3$SUBSTR&!(2.5.4.7$LE&2.5.4.0$APPROX))|?false)`,
	} {
		if g, err := NewGuide(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else if got := g.String(); raw != got {
			t.Errorf("%s[%d] failed:\nwant: %s\ngot:  %s", t.Name(), idx, raw, got)
		}
	}
}

func TestGuide_codecov(t *testing.T) {
	for _, bogus := range []any{
		``,
		nil,
		`account#values`,
		`___#baseOb`,
		`___#baseOb#...`,
		`___#:::::::#...`,
		`#baseObject`,
		`yo#()#1`,
		`account##baseObject`,
		`account#Jerry.Hello#baseObject`,
	} {
		g, _ := NewGuide(bogus)
		_ = g.String()
		eg, _ := NewEnhancedGuide(bogus)
		enhancedGuide(bogus)
		_ = eg.String()
	}

	subsetToInt([]byte(`baseobject`))
	subsetToInt([]byte(`onelevel`))
	subsetToInt([]byte(`wholesubtree`))

	marshalEnhancedGuide("account#...#((?$))#")
	marshalGuide("@..@#Value")

	intToSubset(Integer{ok: true, native: 0})
	intToSubset(Integer{ok: true, native: 1})
	intToSubset(Integer{ok: true, native: 2})
}
