package syntax

import (
	"testing"
)

func TestEnhancedGuide(t *testing.T) {
	for idx, raw := range []string{
		`account#!(?true&?false&2.5.4.0$EQ)|?true#wholeSubtree`,
		`person#((2.5.4.3$GE&!2.5.4.3$SUBSTR)|?false)#oneLevel`,
	} {
		if g, err := NewEnhancedGuide(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else if got := g.String(); raw != got {
			t.Errorf("%s[%d] failed:\nwant: %s\ngot:  %s", t.Name(), idx, raw, got)
		} else {
			g.Criteria.Index(0).Index(0)
		}
	}

	if _, err := NewEnhancedGuide(`account#!(?true&?false&2.5.4.0$EQ)|?true#wholeSybtree`); err == nil {
		t.Errorf("%s failed: expected error, got nil", t.Name())
	}
}

func TestGuide(t *testing.T) {
	for idx, raw := range []string{
		`account#!(?true&?false)|?true`,
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
	var amt AttributeMatchTerm
	amt.IsZero()
	_ = amt.String()

	var bt BoolTerm
	bt.IsZero()
	_ = bt.String()

	var crit Criteria
	crit.IsZero()
	_ = crit.String()
	_ = crit.Index(7)
	crit.Len()

	var at AndTerm
	at.IsZero()
	_ = at.String()
	_ = at.Index(7)
	at.Paren = true
	_ = at.String()
	at.Len()
	at.Valid()

	var not NotTerm
	not.Valid()

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
		guide(bogus)
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

	intToSubset(0)
	intToSubset(1)
	intToSubset(2)
}
