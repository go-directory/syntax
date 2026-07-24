package syntax

import (
	"testing"
)

func TestSubstringAssertion(t *testing.T) {
	for idx, raw := range []string{
		`substring*substring`,
		`substri*ng*thing`,
		`*substring*substring*`,
		`*substr*ing*end`,
		`substring*substring*substring`,
		`subst*`,
		`*ubstr`,
	} {
		if ssa, err := NewSubstringAssertion(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else if got := ssa.String(); got != raw {
			t.Errorf("%s[%d] failed:\n\twant:%s\n\tgot: %s\n",
				t.Name(), idx, raw, got)
		}
	}
}

func TestSubstringAssertion_codecov(t *testing.T) {
	substrProcess1(`11*11`)
	substrProcess1(`aaaa`)
	substrProcess1(`  `)
	substrProcess2(`11*11`)
	substrProcess2(`nil`)
	substrProcess2(`  `)
	substrProcess2(`aaaa`)
	substrProcess3(`11*11`)
	substrProcess3(`  `)
	substrProcess3(`aaaa`)
	substrProcess4(`11*11`)
	substrProcess4(`aaaa`)
	substrProcess4(`    `)

	prepareStringListAssertion([]string{`ahch`, `helkl4`}, `h*lk*4`)

	assertSubstringAssertion(SubstringAssertion{})
	substringAssertion(`aa*a`)
	substrProcess1(`aa*a`)
	substrProcess2(`aa*a`)
	substrProcess3(`aa*a`)
	substrProcess4(`aa*a`)

	marshalSubstringAssertion(nil)
	marshalSubstringAssertion(``)
	marshalSubstringAssertion([]byte{})
	marshalSubstringAssertion(`thisis**bogus`)

	substringsMatch("strXXXX", "*XXX", true)
	substringsMatch("strXXXX", "str*XXX*", true)
	substringsMatch("strXXXX", "str*XXX", true)
	substringsMatch("strXXXX", "*trXXXX", true)

	b, err := caseIgnoreSubstringsMatch(`this is a substring`, `this is*a*substring`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if !b {
		t.Errorf("%s failed:\nwant: TRUE\ngot:  %t", t.Name(), b)
		return
	}

	_, _ = caseIgnoreSubstringsMatch(``, `This*isa*Substring`)
	_, _ = caseIgnoreSubstringsMatch(``, `ThisisaSubstring`)
	_, _ = caseIgnoreSubstringsMatch(`this*isa*substring`, ``)
	_, _ = caseIgnoreSubstringsMatch(`this*isa*substring`, `banana`)

	b, err = caseExactSubstringsMatch(`this*isa*substring`, `This*isa*Substring`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if b {
		t.Errorf("%s failed:\nwant: FALSE\ngot:  %t", t.Name(), b)
		return
	}

	_, _ = caseExactSubstringsMatch(``, `This*isa*Substring`)
	_, _ = caseExactSubstringsMatch(``, `ThisisaSubstring`)
	_, _ = caseExactSubstringsMatch(`this*isa*substring`, ``)
	_, _ = caseExactSubstringsMatch(`this*isa*substring`, `banana`)
	_, _ = caseExactSubstringsMatch(`this*isa*substring`, SubstringAssertion{
		Initial: AssertionValue([]byte{0x1, 0x2}),
		Final:   AssertionValue([]byte{0x1, 0x2}),
	})
	_, _ = caseExactSubstringsMatch(`this*isa*substring`, SubstringAssertion{
		Initial: AssertionValue([]byte{0x1, 0x2}),
		Any:     AssertionValue([]byte(`is*not*subs*ring`)),
		Final:   AssertionValue([]byte{0x1, 0x2}),
	})

	caseIgnoreListSubstringsMatch([]string{`ahch`, `helkl4`}, `h*lk*4`)
}
