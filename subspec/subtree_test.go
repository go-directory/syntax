package subspec

import (
	"testing"
)

func TestSubtreeSpecification(t *testing.T) {
	RegisterOID(`2.5.6.4`, `organization`)
	RegisterOID(`2.5.6.6`, `person`)
	RegisterOID(`2.5.6.9`, `groupOfNames`)
	RegisterOID(`2.5.6.14`, `device`)

	// Verify parsing of valid string-based SubSpec values
	for idx, raw := range testSubSpecs {
		if v, err := New(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else if got := v.String(); got != raw {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot: '%s'",
				t.Name(), idx, raw, got)
		} else if f := v.SpecificationFilter; f != nil {
			if err = f.Verify(); err != nil {
				t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			}
		}
	}

	OIDFwdMap = nil
	OIDRevMap = nil
}

func BenchmarkSubtreeSpecificationParse(b *testing.B) {
	b.StopTimer()
	maxIdx := len(testSubSpecs)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, _ = New(testSubSpecs[i%maxIdx])
	}

}

func TestSubtreeSpecification_codecov(t *testing.T) {
	New(nil)
	New(``)
	New(`X`)
	New(byte(33))
	New(`{base "n=123456,n=1,n=4,n=1,n=6,n=3,n=1", minimum -1, maximum 1, specificationFilter or:{item:2.5.6.5,not:item:2.5.6.4,and:{item:person,item:2.5.6.14}}}`)

	_, _, _ = subtreeBase(rune(11))
	_, _, _ = subtreeBase(`value:...`)
	_, _ = subtreeRefinement(nil)

	_, _ = subtreeRefinement("any:{...}")

	var spec SubtreeSpecification
	spec.Base = "cn=1,cn=2,cn=3"
	spec.ChopSpecification.Exclusions = SpecificExclusions{
		SpecificExclusion{}}
	spec.ChopSpecification = ChopSpecification{}
	spec.SpecificationFilter = RefinementAnd{}
	_ = spec.String()

	_, _, _ = subtreeExclusions("{", 0)
	_, _, _ = subtreeExclusions("{chopBefore:cn=y,chopAfter:cn=x}", 0)

	var orref RefinementOr
	orref.Push(nil)
	_ = orref.String()
	orref.Index(2)
	orref.isRefinement()
	oi1, _ := parseOr("item:2.6.5.0")
	orref.Push(oi1)
	orref.Push("item:2.6.5.5")
	orref = append(orref, RefinementItem(``))

	var andref RefinementAnd
	andref.Push(nil)
	_ = andref.String()
	andref.Index(2)
	andref.isRefinement()
	ai1, _ := parseAnd("item:2.6.5.0")
	andref.Push(ai1)
	andref.Push("item:2.6.5.5")
	andref = append(andref, RefinementItem(``))

	var excls SpecificExclusions
	_ = excls.String()

	var excl SpecificExclusion
	_ = excl.String()

	var iref RefinementItem
	iref.Choice()
	_ = iref.String()
	iref.Len()
	iref.Index(1)
	iref.isRefinement()

	var nref RefinementNot
	_ = nref.String()
	nref.Len()
	nref.Index(1)
	nref.isRefinement()

	var ivref invalidRefinement
	ivref.Index(2)
	ivref.isRefinement()
	ivref.IsZero()
	ivref.Len()
	ivref.Choice()
	_ = ivref.String()

	checkSubtreeEncaps(`fjhdjk`)
	checkSubtreeEncaps(`{..`)
	subtreeExclusions(`F`, 0)
	subtreeExclusions(`a`, 0)

	parseItem("item:something")
	parseItem("item:")
	parseItem(":something")
	parseItem(":")
	parseItem("")

	parseNot("x")
	parseComplexRefinement("and", "{bogus}")

}

var testSubSpecs []string = []string{
	`{}`,
	`{base "n=1,n=4,n=1,n=6,n=3,n=1", minimum 1, maximum 1, specificationFilter and:{item:organization,or:{item:person,item:device}}}`,
	`{base "n=1,n=4,n=1,n=6,n=3,n=1", minimum 1, maximum 1, specificationFilter or:{item:organization,not:item:2.5.6.9,and:{item:person,item:2.5.6.14}}}`,
	`{base "n=1,n=4,n=1,n=6,n=3,n=1", minimum 1, maximum 1, specificationFilter item:device}`,
	`{minimum 1, maximum 1}`,
	`{base "n=1,n=4,n=1,n=6,n=3,n=1", minimum 1, maximum 1, specificationFilter not:item:2.5.6.4}`,
	`{base "ou=Accounts,dc=example,dc=com", specificExclusions { chopBefore "ou=Payroll", chopAfter "ou=Executives", chopAfter "ou=Vendors" }, minimum 1, maximum 1, specificationFilter not:item:device}`,
	`{base "ou=Accounts,dc=example,dc=com", specificExclusions { chopBefore "ou=Payroll", chopAfter "ou=Executives", chopAfter "ou=Vendors" }, minimum 1, maximum 1, specificationFilter item:device}`,
	`{base "n=1,n=4,n=1,n=6,n=3,n=1", specificExclusions { chopBefore "n=14", chopAfter "n=555", chopAfter "n=74,n=6" }, minimum 1, maximum 1, specificationFilter not:and:{item:device,item:person}}`,
	`{base "n=1,n=4,n=1,n=6,n=3,n=1", specificExclusions { chopBefore "n=14", chopAfter "n=555", chopAfter "n=74,n=6" }, minimum 1, maximum 1, specificationFilter and:{item:device,item:person}}`,
	`{base "n=1,n=4,n=1,n=6,n=3,n=1", specificExclusions { chopBefore "n=14", chopAfter "n=555", chopAfter "n=74,n=6" }, minimum 1, maximum 1, specificationFilter or:{item:organization,not:item:2.5.6.9,and:{item:person,item:2.5.6.14}}}`,
}
