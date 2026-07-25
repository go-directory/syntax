package filter

import (
	"fmt"
	"testing"

	"github.com/go-directory/syntax"
)

func TestInvalidFilter_String(t *testing.T) {
	f := invalidFilter{}
	if f.String() != `` {
		t.Errorf("%s failed: unable to print nil filter", t.Name())
	}
}

/*
This example demonstrates the means for properly assigning a value to
an instance of [syntax.AssertionValue].
*/
func ExampleAssertionValue_Set() {
	var av syntax.AssertionValue
	av.Set(`Lučić`)
	fmt.Printf("%s / %s\n",
		av.Escaped(),
		av.Unescaped())
	// Output: Lu\c4\8di\c4\87 / Lučić
}

/*
This example demonstrates the means for accessing a specific slice index
within the return instance of [Filter].
*/
func ExampleFilterAnd_Index() {
	f, _ := New(`(&(|(sn=Lučić)(employeeID=123456789))(objectClass=person))`)

	slice := f.Index(0).Index(1)
	fmt.Printf("%s\n", slice)
	// Output: (employeeID=123456789)
}

/*
This example demonstrates the means for accessing a specific slice index
within the return instance of [Filter].
*/
func ExampleFilterNot_Index() {
	f, _ := New(`(!(&(objectClass=employee)(terminated=TRUE)))`)

	slice := f.Index(0)
	fmt.Printf("%s\n", slice.Choice())
	// Output: equalityMatch
}

/*
This example demonstrates the means for accessing a specific slice index
within the return instance of [Filter].
*/
func ExampleFilterOr_Index() {
	f, _ := New(`(&(|(sn=Lučić)(employeeID=123456789))(objectClass=person))`)

	slice := f.Index(0)
	fmt.Printf("%s [%d]\n", slice.Choice(), slice.Len())
	// Output: or [2]
}

func TestFilter(t *testing.T) {
	// Test cases sourced from RFC4515, go-ldap/filter.go, et al.
	for idx, x := range []struct {
		Input  any
		Output string
		Choice string
		Error  string
		Length int
	}{
		{
			Input:  `(objectGUID=\a)`,
			Output: ``,
			Error:  `Invalid filter`,
			Choice: `invalid`,
		},
		{
			Input:  `(objectGUID=\zz)`,
			Output: ``,
			Error:  `Invalid filter`,
			Choice: `invalid`,
		},
		{
			Input:  `(objectClass=`,
			Output: ``,
			Error:  `Unexpected end of filter`,
			Choice: `invalid`,
		},
		{
			Input:  `(&(objectClass=*)(cn=Jesse))`,
			Output: `(&(objectClass=*)(cn=Jesse))`,
			Choice: `and`,
			Length: 2,
		},
		{
			Input:  `(sn=*ore*a)`,
			Output: `(sn=*ore*a)`,
			Choice: `substrings`,
			Length: 1,
		},
		{
			Input:  `(&(objectClass=*)(|(cn=Jesse)(cn=Courtney)))`,
			Output: `(&(objectClass=*)(|(cn=Jesse)(cn=Courtney)))`,
			Choice: `and`,
			Length: 2,
		},
		{
			Input:  `(objectClass=top)`,
			Output: `(objectClass=top)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(givenName~=Jessi)`,
			Output: `(givenName~=Jessi)`,
			Choice: `approxMatch`,
			Length: 1,
		},
		{
			Input:  `(n>=17485)`,
			Output: `(n>=17485)`,
			Choice: `greaterOrEqual`,
			Length: 1,
		},
		{
			Input:  `(cn=Babs Jensen)`,
			Output: `(cn=Babs Jensen)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(givenName=)`,
			Output: `(givenName=)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(!(cn=Tim Howes))`,
			Output: `(!(cn=Tim Howes))`,
			Choice: `not`,
			Length: 1,
		},
		{
			Input:  `(|(employeeID=123456)(sn=Jensen)(cn=Babs J*))`,
			Output: `(|(employeeID=123456)(sn=Jensen)(cn=Babs J*))`,
			Choice: `or`,
			Length: 3,
		},
		{
			Input:  `(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))`,
			Output: `(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))`,
			Choice: `and`,
			Length: 2,
		},
		{
			Input:  `(o=univ*of*mich*)`,
			Output: `(o=univ*of*mich*)`,
			Choice: `substrings`,
			Length: 1,
		},
		{
			Input:  `(seeAlso=)`,
			Output: `(seeAlso=)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(n<=17485)`,
			Output: `(n<=17485)`,
			Choice: `lessOrEqual`,
			Length: 1,
		},
		{
			Input:  `objectClass=top`,
			Output: `(objectClass=top)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(givenName:=John)`,
			Output: `(givenName:=John)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		/*
			{
				Input:  `(givenName;lang-jp=ジェシー)`, // Jesse :)
				Output: `(givenName;lang-jp=\e3\82\b8\e3\82\a7\e3\82\b7\e3\83\bc)`,
				Choice: `equalityMatch`,
				Length: 1,
			},
			{
				Input:  `(sn;lang-sl:dn:=Lučić)`,
				Output: `(sn;lang-sl:dn:=Lu\c4\8di\c4\87)`,
				Choice: `extensibleMatch`,
				Length: 1,
			},
		*/
		{
			Input:  `(givenName:caseExactMatch:=John)`,
			Output: `(givenName:caseExactMatch:=John)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(givenName:dn:2.5.13.5:=John)`,
			Output: `(givenName:dn:2.5.13.5:=John)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(:caseExactMatch:=John)`,
			Output: `(:caseExactMatch:=John)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(:dn:2.5.13.5:=John)`,
			Output: `(:dn:2.5.13.5:=John)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(cn:caseExactMatch:=Fred Flintstone)`,
			Output: `(cn:caseExactMatch:=Fred Flintstone)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(cn:=Betty Rubble)`,
			Output: `(cn:=Betty Rubble)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(sn:dn:2.4.6.8.10:=Barney Rubble)`,
			Output: `(sn:dn:2.4.6.8.10:=Barney Rubble)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(o:dn:=Ace Industry)`,
			Output: `(o:dn:=Ace Industry)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(:1.2.3:=Wilma Flintstone)`,
			Output: `(:1.2.3:=Wilma Flintstone)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(:DN:2.4.6.8.10:=Dino)`,
			Output: `(:dn:2.4.6.8.10:=Dino)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(o=Parens R Us \28for all your parenthetical needs\29)`,
			Output: `(o=Parens R Us \28for all your parenthetical needs\29)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(cn=*\2A*)`,
			Output: `(cn=*\2A*)`,
			Choice: `substrings`,
			Length: 1,
		},
		{
			Input:  `(filename=C:\5cMyFile)`,
			Output: `(filename=C:\5cMyFile)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(bin=\00\00\00\04)`,
			Output: `(bin=\00\00\00\04)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(sn=Lučić)`,
			Output: `(sn=Lu\c4\8di\c4\87)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(sn=Lu\c4\8di\c4\87)`,
			Output: `(sn=Lu\c4\8di\c4\87)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(1.3.6.1.4.1.1466.0=\04\02\48\69)`,
			Output: `(1.3.6.1.4.1.1466.0=\04\02\48\69)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(objectGUID=абвгдеёжзийклмнопрстуфхцчшщъыьэюя)`,
			Output: `(objectGUID=\d0\b0\d0\b1\d0\b2\d0\b3\d0\b4\d0\b5\d1\91\d0\b6\d0\b7\d0\b8\d0\b9\d0\ba\d0\bb\d0\bc\d0\bd\d0\be\d0\bf\d1\80\d1\81\d1\82\d1\83\d1\84\d1\85\d1\86\d1\87\d1\88\d1\89\d1\8a\d1\8b\d1\8c\d1\8d\d1\8e\d1\8f)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(objectGUID=\d0\b0\d0\b1\d0\b2\d0\b3\d0\b4\d0\b5\d1\91\d0\b6\d0\b7\d0\b8\d0\b9\d0\ba\d0\bb\d0\bc\d0\bd\d0\be\d0\bf\d1\80\d1\81\d1\82\d1\83\d1\84\d1\85\d1\86\d1\87\d1\88\d1\89\d1\8a\d1\8b\d1\8c\d1\8d\d1\8e\d1\8f)`,
			Output: `(objectGUID=\d0\b0\d0\b1\d0\b2\d0\b3\d0\b4\d0\b5\d1\91\d0\b6\d0\b7\d0\b8\d0\b9\d0\ba\d0\bb\d0\bc\d0\bd\d0\be\d0\bf\d1\80\d1\81\d1\82\d1\83\d1\84\d1\85\d1\86\d1\87\d1\88\d1\89\d1\8a\d1\8b\d1\8c\d1\8d\d1\8e\d1\8f)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(sn=Mi*함*r)`,
			Output: `(sn=Mi*\ed\95\a8*r)`,
			Choice: `substrings`,
			Length: 1,
		},
		{
			Input:  ``,
			Output: `(objectClass=*)`,
			Choice: `present`,
			Length: 1,
		},
		{
			Input:  nil,
			Output: `(objectClass=*)`,
			Choice: `present`,
			Length: 1,
		},
		{
			Input:  struct{}{},
			Output: ``,
			Error:  `Invalid or malformed filter`,
			Choice: `invalid`,
			Length: 0,
		},
	} {
		filter, err := New(x.Input)
		if err != nil {
			if err.Error() != x.Error {
				t.Errorf("%s[%d] parse check failed: %v", t.Name(), idx, err)
			}
			continue
		} else if got := filter.String(); got != x.Output {
			t.Errorf("%s[%d] string check failed:\nwant: %s\ngot:  %s",
				t.Name(), idx, x.Output, got)
			continue
		} else if choice := filter.Choice(); choice != x.Choice {
			t.Errorf("%s[%d] choice check failed:\nwant: %s\ngot:  %s\n",
				t.Name(), idx, x.Choice, choice)
			continue
		} else if l := filter.Len(); l != x.Length {
			t.Errorf("%s[%d] length check failed:\nwant: %d\ngot:  %d\n",
				t.Name(), idx, x.Length, l)
			continue
		}
	}
}

func TestFilter_codecov(t *testing.T) {

	var ands FilterAnd
	ands.isFilter()
	ands.IsZero()

	var ors FilterOr
	ors.isFilter()
	ors.IsZero()

	var nots FilterNot
	nots.isFilter()
	nots.IsZero()

	var gEqual FilterGreaterOrEqual
	_ = gEqual.String()
	gEqual.isFilter()
	gEqual.Desc = `n`
	gEqual.Value = syntax.AssertionValue(`test`)
	gEqual.Len()
	gEqual.Index(9)
	gEqual.IsZero()

	var lEqual FilterLessOrEqual
	_ = lEqual.String()
	lEqual.isFilter()
	lEqual.Desc = `n`
	lEqual.Value = syntax.AssertionValue(`test`)
	lEqual.Len()
	lEqual.Index(9)
	lEqual.IsZero()

	var mat MatchingRuleAssertion
	mat.MatchingRule = MatchingRuleID(`test`)
	mat.IsZero()

	var exts FilterExtensibleMatch
	_ = exts.String()
	exts.isFilter()
	exts.DNAttributes = true
	_ = exts.String()
	e, _ := New(`(a:dn:1.2.3:=John)`)
	e.(FilterExtensibleMatch).Len()
	e.(FilterExtensibleMatch).Index(9)
	e.(FilterExtensibleMatch).IsZero()

	_ = isOIDOrDescr(``)
	_ = descrSyntaxCheck(`abc123-`)
	_ = descrSyntaxCheck(`-abc123`)
	_ = descrSyntaxCheck(`abc--123`)
	_ = descrSyntaxCheck(`abc#123`)

	_, _ = assertString([]byte(`123`), 1, `cn`)
	_, _ = assertString(``, 1, `cn`)
	_ = oIDSyntaxCheck(`1.3.-6`)
	_ = oIDSyntaxCheck(`1.3.6.-4`)
	_ = oIDSyntaxCheck(`1.4A`)
	_ = oIDSyntaxCheck(`1.41`)
	_ = oIDSyntaxCheck(`3.4`)
	_ = isValidArc(`a`)
	_ = isValidArc(`06`)
	_ = isValidArc(`?`)
	_ = isValidArc(`-4`)

	var descr AttributeDescription = "cn"
	_ = descr.Type()

	var extns FilterExtensibleMatch
	extns.IsZero()

	var substrings FilterSubstrings
	_ = substrings.String()
	substrings.Substrings = syntax.SubstringAssertion{Any: syntax.AssertionValue(`blarg`)}
	substrings.Index(9)
	substrings.Len()
	substrings.IsZero()

	substrings.isFilter()
	substrings.Type = AttributeDescription(`cn`)

	var eqly FilterEqualityMatch
	_ = eqly.String()
	eqly.Desc = `n`
	eqly.Value = syntax.AssertionValue(`test`)
	eqly.Index(9)
	eqly.IsZero()
	eqly.Len()
	eqly.isFilter()

	var pres FilterPresent
	_ = pres.String()
	pres.Desc = `n`
	pres.Index(9)
	pres.IsZero()
	pres.Len()

	pres.isFilter()

	var aprx FilterApproximateMatch
	_ = aprx.String()
	aprx.Desc = `n`
	aprx.Value = syntax.AssertionValue(`test`)
	aprx.Index(9)
	aprx.IsZero()
	aprx.Len()
	aprx.isFilter()

	_, _ = marshalFilter(`cn=Jesse`)
	_, _ = marshalFilter(`_=Jesse`)
	_, _ = marshalFilter(`_=~Jesse`)
	_, _ = marshalFilter(`cn=~Jesse`)
	_, _ = marshalFilter(`_>=5`)
	_, _ = marshalFilter(`n>=5`)
	_, _ = marshalFilter(`cn=*esse`)

	var invalid invalidFilter
	_ = invalid.String()
	invalid.Index(9)
	invalid.IsZero()
	invalid.Len()
	invalid.isFilter()

	checkParenEncaps(`(bdf`, `fdhjds`)
	checkParenEncaps(`bdf`, `fdhjds)`)
	checkParenEncaps(`bdf`, `fdhjds`)
	checkParenEncaps(`Ibdf`, `fdhjds)`)

	// antipanic checks
	checkFilterOIDs(`at;bogus-tag`, `i`)
	checkFilterOIDs(`at`, `_lr`)
	checkFilterOIDs(`at`, ``)
	checkFilterOIDs(`1.3.5`, ``)
	checkFilterOIDs(`1.3.5`, `i`)
	checkFilterOIDs(``, `1.3.5`)
	checkFilterOIDs(`at`, `1.3.5`)
	checkFilterOIDs(``, `lr`)
	checkFilterOIDs(``, ``)
	checkFilterOIDs(`%$^&@#`, `#^@`)

	parseItemFilter(`4783`)
	parseItemFilter("(something=value")
	parseItemFilter(`47=83`)
	parseItemFilter(`47=_83`)
	parseItemFilter(`a:dn:1.2.3:=John`)
	parseExtensibleMatch(`a:dn:1.2.3.4`, `xxxx`)
	parseFilterNot(`4`)
	parseFilterNot(`uifeds\f43829`)
	marshalFilter(`uifeds\f43829`)
	marshalFilter(` `)
	parseComplexFilter(`_`, `&`)

	dnAttrSplit(`A:dn:Z`)
	dnAttrSplit(`A:DN:Z`)
}

func BenchmarkFilterParse(b *testing.B) {
	b.StopTimer()
	filters := []string{
		`(objectGUID=함수목록)`,
		`(memberOf:1.2.840.113556.1.4.1941:=CN=User1,OU=blah,DC=mydomain,DC=net)`,
		`(objectGUID=\a)`,
		`(objectGUID=\zz)`,
		`(objectClass=`,
		`(&(objectClass=*)(cn=Jesse))`,
		`(sn=*ore*a)`,
		`(&(objectClass=*)(|(cn=Jesse)(cn=Courtney)))`,
		`(objectClass=top)`,
		`(givenName~=Jessi)`,
		`(n>=17485)`,
		`(cn=Babs Jensen)`,
		`(givenName=)`,
		`(!(cn=Tim Howes))`,
		`(|(employeeID=123456)(sn=Jensen)(cn=Babs J*))`,
		`(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))`,
		`(o=univ*of*mich*)`,
		`(seeAlso=)`,
		`(n<=17485)`,
		`objectClass=top`,
		`(givenName:=John)`,
		`(givenName:dn:=John)`,
		`(givenName:caseExactMatch:=John)`,
		`(givenName:dn:2.5.13.5:=John)`,
		`(:caseExactMatch:=John)`,
		`(:dn:2.5.13.5:=John)`,
		`(cn:caseExactMatch:=Fred Flintstone)`,
		`(cn:=Betty Rubble)`,
		`(sn:dn:2.4.6.8.10:=Barney Rubble)`,
		`(o:dn:=Ace Industry)`,
		`(:1.2.3:=Wilma Flintstone)`,
		`(:DN:2.4.6.8.10:=Dino)`,
		`(o=Parens R Us \28for all your parenthetical needs\29)`,
		`(cn=*\2A*)`,
		`(filename=C:\5cMyFile)`,
		`(bin=\00\00\00\04)`,
		`(sn=Lu\c4\8di\c4\87)`,
		`(1.3.6.1.4.1.1466.0=\04\02\48\69)`,
		`(objectGUID=абвгдеёжзийклмнопрстуфхцчшщъыьэюя)`,
		`(objectGUID=\d0\b0\d0\b1\d0\b2\d0\b3\d0\b4\d0\b5\d1\91\d0\b6\d0\b7\d0\b8\d0\b9\d0\ba\d0\bb\d0\bc\d0\bd\d0\be\d0\bf\d1\80\d1\81\d1\82\d1\83\d1\84\d1\85\d1\86\d1\87\d1\88\d1\89\d1\8a\d1\8b\d1\8c\d1\8d\d1\8e\d1\8f)`,
		`(sn=Mi*함*r)`,
		``,
	}

	maxIdx := len(filters)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, _ = New(filters[i%maxIdx])
	}
}
