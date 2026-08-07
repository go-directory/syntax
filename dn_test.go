package syntax

import (
	"testing"
)

func TestDistinguisedName_PreProc(t *testing.T) {
	orig := []byte("cn=Jesse Coretta+o=Acme Co,ou=Consultants,ou=People,dc=example,dc=com")
	_, err := NewDistinguishedName(orig, true)
	if err != nil {
		t.Fatalf("%s failed: %v", t.Name(), err)
	}
	/*
	   t.Logf("%s\n", dn.Case)
	   t.Logf("%s\n", dn.Normal)

	   	for i := 0; i < len(dn.Attributes); i++ {
	   		t.Logf("%s\n", dn.Attributes[i]) // cn, o, ou, dc
	   	}

	   	for i := 0; i < len(dn.Values); i++ {
	   		t.Logf("%s\n", dn.Values[i]) // Jesse Coretta, Acme Co, Consultants, People, example, com
	   	}
	*/
}
