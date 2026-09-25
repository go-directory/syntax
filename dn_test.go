package syntax

import (
	"fmt"
	"testing"
)

func ExampleLDAPDN() {
	dn := LDAPDN(`cn=Jesse Coretta,ou=Consultants,ou=Accounts,dc=example,dc=com`)

	// Get the RDN of the DN
	fmt.Printf("RDN: %s\n", dn.RDN())

	// Get the superior (parent) DN of the DN
	super := dn.Superior()
	fmt.Printf("SUP: %s\n", super)

	// Create a new subordinate DN below DN
	newChildRDN := RelativeLDAPDN(`cn=Private mailing list`)
	fmt.Printf("SUB: %s\n", dn.Subordinate(newChildRDN))

	// Compare two DNs
	fmt.Printf("DNs are the same: %t\n", dn.EqualFold(super))

	// Output:
	// RDN: cn=Jesse Coretta
	// SUP: ou=Consultants,ou=Accounts,dc=example,dc=com
	// SUB: cn=Private mailing list,cn=Jesse Coretta,ou=Consultants,ou=Accounts,dc=example,dc=com
	// DNs are the same: false
}

func ExampleRelativeLDAPDN_roundTripBER() {
	dn, err := NewRelativeLDAPDN([]byte("cn=Jesse Coretta+o=Acme Co"))
	if err != nil {
		fmt.Println(err)
		return
	}

	var enc []byte
	if enc, err = dn.Encode(); err != nil {
		fmt.Println(err)
		return
	}

	var dec RelativeLDAPDN
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(dec)
	// Output: cn=Jesse Coretta+o=Acme Co
}

func ExampleLDAPDN_roundTripBER() {
	dn, err := NewLDAPDN([]byte("cn=Jesse Coretta+o=Acme Co,ou=Consultants,ou=People,dc=example,dc=com"))
	if err != nil {
		fmt.Println(err)
		return
	}

	var enc []byte
	if enc, err = dn.Encode(); err != nil {
		fmt.Println(err)
		return
	}

	var dec LDAPDN
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(dec)
	// Output: cn=Jesse Coretta+o=Acme Co,ou=Consultants,ou=People,dc=example,dc=com
}

func TestDistinguisedName(t *testing.T) {
	orig := []byte("cn=Jesse Coretta+o=Acme Co,ou=Consultants,ou=People,dc=example,dc=com")
	dn, err := NewDistinguishedName(orig, true)
	if err != nil {
		t.Fatalf("%s failed: %v", t.Name(), err)
	} else if len(dn.Normal) == 0 {
		t.Fatalf("%s preprocessing failed: no normalized DN", t.Name())
	}

	dn.Boundary = 1

	root, _ := dn.Root()
	sup, _ := dn.Superior()
	sub, _ := dn.Subordinate("cn=Private Mailing List")

	want := `dc=example,dc=com`
	if got := string(root.Case); got != want {
		t.Fatalf("%s root truncation failed:\n\twant: %q\n\tgot:  %q :=  no normalized DN",
			t.Name(), want, got)
	}

	want = `ou=Consultants,ou=People,dc=example,dc=com`
	if got := string(sup.Case); got != want {
		t.Fatalf("%s superior truncation failed:\n\twant: %q\n\tgot:  %q :=  no normalized DN",
			t.Name(), want, got)
	}

	want = `cn=Private Mailing List,cn=Jesse Coretta+o=Acme Co,ou=Consultants,ou=People,dc=example,dc=com`
	if got := string(sub.Case); got != want {
		t.Fatalf("%s subordinate creation failed:\n\twant: %q\n\tgot:  %q :=  no normalized DN",
			t.Name(), want, got)
	}
}
