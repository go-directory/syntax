package syntax

import (
	"testing"
)

func BenchmarkURIParse(b *testing.B) {
	b.StopTimer()

	maxIdx := len(uriTestValues)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, _ = NewURI(uriTestValues[i%maxIdx].Orig)
	}
}

func TestURL(t *testing.T) {

	for idx, obj := range uriTestValues {
		u, err := NewURI(obj.Orig)
		if obj.Valid {
			if err != nil {
				t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			} else if got := u.String(); got != obj.Want {
				t.Errorf("%s[%d] failed:\n\twant '%s'\n\tgot  '%s'", t.Name(), idx, obj.Want, got)
			}
		} else if err == nil {
			t.Errorf("%s[%d] failed: expected error, got nil", t.Name(), idx)
		}
	}

	var bogus URI
	_ = bogus.String()
}

// NOTE: most of these test values are
// copied directly from § 4 of RFC4516.
var uriTestValues = []struct {
	Orig  string
	Want  string
	Valid bool
}{
	{
		Orig:  "ldap://localhost:389/dc=example%2Cdc=com?cn%2Csn?sub?(cn%3DJohn%20Doe)?!x-foo%3Dbar,!x-bar",
		Want:  "ldap://localhost:389/dc=example,dc=com?cn,sn?sub?(cn=John Doe)?!x-foo=bar,!x-bar",
		Valid: true,
	},
	{
		Orig:  "ldap:///o=University%20of%20Michigan,c=US",
		Want:  "ldap:///o=University of Michigan,c=US",
		Valid: true,
	},
	{
		Orig:  "ldap://ldap1.example.net/o=University%20of%20Michigan,c=US",
		Want:  "ldap://ldap1.example.net/o=University of Michigan,c=US",
		Valid: true,
	},
	{
		Orig:  "ldap://ldap1.example.net/o=University%20of%20Michigan,c=US?postalAddress",
		Want:  "ldap://ldap1.example.net/o=University of Michigan,c=US?postalAddress",
		Valid: true,
	},
	{
		Orig:  "ldap://ldap1.example.net:6666/o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)",
		Want:  "ldap://ldap1.example.net:6666/o=University of Michigan,c=US??sub?(cn=Babs Jensen)",
		Valid: true,
	},
	{
		Orig: "LDAP://ldap1.example.com/c=GB?owner#?ONE",
	},
	{
		Want: "ldap://localhost:389/d%%cc?&&?--%",
	},
	{
		Want: "ldap://localhost:389/?_%2c?cn,_%",
	},
	{
		Orig:  "LDAP://ldap1.example.com/c=GB?objectClass?ONE",
		Want:  "ldap://ldap1.example.com/c=GB?objectClass?one",
		Valid: true,
	},
	{
		Orig:  "ldap://ldap2.example.com/o=Question%3f,c=US?mail",
		Want:  "ldap://ldap2.example.com/o=Question?,c=US?mail",
		Valid: true,
	},
	{
		Orig: "ldap://ldap3.example.com/o=Babsco,c=US???(four-octet=%5c00%5c00%5c00%5c04)%%%",
	},
	{
		Orig: "ldap://ldap3.example.com/o=Babsco,c=US???(?)",
	},
	{
		Orig:  "ldap://ldap3.example.com/o=Babsco,c=US???(four-octet=%5c00%5c00%5c00%5c04)",
		Want:  "ldap://ldap3.example.com/o=Babsco,c=US???(four-octet=\\00\\00\\00\\04)",
		Valid: true,
	},
	{
		Orig:  "ldap://ldap.example.com/o=An%20Example%5C2C%20Inc.,c=US",
		Want:  "ldap://ldap.example.com/o=An Example\\, Inc.,c=US",
		Valid: true,
	},
	{
		Orig:  "ldap://ldap.example.net",
		Want:  "ldap://ldap.example.net/",
		Valid: true,
	},
	{
		Orig:  "ldap://ldap.example.net/",
		Want:  "ldap://ldap.example.net/",
		Valid: true,
	},
	{
		Orig:  "ldap://ldap.example.net/?",
		Want:  "ldap://ldap.example.net/",
		Valid: true,
	},
	{
		Orig: "ldap://ldap.example.net:47328934/?",
	},
	{
		Orig: "ldap://ldap.example.net:@@@/?",
	},
	{
		Orig: "ldapi://ldap.example.net:1234",
	},
	{
		Orig: "ldap:///??sub??e-bindname=cn=Manager%2cdc=example%2cdc=com%%%",
	},
	{
		Orig: "ldap:///??sub??e-bindname=cn=Manager%2cdc=example%2cdc=com?bananas",
	},
	{
		Orig: "ldap:///??suub??e-bindname=cn=Manager%2cdc=example%2cdc=com",
	},
	{
		Orig:  "ldap:///??sub??e-bindname=cn=Manager%2cdc=example%2cdc=com",
		Want:  "ldap:///??sub??e-bindname=cn=Manager,dc=example,dc=com",
		Valid: true,
	},
	{
		Orig:  "ldap:///??sub??!e-bindname=cn=Manager%2cdc=example%2cdc=com",
		Want:  "ldap:///??sub??!e-bindname=cn=Manager,dc=example,dc=com",
		Valid: true,
	},
	{
		Orig: "http:///??sub??!e-bindname=cn=Manager",
	},
	{
		Orig:  "ldap:///",
		Want:  "ldap:///",
		Valid: true,
	},
	{
		Orig:  "ldaps:///",
		Want:  "ldaps:///",
		Valid: true,
	},
	{
		Orig:  "ldapi:///",
		Want:  "ldapi:///",
		Valid: true,
	},
}
