package aci

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/JesseCoretta/go-ldapfilter"
)

func ExampleScope() {
	scope, err := NewSearchScope("one")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(scope)
	// Output: onelevel
}

func ExampleNewInstruction() {
	raw := `( targetfilter = "(&(objectClass=employee)(objectClass=engineering))" )( targetcontrol = "1.2.3.4" || "1.2.3.5" )( targetscope = "onelevel" )(version 3.0; acl "Allow read and write for anyone using greater than or equal 128 SSF - extra nesting"; allow(read,write) ( ( ( userdn = "ldap:///anyone" ) AND ( ssf >= "71" ) ) AND NOT ( dayofweek = "Wed" OR dayofweek = "Fri" ) ); )`

	i, err := NewInstruction(raw)
	if err != nil {
		fmt.Println(err)
		return
	}

	perm := i.PB.Index(0).Permission()
	rule := i.PB.Index(0).BindRule().Index(0).Index(0)
	fmt.Printf("Permission: %s\n", perm)
	fmt.Printf("BindRule: %s\n", rule)
	// Output:
	// Permission: allow(read,write)
	// BindRule: (userdn="ldap:///anyone")
}

func TestNewInstruction(t *testing.T) {
	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `( targetfilter = "(&(objectClass=employee)(objectClass=engineering))" )( targetcontrol = "1.2.3.4" || "1.2.3.5" )( targetscope = "onelevel" )(version 3.0; acl "Allow read and write for anyone using greater than or equal 128 SSF - extra nesting"; allow(read,write) ( ( ( userdn = "ldap:///anyone" ) AND ( ssf >= "71" ) ) AND NOT ( dayofweek = "Wed" OR dayofweek = "Fri" ) ); )`,
			Want: `(targetfilter="(&(objectClass=employee)(objectClass=engineering))")(targetcontrol="1.2.3.4||1.2.3.5")(targetscope="onelevel")(version 3.0; acl "Allow read and write for anyone using greater than or equal 128 SSF - extra nesting"; allow(read,write) (((userdn="ldap:///anyone") AND (ssf>="71")) AND NOT (dayofweek="Wed" OR dayofweek="Fri"));)`,
		},
		{
			Orig: `( targetfilter = "(&(objectClass=employee)(objectClass=engineering))" )( targetcontrol = "1.2.3.4" || "1.2.3.5" )( targetscope = "onelevel" )(version 3.0; acl "Allow read and write for anyone using greater than or equal 128 SSF - extra nesting"; allow(read,write) ( ( ( userdn = "ldap:///anyone" ) AND ( ssf >= "71" ) ) AND NOT ( dayofweek = "Wed" OR dayofweek = "Fri" ) ); deny(proxy,selfwrite) ( userdn = "ldap:///all" ); )`,
			Want: `(targetfilter="(&(objectClass=employee)(objectClass=engineering))")(targetcontrol="1.2.3.4||1.2.3.5")(targetscope="onelevel")(version 3.0; acl "Allow read and write for anyone using greater than or equal 128 SSF - extra nesting"; allow(read,write) (((userdn="ldap:///anyone") AND (ssf>="71")) AND NOT (dayofweek="Wed" OR dayofweek="Fri")); deny(selfwrite,proxy) (userdn="ldap:///all");)`,
		},
		{
			Orig: `( target = "ldap:///uid=*,ou=People,dc=example,dc=com" )(version 3.0; acl "Limit people access to timeframe"; allow(read,search,compare) ( ( timeofday >= "1730" AND timeofday < "2400" ) AND ( userdn = "ldap:///uid=jesse,ou=admin,dc=example,dc=com" OR userdn = "ldap:///uid=courtney,ou=admin,dc=example,dc=com" ) AND NOT ( userattr = "ninja#FALSE" ) ); )`,
			Want: `(target="ldap:///uid=*,ou=People,dc=example,dc=com")(version 3.0; acl "Limit people access to timeframe"; allow(read,search,compare) ((timeofday>="1730" AND timeofday<"2400") AND (userdn="ldap:///uid=jesse,ou=admin,dc=example,dc=com" OR userdn="ldap:///uid=courtney,ou=admin,dc=example,dc=com") AND NOT (userattr="ninja#FALSE"));)`,
		},
	}

	for idx, obj := range tests {
		x, err := NewInstruction(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}

	// coverage
	pbr, _ := NewPermissionBindRule("allow(none) ssf>=128")
	_, _ = NewInstruction("")
	_, _ = NewInstruction("(version 3.0;")
	_, _ = NewInstruction("(version 3.0; acl \"Hello\"")
	_, _ = NewInstruction("(version 3.0; acl \"Hello\";;)")
	_, _ = NewInstruction("(version 3.0; acl 'Hello'; allow(none)")
	_, _ = NewInstruction("(version 3.0; acl \"Hello\"; allow(none) ssf>=128)")
	_, _ = NewInstruction("(version 3.0; acl \"Hello\"; allow(none) ssf>=128]")
	_, _ = NewInstruction(TargetRule{&aCITargetRule{slice: []TargetRuleItem{}}})
	_, _ = NewInstruction(TargetRule{&aCITargetRule{slice: []TargetRuleItem{}}}, "acl", PermissionBindRule{})
	_, _ = NewInstruction(TargetRule{&aCITargetRule{slice: []TargetRuleItem{}}}, "acl", pbr)
	_, _ = NewInstruction(PermissionBindRule{})
	_, _ = NewInstruction("acl", PermissionBindRule{})
	_, _ = NewInstruction(rune(22), PermissionBindRule{})
	_, _ = NewInstruction("my acl", "allow(none) ssf>=128")
	_, _ = NewInstruction("my acl", pbr)
	_, _ = NewInstruction("my acl", rune(22))
	_, _ = NewInstruction(struct{}{}, struct{}{}, struct{}{}, struct{}{})
	_, _ = NewInstruction("(targetattr=\"*\")", "my acl", rune(22))
	_, _ = NewInstruction("(targetattr=\"*\")", rune(22), pbr)
	_, _ = NewInstruction("(targetattr=\"*\")", "my acl", pbr)
	_, _ = NewInstruction(rune(22), "my acl", pbr)
	_, _ = NewInstruction("(targetattr=\"*\")", "my acl", "allow(none) ssf>=128")
}

func TestPermissionBindRuleItem(t *testing.T) {

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `allow(read,search,compare) ((ssf >= "56" OR userdn="ldap:///all") AND NOT (ssf = "256" OR ssf = "255") );`,
			Want: `allow(read,search,compare) ((ssf>="56" OR userdn="ldap:///all") AND NOT (ssf="256" OR ssf="255"));`,
		},
	}

	for idx, obj := range tests {
		x, err := NewPermissionBindRuleItem(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
		_ = x.Permission()
		_ = x.BindRule()
		_ = x.Kind()
		_ = x.Valid()
	}
}

func TestPermissionBindRule(t *testing.T) {
	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `allow(read,search,compare) ((ssf >= "57" OR userdn = "ldap:///all") AND NOT (ssf = "256" OR ssf = "255") ); deny(proxy, add) (timeofday > "1700" AND timeofday <= "1900");`,
			Want: `allow(read,search,compare) ((ssf>="57" OR userdn="ldap:///all") AND NOT (ssf="256" OR ssf="255")); deny(add,proxy) (timeofday>"1700" AND timeofday<="1900");`,
		},
	}

	for idx, obj := range tests {
		x, err := NewPermissionBindRule(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
		_ = x.Index(0)
		_ = x.Kind()
		_ = x.Valid()
	}
}

func TestBindRuleItem(t *testing.T) {
	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `userdn != "ldap:///anyone"`,
			Want: `userdn!="ldap:///anyone"`,
		},
		{
			Orig: `( ssf >= "57" )`,
			Want: `(ssf>="57")`,
		},
	}

	for idx, obj := range tests {
		x, err := NewBindRuleItem(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestBindRuleAnd(t *testing.T) {

	tests := []struct {
		Orig []any
		Want string
	}{
		{
			Orig: []any{
				`ssf >= "128"`,
				`( userdn = "ldap:///uid=jesse,ou=People,o=example" )`,
			},
			Want: `ssf>="128" AND (userdn="ldap:///uid=jesse,ou=People,o=example")`,
		},
	}

	for idx, obj := range tests {
		x, err := NewBindRuleAnd(obj.Orig...)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestBindRuleOr(t *testing.T) {

	tests := []struct {
		Orig []any
		Want string
	}{
		{
			Orig: []any{
				`userdn = "uid=jesse,ou=People,o=example"`,
				`userdn = "uid=courtney,ou=People,o=example"`,
			},
			Want: `userdn="ldap:///uid=jesse,ou=People,o=example" OR userdn="ldap:///uid=courtney,ou=People,o=example"`,
		},
	}

	for idx, obj := range tests {
		x, err := NewBindRuleOr(obj.Orig...)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestNewBindRuleNot(t *testing.T) {

	tests := []struct {
		And  string
		Not  string
		Want string
	}{
		{
			And:  `userdn = "uid=jesse,ou=People,o=example"`,
			Not:  `( userdn = "uid=courtney,ou=People,o=example" )`,
			Want: `userdn="ldap:///uid=jesse,ou=People,o=example" AND NOT (userdn="ldap:///uid=courtney,ou=People,o=example")`,
		},
	}

	for idx, obj := range tests {
		x, err := NewBindRuleAnd(obj.And)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else {
			var z BindRule
			if z, err = NewBindRuleNot(obj.Not); err != nil {
				t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
				return
			}
			x.Push(z)

			if got := x.String(); got != obj.Want {
				t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
				return
			}
		}
	}
}

func TestPermission(t *testing.T) {

	tests := []struct {
		Orig        string
		Want        string
		Disposition bool // true:allow/false:deny
	}{
		{
			Orig:        `allow(read,search,compare)`,
			Want:        `allow(read,search,compare)`,
			Disposition: true,
		},
		{
			Orig:        `deny(write,proxy)`,
			Want:        `deny(write,proxy)`,
			Disposition: false,
		},
	}

	for idx, obj := range tests {
		x, err := NewPermission(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if disp := x.Disposition() == "allow"; disp != obj.Disposition {
			t.Errorf("%s[%d] failed:\n\twant: %t\n\tgot:  %t", t.Name(), idx, obj.Disposition, disp)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestBindRuleInterface(t *testing.T) {

	tests := []struct {
		Orig  string
		Want  string
		Valid bool
	}{
		{
			Orig:  `((ssf >= "102" OR userdn="ldap:///anyone") AND NOT (ssf = "256" OR ssf = "255") )`,
			Want:  `((ssf>="102" OR userdn="ldap:///anyone") AND NOT (ssf="256" OR ssf="255"))`,
			Valid: true,
		},
		{
			Orig:  `( groupdn = "ldap:///cn=Human Resources,dc=example,dc=com" )`,
			Want:  `(groupdn="ldap:///cn=Human Resources,dc=example,dc=com")`,
			Valid: true,
		},
		{
			Orig:  `( uerattr = "aciurl#LDAPURL" )`,
			Valid: false,
		},
		{
			Orig:  `( userdn = "ldap:///all" )`,
			Want:  `(userdn="ldap:///all")`,
			Valid: true,
		},
		{
			Orig:  `( userdn |? "flap:///parent" || "ldap:///self" `,
			Valid: false,
		},
		{
			Orig:  `( userdn = "ldap:///anyone" ) AND ( ip != "192.0.2." )`,
			Want:  `(userdn="ldap:///anyone") AND (ip!="192.0.2.")`,
			Valid: true,
		},
		{
			Orig:  `( udn = "ldap:anyone" )`,
			Valid: false,
		},
		{
			Orig:  `( userdn = "ldap:///self" )`,
			Want:  `(userdn="ldap:///self")`,
			Valid: true,
		},
		{
			Orig:  `( userDN = "ldap:///self" ) UND ( ssf >= "128" )`,
			Valid: false,
		},
		{
			Orig:  `( userdn = "ldap:///uid=user,ou=People,dc=example,dc=com" )`,
			Want:  `(userdn="ldap:///uid=user,ou=People,dc=example,dc=com")`,
			Valid: true,
		},
		{
			Orig:  `( userdn "ldap:///uid=user,ou=People,dc=example,dc=com" ) AND ( dayofweek "Son,Sat" )`,
			Valid: false,
		},
		{
			Orig:  `( userdn = "ldap:///uid=user,ou=People,dc=example,dc=com" ) AND ( timeofday >= "1800" AND timeofday < "2400" )`,
			Want:  `(userdn="ldap:///uid=user,ou=People,dc=example,dc=com") AND (timeofday>="1800" AND timeofday<"2400")`,
			Valid: true,
		},
		{
			Orig:  `groupdn =`,
			Valid: false,
		},
		{
			Orig:  `groupdn = "ldap:///cn=DomainAdmins,ou=Groups,[$dn],dc=example,dc=com"`,
			Want:  `groupdn="ldap:///cn=DomainAdmins,ou=Groups,[$dn],dc=example,dc=com"`,
			Valid: true,
		},
		{
			Orig:  `gropedn "ldap:///cn=DomainAdmins,ou=Groups,dc=subdomain1,dc=hostedCompany1,dc=example,dc=com"`,
			Valid: false,
		},
		{
			Orig:  `groupdn = "ldap:///cn=example,ou=groups,dc=example,dc=com"`,
			Want:  `groupdn="ldap:///cn=example,ou=groups,dc=example,dc=com"`,
			Valid: true,
		},
		{
			Orig:  `"manager#USERDN"`,
			Valid: false,
		},
		{
			Orig:  `userattr = "owner#USERDN"`,
			Want:  `userattr="owner#USERDN"`,
			Valid: true,
		},
		{
			Orig:  `((userattr = "parent[0].owner#USERDN"`,
			Valid: false,
		},
		{
			Orig:  `userattr = "parent[1].manager#USERDN"`,
			Want:  `userattr="parent[1].manager#USERDN"`,
			Valid: true,
		},
		{
			Orig:  `target_to = "http:///anyone" SAND stfu < "128"`,
			Valid: false,
		},
		{
			Orig:  `userdn = "ldap:///anyone" || "ldap:///self" || "ldap:///cn=Admin"`,
			Want:  `userdn="ldap:///anyone || ldap:///self || ldap:///cn=Admin"`,
			Valid: true,
		},
		{
			Orig:  `userdn = "" AND ssf >= "128"`,
			Valid: false,
		},
		{
			Orig:  `( ( ( userdn = "ldap:///anyone" ) AND ( ssf >= "71" ) ) AND NOT ( dayofweek = "Wed" ) )`,
			Want:  `(((userdn="ldap:///anyone") AND (ssf>="71")) AND NOT (dayofweek="Wed"))`,
			Valid: true,
		},
		{
			Orig:  `( ( userdn = "ldap:///anyone" AND ssf >= "128" ) I DID NOT HIT HER dayofweek = "Fri" )`,
			Valid: false,
		},
		{
			Orig:  `( authmethod = "NONE" OR authmethod = "SIMPLE" )`,
			Want:  `(authmethod="NONE" OR authmethod="SIMPLE")`,
			Valid: true,
		},
		{
			Orig:  `userdn = "ldap:///alguien" ) Y ( direcciónIP != "2001:db8::" )`,
			Valid: false,
		},
		{
			Orig:  `groupdn = "ldap:///cn=Administrators,ou=Groups,dc=example,com" AND groupdn = "ldap:///cn=Operators,ou=Groups,dc=example,com"`,
			Want:  `groupdn="ldap:///cn=Administrators,ou=Groups,dc=example,com" AND groupdn="ldap:///cn=Operators,ou=Groups,dc=example,com"`,
			Valid: true,
		},
		{
			Orig:  `extop = "ldap:///cn=Human Resources,ou=People,dc=example,dc=com"`,
			Valid: false,
		},
		{
			Orig:  `userattr = "manager#USERDN"`,
			Want:  `userattr="manager#USERDN"`,
			Valid: true,
		},
		{
			Orig:  `userdn = "ldap:///anyone" AND ssf >= "128" AND NOT [ dayofweek = "Fri" OR dayofweek = "Sun" ]`,
			Valid: false,
		},
		{
			Orig:  `userdn = "ldap:///anyone" AND ssf >= "128" AND NOT dayofweek = "Fri"`,
			Want:  `userdn="ldap:///anyone" AND ssf>="128" AND NOT dayofweek="Fri"`,
			Valid: true,
		},
		{
			Orig:  `usedn = "ldap:///bueller"`,
			Valid: false,
		},
		{
			Orig:  `userdn = "ldap:///cn=Courtney Tolana,dc=example,dc=com"`,
			Want:  `userdn="ldap:///cn=Courtney Tolana,dc=example,dc=com"`,
			Valid: true,
		},
		{
			Orig:  `rolepn # "ldap:///dc=example,dc=com??sub?(manager=example)`,
			Valid: false,
		},
		{
			Orig:  `userdn = "ldap:///ou=People,dc=example,dc=com??sub?(department=Human Resources)"`,
			Want:  `userdn="ldap:///ou=People,dc=example,dc=com??sub?(department=Human Resources)"`,
			Valid: true,
		},
		{
			Orig:  `( userdn = "ldap:///n'importequi" ) ET ( SystèmeDeNomsDeDomaines != "client.example.com" )`,
			Valid: false,
		},
		{
			Orig:  `( userdn = "ldap:///anyone" ) AND ( dns != "client.example.com" )`,
			Want:  `(userdn="ldap:///anyone") AND (dns!="client.example.com")`,
			Valid: true,
		},
		{
			Orig:  `userdn = ''`,
			Valid: false,
		},
		{
			Orig:  `( userdn = "ldap:///anyone" ) AND NOT ( dns != "client.example.com" )`,
			Want:  `(userdn="ldap:///anyone") AND NOT (dns!="client.example.com")`,
			Valid: true,
		},
		{
			Orig:  `useratr = "ldap:///ou=Profiles,ou=Configuration,dc=example,dc=com?hardwareType#physical"`,
			Valid: false,
		},
	}

	for idx, obj := range tests {
		x, err := NewBindRule(obj.Orig)
		if obj.Valid {
			if err != nil {
				t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
				return
			} else if got := x.String(); got != obj.Want {
				t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
				return
			}
		} else if x != nil {
			t.Errorf("%s[%d] failed: expected error, got nil", t.Name(), idx)
			return
		}
	}
}

func TestTargetRule(t *testing.T) {

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `(targetfilter = "(&(objectClass=account)(roleName=User))")(targetattr="cn||sn||givenName")`,
			Want: `(targetfilter="(&(objectClass=account)(roleName=User))")(targetattr="cn||sn||givenName")`,
		},
	}

	for idx, obj := range tests {
		x, err := NewTargetRule(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestTargetRuleItem(t *testing.T) {

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `( targetattr = "cn || sn || givenName" )`,
			Want: `(targetattr="cn||sn||givenName")`,
		},
		{
			Orig: `(targetfilter = "(&(objectClass=account)(roleName=User))")`,
			Want: `(targetfilter="(&(objectClass=account)(roleName=User))")`,
		},
	}

	for idx, obj := range tests {
		x, err := NewTargetRuleItem(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestAttributeFilterOperation(t *testing.T) {

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `add=homeDirectory:(&(objectClass=employee)(cn=Jesse Coretta)) && gecos:(|(objectClass=contractor)(objectClass=intern)),delete=uidNumber:(&(objectClass=accounting)(terminated=FALSE)) && gidNumber:(objectClass=account)`,
			Want: `add=homeDirectory:(&(objectClass=employee)(cn=Jesse Coretta)) && gecos:(|(objectClass=contractor)(objectClass=intern)),delete=uidNumber:(&(objectClass=accounting)(terminated=FALSE)) && gidNumber:(objectClass=account)`,
		},
	}

	for idx, obj := range tests {
		x, err := NewAttributeFilterOperation(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
		x.Kind()
		x.TRM()
		x.Keyword()
		x.SetDelimiter()
		x.SetDelimiter(0)
		x.SetDelimiter(1)
	}
}

func TestAttributeFilterOperationItem(t *testing.T) {

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `add=homeDirectory:(&(objectClass=employee)(cn=Jesse Coretta))`,
			Want: `add=homeDirectory:(&(objectClass=employee)(cn=Jesse Coretta))`,
		},
		{
			Orig: `add=homeDirectory:(&(objectClass=employee)(cn=Jesse Coretta)) && gecos:(|(objectClass=contractor)(objectClass=intern))`,
			Want: `add=homeDirectory:(&(objectClass=employee)(cn=Jesse Coretta)) && gecos:(|(objectClass=contractor)(objectClass=intern))`,
		},
	}

	for idx, obj := range tests {
		x, err := NewAttributeFilterOperationItem(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
		x.Index(0)
		x.Kind()
		x.TRM()
		x.Keyword()
		x.Push(x.Index(0).String())
		x.Contains("")
		x.Contains(rune(88))
		x.Contains(x.Index(0))
	}
}

func TestAttributeFilter(t *testing.T) {

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `homeDirectory:(&(objectClass=employee)(cn=Jesse Coretta))`,
			Want: `homeDirectory:(&(objectClass=employee)(cn=Jesse Coretta))`,
		},
	}

	for idx, obj := range tests {
		x, err := NewAttributeFilter(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
		x.Attribute()
		x.Filter()
	}
}

func ExampleOperator_stringers() {
	for _, cop := range []Operator{
		Eq, Ne, Lt, Gt, Le, Ge,
	} {
		fmt.Printf("[%d] %s (%s)[%s]\n",
			int(cop),
			cop.Description(),
			cop.Context(),
			cop)
	}

	// Output:
	// [1] Equal To (Eq)[=]
	// [2] Not Equal To (Ne)[!=]
	// [3] Less Than (Lt)[<]
	// [4] Greater Than (Gt)[>]
	// [5] Less Than Or Equal (Le)[<=]
	// [6] Greater Than Or Equal (Ge)[>=]
}

func ExampleOperator_Valid() {
	var unknown Operator = Operator(12)
	fmt.Printf("Is a known %T: %t", unknown, unknown.Valid() == nil)
	// Output: Is a known aci.Operator: false
}

/*
This example demonstrates the string representation for all
known ACIv3Operator constants.
*/
func ExampleOperator_String() {
	for _, cop := range []Operator{
		Eq, Ne, Lt, Gt, Le, Ge,
	} {
		fmt.Printf("%s\n", cop)
	}
	// Output:
	// =
	// !=
	// <
	// >
	// <=
	// >=
}

/*
This example demonstrates the use of the Context method to show
all the context name for all Operator constants.
*/
func ExampleOperator_Context() {
	for _, cop := range []Operator{
		Eq, Ne, Lt, Gt, Le, Ge,
	} {
		fmt.Printf("%s\n", cop.Context())
	}
	// Output:
	// Eq
	// Ne
	// Lt
	// Gt
	// Le
	// Ge
}

/*
This example demonstrates the use of the Description method to
show all descriptive text for all Operator constants.
*/
func ExampleOperator_Description() {
	for _, cop := range []Operator{
		Eq, Ne, Lt, Gt, Le, Ge,
	} {
		fmt.Printf("%s\n", cop.Description())
	}
	// Output:
	// Equal To
	// Not Equal To
	// Less Than
	// Greater Than
	// Less Than Or Equal
	// Greater Than Or Equal
}

func ExampleInstruction_OID_netScapeOID() {
	var i Instruction
	fmt.Printf("Netscape 'aci' attribute OID: %s\n", i.OID())
	// Output: Netscape 'aci' attribute OID: 2.16.840.1.113730.3.1.55
}

func TestNetscape_codecov(t *testing.T) {

	bi, err := NewBindRuleItem(`userdn!="ldap:///anyone"`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}
	bi.(BindRuleItem).SetQuotationStyle(0)
	bi.(BindRuleItem).SetQuotationStyle(1)
	bi.(BindRuleItem).SetPaddingStyle(0)
	bi.(BindRuleItem).SetPaddingStyle(1)
	bi.(BindRuleItem).Push("garbage")
	bi.(BindRuleItem).isBindRule()
	bi.(BindRuleItem).Len()
	bi.(BindRuleItem).Index(0)

	_, _ = NewBindRuleItem(BindUDN, Eq, "ldap:///anyone")
	_, _ = NewBindRuleItem(BindUDN, 0x00, "ldap:///anyone")
	_, _ = NewBindRuleItem(rune(88))

	var pbri PermissionBindRuleItem
	pbri.Valid()
	pbri.parse("")
	pbri.parse("bogus")
	pbri.parse("allow(read) stuff")

	var attr Attribute
	attr.Kind()
	attr.Keyword()
	attr, _ = NewAttribute("cn", "sn", "givenName")
	_ = attr.string(true, false)
	_ = attr.string(false, true)
	_ = attr.string(true, true)
	_ = attr.string(false, false)
	attr, _ = NewAttribute("*")
	attr.Ne()
	attr.Push("drink")
	attr.Push("_")
	attr.Push([]string{"drink", "objectClass"})
	attr.Push(Attribute{})
	attr.aCIAttribute.all = true
	attr.string(true, true)
	_ = attr.String()
	attr.Ne()
	attr.aCIAttribute.all = false
	attr.aCIAttribute.slice = []string{"cn", "sn"}
	attr.Push([]string{"cn", "sn"})
	attr.Push("cn", "sn")
	attr.Push(attr)
	attr.Ne()

	var pbr PermissionBindRule
	pbr.Valid()
	pbr.parse("")
	pbr.parse("bogus")

	var bi2 BindRuleItem
	bi2.SetKeyword("userdn")
	bi2.SetOperator("=")
	bi2.SetExpression()
	_ = bi2.String()
	bi2.Valid()
	bi2.aCIBindRuleItem = &aCIBindRuleItem{}
	_ = bi2.String()
	bi2.Valid()
	bi2.SetKeyword("userdn")
	bi2.SetOperator("=")
	bi2.IsParen()
	bi2.Valid()
	_ = bi2.String()

	var bnt BindRuleNot
	bnt.Valid()
	bnt.Push(nil)
	bnt.aCIBindRuleNot = &aCIBindRuleNot{
		BindRule: newACIv3BindRuleItem(`userdn`, `=`, `ldap:///`),
	}
	bnt.Push(bi)
	bnt.Push(`( userdn!="ldap:///all" OR groupdn!="ldap:///parent" )`)
	bnt.SetParen(true)
	bnt.SetQuotationStyle(0)
	bnt.SetQuotationStyle(1)
	bnt.SetPaddingStyle(0)
	bnt.SetPaddingStyle(1)
	bnt.Kind()
	bnt.Len()
	bnt.isBindRule()
	bnt.Index(0)
	bnt.Valid()
	bnt.IsParen()

	var bands BindRuleAnd
	bands.Valid()
	bands.Push(nil)
	bands.aCIBindRuleSlice.aCIBindRuleSliceString(``)
	bands.Push(bi)
	bands.aCIBindRuleSlice = &aCIBindRuleSlice{slice: []BindRule{bi}, pad: true}
	bands.SetParen(true)
	bands.SetPaddingStyle(0)
	bands.SetPaddingStyle(1)
	bands.aCIBindRuleSlice.aCIBindRuleSliceString(``)
	bands.SetQuotationStyle(0)
	bands.Kind()
	bands.isBindRule()
	bands.Len()
	bands.Index(0)
	bands.Valid()
	bands.IsParen()
	bands.aCIBindRuleSlice.slice = append(bands.aCIBindRuleSlice.slice, BindRuleItem{})
	bands.aCIBindRuleSlice.Valid()

	getAndOrBool([]aCIBindRuleTokenType{brValue})

	var bors BindRuleOr
	bors.Valid()
	bors.Push(nil)
	bors.aCIBindRuleSlice.aCIBindRuleSliceString(``)
	bors.Push(bi)
	bors.aCIBindRuleSlice = &aCIBindRuleSlice{}
	bors.aCIBindRuleSlice.Valid()
	bors.aCIBindRuleSlice = &aCIBindRuleSlice{slice: []BindRule{bi}, pad: true}
	bors.SetParen(true)
	bors.Push(bi)
	bors.SetPaddingStyle(0)
	bors.SetPaddingStyle(1)
	bors.SetQuotationStyle(0)
	bors.Kind()
	bors.isBindRule()
	bors.Len()
	bors.Index(0)
	bors.Valid()
	bors.IsParen()

	var pos int
	processACIv3BindRule([]aCIBindRuleToken{}, &pos)
	parseACIv3BindRuleTokens([]aCIBindRuleToken{
		{Type: brParenClose, Value: ")"},
		{},
	})

	var kw Keyword
	kw = BindUDN
	kw.isACIv3Keyword()
	kw = Target
	kw.isACIv3Keyword()

	assertATBTVBindKeyword(BindGAT)
	matchTKW(nil)
	matchTKW(Target)
	matchBKW(nil)
	matchBKW(BindGAT)
	matchBT(``)

	var lousyCop Operator = Operator(7)
	_ = lousyCop.String()
	_ = lousyCop.Context()
	_ = lousyCop.Description()
	_ = lousyCop.Valid()
	lousyCop.Compare(0)
	lousyCop.Compare(``)
	lousyCop.Compare(rune(3))
	lousyCop.Compare(Eq)

	var brm BindRuleMethods
	brm.Valid()
	brm.Index(0)
	brm.Index(2)
	brm.Index(Eq)
	brm.Len()

	var trm TargetRuleMethods
	trm.Valid()
	trm.Len()
	trm.Index(0)
	trm.Index(2)
	trm.Index(Eq)

	NewWeekdaysBindRule(Eq)
	NewWeekendBindRule(Eq)

	var prm Permission
	prm.aCIPermission = &aCIPermission{}
	prm.Valid()
	prm.Shift(1023)
	_ = prm.String()
	marshalACIv3Permission()
	marshalACIv3Permission(rune(22), true)
	parseACIv3Permission("")
	parseACIv3Permission("allow(read")
	parseACIv3Permission("allow(read]")
	parseACIv3Permission("allow(toys)")
	parseACIv3Permission("allow((((((()))))")
	parseACIv3Permission("allowallow()")
	prm, _ = marshalACIv3Permission("allow(read)")
	prm.aCIPermission.shift([]int{16, 32})
	prm.aCIPermission.unshift([]string{"read", "write"})
	prm.aCIPermission.unshift([]int{16, 32})
	prm.cast().Shift(1023)
	_ = prm.String()
	prm, _ = marshalACIv3Permission("allow(none)")
	_ = prm.String()
	prm.aCIPermission.bool = nil
	prm.Valid()
	var allow bool = true
	prm.aCIPermission.bool = &allow

	_, _ = NewPermissionBindRuleItem()
	_, _ = NewPermissionBindRuleItem(rune(22))
	_, _ = NewPermissionBindRuleItem(prm, BindRuleItem{&aCIBindRuleItem{}})
	_, _ = NewPermissionBindRuleItem(prm, struct{}{})
	_, _ = NewPermissionBindRuleItem(prm, bi)

	var ssf SecurityStrengthFactor
	ssf.Set(256)
	ssf.Set(257)
	ssf.Set(nil)
	ssf.Eq()
	ssf.Ne()
	ssf.Lt()
	ssf.Le()
	ssf.Gt()
	ssf.Ge()
	marshalACIv3SecurityStrengthFactor()

	var am AuthenticationMethod
	am = AuthenticationMethod(77)
	am.Valid()
	_ = am.String()
	am = Anonymous
	am.Valid()
	_ = am.String()
	NewAuthenticationMethod()
	NewAuthenticationMethod(1)

	var dow DayOfWeek
	dow.Shift(Sunday)
	dow.Unshift(Sunday)
	dow.Valid()
	dow = newDoW()
	dow.Valid()
	dow.Shift(Sunday)
	dow.Unshift(Saturday)
	dow.Unshift(7)
	dow.Len()
	dow.Valid()
	dow.BRM().Valid()
	dow.parse("sunday")
	dow.parse("humpday")
	dow.Len()
	dow.Eq()
	dow.Ne()
	dow.Keyword()
	_ = matchDoW("sunday")
	_ = matchDoW(1)
	_ = matchDoW(Sunday)
	_, _ = NewDayOfWeek("sunday,monday")
	_, _ = marshalACIv3DayOfWeek()
	_, _ = marshalACIv3DayOfWeek("mon", "tues", "sun")
	_, _ = marshalACIv3DayOfWeek(Sunday)

	parseACIv3BindRuleExpression([]aCIBindRuleToken{{Type: 7, Value: "?"}})
	parseACIv3BindRuleExpression([]aCIBindRuleToken{
		{Type: brValue, Value: "("},
		{Type: 88, Value: ""},
		{Type: brValue, Value: ")"},
	})
	parseACIv3BindRuleGroup([]aCIBindRuleToken{{Type: 7, Value: "?"}}, &pos)
	parseACIv3BindRuleGroup([]aCIBindRuleToken{
		{Type: brValue, Value: "userdn"},
		{Type: brValue, Value: "="},
		{Type: brParenClose, Value: ")"},
		{Type: brValue, Value: "userdn"},
		{Type: brParenOpen, Value: "("},
		{Type: brParenClose, Value: ")"},
	}, &pos)

	for i := 1; i < 8; i++ {
		matchStrDoW(matchIntDoW(i).String())
	}

	var asc Scope
	asc.Keyword()
	asc = Scope(0)
	_ = asc.String()
	asc = Scope(1)
	_ = asc.String()
	asc = Scope(2)
	_ = asc.String()
	asc = Scope(3)
	_ = asc.String()
	asc = Scope(4)
	_ = asc.String()
	asc.Eq()
	asc.Ne()
	asc.TRM()
	_, _ = marshalACIv3SearchScope()
	_, _ = marshalACIv3SearchScope(2)
	_, _ = marshalACIv3SearchScope(rune(2))
	_ = aCIIntToScope(3)
	_ = aCIIntToScope(4)
	_ = aCIStrToScope("base")
	_ = aCIStrToScope("one")
	_ = aCIStrToScope("subtree")
	_ = aCIStrToScope("subordinate")

	var af AttributeFilter
	af.Valid()
	af.aCIAttributeFilter = &aCIAttributeFilter{Attribute: attr}
	af.Valid()
	af.parse("gecos(objectClass=*)")
	af.parse("gecos:(objectClass=*)")
	af.parse("_:(objectClass=*)")
	af.parse(":(objectClass=*)")

	var fqdn FQDN
	fqdn.aCIFQDNLabels.set()
	fqdn.aCIFQDNLabels.set("__bogus__")
	fqdn.aCIFQDNLabels.set("www.?bogus?.com")
	processLabel("www.???.com")

	var ip IPAddress
	ip.Valid()
	ip.Set("192.168/16")
	ip.aCIIPAddresses.set()
	ip.aCIIPAddresses.set("__bogus__")
	ip.Valid()
	isV4("")
	isV6("")
	isV6("dead::beef")

	af.aCIAttributeFilter.Attribute = Attribute{}
	af.Valid()
	af.aCIAttributeFilter.Attribute = Attribute{&aCIAttribute{slice: []string{"gecos"}}}
	af.Valid()
	af.aCIAttributeFilter.Filter, _ = filter.New("(objectClass=*")
	af.Valid()
	af.parse("gecos:(&(objectClass=top)(employeeStatus=active))")
	af.Keyword()
	af.Kind()
	af.IsZero()
	af.Valid()
	_ = af.String()
	af.aCIAttributeFilter.set("gecos")
	af.aCIAttributeFilter.set("(objectClass=top)")
	_, _ = NewAttributeFilter()
	_, _ = NewAttributeFilter(rune(87))
	_, _ = NewAttributeFilter(rune(87), rune(87))
	_, _ = NewAttributeFilter(rune(87), rune(87), rune(87))
	_, _ = NewAttributeFilter("", rune(87))
	_, _ = NewAttributeFilter("", af.Filter)
	_, _ = NewAttributeFilter(attr, af.aCIAttributeFilter.Filter)
	_, _ = NewAttributeFilter(attr, nil)
	_, _ = NewAttributeFilter("gecos", af.aCIAttributeFilter.Filter)
	_, _ = NewAttributeFilter("gecos", nil)
	_, _ = NewAttributeFilter("gecos:(objectClass=top)")
	_, _ = NewAttributeFilter("gecos", "(objectClass=top)")
	_, _ = NewAttributeFilter(attr, "(objectClass=top)")
	_, _ = marshalACIv3AttributeFilterOperationItem(AddOp, nil)

	_, _ = NewAttributeFilterOperation()

	var afoi AttributeFilterOperationItem
	afoi.Contains("this")
	afoi, _ = NewAttributeFilterOperationItem("add=gecos:(objectClass=*)")
	afoi.Eq()
	afoi.Ne()

	var afo AttributeFilterOperation
	afo.Valid()
	afo, _ = NewAttributeFilterOperation("add=gecos:(objectClass=*);delete=homeDirectory:(employeeStatus=terminated)")
	afo.Eq()
	afo.Ne()
	afo.Valid()
	afo.aCIAttributeFilterOperation.semi = true
	_ = afo.String()
	add := afo.aCIAttributeFilterOperation.add
	del := afo.aCIAttributeFilterOperation.del
	afo, _ = NewAttributeFilterOperation(DelOp, del)
	afo.Len()
	afo, _ = NewAttributeFilterOperation(AddOp, add)
	afo.Len()
	afo.Eq()
	afo.Ne()
	afo.Valid()
	afo.Len()
	_ = afo.String()
	afo.aCIAttributeFilterOperation.add.Eq()
	afo.aCIAttributeFilterOperation.add.Ne()
	afo.aCIAttributeFilterOperation.add.aCIAttributeFilterOperationItem.slice = nil
	afo.aCIAttributeFilterOperation.add.Valid()

	checkACIv3AFOSubstr("add=", "del=")
	checkACIv3AFOSubstr("add=...add=", "add=...,add=")
	checkACIv3AFOSubstr("add=", "add=")
	checkACIv3AFOSubstr("=", "=")
	checkACIv3AFOSubstr("add=", "")

	splitACIv3AttributeFilterOperation("")
	splitACIv3AttributeFilterOperation(";")
	splitACIv3AttributeFilterOperation("..;..")
	splitACIv3AttributeFilterOperation("..,..")
	_, _ = NewAttributeFilterOperation(rune(3))
	_, _ = NewAttributeFilterOperation(rune(3), af)
	_, _ = NewAttributeFilterOperation(AddOp, af)
	_, _ = NewAttributeFilterOperation(AddOp, af, nil)

	marshalACIv3AttributeFilterOperation(DelOp, del)

	marshalACIv3AttributeFilterOperationItem()
	marshalACIv3AttributeFilterOperationItem(nil)
	marshalACIv3AttributeFilterOperationItem(AddOp, af)
	marshalACIv3AttributeFilterOperationItem(DelOp, af)
	marshalACIv3AttributeFilterOperationItem(rune(3), af)
	marshalACIv3AttributeFilterOperationItem(rune(3), rune(3), rune(3))
	marshalACIv3AttributeFilterOperationItem(rune(3), af, rune(3))

	var tod TimeOfDay
	tod.Valid()
	tod.Set("0530")
	tod.BRM()
	tod.Valid()
	tod.Keyword()
	longForm := "Jan 2, 2006 at 3:04pm (MST)"
	thyme, _ := time.Parse(longForm, "Feb 3, 2013 at 7:54pm (PST)")
	assertToD(tod.aCITimeOfDay, thyme)
	NewTimeframeBindRule(tod, tod)
	tod, _ = NewTimeOfDay("0530")
	tod.Eq()
	tod.Ne()
	tod.Gt()
	tod.Ge()
	tod.Lt()
	tod.Le()

	var oidc, oide ObjectIdentifier
	oidc.Contains("1.2.3.4")
	oide.Contains("1.2.3.4")
	oidc, _ = NewLDAPControlOIDs("1.2.3.4")
	oide, _ = NewLDAPExtendedOperationOIDs("1.2.3.4")
	oidc.Contains("1.2.3.4")
	oide.Contains("1.2.3.4")
	oidc.Push("1.2.3.4")
	oide.Push("1.2.3.4")
	oidc.Eq().SetQuotationStyle(0)
	oidc.Ne().SetQuotationStyle(1)
	oide.Eq().SetQuotationStyle(0)
	oide.Ne().SetQuotationStyle(1)
	oide.aCIObjectIdentifier.string(true, true)
	oide.aCIObjectIdentifier.string(false, false)
	oide.aCIObjectIdentifier.string(false, true)
	oide.aCIObjectIdentifier.string(true, false)

	processACIv3TargetRuleItem([]aCITargetRuleToken{
		{},
	})
	processACIv3TargetRuleItem([]aCITargetRuleToken{
		{Type: 0x1},
		{},
		{},
		{},
		{},
	})
	processACIv3TargetRuleItem([]aCITargetRuleToken{
		{Type: trParenOpen},
		{Type: trKeyword},
		{},
		{},
		{},
	})
	processACIv3TargetRuleItem([]aCITargetRuleToken{
		{Type: trParenOpen, Value: "("},
		{Type: trKeyword, Value: "-"},
		{Type: trOperator, Value: "?"},
		{Type: trValue, Value: "..."},
		{Type: trParenClose, Value: ")"},
	})
	processACIv3TargetRuleItem([]aCITargetRuleToken{
		{Type: trParenOpen, Value: "("},
		{Type: trKeyword, Value: "target"},
		{Type: trOperator, Value: "?"},
		{Type: trValue, Value: "..."},
		{Type: trParenClose, Value: ")"},
	})

	var tr TargetRule
	_ = tr.Valid()
	_ = tr.parse(``)
	_ = tr.parse(`(target=`)
	_ = tr.Valid()
	_ = tr.parse(`(target="ldap:///cn=user||ldap:///cn=otheruser")`)
	_ = tr.Index(0).Kind()
	tr.SetQuotationStyle(0)
	tr.SetQuotationStyle(1)
	tr.Valid()
	tr.Len()
	_ = tr.String()

	var atb AttributeBindTypeOrValue
	atb.Valid()
	atb.Set()
	atb.atbtv = new(atbtv)
	_ = atb.atbtv.String()
	atb.atbtv[0] = attr
	atb.atbtv[1] = BindUAT
	_ = atb.atbtv.String()
	var blarg string = "blarg"
	atb.atbtv[1] = AttributeValue{&blarg}
	_ = atb.atbtv.String()
	atb.parse("owner#USERDN", BindGAT)
	_ = atb.atbtv.String()
	atb.Eq()
	atb.Ne()
	atb.BRM()
	atb.BindKeyword = BindGAT
	atb.Keyword()
	atb.BindKeyword = BindUAT
	atb.Keyword()
	marshalACIv3AttributeBindTypeOrValue("owner#USERDN")
	marshalACIv3AttributeBindTypeOrValue("owner", "USERDN")
	marshalACIv3AttributeBindTypeOrValue("owner", "USERDN")
	marshalACIv3AttributeBindTypeOrValue("groupattr", atb)
	marshalACIv3AttributeBindTypeOrValue(atb)
	atb.Keyword()
	atb.Set()
	_ = atb.atbtv.String()
	_, _ = parseATBTV("_#GROUPBLARG", BindGDN)

	var tri TargetRuleItem
	_ = tri.String()
	tri.SetKeyword("nothing")
	tri.SetOperator(".")
	tri.SetExpression("nothing")
	tri.Valid()
	tri.IsZero()
	tri.Kind()
	tri.SetQuotationStyle(0)
	tri.SetQuotationStyle(1)
	tr.Push(tri)
	tr.aCITargetRule = &aCITargetRule{}
	tr.aCITargetRule.slice = append(tr.aCITargetRule.slice, TargetRuleItem{&aCITargetRuleItem{}})
	tr.Valid()
	tr.SetQuotationStyle(0)
	tr.SetQuotationStyle(1)
	newACIv3TargetRuleMethods(nil)
	NewTargetRuleItem(TargetScope, rune(22))
	NewTargetRuleItem(TargetKeyword(0x0), rune(22))
	NewTargetRuleItem(TargetKeyword(0x1), rune(22), rune(22))

	tri, _ = NewTargetRuleItem(rune(0), rune(0), nil)
	tri, _ = NewTargetRuleItem(Target, Eq, "bogus")
	_ = tri.String()
	tri, _ = NewTargetRuleItem(Target, Eq, "ldap:///cn=Manager")
	_ = tri.String()
	tri.aCITargetRuleItem.pad = true
	_ = tri.String()

	var bdn BindDistinguishedName = BindDistinguishedName{BindUDN, &aCIDistinguishedName{slice: []string{"ldap:///all"}}}
	bdn.Len()
	bdn.Contains("nothing")
	bdn.Eq()
	bdn.Ne()
	bdn.Push("nothing")
	bdn.Index(0)

	var adn aCIDistinguishedName
	adn.contains(struct{}{})

	_, _ = parseATBTV("#")
	_ = isAttributeDescriptor(`abc-`)
	_ = isAttributeDescriptor(`-abc`)
	_ = isAttributeDescriptor(`a--bc`)
	_ = isAttributeDescriptor(`ab?c`)

	var aoid aCIObjectIdentifier
	aoid.contains(struct{}{})

	_ = strInSlice([]string{`this`}, []string{`that`})
	_ = strInSlice([]string{`this`}, []string{`that`}, true)
	_ = streq(`a`, `A`)

	num := 3
	_ = bitSize(nil)
	_ = bitSize(&num)

	_ = isObjectIdentifier(`blarg`)
	_ = isObjectIdentifier(`3.1.1`)
	_ = isObjectIdentifier(`1.023`)
	_ = isObjectIdentifier(`1.f.2`)
	_ = isObjectIdentifier(`1...2`)
	_ = isObjectIdentifier(`1.-2`)
	_ = isObjectIdentifier(`-1.3.6`)
	_ = isObjectIdentifier(`1.3.-6`)
	_ = isObjectIdentifier(`1.3.6.-6`)
	_ = isObjectIdentifier(`1.3.6.06`)
	_ = isObjectIdentifier(`1.3.6.A`)

	_ = isValidArc(`-3`)
	_ = isValidArc(`06`)
	_ = isValidArc(`6Y8`)

	bdn.aCIDistinguishedName.string(true, false)
	bdn.aCIDistinguishedName.string(false, true)
	bdn.aCIDistinguishedName.string(false, false)
	bdn.aCIDistinguishedName.string(true, true)
	bdn.aCIDistinguishedName.contains("ldap:///all")

	var tdn TargetDistinguishedName = TargetDistinguishedName{Target, &aCIDistinguishedName{slice: []string{"ldap:///all"}}}
	tdn.Len()
	tdn.Contains("nothing")
	tdn.Eq()
	tdn.Ne()
	tdn.Push("nothing")
	tdn.Index(0)

	trm = attr.TRM()
	trm.Valid()
	trm.Len()
	trm.Index("=")
	trm.Index(1)
	trm.Index(1111)
	trm.Index(Eq)

	_, _ = tokenizeACIv3TargetRule(`=!?`)
	_, _ = tokenizeACIv3TargetRule(`!?`)
	_, _ = tokenizeACIv3TargetRule(`!=`)
	_, _, _ = tokenizeACIv3TargetRuleMultival(-1, -1, ``, []aCITargetRuleToken{})
	_, _, _ = tokenizeACIv3TargetRuleKeyword(0x0, -1, -1, ``, []aCITargetRuleToken{})
	_, _, _ = tokenizeTargetRuleQuotedValue(1, 1, `"things"`, []aCITargetRuleToken{})
	_, _, _ = tokenizeTargetRuleQuotedValue(1, 1, `"thi\"ngs\" are cool"`, []aCITargetRuleToken{})
	_, _ = assertTargetValueByKeyword(Target)
	_, _ = assertTargetValueByKeyword(TargetKeyword(99), "")
	_, _ = assertTargetValueByKeyword(TargetAttr, "owner#USERDN")
	_, _ = assertTargetValueByKeyword(TargetAttr, Attribute{&aCIAttribute{all: true}})
	_, _ = assertTargetValueByKeyword(TargetAttr, AttributeBindTypeOrValue{BindUDN, &atbtv{}})
	_, _ = assertTargetValueByKeyword(TargetAttrFilters, "blarg")

	marshalACIv3BindDistinguishedName(Target)
	marshalACIv3TargetDistinguishedName(BindUDN)

	keywordAllowsACIv3Operator(`userdn`, ">=")
	keywordAllowsACIv3Operator(`target`, ">=")
	keywordAllowsACIv3Operator(BindUAT, ">=")
	keywordAllowsACIv3Operator(BindUAT, rune(33))
	keywordAllowsACIv3Operator(rune(33), "")

	// test permutations of keywords and cops

	permutations := map[string]map[Keyword][]any{
		`valid`: {
			// target keywords
			Target:            {`eq`, `ne`, Eq, Ne, 1, 2},
			TargetTo:          {`eq`, `ne`},
			TargetFrom:        {`eq`, `ne`},
			TargetCtrl:        {`eq`, `ne`},
			TargetAttr:        {`eq`, `ne`},
			TargetFilter:      {`eq`, `ne`, Ne, 2},
			TargetExtOp:       {`eq`, `ne`},
			TargetScope:       {`eq`},
			TargetAttrFilters: {`eq`, 1, Eq},

			// bind keywords
			BindUDN: {`eq`, `ne`, Eq, "equal to", `EQ`},
			BindGDN: {`eq`, Ne, `not equal to`, `NE`, `ne`},
			BindRDN: {`eq`, `ne`},
			BindDNS: {`eq`, `ne`},
			BindUAT: {`eq`, `ne`},
			BindGAT: {`eq`, `ne`},
			BindDoW: {`eq`, `ne`},
			BindIP:  {`eq`, `ne`},
			BindAM:  {`eq`, `ne`},
			BindToD: {`eq`, 4, `ne`, Le, `LE`, 6, `le`, Lt, `LT`, `lt`, 3, Ge, `GE`, `ge`, Gt, `GT`, `gt`},
			BindSSF: {`eq`, 1, `ne`, Le, `LE`, 5, `le`, Lt, `LT`, 2, `lt`, Ge, `GE`, `ge`, Gt, `GT`, `gt`},
		},
	}

	for typ, kwmap := range permutations {
		for kw, values := range kwmap {
			for i := 0; i < len(values); i++ {
				op := values[i]
				if !keywordAllowsACIv3Operator(kw, op) {
					t.Errorf("%s [%s] failed: %s %T [%v] denied or not resolved",
						t.Name(), kw, typ, invalidCop, op)
					return
				}
			}
		}
	}
}

var bogusKeywords []string = []string{
	`bagels`,
	`63`,
	`a^574384`,
	``,
	`userdnssf`,
}

func TestKeyword_bogusMatches(t *testing.T) {
	for _, bogus := range bogusKeywords {
		if bt := matchBT(bogus); bt != BindType(0x0) {
			t.Errorf("%s failed: '%s' matched bogus %T",
				t.Name(), bogus, bt)
			return
		}

		if tk := matchTKW(bogus); tk != TargetKeyword(0x0) {
			t.Errorf("%s failed: '%s' matched bogus %T",
				t.Name(), bogus, tk)
			return
		}

		if bk := matchBKW(bogus); bk != BindKeyword(0x0) {
			t.Errorf("%s failed: '%s' matched bogus %T",
				t.Name(), bogus, bk)
			return
		}
	}
}

// Let's print out each BindType constant
// defined in this package.
func ExampleBindType() {
	for idx, bt := range []BindType{
		BindTypeUSERDN,
		BindTypeGROUPDN,
		BindTypeROLEDN,
		BindTypeSELFDN,
		BindTypeLDAPURL,
	} {
		fmt.Printf("%T %d/%d: %s\n",
			bt, idx+1, 5, bt)
	}
	// Output:
	// aci.BindType 1/5: USERDN
	// aci.BindType 2/5: GROUPDN
	// aci.BindType 3/5: ROLEDN
	// aci.BindType 4/5: SELFDN
	// aci.BindType 5/5: LDAPURL
}

/*
This example demonstrates the interrogation of BindKeyword const
definitions. This type qualifies for the Keyword interface type.

There are a total of eleven (11) such BindKeyword definitions.
*/
func ExampleBindKeyword() {
	for idx, bk := range []BindKeyword{
		BindUDN,
		BindRDN,
		BindGDN,
		BindUAT,
		BindGAT,
		BindIP,
		BindDNS,
		BindDoW,
		BindToD,
		BindAM,
		BindSSF,
	} {
		fmt.Printf("[%s] %02d/%d: %s\n",
			bk.Kind(), idx+1, 11, bk)
	}
	// Output:
	// [bindRule] 01/11: userdn
	// [bindRule] 02/11: roledn
	// [bindRule] 03/11: groupdn
	// [bindRule] 04/11: userattr
	// [bindRule] 05/11: groupattr
	// [bindRule] 06/11: ip
	// [bindRule] 07/11: dns
	// [bindRule] 08/11: dayofweek
	// [bindRule] 09/11: timeofday
	// [bindRule] 10/11: authmethod
	// [bindRule] 11/11: ssf
}

/*
This example demonstrates the interrogation of TargetKeyword const
definitions. This type qualifies for the Keyword interface type.

There are a total of nine (9) such TargetKeyword definitions.
*/
func ExampleTargetKeyword() {
	for idx, tk := range []TargetKeyword{
		Target,
		TargetTo,
		TargetAttr,
		TargetCtrl,
		TargetFrom,
		TargetScope,
		TargetFilter,
		TargetAttrFilters,
		TargetExtOp,
	} {
		fmt.Printf("[%s] %d/%d: %s\n",
			tk.Kind(), idx+1, 9, tk)
	}
	// Output:
	// [targetRule] 1/9: target
	// [targetRule] 2/9: target_to
	// [targetRule] 3/9: targetattr
	// [targetRule] 4/9: targetcontrol
	// [targetRule] 5/9: target_from
	// [targetRule] 6/9: targetscope
	// [targetRule] 7/9: targetfilter
	// [targetRule] 8/9: targattrfilters
	// [targetRule] 9/9: extop
}

/*
This example demonstrates the interrogation of qualifiers of
the Keyword interface type (BindKeyword and TargetKeyword
const definitions).

There are a total of twenty (20) qualifying instances (spanning
two (2) distinct types) of this interface.
*/
func ExampleKeyword() {
	for idx, k := range []Keyword{
		BindUDN,
		BindRDN,
		BindGDN,
		BindUAT,
		BindGAT,
		BindIP,
		BindDNS,
		BindDoW,
		BindToD,
		BindAM,
		BindSSF,
		Target,
		TargetTo,
		TargetAttr,
		TargetCtrl,
		TargetFrom,
		TargetScope,
		TargetFilter,
		TargetAttrFilters,
		TargetExtOp,
	} {
		fmt.Printf("[%s] %02d/%d: %s\n",
			k.Kind(), idx+1, 20, k)
	}
	// Output:
	// [bindRule] 01/20: userdn
	// [bindRule] 02/20: roledn
	// [bindRule] 03/20: groupdn
	// [bindRule] 04/20: userattr
	// [bindRule] 05/20: groupattr
	// [bindRule] 06/20: ip
	// [bindRule] 07/20: dns
	// [bindRule] 08/20: dayofweek
	// [bindRule] 09/20: timeofday
	// [bindRule] 10/20: authmethod
	// [bindRule] 11/20: ssf
	// [targetRule] 12/20: target
	// [targetRule] 13/20: target_to
	// [targetRule] 14/20: targetattr
	// [targetRule] 15/20: targetcontrol
	// [targetRule] 16/20: target_from
	// [targetRule] 17/20: targetscope
	// [targetRule] 18/20: targetfilter
	// [targetRule] 19/20: targattrfilters
	// [targetRule] 20/20: extop
}

func ExampleBindKeyword_String() {
	fmt.Printf("%s", BindUDN)
	// Output: userdn
}

func ExampleBindKeyword_Kind() {
	fmt.Printf("%s", BindUDN.Kind())
	// Output: bindRule
}

func ExampleTargetKeyword_String() {
	fmt.Printf("%s", TargetScope)
	// Output: targetscope
}

func ExampleTargetKeyword_Kind() {
	fmt.Printf("%s", TargetAttrFilters.Kind())
	// Output: targetRule
}

func ExampleInheritanceLevel_String() {
	fmt.Printf("%s", Level8)
	// Output: 8
}

func ExampleInheritance_BRM() {

	attr, err := NewAttribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	abtv, err := NewAttributeBindTypeOrValue("userattr", attr, "uid=frank,ou=People,dc=example,dc=com")
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh Inheritance
	inh, err = NewInheritance(abtv, 1, 3)
	if err != nil {
		fmt.Println(err)
		return
	}

	brm := inh.BRM()
	fmt.Printf("%d available comparison operator methods", brm.Len())
	// Output: 2 available comparison operator methods
}

func ExampleInheritance_String() {

	attr, err := NewAttribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var uat AttributeBindTypeOrValue
	uat, err = NewAttributeBindTypeOrValue("userattr", attr, `uid=frank,ou=People,dc=example,dc=com`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh Inheritance
	if inh, err = NewInheritance(uat, Level6, Level7); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", inh)
	// Output: parent[6,7].manager#uid=frank,ou=People,dc=example,dc=com
}

func ExampleInheritance_Valid() {
	var inh Inheritance
	fmt.Printf("%T.Valid: %t", inh, inh.Valid() == nil)
	// Output: aci.Inheritance.Valid: false
}

func ExampleInheritance_Eq() {

	attr, err := NewAttribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var uat AttributeBindTypeOrValue
	uat, err = NewAttributeBindTypeOrValue("userattr", attr, `uid=frank,ou=People,dc=example,dc=com`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh Inheritance
	if inh, err = NewInheritance(uat, Level6, Level7); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", inh.Eq())
	// Output: userattr="parent[6,7].manager#uid=frank,ou=People,dc=example,dc=com"
}

func ExampleInheritance_Ne() {

	attr, err := NewAttribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var uat AttributeBindTypeOrValue
	uat, err = NewAttributeBindTypeOrValue(BindUAT, attr, `uid=frank,ou=People,dc=example,dc=com`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh Inheritance
	if inh, err = NewInheritance(uat, Level1, Level3); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", inh.Ne())
	// Output: userattr!="parent[1,3].manager#uid=frank,ou=People,dc=example,dc=com"
}

func ExampleInheritance_IsZero() {
	var inh Inheritance
	fmt.Printf("%t", inh.IsZero())
	// Output: true
}

func ExampleInheritance_Len() {

	attr, err := NewAttribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var uat AttributeBindTypeOrValue
	uat, err = NewAttributeBindTypeOrValue("userattr", attr, BindTypeUSERDN)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh Inheritance
	if inh, err = NewInheritance(uat, Level6, Level7); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Number of levels: %d", inh.Len())
	// Output: Number of levels: 2
}

func ExampleInheritance_Positive() {

	attr, err := NewAttribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var uat AttributeBindTypeOrValue
	uat, err = NewAttributeBindTypeOrValue(BindUAT, attr, BindTypeUSERDN)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh Inheritance
	if inh, err = NewInheritance(uat, Level6, Level7); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Level 5 positive? %t", inh.Positive(5))
	// Output: Level 5 positive? false
}

func ExampleInheritance_Shift() {

	attr, err := NewAttribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	value := `uid=frank,ou=People,dc=example,dc=com`

	var abtv AttributeBindTypeOrValue
	abtv, err = NewAttributeBindTypeOrValue("groupattr", attr, value)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh Inheritance
	if inh, err = NewInheritance(abtv, 1, 3); err != nil {
		fmt.Println(err)
		return
	}

	inh.Unshift(1)      // we changed our mind; remove level "1"
	inh.Unshift(`1`)    // (or, alternatively ...)
	inh.Unshift(Level1) // (or, alternatively ...)
	inh.Shift(8)        // add the one we forgot

	fmt.Printf("Number of levels: %d", inh.Len())
	// Output: Number of levels: 2
}

func ExampleInheritance_Unshift() {

	attr, err := NewAttribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	value := `uid=frank,ou=People,dc=example,dc=com`

	var abtv AttributeBindTypeOrValue
	abtv, err = NewAttributeBindTypeOrValue("groupattr", attr, value)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh Inheritance
	if inh, err = NewInheritance(abtv, 1, 3, 8); err != nil {
		fmt.Println(err)
		return
	}

	inh.Unshift(1)      // we changed our mind; remove level "1"
	inh.Unshift(`1`)    // (or, alternatively ...)
	inh.Unshift(Level1) // (or, alternatively ...)

	fmt.Printf("Number of levels: %d", inh.Len())
	// Output: Number of levels: 2
}

func ExampleInheritance_Keyword() {

	attr, err := NewAttribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var uat AttributeBindTypeOrValue
	uat, err = NewAttributeBindTypeOrValue("userattr", attr, BindTypeUSERDN)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh Inheritance
	if inh, err = NewInheritance(uat, Level6, Level7); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Keyword: %s", inh.Keyword())
	// Output: Keyword: userattr
}

func ExampleInheritance_Positive_byString() {

	attr, err := NewAttribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var gat AttributeBindTypeOrValue
	gat, err = NewAttributeBindTypeOrValue("userattr", attr, BindTypeGROUPDN)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh Inheritance
	if inh, err = NewInheritance(gat, Level6, Level7); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Level 6 positive? %t", inh.Positive(`6`))
	// Output: Level 6 positive? true
}

func TestInheritance(t *testing.T) {

	attr, err := NewAttribute(`manager`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	var uat AttributeBindTypeOrValue
	uat, err = NewAttributeBindTypeOrValue(BindUAT, attr, "USERDN")
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	var inh Inheritance
	if inh, err = NewInheritance(uat, Level0, Level1, Level2, Level8); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	got := inh.Eq()
	want := `userattr="parent[0,1,2,8].manager#USERDN"`
	if want != got.String() {
		t.Errorf("%s failed: want '%s', got '%s'", t.Name(), want, got)
	}
}

func ExampleInheritance_uSERDN() {

	attr, err := NewAttribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var uat AttributeBindTypeOrValue
	uat, err = NewAttributeBindTypeOrValue(BindUAT, attr, BindTypeUSERDN)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh Inheritance
	if inh, err = NewInheritance(uat, 0, 1, 2, 8); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", inh.Eq())
	// Output: userattr="parent[0,1,2,8].manager#USERDN"
}

func ExampleInheritance_uAT() {

	attr, err := NewAttribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	value := `uid=frank,ou=People,dc=example,dc=com`

	var uat AttributeBindTypeOrValue
	uat, err = NewAttributeBindTypeOrValue("userattr", attr, value)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh Inheritance
	if inh, err = NewInheritance(uat, 3, 4); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", inh.Eq())
	// Output: userattr="parent[3,4].manager#uid=frank,ou=People,dc=example,dc=com"
}

func ExampleInheritance_groupAttr() {

	attr, err := NewAttribute(`owner`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var gat AttributeBindTypeOrValue
	gat, err = NewAttributeBindTypeOrValue("groupattr", attr, BindTypeUSERDN)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh Inheritance
	if inh, err = NewInheritance(gat, 3, 4); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", inh.Eq())
	// Output: groupattr="parent[3,4].owner#USERDN"
}

func TestLevels_bogus(t *testing.T) {
	var inh Inheritance
	if err := inh.Valid(); err == nil {
		t.Errorf("%s failed: invalid %T returned no validity error",
			t.Name(), inh)
		return
	}

	if inh.String() != badACIv3InhStr {
		t.Errorf("%s failed: invalid %T returned no bogus inheritance warning",
			t.Name(), inh)
		return
	}

	if inh.Eq() != badACIv3BindRule {
		t.Errorf("%s failed: invalid %T returned unexpected %T instance during equality bindrule creation",
			t.Name(), inh, badACIv3BindRule)
		return
	}

	if inh.Ne() != badACIv3BindRule {
		t.Errorf("%s failed: invalid %T returned unexpected %T instance during negated equality bindrule creation",
			t.Name(), inh, badACIv3BindRule)
		return
	}

	if !inh.IsZero() {
		t.Errorf("%s failed: bogus %T is non-zero",
			t.Name(), inh)
		return
	}

	for idx, rawng := range []string{
		`100.manager#USERDN`,
		`parent[100].manager#USERDN`,
		`parent[].manager#SELFDN`,
		`parent[4]#ROLEDN`,
		`parent[-1,20,3,476,5,666,7,666,9]?manager#LDAPURI`,
		`parent[0]].owner#GROUPDN`,
		`Parent[1,3,5,7)owner]#LDAPURI`,
		`parent[1,3,5,7)owner#LDAPURI`,
		`parent[1,2,3,4].squatcobbler`,
		``,
	} {
		var inh Inheritance
		err := inh.parse(rawng)
		if err == nil {
			t.Errorf("%s failed [idx:%d]: parsing of bogus %T definition returned no error (%s)",
				t.Name(), idx, inh, rawng)
			return

		}

		if inh.String() != badACIv3InhStr {
			t.Errorf("%s failed [idx:%d]: %T parsing attempt failed; want '%s', got '%s'",
				t.Name(), idx, inh, badACIv3Inheritance, inh)
			return
		}
	}
}

func TestInheritance_parse(t *testing.T) {
	for idx, raw := range []string{
		`parent[0,5,9].manager#USERDN`,
		`parent[1].manager#SELFDN`,
		`parent[4].terminated#ROLEDN`,
		`parent[0,1,2,3,4,5,6,7,8,9].manager#LDAPURI`,
		`parent[0].owner#GROUPDN`,
	} {
		var inh Inheritance
		err := inh.parse(raw)
		if err != nil {
			t.Errorf("%s[%d] failed: %T parsing attempt failed; %v",
				t.Name(), idx, inh, err)
			return

		}

		if raw != inh.String() {
			t.Errorf("%s[%d] failed: %T parsing attempt failed; want '%s', got '%s'",
				t.Name(), idx, inh, raw, inh)
			return
		}

		want := fmt.Sprintf("(userattr=%q)", raw)
		equality := inh.Eq().SetParen(true)

		if got := equality.String(); want != got {
			t.Errorf("%s[%d] failed: %T equality creation error; want '%s', got '%s'",
				t.Name(), idx, inh, want, got)
			return
		}

		negation := inh.Ne().SetParen(true)
		want = fmt.Sprintf("(userattr!=%q)", raw)
		if got := negation.String(); want != got {
			t.Errorf("%s[%d] failed: %T negated equality creation error; want '%s', got '%s'",
				t.Name(), idx, inh, want, got)
			return
		}
	}
}

func TestInheritance_codecov(t *testing.T) {
	var inh Inheritance
	_ = inh.Positive(`4`)
	_ = inh.Keyword()
	_ = inh.String()
	_ = inh.Shift(1370)
	_ = inh.Shift(`farts`)
	_ = inh.Shift(-100)
	_ = inh.Shift(3.14159)
	_ = inh.Unshift(1370)
	_ = inh.Unshift(`farts`)
	_ = inh.Unshift(-100)
	_ = inh.Unshift(3.14159)
	_ = inh.Positive(`fart`)
	_ = inh.Positive(100000)
	_ = inh.Positive(-1)
	_ = inh.Positive(4)
	_ = inh.Positive("something awful")
	_ = inh.Positive(InheritanceLevel(^uint16(0)))
	_ = inh.Positive(3.14159)
	_, _ = marshalACIv3Inheritance()
	_, _ = marshalACIv3Inheritance(rune(22))
	_, _ = marshalACIv3Inheritance(rune(22))
	_, _ = marshalACIv3Inheritance(Inheritance{})
	inh, _ = marshalACIv3Inheritance("parent[0,8].owner#USERDN")
	_, _ = marshalACIv3Inheritance(inh)
	_, _ = marshalACIv3Inheritance("owner#USERDN", 1, 2, 3)
	_, _ = marshalACIv3Inheritance(rune(22), 1, 2, 3)
	inh.Shift(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
	inh.cast().Shift(13782)
	inh.Valid()
}

func TestFQDN(t *testing.T) {
	f, err := NewFQDN()
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	_ = f.Len()
	_ = f.Keyword()
	_ = f.Eq()
	_ = f.Ne()
	_ = f.Valid()
	var typ string = f.Keyword().String()

	if f.len() != 0 {
		t.Errorf("%s failed: unexpected %T length: want '%d', got '%d'",
			t.Name(), f, 0, f.len())
		return
	}

	if err := f.Valid(); err == nil {
		t.Errorf("%s failed: empty %T deemed valid", t.Name(), f)
		return
	}

	f.Set()
	f.Set(``)
	f.Set(`-www-`, `-example`, `com-`)
	f.Set(`www`, `example`, `com`)

	want := `www.example.com`
	got := f.String()

	if want != got {
		t.Errorf("%s failed; want '%s', got '%s'", t.Name(), want, got)
		return
	}

	absurd := `eeeeeeeeeeeeeeeeeeeeeeeee#eee^eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeexample`

	if validLabel(absurd) {
		t.Errorf("%s failed: bogus %T label accepted as valid (%s)",
			t.Name(), absurd, absurd)
		return
	}

	var F FQDN
	if F.String() != badACIv3FQDNStr {
		t.Errorf("%s failed: unexpected string result; want '%s', got '%s'",
			t.Name(), badACIv3FQDN, F)
		return
	}

	F.Set(`www`).Set(`$&^#*(`).Set(absurd).Set(`example`).Set(``).Set(`com`)
	if llen := F.Len(); llen != 3 {
		t.Errorf("%s failed; want '%d', got '%d'", t.Name(), 3, llen)
		return
	}

	// try every comparison operator supported in
	// this context ...
	brm := F.BRM()
	for i := 0; i < brm.Len(); i++ {
		cop, meth := brm.Index(i + 1)
		wcop := fmt.Sprintf("(%s%s\"www.example.com\")", f.Keyword(), cop)
		if T := meth(); T.SetParen(true).String() != wcop {
			t.Errorf("%s [%s] multival failed [%s rule]; %s, %s",
				t.Name(), F.Keyword(), cop.Context(), cop.Description(), typ)
			return
		}
	}
}

func TestDNS_alternativeFQDN(t *testing.T) {
	want := `www.example.com`
	f, _ := NewFQDN(want)
	if got := f.String(); got != want {
		t.Errorf("%s failed; want '%s', got '%s'", t.Name(), want, got)
		return
	}
}

func TestIPAddress_BRM(t *testing.T) {
	var i IPAddress
	_ = i.Len()
	_ = i.Eq()
	_ = i.Ne()
	_ = i.Valid()
	_ = i.Keyword()

	if !i.IsZero() {
		t.Errorf("%s failed: non-zero %T instance", t.Name(), i)
		return
	}

	if got := i.String(); got != badACIv3IPAddrStr {
		t.Errorf("%s failed: unexpected string result; want '%s', got '%s'",
			t.Name(), badACIv3IPAddrStr, got)
		return
	}

	var typ string = i.Keyword().String()

	if !i.unique(`192.168.0`) {
		t.Errorf("%s failed; uniqueness check returned bogus result",
			t.Name())
		return
	}
	i.Set(`192.168.0`)
	i.Set(`12.3.45.*`)
	i.Set(`12.3.45.*`) // duplicate
	i.Set(`10.0.0.0/8`)
	i.Valid()
	i.unique(`10.0.0.0/8`)

	if lens := i.Len(); lens != 3 {
		t.Errorf("%s failed: bad %T length; want '%d', got '%d'", t.Name(), i, 3, lens)
		return
	}

	if cond := i.Ne(); cond.IsZero() {
		t.Errorf("%s failed: nil %T instance!", t.Name(), cond)
		return
	}

	// try every comparison operator supported in
	// this context ...
	brm := i.BRM()
	for j := 0; j < brm.Len(); j++ {
		cop, meth := brm.Index(j + 1)
		if meth == nil {
			t.Errorf("%s [%s] multival failed: expected %s method (%T), got nil",
				t.Name(), i.Keyword(), cop.Context(), meth)
			return
		}

		wcop := fmt.Sprintf("(%s%s%q)", i.Keyword(), cop, i)
		if T := meth(); T.SetParen(true).String() != wcop {
			t.Errorf("%s [%s] multival failed [%s rule]",
				t.Name(), i.Keyword(), typ)
			return
		}
	}
}

func ExampleFQDN_Eq() {

	f, _ := NewFQDN() // no need to check error w/o arguments.

	// Let's set the host labels incrementally ...
	f.Set(`www`)
	f.Set(`example`)
	f.Set(`com`)

	fmt.Printf("%s", f.Eq())
	// Output: dns="www.example.com"
}

func ExampleFQDN_Ne() {

	f, err := NewFQDN(`www.example.com`)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", f.Ne().SetPaddingStyle(1))
	// Output: dns != "www.example.com"
}

func ExampleIPAddress_Set() {

	i, _ := NewIPAddress() // no need to check error w/o arguments.

	i.Set(`192.168.0`).Set(`12.3.45.*`).Set(`10.0.0.0/8`)
	neg := i.Ne().SetParen(true).SetPaddingStyle(1)
	fmt.Printf("%s", neg)
	// Output: ( ip != "192.168.0,12.3.45.*,10.0.0.0/8" )
}

func ExampleIPAddress_Eq_oneShot() {

	i, _ := NewIPAddress()
	fmt.Printf("%s", i.Set(`192.168.0`, `12.3.45.*`, `10.0.0.0/8`).Eq())
	// Output: ip="192.168.0,12.3.45.*,10.0.0.0/8"
}

/*
This example demonstrates the creation of an instance of IPAddress, which
is used in a variety of contexts.

In this example, a string name is fed to the package level IP function to form
a complete IPAddress instance, which is then shown in string representation.
*/
func ExampleIPAddress() {
	ip, err := NewIPAddress(`10.0.0.1`)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", ip)
	// Output: 10.0.0.1
}

/*
This example demonstrates the string representation of the receiver instance.
*/
func ExampleIPAddress_String() {
	ip, err := NewIPAddress(`192.168.56.7`)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s", ip)
	// Output: 192.168.56.7
}

func ExampleIPAddress_Keyword() {
	var ip IPAddress
	fmt.Printf("%v", ip.Keyword())
	// Output: ip
}

func ExampleIPAddress_Kind() {
	var ip IPAddress
	fmt.Printf("%v", ip.Kind())
	// Output: ip
}

func ExampleIPAddress_Len() {
	ip, err := NewIPAddress(`10.8.`)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%d", ip.Len())
	// Output: 1
}

/*
This example demonstrates a check of the receiver for "nilness".
*/
func ExampleIPAddress_IsZero() {
	ip, err := NewIPAddress(`10.8.`, `192.`)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%t", ip.IsZero())
	// Output: false
}

/*
This example demonstrates a check of the receiver for an aberrant state.
*/
func ExampleIPAddress_Valid() {
	var ip IPAddress
	fmt.Printf("Valid: %t", ip.Valid() == nil)
	// Output: Valid: false
}

func ExampleIPAddress_Eq() {

	i, err := NewIPAddress("192.8.", "10.7.0")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", i.Eq())
	// Output: ip="192.8.,10.7.0"
}

func ExampleIPAddress_Ne() {

	i, err := NewIPAddress("10.8.")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", i.Ne())
	// Output: ip!="10.8."
}

func ExampleFQDN_Set() {
	f, err := NewFQDN("*.example.com")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", f)
	// Output: *.example.com
}

func ExampleFQDN_Eq_oneShot() {
	f, err := NewFQDN("www.example.com")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s", f.Eq())
	// Output: dns="www.example.com"
}

/*
This example demonstrates the string representation of the receiver instance.
*/
func ExampleFQDN_String() {
	f, err := NewFQDN("example.com")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", f)
	// Output: example.com
}

func ExampleFQDN_Keyword() {
	var f FQDN
	fmt.Printf("%v", f.Keyword())
	// Output: dns
}

/*
This example demonstrates a check of the receiver for "nilness".
*/
func ExampleFQDN_IsZero() {
	f, err := NewFQDN("www.example.com")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%t", f.IsZero())
	// Output: false
}

/*
This example demonstrates a check of the receiver for an aberrant state.
*/
func ExampleFQDN_Valid() {
	var f FQDN
	fmt.Printf("Valid: %t", f.Valid() == nil)
	// Output: Valid: false
}

func ExampleFQDN_BRM() {
	f, err := NewFQDN("www.example.com")
	if err != nil {
		fmt.Println(err)
		return
	}
	cops := f.BRM()
	fmt.Printf("%T allows Eq: %t", f, cops.Contains(`=`))
	// Output: aci.FQDN allows Eq: true
}

func ExampleFQDN_Len() {
	f, err := NewFQDN("www.example.com")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%T contains %d DNS labels", f, f.Len())
	// Output: aci.FQDN contains 3 DNS labels
}

func ExampleIPAddress_BRM() {
	ip, err := NewIPAddress("www.example.com")
	if err != nil {
		fmt.Println(err)
		return
	}
	cops := ip.BRM()
	fmt.Printf("%T allows Eq: %t", ip, cops.Contains(`=`))
	// Output: aci.IPAddress allows Eq: true
}

func TestSecurityStrengthFactor(t *testing.T) {
	var (
		factor SecurityStrengthFactor
		typ    string = BindSSF.String()
	)

	for i := 0; i < 257; i++ {
		want := strconv.Itoa(i) // what we expect (string representation)

		var err error
		factor, err = NewSecurityStrengthFactor(i)
		if err != nil {
			t.Errorf("%s failed [%s int]: %v",
				t.Name(), typ, err)
			return
		}
		if want != factor.String() {
			t.Errorf("%s failed [%s int]; want %s, got %s",
				t.Name(), typ, want, factor.String())
			return
		}

		// reset using string representation of iterated integer
		if got := factor.Set(want); want != got.String() {
			t.Errorf("%s failed [%s str]",
				t.Name(), typ)
			return
		}

		brm := factor.BRM()
		for c := 0; c < brm.Len(); c++ {
			cop, meth := brm.Index(c + 1)
			wcop := fmt.Sprintf("%s%s%q", factor.Keyword(), cop, factor.String())

			// create bindrule B using comparison
			// operator (cop).
			if B := meth(); B.String() != wcop {
				t.Errorf("%s failed [%s rule]", t.Name(), typ)
				return
			}
		}
		factor.clear() // codecov

	}

	// try to set our factor using special keywords
	// this package understands ...
	for word, value := range map[string]string{
		`mAx`:  `256`,
		`full`: `256`,
		`nOnE`: `0`,
		`OFF`:  `0`,
		`fart`: `0`,
	} {
		factor, _ = NewSecurityStrengthFactor(value)
		if got := factor.Set(word); got.String() != value {
			t.Errorf("%s failed [factor word '%s']", t.Name(), word)
			return
		}
	}
}

func TestACIv3AuthenticationMethod(t *testing.T) {
	// codecov
	_ = noAuth.Eq()
	_ = noAuth.Ne()

	AuthenticationMethodLowerCase = true

	for idx, auth := range authMap {
		if _, err := marshalACIv3AuthenticationMethod(auth); err != nil {
			t.Errorf("%s[%d] failed: unable to match auth method '%s'",
				t.Name(), idx, auth)
			return
		} else if _, err = marshalACIv3AuthenticationMethod(auth.String()); err != nil {
			t.Errorf("%s[%d] failed: unable to match auth method by string (%s)",
				t.Name(), idx, auth.String())
			return
		}
	}

	AuthenticationMethodLowerCase = false
}

func ExampleSecurityStrengthFactor_Eq() {
	ssf, err := NewSecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", ssf.Set(128).Ne().SetParen(true))
	// Output: (ssf!="128")
}

func ExampleSecurityStrengthFactor_Ne() {
	ssf, err := NewSecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", ssf.Set(128).Ne().SetParen(true))
	// Output: (ssf!="128")
}

func ExampleSecurityStrengthFactor_Lt() {
	ssf, err := NewSecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", ssf.Set(128).Lt())
	// Output: ssf<"128"
}

func ExampleSecurityStrengthFactor_Le() {
	ssf, err := NewSecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", ssf.Set(128).Le().SetParen(true))
	// Output: (ssf<="128")
}

func ExampleSecurityStrengthFactor_Gt() {
	ssf, err := NewSecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", ssf.Set(128).Gt().SetParen(true))
	// Output: (ssf>"128")
}

func ExampleSecurityStrengthFactor_Ge() {
	ssf, err := NewSecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", ssf.Set(128).Ge().SetParen(true))
	// Output: (ssf>="128")
}

func ExampleSecurityStrengthFactor_String() {
	ssf, err := NewSecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s", ssf)
	// Output: 128
}

func ExampleSecurityStrengthFactor_Valid() {
	var s SecurityStrengthFactor
	fmt.Printf("Valid: %t", s.Valid() == nil) // zero IS valid, technically speaking!
	// Output: Valid: true
}

func ExampleSecurityStrengthFactor_IsZero() {
	var s SecurityStrengthFactor
	fmt.Printf("Zero: %t", s.IsZero())
	// Output: Zero: true
}

func ExampleSecurityStrengthFactor_Keyword() {
	var s SecurityStrengthFactor
	fmt.Printf("Keyword: %s", s.Keyword())
	// Output: Keyword: ssf
}

func ExampleSecurityStrengthFactor() {
	// convenient alternative to "var X SecurityStrengthFactor, X.Set(...) ..."
	ssf, err := NewSecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s", ssf)
	// Output: 128
}

func ExampleAuthenticationMethod_BRM() {
	meths := Anonymous.BRM()
	fmt.Printf("%d available aci.BindRuleMethod instances", meths.Len())
	// Output: 2 available aci.BindRuleMethod instances
}

func ExampleAuthenticationMethod_Ne() {
	fmt.Printf("%s", Anonymous.Ne())
	// Output: authmethod!="NONE"
}

func ExampleAuthenticationMethod_Eq() {
	fmt.Printf("%s", SASL.Eq())
	// Output: authmethod="SASL"
}

func ExampleSecurityStrengthFactor_BRM() {

	ssf, err := NewSecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}
	meths := ssf.BRM()

	fmt.Printf("%d available aci.BindRuleMethod instances", meths.Len())
	// Output: 6 available aci.BindRuleMethod instances
}

func ExampleAuthenticationMethod_String() {
	fmt.Printf("%s", EXTERNAL)
	// Output: SASL EXTERNAL
}

func ExampleObjectIdentifier_IsZero() {
	var oid ObjectIdentifier
	fmt.Printf("%T is zero: %t\n", oid, oid.IsZero())
	// Output: aci.ObjectIdentifier is zero: true
}

/*
This example demonstrates the use of the Index method to obtain a single slice OID.
*/
func ExampleObjectIdentifier_Index() {

	oid, err := NewLDAPControlOIDs(
		`1.3.6.1.4.1.56521.999.5`,
		`1.3.6.1.4.1.56521.999.6`,
		`1.3.6.1.4.1.56521.999.7`,
	)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Slice keyword: %s", oid.Index(1))
	// Output: Slice keyword: 1.3.6.1.4.1.56521.999.6
}

func ExampleObjectIdentifier_Eq() {

	oid, err := NewLDAPControlOIDs(
		`1.3.6.1.4.1.56521.999.5`,
		`1.3.6.1.4.1.56521.999.6`,
		`1.3.6.1.4.1.56521.999.7`,
	)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Target rule: %s", oid.Eq())
	// Output: Target rule: (targetcontrol="1.3.6.1.4.1.56521.999.5||1.3.6.1.4.1.56521.999.6||1.3.6.1.4.1.56521.999.7")
}

func ExampleObjectIdentifier_Ne() {

	oid, err := NewLDAPExtendedOperationOIDs(
		`1.3.6.1.4.1.56521.999.5`,
		`1.3.6.1.4.1.56521.999.6`,
		`1.3.6.1.4.1.56521.999.7`,
	)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Target rule: %s", oid.Ne())
	// Output: Target rule: (extop!="1.3.6.1.4.1.56521.999.5||1.3.6.1.4.1.56521.999.6||1.3.6.1.4.1.56521.999.7")
}

func ExampleObjectIdentifier_Push() {

	oid, err := NewLDAPExtendedOperationOIDs(
		`1.3.6.1.4.1.56521.999.5`,
		`1.3.6.1.4.1.56521.999.6`,
	)

	if err != nil {
		fmt.Println(err)
		return
	}

	// Add a third OID we forgot:
	oid.Push(`1.3.6.1.4.1.56521.999.7`)

	fmt.Printf("%d", oid.Len())
	// Output: 3
}

/*
This example demonstrates use of the [ACIv3ObjectIdentifier.Len] method to return the number of slices present within the receiver as an integer.
*/
func ExampleObjectIdentifier_Len() {

	oid, err := NewLDAPExtendedOperationOIDs(
		`1.3.6.1.4.1.56521.999.5`,
		`1.3.6.1.4.1.56521.999.6`,
		`1.3.6.1.4.1.56521.999.7`,
	)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%d", oid.Len())
	// Output: 3
}

/*
This example demonstrates use of the [ACIv3ObjectIdentifier.Keyword] method to obtain the current [ACIv3TargetKeyword] context from the receiver.
*/
func ExampleObjectIdentifier_Keyword() {

	oid, err := NewLDAPExtendedOperationOIDs(
		`1.3.6.1.4.1.56521.999.5`,
		`1.3.6.1.4.1.56521.999.6`,
		`1.3.6.1.4.1.56521.999.7`,
	)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", oid.Keyword())
	// Output: extop
}

/*
This example demonstrates the use of the [ACIv3ObjectIdentifier.TRM] method to obtain a list of available [ACIv3Operator] identifiers and methods.
*/
func ExampleObjectIdentifier_TRM() {
	var oid ObjectIdentifier
	fmt.Printf("Allows greater-than: %t", oid.TRM().Contains(Gt))
	// Output: Allows greater-than: false
}

/*
This example demonstrates the use of the [ACIv3ObjectIdentifier.Valid] method upon a nil receiver.
*/
func ExampleObjectIdentifier_Valid() {
	var oid ObjectIdentifier
	fmt.Printf("Valid: %t", oid.Valid() == nil)
	// Output: Valid: false
}

func TestAllow_all(t *testing.T) {

	G, err := NewPermission(true,
		ReadAccess,
		CompareAccess,
		SearchAccess,
		ImportAccess,
		ExportAccess,
		SelfWriteAccess,
		DeleteAccess,
		AddAccess,
		WriteAccess)

	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	want := `allow(all)`
	got := G.String()
	if want != got {
		t.Errorf("%s failed: want '%s', got '%s'", t.Name(), want, got)
		return
	}
}

func ExampleRight_String() {
	// iterate all of the known Right definitions
	// defined as constants in this package.
	for idx, privilege := range []Right{
		NoAccess,
		ReadAccess,
		WriteAccess,
		AddAccess,
		DeleteAccess,
		SearchAccess,
		CompareAccess,
		SelfWriteAccess,
		ProxyAccess,
		ImportAccess,
		ExportAccess,
		AllAccess, // does NOT include proxy access !
	} {
		fmt.Printf("Privilege %02d/%d: %s (bit:%d)\n", idx+1, 12, privilege, int(privilege))
	}
	// Output:
	// Privilege 01/12: none (bit:0)
	// Privilege 02/12: read (bit:1)
	// Privilege 03/12: write (bit:2)
	// Privilege 04/12: add (bit:4)
	// Privilege 05/12: delete (bit:8)
	// Privilege 06/12: search (bit:16)
	// Privilege 07/12: compare (bit:32)
	// Privilege 08/12: selfwrite (bit:64)
	// Privilege 09/12: proxy (bit:128)
	// Privilege 10/12: import (bit:256)
	// Privilege 11/12: export (bit:512)
	// Privilege 12/12: all (bit:895)
}

/*
This example demonstrates the withholding (denial) of all privileges except proxy.
*/
func ExamplePermission_granting() {

	// grant read/write
	p, err := NewPermission(true, ReadAccess, WriteAccess)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", p)
	// Output: allow(read,write)
}

/*
This example demonstrates the withholding (denial) of all privileges except proxy.
*/
func ExamplePermission_withholding() {

	// deny everything (this does not include proxy privilege)
	p, err := NewPermission(false, AllAccess)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", p)
	// Output: deny(all)
}

func ExamplePermission_IsZero() {
	var p Permission
	fmt.Printf("Privileges are undefined: %t", p.IsZero())
	// Output: Privileges are undefined: true
}

func ExamplePermission_Valid() {
	var p Permission
	fmt.Printf("%T is ready for use: %t", p, p.Valid() == nil)
	// Output: aci.Permission is ready for use: false
}

func ExamplePermission_Disposition() {
	p, err := NewPermission(true, "read", "write", "compare", "selfwrite")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", p.Disposition())
	// Output: allow
}

func ExamplePermission_String() {
	p, err := NewPermission(true, "read", "write", "compare", "selfwrite")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s", p)
	// Output: allow(read,write,compare,selfwrite)
}

func ExamplePermission_Len() {
	p, err := NewPermission(false, "read", "write", "compare", "search", "proxy")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Number of privileges denied: %d", p.Len())
	// Output: Number of privileges denied: 5
}

func ExamplePermission_shifting() {
	// Shift or Unshift values may be Right constants, or their
	// string or uint16 equivalents:
	p, err := NewPermission(false, ReadAccess, "write", 32, SearchAccess, "PROXY")
	if err != nil {
		fmt.Println(err)
		return
	}

	p.Unshift("compare") // remove the negated compare (bit 32) privilege
	fmt.Printf("Forbids compare: %t", p.Positive(`compare`))
	// Output: Forbids compare: false
}

func TestRights_bogus(t *testing.T) {
	var p Permission
	err := p.Valid()
	if err == nil {
		t.Errorf("%s failed: invalid %T returned no validity error",
			t.Name(), p)
		return
	}

	p, _ = NewPermission(true)
	if p.String() != badACIv3PermStr {
		t.Errorf("%s failed: invalid %T returned no bogus string warning",
			t.Name(), p)
		return
	}

	p.Unshift(`all`)
	p.Shift(-1985)       //underflow
	p.Shift(45378297659) //overflow
	if !p.IsZero() {
		t.Errorf("%s failed: overflow or underflow shift value accepted for %T",
			t.Name(), p)
		return
	}

	p.Unshift(-5)     //underflow
	p.Unshift(134559) //overflow
	if !p.IsZero() {
		t.Errorf("%s failed: overflow or underflow unshift value accepted for %T",
			t.Name(), p)
		return
	}

}

func TestRights_lrShift(t *testing.T) {
	p, err := NewPermission(true, "none")
	if err != nil {
		fmt.Println(err)
		return
	} else if !p.Positive(0) || !p.Positive(`none`) || !p.positive(NoAccess) {
		t.Errorf("%s failed: cannot identify 'none' permission", t.Name())
		return
	}

	// three iterations, one per supported
	// Right type
	for i := 0; i < 3; i++ {

		// iterate each of the rights in the
		// rights/names map
		for k, v := range aCIRightsMap {

			if k == 0 {
				continue
			}

			term, typ := testGetRightsTermType(i, k, v)

			shifters := map[int]func(...any) Permission{
				0: p.Shift,
				1: p.Unshift,
			}

			for j := 0; j < len(shifters); j++ {
				mode, phase := testGetRightsPhase(j)
				if shifters[j](term); p.Positive(term) != phase {
					t.Errorf("%s failed: %T %s %s failed [key:%d; term:%v] (value:%v)",
						t.Name(), p, typ, mode, k, term, p)
					return
				}
			}
		}
	}
}

func testGetRightsPhase(j int) (mode string, phase bool) {
	mode = `shift`
	if phase = (0 == j); !phase {
		mode = `un` + mode
	}

	return
}

func testGetRightsTermType(i int, k Right, v string) (term any, typ string) {
	term = k // default
	switch i {
	case 1:
		term = v // string name (e.g.: read)
	case 2:
		term = Right(k) // Right
	}
	typ = fmt.Sprintf("%T", term) // label for err

	return
}

func TestPermission_codecov(t *testing.T) {
	var p, d Permission
	_ = p.Valid()
	_ = p.Len()
	_ = p.Valid()
	_ = p.Disposition()
	_ = p.Shift()
	_ = p.Shift(nil)
	_ = p.Positive(nil)
	_ = p.Shift(4)
	_ = p.Shift(4547887935)
	_ = p.Shift(-45478879)
	_ = p.Unshift()
	_ = p.Unshift(nil)
	_ = p.Unshift(4)
	_ = p.Unshift(4547887935)
	_ = p.Unshift(-45478879)
	_, err := marshalACIv3Permission(`alow(red,rite)`)
	if err == nil {
		t.Errorf("%s failed: expected error, got nothing", t.Name())
		return
	}
	_ = p.Disposition()
	_ = p.Positive("PROXY")

	p, err = NewPermission(true, "read", "write")
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	d, err = NewPermission(false, "read", "write")
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	_ = p.Unshift()
	_ = p.Unshift(nil)
	_ = p.Unshift(4)
	_ = p.Shift(4547887935)
	_ = p.Positive(4547887935)
	_ = p.Shift(-45478879)
	_ = p.Unshift(4547887935)
	_ = p.Unshift(-45478879)
	_ = d.Unshift()
	_ = d.Unshift(nil)
	_ = d.Unshift(4)
	_ = d.Shift(4547887935)
	_ = d.Positive(4547887935)
	_ = d.Shift(-45478879)
	_ = d.Unshift(4547887935)
}

func TestACIv3DistinguishedName(t *testing.T) {
	// Create a mix of proper DistinguishedName instances,
	// or their string equivalents.
	dNs := []any{
		"cn=Tarbash The Egyptian Magician,ou=Vendors,ou=Accounts,dc=example,dc=com",
		"cn=Frank Rizzo,ou=Customers,ou=Accounts,dc=example,dc=com",
	}

	var strRes []string
	for _, dn := range dNs {
		switch tv := dn.(type) {
		case string:
			if !strings.HasPrefix(tv, "ldap:///") {
				tv = "ldap:///" + tv
			}
			strRes = append(strRes, tv)
		default:
			t.Errorf("%s failed: invalid DN type (%T)", t.Name(), dn)
			return
		}
	}

	// Resulting string value we expect
	expect := strings.Join(strRes, `||`)

	for idx, kw := range []BindKeyword{
		BindUDN,
		BindGDN,
		BindRDN,
	} {
		for idx2, typ := range []any{
			kw,
			kw.String(),
		} {
			dn, err := NewBindDistinguishedName(append([]any{typ}, dNs...)...)
			if err != nil {
				t.Errorf("%s[%d][%d] failed: %v", t.Name(), idx, idx2, err)
				return
			} else if dn.Len() != len(dNs) {
				t.Errorf("%s[%d][%d] failed: expected %d, got %d", t.Name(), idx, idx2, len(dNs), dn.Len())
				return
			}

			rule := dn.Eq()
			want := kw.String() + "=\"" + expect + `"`
			if got := rule.String(); got != want {
				t.Errorf("%s[%d][%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, idx2, want, got)
				return
			}
		}
	}

	for idx, kw := range []TargetKeyword{
		Target,
		TargetTo,
		TargetFrom,
	} {
		for idx2, typ := range []any{
			kw,
			kw.String(),
		} {
			dn, err := NewTargetDistinguishedName(append([]any{typ}, dNs...)...)
			if err != nil {
				t.Errorf("%s[%d][%d] failed: %v", t.Name(), idx, idx2, err)
				return
			} else if dn.Len() != len(dNs) {
				t.Errorf("%s[%d][%d] failed: expected %d, got %d", t.Name(), idx, idx2, len(dNs), dn.Len())
				return
			}

			rule := dn.Eq()
			want := `(` + kw.String() + "=\"" + expect + `")`
			if got := rule.String(); got != want {
				t.Errorf("%s[%d][%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, idx2, want, got)
				return
			}
		}
	}

}
