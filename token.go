package syntax

/*
token.go defines []byte(X) tokens frequently used throughout
this package.
*/

var (
	uriLDAP  = []byte("ldap://")
	uriLDAPS = []byte("ldaps://")
	uriLDAPI = []byte("ldapi:///")

	tTripleSlash      = []byte("///")
	tColonDoubleSlash = []byte("://")
	tDollar           = []byte("$")
	tBSlash           = []byte(`\`)
	tSlash            = []byte("/")
	tColon            = []byte(":")
	tComma            = []byte(",")
	tQMark            = []byte("?")
	tSpace            = []byte(" ")
	tSharp            = []byte(`#`)
	tSemi             = []byte(`;`)
	tEquals           = []byte(`=`)
	tEmpty            = []byte(``)
)

var (
	scopeBase = []byte("base")
	scopeOne  = []byte("one")
	scopeSub  = []byte("sub")
)

var (
	tItemEQ  = []byte("EQ")
	tItemGE  = []byte("GE")
	tItemLE  = []byte("LE")
	tItemAPX = []byte("APPROX")
	tItemSUB = []byte("SUBSTR")
	tTrue    = []byte("true")
	tFalse   = []byte("false")
)
