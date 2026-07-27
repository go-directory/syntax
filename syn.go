package syntax

/*
SyntaxVerifiers is a map instance which stores closure functions or
methods intended to check an assertion value against an associated
syntax.

Each string map index should be the OID of the relevant LDAP syntax.
The value should be a closure function or method with a signature of:

	func(any) (bool, error)

Prior to use, this map instance should be initialized by the caller.
*/
var SyntaxVerifiers map[string]func(any) (bool, error)

func init() {
	SyntaxVerifiers = map[string]func(any) (bool, error){
		`1.3.6.1.4.1.1466.115.121.1.6`:  bitString,
		`1.3.6.1.4.1.1466.115.121.1.7`:  boolean,
		`1.3.6.1.4.1.1466.115.121.1.11`: countryString,
		`1.3.6.1.4.1.1466.115.121.1.12`: dN,
		`1.3.6.1.4.1.1466.115.121.1.14`: deliveryMethod,
		`1.3.6.1.4.1.1466.115.121.1.15`: directoryString,
		`1.3.6.1.4.1.1466.115.121.1.21`: enhancedGuide,
		`1.3.6.1.4.1.1466.115.121.1.22`: facsimileTelephoneNumber,
		`1.3.6.1.4.1.1466.115.121.1.24`: generalizedTime,
		`1.3.6.1.4.1.1466.115.121.1.25`: guide, // OBSOLETE, use enhancedGuide
		`1.3.6.1.4.1.1466.115.121.1.26`: iA5String,
		`1.3.6.1.4.1.1466.115.121.1.27`: integer,
		`1.3.6.1.4.1.1466.115.121.1.28`: jPEG,
		`1.3.6.1.4.1.1466.115.121.1.34`: nameAndOptionalUID,
		`1.3.6.1.4.1.1466.115.121.1.36`: numericString,
		`1.3.6.1.4.1.1466.115.121.1.40`: octetString,
		`1.3.6.1.4.1.1466.115.121.1.38`: oID,
		`1.3.6.1.4.1.1466.115.121.1.39`: otherMailbox,
		`1.3.6.1.4.1.1466.115.121.1.41`: postalAddress,
		`1.3.6.1.4.1.1466.115.121.1.44`: printableString,
		`1.3.6.1.4.1.1466.115.121.1.58`: substringAssertion,
		`1.3.6.1.4.1.1466.115.121.1.50`: telephoneNumber,
		`1.3.6.1.4.1.1466.115.121.1.51`: teletexTerminalIdentifier,
		`1.3.6.1.4.1.1466.115.121.1.52`: telexNumber,
		`1.3.6.1.4.1.1466.115.121.1.53`: uTCTime, // OBSOLETE, use generalizedTime
		`1.3.6.1.1.16.1`:                uUID,
	}

	// TODO: I honestly don't have a clue what
	// my plan should be for fax data.
	//`1.3.6.1.4.1.1466.115.121.1.23`: fax,
}
