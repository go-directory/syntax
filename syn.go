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

	// TODO:
	// 1.3.6.1.4.1.1466.115.121.1.1 (aci item)
	// 1.3.6.1.4.1.1466.115.121.1.2 (access point)
	// 1.3.6.1.4.1.1466.115.121.1.13 (data quality)
	// 1.3.6.1.4.1.1466.115.121.1.18 (dl submit permission)
	// 1.3.6.1.4.1.1466.115.121.1.19 (dsa quality)
	// 1.3.6.1.4.1.1466.115.121.1.20 (dse type)
	// 1.3.6.1.4.1.1466.115.121.1.32 (main preference)
	// 1.3.6.1.4.1.1466.115.121.1.33 (mhs or address)
	// 1.3.6.1.4.1.1466.115.121.1.42 (protocol information)
	// 1.3.6.1.4.1.1466.115.121.1.43 (presentation address)
	// 1.3.6.1.4.1.1466.115.121.1.46 (supplier information)
	// 1.3.6.1.4.1.1466.115.121.1.47 (supplier or consumer)
	// 1.3.6.1.4.1.1466.115.121.1.48 (supplier and consumer)
	// 1.3.6.1.4.1.1466.115.121.1.55 (modify rights)
	// 1.3.6.1.4.1.1466.115.121.1.8 (certificate)
	// 1.3.6.1.4.1.1466.115.121.1.9 (certificate list)
	// 1.3.6.1.4.1.1466.115.121.1.10 (certificate pair)
	// 1.3.6.1.4.1.1466.115.121.1.49 (supported algorithm)
	// 1.3.6.1.1.15.1 (X.509 Certificate Exact Assertion)
	// 1.3.6.1.1.15.2 (X.509 Certificate Assertion)
	// 1.3.6.1.1.15.3 (X.509 Certificate Pair Exact Assertion))
	// 1.3.6.1.1.15.4 (X.509 Certificate Pair Assertion)
	// 1.3.6.1.1.15.5 (X.509 Certificate List Exact Assertion)
	// 1.3.6.1.1.15.6 (X.509 Certificate List Assertion)
	// 1.3.6.1.1.15.7 (X.509 Algorithm Identifier)

	// TODO: I honestly don't have a clue what
	// my plan should be for fax data.
	//`1.3.6.1.4.1.1466.115.121.1.23`: fax,
}
