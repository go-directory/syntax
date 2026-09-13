package syntax

/*
Syntax Object Identifiers serve as map indices for calling syntax verification
functions from the [SyntaxVerifiers] global instance.
*/
var (
	OIDAlgorithmIdentifierAssertionSyntax  = "1.3.6.1.1.15.7"                // RFC 4523
	OIDBitStringSyntax                     = `1.3.6.1.4.1.1466.115.121.1.6`  // RFC 4517
	OIDBooleanSyntax                       = `1.3.6.1.4.1.1466.115.121.1.7`  // RFC 4517
	OIDCertificateAssertionSyntax          = "1.3.6.1.1.15.2"                // RFC 4523
	OIDCertificateExactAssertionSyntax     = "1.3.6.1.1.15.1"                // RFC 4523
	OIDCertificateListAssertionSyntax      = "1.3.6.1.1.15.6"                // RFC 4523
	OIDCertificateListExactAssertionSyntax = "1.3.6.1.1.15.5"                // RFC 4523
	OIDCertificateListSyntax               = "1.3.6.1.4.1.1466.115.121.1.9"  // RFC 4523
	OIDCertificatePairAssertionSyntax      = "1.3.6.1.1.15.4"                // RFC 4523
	OIDCertificatePairExactAssertionSyntax = "1.3.6.1.1.15.3"                // RFC 4523
	OIDCertificatePairSyntax               = "1.3.6.1.4.1.1466.115.121.1.10" // RFC 4523
	OIDCertificateSyntax                   = "1.3.6.1.4.1.1466.115.121.1.8"  // RFC 4523
	OIDCountryStringSyntax                 = `1.3.6.1.4.1.1466.115.121.1.11` // RFC 4517
	OIDDeliveryMethodSyntax                = `1.3.6.1.4.1.1466.115.121.1.14` // RFC 4517
	OIDDirectoryStringSyntax               = `1.3.6.1.4.1.1466.115.121.1.15` // RFC 4517
	OIDDistinguishedNameSyntax             = `1.3.6.1.4.1.1466.115.121.1.12` // RFC 4517
	OIDEnhancedGuideSyntax                 = `1.3.6.1.4.1.1466.115.121.1.21` // RFC 4517
	OIDFacsimileTelephoneNumberSyntax      = `1.3.6.1.4.1.1466.115.121.1.22` // RFC 4517
	OIDGeneralizedTimeSyntax               = `1.3.6.1.4.1.1466.115.121.1.24` // RFC 4517
	OIDGuideSyntax                         = `1.3.6.1.4.1.1466.115.121.1.25` // RFC 4517
	OIDIA5StringSyntax                     = `1.3.6.1.4.1.1466.115.121.1.26` // RFC 4517
	OIDIntegerSyntax                       = `1.3.6.1.4.1.1466.115.121.1.27` // RFC 4517
	OIDJPEGSyntax                          = `1.3.6.1.4.1.1466.115.121.1.28` // RFC 4517
	OIDNameAndOptionalUIDSyntax            = `1.3.6.1.4.1.1466.115.121.1.34` // RFC 4517
	OIDNumericStringSyntax                 = `1.3.6.1.4.1.1466.115.121.1.36` // RFC 4517
	OIDObjectIdentifierSyntax              = `1.3.6.1.4.1.1466.115.121.1.38` // RFC 4517
	OIDOctetStringSyntax                   = `1.3.6.1.4.1.1466.115.121.1.40` // RFC 4517
	OIDOtherMailboxSyntax                  = `1.3.6.1.4.1.1466.115.121.1.39` // RFC 4517
	OIDPostalAddressSyntax                 = `1.3.6.1.4.1.1466.115.121.1.41` // RFC 4517
	OIDPrintableStringSyntax               = `1.3.6.1.4.1.1466.115.121.1.44` // RFC 4517
	OIDSubstringAssertionSyntax            = `1.3.6.1.4.1.1466.115.121.1.58` // RFC 4517
	OIDSubtreeSpecificationSyntax          = `1.3.6.1.4.1.1466.115.121.1.45` // RFC 3672
	OIDSupportedAlgorithmSyntax            = "1.3.6.1.4.1.1466.115.121.1.49" // RFC 4523
	OIDTelephoneNumberSyntax               = `1.3.6.1.4.1.1466.115.121.1.50` // RFC 4517
	OIDTeletexTerminalIdentifierSyntax     = `1.3.6.1.4.1.1466.115.121.1.51` // RFC 4517
	OIDTelexNumberSyntax                   = `1.3.6.1.4.1.1466.115.121.1.52` // RFC 4517
	OIDUTCTimeSyntax                       = `1.3.6.1.4.1.1466.115.121.1.53` // RFC 4517
	OIDUUIDSyntax                          = `1.3.6.1.1.16.1`                // RFC 4517
)

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
		OIDAlgorithmIdentifierAssertionSyntax:  algorithmIdentifierAssertion,
		OIDBitStringSyntax:                     bitString,
		OIDBooleanSyntax:                       boolean,
		OIDCertificateAssertionSyntax:          certificateAssertion,
		OIDCertificateExactAssertionSyntax:     certificateExactAssertion,
		OIDCertificateListAssertionSyntax:      certificateListAssertion,
		OIDCertificateListExactAssertionSyntax: certificateListExactAssertion,
		OIDCertificateListSyntax:               certificateList,
		OIDCertificatePairAssertionSyntax:      certificatePairAssertion,
		OIDCertificatePairExactAssertionSyntax: certificatePairExactAssertion,
		OIDCertificatePairSyntax:               certificatePair,
		OIDCertificateSyntax:                   certificate,
		OIDCountryStringSyntax:                 countryString,
		OIDDeliveryMethodSyntax:                deliveryMethod,
		OIDDirectoryStringSyntax:               directoryString,
		OIDDistinguishedNameSyntax:             dN,
		OIDEnhancedGuideSyntax:                 enhancedGuide,
		OIDFacsimileTelephoneNumberSyntax:      facsimileTelephoneNumber,
		OIDGeneralizedTimeSyntax:               generalizedTime,
		OIDGuideSyntax:                         guide, // OBSOLETE, use enhancedGuide
		OIDIA5StringSyntax:                     iA5String,
		OIDIntegerSyntax:                       integer,
		OIDJPEGSyntax:                          jPEG,
		OIDNameAndOptionalUIDSyntax:            nameAndOptionalUID,
		OIDNumericStringSyntax:                 numericString,
		OIDObjectIdentifierSyntax:              oID,
		OIDOctetStringSyntax:                   octetString,
		OIDOtherMailboxSyntax:                  otherMailbox,
		OIDPostalAddressSyntax:                 postalAddress,
		OIDPrintableStringSyntax:               printableString,
		OIDSubstringAssertionSyntax:            substringAssertion,
		OIDSubtreeSpecificationSyntax:          subtreeSpecification,
		OIDTelephoneNumberSyntax:               telephoneNumber,
		OIDTeletexTerminalIdentifierSyntax:     teletexTerminalIdentifier,
		OIDTelexNumberSyntax:                   telexNumber,
		OIDUTCTimeSyntax:                       uTCTime, // OBSOLETE, use generalizedTime
		OIDUUIDSyntax:                          uUID,
	}

	// TODO:
	// 1.3.6.1.4.1.1466.115.121.1.49 (supported algorithm)
	//OIDSupportedAlgorithmSyntax:

	// Syntaxes not for LDAP, but base X.500. Someday ...
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

	// TODO: I honestly don't have a clue what
	// my plan should be for fax data.
	//`1.3.6.1.4.1.1466.115.121.1.23`: fax,
}
