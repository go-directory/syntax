package syntax

/*
DirectoryString implements the Directory String syntax.

From [§ 3.3.6 of RFC 4517]:

	DirectoryString = 1*UTF8

From [§ 1.4 of RFC 4512]:

	UTF8 = UTF1 / UTFMB
	UTFMB = UTF2 / UTF3 / UTF4
	UTF0  = %x80-BF
	UTF1  = %x00-7F
	UTF2  = %xC2-DF UTF0
	UTF3  = %xE0 %xA0-BF UTF0 / %xE1-EC 2(UTF0) /
	        %xED %x80-9F UTF0 / %xEE-EF 2(UTF0)
	UTF4  = %xF0 %x90-BF 2(UTF0) / %xF1-F3 3(UTF0) /
	        %xF4 %x80-8F 2(UTF0)

From [ITU-T Rec. X.520 clause 2.6]:

	UnboundedDirectoryString ::= CHOICE {
		teletexString TeletexString(SIZE (1..MAX)),
		printableString PrintableString(SIZE (1..MAX)),
		bmpString BMPString(SIZE (1..MAX)),
		universalString UniversalString(SIZE (1..MAX)),
		uTF8String UTF8String(SIZE (1..MAX)) }

	DirectoryString{INTEGER:maxSize} ::= CHOICE {
		teletexString TeletexString(SIZE (1..maxSize,...)),
		printableString PrintableString(SIZE (1..maxSize,...)),
		bmpString BMPString(SIZE (1..maxSize,...)),
		universalString UniversalString(SIZE (1..maxSize,...)),
		uTF8String UTF8String(SIZE (1..maxSize,...)) }

While classic X.520 logic -- that is, the support for [TeletexString],
[PrintableString], [BMPString] and [UniversalString] -- is implemented
in this package for compatibility, generally it is recommended that end
users stick with the [UTF8String] path for [DirectoryString] instances,
as this is preferred in LDAP.

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.3.6 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.6
[ITU-T Rec. X.520 clause 2.6]: https://www.itu.int/rec/T-REC-X.520
*/
type DirectoryString interface {
	String() string
	Choice() string
	isDirectoryString() // differentiate from other interfaces
}

func (r BMPString) isDirectoryString()       {}
func (r UTF8String) isDirectoryString()      {}
func (r UniversalString) isDirectoryString() {}
func (r TeletexString) isDirectoryString()   {}
func (r PrintableString) isDirectoryString() {}

func (r BMPString) Choice() string       { return `bmpString` }
func (r UTF8String) Choice() string      { return `utf8String` }
func (r UniversalString) Choice() string { return `universalString` }
func (r TeletexString) Choice() string   { return `teletexString` }
func (r PrintableString) Choice() string { return `printableString` }

/*
DirectoryString returns an instance of [DirectoryString] alongside an error.

The following input types are accepted:

  - []byte or string (parsed as [UTF8String])
  - [UTF8String]
  - [PrintableString]
  - [TeletexString]
  - [BMPString]
  - [UniversalString]
*/
func NewDirectoryString(x any) (DirectoryString, error) {
	return marshalDirectoryString(x)
}

func directoryString(x any) (result bool, err error) {
	_, err = marshalDirectoryString(x)
	result = err == nil
	return
}

func marshalDirectoryString(x any) (ds DirectoryString, err error) {
	switch tv := x.(type) {
	case UTF8String, string, []byte:
		ds, err = assertUTF8String(tv)
	case PrintableString:
		ds, err = marshalPrintableString(tv)
	case UniversalString:
		ds, err = marshalUniversalString(tv)
	case BMPString:
		ds, err = assertBMPString(tv)
	case TeletexString:
		ds, err = marshalTeletexString(tv)
	default:
		err = errorBadType("Directory String")
	}

	return ds, err
}

/*
directoryStringFirstComponentMatch implements [§ 4.2.15 of RFC 4517].

OID: 2.5.13.31

[§ 4.2.15 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.15
*/
func directoryStringFirstComponentMatch(a, b any) (result bool, err error) {

	// Use reflection to handle the attribute value.
	// This value MUST be a struct (SEQUENCE).
	realValue := assertFirstStructField(a)
	if realValue == nil {
		return
	}

	var field DirectoryString
	if field, err = marshalDirectoryString(realValue); err == nil {
		var ds DirectoryString
		if assertValue := assertFirstStructField(b); assertValue == nil {
			ds, err = marshalDirectoryString(b)
			result = field.String() == ds.String()
		} else {
			ds, err = marshalDirectoryString(assertValue)
			result = field.String() == ds.String()
		}
	}

	return
}
