package syntax

/*
ub.go exports uint constants that define the upper bounds
(maximum lengths) permitted with certain types.

In terms of an Attribute Type Description, these manifest
as shown in the "noidlen" ABNF, per § 4.1 of RFC 4512, e.g.:

  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256}
                                        ^
                                        |
                                   Upper bounds

Note that not all of these constants are associated with a
type that has (yet) been implemented in this package.  As
such, some of the various definitions here are merely kept
as placeholders.

For the sake of simplicity, these constants are just using
the basic Go uint type, as opposed to using the formal,
[Integer] type. This is because I honestly can't imagine
there is a single upper-bounds definition in the world that
would ever overflow uint, thus its not worth the overhead.
*/

/*
	ub-<identifier> INTEGER ::= <non-zero-unsigned-base10-number>

Upper bounds constant definitions sourced from various
standards documents and recommendations.

Upper bounds are NEVER zero (0).
*/
const (
	UBAudio                uint = 250000 // RFC 1274
	UBBuildingName         uint = 256    // RFC 1274
	UBDocumentIdentifier   uint = 256    // RFC 1274
	UBDocumentLocation     uint = 256    // RFC 1274
	UBDocumentTitle        uint = 256    // RFC 1274
	UBDocumentVersion      uint = 256    // RFC 1274
	UBFavouriteDrink       uint = 256    // RFC 1274
	UBHost                 uint = 256    // RFC 1274
	UBInformation          uint = 2048   // RFC 1274
	UBJanetMailbox         uint = 256    // RFC 1274
	UBOrganizationalStatus uint = 256    // RFC 1274
	UBPersonalSignature    uint = 50000  // RFC 1274
	UBPersonalTitle        uint = 256    // RFC 1274
	UBPhoto                uint = 250000 // RFC 1274
	UBRfc822Mailbox        uint = 256    // RFC 1274
	UBRoomNumber           uint = 256    // RFC 1274
	UBTextOrAddress        uint = 256    // RFC 1274
	UBUniqueIdentifier     uint = 256    // RFC 1274
	UBUserClass            uint = 256    // RFC 1274
	UBUserIdentifier       uint = 256    // RFC 1274
)
