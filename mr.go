package syntax

/*
LessOrEqual (<=), when input to an [OrderingRuleAssertion] function,
results in a less or equal (LE) comparison.
*/
const LessOrEqual byte = 0x0

/*
GreaterOrEqual (>=), when input to an [OrderingRuleAssertion] function,
results in a greater or equal (GE) comparison.
*/
const GreaterOrEqual byte = 0x1

/*
MatchingRuleAssertion implements an [EqualityRuleAssertion],
[SubstringsRuleAssertion] or [OrderingRuleAssertion] function
or method.
*/
type MatchingRuleAssertion interface {
	isMatchingRuleAssertionFunction()
}

/*
EqualityRuleAssertion defines a closure signature held by qualifying
function instances intended to implement an Equality MatchingRuleAssertion.

The semantics of the MatchingRuleAssertion are discussed in [§ 4.1 of
RFC 4517].

[§ 4.1 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.1
*/
type EqualityRuleAssertion func(any, any) (bool, error)

func (r EqualityRuleAssertion) isMatchingRuleAssertionFunction() {}

/*
SubstringsRuleAssertion defines a closure signature held by qualifying
function instances intended to implement a Substrings MatchingRuleAssertion.

The semantics of the MatchingRuleAssertion are discussed in [§ 4.1 of
RFC 4517].

[§ 4.1 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.1
*/
type SubstringsRuleAssertion func(any, any) (bool, error)

func (r SubstringsRuleAssertion) isMatchingRuleAssertionFunction() {}

/*
OrderingRuleAssertion defines a closure signature held by qualifying
function instances intended to implement an Ordering MatchingRuleAssertion.

The semantics of the MatchingRuleAssertion are discussed in [§ 4.1 of
RFC 4517].

[§ 4.1 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.1
*/
type OrderingRuleAssertion func(any, byte, any) (bool, error)

func (r OrderingRuleAssertion) isMatchingRuleAssertionFunction() {}

var MatchingRuleAssertions map[string]MatchingRuleAssertion

func init() {
	MatchingRuleAssertions = map[string]MatchingRuleAssertion{
		"2.5.13.0":                   EqualityRuleAssertion(objectIdentifierMatch),
		"2.5.13.1":                   EqualityRuleAssertion(distinguishedNameMatch),
		"2.5.13.2":                   EqualityRuleAssertion(caseIgnoreMatch),
		"2.5.13.3":                   OrderingRuleAssertion(caseIgnoreOrderingMatch),
		"2.5.13.4":                   SubstringsRuleAssertion(caseIgnoreSubstringsMatch),
		"2.5.13.5":                   EqualityRuleAssertion(caseExactMatch),
		"2.5.13.6":                   OrderingRuleAssertion(caseExactOrderingMatch),
		"2.5.13.7":                   SubstringsRuleAssertion(caseExactSubstringsMatch),
		"2.5.13.8":                   EqualityRuleAssertion(numericStringMatch),
		"2.5.13.9":                   OrderingRuleAssertion(numericStringOrderingMatch),
		"2.5.13.10":                  SubstringsRuleAssertion(numericStringSubstringsMatch),
		"2.5.13.11":                  EqualityRuleAssertion(caseIgnoreListMatch),
		"2.5.13.12":                  SubstringsRuleAssertion(caseIgnoreListSubstringsMatch),
		"2.5.13.13":                  EqualityRuleAssertion(booleanMatch),
		"2.5.13.14":                  EqualityRuleAssertion(integerMatch),
		"2.5.13.15":                  OrderingRuleAssertion(integerOrderingMatch),
		"2.5.13.16":                  EqualityRuleAssertion(bitStringMatch),
		"2.5.13.17":                  EqualityRuleAssertion(octetStringMatch),
		"2.5.13.18":                  OrderingRuleAssertion(octetStringOrderingMatch),
		"2.5.13.20":                  EqualityRuleAssertion(telephoneNumberMatch),
		"2.5.13.21":                  SubstringsRuleAssertion(telephoneNumberSubstringsMatch),
		"2.5.13.23":                  EqualityRuleAssertion(uniqueMemberMatch),
		"2.5.13.27":                  EqualityRuleAssertion(generalizedTimeMatch),
		"2.5.13.28":                  OrderingRuleAssertion(generalizedTimeOrderingMatch),
		"2.5.13.29":                  EqualityRuleAssertion(integerFirstComponentMatch),
		"2.5.13.30":                  EqualityRuleAssertion(objectIdentifierFirstComponentMatch),
		"2.5.13.31":                  EqualityRuleAssertion(directoryStringFirstComponentMatch),
		"2.5.13.32":                  EqualityRuleAssertion(wordMatch),
		"2.5.13.33":                  EqualityRuleAssertion(keywordMatch),
		"1.3.6.1.4.1.1466.109.114.1": EqualityRuleAssertion(caseExactIA5Match),
		"1.3.6.1.4.1.1466.109.114.2": EqualityRuleAssertion(caseIgnoreIA5Match),
		"1.3.6.1.4.1.1466.109.114.3": SubstringsRuleAssertion(caseIgnoreIA5SubstringsMatch),
		"1.3.6.1.1.16.2":             EqualityRuleAssertion(uuidMatch),
		"1.3.6.1.1.16.3":             OrderingRuleAssertion(uuidOrderingMatch),
	}
}
