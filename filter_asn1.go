package syntax

import (
	"strconv"

	"github.com/go-directory/encoding/asn1"
)

/*
FilterDecode returns an instance of [Filter] alongside an error
following an attempt to decode and write the input enc bytes.

This function is useful for when a [Filter] needs to be decoded,
but the outer type is not known.
*/
func FilterDecode(enc []byte) (Filter, error) {
	p := 0

	var f Filter
	tag, _, err := asn1.ReadConstructedTLV(enc, &p)
	if err == nil {
		f, err = decodeFilterByTag(tag.Tag, enc)
	}

	return f, err
}

func (r FilterAnd) Encode() ([]byte, error) {
	return encodeFilterSet(uint32(r.Tag()), r)
}

func (r FilterOr) Encode() ([]byte, error) {
	return encodeFilterSet(uint32(r.Tag()), r)
}

func (r *FilterAnd) Decode(enc []byte) error {
	var f []Filter
	var err error
	f, err = decodeFilterSet(uint32(r.Tag()), enc)
	if err == nil {
		*r = FilterAnd(f)
	}
	return err
}

func (r *FilterOr) Decode(enc []byte) error {
	var f []Filter
	var err error
	f, err = decodeFilterSet(uint32(r.Tag()), enc)
	if err == nil {
		*r = FilterOr(f)
	}
	return err
}

func (r FilterNot) Encode() ([]byte, error) {
	enc, err := r.Filter.Encode()
	var out []byte
	if err == nil {
		out, err = asn1.WrapTLV(enc,
			aTag(asn1.ClassContextSpecific,
				true, uint32(r.Tag())))
	}

	return out, err
}

func (r *FilterNot) Decode(enc []byte) error {
	p := 0

	payload, err := asn1.ReadExpectedConstructedTLV(enc, &p,
		asn1.ClassContextSpecific, uint32(r.Tag()))

	if err == nil {

		p2 := 0
		start := p2

		var childTag asn1.Tag
		if childTag, _, err = asn1.ReadConstructedTLV(payload, &p2); err == nil {
			var f Filter
			if f, err = decodeFilterByTag(childTag.Tag, payload[start:p2]); err == nil {
				r.Filter = f
			}
		}
	}

	return err
}

func encodeFilterSet(tag uint32, fs []Filter) ([]byte, error) {
	var payload []byte
	var err error

	for i := 0; i < len(fs) && err == nil; i++ {
		var enc []byte
		enc, err = fs[i].Encode()
		if err == nil {
			payload = append(payload, enc...)
		}
	}

	var out []byte
	if err == nil {
		out, err = asn1.WrapTLV(payload,
			aTag(asn1.ClassUniversal, true, uint32(asn1.TagSet)),
			aTag(asn1.ClassContextSpecific, true, tag))
	}

	return out, err
}

func decodeFilterSet(tag uint32, enc []byte) ([]Filter, error) {

	payload, err := asn1.UnwrapTLV(enc,
		aTag(asn1.ClassContextSpecific, true, tag),
		aTag(asn1.ClassUniversal, true, uint32(asn1.TagSet)))

	var out []Filter
	if err == nil {
		p := 0
		for p < len(payload) && err == nil {
			start := p

			var childTag asn1.Tag
			if childTag, _, err = asn1.ReadConstructedTLV(payload, &p); err == nil {
				var f Filter
				f, err = decodeFilterByTag(childTag.Tag, payload[start:p])
				if err == nil {
					out = append(out, f)
				}
			}
		}
	}

	return out, err
}

func decodeFilterByTag(tag uint32, payload []byte) (f Filter, err error) {
	switch tag {
	case 0:
		var x FilterAnd
		err = x.Decode(payload)
		f = x
	case 1:
		var x FilterOr
		err = x.Decode(payload)
		f = x
	case 2:
		var x FilterNot
		err = x.Decode(payload)
		f = x
	case 3:
		var x FilterEqualityMatch
		err = x.Decode(payload)
		f = x
	case 4:
		var x FilterSubstrings
		err = x.Decode(payload)
		f = x
	case 5:
		var x FilterGreaterOrEqual
		err = x.Decode(payload)
		f = x
	case 6:
		var x FilterLessOrEqual
		err = x.Decode(payload)
		f = x
	case 7:
		var x FilterPresent
		err = x.Decode(payload)
		f = x
	case 8:
		var x FilterApproximateMatch
		err = x.Decode(payload)
		f = x
	case 9:
		var x FilterExtensibleMatch
		err = x.Decode(payload)
		f = x
	default:
		err = asn1Error("unexpected Filter tag ", strconv.Itoa(int(tag)))
	}

	return
}

func (r FilterSubstrings) Encode() ([]byte, error) {
	var outer []byte

	ad, err := r.Type.Encode()
	if err == nil {
		var payload []byte
		payload = append(payload, ad...)
		var sub []byte
		if sub, err = r.Substrings.Encode(); err == nil {
			payload = append(payload, sub...)
			outer, err = asn1.WrapTLV(payload, uSeqTag(),
				aTag(asn1.ClassContextSpecific, true, uint32(r.Tag())))
		}
	}

	return outer, err
}

func (r *FilterSubstrings) Decode(enc []byte) error {
	payload, err := asn1.UnwrapTLV(enc,
		aTag(asn1.ClassContextSpecific, true, uint32(r.Tag())),
		uSeqTag())

	if err == nil {
		p := 0
		var subs []byte
		for p < len(payload) && err == nil {
			var dTag asn1.Tag
			var dPayload []byte
			if dTag, dPayload, err = asn1.ReadConstructedTLV(payload, &p); err == nil {
				switch dTag.Tag {
				case 4:
					// 0x04 OCTET STRING
					r.Type = AttributeDescription(dPayload)
				case 16:
					// 0x10 SEQUENCE
					var wrapped []byte
					wrapped, err = asn1.WrapTLV(dPayload, uSeqTag())

					subs = append(subs, wrapped...)
				}
			}
		}
		err = r.Substrings.Decode(subs)
	}

	return err
}

func (r FilterPresent) Encode() ([]byte, error) {
	var payload, outer []byte

	// attributeDesc
	ad := AttributeDescription(r.Desc)

	encDesc, err := ad.Encode()
	if err == nil {
		payload = append(payload, encDesc...)

		outer, err = asn1.WrapTLV(payload,
			uSeqTag(),
			aTag(asn1.ClassUniversal, true, uint32(r.Tag())))
	}

	return outer, err
}

func (r *FilterPresent) Decode(enc []byte) error {

	// Outer SEQUENCE
	payload, err := asn1.UnwrapTLV(enc,
		aTag(asn1.ClassUniversal, true, uint32(r.Tag())),
		uSeqTag(),
		aTag(asn1.ClassUniversal, false, uint32(asn1.TagOctetString)))

	if err == nil {
		r.Desc = AttributeDescription(payload)
	}

	return err
}

func (r FilterGreaterOrEqual) Encode() ([]byte, error) {
	enc, err := AttributeValueAssertion(r).Encode()
	var out []byte
	if err == nil {
		// Strip the outer SEQUENCE (UNIVERSAL, constructed, tag = TagSequence)
		p := 0
		var innerPayload []byte
		innerPayload, err = asn1.ReadExpectedConstructedTLV(enc, &p,
			asn1.ClassUniversal, uint32(asn1.TagSequence))

		if err == nil {
			// wrap as Filter greaterOrEqual: [5] AttributeValueAssertion
			// ClassContextSpecific, constructed = true, tagNum = 5
			out, err = asn1.WrapTLV(innerPayload,
				aTag(asn1.ClassContextSpecific, true, uint32(r.Tag())))
		}
	}

	return out, err
}

func (r *FilterGreaterOrEqual) Decode(enc []byte) error {
	// Outer wrapper: [5] AttributeValueAssertion
	p := 0
	inner, err := asn1.ReadExpectedConstructedTLV(enc, &p,
		asn1.ClassContextSpecific, uint32(r.Tag()))

	if err == nil {
		// Now inner is the raw SEQUENCE payload of AttributeValueAssertion.
		// AttributeValueAssertion.Decode expects the full SEQUENCE TLV,
		// not just the payload, so we must re-wrap it.
		var seq []byte
		seq, err = asn1.WrapTLV(inner, uSeqTag())

		if err == nil {
			var ava AttributeValueAssertion
			if err = ava.Decode(seq); err == nil {
				*r = FilterGreaterOrEqual(ava)
			}
		}
	}

	return err
}

func (r FilterLessOrEqual) Encode() ([]byte, error) {
	enc, err := AttributeValueAssertion(r).Encode()
	var out []byte
	if err == nil {
		var payload []byte
		p := 0
		payload, err = asn1.ReadExpectedConstructedTLV(enc, &p,
			asn1.ClassUniversal, uint32(asn1.TagSequence))

		if err == nil {
			// Wrap as Filter lessOrEqual: [6] AttributeValueAssertion
			// ClassContextSpecific, constructed = true, tagNum = 6
			out, err = asn1.WrapTLV(payload,
				aTag(asn1.ClassContextSpecific, true, uint32(r.Tag())))
		}
	}

	return out, err
}

func (r *FilterLessOrEqual) Decode(enc []byte) error {
	p := 0

	// Outer wrapper: [6] AttributeValueAssertion
	inner, err := asn1.ReadExpectedConstructedTLV(enc, &p,
		asn1.ClassContextSpecific, uint32(r.Tag()))

	if err == nil {
		// Now inner is the raw SEQUENCE payload of AttributeValueAssertion.
		// AttributeValueAssertion.Decode expects the full SEQUENCE TLV,
		// not just the payload, so we must re-wrap it.
		var seq []byte
		seq, err = asn1.WrapTLV(inner, uSeqTag())

		if err == nil {
			var ava AttributeValueAssertion
			if err = ava.Decode(seq); err == nil {
				*r = FilterLessOrEqual(ava)
			}
		}
	}

	return err
}

func (r FilterApproximateMatch) Encode() ([]byte, error) {
	enc, err := AttributeValueAssertion(r).Encode()
	var out []byte
	if err == nil {
		p := 0
		// Strip the outer SEQUENCE (UNIVERSAL, constructed, tag = TagSequence)
		var payload []byte
		payload, err = asn1.ReadExpectedConstructedTLV(enc, &p,
			asn1.ClassUniversal, uint32(asn1.TagSequence))

		if err == nil {
			// Wrap as Filter approximateMatch: [8] AttributeValueAssertion
			// ClassContextSpecific, constructed = true, tagNum = 8
			out, err = asn1.WrapTLV(payload,
				aTag(asn1.ClassContextSpecific,
					true, uint32(r.Tag())))
		}
	}

	return out, err
}

func (r *FilterApproximateMatch) Decode(enc []byte) error {
	p := 0

	// Outer wrapper: [8] AttributeValueAssertion
	inner, err := asn1.ReadExpectedConstructedTLV(enc, &p,
		asn1.ClassContextSpecific, uint32(r.Tag()))

	if err == nil {
		// Now inner is the raw SEQUENCE payload of AttributeValueAssertion.
		// AttributeValueAssertion.Decode expects the full SEQUENCE TLV,
		// not just the payload, so we must re-wrap it.
		var seq []byte
		seq, err = asn1.WrapTLV(inner, uSeqTag())

		if err == nil {
			var ava AttributeValueAssertion
			if err = ava.Decode(seq); err == nil {
				*r = FilterApproximateMatch(ava)
			}
		}
	}

	return err
}

func (r FilterEqualityMatch) Encode() ([]byte, error) {
	enc, err := AttributeValueAssertion(r).Encode()
	var out []byte
	if err == nil {
		p := 0
		// Strip the outer SEQUENCE (UNIVERSAL, constructed, tag = TagSequence)
		var payload []byte
		payload, err = asn1.ReadExpectedConstructedTLV(enc, &p,
			asn1.ClassUniversal, uint32(asn1.TagSequence))

		if err == nil {
			// Wrap as Filter equalityMatch: [3] AttributeValueAssertion
			// ClassContextSpecific, constructed = true, tagNum = 3
			out, err = asn1.WrapTLV(payload,
				aTag(asn1.ClassContextSpecific,
					true, uint32(r.Tag())))
		}
	}

	return out, err
}

func (r *FilterEqualityMatch) Decode(enc []byte) error {
	p := 0

	// Outer wrapper: [3] AttributeValueAssertion
	inner, err := asn1.ReadExpectedConstructedTLV(enc, &p,
		asn1.ClassContextSpecific, uint32(r.Tag()))

	if err == nil {
		// Now inner is the raw SEQUENCE payload of AttributeValueAssertion.
		// AttributeValueAssertion.Decode expects the full SEQUENCE TLV,
		// not just the payload, so we must re-wrap it.
		var seq []byte
		seq, err = asn1.WrapTLV(inner, uSeqTag())

		if err == nil {
			var ava AttributeValueAssertion
			if err = ava.Decode(seq); err == nil {
				*r = FilterEqualityMatch(ava)
			}
		}
	}

	return err
}

func (r FilterExtensibleMatch) Encode() ([]byte, error) {
	enc, err := MatchingRuleAssertion(r).Encode()
	var out []byte
	if err == nil {
		p := 0
		var payload []byte
		payload, err = asn1.ReadExpectedConstructedTLV(enc, &p,
			asn1.ClassUniversal, uint32(asn1.TagSequence))

		if err == nil {
			// Wrap as Filter extensibleMatch: [9] MatchingRuleAssertion
			// ClassContextSpecific, constructed = true, tagNum = 9
			out, err = asn1.WrapTLV(payload,
				aTag(asn1.ClassContextSpecific,
					true, uint32(tagFilterExtensibleMatch)))
		}
	}

	return out, err
}

func (r *FilterExtensibleMatch) Decode(enc []byte) error {
	p := 0

	// Outer wrapper: [9] MatchingRuleAssertion
	inner, err := asn1.ReadExpectedConstructedTLV(enc, &p,
		asn1.ClassContextSpecific,
		uint32(tagFilterExtensibleMatch))

	if err == nil {
		// Now inner is the raw SEQUENCE payload of MatchingRuleAssertion.
		// MatchingRuleAssertion.Decode expects the full SEQUENCE TLV,
		// not just the payload, so we must re-wrap it.
		var seq []byte
		seq, err = asn1.WrapTLV(inner, uSeqTag())

		if err == nil {
			var mra MatchingRuleAssertion
			if err = mra.Decode(seq); err == nil {
				*r = FilterExtensibleMatch(mra)
			}
		}
	}

	return err
}

func (r AttributeValueAssertion) Encode() ([]byte, error) {
	var payload []byte

	// attributeDesc
	ad := AttributeDescription(r.Desc)
	encDesc, err := ad.Encode()
	if err != nil {
		return nil, err
	}
	payload = append(payload, encDesc...)

	// assertionValue
	o := OctetString(r.Value)
	encVal, err := o.Encode()
	if err != nil {
		return nil, err
	}
	payload = append(payload, encVal...)

	// wrap both in SEQUENCE
	return asn1.WrapTLV(payload, uSeqTag())
}

func (r *AttributeValueAssertion) Decode(enc []byte) error {

	// Outer SEQUENCE
	p := 0
	payload, err := asn1.ReadExpectedConstructedTLV(enc, &p,
		asn1.ClassUniversal, uint32(asn1.TagSequence))

	if err == nil {
		p2 := 0
		// Reset receiver
		*r = AttributeValueAssertion{}

		// First child: attributeDesc (OCTET STRING)
		var childPayload []byte
		childPayload, err = asn1.ReadExpectedPrimitiveTLV(payload, &p2,
			asn1.ClassUniversal, uint32(asn1.TagOctetString))

		if err == nil {
			r.Desc = childPayload

			// Second child: assertionValue (OCTET STRING)
			childPayload, err = asn1.ReadExpectedPrimitiveTLV(payload, &p2,
				asn1.ClassUniversal, uint32(asn1.TagOctetString))

			if err == nil {
				r.Value = childPayload
			}
		}
	}

	return err
}

func (r MatchingRuleAssertion) Encode() ([]byte, error) {
	var payload []byte

	// [1] MatchingRuleId OPTIONAL
	if len(r.MatchingRule) > 0 {
		o := OctetString(r.MatchingRule)
		inner, err := o.Encode()
		if err != nil {
			return nil, err
		}

		p := 0
		_, innerPayload, err := asn1.ReadConstructedTLV(inner, &p)
		if err != nil {
			return nil, err
		}

		payload = append(payload,
			asn1.WriteConstructedTLV(nil, asn1.ClassContextSpecific, false, 1, innerPayload)...)
	}

	// [2] AttributeDescription OPTIONAL
	if len(r.Type) > 0 {
		o := OctetString(r.Type) // AttributeDescription is []byte/LDAPString
		inner, err := o.Encode() // 04 <len> <payload>
		if err != nil {
			return nil, err
		}

		p := 0
		_, innerPayload, err := asn1.ReadConstructedTLV(inner, &p)
		if err != nil {
			return nil, err
		}

		payload = append(payload,
			asn1.WriteConstructedTLV(nil, asn1.ClassContextSpecific, false, 2, innerPayload)...)
	}

	// [3] AssertionValue (OCTET STRING)
	o := OctetString(r.MatchValue)
	inner, err := o.Encode()
	if err != nil {
		return nil, err
	}

	p := 0
	_, innerPayload, err := asn1.ReadConstructedTLV(inner, &p)
	if err != nil {
		return nil, err
	}

	payload = append(payload,
		asn1.WriteConstructedTLV(nil, asn1.ClassContextSpecific, false, 3, innerPayload)...)

	// [4] BOOLEAN DEFAULT FALSE
	if r.DNAttributes != Boolean(false) {
		inner, err := r.DNAttributes.Encode()
		if err != nil {
			return nil, err
		}

		p := 0
		_, innerPayload, err := asn1.ReadConstructedTLV(inner, &p)
		if err != nil {
			return nil, err
		}

		payload = append(payload,
			asn1.WriteConstructedTLV(nil, asn1.ClassContextSpecific, false, 4, innerPayload)...)
	}

	// Wrap in universal SEQUENCE
	return asn1.WrapTLV(payload, uSeqTag())
}

func (r *MatchingRuleAssertion) Decode(enc []byte) error {
	p := 0

	// Outer SEQUENCE
	payload, err := asn1.ReadExpectedConstructedTLV(enc, &p,
		asn1.ClassUniversal, uint32(asn1.TagSequence))

	if err == nil {
		// Reset receiver
		*r = MatchingRuleAssertion{}

		p2 := 0
		for p2 < len(payload) && err == nil {
			var childTag asn1.Tag
			var childPayload []byte
			if childTag, childPayload, err = asn1.ReadConstructedTLV(payload, &p2); err != nil {
				break
			}

			if childTag.Class != asn1.ClassContextSpecific {
				err = asn1Error("MatchingRuleAssertion.Decode: wrong class: got ",
					strconv.Itoa(int(childTag.Class)), ", want ",
					strconv.Itoa(int(asn1.ClassContextSpecific)))
				break
			}

			switch childTag.Tag {
			case 1: // matchingRule [1] MatchingRuleId OPTIONAL
				if err = childTag.Expect(asn1.ClassContextSpecific, false, 1); err == nil {
					// childPayload already holds the raw OCTET STRING value
					r.MatchingRule = MatchingRuleID(childPayload)
				}

			case 2: // type [2] AttributeDescription OPTIONAL
				if err = childTag.Expect(asn1.ClassContextSpecific, false, 2); err == nil {
					inner := asn1.WriteConstructedTLV(nil, asn1.ClassUniversal, false, uint32(asn1.TagOctetString), childPayload)

					var ad AttributeDescription
					err = ad.Decode(inner)
					r.Type = ad
				}

			case 3: // matchValue [3] AssertionValue
				if err = childTag.Expect(asn1.ClassContextSpecific, false, 3); err == nil {
					// childPayload already holds the raw OCTET STRING value
					r.MatchValue = AssertionValue(childPayload)
				}

			case 4: // dnAttributes [4] BOOLEAN DEFAULT FALSE
				if err = childTag.Expect(asn1.ClassContextSpecific, false, 4); err == nil {
					inner := asn1.WriteConstructedTLV(nil, asn1.ClassUniversal, false, uint32(asn1.TagBoolean), childPayload)

					var b Boolean
					err = b.Decode(inner)
					r.DNAttributes = b
				}

			default:
				err = asn1Error("MatchingRuleAssertion.Decode: unexpected context-specific tag ",
					strconv.Itoa(int(childTag.Tag)))
			}
		}
	}

	return err
}
