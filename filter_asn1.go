package syntax

/*
FilterDefaultEncoding defines a pre-computed BER encoding of the
official LDAP Search Filter default, "objectClass=*". When properly
decoded, it will manifest as an instance of [FilterPresent].

This variable is defined specifically for performance reasons, and
is intended for use during the encoding of a search request which
lacks a [Filter] value.

See [§ 2 of RFC4515] for the relevant ASN.1 definition and encoding
details.

[§ 2 of RFC4515]: https://datatracker.ietf.org/doc/html/rfc4515#section-2
*/
var FilterDefaultEncoding = []byte{
	0x87, 0x0b, // CONTEXT-SPECIFIC [7], LEN: 11
	0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, // 'o' 'b' 'j' 'e' 'c' 't'
	0x43, 0x6c, 0x61, 0x73, 0x73, // 'C' 'l' 'a' 's' 's'
}

/*
FilterDecode returns an instance of [Filter] alongside an error
following an attempt to decode and write the input enc bytes.

This function is useful for when a [Filter] needs to be decoded,
but the outer type is not known.
*/
func FilterDecode(enc []byte) (Filter, error) {
	p := 0

	var f Filter
	tag, _, err := readCTLV(enc, &p)
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
		out, err = wrapTLV(enc,
			aTag(classC,
				true, uint32(r.Tag())))
	}

	return out, err
}

func (r *FilterNot) Decode(enc []byte) error {
	p := 0

	payload, err := readECTLV(enc, &p, classC, uint32(r.Tag()))

	if err == nil {

		p2 := 0
		start := p2

		var childTag Tag
		if childTag, _, err = readCTLV(payload, &p2); err == nil {
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
		out, err = wrapTLV(payload,
			//aTag(classU, true, uint32(tSet)),
			aTag(classC, true, tag))
	}

	return out, err
}

func decodeFilterSet(tag uint32, enc []byte) ([]Filter, error) {

	payload, err := unwrapTLV(enc,
		aTag(classC, true, tag))
	//aTag(classU, true, uint32(tSet)))

	var out []Filter
	if err == nil {
		p := 0
		for p < len(payload) && err == nil {
			start := p

			var childTag Tag
			if childTag, _, err = readCTLV(payload, &p); err == nil {
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
		err = asn1Error("unexpected Filter tag ", itoa(int(tag)))
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
			outer, err = wrapTLV(payload,
				aTag(classC, true, uint32(r.Tag())))
		}
	}

	return outer, err
}

func (r *FilterSubstrings) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc,
		aTag(classC, true, uint32(r.Tag())))

	if err == nil {
		p := 0
		var subs []byte
		for p < len(payload) && err == nil {
			var dTag Tag
			var dPayload []byte
			if dTag, dPayload, err = readCTLV(payload, &p); err == nil {
				switch dTag.Tag {
				case 4:
					// 0x04 OCTET STRING
					r.Type = AttributeDescription(dPayload)
				case 16:
					subs = append(subs, dPayload...)
				}
			}
		}
		err = r.Substrings.Decode(subs)
	}

	return err
}

func (r FilterPresent) Encode() ([]byte, error) {
	// TODO: isAttr check for r.Desc.
	return wrapTLV(r.Desc,
		aTag(classC, false, uint32(r.Tag())))
}

func (r *FilterPresent) Decode(enc []byte) error {

	// Outer SEQUENCE
	payload, err := unwrapTLV(enc,
		aTag(classC, false, uint32(r.Tag())))

	if err == nil {
		r.Desc = payload
	}

	return err
}

func (r FilterGreaterOrEqual) Encode() ([]byte, error) {
	var enc []byte
	ava, err := AttributeValueAssertion(r).Encode()
	if err == nil {
		// Strip the outer SEQUENCE (UNIVERSAL, constructed, tag = TagSequence)
		enc, err = unwrapTLV(ava,
			aTag(classU, true, uint32(tSeq)))

		if err == nil {
			// wrap as Filter greaterOrEqual: [5] AttributeValueAssertion
			// ClassContextSpecific, constructed = true, tagNum = 5
			enc, err = wrapTLV(enc,
				aTag(classC, true, uint32(r.Tag())))
		}
	}

	return enc, err
}

func (r *FilterGreaterOrEqual) Decode(enc []byte) error {
	var err error
	enc, err = unwrapTLV(enc,
		aTag(classC, true, uint32(r.Tag()))) // CONTEXT-SPECIFIC [5] (AVA)

	if err == nil {
		// Now payload is the raw SEQUENCE payload of AttributeValueAssertion.
		// AttributeValueAssertion.Decode expects the full SEQUENCE TLV,
		// not just the payload, so we must re-wrap it.
		enc, err = wrapTLV(enc, uSeqTag())

		if err == nil {
			var ava AttributeValueAssertion
			if err = ava.Decode(enc); err == nil { // SEQUENCE (AVA)
				*r = FilterGreaterOrEqual(ava)
			}
		}
	}

	return err
}

func (r FilterLessOrEqual) Encode() ([]byte, error) {
	enc, err := AttributeValueAssertion(r).Encode() // SEQUENCE
	if err == nil {
		enc, err = unwrapTLV(enc, aTag(classU, true, uint32(tSeq))) // SEQUENCE (remove)
		if err == nil {
			// Wrap as Filter lessOrEqual: [6] AttributeValueAssertion
			// ClassContextSpecific, constructed = true, tagNum = 6
			enc, err = wrapTLV(enc,
				aTag(classC, true, uint32(r.Tag()))) // CONTEXT-SPECIFIC [6]
		}
	}

	return enc, err
}

func (r *FilterLessOrEqual) Decode(enc []byte) error {
	var err error
	enc, err = unwrapTLV(enc,
		aTag(classC, true, uint32(r.Tag()))) // CONTEXT-SPECIFIC [6] (AVA)
	if err == nil {
		// Now inner is the raw SEQUENCE payload of AttributeValueAssertion.
		// AttributeValueAssertion.Decode expects the full SEQUENCE TLV,
		// not just the payload, so we must re-wrap it.
		enc, err = wrapTLV(enc, uSeqTag()) // SEQUENCE

		if err == nil {
			var ava AttributeValueAssertion
			if err = ava.Decode(enc); err == nil { // SEQUENCE (AVA)
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
		payload, err = readECTLV(enc, &p,
			classU, uint32(tSeq))

		if err == nil {
			// Wrap as Filter approximateMatch: [8] AttributeValueAssertion
			// ClassContextSpecific, constructed = true, tagNum = 8
			out, err = wrapTLV(payload,
				aTag(classC,
					true, uint32(r.Tag())))
		}
	}

	return out, err
}

func (r *FilterApproximateMatch) Decode(enc []byte) error {
	p := 0

	// Outer wrapper: [8] AttributeValueAssertion
	inner, err := readECTLV(enc, &p,
		classC, uint32(r.Tag()))

	if err == nil {
		// Now inner is the raw SEQUENCE payload of AttributeValueAssertion.
		// AttributeValueAssertion.Decode expects the full SEQUENCE TLV,
		// not just the payload, so we must re-wrap it.
		var seq []byte
		seq, err = wrapTLV(inner, uSeqTag())

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
		payload, err = readECTLV(enc, &p,
			classU, uint32(tSeq))

		if err == nil {
			// Wrap as Filter equalityMatch: [3] AttributeValueAssertion
			// ClassContextSpecific, constructed = true, tagNum = 3
			out, err = wrapTLV(payload,
				aTag(classC,
					true, uint32(r.Tag())))
		}
	}

	return out, err
}

func (r *FilterEqualityMatch) Decode(enc []byte) error {
	p := 0

	// Outer wrapper: [3] AttributeValueAssertion
	inner, err := readECTLV(enc, &p,
		classC, uint32(r.Tag()))

	if err == nil {
		// Now inner is the raw SEQUENCE payload of AttributeValueAssertion.
		// AttributeValueAssertion.Decode expects the full SEQUENCE TLV,
		// not just the payload, so we must re-wrap it.
		var seq []byte
		seq, err = wrapTLV(inner, uSeqTag())

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
		payload, err = readECTLV(enc, &p,
			classU, uint32(tSeq))

		if err == nil {
			// Wrap as Filter extensibleMatch: [9] MatchingRuleAssertion
			// ClassContextSpecific, constructed = true, tagNum = 9
			out, err = wrapTLV(payload,
				aTag(classC,
					true, uint32(tagFilterExtensibleMatch)))
		}
	}

	return out, err
}

func (r *FilterExtensibleMatch) Decode(enc []byte) error {
	p := 0

	// Outer wrapper: [9] MatchingRuleAssertion
	inner, err := readECTLV(enc, &p, classC, uint32(tagFilterExtensibleMatch))

	if err == nil {
		// Now inner is the raw SEQUENCE payload of MatchingRuleAssertion.
		// MatchingRuleAssertion.Decode expects the full SEQUENCE TLV,
		// not just the payload, so we must re-wrap it.
		var seq []byte
		seq, err = wrapTLV(inner, uSeqTag())

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
	var enc []byte

	val, err := r.Desc.Encode()
	if err == nil {
		enc = append(enc, val...) // attributeDesc (OCTET STRING)
		val, err = OctetString(r.Value).Encode()
		if err == nil {
			enc = append(enc, val...)          // assertionValue (OCTET STRING)
			enc, err = wrapTLV(enc, uSeqTag()) // SEQUENCE

		}
	}

	return enc, err
}

func (r *AttributeValueAssertion) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag()) // SEQUENCE
	if err == nil {
		p := 0
		r.Desc, err = readEPTLV(payload, &p,
			classU, uint32(tOct)) // attributeDescr (OCTET STRING)
		if err == nil {
			r.Value, err = readEPTLV(payload, &p,
				classU, uint32(tOct)) // assertionValue (OCTET STRING)
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
		_, innerPayload, err := readCTLV(inner, &p)
		if err != nil {
			return nil, err
		}

		payload = append(payload,
			writeCTLV(nil, classC, false, 1, innerPayload)...)
	}

	// [2] AttributeDescription OPTIONAL
	if len(r.Type) > 0 {
		o := OctetString(r.Type) // AttributeDescription is []byte/LDAPString
		inner, err := o.Encode() // 04 <len> <payload>
		if err != nil {
			return nil, err
		}

		p := 0
		_, innerPayload, err := readCTLV(inner, &p)
		if err != nil {
			return nil, err
		}

		payload = append(payload,
			writeCTLV(nil, classC, false, 2, innerPayload)...)
	}

	// [3] AssertionValue (OCTET STRING)
	o := OctetString(r.MatchValue)
	inner, err := o.Encode()
	if err != nil {
		return nil, err
	}

	p := 0
	_, innerPayload, err := readCTLV(inner, &p)
	if err != nil {
		return nil, err
	}

	payload = append(payload,
		writeCTLV(nil, classC, false, 3, innerPayload)...)

	// [4] BOOLEAN DEFAULT FALSE
	if r.DNAttributes != Boolean(false) {
		inner, err := r.DNAttributes.Encode()
		if err != nil {
			return nil, err
		}

		p := 0
		_, innerPayload, err := readCTLV(inner, &p)
		if err != nil {
			return nil, err
		}

		payload = append(payload,
			writeCTLV(nil, classC, false, 4, innerPayload)...)
	}

	// Wrap in universal SEQUENCE
	return wrapTLV(payload, uSeqTag())
}

func (r *MatchingRuleAssertion) Decode(enc []byte) error {
	p := 0

	// Outer SEQUENCE
	payload, err := readECTLV(enc, &p, classU, uint32(tSeq))

	if err == nil {
		// Reset receiver
		*r = MatchingRuleAssertion{}

		p2 := 0
		for p2 < len(payload) && err == nil {
			var childTag Tag
			var childPayload []byte
			if childTag, childPayload, err = readCTLV(payload, &p2); err != nil {
				break
			}

			if childTag.Class != classC {
				err = asn1Error("MatchingRuleAssertion.Decode: wrong class: got ",
					itoa(int(childTag.Class)), ", want ",
					itoa(int(classC)))
				break
			}

			switch childTag.Tag {
			case 1: // matchingRule [1] MatchingRuleId OPTIONAL
				if err = childTag.Expect(classC, false, 1); err == nil {
					// childPayload already holds the raw OCTET STRING value
					r.MatchingRule = MatchingRuleID(childPayload)
				}

			case 2: // type [2] AttributeDescription OPTIONAL
				if err = childTag.Expect(classC, false, 2); err == nil {
					inner := writeCTLV(nil, classU, false, uint32(tOct), childPayload)

					var ad AttributeDescription
					err = ad.Decode(inner)
					r.Type = ad
				}

			case 3: // matchValue [3] AssertionValue
				if err = childTag.Expect(classC, false, 3); err == nil {
					// childPayload already holds the raw OCTET STRING value
					r.MatchValue = AssertionValue(childPayload)
				}

			case 4: // dnAttributes [4] BOOLEAN DEFAULT FALSE
				if err = childTag.Expect(classC, false, 4); err == nil {
					inner := writeCTLV(nil, classU, false, uint32(tBool), childPayload)

					var b Boolean
					err = b.Decode(inner)
					r.DNAttributes = b
				}

			default:
				err = asn1Error("MatchingRuleAssertion.Decode: unexpected context-specific tag ",
					itoa(int(childTag.Tag)))
			}
		}
	}

	return err
}
