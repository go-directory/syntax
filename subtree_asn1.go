package syntax

/*
subtree_asn1.go implements the SubtreeSpecification ASN.1 DER codec.
*/

import (
	"errors"
	"strconv"

	"github.com/go-directory/encoding/asn1"
)

// Context tag numbers used in schema
const (
	// SubtreeSpecification fields
	ctBase   = 0
	ctChop   = 1
	ctFilter = 2

	// ChopSpecification fields
	ctExclusions = 0
	ctMinimum    = 1
	ctMaximum    = 2

	// SpecificExclusion fields
	ctChopBefore = 0
	ctChopAfter  = 1
	ctExclusion  = 3
)

func decodeRefinementDER(b []byte) (ref Refinement, err error) {
	var tag asn1.Tag
	var payload []byte
	var p int

	if tag, payload, err = asn1.ReadConstructedTLV(b, &p); err != nil {
		return nil, err
	}

	if tag.Class != 2 {
		return nil, errors.New("expected context-specific refinement tag, got class " +
			strconv.FormatUint(uint64(tag.Class), 10))
	}

	decodeSlice := func(tag uint32, payload []byte) (slice Refinement, err error) {
		var and RefinementAnd
		var or RefinementOr

		var q int
		for q < len(payload) && err == nil {
			var t asn1.Tag
			var pld []byte
			if t, pld, err = asn1.ReadConstructedTLV(payload, &q); err == nil {
				// reconstruct full TLV bytes for recursive decode
				var full []byte
				full = asn1.WriteTag(full, t.Class, t.Constructed, t.Tag)
				full = asn1.WriteLength(full, len(pld))
				full = append(full, pld...)

				var child Refinement
				if child, err = decodeRefinementDER(full); err == nil {
					if tag == 0 {
						and = append(and, child)
					} else {
						or = append(or, child)
					}
				}
			}
		}

		if tag == 0 {
			slice = and
		} else {
			slice = or
		}

		return
	}

	switch tag.Tag {
	case 0, 1:
		ref, err = decodeSlice(tag.Tag, payload)
	case 2:
		// payload contains a single child context TLV
		var child Refinement
		if child, err = decodeRefinementDER(payload); err == nil {
			ref = RefinementNot{Refinement: child}
		}
	case 3:
		// payload should contain a universal UTF8String TLV
		var x UTF8String
		if err = x.Decode(payload); err == nil {
			ref = RefinementItem(x)
		}
	default:
		err = errors.New("unknown refinement tag " +
			strconv.FormatUint(uint64(tag.Tag), 10))
	}

	return
}

func encodeRefinementDER(dst []byte, r Refinement) ([]byte, error) {
	if r == nil {
		return dst, nil
	}

	var err error

	switch v := r.(type) {
	case RefinementAnd, RefinementOr:
		var inner []byte
		for i := 0; i < v.Len() && err == nil; i++ {
			inner, err = encodeRefinementDER(inner, v.Index(i))
		}
		dst = asn1.WriteConstructedTLV(dst, 2, true, uint32(v.Tag()), inner)

	case RefinementNot:
		var child []byte
		child, err = encodeRefinementDER(child, v.Refinement)
		if err == nil {
			dst = asn1.WriteConstructedTLV(dst, 2, true, uint32(v.Tag()), child)
		}

	case RefinementItem:
		inner, _ := asn1.EncodePrimitive(asn1.TagUTF8String, []byte(v))
		dst = asn1.WriteConstructedTLV(dst, 2, true, uint32(v.Tag()), inner)

	default:
		err = errors.New("Unknown Refinement type (none of AND, OR, NOT or ITEM)")
	}

	return dst, err
}

func encodeSubtreeSpecification(r SubtreeSpecification) (out []byte, err error) {
	out = append(out, 0x01) // version

	// base [0] EXPLICIT UTF8String
	if len(r.Base) > 0 {
		inner, _ := asn1.EncodePrimitive(asn1.TagUTF8String, r.Base)
		out = asn1.WriteConstructedTLV(out, 2, true, ctBase, inner)
	}

	// chopSpecification [1] EXPLICIT SEQUENCE
	var chopInner []byte

	// exclusions [0] EXPLICIT SEQUENCE OF SpecificExclusion
	if len(r.ChopSpecification.Exclusions) > 0 {
		var exSeq []byte
		for _, ex := range r.ChopSpecification.Exclusions {
			var one []byte
			if len(ex.ChopBefore) > 0 {
				inner, _ := asn1.EncodePrimitive(asn1.TagUTF8String, []byte(ex.ChopBefore))
				one = asn1.WriteConstructedTLV(one, 2, true, ctChopBefore, inner)
			}
			if len(ex.ChopAfter) > 0 {
				inner, _ := asn1.EncodePrimitive(asn1.TagUTF8String, []byte(ex.ChopAfter))
				one = asn1.WriteConstructedTLV(one, 2, true, ctChopAfter, inner)
			}
			// wrap SpecificExclusion as context [ctExclusion] constructed
			exSeq = asn1.WriteConstructedTLV(exSeq, 2, true, ctExclusion, one)
		}
		chopInner = asn1.WriteConstructedTLV(chopInner, 2, true, ctExclusions, exSeq)
	}

	// minimum [1] EXPLICIT INTEGER
	if r.ChopSpecification.Minimum != 0 {
		inner := asn1.EncodeInteger[int64](int64(r.ChopSpecification.Minimum))
		chopInner = asn1.WriteConstructedTLV(chopInner, 2, true, ctMinimum, inner)
	}

	// maximum [2] EXPLICIT INTEGER
	if r.ChopSpecification.Maximum != 0 {
		inner := asn1.EncodeInteger[int64](int64(r.ChopSpecification.Maximum))
		chopInner = asn1.WriteConstructedTLV(chopInner, 2, true, ctMaximum, inner)
	}

	if len(chopInner) > 0 {
		out = asn1.WriteConstructedTLV(out, 2, true, ctChop, chopInner)
	}

	// specificationFilter [2] EXPLICIT Refinement
	if r.SpecificationFilter != nil {
		var fbuf []byte
		var err error
		if fbuf, err = encodeRefinementDER(fbuf, r.SpecificationFilter); err == nil {
			out = asn1.WriteConstructedTLV(out, 2, true, ctFilter, fbuf)
		}
	}

	return
}

func decodeSubtreeSpecification(r *SubtreeSpecification, enc []byte) (err error) {
	if len(enc) == 0 {
		err = errors.New("empty data")
		return
	}

	var p int

	ver := enc[p]
	p++
	if ver != 0x01 {
		err = errors.New("unsupported version " + strconv.FormatUint(uint64(ver), 10))
		return
	}

	for p < len(enc) && err == nil {
		var tag asn1.Tag
		var payload []byte
		if tag, payload, err = asn1.ReadConstructedTLV(enc, &p); err == nil {
			if tag.Class != 2 {
				continue
			}
			switch tag.Tag {
			case ctBase:
				err = decodeBase(r, payload)
			case ctChop:
				err = decodeChop(r, payload)
			case ctFilter:
				err = decodeSpecFilter(r, payload)
			default:
				// ignore unknown top-level tags
			}
		}
	}

	return
}

// decodeBase decodes [0] EXPLICIT UTF8String into s.Base.
func decodeBase(s *SubtreeSpecification, payload []byte) (err error) {
	if len(payload) == 0 {
		s.Base = nil
		return
	}

	var x UTF8String
	if err = x.Decode(payload); err == nil {
		s.Base = LocalName([]byte(x))
	}

	return
}

// decodeChop decodes the ChopSpecification ([1] EXPLICIT SEQUENCE) payload.
func decodeChop(s *SubtreeSpecification, payload []byte) (err error) {
	var p int
	for p < len(payload) && err == nil {
		var ct asn1.Tag
		var cp []byte
		if ct, cp, err = asn1.ReadConstructedTLV(payload, &p); err == nil {
			if ct.Class != 2 {
				continue
			}
			var itg Integer
			switch ct.Tag {
			case ctExclusions:
				err = decodeExclusions(&s.ChopSpecification, cp)
			case ctMinimum:
				itg.Decode(cp)
				s.ChopSpecification.Minimum = BaseDistance(itg.Native())
			case ctMaximum:
				itg.Decode(cp)
				s.ChopSpecification.Maximum = BaseDistance(itg.Native())
			default:
				// ignore unknown chop fields
			}
		}
	}
	return
}

// decodeExclusions decodes [0] EXPLICIT SEQUENCE OF SpecificExclusion.
func decodeExclusions(chop *ChopSpecification, payload []byte) (err error) {
	var p int
	for p < len(payload) && err == nil {
		var etag asn1.Tag
		var ep []byte

		if etag, ep, err = asn1.ReadConstructedTLV(payload, &p); err == nil {
			if etag.Class != 2 || etag.Tag != ctExclusion {
				continue
			}
			var ex SpecificExclusion
			if ex, err = decodeSpecificExclusion(ep); err == nil {
				chop.Exclusions = append(chop.Exclusions, ex)
			}
		}
	}
	return nil
}

// decodeSpecificExclusion decodes a single SpecificExclusion container payload.
func decodeSpecificExclusion(payload []byte) (ex SpecificExclusion, err error) {
	var p int
	for p < len(payload) && err == nil {
		var it asn1.Tag
		var ip []byte
		if it, ip, err = asn1.ReadConstructedTLV(payload, &p); err == nil {
			if it.Class != 2 {
				continue
			}

			var x UTF8String
			err = x.Decode(ip)

			switch it.Tag {
			case ctChopBefore:
				ex.ChopBefore = LocalName([]byte(x))
			case ctChopAfter:
				ex.ChopAfter = LocalName([]byte(x))
			default:
				// ignore unknown fields inside SpecificExclusion
			}
		}
	}
	return
}

// decodeSpecFilter decodes [2] EXPLICIT Refinement into s.SpecificationFilter.
func decodeSpecFilter(s *SubtreeSpecification, payload []byte) (err error) {
	if len(payload) == 0 {
		s.SpecificationFilter = nil
		return
	}
	var ref Refinement
	if ref, err = decodeRefinementDER(payload); err == nil {
		s.SpecificationFilter = ref
	}
	return
}
