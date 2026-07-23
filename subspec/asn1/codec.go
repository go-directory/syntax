package asn1

/*
codec.go implements SubtreeSpecification ASN.1 DER encoding/decoding.
*/

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strconv"

	"github.com/go-directory/syntax/subspec"
)

// Universal tags
const (
	tagUTF8String = 0x0C
	tagInteger    = 0x02
	tagSequence   = 0x10
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

	// Refinement choice tags
	ctRefAnd  = 0
	ctRefOr   = 1
	ctRefNot  = 2
	ctRefItem = 3
)

// writeTag writes class+constructed+tagNumber (supports high-tag-number form).
// class: 0=universal, 1=application, 2=context-specific, 3=private
func writeTag(w io.Writer, class byte, constructed bool, tagNum uint32) error {
	var first byte
	first = (class << 6)
	if constructed {
		first |= 0x20
	}
	if tagNum < 31 {
		first |= byte(tagNum)
		if _, err := w.Write([]byte{first}); err != nil {
			return err
		}
		return nil
	}
	// high-tag-number form
	first |= 0x1F
	if _, err := w.Write([]byte{first}); err != nil {
		return err
	}
	// encode tagNum in base-128 big-endian with MSB continuation
	var buf [6]byte
	i := len(buf)
	n := tagNum
	for {
		i--
		buf[i] = byte(n & 0x7F)
		n >>= 7
		if n == 0 {
			break
		}
	}
	// set continuation bits except last
	for j := i; j < len(buf)-1; j++ {
		buf[j] |= 0x80
	}
	_, err := w.Write(buf[i:])
	return err
}

func writeLength(w io.Writer, n int) error {
	if n < 0 {
		return errors.New("negative length")
	}
	if n <= 127 {
		_, err := w.Write([]byte{byte(n)})
		return err
	}
	// long form
	var tmp [8]byte
	l := 0
	v := uint64(n)
	for v > 0 {
		tmp[l] = byte(v & 0xFF)
		v >>= 8
		l++
	}
	if l > 8 {
		return errors.New("length too large")
	}
	if _, err := w.Write([]byte{0x80 | byte(l)}); err != nil {
		return err
	}
	for i := l - 1; i >= 0; i-- {
		if _, err := w.Write([]byte{tmp[i]}); err != nil {
			return err
		}
	}
	return nil
}

func writeTLV(w io.Writer, class byte, constructed bool, tagNum uint32, payload []byte) error {
	if err := writeTag(w, class, constructed, tagNum); err != nil {
		return err
	}
	if err := writeLength(w, len(payload)); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

type asn1Tag struct {
	class       byte
	constructed bool
	tagNum      uint32
}

func readTag(r io.Reader) (asn1Tag, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return asn1Tag{}, err
	}
	bt := b[0]
	class := bt >> 6
	constructed := (bt & 0x20) != 0
	tagNum := uint32(bt & 0x1F)
	if tagNum == 0x1F {
		// high-tag-number
		var n uint32
		for {
			if _, err := io.ReadFull(r, b[:]); err != nil {
				return asn1Tag{}, err
			}
			n = (n << 7) | uint32(b[0]&0x7F)
			if b[0]&0x80 == 0 {
				break
			}
		}
		tagNum = n
	}
	return asn1Tag{class: class, constructed: constructed, tagNum: tagNum}, nil
}

func readLength(r io.Reader) (int, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	first := b[0]
	if first&0x80 == 0 {
		return int(first), nil
	}
	n := int(first & 0x7F)
	if n == 0 || n > 8 {
		return 0, errors.New("unsupported length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	val := 0
	for i := 0; i < n; i++ {
		val = (val << 8) | int(buf[i])
	}
	return val, nil
}

func readTLV(r io.Reader) (asn1Tag, []byte, error) {
	tag, err := readTag(r)
	if err != nil {
		return tag, nil, err
	}
	l, err := readLength(r)
	if err != nil {
		return tag, nil, err
	}
	if l == 0 {
		return tag, nil, nil
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return tag, nil, err
	}
	return tag, buf, nil
}

func encodeDERInteger(v int64) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(v))
	// find minimal two's complement representation
	i := 0
	for i < 7 {
		// drop leading 0x00 if next byte high bit is 0
		if tmp[i] == 0x00 && tmp[i+1]&0x80 == 0 {
			i++
			continue
		}
		// drop leading 0xFF if next byte high bit is 1
		if tmp[i] == 0xFF && tmp[i+1]&0x80 != 0 {
			i++
			continue
		}
		break
	}
	return append([]byte{}, tmp[i:]...)
}

func decodeDERInteger(b []byte) (int64, error) {
	if len(b) == 0 {
		return 0, errors.New("empty integer")
	}
	var tmp [8]byte
	// sign extend
	if b[0]&0x80 != 0 {
		for i := 0; i < 8-len(b); i++ {
			tmp[i] = 0xFF
		}
	}
	copy(tmp[8-len(b):], b)
	return int64(binary.BigEndian.Uint64(tmp[:])), nil
}

func encodeUTF8StringTLV(s string) []byte {
	var buf bytes.Buffer
	_ = writeTLV(&buf, 0, false, tagUTF8String, []byte(s))
	return buf.Bytes()
}

func encodeIntegerTLV(v int64) []byte {
	var buf bytes.Buffer
	_ = writeTLV(&buf, 0, false, tagInteger, encodeDERInteger(v))
	return buf.Bytes()
}

func decodeUTF8StringFromTLV(b []byte) (string, error) {
	r := bytes.NewReader(b)
	tag, payload, err := readTLV(r)
	if err != nil {
		return "", err
	}
	if tag.class != 0 || tag.tagNum != tagUTF8String {
		return "", errors.New("expected UTF8String universal tag, got class=" +
			strconv.FormatUint(uint64(tag.class), 10) + " tag=" +
			strconv.FormatUint(uint64(tag.tagNum), 10))
	}
	return string(payload), nil
}

func decodeIntegerFromTLV(b []byte) (int64, error) {
	r := bytes.NewReader(b)
	tag, payload, err := readTLV(r)
	if err != nil {
		return 0, err
	}
	if tag.class != 0 || tag.tagNum != tagInteger {
		return 0, errors.New("expected INTEGER universal tag, got class=" +
			strconv.FormatUint(uint64(tag.class), 10) + " tag=" +
			strconv.FormatUint(uint64(tag.tagNum), 10))
	}
	return decodeDERInteger(payload)
}

func encodeRefinementDER(w io.Writer, r subspec.Refinement) error {
	if r == nil {
		return nil
	}
	switch v := r.(type) {
	case subspec.RefinementAnd:
		var inner bytes.Buffer
		// each child is encoded as a full explicit refinement TLV
		for i := 0; i < v.Len(); i++ {
			var childBuf bytes.Buffer
			if err := encodeRefinementDER(&childBuf, v.Index(i)); err != nil {
				return err
			}
			// childBuf already contains a context-tagged TLV; append it
			inner.Write(childBuf.Bytes())
		}
		// wrap inner with context [ctRefAnd] constructed
		return writeTLV(w, 2, true, ctRefAnd, inner.Bytes())
	case subspec.RefinementOr:
		var inner bytes.Buffer
		for i := 0; i < v.Len(); i++ {
			var childBuf bytes.Buffer
			if err := encodeRefinementDER(&childBuf, v.Index(i)); err != nil {
				return err
			}
			inner.Write(childBuf.Bytes())
		}
		return writeTLV(w, 2, true, ctRefOr, inner.Bytes())
	case subspec.RefinementNot:
		var childBuf bytes.Buffer
		if err := encodeRefinementDER(&childBuf, v.Refinement); err != nil {
			return err
		}
		return writeTLV(w, 2, true, ctRefNot, childBuf.Bytes())
	case subspec.RefinementItem:
		// inner is universal UTF8String TLV, then wrap explicitly
		inner := encodeUTF8StringTLV(string(v))
		return writeTLV(w, 2, true, ctRefItem, inner)
	default:
		return nil
	}
}

func decodeRefinementDER(b []byte) (subspec.Refinement, error) {
	r := bytes.NewReader(b)
	tag, payload, err := readTLV(r)
	if err != nil {
		return nil, err
	}
	if tag.class != 2 {
		return nil, errors.New("expected context-specific refinement tag, got class " +
			strconv.FormatUint(uint64(tag.class), 10))
	}
	switch tag.tagNum {
	case ctRefItem:
		// payload should contain a universal UTF8String TLV
		s, err := decodeUTF8StringFromTLV(payload)
		if err != nil {
			return nil, err
		}
		return subspec.RefinementItem(s), nil
	case ctRefNot:
		// payload contains a single child context TLV
		child, err := decodeRefinementDER(payload)
		if err != nil {
			return nil, err
		}
		return subspec.RefinementNot{Refinement: child}, nil
	case ctRefAnd:
		pr := bytes.NewReader(payload)
		var arr subspec.RefinementAnd
		for pr.Len() > 0 {
			t, p, err := readTLV(pr)
			if err != nil {
				return nil, err
			}
			// reconstruct full TLV bytes for recursive decode
			var full bytes.Buffer
			_ = writeTag(&full, t.class, t.constructed, t.tagNum)
			_ = writeLength(&full, len(p))
			full.Write(p)
			child, err := decodeRefinementDER(full.Bytes())
			if err != nil {
				return nil, err
			}
			arr = append(arr, child)
		}
		return arr, nil
	case ctRefOr:
		pr := bytes.NewReader(payload)
		var arr subspec.RefinementOr
		for pr.Len() > 0 {
			t, p, err := readTLV(pr)
			if err != nil {
				return nil, err
			}
			var full bytes.Buffer
			_ = writeTag(&full, t.class, t.constructed, t.tagNum)
			_ = writeLength(&full, len(p))
			full.Write(p)
			child, err := decodeRefinementDER(full.Bytes())
			if err != nil {
				return nil, err
			}
			arr = append(arr, child)
		}
		return arr, nil
	default:
		return nil, errors.New("unknown refinement tag " +
			strconv.FormatUint(uint64(tag.tagNum), 10))
	}
}

/*
Encode returns []byte alongside an error following an attempt to DER encode
the input [subspec.SubtreeSpecification] instance.
*/
func Encode(s subspec.SubtreeSpecification) ([]byte, error) {
	var out bytes.Buffer
	out.WriteByte(0x01) // version

	// base [0] EXPLICIT UTF8String
	if len(s.Base) > 0 {
		inner := encodeUTF8StringTLV(string(s.Base))
		if err := writeTLV(&out, 2, true, ctBase, inner); err != nil {
			return nil, err
		}
	}

	// chopSpecification [1] EXPLICIT SEQUENCE
	var chopInner bytes.Buffer
	// exclusions [0] EXPLICIT SEQUENCE OF SpecificExclusion
	if len(s.ChopSpecification.Exclusions) > 0 {
		var exSeq bytes.Buffer
		for _, ex := range s.ChopSpecification.Exclusions {
			var one bytes.Buffer
			if len(ex.ChopBefore) > 0 {
				inner := encodeUTF8StringTLV(string(ex.ChopBefore))
				_ = writeTLV(&one, 2, true, ctChopBefore, inner)
			}
			if len(ex.ChopAfter) > 0 {
				inner := encodeUTF8StringTLV(string(ex.ChopAfter))
				_ = writeTLV(&one, 2, true, ctChopAfter, inner)
			}
			// wrap SpecificExclusion as context [ctExclusion] constructed
			_ = writeTLV(&exSeq, 2, true, ctExclusion, one.Bytes())
		}
		_ = writeTLV(&chopInner, 2, true, ctExclusions, exSeq.Bytes())
	}
	// minimum [1] EXPLICIT INTEGER
	if s.ChopSpecification.Minimum != 0 {
		inner := encodeIntegerTLV(int64(s.ChopSpecification.Minimum))
		_ = writeTLV(&chopInner, 2, true, ctMinimum, inner)
	}
	// maximum [2] EXPLICIT INTEGER
	if s.ChopSpecification.Maximum != 0 {
		inner := encodeIntegerTLV(int64(s.ChopSpecification.Maximum))
		_ = writeTLV(&chopInner, 2, true, ctMaximum, inner)
	}
	if chopInner.Len() > 0 {
		if err := writeTLV(&out, 2, true, ctChop, chopInner.Bytes()); err != nil {
			return nil, err
		}
	}

	// specificationFilter [2] EXPLICIT Refinement
	if s.SpecificationFilter != nil {
		var fbuf bytes.Buffer
		if err := encodeRefinementDER(&fbuf, s.SpecificationFilter); err != nil {
			return nil, err
		}
		if err := writeTLV(&out, 2, true, ctFilter, fbuf.Bytes()); err != nil {
			return nil, err
		}
	}

	return out.Bytes(), nil
}

/*
Decode returns an instance of [subspec.SubtreeSpecification] alongside
an error following an attempt to decode the input DER bytes.
*/
func Decode(data []byte) (subspec.SubtreeSpecification, error) {
	var s subspec.SubtreeSpecification
	if len(data) == 0 {
		return s, errors.New("empty data")
	}
	r := bytes.NewReader(data)

	ver, err := r.ReadByte()
	if err != nil {
		return s, err
	}
	if ver != 0x01 {
		return s, errors.New("unsupported version " + strconv.FormatUint(uint64(ver), 10))
	}

	for r.Len() > 0 {
		tag, payload, err := readTLV(r)
		if err != nil {
			return s, err
		}
		if tag.class != 2 {
			continue
		}
		switch tag.tagNum {
		case ctBase:
			if err := decodeBase(&s, payload); err != nil {
				return s, err
			}
		case ctChop:
			if err := decodeChop(&s, payload); err != nil {
				return s, err
			}
		case ctFilter:
			if err := decodeFilter(&s, payload); err != nil {
				return s, err
			}
		default:
			// ignore unknown top-level tags
		}
	}
	return s, nil
}

// decodeBase decodes [0] EXPLICIT UTF8String into s.Base.
func decodeBase(s *subspec.SubtreeSpecification, payload []byte) error {
	if len(payload) == 0 {
		s.Base = ""
		return nil
	}
	str, err := decodeUTF8StringFromTLV(payload)
	if err != nil {
		return err
	}
	s.Base = subspec.LocalName(str)
	return nil
}

// decodeChop decodes the ChopSpecification ([1] EXPLICIT SEQUENCE) payload.
func decodeChop(s *subspec.SubtreeSpecification, payload []byte) error {
	pr := bytes.NewReader(payload)
	for pr.Len() > 0 {
		ct, cp, err := readTLV(pr)
		if err != nil {
			return err
		}
		if ct.class != 2 {
			continue
		}
		switch ct.tagNum {
		case ctExclusions:
			if err := decodeExclusions(&s.ChopSpecification, cp); err != nil {
				return err
			}
		case ctMinimum:
			v, err := decodeIntegerFromTLV(cp)
			if err != nil {
				return err
			}
			s.ChopSpecification.Minimum = subspec.BaseDistance(v)
		case ctMaximum:
			v, err := decodeIntegerFromTLV(cp)
			if err != nil {
				return err
			}
			s.ChopSpecification.Maximum = subspec.BaseDistance(v)
		default:
			// ignore unknown chop fields
		}
	}
	return nil
}

// decodeExclusions decodes [0] EXPLICIT SEQUENCE OF SpecificExclusion.
func decodeExclusions(chop *subspec.ChopSpecification, payload []byte) error {
	pr2 := bytes.NewReader(payload)
	for pr2.Len() > 0 {
		etag, ep, err := readTLV(pr2)
		if err != nil {
			return err
		}
		if etag.class != 2 || etag.tagNum != ctExclusion {
			continue
		}
		ex, err := decodeSpecificExclusion(ep)
		if err != nil {
			return err
		}
		chop.Exclusions = append(chop.Exclusions, ex)
	}
	return nil
}

// decodeSpecificExclusion decodes a single SpecificExclusion container payload.
func decodeSpecificExclusion(payload []byte) (subspec.SpecificExclusion, error) {
	var ex subspec.SpecificExclusion
	er := bytes.NewReader(payload)
	for er.Len() > 0 {
		it, ip, err := readTLV(er)
		if err != nil {
			return ex, err
		}
		if it.class != 2 {
			continue
		}
		switch it.tagNum {
		case ctChopBefore:
			str, err := decodeUTF8StringFromTLV(ip)
			if err != nil {
				return ex, err
			}
			ex.ChopBefore = subspec.LocalName(str)
		case ctChopAfter:
			str, err := decodeUTF8StringFromTLV(ip)
			if err != nil {
				return ex, err
			}
			ex.ChopAfter = subspec.LocalName(str)
		default:
			// ignore unknown fields inside SpecificExclusion
		}
	}
	return ex, nil
}

// decodeFilter decodes [2] EXPLICIT Refinement into s.SpecificationFilter.
func decodeFilter(s *subspec.SubtreeSpecification, payload []byte) error {
	if len(payload) == 0 {
		s.SpecificationFilter = nil
		return nil
	}
	ref, err := decodeRefinementDER(payload)
	if err != nil {
		return err
	}
	s.SpecificationFilter = ref
	return nil
}
