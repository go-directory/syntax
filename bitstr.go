package syntax

/*
bitstring.go implements the ASN.1 BIT STRING type and methods.

Note that some of this originated in Go's encoding/asn1 package,
namely the BitString.At and BitString.RightAlign methods.
*/

/*
BitString implements [§ 3.3.2 of RFC 4517] and [§ 22 of ITU-T Rec. X.680].

The ABNF below describes the LDAP specific encoding of values of this type.

	BitString    = SQUOTE *binary-digit SQUOTE "B"
	binary-digit = "0" / "1"

	SQUOTE  = %x27 ; single quote ("'") // RFC 4512

The ASN.1 BIT STRING type definition originates in [§ 22 of ITU-T Rec. X.680].

	BitStringType ::=
	     BIT STRING
	   | BIT STRING "{" NamedBitList "}"

[§ 22 of ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
[§ 3.3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.2

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
type BitString struct {
	Bytes     []byte // bits packed into bytes.
	BitLength int    // length in bits.
}

/*
String returns the string representation of the receiver instance.
*/
func (b BitString) String() string {
	if b.BitLength == 0 {
		return "''B"
	}

	// reconstruct bits from Bytes using BitLength
	out := make([]byte, b.BitLength)
	for i := 0; i < b.BitLength; i++ {
		byteIndex := i / 8
		bitPos := 7 - (i % 8)
		bit := (b.Bytes[byteIndex] >> bitPos) & 1
		if bit == 0 {
			out[i] = '0'
		} else {
			out[i] = '1'
		}
	}

	// wrap in ASN.1 BIT STRING literal form
	return "'" + b2s(out) + "'B"
}

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the receiver instance as an ASN.1 BIT STRING.
*/
func (r BitString) Encode() ([]byte, error) {
	if r.BitLength < 0 {
		return nil, errInvalidBitStrBitLen
	}
	if len(r.Bytes) == 0 && r.BitLength != 0 {
		return nil, errInvalidBitStrBitLen
	}

	// Compute padding bits
	pad := (8 - (r.BitLength & 7)) & 7

	// BIT STRING value = [pad][bytes...]
	v := make([]byte, 1+len(r.Bytes))
	v[0] = byte(pad)
	copy(v[1:], r.Bytes)

	return encodeP(tBit, v)
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance.  The encoding must
not be truncated, and must bear the ASN.1 BIT STRING tag (0x03).
*/
func (r *BitString) Decode(enc []byte) error {
	p := 0

	v, err := readEPTLV(enc, &p, classU, uint32(tBit))
	if err != nil {
		return err
	}

	if len(v) == 0 {
		return errInvalidBitStrLen
	}

	pad := int(v[0])
	if pad > 7 {
		return errInvalidBitStrPadCt
	}

	if len(v) == 1 && pad != 0 {
		return errInvalidBitStrPadEmpty
	}

	// Validate padding bits in last byte
	if pad > 0 {
		last := v[len(v)-1]
		mask := byte((1 << pad) - 1)
		if last&mask != 0 {
			return errInvalidBitStrNonZeroPad
		}
	}

	r.BitLength = (len(v)-1)*8 - pad
	r.Bytes = v[1:]

	return nil
}

/*
Set enables the specified bit value within the receiver instance.
*/
func (r *BitString) Set(pos int) {
	if pos < 0 {
		return
	}

	// Ensure capacity
	byteIndex := pos >> 3
	bitOffset := 7 - (pos & 7) // MSB‑first

	if byteIndex >= len(r.Bytes) {
		newBytes := make([]byte, byteIndex+1)
		copy(newBytes, r.Bytes)
		r.Bytes = newBytes
	}

	// Set the bit
	r.Bytes[byteIndex] |= (1 << bitOffset)

	// Update bit length if needed
	if pos+1 > r.BitLength {
		r.BitLength = pos + 1
	}
}

/*
Unset clears the specified bit from the receiver instance.
*/
func (r *BitString) Unset(pos int) {
	if pos < 0 {
		return
	}

	byteIndex := pos >> 3
	if byteIndex >= len(r.Bytes) {
		return
	}

	bitOffset := 7 - (pos & 7)
	r.Bytes[byteIndex] &^= (1 << bitOffset)
}

/*
Has returns a Boolean value indicative of the specified
bit being set.
*/
func (r BitString) Has(pos int) bool {
	if pos < 0 {
		return false
	}

	byteIndex := pos >> 3
	if byteIndex >= len(r.Bytes) {
		return false
	}

	bitOffset := 7 - (pos & 7)
	return (r.Bytes[byteIndex] & (1 << bitOffset)) != 0
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r BitString) IsZero() bool { return &r == nil }

/*
BitString returns instance of [BitString] alongside an error following
an attempt to parse x in the context of an ASN.1 BIT STRING.

The input value must use the LDAP specific encoding defined in [§ 3.3.2
of RFC 4517].
[§ 3.3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.2
*/
func NewBitString(x any) (bs BitString, err error) {
	bs, err = marshalBitString(x)
	return
}

/*
At returns the bit at the given index. If the index is out of range it
returns 0.

Disclaimer: copied from Go's "encoding/asn1" package.
*/
func (r BitString) At(i int) int {
	if i < 0 || i >= r.BitLength {
		return 0
	}
	x := i / 8
	y := 7 - uint(i%8)
	return int(r.Bytes[x]>>y) & 1
}

/*
RightAlign returns a slice where the padding bits are at the beginning. The
slice may share memory with the [BitString].

Disclaimer: copied from Go's "encoding/asn1" package.
*/
func (r BitString) RightAlign() []byte {
	shift := uint(8 - (r.BitLength % 8))
	if shift == 8 || len(r.Bytes) == 0 {
		return r.Bytes
	}

	a := make([]byte, len(r.Bytes))
	a[0] = r.Bytes[0] >> shift
	for i := 1; i < len(r.Bytes); i++ {
		a[i] = r.Bytes[i-1] << (8 - shift)
		a[i] |= r.Bytes[i] >> shift
	}

	return a
}

/*
parseBitString parses an ASN.1 bit string from the given byte slice and returns it.
*/
func parseBitString(bytes []byte) (ret BitString, err error) {
	if len(bytes) == 0 {
		err = errInvalidBitStrLen
		return
	}
	paddingBits := int(bytes[0])
	if paddingBits > 7 ||
		len(bytes) == 1 && paddingBits > 0 ||
		bytes[len(bytes)-1]&((1<<bytes[0])-1) != 0 {
		err = errInvalidBitStrBadPad
		return
	}
	ret.BitLength = (len(bytes)-1)*8 - paddingBits
	ret.Bytes = bytes[1:]
	return
}

func bitString(x any) (result bool, err error) {
	_, err = marshalBitString(x)
	result = err == nil
	return
}

func marshalBitString(x any) (bs BitString, err error) {
	var raw []byte
	if raw, err = assertBitString(x); err != nil {
		return
	}
	if raw, err = verifyBitStringContents(raw); err != nil {
		return
	}

	// raw is the bit chars between quotes, e.g. "010101110101"
	n := len(raw)
	if n == 0 {
		err = errorBadLength("BitString", 0)
		return
	}

	// MSB-first packing, DER-style
	bytes := make([]byte, (n+7)/8)
	for i := 0; i < n; i++ {
		if raw[i] == '0' {
			continue
		}
		byteIndex := i / 8
		bitPos := 7 - (i % 8)
		bytes[byteIndex] |= 1 << bitPos
	}

	bs = BitString{
		Bytes:     bytes,
		BitLength: n,
	}
	return
}

func assertBitString(x any) (raw []byte, err error) {
	switch tv := x.(type) {
	case []byte:
		if len(tv) == 0 {
			err = errorBadLength("BitString", 0)
			break
		}
		raw = tv
	case string:
		raw, err = assertBitString(s2b(tv))
	default:
		err = errorBadType("BitString")
	}

	return
}

func verifyBitStringContents(raw []byte) ([]byte, error) {
	var err error

	// Last char MUST be 'B' rune, else die.
	if term := raw[len(raw)-1]; term != 'B' {
		err = syntaxError("BIT STRING: incompatible terminating character: ",
			string(term))
		return raw, err
	}

	// Trim terminating char
	raw = raw[:len(raw)-1]

	// Make sure there are enough remaining
	// characters to actually do something.
	if len(raw) < 3 {
		err = syntaxError("BIT STRING: incompatible remaining length: ",
			fint(int64(len(raw)), 10))
		return raw, err
	}

	// Verify (and then remove) single quotes
	L := raw[0]
	R := raw[len(raw)-1]
	if L != '\'' || R != '\'' {
		err = syntaxError("BIT STRING: incompatible encapsulating characters: ",
			string(L), "/", string(R))
		return raw, err
	}
	raw = raw[1 : len(raw)-1]

	for i := 0; i < len(raw); i++ {
		if !isBase2(rune(raw[i])) {
			err = syntaxError("BIT STRING: incompatible non-binary character: ",
				string(raw[i]))
			break
		}
	}

	return raw, err
}

/*
bitStringMatch returns a Boolean value indicative of a BitStringMatch
as described in [§ 4.2.1 of RFC 4517].

OID: 2.5.13.16

[§ 4.2.1 of RFC 4517]: https://www.rfc-editor.org/rfc/rfc4517#section-4.2.1
*/
func bitStringMatch(a, b any) (result bool, err error) {
	var abs, bbs BitString

	if abs, err = marshalBitString(a); err != nil {
		return
	}

	abytes := abs.Bytes
	abits := abs.BitLength

	if bbs, err = marshalBitString(b); err != nil {
		return
	}

	bbytes := bbs.Bytes
	bbits := bbs.BitLength

	// Check if both bit strings have the same number of bits
	if abits == bbits {
		// Compare bit strings bitwise
		result = true
		for i := 0; i < len(abytes) && result; i++ {
			result = abytes[i] == bbytes[i]
		}
	}

	return
}

var (
	errInvalidBitStrEncoding   = syntaxError("BIT STRING: invalid encoding")
	errInvalidBitStrBitLen     = syntaxError("BIT STRING: invalid BitLength")
	errInvalidBitStrLen        = syntaxError("BIT STRING: zero length")
	errInvalidBitStrPadCt      = syntaxError("BIT STRING: invalid padding count")
	errInvalidBitStrPadEmpty   = syntaxError("BIT STRING: padding but no data")
	errInvalidBitStrNonZeroPad = syntaxError("BIT STRING: nonzero padding bits")
	errInvalidBitStrBadPad     = syntaxError("BIT STRING: invalid padding bits")
)
