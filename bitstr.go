package syntax

/*
bitstring.go implements the ASN.1 BIT STRING type and methods.
*/

import (
	"strconv"
)

/*
BitString implements [§ 3.3.2 of RFC 4517]:

	BitString    = SQUOTE *binary-digit SQUOTE "B"
	binary-digit = "0" / "1"

From [§ 1.4 of RFC 4512]:

	SQUOTE  = %x27 ; single quote ("'")

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.2
*/
type BitString struct {
	Bytes     []byte // bits packed into bytes.
	BitLength int    // length in bits.
}

/*
String returns the string representation of the receiver instance.
*/
func (r BitString) String() (bs string) {
	if len(r.Bytes)*8 == r.BitLength {
		for _, b := range r.Bytes {
			bs += strconv.FormatUint(uint64(b), 2)
		}

		bs = string(rune('\'')) + bs +
			string(rune('\'')) +
			string(rune('B'))
	}

	return
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r BitString) IsZero() bool { return &r == nil }

/*
BitString returns an error following an analysis of x in the context of
an ASN.1 BIT STRING.
*/
func NewBitString(x any) (bs BitString, err error) {
	bs, err = marshalBitString(x)
	return
}

func bitString(x any) (result bool, err error) {
	_, err = marshalBitString(x)
	result = err == nil

	return
}

func marshalBitString(x any) (bs BitString, err error) {
	var raw []byte
	if raw, err = assertBitString(x); err == nil {
		if raw, err = verifyBitStringContents(raw); err == nil {
			var tx string
			var bss BitString

			for i := len(raw); i > 0 && err == nil; i -= 8 {
				tx = string(raw[:i])
				if i-8 >= 0 {
					tx = string(raw[i-8 : i])
				}

				var bd uint64
				bd, err = strconv.ParseUint(tx, 2, 8)
				bss.Bytes = append(bss.Bytes, []byte{byte(bd)}...)
			}

			if err == nil {
				bss.BitLength = len(bss.Bytes) * 8
				bs = BitString(bss)
			}
		}
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
		raw, err = assertBitString([]byte(tv))
	default:
		err = errorBadType("BitString")
	}

	return
}

func verifyBitStringContents(raw []byte) ([]byte, error) {
	var err error

	// Last char MUST be 'B' rune, else die.
	if term := raw[len(raw)-1]; term != 'B' {
		err = syntaxError("Incompatible terminating character for BitString: ", string(term))
		return raw, err
	}

	// Trim terminating char
	raw = raw[:len(raw)-1]

	// Make sure there are enough remaining
	// characters to actually do something.
	if len(raw) < 3 {
		err = syntaxError("Incompatible remaining length for BitString: ",
			strconv.FormatInt(int64(len(raw)), 10))
		return raw, err
	}

	// Verify (and then remove) single quotes
	L := raw[0]
	R := raw[len(raw)-1]
	if L != '\'' || R != '\'' {
		err = syntaxError("Incompatible encapsulating characters BitString: ", string(L), "/", string(R))
		return raw, err
	}
	raw = raw[1 : len(raw)-1]

	for i := 0; i < len(raw); i++ {
		if !(rune(raw[i]) == '0' || rune(raw[i]) == '1') {
			err = syntaxError("Incompatible non-binary character for BitString", string(raw[i]))
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

	// TODO
	//if namedBitList {
	//        // Remove trailing zero bits
	//        abits = stripTrailingZeros(abytes, abits)
	//        bbits = stripTrailingZeros(bbytes, bbits)
	//}

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

// stripTrailingZeros removes trailing zero bits and returns the new bit length
func stripTrailingZeros(bytes []byte, bitLength int) (blen int) {
	blen = bitLength
	for i := len(bytes) - 1; i >= 0; i-- {
		for bit := 0; bit < 8; bit++ {
			if (bytes[i] & (1 << bit)) != 0 {
				return blen
			}
			blen--
		}
	}

	return
}
