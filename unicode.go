package syntax

/*
unicode.go handles rune analysis and unicode ranging.
*/

import (
	"errors"
	"unicode"
)

var (
	sfold   func(rune) rune = unicode.SimpleFold
	isPunct func(rune) bool = unicode.IsPunct
)

var t61NonContiguous []rune

var (
	digits,
	lAlphas,
	uAlphas,
	uCSRange,
	ttxRange,
	t61Ranges,
	lineCharRange,
	prsRange,
	telRange,
	substrRange *unicode.RangeTable
)

var telephoneNumberRunes []rune

func isDigits(x []byte) (is bool) {
	L := len(x)
	if L == 0 {
		return false
	}

	for i := 0; i < len(x) && !is; i++ {
		is = isDigit(rune(x[i]))
	}

	return
}

// foldRune is returns the smallest rune for
// all runes in the same fold set.
func foldRune(r rune) rune {
	for {
		r2 := unicode.SimpleFold(r)
		if r2 <= r {
			return r
		}
		r = r2
	}
}

func isBase2(r rune) bool  { return '0' == r || r == '1' }
func isDigit(r rune) bool  { return '0' <= r && r <= '9' }
func isLAlpha(r rune) bool { return 'a' <= r && r <= 'z' }
func isUAlpha(r rune) bool { return 'A' <= r && r <= 'Z' }
func isAlpha(r rune) bool  { return isLAlpha(r) || isUAlpha(r) }
func isAlnum(r rune) bool  { return isDigit(r) || isAlpha(r) }

func isWHSP(ch rune) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

func runeInSlice(r rune, slice []rune) bool {
	for i := 0; i < len(slice); i++ {
		if r == slice[i] {
			return true
		}
	}

	return false
}

/*
isT61RangedRune returns a Boolean value whether rune r matches an allowed
Unicode codepoint range.
*/
func isT61RangedRune(r rune) bool {
	return unicode.IsOneOf([]*unicode.RangeTable{t61Ranges}, r)
}

/*
UTF8String        = StringValue
StringValue       = dquote *SafeUTF8Character dquote

dquote            = %x22 ; " (double quote)
SafeUTF8Character = %x00-21 / %x23-7F /   ; ASCII minus dquote

	dquote dquote /       ; escaped double quote
	%xC0-DF %x80-BF /     ; 2 byte UTF-8 character
	%xE0-EF 2(%x80-BF) /  ; 3 byte UTF-8 character
	%xF0-F7 3(%x80-BF)    ; 4 byte UTF-8 character
*/
func isSafeUTF8(x any) (err error) {
	var raw []rune
	if raw, err = assertRunes(x); err != nil {
		return
	}

	funcs := map[int]func(string) error{
		2: isSafeUTF2,
		3: isSafeUTF3,
		4: isSafeUTF4,
	}

	var last rune
	for i := 0; i < len(raw) && err == nil; i++ {
		r := raw[i]
		switch rL := runeLen(r); rL {
		case 1:
			// ASCII range w/o double-quote
			err = isSafeUTF1(string(r))
			if '"' == r && last != '\u005C' {
				err = errors.New("Unescaped double-quote; not a UTF8 Safe Character")
			}
			last = r
		case 2, 3, 4:
			// UTF2/3/4
			err = funcs[rL](string(r))
		}
	}

	return
}

func assertRunes(x any, zok ...bool) (runes []rune, err error) {
	var zerook bool
	if len(zok) > 0 {
		zerook = zok[0]
	}
	switch tv := x.(type) {
	case []rune:
		runes = tv
	case rune:
		runes = append(runes, tv)
	case byte:
		runes = append(runes, rune(tv))
	case []byte:
		runes, err = assertRunes(string(tv))
	case string:
		if len(tv) == 0 && !zerook {
			err = errorBadLength("Zero length rune", 0)
			break
		}
		runes = []rune(tv)
	default:
		err = errorBadType("Not rune compatible")
	}

	return
}

func isHex(char rune) bool {
	return ('0' <= char && char <= '9') ||
		('A' <= char && char <= 'F') ||
		('a' <= char && char <= 'f')
}

func init() {

	ttxRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0000, 0x0023, 1},
		{0x0025, 0x005B, 1},
		{0x005D, 0x00FF, 1},
	}}

	digits = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0030, 0x0039, 1},
	}}

	lAlphas = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0041, 0x005A, 1},
	}}

	uAlphas = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0061, 0x007A, 1},
	}}

	uCSRange = &unicode.RangeTable{R32: []unicode.Range32{
		{0x0000, 0xFFFF, 1},
	}}

	/*
		t61NonContiguous contains all non-contiguous characters (i.e.: those NOT incorporated
		through the t61Ranges *unicode.RangeTable instance) that are allowed per T.61.  These
		characters are as follows:

		  - '\u009B' (�, npc)
		  - '\u005C' (\)
		  - '\u005D' (])
		  - '\u005F' (_)
		  - '\u003F' (?)
		  - '\u007C' ([)
		  - '\u007F' (])
		  - '\u001d' (SS3, npc)
		  - '\u0111' (đ)
		  - '\u0138' (ĸ)
		  - '\u0332' ( ̲)
		  - '\u2126' (Ω)
		  - '\u013F' (Ŀ)
		  - '\u014B' (ŋ)
	*/
	t61NonContiguous = []rune{
		'\u009B',
		'\u005C',
		'\u005D',
		'\u005F',
		'\u003F',
		'\u007C',
		'\u007F',
		'\u001d',
		'\u0111',
		'\u0138',
		'\u0332',
		'\u2126',
		'\u013F',
		'\u014B',
	}

	prsRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0020, 0x0020, 1},
		{0x0027, 0x0029, 1},
		{0x002b, 0x002f, 1},
		{0x003a, 0x003a, 1},
		{0x003f, 0x003f, 1},
	}}

	telRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0020, 0x0020, 1},
		{0x0022, 0x0022, 1},
		{0x0027, 0x0027, 1},
		{0x0028, 0x0028, 1},
		{0x002b, 0x002f, 1},
		{0x003a, 0x003a, 1},
		{0x003f, 0x003f, 1},
		{0x005c, 0x005c, 1},
	}}

	/*
		t61Ranges defines a *unicode.RangeTable instance containing specific
		16-bit and 32-bit character ranges that (partially) describe allowed
		Unicode codepoints within a given T.61 value.

		See also the t61NonContiguous global variable.
	*/
	t61Ranges = &unicode.RangeTable{

		// 16-bit Unicode codepoints.
		R16: []unicode.Range16{
			{0x0009, 0x000f, 1}, // TAB through SHIFT-IN
			{0x0020, 0x0039, 1}, // ' ' .. '9'
			{0x0041, 0x005B, 1}, // 'a' .. '['
			{0x0061, 0x007A, 1}, // 'A' .. 'Z'
			{0x00A0, 0x00FF, 1},
			{0x008B, 0x008C, 1},
		},

		// 32-bit Unicode codepoints.
		R32: []unicode.Range32{
			{0x0126, 0x0127, 1},
			{0x0131, 0x0132, 1},
			{0x0140, 0x0142, 1},
			{0x0149, 0x014A, 1},
			{0x0152, 0x0153, 1},
			{0x0166, 0x0167, 1},
			{0x0300, 0x0304, 1},
			{0x0306, 0x0308, 1},
			{0x030A, 0x030C, 1},
			{0x0327, 0x0328, 1},
		},
	}

	lineCharRange = &unicode.RangeTable{R16: []unicode.Range16{
		// ASCII 00 through 7F with two exclusions ...
		{0x0000, 0x0023, 1}, // skip DOLLAR
		{0x0025, 0x005B, 1}, // skip ESC
		{0x005D, 0x007F, 1},
	}}

	substrRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0000, 0x0029, 1},
		{0x002B, 0x005B, 1},
		{0x005D, 0x007F, 1},
	}}
}
