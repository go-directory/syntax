package subspec

/*
unicode.go handles rune analysis and unicode ranging.
*/

import (
	"unicode"
	"unicode/utf8"
)

var (
	utf1Range,
	utf2aSafeRange,
	utf2bSafeRange,
	utf3SafeRange,
	utf4SafeRange *unicode.RangeTable
)

func isDigit(r rune) bool {
	return '0' <= r && r <= '9'
}

func isAlpha(r rune) bool {
	return isLAlpha(r) || isUAlpha(r)
}

func isUAlpha(r rune) bool {
	return 'A' <= r && r <= 'Z'
}

func isLAlpha(r rune) bool {
	return 'a' <= r && r <= 'z'
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
		switch rL := utf8.RuneLen(r); rL {
		case 1:
			// ASCII range w/o double-quote
			err = isSafeUTF1(string(r))
			if '"' == r && last != '\u005C' {
				err = mkerr("Unescaped double-quote; not a UTF8 Safe Character")
			}
			last = r
		case 2, 3, 4:
			// UTF2/3/4
			err = funcs[rL](string(r))
		}
	}

	return
}

func isSafeUTF1(x string) (err error) {
	z := rune([]byte(x)[0])
	if !(unicode.Is(utf1Range, z) && z != '"') {
		err = mkerr("Incompatible char for UTF0 (in ASCII Safe Range):" + x)
	}

	return
}

func isSafeUTF2(x string) (err error) {
	z := []byte(string(x))
	ch1 := rune(z[0])
	ch2 := rune(z[1])
	if !(unicode.Is(utf2aSafeRange, ch1) &&
		unicode.Is(utf2bSafeRange, ch2)) {
		err = mkerr("Incompatible chars for UTF2 (in UTF2 Safe Range): " + x)
	}

	return
}

func isSafeUTF3(x string) (err error) {
	z := []byte(string(x))
	ch1 := rune(z[0])
	ch2 := rune(z[1])
	ch3 := rune(z[2])
	if !(unicode.Is(utf3SafeRange, ch1) &&
		unicode.Is(utf2bSafeRange, ch2) &&
		unicode.Is(utf2bSafeRange, ch3)) {
		err = mkerr("Incompatible chars for UTF3 (in UTF3 Safe Range): " + x)
	}

	return
}

func isSafeUTF4(x string) (err error) {
	z := []byte(string(x))
	ch1 := rune(z[0])
	ch2 := rune(z[1])
	ch3 := rune(z[2])
	ch4 := rune(z[3])
	if !(unicode.Is(utf4SafeRange, ch1) &&
		unicode.Is(utf2bSafeRange, ch2) &&
		unicode.Is(utf2bSafeRange, ch3) &&
		unicode.Is(utf2bSafeRange, ch4)) {
		err = mkerr("Incompatible chars for UTF4 (in UTF4 Safe Range): " + x)
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

func init() {

	utf1Range = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0000, 0x007F, 1},
	}}

	utf2aSafeRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00C0, 0x00DF, 1},
	}}

	utf2bSafeRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0080, 0x00BF, 1},
	}}

	utf3SafeRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00E0, 0x00EF, 1},
	}}

	utf4SafeRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00F0, 0x00F7, 1},
	}}
}
