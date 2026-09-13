package syntax

import (
	"testing"
)

func TestTelexNumber(t *testing.T) {
	for _, raw := range []string{
		`12345$US$getrac`,
	} {
		if tn, err := NewTelexNumber(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := tn.String(); got != raw {
			t.Errorf("%s failed:\n\twant:%s\n\tgot: %s\n",
				t.Name(), raw, got)
		}
	}

	NewTelexNumber(``)
	NewTelexNumber(`333`)
	NewTelexNumber(`3\$3__3`)
}

func TestTeletexTerminalIdentifier(t *testing.T) {
	for _, raw := range []string{
		`P$graphic:abcd$misc:123`,
		`P$control:a`,
		`P$graphic:abf$page:`,
		`P$control:abge$private:hi`,
	} {
		if tti, err := NewTeletexTerminalIdentifier(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := tti.String(); got != raw {
			t.Errorf("%s failed:\n\twant:%s\n\tgot: %s\n",
				t.Name(), raw, got)
		}
	}
}

func TestFacsimileTelephoneNumber(t *testing.T) {
	for _, raw := range []string{
		`+1 555 555 0280$b4Length$uncompressed$twoDimensional`,
	} {
		if f, err := NewFacsimileTelephoneNumber(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
			return
		} else if got := f.String(); len(got) != len(raw) {
			t.Errorf("%s failed:\n\twant:%s\n\tgot: %s\n",
				t.Name(), raw, got)
			return
		}
	}

	var tel FacsimileTelephoneNumber
	_ = tel.String()

	tel, _ = NewFacsimileTelephoneNumber(``)
	_ = tel.String()

	tel, _ = NewFacsimileTelephoneNumber(`A`)
	_ = tel.String()

	tel, _ = NewFacsimileTelephoneNumber(`+1 555 555 0280$b4Length$uncompressed$twoDimensional`)
	_ = tel.String()
	tel.set(uint(32))
	tel.set(uint(2))
}

func TestTelephoneNumber_SubstringMatch(t *testing.T) {
	for key, value := range map[string][]byte{
		`+1 555 555 FILK`: []byte(`+1*55555F*LK`),
	} {
		if result, err := telephoneNumberSubstringsMatch([]byte(key), value); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if !result {
			t.Errorf("%s failed:\nwant: %t\ngot:  %t",
				t.Name(), true, result)
		}
	}
}

func TestTelephoneNumber(t *testing.T) {
	for _, raw := range []string{
		`+1 555 555 0280`,
		`+1 800 GOT MILK`,
		`+1555FILK`,
	} {
		if tel, err := NewTelephoneNumber(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := tel.String(); got != raw {
			t.Errorf("%s failed:\n\twant:%s\n\tgot: %s\n",
				t.Name(), raw, got)
		}
	}

	var tel TelephoneNumber
	_ = tel.String()

	tel, _ = NewTelephoneNumber(``)
	_ = tel.String()

	tel, _ = NewTelephoneNumber(`1`)
	_ = tel.String()
}

func TestTelephony_codecov(t *testing.T) {
	_, _ = NewFacsimileTelephoneNumber(`\$`)
	_, _ = NewFacsimileTelephoneNumber(` $ `)
	_, _ = NewFacsimileTelephoneNumber(`twoDimensional$twoDimensional$`)

	_, _ = telephoneNumberMatch(`+1 555 555 FILK`, `+1 555 555 FILM`)

	_, _, _ = prepareTelephoneNumberAssertion(`+1 555 555 FILK`, `fh`)
	_, _, _ = prepareTelephoneNumberAssertion(`+1 555 555 FILK`, struct{}{})
	_, _, _ = prepareTelephoneNumberAssertion(nil, struct{}{})
	_, _, _ = prepareTelephoneNumberAssertion(struct{}{}, nil)

	_, _ = NewTelephoneNumber(nil)
	_, _ = NewTelephoneNumber(`naïve§`)
	_, _ = marshalTelephoneNumber(`+@@@AX`)

	var ffax FacsimileTelephoneNumber
	ffax.isSet(10394)

	_ = teletexSuffixValue([]byte(`ds世3`))
	_, _, _ = marshalTeletex([][]byte{})
	_, _, _ = marshalTeletex([][]byte{[]byte("a"), []byte("b"), []byte("c")})
	_, _, _ = marshalTeletex([][]byte{[]byte("graphic:this"), []byte("control:34"), []byte("misc:misc"), []byte("page:48"), []byte("private:psst")})
	_, _, _ = marshalTeletex([][]byte{[]byte("graphic:this"), []byte("control:34"), []byte("misc:misc"), []byte("page:48"), []byte("private:psst"), []byte("graphic:this"), []byte("control:34"), []byte("misc:misc"), []byte("page:48"), []byte("private:psst")})
	var uboverflow [][]byte
	for len(uboverflow) < UBTeletexTerminalID+1 {
		uboverflow = append(uboverflow, []byte("graphic:this"))
	}

	_, _, _ = marshalTeletex(uboverflow)

	_, _ = facsimileTelephoneNumber(`+1 555 555 FILK$twoDimensional$twoDimensional`)
	_, _ = facsimileTelephoneNumber(`@K$twoDimensional$twoDimensional`)
	_, _ = telephoneNumber(`+1 555 555 FILK`)
	_, _ = telexNumber(`+1 555 555 FILK`)
	_, _ = teletexTerminalIdentifier(rune(88))
	_, _ = teletexTerminalIdentifier(`👩$👩`)
	_, _ = teletexTerminalIdentifier(`+1 555 555 FILK`)
	_, _ = teletexTerminalIdentifier(`P$control:abge$private:👩👩`)
	_, _ = teletexTerminalIdentifier(`👩👩P$control:abge$private:?>`)
	_, _ = teletexTerminalIdentifier(`👩👩P$controlly:abge$privape:?>`)
	_, _ = teletexTerminalIdentifier(`P$controlly:abge$privape:?>`)
	_, _ = teletexTerminalIdentifier(`P$control:abge$control:?>`)

	_, _ = marshalTelexNumber(`+12345US$getrac`)
	_, _ = marshalTelexNumber("1223$618$Hello?")
	_, _ = marshalTelexNumber("1223$618$Hello?👩👩")
	_, _ = marshalTelexNumber("👩$1223$618$...$👩")
	_, _ = marshalTelexNumber(`1 555 123 4567$`)

	teletexSuffixValue([]byte(`$$`))
	teletexSuffixValue([]byte(`@_+`))
	teletexSuffixValue([]byte(`\\\\\`))
}
