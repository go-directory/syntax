package syntax

import (
	"testing"
)

func TestDeliveryMethod(t *testing.T) {
	for _, raw := range []string{
		`any`,
		`mhs $ g3fax $ ia5 $ telephone`,
	} {
		if dm, err := NewDeliveryMethod(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := dm.String(); got != raw {
			t.Errorf("%s failed:\nwant: %s\ngot:  %s",
				t.Name(), raw, got)
		}
	}
}

func TestPostalAddress(t *testing.T) {
	for _, raw := range []string{
		`123 Fake Street$Palm Springs$CA$92111`,
		`The \$100000 Sweepstakes$10 Million Dollar Avenue$New York$NY`,
		`104 West Fake Street$Unit #10$Nowhere$MA$01234$US`,
	} {
		if pa, err := NewPostalAddress(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := pa.String(); got != raw {
			t.Errorf("%s failed:\nwant: %s\ngot:  %s",
				t.Name(), raw, got)
		}
	}
}

func TestOtherMailbox(t *testing.T) {
	for _, raw := range []string{
		`other$mailbox`,
		`test+,+$mailbox`,
	} {
		if _, err := NewOtherMailbox(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}

	NewOtherMailbox(`界ac`)
}

func TestPostal_codecov(t *testing.T) {
	_, _ = deliveryMethod(nil)
	_, _ = postalAddress(nil)
	_, _ = otherMailbox(nil)

	_, _ = printableString(`Hello.`)

	lineChar([]byte(`.#.$.$.$$`))
	lineChar([]byte(`.#.naïve.$.$$`))
	lineChar([]byte(string(rune('\U0010AAAA')) + `ð`))
	lineChar([]byte(`$a\\bc$界$`))
	lineChar([]byte(string([]rune{'\u00e0', '$', '\u00FF'})))
	lineChar([]byte(string([]rune{'\u00e0', '$', '\uFFFF'})))

	marshalDeliveryMethod("bogus$value")
}
