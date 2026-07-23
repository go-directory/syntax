package asn1

import (
	"testing"

	"github.com/go-directory/syntax/subspec"
)

func BenchmarkCodecRoundtrip(b *testing.B) {
	var subs []subspec.SubtreeSpecification
	for i := 0; i < len(testSubSpecs); i++ {
		spec, _ := subspec.New(testSubSpecs[i])
		subs = append(subs, spec)
	}

	b.StopTimer()
	maxIdx := len(subs)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		bts, _ := Encode(subs[i%maxIdx])
		_, _ = Decode(bts)
	}
}

func TestCodecRoundtrip(t *testing.T) {
	for idx, raw := range testSubSpecs {
		spec, err := subspec.New(raw)
		if err != nil {
			t.Errorf("%s [%d] failed: %v\n", t.Name(), idx, err)
			continue
		}

		var bts []byte
		bts, err = Encode(spec)
		if err != nil {
			t.Errorf("%s [%d] encoding failed: %v\n", t.Name(), idx, err)
			continue
		}

		var dest subspec.SubtreeSpecification
		dest, err = Decode(bts)
		if err != nil {
			t.Errorf("%s [%d] decoding failed: %v\n", t.Name(), idx, err)
			continue
		}

		if d := dest.String(); raw != d {
			t.Errorf("%s [%d] string compare failed:\n\twant: %q\n\tgot:  %q\n",
				t.Name(), idx, raw, d)
		}
	}
}

var testSubSpecs = []string{
	`{}`,
	`{base "n=1,n=4,n=1,n=6,n=3,n=1", minimum 1, maximum 1, specificationFilter and:{item:organization,or:{item:person,item:device}}}`,
	`{base "n=1,n=4,n=1,n=6,n=3,n=1", minimum 1, maximum 1, specificationFilter or:{item:organization,not:item:2.5.6.9,and:{item:person,item:2.5.6.14}}}`,
	`{base "n=1,n=4,n=1,n=6,n=3,n=1", minimum 1, maximum 1, specificationFilter item:device}`,
	`{minimum 1, maximum 1}`,
	`{base "n=1,n=4,n=1,n=6,n=3,n=1", minimum 1, maximum 1, specificationFilter not:item:2.5.6.4}`,
	`{base "ou=Accounts,dc=example,dc=com", specificExclusions { chopBefore "ou=Payroll", chopAfter "ou=Executives", chopAfter "ou=Vendors" }, minimum 1, maximum 1, specificationFilter not:item:device}`,
	`{base "ou=Accounts,dc=example,dc=com", specificExclusions { chopBefore "ou=Payroll", chopAfter "ou=Executives", chopAfter "ou=Vendors" }, minimum 1, maximum 1, specificationFilter item:device}`,
	`{base "n=1,n=4,n=1,n=6,n=3,n=1", specificExclusions { chopBefore "n=14", chopAfter "n=555", chopAfter "n=74,n=6" }, minimum 1, maximum 1, specificationFilter not:and:{item:device,item:person}}`,
	`{base "n=1,n=4,n=1,n=6,n=3,n=1", specificExclusions { chopBefore "n=14", chopAfter "n=555", chopAfter "n=74,n=6" }, minimum 1, maximum 1, specificationFilter and:{item:device,item:person}}`,
	`{base "n=1,n=4,n=1,n=6,n=3,n=1", specificExclusions { chopBefore "n=14", chopAfter "n=555", chopAfter "n=74,n=6" }, minimum 1, maximum 1, specificationFilter or:{item:organization,not:item:2.5.6.9,and:{item:person,item:2.5.6.14}}}`,
}
