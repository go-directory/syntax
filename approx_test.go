package syntax

import (
	"testing"
)

func TestApproxMatch(t *testing.T) {
	for k, v := range map[string][]string{
		`Jesse`:  {`Tessi`, `Tessi`, `Jessi`, `Jesy`, `Jesi`},
		`Fred`:   {`Tred`, `Ted`, `Ned`, `Shed`},
		`Beefs`:  {`Teefs`, `Teafs`, `Beeps`},
		`Beef`:   {`Teef`, `Reef`, `Leaf`},
		`Mark`:   {`Marc`, `Lark`, `Spark`},
		`Steven`: {`Stephen`, `Slevin`},
		`Sean`:   {`Shawn`, `Fawn`, `Lawn`},
		`Vowels`: {`Bowels`, `Cowls`},
		`Sara`:   {`Sarah`, `Sarrah`},
		`Jon`:    {`John`, `Fon`, `Gone`},
		`Kathy`:  {`Cathy`, `Cathay`},
		`Philip`: {`Filip`},
	} {
		for i, sl := range v {
			if !ApproxMatch([]byte(k), []byte(sl)) {
				t.Errorf("%s failed: expected true, got false for index %q[%d]",
					t.Name(), k, i)
			}
		}
	}
}
