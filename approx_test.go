package syntax

import (
	"testing"
)

/*
func TestApproxMatch(t *testing.T) {
        for k, v := range map[string]string{
                `Beefs`: `Teefs`,
                `Fred`:  `Tred`,
                `Fred`:  `Ned`,
                `Fred`:  `Bed`,
                `Fred`:  `Ted`,
                `Jesse`: `Tessi`,
                `Jesse`: `Jessi`,
                `Jesse`: `Jess`,
                `Jesse`: `Jessy`,
                `Jesse`: `Jesi`,
                `Beefs`: `Beeps`,
                `Beefs`: `Beef`,
                `Beefs`: `Teef`,
                `Mark`:  `Marc`,
                `Mark`:  `Marq`,
		`Bowels`: `Vowels`,
                `Steven`: `Stephen`,
                `Sean`:   `Shawn`,
                `Sara`:   `Sarah`,
                `Jon`:    `John`,
                `Kathy`:  `Cathy`,
                `Philip`: `Filip`,
        }{
                if !ApproxMatch(k,v) {
                        t.Errorf("%s failed: expected true, got false for index %q", t.Name(), k)
                }
        }
}
*/

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
			if !ApproxMatch(k, sl) {
				t.Errorf("%s failed: expected true, got false for index %q[%d]",
					t.Name(), k, i)
			}
		}
	}
}
