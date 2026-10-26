package syntax

import (
	"testing"
	"time"
)

func TestGeneralizedTimeOrderingMatch(t *testing.T) {
	var gt1, gt2 GeneralizedTime
	var err error

	if gt1, err = NewGeneralizedTime(`19950218155703.000000Z`); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	if gt2, err = NewGeneralizedTime(`20240229155703.000000Z`); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	var result bool
	// GreaterOrEqual
	result, _ = generalizedTimeOrderingMatch(gt1, GreaterOrEqual, gt2) // >=
	if result {
		t.Errorf("%s [GE] failed:\nwant: %t\ngot:  %t",
			t.Name(), true, result)
		return
	}

	// LessOrEqual
	result, _ = generalizedTimeOrderingMatch(gt1, LessOrEqual, gt2) // <=
	if !result {
		t.Errorf("%s [LE] failed:\nwant: %t\ngot:  %t",
			t.Name(), false, result)
		return
	}
}

func TestGeneralizedTime_codecov(t *testing.T) {
	_, _ = generalizedTime(`...`)
	_, _ = uTCTime(`...`)
	var u UTCTime
	u.Cast()

	var a, b UTCTime
	var err error

	if a, err = NewUTCTime(`9911040404`); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	if b, err = NewUTCTime(`9911040403`); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	_, _ = timeMatch(`20210404041113Z`, `20210404041113Z`)
	_, _ = timeMatch(`9911040404`, `9901160801`)
	_, _ = timeMatch(a, b)
	_, _ = timeMatch(`127`, b)
	_, _ = timeMatch(a, b)
}

func TestUTCTime(t *testing.T) {

	for idx, thyme := range []string{
		`9805061703Z`,
		`980506170306Z`,
		`620506170306-0500`,
	} {
		if utct, err := NewUTCTime(thyme); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else {
			_ = utct.String()
		}
	}

	for idx, thyme := range []any{
		`20`,
		20,
		`F`,
		`00Z`,
		rune(10),
		struct{}{},
		`98170306Z`,
	} {
		if _, err := NewUTCTime(thyme); err == nil {
			t.Errorf("%s[%d] failed: expected error, got nil", t.Name(), idx)
			return
			//} else {
			//timeMatch(utct, utct, 1)
		}
	}
}

func TestGeneralizedTime(t *testing.T) {

	for idx, thyme := range []string{
		`20240229155701.0Z`,
		`20240229155703.00Z`,
		`20240229155702.000Z`,
		`20240229155703.0000Z`,
		`20240229155703.00000Z`,
		`20240229155703.000000Z`,
		`19540426135103Z`,
		`20240229155703-0500`,
		`20240229155703.0-0700`,
		`20240229155703.00-0700`,
		`20240229155703.000+1100`,
		`20240229155703.0000-0200`,
		`20240229155703.00000-0800`,
		`20200629155703.000000-0100`,
	} {
		if thyme, err := NewGeneralizedTime(thyme); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else {
			_ = thyme.String()
		}
	}

	for idx, thyme := range []any{
		`20`,
		20,
		`F`,
		`00Z`,
		rune(10),
		struct{}{},
		`202402291550.0000000-0800`,
		`20241202183734.0000000-0700`,
	} {
		if _, err := NewGeneralizedTime(thyme); err == nil {
			t.Errorf("%s[%d] failed: expected error, got nil", t.Name(), idx)
			return
		}
	}

	_, err := genTimeFracDiffFormat(`20241202183734Z`, `.00000000`, `-0700`, `20060102150405`)
	if err == nil {
		t.Errorf("%s failed: expected error, got nil", t.Name())
	}
}

func TestGeneralizedTimeMatchingRules(t *testing.T) {
	assertions := map[int]string{
		0: `equalityMatch`,
		2: `lessOrEqual/greaterOrEqual`,
	}

	type assertion struct {
		A, B any
		T    int
		R    [4]bool
	}

	var err error
	for idx, try := range []assertion{
		{A: `20250408193455Z`, B: `20250408193455Z`, T: 0, R: [4]bool{true, true, true, true}},
		{A: `20210408193455Z`, B: `20240101000001.163742-0700`, T: 2, R: [4]bool{false, false, true, true}},
	} {
		var A, B GeneralizedTime
		if A, err = NewGeneralizedTime(try.A); err != nil {
			t.Errorf("%s[%d] parse failed: %v", t.Name(), idx, err)
			continue
		}
		if B, err = NewGeneralizedTime(try.B); err != nil {
			t.Errorf("%s[%d] parse failed: %v", t.Name(), idx, err)
			continue
		}

		AT := time.Time(A)
		BT := time.Time(B)

		tM := func(a, b any) bool {
			bewl, _ := generalizedTimeMatch(a, b)
			return bewl
		}

		tOM := func(a any, operator byte, b any) bool {
			bewl, _ := generalizedTimeOrderingMatch(a, operator, b)
			return bewl
		}

		var results []bool = make([]bool, len(try.R), len(try.R))
		switch try.T {
		case 0:
			results[0] = try.R[0] == tM(A, BT)
			results[1] = try.R[1] == tM(B, AT)
			results[2] = try.R[2] == tM(A, B)
			results[3] = try.R[3] == tM(A, B.String())
		case 2:
			results[0] = try.R[0] == tOM(AT, GreaterOrEqual, B)
			results[1] = try.R[1] == tOM(BT, LessOrEqual, A)
			results[2] = try.R[2] == tOM(B, GreaterOrEqual, A)
			results[3] = try.R[3] == tOM(B.String(), GreaterOrEqual, A)
		}

		for idx2, res := range results {
			if !res {
				t.Errorf("%s[%d] %s failed [gen time]:\nwant: %t\ngot:  %t",
					t.Name(), idx2, assertions[idx], try.R[idx2], res)
			}
		}
	}
}
