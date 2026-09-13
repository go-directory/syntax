package syntax

import (
	"testing"
)

func TestList(t *testing.T) {
	result, err := caseIgnoreListMatch(
		[][]byte{
			[]byte(`this`), []byte(`is`), []byte(`a`), []byte(`list`),
		},
		[][]byte{
			[]byte(`this`), []byte(`is`), []byte(`a`), []byte(`list`),
		})

	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result {
		t.Errorf("%s failed:\nwant: %t\ngot:  %t",
			t.Name(), true, result)
	}

	result, err = caseIgnoreListMatch(
		[][]byte{
			[]byte(`this`), []byte(`iz`), []byte(`a`), []byte(`list`),
		},
		[][]byte{
			[]byte(`this`), []byte(`is`), []byte(`a`), []byte(`list`),
		})

	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if result {
		t.Errorf("%s failed:\nwant: %t\ngot:  %t",
			t.Name(), false, result)
	}

	_, _ = caseIgnoreListMatch(nil, nil)
	_, _ = caseIgnoreListMatch([]string{}, nil)
	_, _ = caseIgnoreListMatch([]string{}, []string{`a`})
	_, _ = caseIgnoreListMatch(nil, struct{}{})
	_, _ = caseIgnoreListMatch(struct{}{}, nil)
}
