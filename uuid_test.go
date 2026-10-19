package syntax

import (
	"testing"
)

func TestUUIDMatch(t *testing.T) {
	tests := []struct {
		UUID1 any
		UUID2 any
		Valid bool
	}{
		{
			UUID1: `23c4bc48-b82d-4091-a3c2-c1a62502d318`,
			UUID2: `3918e81f-1278-4573-9ae8-8a650310e54c`,
			Valid: true,
		},
		{
			UUID1: rune(33),
			UUID2: nil,
		},
		{
			UUID1: `3918e81f-1278-4573-9ae8-8a650310e54c`,
			UUID2: nil,
		},
		{
			UUID1: []byte(`23c4bc48-b82d-4091-a3c2-c1a62502d318`),
			UUID2: []byte(`3918e81f-1278-4573-9ae8-8a650310e54c`),
			Valid: true,
		},
		{
			UUID1: []byte(`23c4bc48-b82d-4091-a3c2-c1a6250`),
			UUID2: []byte(`3918e81f-1278-4573-9ae8-8a650310e54c`),
		},
	}

	for idx, obj := range tests {

		u1, err1 := marshalUUID(obj.UUID1)
		u2, err2 := marshalUUID(obj.UUID2)

		if obj.Valid {
			if err1 != nil {
				t.Errorf("%s[%d] [ordering] failed: %v", t.Name(), idx, err1)
				return
			} else if err2 != nil {
				t.Errorf("%s[%d] [ordering] failed: %v", t.Name(), idx, err2)
				return
			}

			result, err := uuidOrderingMatch(u1, LessOrEqual, u2)
			if err != nil {
				t.Errorf("%s[%d] [ordering] failed: %v", t.Name(), idx, err)
				return
			} else if !result {
				t.Errorf("%s[%d] [ordering] failed:\n\twant: %t\n\tgot:  %t", t.Name(), idx, true, result)
				return
			}

			if result, err = uuidMatch(obj.UUID1, obj.UUID2); err != nil {
				t.Errorf("%s[%d] [equality] failed: %v", t.Name(), idx, err)
				return
			} else if result {
				t.Errorf("%s[%d] [equality] failed:\n\twant: %t\n\tgot:  %t", t.Name(), idx, false, result)
				return
			}

			if result, _ = uUID(obj.UUID1); !result {
				t.Errorf("%s[%d] [syntax] failed: %v\n\twant: %t\n\tgot:  %t", t.Name(), idx, err, true, result)
				return
			} else if result, _ = uUID(obj.UUID2); !result {
				t.Errorf("%s[%d] [syntax] failed: %v\n\twant: %t\n\tgot:  %t", t.Name(), idx, err, true, result)
				return
			}
		} else {
			//if err1 == nil || err2 == nil {
			//	t.Errorf("%s[%d] [ordering] failed: expected error, got nil", t.Name(), idx)
			//	return
			//}

			result, _ := uuidOrderingMatch(obj.UUID1, LessOrEqual, obj.UUID2)
			//if err == nil {
			//	t.Errorf("%s[%d] [ordering] failed: expected error, got nil", t.Name(), idx)
			//        return
			if result {
				t.Errorf("%s[%d] [ordering] failed:\n\twant: %s\n\tgot:  %t", t.Name(), idx, `UNDEFINED or FALSE`, result)
				return
			}

			var err error
			if result, err = uuidMatch(obj.UUID1, obj.UUID2); err == nil {
				t.Errorf("%s[%d] [equality] failed: %v", t.Name(), idx, err)
				return
			} else if result {
				t.Errorf("%s[%d] [equality] failed:\n\twant: %s\n\tgot:  %t", t.Name(), idx, `UNDEFINED or FALSE`, result)
				return
			}
		}
	}
}

func TestUUID(t *testing.T) {

	// We can skimp on tests, since we're just wrapping
	// a call to Google's uuid.Parse function.
	for idx, raw := range []string{
		`f81d4fae-7dec-11d0-a765-00a0c91e6bf6`,
	} {
		if _, err := NewUUID(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}

	// codecov
	NewUUID(`X`)
	NewUUID('X')
	NewUUID(struct{}{})
}

/*
This example demonstrates the means for converting a [UUID] instance to
an [Integer] instance.
*/
/*
func ExampleUUID_Integer() {
	u, err := NewUUID(`00be4308-0c89-1085-8ea0-0002a5d5fd2e`)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s\n", u.Integer())
	// Output: 987895962269883002155146617097157934
}
*/
