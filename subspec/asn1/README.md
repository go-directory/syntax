# asn1

Package asn1 offers a basic ASN.1 DER encoder and decoder of subspec.SubtreeSpecification instances and all components therein.

## Example

```go
package main

import (
	"github.com/go-directory/syntax/subspec"
	ssasn1 "github.com/go-directory/syntax/subspec/asn1"
)

func main() {
	raw := `... your subtree specification string ...` // see unit tests for real values

	spec, err := subspec.New(raw)
	// check err

	var bts []byte
	bts, err = ssasn1.Encode(spec)
	// check err

	var dest subspec.SubtreeSpecification
	dest, err = ssasn1.Decode(bts)
	// check err

	if d := dest.String(); raw != d {
		panic(raw + " != " + d)
	}

	// No news is good news
}
```
