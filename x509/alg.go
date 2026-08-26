package x509

type AlgorithmIdentifier struct {
	OID    []byte
	Params []byte
}

func ParseAlgorithmIdentifier(b []byte) (AlgorithmIdentifier, error) {
	t, err := ParseDER(b)
	if err != nil {
		return AlgorithmIdentifier{}, err
	}
	if t.Tag != 0x10 || !t.Constructed {
		return AlgorithmIdentifier{}, errNotSeq
	}

	var ai AlgorithmIdentifier

	if len(t.Children) < 1 {
		return ai, errNoOID
	}

	ai.OID = t.Children[0].Value

	if len(t.Children) > 1 {
		ai.Params = t.Children[1].Value
	}

	return ai, nil
}

type AlgorithmIdentifierAssertion = AlgorithmIdentifier

func ParseAlgorithmIdentifierAssertion(b []byte) (AlgorithmIdentifierAssertion, error) {
	return ParseAlgorithmIdentifier(b)
}
