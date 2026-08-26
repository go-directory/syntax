package x509

type CertificatePair struct {
	ForwardDER []byte
	ReverseDER []byte
}

func ParseCertificatePair(b []byte) (CertificatePair, error) {
	t, err := ParseDER(b)
	if err != nil {
		return CertificatePair{}, err
	}
	if t.Tag != 0x10 || !t.Constructed {
		return CertificatePair{}, errNotSeq
	}

	var cp CertificatePair

	for _, c := range t.Children {
		if c.Class == TagContextSpecific && c.Tag == 0 && c.Constructed {
			cp.ForwardDER = c.Children[0].Value
		}
		if c.Class == TagContextSpecific && c.Tag == 1 && c.Constructed {
			cp.ReverseDER = c.Children[0].Value
		}
	}

	return cp, nil
}

type CertificatePairAssertion CertificatePair

func ParseCertificatePairAssertion(b []byte) (CertificatePairAssertion, error) {
	t, err := ParseDER(b)
	if err != nil {
		return CertificatePairAssertion{}, err
	}
	if t.Tag != 0x10 || !t.Constructed {
		return CertificatePairAssertion{}, errNotSeq
	}

	var a CertificatePairAssertion

	for _, c := range t.Children {
		if c.Class == TagContextSpecific && c.Tag == 0 && !c.Constructed {
			a.ForwardDER = c.Value
		}
		if c.Class == TagContextSpecific && c.Tag == 1 && !c.Constructed {
			a.ReverseDER = c.Value
		}
	}

	return a, nil
}

func ParseCertificatePairExactAssertion(b []byte) ([]byte, error) {
	t, err := ParseDER(b)
	if err != nil {
		return nil, err
	}
	if t.Tag != 0x04 || t.Constructed {
		return nil, errNotOct
	}
	return t.Value, nil
}
