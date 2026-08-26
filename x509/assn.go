package x509

func ParseCertificateExactAssertion(b []byte) ([]byte, error) {
	t, err := ParseDER(b)
	if err != nil {
		return nil, err
	}
	if t.Tag != 0x04 || t.Constructed {
		return nil, errNotOct
	}
	return t.Value, nil
}

type CertificateAssertion struct {
	IssuerDER  []byte
	SerialDER  []byte
	SubjectDER []byte
}

func ParseCertificateAssertion(b []byte) (CertificateAssertion, error) {
	t, err := ParseDER(b)
	if err != nil {
		return CertificateAssertion{}, err
	}
	if t.Tag != 0x10 || !t.Constructed {
		return CertificateAssertion{}, errNotSeq
	}

	var ca CertificateAssertion

	for _, c := range t.Children {
		switch {
		case c.Class == TagContextSpecific && c.Tag == 0:
			ca.IssuerDER = c.Value
		case c.Class == TagContextSpecific && c.Tag == 1:
			ca.SerialDER = c.Value
		case c.Class == TagContextSpecific && c.Tag == 2:
			ca.SubjectDER = c.Value
		}
	}

	return ca, nil
}

type CRLAssertion struct {
	IssuerDER []byte
}

func ParseCRLAssertion(b []byte) (CRLAssertion, error) {
	t, err := ParseDER(b)
	if err != nil {
		return CRLAssertion{}, err
	}
	if t.Tag != 0x10 || !t.Constructed {
		return CRLAssertion{}, errNotSeq
	}

	var ca CRLAssertion

	for _, c := range t.Children {
		if c.Class == TagContextSpecific && c.Tag == 0 {
			ca.IssuerDER = c.Value
		}
	}

	return ca, nil
}
