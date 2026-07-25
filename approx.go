package syntax

/*
approx.go implements approximate matching.  Note that
officially, there is no standard algorithm for such
matching, as the design is left up to the various
directory products which *might* implement it.
*/

// consonant class table (same groups Soundex uses)
var classTable = [256]byte{
	'b': '1', 'f': '1', 'p': '1', 'v': '1',
	'c': '2', 'g': '2', 'j': '2', 'k': '2', 'q': '2', 's': '2', 'x': '2', 'z': '2',
	'd': '3', 't': '3',
	'l': '4',
	'm': '5', 'n': '5',
	'r': '6',
}

// normalize produces a phonetic code similar to soundex
// but encodes the first letter instead of preserving it.
func normalize(s string) string {
	if len(s) == 0 {
		return ""
	}

	// lowercase
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b = append(b, c)
	}

	// encode first letter into its class
	first := classTable[b[0]]
	if first == 0 {
		first = b[0]
	}

	out := []byte{first}

	// encode remaining letters
	prev := first
	for i := 1; i < len(b); i++ {
		c := b[i]
		cls := classTable[c]
		if cls == 0 {
			// vowels and others -> skip
			continue
		}
		if cls != prev {
			out = append(out, cls)
			prev = cls
		}
	}

	return string(out)
}

// levenshtein distance
func levenshtein(a, b string) int {
	la := len(a)
	lb := len(b)

	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	prev := make([]int, lb+1)
	curr := make([]int, lb+1)

	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 0; i < la; i++ {
		curr[0] = i + 1
		ai := a[i]
		for j := 0; j < lb; j++ {
			cost := 0
			if ai != b[j] {
				cost = 1
			}

			del := prev[j+1] + 1
			ins := curr[j] + 1
			sub := prev[j] + cost

			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[j+1] = m
		}
		prev, curr = curr, prev
	}

	return prev[lb]
}

// ApproxMatch implements a reliable approximateMatch rule.
func ApproxMatch(realVal, assertionVal string) bool {
	r := normalize(realVal)
	a := normalize(assertionVal)

	// phonetic match
	if r == a {
		return true
	}

	// first-consonant substitution rule
	if len(r) == len(a) && len(r) > 1 {
		if r[1:] == a[1:] {
			return true
		}
	}

	// edit distance fallback
	d := levenshtein(realVal, assertionVal)
	return d <= 2
}
