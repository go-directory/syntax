package syntax

/*
time.go implements all temporal syntaxes and matching rules -- namely
those for Generalized Time and the (deprecated) UTC Time.
*/

import (
	"time"
)

/*
GeneralizedTime aliases an instance of [time.Time] to implement [§ 3.3.13
of RFC 4517]:

	GeneralizedTime = century year month day hour
	        [ minute [ second / leap-second ] ]
	        [ fraction ]
	        g-time-zone

	century = 2(%x30-39) ; "00" to "99"
	year    = 2(%x30-39) ; "00" to "99"
	month   =   ( %x30 %x31-39 ) ; "01" (January) to "09"
	          / ( %x31 %x30-32 ) ; "10" to "12"
	day     =   ( %x30 %x31-39 )    ; "01" to "09"
	          / ( %x31-32 %x30-39 ) ; "10" to "29"
	          / ( %x33 %x30-31 )    ; "30" to "31"
	hour    = ( %x30-31 %x30-39 ) / ( %x32 %x30-33 ) ; "00" to "23"
	minute  = %x30-35 %x30-39                        ; "00" to "59"

	second      = ( %x30-35 %x30-39 ) ; "00" to "59"
	leap-second = ( %x36 %x30 )       ; "60"

	fraction        = ( DOT / COMMA ) 1*(%x30-39)
	g-time-zone     = %x5A  ; "Z"
	                  / g-differential
	g-differential  = ( MINUS / PLUS ) hour [ minute ]
	MINUS           = %x2D  ; minus sign ("-")

[§ 3.3.13 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.13
*/
type GeneralizedTime time.Time

/*
GeneralizedTime returns an instance of [GeneralizedTime] alongside an error.
*/
func NewGeneralizedTime(x any) (gt GeneralizedTime, err error) {
	gt, err = marshalGenTime(x)
	return
}

func generalizedTime(x any) (result bool, err error) {
	_, err = marshalGenTime(x)
	result = err == nil
	return
}

func marshalGenTime(x any) (gt GeneralizedTime, err error) {
	var (
		format string = `20060102150405` // base format
		diff   string = `-0700`
		base   string
		raw    string
	)

	if raw, err = assertString(x, 15, "Generalized Time"); err != nil {
		return
	}
	raw = chopZulu(raw)

	// If we've got nothing left, must be zulu
	// without any fractional or differential
	// components
	if base = raw[14:]; len(base) == 0 {
		var _gt time.Time
		if _gt, err = time.Parse(format, raw); err == nil {
			gt = GeneralizedTime(_gt)
		}
		return
	}

	// Handle fractional component (up to six (6) digits)
	if format, err = genTimeFracDiffFormat(raw, base, diff, format); err != nil {
		return
	}

	var _gt time.Time
	if _gt, err = time.Parse(format, raw); err == nil {
		gt = GeneralizedTime(_gt)
	}

	return
}

// Handle generalizedTime fractional component (up to six (6) digits)
func genTimeFracDiffFormat(raw, base, diff, format string) (string, error) {
	var err error

	if base[0] == '.' || base[0] == ',' {
		format += string(".")
		for fidx, ch := range base[1:] {
			if fidx > 6 {
				err = syntaxError(`Fraction exceeds Generalized Time fractional limit`)
			} else if isDigit(ch) {
				format += `0`
				continue
			}
			break
		}
	}

	// Handle differential time, or bail out if not
	// already known to be zulu.
	if raw[len(raw)-5] == '+' || raw[len(raw)-5] == '-' {
		format += diff
	}

	return format, err
}

/*
String returns the string representation of the receiver instance.
*/
func (r GeneralizedTime) String() string {
	return time.Time(r).Format(`20060102150405`) + `Z`
}

/*
Cast unwraps and returns the underlying instance of [time.Time].
*/
func (r GeneralizedTime) Cast() time.Time {
	return time.Time(r)
}

/*
Deprecated: UTCTime implements [§ 3.3.34 of RFC 4517].

	UTCTime         = year month day hour minute [ second ] [ u-time-zone ]
	u-time-zone     = %x5A  ; "Z"
	                  / u-differential
	u-differential  = ( MINUS / PLUS ) hour minute

Use instances of [GeneralizedTime] instead.

[§ 3.3.34 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.34
*/
type UTCTime time.Time

/*
String returns the string representation of the receiver instance.
*/
func (r UTCTime) String() string {
	return time.Time(r).Format(`0601021504`) + `Z`
}

/*
Cast unwraps and returns the underlying instance of [time.Time].
*/
func (r UTCTime) Cast() time.Time {
	return time.Time(r)
}

/*
Deprecated: UTCTime is intended for historical support only; use [GeneralizedTime]
instead.

UTCTime returns an error following an analysis of x in the context of a
(deprecated) UTC Time value.
*/
func NewUTCTime(x any) (utc UTCTime, err error) {
	utc, err = marshalUTCTime(x)
	return
}

func uTCTime(x any) (result bool, err error) {
	_, err = marshalUTCTime(x)
	result = err == nil
	return
}

func marshalUTCTime(x any) (utc UTCTime, err error) {
	var (
		format string = `0601021504` // base format
		sec    string = `05`
		diff   string = `-0700`
		raw    string
	)

	switch tv := x.(type) {
	case string:
		raw = chopZulu(tv)

		if len(raw) < 10 {
			err = errorBadLength(`UTC Time`, len(tv))
			break
		}
		utc, err = uTCHandler(raw, sec, diff, format)
	default:
		err = errorBadType(`UTC Time`)
	}

	return

}

func chopZulu(raw string) string {
	if zulu := raw[len(raw)-1] == 'Z'; zulu {
		raw = raw[:len(raw)-1]
	}

	return raw
}

func uTCHandler(raw, sec, diff, format string) (utc UTCTime, err error) {
	var _utc time.Time

	switch len(raw) {
	case 10:
		// base time containing neither seconds
		// nor a differential.
		if _utc, err = time.Parse(format, raw); err == nil {
			utc = UTCTime(_utc)
		}
		return
	case 12:
		// base time containing only seconds.
		if _utc, err = time.Parse(format+sec, raw); err == nil {
			utc = UTCTime(_utc)
		}
		return
	}

	format += sec

	// Handle differential component
	if raw[len(raw)-5] == '+' || raw[len(raw)-5] == '-' {
		format += diff
	}

	if _utc, err = time.Parse(format, raw); err == nil {
		utc = UTCTime(_utc)
	}

	return
}

/*
generalizedTimeMatch implements [§ 4.2.16 of RFC 4517].

OID: 2.5.13.27.

[§ 4.2.16 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.16
*/
func generalizedTimeMatch(a, b any) (result bool, err error) {
	result, err = timeMatch(a, b)
	return
}

/*
generalizedTimeOrderingMatch implements [§ 4.2.17 of RFC 4517].

OID: 2.5.13.28.

[§ 4.2.17 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.17
*/
func generalizedTimeOrderingMatch(a any, operator byte, b any) (result bool, err error) {
	result, err = timeMatch(a, b, operator)
	return
}

func timeMatch(rcv, assert any, operator ...byte) (result bool, err error) {
	var c time.Time
	var utc bool

	switch tv := rcv.(type) {
	case GeneralizedTime:
		c = tv.Cast().UTC()
	case UTCTime:
		c = tv.Cast().UTC()
		utc = true
	case string:
		switch len(tv) {
		case 15:
			var gt GeneralizedTime
			gt, err = marshalGenTime(tv)
			c = gt.Cast().UTC()
		case 10:
			utc = true
			var ut UTCTime
			ut, err = marshalUTCTime(tv)
			c = ut.Cast().UTC()
		default:
			err = syntaxError("invalid GeneralizedTime or UTCTime format")
		}
	default:
		err = errorBadType("GeneralizedTime")
	}

	if err == nil {
		if len(operator) == 1 {
			if operator[0] == GreaterOrEqual {
				result = compareTimes(assert, utc, func(thyme time.Time) bool {
					return c.Before(thyme) || c.Equal(thyme)
				})
			} else {
				result = compareTimes(assert, utc, func(thyme time.Time) bool {
					return c.After(thyme) || c.Equal(thyme)
				})
			}
		} else {
			result = compareTimes(assert, utc, func(thyme time.Time) bool {
				return c.Equal(thyme)
			})
		}
	}

	return
}

func compareTimes(assert any, utc bool, funk func(time.Time) bool) (result bool) {
	switch tv := assert.(type) {
	case GeneralizedTime:
		result = funk(tv.Cast())
	case UTCTime:
		result = funk(tv.Cast())
	case time.Time:
		result = funk(tv)
	default:
		if utc {
			d, err := marshalUTCTime(tv)
			result = funk(d.Cast()) && err == nil
		} else {
			d, err := marshalGenTime(tv)
			result = funk(d.Cast()) && err == nil
		}
	}

	return
}
