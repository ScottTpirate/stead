package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/modules/authorization"
)

func TestBoundedPolicyTimeRejectsRollbackBeforeClamping(t *testing.T) {
	high := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	expires := high.Add(2 * time.Second)
	for _, fixture := range []struct {
		name               string
		now, high, expires time.Time
		denied             bool
	}{
		{"initial excessive rollback", high.Add(-authorization.MaxPolicyClockSkew - time.Nanosecond), high, expires, true},
		{"final excessive rollback after earlier successful sample", high.Add(-authorization.MaxPolicyClockSkew - time.Second), high, expires, true},
		{"permitted skew clamps without extending expiry", high.Add(-authorization.MaxPolicyClockSkew), high, expires, false},
		{"before original expiry", expires.Add(-time.Nanosecond), high, expires, false},
		{"at original expiry", expires, high, expires, true},
		{"after original expiry", expires.Add(time.Nanosecond), high, expires, true},
		{"anchor reaches original expiry", expires.Add(-time.Millisecond), expires, expires, true},
		{"missing clock", time.Time{}, high, expires, true},
		{"missing anchor", high, time.Time{}, expires, true},
		{"missing sealed expiry", high, high, time.Time{}, true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			got, err := boundedPolicyTime(fixture.now, fixture.high, fixture.expires)
			if fixture.denied {
				if !errors.Is(err, authorization.ErrDenied) || !got.IsZero() {
					t.Fatal("unsafe clock/expiry accepted", got, err)
				}
				return
			}
			if err != nil || got.Before(fixture.high) || !got.Before(expires) {
				t.Fatal("bounded policy time rejected or extended", got, err)
			}
		})
	}
}
