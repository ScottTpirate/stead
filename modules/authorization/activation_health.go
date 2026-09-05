package authorization

import "time"

// ValidAt is readiness information, never a resource authorization decision.
// Callers must separately verify the current independent anchor and database
// pointer; this method neither refreshes nor extends the signed activation.
func (activation *VerifiedActivation) ValidAt(now time.Time) bool {
	return activation != nil && activation.valid && activation.evaluator != nil && validBinding(activation.binding) && !now.IsZero() && !now.Before(activation.issuedAt) && now.Before(activation.expiresAt)
}
