package transaction

import "errors"

// ErrorCode is a bounded, non-disclosing failure classification. It never
// includes participant, owner, resource, policy, or intent contents.
type ErrorCode string

const (
	CodeInvalidContract    ErrorCode = "invalid_contract"
	CodeInvalidPlan        ErrorCode = "invalid_plan"
	CodePlanUnavailable    ErrorCode = "plan_unavailable"
	CodeCancelled          ErrorCode = "cancelled"
	CodeBeginFailed        ErrorCode = "begin_failed"
	CodeParticipantFailed  ErrorCode = "participant_failed"
	CodeOutboxFailed       ErrorCode = "outbox_failed"
	CodeCommitFailed       ErrorCode = "commit_failed"
	CodeRollbackFailed     ErrorCode = "rollback_failed"
	CodeBoundaryDenied     ErrorCode = "boundary_denied"
	CodeStrictUnavailable  ErrorCode = "commit_boundary_unavailable"
	CodeDurableHandoffFail ErrorCode = "durable_handoff_failed"
)

type contractError struct {
	code ErrorCode
}

func (e *contractError) Error() string {
	if e == nil {
		return "core transaction contract failed"
	}
	return "core transaction contract failed: " + string(e.code)
}

func fail(code ErrorCode) error {
	return &contractError{code: code}
}

func ErrorCodeOf(err error) ErrorCode {
	var target *contractError
	if errors.As(err, &target) {
		return target.code
	}
	return CodeInvalidContract
}
