package transfer

import "errors"

// Sentinel errors for transfer negotiation and integrity checks.
var (
	ErrBadFrame       = errors.New("transfer: invalid frame")
	ErrRejected       = errors.New("transfer: offer rejected")
	ErrAborted        = errors.New("transfer: aborted by peer")
	ErrSizeMismatch   = errors.New("transfer: size mismatch")
	ErrHashMismatch   = errors.New("transfer: content hash mismatch")
	ErrResumePastEnd  = errors.New("transfer: resume offset exceeds size")
	ErrClosed         = errors.New("transfer: connection closed during transfer")
	ErrTooManyRetries = errors.New("transfer: exceeded MaxAttempts")
)
