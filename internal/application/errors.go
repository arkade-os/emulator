package application

import (
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ArkdError is a deterministic rejection returned by arkd when the emulator
// forwards a transaction: arkd already validated the request and refused it
// with a client-fault status, so the code and message are safe and useful to
// relay to the emulator's caller.
type ArkdError struct {
	Code codes.Code
	Msg  string
	Err  error
}

func (e *ArkdError) Error() string { return fmt.Sprintf("arkd rejected the tx: %s", e.Msg) }

func (e *ArkdError) Unwrap() error { return e.Err }

// relayableCodes are the arkd status codes caused by the submitted transaction
// rather than by a server fault. Any other code stays hidden behind a generic
// internal error.
var relayableCodes = map[codes.Code]bool{
	codes.InvalidArgument:    true,
	codes.FailedPrecondition: true,
	codes.NotFound:           true,
	codes.AlreadyExists:      true,
	codes.OutOfRange:         true,
}

// grpcStatus is implemented by gRPC status errors, including wrapped ones.
type grpcStatus interface{ GRPCStatus() *status.Status }

// arkdRejection returns err as an ArkdError when arkd refused the request with
// a relayable status code, keeping the status message arkd sent rather than
// any wrapper text. It returns nil for server-side or non-status errors.
func arkdRejection(err error) *ArkdError {
	var gs grpcStatus
	if !errors.As(err, &gs) {
		return nil
	}
	st := gs.GRPCStatus()
	if st == nil || !relayableCodes[st.Code()] {
		return nil
	}
	return &ArkdError{Code: st.Code(), Msg: st.Message(), Err: err}
}
