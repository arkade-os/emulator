package handlers

import (
	"context"
	"errors"

	"github.com/arkade-os/emulator/internal/application"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/btcsuite/btcd/txscript/v2"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Unexpected faults are logged with their cause, but never exposed to callers.
const internalErrMsg = "internal error"

func serviceError(err error, operation string) error {
	rpcErr := toRPCError(err)
	entry := log.WithError(err)
	if status.Code(rpcErr) == codes.Internal {
		entry.Error(operation)
	} else {
		entry.Debug(operation)
	}
	return rpcErr
}

// rpcErrorConverters maps an error to a gRPC status error, in precedence
// order: the first converter that recognizes the error wins.
var rpcErrorConverters = []func(error) (error, bool){
	contextRPCError,
	validationRPCError,
	scriptRPCError,
	executionRPCError,
	emulationRPCError,
	backendRPCError,
}

// toRPCError exposes known request errors. Typed errors retain transaction and
// opcode context without exposing private context from outer service wrappers.
// Anything unrecognized is reported as a generic internal error.
func toRPCError(err error) error {
	for _, convert := range rpcErrorConverters {
		if rpcErr, ok := convert(err); ok {
			return rpcErr
		}
	}
	return status.Error(codes.Internal, internalErrMsg)
}

// contextRPCError maps client cancellation and deadline exhaustion.
func contextRPCError(err error) (error, bool) {
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, context.Canceled.Error()), true
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, context.DeadlineExceeded.Error()), true
	}
	return nil, false
}

// validationRPCError exposes rejected requests: ValidationError marks messages
// that are safe to return to the caller.
func validationRPCError(err error) (error, bool) {
	if validationErr, ok := errors.AsType[*application.ValidationError](err); ok {
		return status.Error(codes.InvalidArgument, validationErr.Error()), true
	}
	return nil, false
}

// scriptRPCError classifies VM failures by opcode. The message prefers an
// emulation or execution wrapper when present, since those carry transaction
// and opcode context the raw script error lacks.
func scriptRPCError(err error) (error, bool) {
	scriptErr, ok := errors.AsType[txscript.Error](err)
	if !ok {
		return nil, false
	}
	code := scriptErrorCode(scriptErr.ErrorCode)
	if code == codes.Internal {
		return status.Error(code, internalErrMsg), true
	}
	message := scriptErr.Error()
	var emulationErr *emulator.Error
	if errors.As(err, &emulationErr) {
		message = emulationErr.Error()
	} else {
		var executionErr *arkade.ExecutionError
		if errors.As(err, &executionErr) {
			message = executionErr.Error()
		}
	}
	return status.Error(code, message), true
}

// executionRPCError keeps located execution failures internal: an
// ExecutionError pinpoints the failure but does not guarantee it is the
// caller's fault, so it must not fall through to validation.
func executionRPCError(err error) (error, bool) {
	if _, ok := errors.AsType[*arkade.ExecutionError](err); ok {
		return status.Error(codes.Internal, internalErrMsg), true
	}
	return nil, false
}

// emulationRPCError exposes emulation errors as bad requests.
func emulationRPCError(err error) (error, bool) {
	if emulationErr, ok := errors.AsType[*emulator.Error](err); ok {
		return status.Error(codes.InvalidArgument, emulationErr.Error()), true
	}
	return nil, false
}

// backendRPCError passes through the backend's own status for codes that are
// safe to expose, keeping its structured details. The status is read directly:
// status.FromError would include outer wrapper text.
func backendRPCError(err error) (error, bool) {
	var backendErr interface{ GRPCStatus() *status.Status }
	if !errors.As(err, &backendErr) {
		return nil, false
	}
	st := backendErr.GRPCStatus()
	if st == nil {
		return nil, false
	}
	switch st.Code() {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.NotFound,
		codes.AlreadyExists, codes.OutOfRange:
		return st.Err(), true
	}
	return nil, false
}

func scriptErrorCode(code txscript.ErrorCode) codes.Code {
	switch code {
	// A well-formed script whose checks fail, including a timelock that may
	// become satisfied later, is a precondition failure.
	case txscript.ErrVerify, txscript.ErrEqualVerify, txscript.ErrNumEqualVerify,
		txscript.ErrCheckSigVerify, txscript.ErrEvalFalse,
		txscript.ErrUnsatisfiedLockTime, txscript.ErrNullFail:
		return codes.FailedPrecondition
	// These codes only describe malformed scripts, operands, or work limits.
	case txscript.ErrEarlyReturn, txscript.ErrEmptyStack, txscript.ErrCleanStack,
		txscript.ErrScriptTooBig, txscript.ErrElementTooBig, txscript.ErrStackOverflow,
		txscript.ErrNumberTooBig, txscript.ErrMalformedPush, txscript.ErrMinimalData,
		txscript.ErrMinimalIf, txscript.ErrNegativeLockTime, txscript.ErrNotPushOnly,
		txscript.ErrReservedOpcode, txscript.ErrUnbalancedConditional,
		txscript.ErrInvalidSigHashType, txscript.ErrInvalidTaprootSigLen,
		txscript.ErrTaprootPubkeyIsEmpty, txscript.ErrTapscriptCheckMultisig,
		txscript.ErrControlBlockTooSmall, txscript.ErrControlBlockTooLarge,
		txscript.ErrControlBlockInvalidLength, txscript.ErrTaprootMerkleProofInvalid,
		txscript.ErrTaprootOutputKeyParityMismatch,
		txscript.ErrDiscourageUpgradableNOPs, txscript.ErrDiscourageUpgradeablePubKeyType,
		txscript.ErrInvalidStackOperation:
		return codes.InvalidArgument
	default:
		return codes.Internal
	}
}
