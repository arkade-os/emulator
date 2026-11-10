package arkade

import (
	"fmt"

	"github.com/btcsuite/btcd/txscript/v2"
)

// ExecutionError identifies the opcode being processed when a script step failed.
type ExecutionError struct {
	ScriptIndex int
	Position    int // position in the script executed
	Opcode      string
	Err         error
}

func (e *ExecutionError) Error() string {
	return fmt.Sprintf("script=%d position=%d opcode=%s: %v",
		e.ScriptIndex, e.Position, e.Opcode, e.Err)
}

func (e *ExecutionError) Unwrap() error { return e.Err }

// scriptError creates an Error given a set of arguments.
func scriptError(c txscript.ErrorCode, desc string) error {
	return txscript.Error{ErrorCode: c, Description: desc}
}
