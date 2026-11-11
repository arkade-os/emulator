package emulator

import "fmt"

// Error describes an emulation failure and the transaction involved, if known.
// TxID is empty when the transaction is unavailable.
type Error struct {
	Operation       string
	TransactionKind string
	TxID            string
	Err             error
}

func (e *Error) Error() string {
	if e.TxID == "" {
		return fmt.Sprintf("%s: %v", e.Operation, e.Err)
	}
	field := e.TransactionKind + "_txid"
	if e.TransactionKind == "onchain" {
		field = "txid"
	}
	return fmt.Sprintf("%s %s=%s: %v", e.Operation, field, e.TxID, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

func offchainTxError(txid string, err error) *Error {
	return &Error{Operation: "emulate offchain tx", TransactionKind: "ark", TxID: txid, Err: err}
}

func onchainTxError(txid string, err error) *Error {
	return &Error{Operation: "emulate onchain tx", TransactionKind: "onchain", TxID: txid, Err: err}
}

func batchRegistrationError(txid string, err error) *Error {
	return &Error{Operation: "emulate batch registration", TransactionKind: "proof", TxID: txid, Err: err}
}

func batchFinalizationError(role string, txid string, err error) *Error {
	return &Error{Operation: "emulate batch finalization", TransactionKind: role, TxID: txid, Err: err}
}
