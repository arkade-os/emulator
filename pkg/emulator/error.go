package emulator

import "fmt"

// Error describes an emulation failure and the transaction involved, if known.
// TxID is empty when the transaction is unavailable.
type Error struct {
	Operation       string
	TransactionRole string
	TxID            string
	Err             error
}

func (e *Error) Error() string {
	if e.TxID == "" {
		return fmt.Sprintf("%s: %v", e.Operation, e.Err)
	}
	field := e.TransactionRole + "_txid"
	if e.TransactionRole == "onchain" {
		field = "txid"
	}
	return fmt.Sprintf("%s %s=%s: %v", e.Operation, field, e.TxID, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

func offchainTxError(txid string, err error) *Error {
	return &Error{Operation: "emulate offchain tx", TransactionRole: "ark", TxID: txid, Err: err}
}

func onchainTxError(txid string, err error) *Error {
	return &Error{Operation: "emulate onchain tx", TransactionRole: "onchain", TxID: txid, Err: err}
}

func intentError(txid string, err error) *Error {
	return &Error{Operation: "emulate intent", TransactionRole: "proof", TxID: txid, Err: err}
}

func batchFinalizationError(role string, txid string, err error) *Error {
	return &Error{Operation: "emulate batch finalization", TransactionRole: role, TxID: txid, Err: err}
}
