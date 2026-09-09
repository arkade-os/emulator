package arkade

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/txscript"
	"github.com/tidwall/gjson"
)

const (
	maxIntentMessageSize       = 1024 * 1024 // 1 MB
	maxBigNumDecimalDigitCount = 1255
)

// opcodeInspectIntentMessage queries the canonical intent message bound by the
// application. The presence flag is always pushed last.
func opcodeInspectIntentMessage(op *opcode, data []byte, vm *Engine) error {
	pathBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if vm.intentMessage == nil {
		pushIntentMessageMiss(vm)
		return nil
	}
	if len(vm.intentMessage) > maxIntentMessageSize {
		return scriptError(txscript.ErrElementTooBig, "intent message exceeds 1 MiB")
	}
	path := string(pathBytes)
	if !isSimpleIntentMessagePath(path) {
		return scriptError(txscript.ErrInvalidStackOperation,
			fmt.Sprintf("invalid intent message path %q", path))
	}

	result := gjson.GetBytes(vm.intentMessage, path)
	switch result.Type {
	case gjson.Null:
		pushIntentMessageMiss(vm)
		return nil
	case gjson.String:
		return pushIntentMessageBytes(vm, []byte(result.Str))
	case gjson.Number:
		n, integer, err := parseJSONInteger(result.Raw)
		if err != nil {
			return err
		}
		if !integer {
			pushIntentMessageMiss(vm)
			return nil
		}
		if err := pushBigIntAsBigNum(vm, n); err != nil {
			return err
		}
		vm.dstack.PushBool(true)
		return nil
	case gjson.True:
		return pushIntentMessageBytes(vm, []byte{1})
	case gjson.False:
		return pushIntentMessageBytes(vm, nil)
	case gjson.JSON:
		return pushIntentMessageBytes(vm, []byte(result.Raw))
	default:
		pushIntentMessageMiss(vm)
		return nil
	}
}

// isSimpleIntentMessagePath accepts plain lowercase keys and bounded array indexes.
// GJSON operators are rejected to keep lookup cost predictable.
func isSimpleIntentMessagePath(path string) bool {
	for segment := range strings.SplitSeq(path, ".") {
		if segment == "" {
			return false
		}
		if segment[0] >= '0' && segment[0] <= '9' {
			index, err := strconv.ParseUint(segment, 10, 64)
			if err != nil || (len(segment) > 1 && segment[0] == '0') || index >= maxIntentMessageSize {
				return false
			}
			continue
		}
		if segment[0] != '_' && (segment[0] < 'a' || segment[0] > 'z') {
			return false
		}
		for i := 1; i < len(segment); i++ {
			c := segment[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
				return false
			}
		}
	}
	return true
}

func pushIntentMessageMiss(vm *Engine) {
	vm.dstack.PushByteArray(nil)
	vm.dstack.PushBool(false)
}

func pushIntentMessageBytes(vm *Engine, value []byte) error {
	if len(value) > txscript.MaxScriptElementSize {
		return scriptError(txscript.ErrElementTooBig, fmt.Sprintf(
			"intent message result size %d exceeds max allowed size %d",
			len(value), txscript.MaxScriptElementSize,
		))
	}
	vm.dstack.PushByteArray(value)
	vm.dstack.PushBool(true)
	return nil
}

// parseJSONInteger returns the exact integer represented by a JSON number.
// Exponents are bounded before expansion so a short value such as 1e999999999
// cannot force an oversized allocation.
func parseJSONInteger(raw string) (*big.Int, bool, error) {
	if raw == "" {
		return nil, false, nil
	}

	negative := raw[0] == '-'
	if negative {
		raw = raw[1:]
		if raw == "" {
			return nil, false, nil
		}
	}

	mantissa := raw
	exponentText := ""
	hasExponent := false
	if i := strings.IndexAny(raw, "eE"); i >= 0 {
		mantissa, exponentText = raw[:i], raw[i+1:]
		hasExponent = true
	}

	fractionDigits := 0
	if i := strings.IndexByte(mantissa, '.'); i >= 0 {
		fractionDigits = len(mantissa) - i - 1
		mantissa = mantissa[:i] + mantissa[i+1:]
	}
	if mantissa == "" || !decimalDigits(mantissa) {
		return nil, false, nil
	}

	digits := strings.TrimLeft(mantissa, "0")
	if digits == "" {
		return new(big.Int), true, nil
	}

	exponent := int64(0)
	if hasExponent {
		parsed, err := strconv.ParseInt(exponentText, 10, 64)
		if err != nil {
			// only a genuine int64 overflow of a positive exponent means "too
			// big"; a malformed exponent (empty, garbage) is not an integer
			if errors.Is(err, strconv.ErrRange) && exponentText[0] != '-' {
				return nil, false, scriptError(txscript.ErrNumberTooBig,
					"intent message number exceeds the BigNum range")
			}
			return nil, false, nil
		}
		exponent = parsed
	}

	if exponent < int64(fractionDigits)-int64(len(digits)) {
		return nil, false, nil
	}
	scale := exponent - int64(fractionDigits)
	if scale < 0 {
		trim := -scale
		if trim > int64(len(digits)) || strings.Trim(digits[len(digits)-int(trim):], "0") != "" {
			return nil, false, nil
		}
		digits = strings.TrimLeft(digits[:len(digits)-int(trim)], "0")
		if digits == "" {
			return new(big.Int), true, nil
		}
	} else if scale > 0 {
		// 520 bytes hold fewer than 1,255 decimal digits. The final binary
		// encoding check remains authoritative at the boundary.
		if scale > maxBigNumDecimalDigitCount || int64(len(digits))+scale > maxBigNumDecimalDigitCount {
			return nil, false, scriptError(txscript.ErrNumberTooBig,
				"intent message number exceeds the BigNum range")
		}
		digits += strings.Repeat("0", int(scale))
	}
	if len(digits) > maxBigNumDecimalDigitCount {
		return nil, false, scriptError(txscript.ErrNumberTooBig,
			"intent message number exceeds the BigNum range")
	}

	n, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		return nil, false, nil
	}
	if negative {
		n.Neg(n)
	}
	return n, true, nil
}

func decimalDigits(s string) bool {
	for i := range s {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
