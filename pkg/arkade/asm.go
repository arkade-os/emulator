package arkade

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// AssembleScript converts TS-sdk style ASM into arkade script bytes.
func AssembleScript(asm string) ([]byte, error) {
	script := make([]byte, 0, len(asm)/2)

	for token := range strings.FieldsSeq(asm) {
		if op, ok := asmOpcodes[token]; ok {
			script = append(script, op)
			continue
		}

		data, err := hex.DecodeString(token)
		if err != nil {
			return nil, fmt.Errorf("invalid ASM token: %s", token)
		}
		script = appendScriptPush(script, data)
	}

	return script, nil
}

var asmOpcodes = buildASMOpcodes()

func buildASMOpcodes() map[string]byte {
	opcodes := make(map[string]byte, 256)
	opcodes["OP_FALSE"] = OP_FALSE
	opcodes["OP_TRUE"] = OP_TRUE

	for _, op := range opcodeArray {
		name := op.name
		if name == "" || op.value >= OP_DATA_1 && op.value <= OP_PUSHDATA4 || strings.HasPrefix(name, "OP_UNKNOWN") {
			continue
		}
		switch name {
		case "OP_SMALLINTEGER", "OP_PUBKEYS", "OP_PUBKEYHASH", "OP_PUBKEY", "OP_INVALIDOPCODE":
			continue
		}

		opcodes[name] = op.value
		if suffix, ok := strings.CutPrefix(name, "OP_"); ok {
			switch suffix {
			case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16":
				continue
			}
			opcodes[suffix] = op.value
		}
	}

	return opcodes
}

func appendScriptPush(script []byte, data []byte) []byte {
	switch {
	case len(data) < OP_PUSHDATA1:
		script = append(script, byte(len(data)))
	case len(data) <= 0xff:
		script = append(script, OP_PUSHDATA1, byte(len(data)))
	case len(data) <= 0xffff:
		var lenBytes [2]byte
		binary.LittleEndian.PutUint16(lenBytes[:], uint16(len(data)))
		script = append(script, OP_PUSHDATA2)
		script = append(script, lenBytes[:]...)
	default:
		var lenBytes [4]byte
		binary.LittleEndian.PutUint32(lenBytes[:], uint32(len(data)))
		script = append(script, OP_PUSHDATA4)
		script = append(script, lenBytes[:]...)
	}
	return append(script, data...)
}
