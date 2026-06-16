package arkade

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

type opcodeSpec struct {
	opcode          byte
	validVectors    []opcodeVector
	invalidVectors  []opcodeVector
	disasm          *opcodeDisasm
	checkProperties opcodePropertyChecker
}

type opcodeCheckContext struct {
	before     *Engine
	after      *Engine
	opcodeData []byte
	execErr    error
	opcode     byte
	opcodeName string
	phase      string
	order      int
}

type opcodePropertyChecker func(t *testing.T, c opcodeCheckContext)

type opcodeDisasm struct {
	data    []byte
	compact string
	full    string
}

type opcodeVector struct {
	name             string
	inputStack       [][]byte
	inputAltStack    [][]byte
	opcodeData       []byte
	expectedStack    [][]byte
	expectedAltStack [][]byte
	expectedError    txscript.ErrorCode
	expectedExecErr  error
	setupWorld       func(*opcodeWorld)
	setupVM          func(*Engine)
}

type opcodeWorld struct {
	tx              wire.MsgTx
	prevouts        map[wire.OutPoint]*wire.TxOut
	prevFetcher     ArkPrevOutFetcher
	assetPacket     asset.Packet
	scriptByVin     map[int][]byte
	execScriptByVin map[int][]byte
	witnessByVin    map[int]wire.TxWitness
	packet          EmulatorPacket
}

var opcodeSpecs = [256]*opcodeSpec{
	OP_0:                  constantSpec(OP_0, 0),
	OP_1NEGATE:            constantSpec(OP_1NEGATE, -1),
	OP_1:                  constantSpec(OP_1, 1),
	OP_2:                  constantSpec(OP_2, 2),
	OP_3:                  constantSpec(OP_3, 3),
	OP_4:                  constantSpec(OP_4, 4),
	OP_5:                  constantSpec(OP_5, 5),
	OP_6:                  constantSpec(OP_6, 6),
	OP_7:                  constantSpec(OP_7, 7),
	OP_8:                  constantSpec(OP_8, 8),
	OP_9:                  constantSpec(OP_9, 9),
	OP_10:                 constantSpec(OP_10, 10),
	OP_11:                 constantSpec(OP_11, 11),
	OP_12:                 constantSpec(OP_12, 12),
	OP_13:                 constantSpec(OP_13, 13),
	OP_14:                 constantSpec(OP_14, 14),
	OP_15:                 constantSpec(OP_15, 15),
	OP_16:                 constantSpec(OP_16, 16),
	OP_DATA_1:             dataPushSpec(OP_DATA_1),
	OP_DATA_2:             dataPushSpec(OP_DATA_2),
	OP_DATA_3:             dataPushSpec(OP_DATA_3),
	OP_DATA_4:             dataPushSpec(OP_DATA_4),
	OP_DATA_5:             dataPushSpec(OP_DATA_5),
	OP_DATA_6:             dataPushSpec(OP_DATA_6),
	OP_DATA_7:             dataPushSpec(OP_DATA_7),
	OP_DATA_8:             dataPushSpec(OP_DATA_8),
	OP_DATA_9:             dataPushSpec(OP_DATA_9),
	OP_DATA_10:            dataPushSpec(OP_DATA_10),
	OP_DATA_11:            dataPushSpec(OP_DATA_11),
	OP_DATA_12:            dataPushSpec(OP_DATA_12),
	OP_DATA_13:            dataPushSpec(OP_DATA_13),
	OP_DATA_14:            dataPushSpec(OP_DATA_14),
	OP_DATA_15:            dataPushSpec(OP_DATA_15),
	OP_DATA_16:            dataPushSpec(OP_DATA_16),
	OP_DATA_17:            dataPushSpec(OP_DATA_17),
	OP_DATA_18:            dataPushSpec(OP_DATA_18),
	OP_DATA_19:            dataPushSpec(OP_DATA_19),
	OP_DATA_20:            dataPushSpec(OP_DATA_20),
	OP_DATA_21:            dataPushSpec(OP_DATA_21),
	OP_DATA_22:            dataPushSpec(OP_DATA_22),
	OP_DATA_23:            dataPushSpec(OP_DATA_23),
	OP_DATA_24:            dataPushSpec(OP_DATA_24),
	OP_DATA_25:            dataPushSpec(OP_DATA_25),
	OP_DATA_26:            dataPushSpec(OP_DATA_26),
	OP_DATA_27:            dataPushSpec(OP_DATA_27),
	OP_DATA_28:            dataPushSpec(OP_DATA_28),
	OP_DATA_29:            dataPushSpec(OP_DATA_29),
	OP_DATA_30:            dataPushSpec(OP_DATA_30),
	OP_DATA_31:            dataPushSpec(OP_DATA_31),
	OP_DATA_32:            dataPushSpec(OP_DATA_32),
	OP_DATA_33:            dataPushSpec(OP_DATA_33),
	OP_DATA_34:            dataPushSpec(OP_DATA_34),
	OP_DATA_35:            dataPushSpec(OP_DATA_35),
	OP_DATA_36:            dataPushSpec(OP_DATA_36),
	OP_DATA_37:            dataPushSpec(OP_DATA_37),
	OP_DATA_38:            dataPushSpec(OP_DATA_38),
	OP_DATA_39:            dataPushSpec(OP_DATA_39),
	OP_DATA_40:            dataPushSpec(OP_DATA_40),
	OP_DATA_41:            dataPushSpec(OP_DATA_41),
	OP_DATA_42:            dataPushSpec(OP_DATA_42),
	OP_DATA_43:            dataPushSpec(OP_DATA_43),
	OP_DATA_44:            dataPushSpec(OP_DATA_44),
	OP_DATA_45:            dataPushSpec(OP_DATA_45),
	OP_DATA_46:            dataPushSpec(OP_DATA_46),
	OP_DATA_47:            dataPushSpec(OP_DATA_47),
	OP_DATA_48:            dataPushSpec(OP_DATA_48),
	OP_DATA_49:            dataPushSpec(OP_DATA_49),
	OP_DATA_50:            dataPushSpec(OP_DATA_50),
	OP_DATA_51:            dataPushSpec(OP_DATA_51),
	OP_DATA_52:            dataPushSpec(OP_DATA_52),
	OP_DATA_53:            dataPushSpec(OP_DATA_53),
	OP_DATA_54:            dataPushSpec(OP_DATA_54),
	OP_DATA_55:            dataPushSpec(OP_DATA_55),
	OP_DATA_56:            dataPushSpec(OP_DATA_56),
	OP_DATA_57:            dataPushSpec(OP_DATA_57),
	OP_DATA_58:            dataPushSpec(OP_DATA_58),
	OP_DATA_59:            dataPushSpec(OP_DATA_59),
	OP_DATA_60:            dataPushSpec(OP_DATA_60),
	OP_DATA_61:            dataPushSpec(OP_DATA_61),
	OP_DATA_62:            dataPushSpec(OP_DATA_62),
	OP_DATA_63:            dataPushSpec(OP_DATA_63),
	OP_DATA_64:            dataPushSpec(OP_DATA_64),
	OP_DATA_65:            dataPushSpec(OP_DATA_65),
	OP_DATA_66:            dataPushSpec(OP_DATA_66),
	OP_DATA_67:            dataPushSpec(OP_DATA_67),
	OP_DATA_68:            dataPushSpec(OP_DATA_68),
	OP_DATA_69:            dataPushSpec(OP_DATA_69),
	OP_DATA_70:            dataPushSpec(OP_DATA_70),
	OP_DATA_71:            dataPushSpec(OP_DATA_71),
	OP_DATA_72:            dataPushSpec(OP_DATA_72),
	OP_DATA_73:            dataPushSpec(OP_DATA_73),
	OP_DATA_74:            dataPushSpec(OP_DATA_74),
	OP_DATA_75:            dataPushSpec(OP_DATA_75),
	OP_PUSHDATA1:          pushDataNSpec(OP_PUSHDATA1, 1),
	OP_PUSHDATA2:          pushDataNSpec(OP_PUSHDATA2, 2),
	OP_PUSHDATA4:          pushDataNSpec(OP_PUSHDATA4, 4),
	OP_NOP:                nopSpec(OP_NOP),
	OP_NOP1:               nopSpec(OP_NOP1),
	OP_NOP5:               nopSpec(OP_NOP5),
	OP_NOP6:               nopSpec(OP_NOP6),
	OP_NOP7:               nopSpec(OP_NOP7),
	OP_NOP8:               nopSpec(OP_NOP8),
	OP_NOP9:               nopSpec(OP_NOP9),
	OP_NOP10:              nopSpec(OP_NOP10),
	OP_IF:                 ifSpec(OP_IF),
	OP_NOTIF:              ifSpec(OP_NOTIF),
	OP_ELSE:               elseSpec(),
	OP_ENDIF:              endifSpec(),
	OP_VERIFY:             verifySpec(),
	OP_RETURN:             returnSpec(),
	OP_TOALTSTACK:         toAltStackSpec(),
	OP_FROMALTSTACK:       fromAltStackSpec(),
	OP_2DROP:              stackOpSpec(OP_2DROP),
	OP_2DUP:               stackOpSpec(OP_2DUP),
	OP_3DUP:               stackOpSpec(OP_3DUP),
	OP_2OVER:              stackOpSpec(OP_2OVER),
	OP_2ROT:               stackOpSpec(OP_2ROT),
	OP_2SWAP:              stackOpSpec(OP_2SWAP),
	OP_IFDUP:              ifDupSpec(),
	OP_DEPTH:              depthSpec(),
	OP_DROP:               stackOpSpec(OP_DROP),
	OP_DUP:                stackOpSpec(OP_DUP),
	OP_NIP:                stackOpSpec(OP_NIP),
	OP_OVER:               stackOpSpec(OP_OVER),
	OP_PICK:               pickSpec(),
	OP_ROLL:               rollSpec(),
	OP_ROT:                stackOpSpec(OP_ROT),
	OP_SWAP:               stackOpSpec(OP_SWAP),
	OP_TUCK:               stackOpSpec(OP_TUCK),
	OP_CAT:                catSpec(),
	OP_SUBSTR:             substrSpec(),
	OP_LEFT:               leftSpec(),
	OP_RIGHT:              rightSpec(),
	OP_SIZE:               sizeSpec(),
	OP_INVERT:             invertSpec(),
	OP_AND:                bitwiseSpec(OP_AND),
	OP_OR:                 bitwiseSpec(OP_OR),
	OP_XOR:                bitwiseSpec(OP_XOR),
	OP_EQUAL:              equalSpec(),
	OP_EQUALVERIFY:        equalVerifySpec(),
	OP_1ADD:               oneAddSpec(),
	OP_1SUB:               oneSubSpec(),
	OP_2MUL:               twoMulSpec(),
	OP_2DIV:               twoDivSpec(),
	OP_NEGATE:             negateSpec(),
	OP_ABS:                absSpec(),
	OP_NOT:                notSpec(),
	OP_0NOTEQUAL:          zeroNotEqualSpec(),
	OP_ADD:                addSpec(),
	OP_SUB:                subSpec(),
	OP_MUL:                mulSpec(),
	OP_DIV:                divSpec(),
	OP_MOD:                modSpec(),
	OP_LSHIFT:             shiftSpec(OP_LSHIFT),
	OP_RSHIFT:             shiftSpec(OP_RSHIFT),
	OP_BOOLAND:            boolAndSpec(),
	OP_BOOLOR:             boolOrSpec(),
	OP_NUMEQUAL:           numEqualSpec(),
	OP_NUMEQUALVERIFY:     numEqualVerifySpec(),
	OP_NUMNOTEQUAL:        numNotEqualSpec(),
	OP_LESSTHAN:           lessThanSpec(),
	OP_GREATERTHAN:        greaterThanSpec(),
	OP_LESSTHANOREQUAL:    lessThanOrEqualSpec(),
	OP_GREATERTHANOREQUAL: greaterThanOrEqualSpec(),
	OP_MIN:                minSpec(),
	OP_MAX:                maxSpec(),
	OP_WITHIN:             withinSpec(),
	OP_RIPEMD160: hashSpec(
		OP_RIPEMD160,
		"0102",
		"189f7c8b1a386ffe8eed91b3830c7a7bcd1e778c",
		20,
	),
	OP_SHA1: hashSpec(
		OP_SHA1,
		"0102",
		"0ca623e2855f2c75c842ad302fe820e41b4d197d",
		20,
	),
	OP_SHA256: hashSpec(
		OP_SHA256,
		"0102",
		"a12871fee210fb8619291eaea194581cbd2531e4b23759d225f6806923f63222",
		32,
	),
	OP_HASH160: hashSpec(
		OP_HASH160,
		"0102",
		"15cc49e191cbc520d91944600a5cb77af6aa3291",
		20,
	),
	OP_HASH256: hashSpec(
		OP_HASH256,
		"0102",
		"76a56aced915d2513dcd84c2c378b2e8aa5cd632b5b71ca2f2ac5b0e3a649bdb",
		32,
	),
	OP_CODESEPARATOR:  noContextReservedSpec(OP_CODESEPARATOR, nil),
	OP_CHECKSIG:       noContextReservedSpec(OP_CHECKSIG, [][]byte{nil, nil}),
	OP_CHECKSIGVERIFY: noContextReservedSpec(OP_CHECKSIGVERIFY, [][]byte{nil, nil}),
	OP_CHECKSIGADD: noContextReservedSpec(
		OP_CHECKSIGADD,
		[][]byte{nil, {0x01}, nil},
	),
	OP_CHECKMULTISIG:                 tapscriptDisabledSpec(OP_CHECKMULTISIG),
	OP_CHECKMULTISIGVERIFY:           tapscriptDisabledSpec(OP_CHECKMULTISIGVERIFY),
	OP_CHECKLOCKTIMEVERIFY:           checkLockTimeVerifySpec(),
	OP_CHECKSEQUENCEVERIFY:           checkSequenceVerifySpec(),
	OP_MERKLEBRANCHVERIFY:            merkleBranchVerifySpec(),
	OP_SHA256INITIALIZE:              sha256InitializeSpec(),
	OP_SHA256UPDATE:                  sha256UpdateSpec(),
	OP_SHA256FINALIZE:                sha256FinalizeSpec(),
	OP_INSPECTINPUTOUTPOINT:          inspectInputOutpointSpec(),
	OP_INSPECTINPUTARKADESCRIPTHASH:  inspectInputArkadeScriptHashSpec(),
	OP_INSPECTINPUTVALUE:             inspectInputValueSpec(),
	OP_INSPECTINPUTSCRIPTPUBKEY:      inspectInputScriptPubkeySpec(),
	OP_INSPECTINPUTSEQUENCE:          inspectInputSequenceSpec(),
	OP_CHECKSIGFROMSTACK:             checksigFromStackSpec(),
	OP_PUSHCURRENTINPUTINDEX:         pushCurrentInputIndexSpec(),
	OP_INSPECTINPUTARKADEWITNESSHASH: inspectInputArkadeWitnessHashSpec(),
	OP_INSPECTOUTPUTVALUE:            inspectOutputValueSpec(),
	OP_INSPECTOUTPUTSCRIPTPUBKEY:     inspectOutputScriptPubkeySpec(),
	OP_INSPECTVERSION:                inspectVersionSpec(),
	OP_INSPECTLOCKTIME:               inspectLocktimeSpec(),
	OP_INSPECTNUMINPUTS:              inspectNumInputsSpec(),
	OP_INSPECTNUMOUTPUTS:             inspectNumOutputsSpec(),
	OP_TXWEIGHT:                      txWeightSpec(),
	OP_NUM2BIN:                       num2BinSpec(),
	OP_BIN2NUM:                       bin2NumSpec(),
	OP_REVERSEBYTES:                  reverseBytesSpec(),
	OP_MODEXP:                        modexpSpec(),
	OP_UNKNOWN219:                    invalidSpec(OP_UNKNOWN219),
	OP_UNKNOWN220:                    invalidSpec(OP_UNKNOWN220),
	OP_UNKNOWN221:                    invalidSpec(OP_UNKNOWN221),
	OP_UNKNOWN222:                    invalidSpec(OP_UNKNOWN222),
	OP_UNKNOWN223:                    invalidSpec(OP_UNKNOWN223),
	OP_ECADD:                         ecAddSpec(),
	OP_ECMUL:                         ecMulSpec(),
	OP_ECPAIRING:                     ecPairingSpec(),
	OP_ECMULSCALARVERIFY:             ecmulScalarVerifySpec(),
	OP_TWEAKVERIFY:                   tweakVerifySpec(),
	OP_INSPECTNUMASSETGROUPS:         assetSpec(OP_INSPECTNUMASSETGROUPS),
	OP_INSPECTASSETGROUPASSETID:      assetSpec(OP_INSPECTASSETGROUPASSETID),
	OP_INSPECTASSETGROUPCTRL:         assetSpec(OP_INSPECTASSETGROUPCTRL),
	OP_FINDASSETGROUPBYASSETID:       assetSpec(OP_FINDASSETGROUPBYASSETID),
	OP_INSPECTASSETGROUPMETADATAHASH: assetSpec(OP_INSPECTASSETGROUPMETADATAHASH),
	OP_INSPECTASSETGROUPNUM:          assetSpec(OP_INSPECTASSETGROUPNUM),
	OP_INSPECTASSETGROUP:             assetSpec(OP_INSPECTASSETGROUP),
	OP_INSPECTASSETGROUPSUM:          assetSpec(OP_INSPECTASSETGROUPSUM),
	OP_INSPECTOUTASSETCOUNT:          assetSpec(OP_INSPECTOUTASSETCOUNT),
	OP_INSPECTOUTASSETAT:             assetSpec(OP_INSPECTOUTASSETAT),
	OP_INSPECTOUTASSETLOOKUP:         assetSpec(OP_INSPECTOUTASSETLOOKUP),
	OP_INSPECTINASSETCOUNT:           assetSpec(OP_INSPECTINASSETCOUNT),
	OP_INSPECTINASSETAT:              assetSpec(OP_INSPECTINASSETAT),
	OP_INSPECTINASSETLOOKUP:          assetSpec(OP_INSPECTINASSETLOOKUP),
	OP_TXID:                          txIDSpec(),
	OP_RESERVED:                      reservedSpec(OP_RESERVED),
	OP_VER:                           reservedSpec(OP_VER),
	OP_VERIF:                         reservedSpec(OP_VERIF),
	OP_VERNOTIF:                      reservedSpec(OP_VERNOTIF),
	OP_RESERVED1:                     reservedSpec(OP_RESERVED1),
	OP_RESERVED2:                     reservedSpec(OP_RESERVED2),
	OP_UNKNOWN187:                    invalidSpec(OP_UNKNOWN187),
	OP_UNKNOWN188:                    invalidSpec(OP_UNKNOWN188),
	OP_UNKNOWN189:                    invalidSpec(OP_UNKNOWN189),
	OP_UNKNOWN190:                    invalidSpec(OP_UNKNOWN190),
	OP_UNKNOWN191:                    invalidSpec(OP_UNKNOWN191),
	OP_UNKNOWN192:                    invalidSpec(OP_UNKNOWN192),
	OP_UNKNOWN193:                    invalidSpec(OP_UNKNOWN193),
	OP_UNKNOWN194:                    invalidSpec(OP_UNKNOWN194),
	OP_UNKNOWN195:                    invalidSpec(OP_UNKNOWN195),
	OP_UNKNOWN208:                    invalidSpec(OP_UNKNOWN208),
	OP_INSPECTPACKET:                 inspectPacketSpec(),
	OP_INSPECTINPUTPACKET:            inspectInputPacketSpec(),
	OP_SIGHASH:                       sighashSpec(),
	OP_UNKNOWN247:                    invalidSpec(OP_UNKNOWN247),
	OP_UNKNOWN248:                    invalidSpec(OP_UNKNOWN248),
	OP_UNKNOWN249:                    invalidSpec(OP_UNKNOWN249),
	OP_SMALLINTEGER:                  invalidSpec(OP_SMALLINTEGER),
	OP_PUBKEYS:                       invalidSpec(OP_PUBKEYS),
	OP_UNKNOWN252:                    invalidSpec(OP_UNKNOWN252),
	OP_PUBKEYHASH:                    invalidSpec(OP_PUBKEYHASH),
	OP_PUBKEY:                        invalidSpec(OP_PUBKEY),
	OP_INVALIDOPCODE:                 invalidSpec(OP_INVALIDOPCODE),
}

func TestOpcodeVectors(t *testing.T) {
	t.Parallel()

	for opcode, spec := range opcodeSpecs {
		if spec == nil {
			continue
		}

		opcode := byte(opcode)
		t.Run(opcodeArray[opcode].name, func(t *testing.T) {
			t.Parallel()

			runVector := func(t *testing.T, v opcodeVector) {
				t.Helper()
				world := buildOpcodeWorld()
				if v.setupWorld != nil {
					v.setupWorld(world)
				}
				vm, err := newOpcodeEngine(world, 0)
				require.NoError(t, err)
				if v.setupWorld != nil {
					vm.emulatorPacket = world.packet
				}
				vm.SetStack(v.inputStack)
				vm.SetAltStack(v.inputAltStack)
				if v.setupVM != nil {
					v.setupVM(vm)
				}
				opcodeData := append([]byte(nil), v.opcodeData...)
				before := cloneEngineForExpectedResult(vm)

				require.NotNil(t, spec.checkProperties)
				err = invokeOpcodeWithData(spec.opcode, opcodeData, vm)
				spec.checkProperties(
					t,
					opcodeCheckContext{
						before:     before,
						after:      vm,
						opcodeData: opcodeData,
						execErr:    err,
					},
				)

				if v.expectedError != 0 {
					requireScriptErrorCode(t, err, v.expectedError)
					return
				}
				if v.expectedExecErr != nil {
					require.ErrorIs(t, err, v.expectedExecErr)
					return
				}
				require.NoError(t, err)

				if v.expectedStack != nil {
					require.Equal(t, v.expectedStack, vm.GetStack())
				}
				if v.expectedAltStack != nil {
					require.Equal(t, v.expectedAltStack, vm.GetAltStack())
				}
			}

			t.Run("valid", func(t *testing.T) {
				t.Parallel()
				for _, v := range spec.validVectors {
					t.Run(v.name, func(t *testing.T) {
						t.Parallel()
						runVector(t, v)
					})
				}
			})
			t.Run("invalid", func(t *testing.T) {
				t.Parallel()
				for _, v := range spec.invalidVectors {
					t.Run(v.name, func(t *testing.T) {
						t.Parallel()
						runVector(t, v)
					})
				}
			})
		})
	}
}

func TestOpcodeDisasm(t *testing.T) {
	t.Parallel()

	for opcode, spec := range opcodeSpecs {
		if spec == nil {
			continue
		}

		opcodeVal := byte(opcode)
		t.Run(opcodeArray[opcodeVal].name, func(t *testing.T) {
			t.Parallel()

			data := []byte{}
			expectedCompact := opcodeArray[opcodeVal].name
			expectedFull := opcodeArray[opcodeVal].name

			if spec.disasm != nil {
				data = spec.disasm.data
				expectedCompact = spec.disasm.compact
				expectedFull = spec.disasm.full
			}

			// Compact mode
			var buf strings.Builder
			disasmOpcode(&buf, &opcodeArray[opcodeVal], data, true)
			require.Equal(t, expectedCompact, buf.String(), "compact disasm mismatch")

			// Full mode
			buf.Reset()
			disasmOpcode(&buf, &opcodeArray[opcodeVal], data, false)
			require.Equal(t, expectedFull, buf.String(), "full disasm mismatch")
		})
	}
}

// Builders
func constantSpec(op byte, val int64) *opcodeSpec {
	compact := strconv.FormatInt(val, 10)
	full := opcodeArray[op].name
	wantTop := scriptNum(val).Bytes()
	return &opcodeSpec{
		opcode: op,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.NoError(t, c.execErr)
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			beforeStack := c.before.GetStack()
			afterStack := c.after.GetStack()
			require.Equal(t, len(beforeStack)+1, len(afterStack))
			require.Equal(t, beforeStack, afterStack[:len(beforeStack)])
			require.Equal(t, wantTop, afterStack[len(afterStack)-1])
		},
		validVectors: []opcodeVector{
			{name: "push", expectedStack: [][]byte{scriptNum(val).Bytes()}},
		},
		disasm: &opcodeDisasm{
			compact: compact,
			full:    full,
		},
	}
}

func pushDataPropertyChecker(op byte) opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
		require.Equal(t, c.before.condStack, c.after.condStack)

		beforeStack := c.before.GetStack()
		afterStack := c.after.GetStack()
		if c.execErr != nil {
			requireScriptErrorCodeIn(t, c.execErr,
				txscript.ErrMinimalData,
				txscript.ErrElementTooBig,
			)
			require.Equal(t, beforeStack, afterStack)
			return
		}

		require.Equal(t, len(beforeStack)+1, len(afterStack))
		require.Equal(t, beforeStack, afterStack[:len(beforeStack)])

		wantTop := c.opcodeData
		if wantTop == nil {
			wantTop = []byte{}
		}
		require.Truef(
			t,
			bytes.Equal(wantTop, afterStack[len(afterStack)-1]),
			"opcode=%s",
			opcodeArray[op].name,
		)
	}
}

func dataPushSpec(op byte) *opcodeSpec {
	data := bytes.Repeat([]byte{0x01}, int(op))
	if op == OP_DATA_1 {
		data = []byte{0x17}
	}
	compact := hex.EncodeToString(data)
	full := fmt.Sprintf("%s 0x%s", opcodeArray[op].name, compact)

	spec := &opcodeSpec{
		opcode:          op,
		checkProperties: pushDataPropertyChecker(op),
		validVectors: []opcodeVector{
			{name: "push", opcodeData: data, expectedStack: [][]byte{data}},
		},
		disasm: &opcodeDisasm{
			data:    data,
			compact: compact,
			full:    full,
		},
	}
	if op == OP_DATA_1 {
		spec.invalidVectors = []opcodeVector{
			{
				name:          "non_minimal_small_int",
				opcodeData:    []byte{0x01},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name:          "non_minimal_negative_one",
				opcodeData:    []byte{0x81},
				expectedError: txscript.ErrMinimalData,
			},
		}
	}
	return spec
}

func pushDataNSpec(op byte, n int) *opcodeSpec {
	data := bytes.Repeat([]byte{0x01}, n)
	compact := strings.Repeat("01", n)
	full := fmt.Sprintf("%s 0x%0*x 0x%s", opcodeArray[op].name, n*2, len(data), compact)

	spec := &opcodeSpec{
		opcode:          op,
		checkProperties: pushDataPropertyChecker(op),
		disasm: &opcodeDisasm{
			data:    data,
			compact: compact,
			full:    full,
		},
	}

	switch op {
	case OP_PUSHDATA1:
		validData := bytes.Repeat([]byte{0x01}, 76)
		spec.validVectors = []opcodeVector{
			{name: "push", opcodeData: validData, expectedStack: [][]byte{validData}},
		}
		spec.invalidVectors = []opcodeVector{
			{
				name:          "non_minimal_direct_push",
				opcodeData:    []byte{0x17},
				expectedError: txscript.ErrMinimalData,
			},
		}
	case OP_PUSHDATA2:
		validData := bytes.Repeat([]byte{0x01}, 256)
		spec.validVectors = []opcodeVector{
			{name: "push", opcodeData: validData, expectedStack: [][]byte{validData}},
		}
		spec.invalidVectors = []opcodeVector{
			{
				name:          "non_minimal_pushdata1",
				opcodeData:    bytes.Repeat([]byte{0x01}, 255),
				expectedError: txscript.ErrMinimalData,
			},
		}
	case OP_PUSHDATA4:
		spec.invalidVectors = []opcodeVector{
			{
				name:          "non_minimal_pushdata2",
				opcodeData:    bytes.Repeat([]byte{0x01}, 256),
				expectedError: txscript.ErrMinimalData,
			},
		}
	}

	return spec
}

func nopSpec(op byte) *opcodeSpec {
	var err txscript.ErrorCode
	full := opcodeArray[op].name
	switch op {
	case OP_NOP1, OP_NOP5, OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10:
		err = txscript.ErrDiscourageUpgradableNOPs
	}
	checker := unchangedStateChecker()
	if err != 0 {
		checker = unchangedStateWithErrorCodeChecker(err)
	}
	spec := &opcodeSpec{
		opcode:          op,
		checkProperties: checker,
		disasm: &opcodeDisasm{
			compact: full,
			full:    full,
		},
	}
	if err != 0 {
		spec.invalidVectors = []opcodeVector{{name: "nop", expectedError: err}}
	} else {
		spec.validVectors = []opcodeVector{{name: "nop"}}
	}
	return spec
}

func invalidSpec(op byte) *opcodeSpec {
	return &opcodeSpec{
		opcode:          op,
		checkProperties: unchangedStateWithErrorCodeChecker(txscript.ErrReservedOpcode),
		invalidVectors: []opcodeVector{
			{name: "invalid", expectedError: txscript.ErrReservedOpcode},
		},
	}
}

func reservedSpec(op byte) *opcodeSpec {
	return &opcodeSpec{
		opcode:          op,
		checkProperties: unchangedStateWithErrorCodeChecker(txscript.ErrReservedOpcode),
		invalidVectors: []opcodeVector{
			{name: "reserved", expectedError: txscript.ErrReservedOpcode},
		},
	}
}

func unchangedStateChecker() opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		require.NoError(t, c.execErr)
		require.Equal(t, c.before.GetStack(), c.after.GetStack())
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
	}
}

func unchangedStateWithErrorCodeChecker(code txscript.ErrorCode) opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		requireScriptErrorCode(t, c.execErr, code)
		require.Equal(t, c.before.GetStack(), c.after.GetStack())
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
	}
}

func errorNoMutationChecker(code txscript.ErrorCode) opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		requireScriptErrorCode(t, c.execErr, code)
		require.Equal(t, c.before.GetStack(), c.after.GetStack())
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
		require.Equal(t, c.before.condStack, c.after.condStack)
	}
}

func returnSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_RETURN,
		checkProperties: errorNoMutationChecker(txscript.ErrEarlyReturn),
		invalidVectors: []opcodeVector{
			{name: "early_return", expectedError: txscript.ErrEarlyReturn},
		},
	}
}

func noContextReservedSpec(op byte, inputStack [][]byte) *opcodeSpec {
	return &opcodeSpec{
		opcode:          op,
		checkProperties: errorNoMutationChecker(txscript.ErrReservedOpcode),
		invalidVectors: []opcodeVector{
			{
				name:          "invalid_no_context",
				inputStack:    inputStack,
				expectedError: txscript.ErrReservedOpcode,
			},
		},
	}
}

func tapscriptDisabledSpec(op byte) *opcodeSpec {
	return &opcodeSpec{
		opcode:          op,
		checkProperties: errorNoMutationChecker(txscript.ErrTapscriptCheckMultisig),
		invalidVectors: []opcodeVector{
			{name: "disabled", expectedError: txscript.ErrTapscriptCheckMultisig},
		},
	}
}

func ecmulScalarVerifySpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_ECMULSCALARVERIFY,
		checkProperties: ecmulLikePropertyChecker(),
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func tweakVerifySpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_TWEAKVERIFY,
		checkProperties: ecmulLikePropertyChecker(),
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func ecmulLikePropertyChecker() opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
		require.Equal(t, c.before.condStack, c.after.condStack)
		if c.execErr != nil {
			requireScriptErrorCode(t, c.execErr, txscript.ErrInvalidStackOperation)
			return
		}
		require.Equal(t, len(c.before.GetStack())-3, len(c.after.GetStack()))
	}
}

func checksigFromStackSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_CHECKSIGFROMSTACK,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				if beforeDepth < 3 {
					requireScriptErrorCode(t, c.execErr, txscript.ErrInvalidStackOperation)
				}
				return
			}

			require.GreaterOrEqual(t, beforeDepth, 3)
			require.Equal(t, beforeDepth-2, afterDepth)
			top := c.after.GetStack()[afterDepth-1]
			require.True(t, len(top) == 0 || bytes.Equal(top, []byte{1}))
		},
		validVectors: []opcodeVector{
			{name: "valid_sig", inputStack: [][]byte{
				{
					0xE9, 0x07, 0x83, 0x1F, 0x80, 0x84, 0x8D, 0x10,
					0x69, 0xA5, 0x37, 0x1B, 0x40, 0x24, 0x10, 0x36,
					0x4B, 0xDF, 0x1C, 0x5F, 0x83, 0x07, 0xB0, 0x08,
					0x4C, 0x55, 0xF1, 0xCE, 0x2D, 0xCA, 0x82, 0x15,
					0x25, 0xF6, 0x6A, 0x4A, 0x85, 0xEA, 0x8B, 0x71,
					0xE4, 0x82, 0xA7, 0x4F, 0x38, 0x2D, 0x2C, 0xE5,
					0xEB, 0xEE, 0xE8, 0xFD, 0xB2, 0x17, 0x2F, 0x47,
					0x7D, 0xF4, 0x90, 0x0D, 0x31, 0x05, 0x36, 0xC0,
				},
				{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				{
					0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10,
					0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D, 0x52, 0x29,
					0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0,
					0x86, 0x01, 0xF1, 0x13, 0xBC, 0xE0, 0x36, 0xF9,
				},
			}, expectedStack: [][]byte{{1}}},
			{
				name:          "empty_sig",
				inputStack:    [][]byte{nil, nil, nil},
				expectedStack: [][]byte{emptyByteVector()},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "invalid_pk_size",
				inputStack:    [][]byte{{0x01}, {0x02}, {0x03}},
				expectedError: txscript.ErrInvalidStackOperation,
			},
		},
	}
}

func merkleBranchVerifySpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_MERKLEBRANCHVERIFY,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireScriptErrorCode(t, c.execErr, txscript.ErrInvalidStackOperation)
				return
			}

			require.GreaterOrEqual(t, beforeDepth, 4)
			require.Equal(t, beforeDepth-3, afterDepth)
			require.Len(t, c.after.GetStack()[afterDepth-1], 32)
		},
		validVectors: []opcodeVector{
			{
				name: "valid_path",
				inputStack: [][]byte{
					[]byte("tag_leaf"),
					[]byte("tag_branch"),
					bytes.Repeat([]byte{0x01}, 32),
					bytes.Repeat([]byte{0x00}, 32),
				},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "invalid_proof_len",
				inputStack:    [][]byte{[]byte("tag_l"), []byte("tag_b"), {0x01}, []byte("leaf")},
				expectedError: txscript.ErrInvalidStackOperation,
			},
		},
	}
}

func verifySpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_VERIFY,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireScriptErrorCodeIn(
					t,
					c.execErr,
					txscript.ErrInvalidStackOperation,
					txscript.ErrVerify,
				)
				require.True(t, afterDepth == beforeDepth || afterDepth == beforeDepth-1)
				return
			}

			require.Equal(t, beforeDepth-1, afterDepth)
		},
		validVectors: []opcodeVector{
			{name: "true", inputStack: [][]byte{{0x01}}},
		},
		invalidVectors: []opcodeVector{
			{name: "false", inputStack: [][]byte{nil}, expectedError: txscript.ErrVerify},
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func ifSpec(op byte) *opcodeSpec {
	spec := &opcodeSpec{
		opcode: op,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			branchExecuting := len(c.before.condStack) == 0 ||
				c.before.condStack[len(c.before.condStack)-1] == txscript.OpCondTrue

			if c.execErr != nil {
				requireScriptErrorCodeIn(
					t,
					c.execErr,
					txscript.ErrInvalidStackOperation,
					txscript.ErrMinimalIf,
				)
				require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
				require.Equal(t, c.before.condStack, c.after.condStack)
				require.True(t, afterDepth == beforeDepth || afterDepth == beforeDepth-1)
				return
			}

			require.Equal(t, len(c.before.condStack)+1, len(c.after.condStack))
			if branchExecuting {
				require.Equal(t, beforeDepth-1, afterDepth)
			} else {
				require.Equal(t, beforeDepth, afterDepth)
			}
		},
		validVectors: []opcodeVector{
			{name: "true", inputStack: [][]byte{{0x01}}},
			{name: "false", inputStack: [][]byte{nil}},
			{
				name:       "nested_skip",
				inputStack: [][]byte{{0x02}},
				setupVM: func(vm *Engine) {
					vm.condStack = append(vm.condStack, txscript.OpCondFalse)
				},
			},
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "minimal_if_bad_byte",
				inputStack:    [][]byte{{0x02}},
				expectedError: txscript.ErrMinimalIf,
			},
			{
				name:          "minimal_if_bad_len",
				inputStack:    [][]byte{{0x01, 0x00}},
				expectedError: txscript.ErrMinimalIf,
			},
		},
	}
	return spec
}

func elseSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_ELSE,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetStack(), c.after.GetStack())
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())

			if c.execErr != nil {
				requireScriptErrorCode(t, c.execErr, txscript.ErrUnbalancedConditional)
				require.Equal(t, c.before.condStack, c.after.condStack)
				return
			}

			require.Equal(t, len(c.before.condStack), len(c.after.condStack))
		},
		validVectors: []opcodeVector{
			{
				name: "balanced_true_to_false",
				setupVM: func(vm *Engine) {
					vm.condStack = []int{txscript.OpCondTrue}
				},
			},
			{
				name: "balanced_false_to_true",
				setupVM: func(vm *Engine) {
					vm.condStack = []int{txscript.OpCondFalse}
				},
			},
			{
				name: "balanced_skip_stays_skip",
				setupVM: func(vm *Engine) {
					vm.condStack = []int{txscript.OpCondSkip}
				},
			},
		},
		invalidVectors: []opcodeVector{
			{name: "unbalanced", expectedError: txscript.ErrUnbalancedConditional},
		},
	}
}

func endifSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_ENDIF,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetStack(), c.after.GetStack())
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())

			if c.execErr != nil {
				requireScriptErrorCode(t, c.execErr, txscript.ErrUnbalancedConditional)
				require.Equal(t, c.before.condStack, c.after.condStack)
				return
			}

			require.Equal(t, len(c.before.condStack)-1, len(c.after.condStack))
		},
		validVectors: []opcodeVector{
			{
				name: "balanced_pop",
				setupVM: func(vm *Engine) {
					vm.condStack = []int{txscript.OpCondTrue, txscript.OpCondFalse}
				},
			},
		},
		invalidVectors: []opcodeVector{
			{name: "unbalanced", expectedError: txscript.ErrUnbalancedConditional},
		},
	}
}

func toAltStackSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_TOALTSTACK,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeStack := len(c.before.GetStack())
			afterStack := len(c.after.GetStack())
			beforeAlt := len(c.before.GetAltStack())
			afterAlt := len(c.after.GetAltStack())
			if c.execErr != nil {
				requireScriptErrorCode(t, c.execErr, txscript.ErrInvalidStackOperation)
				require.Equal(t, c.before.GetStack(), c.after.GetStack())
				require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
				return
			}

			require.Equal(t, beforeStack-1, afterStack)
			require.Equal(t, beforeAlt+1, afterAlt)
		},
		validVectors: []opcodeVector{
			{name: "move", inputStack: [][]byte{{0x01}}, expectedAltStack: [][]byte{{0x01}}},
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func fromAltStackSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_FROMALTSTACK,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeStack := len(c.before.GetStack())
			afterStack := len(c.after.GetStack())
			beforeAlt := len(c.before.GetAltStack())
			afterAlt := len(c.after.GetAltStack())
			if c.execErr != nil {
				requireScriptErrorCode(t, c.execErr, txscript.ErrInvalidStackOperation)
				require.Equal(t, c.before.GetStack(), c.after.GetStack())
				require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
				return
			}

			require.Equal(t, beforeStack+1, afterStack)
			require.Equal(t, beforeAlt-1, afterAlt)
		},
		validVectors: []opcodeVector{
			{name: "move_back", inputAltStack: [][]byte{{0x01}}, expectedStack: [][]byte{{0x01}}},
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func ifDupSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_IFDUP,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireScriptErrorCode(t, c.execErr, txscript.ErrInvalidStackOperation)
				require.Equal(t, c.before.GetStack(), c.after.GetStack())
				return
			}

			require.True(t, afterDepth == beforeDepth || afterDepth == beforeDepth+1)
		},
		validVectors: []opcodeVector{
			{name: "zero", inputStack: [][]byte{nil}, expectedStack: [][]byte{zeroStackItem()}},
			{
				name:          "non_zero",
				inputStack:    [][]byte{{0x01}},
				expectedStack: [][]byte{{0x01}, {0x01}},
			},
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func depthSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_DEPTH,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)
			require.NoError(t, c.execErr)
			require.Equal(t, len(c.before.GetStack())+1, len(c.after.GetStack()))
		},
		validVectors: []opcodeVector{
			{name: "empty", expectedStack: [][]byte{zeroStackItem()}},
			{
				name:          "two",
				inputStack:    [][]byte{{0x01}, {0x02}},
				expectedStack: [][]byte{{0x01}, {0x02}, scriptNum(2).Bytes()},
			},
		},
	}
}

func pickSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_PICK,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireScriptErrorCodeIn(t, c.execErr,
					txscript.ErrInvalidStackOperation,
					txscript.ErrNumberTooBig,
					txscript.ErrMinimalData,
				)
				require.True(t, afterDepth == beforeDepth || afterDepth == beforeDepth-1)
				return
			}

			require.Equal(t, beforeDepth, afterDepth)
		},
		validVectors: []opcodeVector{
			{
				name:          "pick_0",
				inputStack:    [][]byte{{0x01}, {0x02}, nil},
				expectedStack: [][]byte{{0x01}, {0x02}, {0x02}},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "negative_index",
				inputStack:    [][]byte{{0x01}, scriptNum(-1).Bytes()},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name:          "out_of_range",
				inputStack:    [][]byte{{0x01}, scriptNum(2).Bytes()},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func rollSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_ROLL,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireScriptErrorCodeIn(t, c.execErr,
					txscript.ErrInvalidStackOperation,
					txscript.ErrNumberTooBig,
					txscript.ErrMinimalData,
				)
				require.True(t, afterDepth == beforeDepth || afterDepth == beforeDepth-1)
				return
			}

			require.Equal(t, beforeDepth-1, afterDepth)
		},
		validVectors: []opcodeVector{
			{
				name:          "roll_1",
				inputStack:    [][]byte{{0x01}, {0x02}, {0x01}},
				expectedStack: [][]byte{{0x02}, {0x01}},
			},
			{
				name:          "roll_0",
				inputStack:    [][]byte{{0x01}, {0x02}, nil},
				expectedStack: [][]byte{{0x01}, {0x02}},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "negative_index",
				inputStack:    [][]byte{{0x01}, scriptNum(-1).Bytes()},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name:          "out_of_range",
				inputStack:    [][]byte{{0x01}, scriptNum(2).Bytes()},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func stackOpSpec(op byte) *opcodeSpec {
	vector := opcodeVector{name: "valid"}

	switch op {
	case OP_2DROP:
		vector.inputStack = [][]byte{{0x01}, {0x02}}
		vector.expectedStack = [][]byte{}
	case OP_2DUP:
		vector.inputStack = [][]byte{{0x01}, {0x02}}
		vector.expectedStack = [][]byte{{0x01}, {0x02}, {0x01}, {0x02}}
	case OP_3DUP:
		vector.inputStack = [][]byte{{0x01}, {0x02}, {0x03}}
		vector.expectedStack = [][]byte{{0x01}, {0x02}, {0x03}, {0x01}, {0x02}, {0x03}}
	case OP_2OVER:
		vector.inputStack = [][]byte{{0x01}, {0x02}, {0x03}, {0x04}}
		vector.expectedStack = [][]byte{{0x01}, {0x02}, {0x03}, {0x04}, {0x01}, {0x02}}
	case OP_2ROT:
		vector.inputStack = [][]byte{{0x01}, {0x02}, {0x03}, {0x04}, {0x05}, {0x06}}
		vector.expectedStack = [][]byte{{0x03}, {0x04}, {0x05}, {0x06}, {0x01}, {0x02}}
	case OP_2SWAP:
		vector.inputStack = [][]byte{{0x01}, {0x02}, {0x03}, {0x04}}
		vector.expectedStack = [][]byte{{0x03}, {0x04}, {0x01}, {0x02}}
	case OP_DROP:
		vector.inputStack = [][]byte{{0x01}}
		vector.expectedStack = [][]byte{}
	case OP_DUP:
		vector.inputStack = [][]byte{{0x01}}
		vector.expectedStack = [][]byte{{0x01}, {0x01}}
	case OP_NIP:
		vector.inputStack = [][]byte{{0x01}, {0x02}}
		vector.expectedStack = [][]byte{{0x02}}
	case OP_OVER:
		vector.inputStack = [][]byte{{0x01}, {0x02}}
		vector.expectedStack = [][]byte{{0x01}, {0x02}, {0x01}}
	case OP_ROT:
		vector.inputStack = [][]byte{{0x01}, {0x02}, {0x03}}
		vector.expectedStack = [][]byte{{0x02}, {0x03}, {0x01}}
	case OP_SWAP:
		vector.inputStack = [][]byte{{0x01}, {0x02}}
		vector.expectedStack = [][]byte{{0x02}, {0x01}}
	case OP_TUCK:
		vector.inputStack = [][]byte{{0x01}, {0x02}}
		vector.expectedStack = [][]byte{{0x02}, {0x01}, {0x02}}
	default:
		panic(fmt.Sprintf("missing stack op vector mapping for opcode %s", opcodeArray[op].name))
	}

	return &opcodeSpec{
		opcode:       op,
		validVectors: []opcodeVector{vector},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equalf(
				t,
				c.before.GetAltStack(),
				c.after.GetAltStack(),
				"opcode=%s (0x%02x) phase=%s order=%d",
				c.opcodeName,
				c.opcode,
				c.phase,
				c.order,
			)
			require.Equalf(
				t,
				c.before.condStack,
				c.after.condStack,
				"opcode=%s (0x%02x) phase=%s order=%d",
				c.opcodeName,
				c.opcode,
				c.phase,
				c.order,
			)

			if c.execErr != nil {
				requireScriptErrorCode(t, c.execErr, txscript.ErrInvalidStackOperation)
				return
			}

			require.NoError(t, c.execErr)
		},
	}
}

func catSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_CAT,
		checkProperties: byteTransformPropertyChecker(OP_CAT),
		validVectors: []opcodeVector{
			{
				name:          "concat",
				inputStack:    [][]byte{{0x01}, {0x02}},
				expectedStack: [][]byte{{0x01, 0x02}},
			},
			{
				// Concatenating to exactly MaxScriptElementSize (520) is
				// allowed; only results strictly larger are rejected.
				name: "result_at_max_element_size",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, 260),
					bytes.Repeat([]byte{0x02}, 260),
				},
				expectedStack: [][]byte{
					append(bytes.Repeat([]byte{0x01}, 260), bytes.Repeat([]byte{0x02}, 260)...),
				},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "underflow",
				inputStack:    [][]byte{{0x01}},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				// Two individually valid (<=520 byte) operands whose
				// concatenation exceeds MaxScriptElementSize (520) must
				// fail rather than produce an oversized stack element.
				name: "result_exceeds_max_element_size",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, 300),
					bytes.Repeat([]byte{0x02}, 300),
				},
				expectedError: txscript.ErrElementTooBig,
			},
		},
	}
}

func substrSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_SUBSTR,
		checkProperties: byteTransformPropertyChecker(OP_SUBSTR),
		validVectors: []opcodeVector{
			{
				name:          "slice",
				inputStack:    [][]byte{{0x01, 0x02, 0x03}, {0x01}, {0x01}},
				expectedStack: [][]byte{{0x02}},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "invalid_range",
				inputStack:    [][]byte{{0x01, 0x02, 0x03}, {0x01}, {0x03}},
				expectedError: txscript.ErrInvalidIndex,
			},
			{
				name:          "underflow",
				inputStack:    [][]byte{{0x01}, {0x01}},
				expectedError: txscript.ErrInvalidStackOperation,
			},
		},
	}
}

func leftSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_LEFT,
		checkProperties: byteTransformPropertyChecker(OP_LEFT),
		validVectors: []opcodeVector{
			{
				name:          "take",
				inputStack:    [][]byte{{0x01, 0x02}, {0x01}},
				expectedStack: [][]byte{{0x01}},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "invalid_n",
				inputStack:    [][]byte{{0x01}, {0x02}},
				expectedError: txscript.ErrInvalidIndex,
			},
			{
				name:          "underflow",
				inputStack:    [][]byte{},
				expectedError: txscript.ErrInvalidStackOperation,
			},
		},
	}
}

func rightSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_RIGHT,
		checkProperties: byteTransformPropertyChecker(OP_RIGHT),
		validVectors: []opcodeVector{
			{
				name:          "take",
				inputStack:    [][]byte{{0x01, 0x02}, {0x01}},
				expectedStack: [][]byte{{0x02}},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "invalid_n",
				inputStack:    [][]byte{{0x01}, {0x02}},
				expectedError: txscript.ErrInvalidIndex,
			},
			{
				name:          "underflow",
				inputStack:    [][]byte{},
				expectedError: txscript.ErrInvalidStackOperation,
			},
		},
	}
}

func sizeSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_SIZE,
		checkProperties: byteTransformPropertyChecker(OP_SIZE),
		validVectors: []opcodeVector{
			{
				name:          "empty",
				inputStack:    [][]byte{nil},
				expectedStack: [][]byte{zeroStackItem(), zeroStackItem()},
			},
			{
				name:          "three",
				inputStack:    [][]byte{{0x01, 0x02, 0x03}},
				expectedStack: [][]byte{{0x01, 0x02, 0x03}, {0x03}},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "underflow",
				inputStack:    [][]byte{},
				expectedError: txscript.ErrInvalidStackOperation,
			},
		},
	}
}

func invertSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_INVERT,
		checkProperties: byteTransformPropertyChecker(OP_INVERT),
		validVectors: []opcodeVector{
			{
				name:          "not",
				inputStack:    [][]byte{{0xAA, 0x55}},
				expectedStack: [][]byte{{0x55, 0xAA}},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "underflow",
				inputStack:    [][]byte{},
				expectedError: txscript.ErrInvalidStackOperation,
			},
		},
	}
}

func byteTransformPropertyChecker(op byte) opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
		require.Equal(t, c.before.condStack, c.after.condStack)

		beforeDepth := len(c.before.GetStack())
		afterDepth := len(c.after.GetStack())
		if c.execErr != nil {
			requireScriptErrorCodeIn(t, c.execErr,
				txscript.ErrInvalidStackOperation,
				txscript.ErrInvalidIndex,
				txscript.ErrNumberTooBig,
				txscript.ErrMinimalData,
				txscript.ErrElementTooBig,
			)
			require.LessOrEqual(t, afterDepth, beforeDepth)
			return
		}

		switch op {
		case OP_INVERT:
			require.Equal(t, beforeDepth, afterDepth)
		case OP_SIZE:
			require.Equal(t, beforeDepth+1, afterDepth)
		case OP_CAT, OP_LEFT, OP_RIGHT:
			require.Equal(t, beforeDepth-1, afterDepth)
		case OP_SUBSTR:
			require.Equal(t, beforeDepth-2, afterDepth)
		default:
			t.Fatalf("unsupported byte transform %s", opcodeArray[op].name)
		}

		if op == OP_SIZE {
			top := c.after.GetStack()[afterDepth-1]
			require.LessOrEqual(t, len(top), 5)
		}
	}
}

func equalSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_EQUAL,
		checkProperties: equalPropertyChecker(OP_EQUAL),
		validVectors: []opcodeVector{
			{name: "equal", inputStack: [][]byte{{0x01}, {0x01}}, expectedStack: [][]byte{{1}}},
			{
				name:          "not_equal",
				inputStack:    [][]byte{{0x01}, {0x02}},
				expectedStack: [][]byte{falseStackItem()},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "underflow",
				inputStack:    [][]byte{},
				expectedError: txscript.ErrInvalidStackOperation,
			},
		},
	}
}

func equalVerifySpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_EQUALVERIFY,
		checkProperties: equalPropertyChecker(OP_EQUALVERIFY),
		validVectors: []opcodeVector{
			{name: "equal", inputStack: [][]byte{{0x01}, {0x01}}},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "not_equal",
				inputStack:    [][]byte{{0x01}, {0x02}},
				expectedError: txscript.ErrEqualVerify,
			},
			{
				name:          "underflow",
				inputStack:    [][]byte{},
				expectedError: txscript.ErrInvalidStackOperation,
			},
		},
	}
}

func equalPropertyChecker(op byte) opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
		require.Equal(t, c.before.condStack, c.after.condStack)

		beforeDepth := len(c.before.GetStack())
		afterDepth := len(c.after.GetStack())
		if c.execErr != nil {
			requireScriptErrorCodeIn(
				t,
				c.execErr,
				txscript.ErrInvalidStackOperation,
				txscript.ErrEqualVerify,
			)
			require.LessOrEqual(t, afterDepth, beforeDepth)
			return
		}

		if op == OP_EQUAL {
			require.Equal(t, beforeDepth-1, afterDepth)
			top := c.after.GetStack()[afterDepth-1]
			require.True(t, len(top) == 0 || bytes.Equal(top, []byte{1}))
			return
		}

		require.Equal(t, beforeDepth-2, afterDepth)
	}
}

func shiftSpec(op byte) *opcodeSpec {
	validVectors := []opcodeVector{
		{name: "shift", inputStack: [][]byte{{0x01}, {0x01}}, expectedStack: [][]byte{{0x02}}},
		{name: "5 << 1 = 10", inputStack: [][]byte{{0x05}, {0x01}}, expectedStack: [][]byte{{0x0a}}},
		{name: "255 << 1 = 510", inputStack: [][]byte{{0xff, 0x00}, {0x01}}, expectedStack: [][]byte{{0xfe, 0x01}}},
	}
	if op == OP_RSHIFT {
		validVectors = []opcodeVector{
			{name: "shift", inputStack: [][]byte{{0x02}, {0x01}}, expectedStack: [][]byte{{0x01}}},
			{name: "-7 >> 1 = -4", inputStack: [][]byte{{0x87}, {0x01}}, expectedStack: [][]byte{{0x84}}},
			{name: "-1 >> 100 = -1", inputStack: [][]byte{{0x81}, {0x64}}, expectedStack: [][]byte{{0x81}}},
		}
	}

	return &opcodeSpec{
		opcode: op,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireScriptErrorCodeIn(t, c.execErr,
					txscript.ErrInvalidStackOperation,
					txscript.ErrInvalidIndex,
					txscript.ErrNumberTooBig,
					txscript.ErrMinimalData,
				)
				require.LessOrEqual(t, afterDepth, beforeDepth)
				return
			}

			require.Equal(t, beforeDepth-1, afterDepth)
		},
		validVectors: validVectors,
		invalidVectors: []opcodeVector{
			{
				name:          "underflow",
				inputStack:    [][]byte{},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name:          "missing_x",
				inputStack:    [][]byte{{0x01}},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name:          "negative_shift",
				inputStack:    [][]byte{{0x01}, scriptNum(-1).Bytes()},
				expectedError: txscript.ErrInvalidIndex,
			},
		},
	}
}

func bitwiseSpec(op byte) *opcodeSpec {
	validInput := [][]byte{{0x0F}, {0xF0}}
	var expectedStack [][]byte
	switch op {
	case OP_AND:
		expectedStack = [][]byte{{0x00}}
	case OP_OR:
		expectedStack = [][]byte{{0xFF}}
	case OP_XOR:
		expectedStack = [][]byte{{0xFF}}
	default:
		panic(fmt.Sprintf("missing bitwise vector mapping for opcode %s", opcodeArray[op].name))
	}

	return &opcodeSpec{
		opcode: op,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			if c.execErr != nil {
				requireScriptErrorCode(t, c.execErr, txscript.ErrInvalidStackOperation)
				require.LessOrEqual(t, len(c.after.GetStack()), len(c.before.GetStack()))
				return
			}

			require.NoError(t, c.execErr)
		},
		validVectors: []opcodeVector{
			{name: "valid", inputStack: validInput, expectedStack: expectedStack},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "mismatch",
				inputStack:    [][]byte{{0x01}, {0x01, 0x02}},
				expectedError: txscript.ErrInvalidStackOperation,
			},
		},
	}
}

func hashSpec(op byte, inputHex, expectedHex string, hashLen int) *opcodeSpec {
	input, err := hex.DecodeString(inputHex)
	if err != nil {
		panic(fmt.Sprintf("invalid crypto input hex for opcode %s: %v", opcodeArray[op].name, err))
	}
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		panic(
			fmt.Sprintf("invalid crypto expected hex for opcode %s: %v", opcodeArray[op].name, err),
		)
	}

	return &opcodeSpec{
		opcode: op,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireScriptErrorCode(t, c.execErr, txscript.ErrInvalidStackOperation)
				require.LessOrEqual(t, afterDepth, beforeDepth)
				return
			}

			require.Equal(t, beforeDepth, afterDepth)
			top := c.after.GetStack()[afterDepth-1]
			require.Len(t, top, hashLen)
		},
		validVectors: []opcodeVector{
			{name: "hash", inputStack: [][]byte{input}, expectedStack: [][]byte{expected}},
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

type unaryBigNumCase struct {
	name string
	in   BigNum
	out  BigNum
}

type binaryBigNumCase struct {
	name string
	a    BigNum
	b    BigNum
	out  BigNum
}

func mustBigNumBytes(n BigNum) []byte {
	b, err := n.Bytes()
	if err != nil {
		panic(fmt.Sprintf("BigNum.Bytes: %v", err))
	}
	return b
}

func mustBigNumFromBigInt(v *big.Int) BigNum {
	n := BigNum{big: new(big.Int).Set(v), useBig: true}
	if _, err := n.Bytes(); err != nil {
		panic(fmt.Sprintf("invalid BigNum test value: %v", err))
	}
	return n
}

func binaryBigNumVector(tc binaryBigNumCase) opcodeVector {
	return opcodeVector{
		name: tc.name,
		inputStack: [][]byte{
			mustBigNumBytes(tc.a),
			mustBigNumBytes(tc.b),
		},
		expectedStack: [][]byte{mustBigNumBytes(tc.out)},
	}
}

type ternaryBigNumCase struct {
	name string
	a    BigNum
	b    BigNum
	c    BigNum
	out  BigNum
}

func ternaryBigNumVector(tc ternaryBigNumCase) opcodeVector {
	return opcodeVector{
		name: tc.name,
		inputStack: [][]byte{
			mustBigNumBytes(tc.a),
			mustBigNumBytes(tc.b),
			mustBigNumBytes(tc.c),
		},
		expectedStack: [][]byte{mustBigNumBytes(tc.out)},
	}
}

func unaryBigNumVector(tc unaryBigNumCase) opcodeVector {
	return opcodeVector{
		name:          tc.name,
		inputStack:    [][]byte{mustBigNumBytes(tc.in)},
		expectedStack: [][]byte{mustBigNumBytes(tc.out)},
	}
}

func maxPositiveBigNum(bytesLen int) BigNum {
	b := bytes.Repeat([]byte{0xff}, bytesLen)
	b[bytesLen-1] = 0x7f
	n, err := BigNumFromBytes(b)
	if err != nil {
		panic(fmt.Sprintf("BigNumFromBytes(maxPositiveBigNum): %v", err))
	}
	return n
}

func requireCanonicalBoolStackItem(t *testing.T, got []byte, want bool) {
	t.Helper()
	if want {
		require.Equal(t, []byte{0x01}, got)
		return
	}
	require.Equal(t, zeroStackItem(), got)
}

func arithmeticBigNumPropertyChecker(
	eval func(a, b BigNum) (BigNum, error),
	errChecks ...func(*testing.T, error),
) opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
		require.Equal(t, c.before.condStack, c.after.condStack)

		beforeDepth := len(c.before.GetStack())
		afterDepth := len(c.after.GetStack())
		if c.execErr != nil {
			for _, check := range errChecks {
				check(t, c.execErr)
			}
			require.True(t, afterDepth <= beforeDepth && afterDepth >= beforeDepth-2)
			return
		}

		require.Equal(t, beforeDepth-1, afterDepth)

		b, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-1])
		require.NoError(t, err)
		a, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-2])
		require.NoError(t, err)
		want, err := eval(a, b)
		require.NoError(t, err)
		got, err := BigNumFromBytes(c.after.GetStack()[afterDepth-1])
		require.NoError(t, err)
		require.Zero(t, want.Cmp(got))
	}
}

func ternaryArithmeticBigNumPropertyChecker(
	eval func(a, b, c BigNum) (BigNum, error),
	errChecks ...func(*testing.T, error),
) opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
		require.Equal(t, c.before.condStack, c.after.condStack)

		beforeDepth := len(c.before.GetStack())
		afterDepth := len(c.after.GetStack())
		if c.execErr != nil {
			for _, check := range errChecks {
				check(t, c.execErr)
			}
			require.True(t, afterDepth <= beforeDepth && afterDepth >= beforeDepth-3)
			return
		}

		require.Equal(t, beforeDepth-2, afterDepth)

		c3, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-1])
		require.NoError(t, err)
		c2, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-2])
		require.NoError(t, err)
		c1, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-3])
		require.NoError(t, err)
		want, err := eval(c1, c2, c3)
		require.NoError(t, err)
		got, err := BigNumFromBytes(c.after.GetStack()[afterDepth-1])
		require.NoError(t, err)
		require.Zero(t, want.Cmp(got))
	}
}

func comparisonBigNumPropertyChecker(
	cmp func(a, b BigNum) bool,
	errChecks ...func(*testing.T, error),
) opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
		require.Equal(t, c.before.condStack, c.after.condStack)

		beforeDepth := len(c.before.GetStack())
		afterDepth := len(c.after.GetStack())
		if c.execErr != nil {
			for _, check := range errChecks {
				check(t, c.execErr)
			}
			require.True(t, afterDepth <= beforeDepth && afterDepth >= beforeDepth-2)
			return
		}

		require.Equal(t, beforeDepth-1, afterDepth)

		b, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-1])
		require.NoError(t, err)
		a, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-2])
		require.NoError(t, err)
		requireCanonicalBoolStackItem(t, c.after.GetStack()[afterDepth-1], cmp(a, b))
	}
}

func unaryBigNumPropertyChecker(
	eval func(BigNum) BigNum,
	errChecks ...func(*testing.T, error),
) opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
		require.Equal(t, c.before.condStack, c.after.condStack)

		beforeDepth := len(c.before.GetStack())
		afterDepth := len(c.after.GetStack())
		if c.execErr != nil {
			for _, check := range errChecks {
				check(t, c.execErr)
			}
			require.True(t, afterDepth == beforeDepth || afterDepth == beforeDepth-1)
			return
		}

		require.Equal(t, beforeDepth, afterDepth)

		in, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-1])
		require.NoError(t, err)
		want := eval(in)
		got, err := BigNumFromBytes(c.after.GetStack()[afterDepth-1])
		require.NoError(t, err)
		require.Zero(t, want.Cmp(got))
	}
}

func unaryBoolBigNumPropertyChecker(
	eval func(BigNum) bool,
	errChecks ...func(*testing.T, error),
) opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
		require.Equal(t, c.before.condStack, c.after.condStack)

		beforeDepth := len(c.before.GetStack())
		afterDepth := len(c.after.GetStack())
		if c.execErr != nil {
			for _, check := range errChecks {
				check(t, c.execErr)
			}
			require.True(t, afterDepth == beforeDepth || afterDepth == beforeDepth-1)
			return
		}

		require.Equal(t, beforeDepth, afterDepth)

		in, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-1])
		require.NoError(t, err)
		requireCanonicalBoolStackItem(t, c.after.GetStack()[afterDepth-1], eval(in))
	}
}

func requireBigNumScriptErrorCodes(t *testing.T, err error) {
	t.Helper()
	requireScriptErrorCodeIn(t, err,
		txscript.ErrInvalidStackOperation,
		txscript.ErrNumberTooBig,
		txscript.ErrMinimalData,
	)
}

func requireBigNumDivisionError(t *testing.T, err error) {
	t.Helper()
	require.True(t,
		errors.Is(err, ErrBigNumDivisionByZero) ||
			isScriptError(err, txscript.ErrInvalidStackOperation) ||
			isScriptError(err, txscript.ErrNumberTooBig) ||
			isScriptError(err, txscript.ErrMinimalData),
		"unexpected division error: %T: %v", err, err,
	)
}

func requireBigNumModuloError(t *testing.T, err error) {
	t.Helper()
	require.True(t,
		errors.Is(err, ErrBigNumModuloByZero) ||
			isScriptError(err, txscript.ErrInvalidStackOperation) ||
			isScriptError(err, txscript.ErrNumberTooBig) ||
			isScriptError(err, txscript.ErrMinimalData),
		"unexpected modulo error: %T: %v", err, err,
	)
}

func oneAddSpec() *opcodeSpec {
	maxIntPlusOne := mustBigNumFromBigInt(
		new(big.Int).Add(big.NewInt(math.MaxInt64), big.NewInt(1)),
	)
	max520 := maxPositiveBigNum(maxBigNumLen)
	return &opcodeSpec{
		opcode: OP_1ADD,
		checkProperties: unaryBigNumPropertyChecker(
			func(n BigNum) BigNum { return n.Add(BigNumFromInt64(1)) },
			requireBigNumScriptErrorCodes,
		),
		validVectors: []opcodeVector{
			unaryBigNumVector(
				unaryBigNumCase{name: "small", in: BigNumFromInt64(1), out: BigNumFromInt64(2)},
			),
			unaryBigNumVector(
				unaryBigNumCase{
					name: "negative_to_zero",
					in:   BigNumFromInt64(-1),
					out:  BigNumFromInt64(0),
				},
			),
			unaryBigNumVector(
				unaryBigNumCase{
					name: "promotes_past_int64",
					in:   BigNumFromInt64(math.MaxInt64),
					out:  maxIntPlusOne,
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name:          "oversized_input",
				inputStack:    [][]byte{bytes.Repeat([]byte{0x01}, maxBigNumLen+1)},
				expectedError: txscript.ErrNumberTooBig,
			},
			{
				name:          "oversized_result",
				inputStack:    [][]byte{mustBigNumBytes(max520)},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func oneSubSpec() *opcodeSpec {
	minIntMinusOne := mustBigNumFromBigInt(
		new(big.Int).Sub(big.NewInt(math.MinInt64), big.NewInt(1)),
	)
	negMax520 := maxPositiveBigNum(maxBigNumLen).Negate()
	return &opcodeSpec{
		opcode: OP_1SUB,
		checkProperties: unaryBigNumPropertyChecker(
			func(n BigNum) BigNum { return n.Sub(BigNumFromInt64(1)) },
			requireBigNumScriptErrorCodes,
		),
		validVectors: []opcodeVector{
			unaryBigNumVector(
				unaryBigNumCase{name: "small", in: BigNumFromInt64(1), out: BigNumFromInt64(0)},
			),
			unaryBigNumVector(
				unaryBigNumCase{
					name: "zero_to_negative",
					in:   BigNumFromInt64(0),
					out:  BigNumFromInt64(-1),
				},
			),
			unaryBigNumVector(
				unaryBigNumCase{
					name: "promotes_past_int64",
					in:   BigNumFromInt64(math.MinInt64),
					out:  minIntMinusOne,
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name:          "oversized_input",
				inputStack:    [][]byte{bytes.Repeat([]byte{0x01}, maxBigNumLen+1)},
				expectedError: txscript.ErrNumberTooBig,
			},
			{
				name:          "oversized_result",
				inputStack:    [][]byte{mustBigNumBytes(negMax520)},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func twoMulSpec() *opcodeSpec {
	twoTo63 := mustBigNumFromBigInt(new(big.Int).Lsh(big.NewInt(1), 63))
	max520 := maxPositiveBigNum(maxBigNumLen)
	return &opcodeSpec{
		opcode: OP_2MUL,
		checkProperties: unaryBigNumPropertyChecker(
			func(n BigNum) BigNum { return n.Add(n) },
			requireBigNumScriptErrorCodes,
		),
		validVectors: []opcodeVector{
			unaryBigNumVector(
				unaryBigNumCase{name: "small", in: BigNumFromInt64(3), out: BigNumFromInt64(6)},
			),
			unaryBigNumVector(
				unaryBigNumCase{
					name: "negative",
					in:   BigNumFromInt64(-3),
					out:  BigNumFromInt64(-6),
				},
			),
			unaryBigNumVector(
				unaryBigNumCase{
					name: "promotes_past_int64",
					in:   BigNumFromInt64(1 << 62),
					out:  twoTo63,
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name:          "oversized_input",
				inputStack:    [][]byte{bytes.Repeat([]byte{0x01}, maxBigNumLen+1)},
				expectedError: txscript.ErrNumberTooBig,
			},
			{
				name:          "oversized_result",
				inputStack:    [][]byte{mustBigNumBytes(max520)},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func twoDivSpec() *opcodeSpec {
	minusTwoTo62 := mustBigNumFromBigInt(new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 62)))
	return &opcodeSpec{
		opcode: OP_2DIV,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			unaryBigNumPropertyChecker(
				func(n BigNum) BigNum {
					result, err := n.Div(BigNumFromInt64(2))
					require.NoError(t, err)
					return result
				},
				requireBigNumDivisionError,
			)(t, c)
		},
		validVectors: []opcodeVector{
			unaryBigNumVector(
				unaryBigNumCase{name: "small", in: BigNumFromInt64(6), out: BigNumFromInt64(3)},
			),
			unaryBigNumVector(
				unaryBigNumCase{
					name: "positive_odd_truncates",
					in:   BigNumFromInt64(7),
					out:  BigNumFromInt64(3),
				},
			),
			unaryBigNumVector(
				unaryBigNumCase{
					name: "negative_odd_truncates",
					in:   BigNumFromInt64(-7),
					out:  BigNumFromInt64(-3),
				},
			),
			unaryBigNumVector(
				unaryBigNumCase{
					name: "min_int64_halves",
					in:   BigNumFromInt64(math.MinInt64),
					out:  minusTwoTo62,
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name:          "oversized_input",
				inputStack:    [][]byte{bytes.Repeat([]byte{0x01}, maxBigNumLen+1)},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func absSpec() *opcodeSpec {
	minInt64Abs := mustBigNumFromBigInt(new(big.Int).Neg(big.NewInt(math.MinInt64)))
	return &opcodeSpec{
		opcode: OP_ABS,
		checkProperties: unaryBigNumPropertyChecker(
			func(n BigNum) BigNum { return n.Abs() },
			requireBigNumScriptErrorCodes,
		),
		validVectors: []opcodeVector{
			unaryBigNumVector(
				unaryBigNumCase{name: "negative", in: BigNumFromInt64(-5), out: BigNumFromInt64(5)},
			),
			unaryBigNumVector(
				unaryBigNumCase{name: "positive", in: BigNumFromInt64(5), out: BigNumFromInt64(5)},
			),
			unaryBigNumVector(
				unaryBigNumCase{
					name: "promotes_past_int64",
					in:   BigNumFromInt64(math.MinInt64),
					out:  minInt64Abs,
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name:          "oversized_input",
				inputStack:    [][]byte{bytes.Repeat([]byte{0x01}, maxBigNumLen+1)},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func notSpec() *opcodeSpec {
	bigNonZero := mustBigNumFromBigInt(new(big.Int).Lsh(big.NewInt(1), 63))
	return &opcodeSpec{
		opcode: OP_NOT,
		checkProperties: unaryBoolBigNumPropertyChecker(
			func(n BigNum) bool { return n.IsZero() },
			requireBigNumScriptErrorCodes,
		),
		validVectors: []opcodeVector{
			unaryBigNumVector(
				unaryBigNumCase{name: "zero", in: BigNumFromInt64(0), out: BigNumFromInt64(1)},
			),
			unaryBigNumVector(
				unaryBigNumCase{name: "one", in: BigNumFromInt64(1), out: BigNumFromInt64(0)},
			),
			unaryBigNumVector(
				unaryBigNumCase{
					name: "small_non_zero",
					in:   BigNumFromInt64(5),
					out:  BigNumFromInt64(0),
				},
			),
			unaryBigNumVector(
				unaryBigNumCase{name: "big_non_zero", in: bigNonZero, out: BigNumFromInt64(0)},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name:          "oversized_input",
				inputStack:    [][]byte{bytes.Repeat([]byte{0x01}, maxBigNumLen+1)},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func zeroNotEqualSpec() *opcodeSpec {
	bigNonZero := mustBigNumFromBigInt(new(big.Int).Lsh(big.NewInt(1), 63))
	return &opcodeSpec{
		opcode: OP_0NOTEQUAL,
		checkProperties: unaryBoolBigNumPropertyChecker(
			func(n BigNum) bool { return !n.IsZero() },
			requireBigNumScriptErrorCodes,
		),
		validVectors: []opcodeVector{
			unaryBigNumVector(
				unaryBigNumCase{name: "zero", in: BigNumFromInt64(0), out: BigNumFromInt64(0)},
			),
			unaryBigNumVector(
				unaryBigNumCase{name: "one", in: BigNumFromInt64(1), out: BigNumFromInt64(1)},
			),
			unaryBigNumVector(
				unaryBigNumCase{
					name: "small_non_zero",
					in:   BigNumFromInt64(5),
					out:  BigNumFromInt64(1),
				},
			),
			unaryBigNumVector(
				unaryBigNumCase{name: "big_non_zero", in: bigNonZero, out: BigNumFromInt64(1)},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name:          "oversized_input",
				inputStack:    [][]byte{bytes.Repeat([]byte{0x01}, maxBigNumLen+1)},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func modSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_MOD,
		checkProperties: arithmeticBigNumPropertyChecker(
			func(a, b BigNum) (BigNum, error) { return a.Mod(b) },
			requireBigNumModuloError,
		),
		validVectors: []opcodeVector{
			binaryBigNumVector(
				binaryBigNumCase{
					name: "small",
					a:    BigNumFromInt64(13),
					b:    BigNumFromInt64(3),
					out:  BigNumFromInt64(1),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "negative_dividend",
					a:    BigNumFromInt64(-7),
					b:    BigNumFromInt64(2),
					out:  BigNumFromInt64(-1),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "negative_divisor",
					a:    BigNumFromInt64(7),
					b:    BigNumFromInt64(-2),
					out:  BigNumFromInt64(1),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "min_int64_mod_minus_one",
					a:    BigNumFromInt64(math.MinInt64),
					b:    BigNumFromInt64(-1),
					out:  BigNumFromInt64(0),
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name: "mod_zero",
				inputStack: [][]byte{
					mustBigNumBytes(BigNumFromInt64(1)),
					mustBigNumBytes(BigNumFromInt64(0)),
				},
				expectedExecErr: ErrBigNumModuloByZero,
			},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}, mustBigNumBytes(BigNumFromInt64(2))},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_input",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func modexpSpec() *opcodeSpec {
	requireModexpError := func(t *testing.T, err error) {
		t.Helper()
		require.True(t,
			errors.Is(err, ErrBigNumModulusNotPositive) ||
				errors.Is(err, ErrBigNumNegativeExponent) ||
				isScriptError(err, txscript.ErrInvalidStackOperation) ||
				isScriptError(err, txscript.ErrNumberTooBig) ||
				isScriptError(err, txscript.ErrMinimalData),
			"unexpected modexp error: %T: %v", err, err,
		)
	}
	// Largest positive value that fits in exactly maxModexpOperandLen bytes:
	// 2^(8*maxModexpOperandLen - 1) - 1.
	maxAtCap := new(big.Int).Lsh(big.NewInt(1), uint(8*maxModexpOperandLen-1))
	maxAtCap.Sub(maxAtCap, big.NewInt(1))
	modAtCap := mustBigNumFromBigInt(maxAtCap)
	// One byte above the cap (encoded as 8 more bits of magnitude).
	aboveCap := new(big.Int).Lsh(big.NewInt(1), uint(8*(maxModexpOperandLen+1)-1))
	aboveCap.Sub(aboveCap, big.NewInt(1))
	modAboveCap := mustBigNumFromBigInt(aboveCap)
	return &opcodeSpec{
		opcode: OP_MODEXP,
		checkProperties: ternaryArithmeticBigNumPropertyChecker(
			func(a, b, c BigNum) (BigNum, error) { return a.Modexp(b, c) },
			requireModexpError,
		),
		validVectors: []opcodeVector{
			ternaryBigNumVector(
				ternaryBigNumCase{
					name: "small",
					a:    BigNumFromInt64(2),
					b:    BigNumFromInt64(10),
					c:    BigNumFromInt64(1000),
					out:  BigNumFromInt64(24),
				},
			),
			ternaryBigNumVector(
				ternaryBigNumCase{
					name: "exp_zero",
					a:    BigNumFromInt64(5),
					b:    BigNumFromInt64(0),
					c:    BigNumFromInt64(7),
					out:  BigNumFromInt64(1),
				},
			),
			ternaryBigNumVector(
				ternaryBigNumCase{
					name: "zero_pow_zero",
					a:    BigNumFromInt64(0),
					b:    BigNumFromInt64(0),
					c:    BigNumFromInt64(7),
					out:  BigNumFromInt64(1),
				},
			),
			ternaryBigNumVector(
				ternaryBigNumCase{
					name: "base_zero_exp_positive",
					a:    BigNumFromInt64(0),
					b:    BigNumFromInt64(5),
					c:    BigNumFromInt64(7),
					out:  BigNumFromInt64(0),
				},
			),
			ternaryBigNumVector(
				ternaryBigNumCase{
					name: "modulus_one",
					a:    BigNumFromInt64(123456789),
					b:    BigNumFromInt64(42),
					c:    BigNumFromInt64(1),
					out:  BigNumFromInt64(0),
				},
			),
			ternaryBigNumVector(
				ternaryBigNumCase{
					name: "negative_base_even_exp",
					a:    BigNumFromInt64(-3),
					b:    BigNumFromInt64(2),
					c:    BigNumFromInt64(5),
					out:  BigNumFromInt64(4),
				},
			),
			ternaryBigNumVector(
				ternaryBigNumCase{
					name: "negative_base_odd_exp_canonicalized",
					a:    BigNumFromInt64(-2),
					b:    BigNumFromInt64(3),
					c:    BigNumFromInt64(5),
					out:  BigNumFromInt64(2),
				},
			),
			ternaryBigNumVector(
				ternaryBigNumCase{
					name: "fermat_inverse_small_prime",
					a:    BigNumFromInt64(3),
					b:    BigNumFromInt64(5),
					c:    BigNumFromInt64(7),
					out:  BigNumFromInt64(5),
				},
			),
			ternaryBigNumVector(
				ternaryBigNumCase{
					name: "modulus_at_operand_cap",
					a:    BigNumFromInt64(2),
					b:    BigNumFromInt64(10),
					c:    modAtCap,
					out:  BigNumFromInt64(1024),
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name: "modulus_above_operand_cap",
				inputStack: [][]byte{
					mustBigNumBytes(BigNumFromInt64(2)),
					mustBigNumBytes(BigNumFromInt64(10)),
					mustBigNumBytes(modAboveCap),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
			{
				name: "base_above_operand_cap",
				inputStack: [][]byte{
					mustBigNumBytes(modAboveCap),
					mustBigNumBytes(BigNumFromInt64(10)),
					mustBigNumBytes(BigNumFromInt64(7)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
			{
				name: "exp_above_operand_cap",
				inputStack: [][]byte{
					mustBigNumBytes(BigNumFromInt64(2)),
					mustBigNumBytes(modAboveCap),
					mustBigNumBytes(BigNumFromInt64(7)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
			{
				name: "modulus_zero",
				inputStack: [][]byte{
					mustBigNumBytes(BigNumFromInt64(2)),
					mustBigNumBytes(BigNumFromInt64(3)),
					mustBigNumBytes(BigNumFromInt64(0)),
				},
				expectedExecErr: ErrBigNumModulusNotPositive,
			},
			{
				name: "modulus_negative",
				inputStack: [][]byte{
					mustBigNumBytes(BigNumFromInt64(2)),
					mustBigNumBytes(BigNumFromInt64(3)),
					mustBigNumBytes(BigNumFromInt64(-7)),
				},
				expectedExecErr: ErrBigNumModulusNotPositive,
			},
			{
				name: "exp_negative",
				inputStack: [][]byte{
					mustBigNumBytes(BigNumFromInt64(2)),
					mustBigNumBytes(BigNumFromInt64(-1)),
					mustBigNumBytes(BigNumFromInt64(7)),
				},
				expectedExecErr: ErrBigNumNegativeExponent,
			},
			{
				name: "non_minimal_base",
				inputStack: [][]byte{
					{0x01, 0x00},
					mustBigNumBytes(BigNumFromInt64(3)),
					mustBigNumBytes(BigNumFromInt64(7)),
				},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "non_minimal_exp",
				inputStack: [][]byte{
					mustBigNumBytes(BigNumFromInt64(2)),
					{0x01, 0x00},
					mustBigNumBytes(BigNumFromInt64(7)),
				},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "non_minimal_modulus",
				inputStack: [][]byte{
					mustBigNumBytes(BigNumFromInt64(2)),
					mustBigNumBytes(BigNumFromInt64(3)),
					{0x01, 0x00},
				},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_base",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(3)),
					mustBigNumBytes(BigNumFromInt64(7)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
			{
				name: "oversized_exp",
				inputStack: [][]byte{
					mustBigNumBytes(BigNumFromInt64(2)),
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(7)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
			{
				name: "oversized_modulus",
				inputStack: [][]byte{
					mustBigNumBytes(BigNumFromInt64(2)),
					mustBigNumBytes(BigNumFromInt64(3)),
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func boolAndSpec() *opcodeSpec {
	bigNonZero := mustBigNumFromBigInt(new(big.Int).Lsh(big.NewInt(1), 63))
	return &opcodeSpec{
		opcode: OP_BOOLAND,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireBigNumScriptErrorCodes(t, c.execErr)
				require.True(t, afterDepth <= beforeDepth && afterDepth >= beforeDepth-2)
				return
			}

			require.Equal(t, beforeDepth-1, afterDepth)
			b, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-1])
			require.NoError(t, err)
			a, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-2])
			require.NoError(t, err)
			requireCanonicalBoolStackItem(
				t,
				c.after.GetStack()[afterDepth-1],
				!a.IsZero() && !b.IsZero(),
			)
		},
		validVectors: []opcodeVector{
			binaryBigNumVector(
				binaryBigNumCase{
					name: "true",
					a:    BigNumFromInt64(5),
					b:    BigNumFromInt64(10),
					out:  BigNumFromInt64(1),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "right_zero",
					a:    BigNumFromInt64(5),
					b:    BigNumFromInt64(0),
					out:  BigNumFromInt64(0),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "left_zero",
					a:    BigNumFromInt64(0),
					b:    BigNumFromInt64(7),
					out:  BigNumFromInt64(0),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "big_non_zero",
					a:    bigNonZero,
					b:    BigNumFromInt64(1),
					out:  BigNumFromInt64(1),
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}, mustBigNumBytes(BigNumFromInt64(2))},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_input",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func boolOrSpec() *opcodeSpec {
	bigNonZero := mustBigNumFromBigInt(new(big.Int).Lsh(big.NewInt(1), 63))
	return &opcodeSpec{
		opcode: OP_BOOLOR,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireBigNumScriptErrorCodes(t, c.execErr)
				require.True(t, afterDepth <= beforeDepth && afterDepth >= beforeDepth-2)
				return
			}

			require.Equal(t, beforeDepth-1, afterDepth)
			b, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-1])
			require.NoError(t, err)
			a, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-2])
			require.NoError(t, err)
			requireCanonicalBoolStackItem(
				t,
				c.after.GetStack()[afterDepth-1],
				!a.IsZero() || !b.IsZero(),
			)
		},
		validVectors: []opcodeVector{
			binaryBigNumVector(
				binaryBigNumCase{
					name: "true",
					a:    BigNumFromInt64(5),
					b:    BigNumFromInt64(0),
					out:  BigNumFromInt64(1),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "both_zero",
					a:    BigNumFromInt64(0),
					b:    BigNumFromInt64(0),
					out:  BigNumFromInt64(0),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "right_non_zero",
					a:    BigNumFromInt64(0),
					b:    BigNumFromInt64(7),
					out:  BigNumFromInt64(1),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "big_non_zero",
					a:    bigNonZero,
					b:    BigNumFromInt64(0),
					out:  BigNumFromInt64(1),
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}, mustBigNumBytes(BigNumFromInt64(2))},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_input",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func numEqualSpec() *opcodeSpec {
	twoTo63 := mustBigNumFromBigInt(new(big.Int).Lsh(big.NewInt(1), 63))
	return &opcodeSpec{
		opcode: OP_NUMEQUAL,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireBigNumScriptErrorCodes(t, c.execErr)
				require.True(t, afterDepth <= beforeDepth && afterDepth >= beforeDepth-2)
				return
			}

			require.Equal(t, beforeDepth-1, afterDepth)
			b, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-1])
			require.NoError(t, err)
			a, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-2])
			require.NoError(t, err)
			requireCanonicalBoolStackItem(t, c.after.GetStack()[afterDepth-1], a.Cmp(b) == 0)
		},
		validVectors: []opcodeVector{
			binaryBigNumVector(
				binaryBigNumCase{
					name: "equal",
					a:    BigNumFromInt64(5),
					b:    BigNumFromInt64(5),
					out:  BigNumFromInt64(1),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "not_equal",
					a:    BigNumFromInt64(5),
					b:    BigNumFromInt64(6),
					out:  BigNumFromInt64(0),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "negative_equal",
					a:    BigNumFromInt64(-7),
					b:    BigNumFromInt64(-7),
					out:  BigNumFromInt64(1),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "big_equal",
					a:    twoTo63,
					b:    twoTo63,
					out:  BigNumFromInt64(1),
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}, mustBigNumBytes(BigNumFromInt64(2))},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_input",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func numNotEqualSpec() *opcodeSpec {
	twoTo63 := mustBigNumFromBigInt(new(big.Int).Lsh(big.NewInt(1), 63))
	return &opcodeSpec{
		opcode: OP_NUMNOTEQUAL,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireBigNumScriptErrorCodes(t, c.execErr)
				require.True(t, afterDepth <= beforeDepth && afterDepth >= beforeDepth-2)
				return
			}

			require.Equal(t, beforeDepth-1, afterDepth)
			b, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-1])
			require.NoError(t, err)
			a, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-2])
			require.NoError(t, err)
			requireCanonicalBoolStackItem(t, c.after.GetStack()[afterDepth-1], a.Cmp(b) != 0)
		},
		validVectors: []opcodeVector{
			binaryBigNumVector(
				binaryBigNumCase{
					name: "not_equal",
					a:    BigNumFromInt64(5),
					b:    BigNumFromInt64(6),
					out:  BigNumFromInt64(1),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "equal",
					a:    BigNumFromInt64(5),
					b:    BigNumFromInt64(5),
					out:  BigNumFromInt64(0),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "sign_differs",
					a:    BigNumFromInt64(-7),
					b:    BigNumFromInt64(7),
					out:  BigNumFromInt64(1),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "big_not_equal",
					a:    twoTo63,
					b:    BigNumFromInt64(math.MaxInt64),
					out:  BigNumFromInt64(1),
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}, mustBigNumBytes(BigNumFromInt64(2))},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_input",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func minSpec() *opcodeSpec {
	twoTo63 := mustBigNumFromBigInt(new(big.Int).Lsh(big.NewInt(1), 63))
	return &opcodeSpec{
		opcode: OP_MIN,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireBigNumScriptErrorCodes(t, c.execErr)
				require.True(t, afterDepth <= beforeDepth && afterDepth >= beforeDepth-2)
				return
			}

			require.Equal(t, beforeDepth-1, afterDepth)
			b, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-1])
			require.NoError(t, err)
			a, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-2])
			require.NoError(t, err)
			want := b
			if a.Cmp(b) < 0 {
				want = a
			}
			got, err := BigNumFromBytes(c.after.GetStack()[afterDepth-1])
			require.NoError(t, err)
			require.Zero(t, want.Cmp(got))
		},
		validVectors: []opcodeVector{
			binaryBigNumVector(
				binaryBigNumCase{
					name: "small",
					a:    BigNumFromInt64(5),
					b:    BigNumFromInt64(10),
					out:  BigNumFromInt64(5),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "reversed",
					a:    BigNumFromInt64(10),
					b:    BigNumFromInt64(5),
					out:  BigNumFromInt64(5),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "negative",
					a:    BigNumFromInt64(-7),
					b:    BigNumFromInt64(2),
					out:  BigNumFromInt64(-7),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "big_width",
					a:    BigNumFromInt64(math.MaxInt64),
					b:    twoTo63,
					out:  BigNumFromInt64(math.MaxInt64),
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}, mustBigNumBytes(BigNumFromInt64(2))},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_input",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func maxSpec() *opcodeSpec {
	twoTo63 := mustBigNumFromBigInt(new(big.Int).Lsh(big.NewInt(1), 63))
	return &opcodeSpec{
		opcode: OP_MAX,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireBigNumScriptErrorCodes(t, c.execErr)
				require.True(t, afterDepth <= beforeDepth && afterDepth >= beforeDepth-2)
				return
			}

			require.Equal(t, beforeDepth-1, afterDepth)
			b, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-1])
			require.NoError(t, err)
			a, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-2])
			require.NoError(t, err)
			want := b
			if a.Cmp(b) > 0 {
				want = a
			}
			got, err := BigNumFromBytes(c.after.GetStack()[afterDepth-1])
			require.NoError(t, err)
			require.Zero(t, want.Cmp(got))
		},
		validVectors: []opcodeVector{
			binaryBigNumVector(
				binaryBigNumCase{
					name: "small",
					a:    BigNumFromInt64(5),
					b:    BigNumFromInt64(10),
					out:  BigNumFromInt64(10),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "reversed",
					a:    BigNumFromInt64(10),
					b:    BigNumFromInt64(5),
					out:  BigNumFromInt64(10),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "negative",
					a:    BigNumFromInt64(-7),
					b:    BigNumFromInt64(2),
					out:  BigNumFromInt64(2),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "big_width",
					a:    BigNumFromInt64(math.MaxInt64),
					b:    twoTo63,
					out:  twoTo63,
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}, mustBigNumBytes(BigNumFromInt64(2))},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_input",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func negateSpec() *opcodeSpec {
	minInt64Negated := mustBigNumFromBigInt(new(big.Int).Neg(big.NewInt(math.MinInt64)))
	return &opcodeSpec{
		opcode: OP_NEGATE,
		checkProperties: unaryBigNumPropertyChecker(
			func(n BigNum) BigNum { return n.Negate() },
			requireBigNumScriptErrorCodes,
		),
		validVectors: []opcodeVector{
			unaryBigNumVector(
				unaryBigNumCase{name: "small", in: BigNumFromInt64(5), out: BigNumFromInt64(-5)},
			),
			unaryBigNumVector(
				unaryBigNumCase{name: "zero", in: BigNumFromInt64(0), out: BigNumFromInt64(0)},
			),
			unaryBigNumVector(
				unaryBigNumCase{name: "negative", in: BigNumFromInt64(-7), out: BigNumFromInt64(7)},
			),
			unaryBigNumVector(
				unaryBigNumCase{
					name: "promotes past int64",
					in:   BigNumFromInt64(math.MinInt64),
					out:  minInt64Negated,
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name:          "oversized_input",
				inputStack:    [][]byte{bytes.Repeat([]byte{0x01}, maxBigNumLen+1)},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func addSpec() *opcodeSpec {
	maxIntPlusOne := mustBigNumFromBigInt(
		new(big.Int).Add(big.NewInt(math.MaxInt64), big.NewInt(1)),
	)
	max520 := maxPositiveBigNum(maxBigNumLen)
	return &opcodeSpec{
		opcode: OP_ADD,
		checkProperties: arithmeticBigNumPropertyChecker(func(a, b BigNum) (BigNum, error) {
			return a.Add(b), nil
		}, requireBigNumScriptErrorCodes),
		validVectors: []opcodeVector{
			binaryBigNumVector(
				binaryBigNumCase{
					name: "small",
					a:    BigNumFromInt64(1),
					b:    BigNumFromInt64(2),
					out:  BigNumFromInt64(3),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "negative plus positive",
					a:    BigNumFromInt64(-7),
					b:    BigNumFromInt64(2),
					out:  BigNumFromInt64(-5),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "promotes past int64",
					a:    BigNumFromInt64(math.MaxInt64),
					b:    BigNumFromInt64(1),
					out:  maxIntPlusOne,
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}, mustBigNumBytes(BigNumFromInt64(2))},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_input",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
			{
				name:          "oversized_result",
				inputStack:    [][]byte{mustBigNumBytes(max520), mustBigNumBytes(max520)},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func subSpec() *opcodeSpec {
	minIntMinusOne := mustBigNumFromBigInt(
		new(big.Int).Sub(big.NewInt(math.MinInt64), big.NewInt(1)),
	)
	max520 := maxPositiveBigNum(maxBigNumLen)
	negMax520 := max520.Negate()
	return &opcodeSpec{
		opcode: OP_SUB,
		checkProperties: arithmeticBigNumPropertyChecker(func(a, b BigNum) (BigNum, error) {
			return a.Sub(b), nil
		}, requireBigNumScriptErrorCodes),
		validVectors: []opcodeVector{
			binaryBigNumVector(
				binaryBigNumCase{
					name: "small",
					a:    BigNumFromInt64(5),
					b:    BigNumFromInt64(2),
					out:  BigNumFromInt64(3),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "subtract negative",
					a:    BigNumFromInt64(5),
					b:    BigNumFromInt64(-2),
					out:  BigNumFromInt64(7),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "promotes past int64",
					a:    BigNumFromInt64(math.MinInt64),
					b:    BigNumFromInt64(1),
					out:  minIntMinusOne,
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}, mustBigNumBytes(BigNumFromInt64(2))},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_input",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
			{
				name:          "oversized_result",
				inputStack:    [][]byte{mustBigNumBytes(max520), mustBigNumBytes(negMax520)},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func mulSpec() *opcodeSpec {
	twoTo64 := mustBigNumFromBigInt(new(big.Int).Lsh(big.NewInt(1), 64))
	max520 := maxPositiveBigNum(maxBigNumLen)
	return &opcodeSpec{
		opcode: OP_MUL,
		checkProperties: arithmeticBigNumPropertyChecker(func(a, b BigNum) (BigNum, error) {
			return a.Mul(b), nil
		}, requireBigNumScriptErrorCodes),
		validVectors: []opcodeVector{
			binaryBigNumVector(
				binaryBigNumCase{
					name: "small",
					a:    BigNumFromInt64(3),
					b:    BigNumFromInt64(4),
					out:  BigNumFromInt64(12),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "negative",
					a:    BigNumFromInt64(-3),
					b:    BigNumFromInt64(4),
					out:  BigNumFromInt64(-12),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "promotes past int64",
					a:    BigNumFromInt64(1 << 32),
					b:    BigNumFromInt64(1 << 32),
					out:  twoTo64,
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}, mustBigNumBytes(BigNumFromInt64(2))},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_input",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
			{
				name: "oversized_result",
				inputStack: [][]byte{
					mustBigNumBytes(max520),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func divSpec() *opcodeSpec {
	minIntDivNegOne := mustBigNumFromBigInt(new(big.Int).Lsh(big.NewInt(1), 63))
	return &opcodeSpec{
		opcode: OP_DIV,
		checkProperties: arithmeticBigNumPropertyChecker(func(a, b BigNum) (BigNum, error) {
			return a.Div(b)
		}, requireBigNumDivisionError),
		validVectors: []opcodeVector{
			binaryBigNumVector(
				binaryBigNumCase{
					name: "small",
					a:    BigNumFromInt64(12),
					b:    BigNumFromInt64(3),
					out:  BigNumFromInt64(4),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "negative dividend truncates",
					a:    BigNumFromInt64(-7),
					b:    BigNumFromInt64(2),
					out:  BigNumFromInt64(-3),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "negative divisor truncates",
					a:    BigNumFromInt64(7),
					b:    BigNumFromInt64(-2),
					out:  BigNumFromInt64(-3),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "promotes past int64",
					a:    BigNumFromInt64(math.MinInt64),
					b:    BigNumFromInt64(-1),
					out:  minIntDivNegOne,
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name: "div_zero",
				inputStack: [][]byte{
					mustBigNumBytes(BigNumFromInt64(1)),
					mustBigNumBytes(BigNumFromInt64(0)),
				},
				expectedExecErr: ErrBigNumDivisionByZero,
			},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}, mustBigNumBytes(BigNumFromInt64(2))},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_input",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func lessThanSpec() *opcodeSpec {
	twoTo63 := mustBigNumFromBigInt(new(big.Int).Lsh(big.NewInt(1), 63))
	return &opcodeSpec{
		opcode: OP_LESSTHAN,
		checkProperties: comparisonBigNumPropertyChecker(
			func(a, b BigNum) bool { return a.Cmp(b) < 0 },
			requireBigNumScriptErrorCodes,
		),
		validVectors: []opcodeVector{
			binaryBigNumVector(
				binaryBigNumCase{
					name: "true",
					a:    BigNumFromInt64(5),
					b:    BigNumFromInt64(10),
					out:  BigNumFromInt64(1),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "false equal",
					a:    BigNumFromInt64(5),
					b:    BigNumFromInt64(5),
					out:  BigNumFromInt64(0),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "false negative",
					a:    BigNumFromInt64(-2),
					b:    BigNumFromInt64(-7),
					out:  BigNumFromInt64(0),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "big width true",
					a:    BigNumFromInt64(math.MaxInt64),
					b:    twoTo63,
					out:  BigNumFromInt64(1),
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}, mustBigNumBytes(BigNumFromInt64(2))},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_input",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func lessThanOrEqualSpec() *opcodeSpec {
	twoTo63 := mustBigNumFromBigInt(new(big.Int).Lsh(big.NewInt(1), 63))
	return &opcodeSpec{
		opcode: OP_LESSTHANOREQUAL,
		checkProperties: comparisonBigNumPropertyChecker(
			func(a, b BigNum) bool { return a.Cmp(b) <= 0 },
			requireBigNumScriptErrorCodes,
		),
		validVectors: []opcodeVector{
			binaryBigNumVector(
				binaryBigNumCase{
					name: "equal",
					a:    BigNumFromInt64(5),
					b:    BigNumFromInt64(5),
					out:  BigNumFromInt64(1),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "true less",
					a:    BigNumFromInt64(-7),
					b:    BigNumFromInt64(2),
					out:  BigNumFromInt64(1),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "false greater",
					a:    BigNumFromInt64(10),
					b:    BigNumFromInt64(5),
					out:  BigNumFromInt64(0),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "big width false",
					a:    twoTo63,
					b:    BigNumFromInt64(math.MaxInt64),
					out:  BigNumFromInt64(0),
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}, mustBigNumBytes(BigNumFromInt64(2))},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_input",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func greaterThanSpec() *opcodeSpec {
	twoTo63 := mustBigNumFromBigInt(new(big.Int).Lsh(big.NewInt(1), 63))
	return &opcodeSpec{
		opcode: OP_GREATERTHAN,
		checkProperties: comparisonBigNumPropertyChecker(
			func(a, b BigNum) bool { return a.Cmp(b) > 0 },
			requireBigNumScriptErrorCodes,
		),
		validVectors: []opcodeVector{
			binaryBigNumVector(
				binaryBigNumCase{
					name: "true",
					a:    BigNumFromInt64(10),
					b:    BigNumFromInt64(5),
					out:  BigNumFromInt64(1),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "false equal",
					a:    BigNumFromInt64(5),
					b:    BigNumFromInt64(5),
					out:  BigNumFromInt64(0),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "true negative",
					a:    BigNumFromInt64(-2),
					b:    BigNumFromInt64(-7),
					out:  BigNumFromInt64(1),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "big width false",
					a:    BigNumFromInt64(math.MaxInt64),
					b:    twoTo63,
					out:  BigNumFromInt64(0),
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}, mustBigNumBytes(BigNumFromInt64(2))},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_input",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func greaterThanOrEqualSpec() *opcodeSpec {
	twoTo63 := mustBigNumFromBigInt(new(big.Int).Lsh(big.NewInt(1), 63))
	return &opcodeSpec{
		opcode: OP_GREATERTHANOREQUAL,
		checkProperties: comparisonBigNumPropertyChecker(
			func(a, b BigNum) bool { return a.Cmp(b) >= 0 },
			requireBigNumScriptErrorCodes,
		),
		validVectors: []opcodeVector{
			binaryBigNumVector(
				binaryBigNumCase{
					name: "equal",
					a:    BigNumFromInt64(5),
					b:    BigNumFromInt64(5),
					out:  BigNumFromInt64(1),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "true greater",
					a:    BigNumFromInt64(10),
					b:    BigNumFromInt64(5),
					out:  BigNumFromInt64(1),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "false less",
					a:    BigNumFromInt64(-7),
					b:    BigNumFromInt64(2),
					out:  BigNumFromInt64(0),
				},
			),
			binaryBigNumVector(
				binaryBigNumCase{
					name: "big width true",
					a:    twoTo63,
					b:    BigNumFromInt64(math.MaxInt64),
					out:  BigNumFromInt64(1),
				},
			),
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "non_minimal",
				inputStack:    [][]byte{{0x01, 0x00}, mustBigNumBytes(BigNumFromInt64(2))},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_input",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func numEqualVerifySpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_NUMEQUALVERIFY,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireScriptErrorCodeIn(t, c.execErr,
					txscript.ErrInvalidStackOperation,
					txscript.ErrNumEqualVerify,
					txscript.ErrNumberTooBig,
					txscript.ErrMinimalData,
				)
				require.True(t, afterDepth <= beforeDepth && afterDepth >= beforeDepth-2)
				return
			}

			require.Equal(t, beforeDepth-2, afterDepth)
		},
		validVectors: []opcodeVector{
			{name: "equal", inputStack: [][]byte{scriptNum(5).Bytes(), scriptNum(5).Bytes()}},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "not_equal",
				inputStack:    [][]byte{scriptNum(5).Bytes(), scriptNum(6).Bytes()},
				expectedError: txscript.ErrNumEqualVerify,
			},
			{
				name:          "underflow",
				inputStack:    [][]byte{},
				expectedError: txscript.ErrInvalidStackOperation,
			},
		},
	}
}

func withinSpec() *opcodeSpec {
	twoTo63 := mustBigNumFromBigInt(new(big.Int).Lsh(big.NewInt(1), 63))
	return &opcodeSpec{
		opcode: OP_WITHIN,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireScriptErrorCodeIn(t, c.execErr,
					txscript.ErrInvalidStackOperation,
					txscript.ErrNumberTooBig,
					txscript.ErrMinimalData,
				)
				require.True(t, afterDepth <= beforeDepth && afterDepth >= beforeDepth-3)
				return
			}

			require.Equal(t, beforeDepth-2, afterDepth)

			maxVal, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-1])
			require.NoError(t, err)
			minVal, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-2])
			require.NoError(t, err)
			x, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-3])
			require.NoError(t, err)
			requireCanonicalBoolStackItem(
				t,
				c.after.GetStack()[afterDepth-1],
				x.Cmp(minVal) >= 0 && x.Cmp(maxVal) < 0,
			)
		},
		validVectors: []opcodeVector{
			{
				name: "in",
				inputStack: [][]byte{
					mustBigNumBytes(BigNumFromInt64(5)),
					mustBigNumBytes(BigNumFromInt64(0)),
					mustBigNumBytes(BigNumFromInt64(10)),
				},
				expectedStack: [][]byte{{1}},
			},
			{
				name: "out",
				inputStack: [][]byte{
					mustBigNumBytes(BigNumFromInt64(11)),
					mustBigNumBytes(BigNumFromInt64(0)),
					mustBigNumBytes(BigNumFromInt64(10)),
				},
				expectedStack: [][]byte{falseStackItem()},
			},
			{
				name: "equal_to_min",
				inputStack: [][]byte{
					mustBigNumBytes(BigNumFromInt64(-7)),
					mustBigNumBytes(BigNumFromInt64(-7)),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedStack: [][]byte{{1}},
			},
			{
				name: "equal_to_max_is_out",
				inputStack: [][]byte{
					mustBigNumBytes(BigNumFromInt64(2)),
					mustBigNumBytes(BigNumFromInt64(-7)),
					mustBigNumBytes(BigNumFromInt64(2)),
				},
				expectedStack: [][]byte{falseStackItem()},
			},
			{
				name: "big_width_in",
				inputStack: [][]byte{
					mustBigNumBytes(twoTo63),
					mustBigNumBytes(BigNumFromInt64(math.MaxInt64)),
					mustBigNumBytes(mustBigNumFromBigInt(new(big.Int).Lsh(big.NewInt(1), 64))),
				},
				expectedStack: [][]byte{{1}},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "underflow",
				inputStack:    [][]byte{},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "non_minimal",
				inputStack: [][]byte{
					{0x01, 0x00},
					mustBigNumBytes(BigNumFromInt64(0)),
					mustBigNumBytes(BigNumFromInt64(10)),
				},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_input",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					mustBigNumBytes(BigNumFromInt64(0)),
					mustBigNumBytes(BigNumFromInt64(10)),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func num2BinSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_NUM2BIN,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireScriptErrorCodeIn(t, c.execErr,
					txscript.ErrInvalidStackOperation,
					txscript.ErrNumberTooBig,
					txscript.ErrMinimalData,
				)
				require.True(t, afterDepth <= beforeDepth && afterDepth >= beforeDepth-2)
				return
			}

			require.Equal(t, beforeDepth-1, afterDepth)

			size, err := MakeScriptNum(c.before.GetStack()[beforeDepth-1], true, maxScriptNumLen)
			require.NoError(t, err)
			num, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-2])
			require.NoError(t, err)
			want, err := num.FixedBytes(int(size))
			require.NoError(t, err)
			require.Equal(t, want, c.after.GetStack()[afterDepth-1])
		},
		validVectors: []opcodeVector{
			{
				name:          "5_as_4_bytes",
				inputStack:    [][]byte{{0x05}, scriptNum(4).Bytes()},
				expectedStack: [][]byte{{0x05, 0x00, 0x00, 0x00}},
			},
			{
				name:          "neg5_as_4_bytes",
				inputStack:    [][]byte{{0x85}, scriptNum(4).Bytes()},
				expectedStack: [][]byte{{0x05, 0x00, 0x00, 0x80}},
			},
			{
				name:          "neg5_as_1_byte",
				inputStack:    [][]byte{{0x85}, scriptNum(1).Bytes()},
				expectedStack: [][]byte{{0x85}},
			},
			{
				name:          "zero_as_4_bytes",
				inputStack:    [][]byte{nil, scriptNum(4).Bytes()},
				expectedStack: [][]byte{{0x00, 0x00, 0x00, 0x00}},
			},
			{
				name:          "zero_as_0_bytes",
				inputStack:    [][]byte{nil, scriptNum(0).Bytes()},
				expectedStack: [][]byte{emptyByteVector()},
			},
			{
				name:          "128_as_2_bytes",
				inputStack:    [][]byte{{0x80, 0x00}, scriptNum(2).Bytes()},
				expectedStack: [][]byte{{0x80, 0x00}},
			},
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "missing_num",
				inputStack:    [][]byte{scriptNum(1).Bytes()},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name:          "negative_size",
				inputStack:    [][]byte{nil, scriptNum(-1).Bytes()},
				expectedError: txscript.ErrNumberTooBig,
			},
			{
				name:          "size_over_max",
				inputStack:    [][]byte{nil, scriptNum(521).Bytes()},
				expectedError: txscript.ErrNumberTooBig,
			},
			{
				name:          "num_does_not_fit",
				inputStack:    [][]byte{{0xff, 0x00}, scriptNum(1).Bytes()},
				expectedError: txscript.ErrNumberTooBig,
			},
			{
				name:          "non_minimal_num",
				inputStack:    [][]byte{{0x01, 0x00}, scriptNum(1).Bytes()},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "oversized_num",
				inputStack: [][]byte{
					bytes.Repeat([]byte{0x01}, maxBigNumLen+1),
					scriptNum(1).Bytes(),
				},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

func bin2NumSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_BIN2NUM,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireScriptErrorCodeIn(t, c.execErr,
					txscript.ErrInvalidStackOperation,
					txscript.ErrNumberTooBig,
				)
				require.True(t, afterDepth == beforeDepth || afterDepth == beforeDepth-1)
				return
			}

			require.Equal(t, beforeDepth, afterDepth)
			want := minimallyEncode(c.before.GetStack()[beforeDepth-1])
			require.Equal(t, want, c.after.GetStack()[afterDepth-1])
			_, err := BigNumFromBytes(c.after.GetStack()[afterDepth-1])
			require.NoError(t, err)
		},
		validVectors: []opcodeVector{
			{
				name:          "5_from_4_bytes",
				inputStack:    [][]byte{{0x05, 0x00, 0x00, 0x00}},
				expectedStack: [][]byte{{0x05}},
			},
			{
				name:          "negative_zero_normalizes",
				inputStack:    [][]byte{{0x00, 0x00, 0x00, 0x80}},
				expectedStack: [][]byte{emptyByteVector()},
			},
			{
				name:          "neg5_from_4_bytes",
				inputStack:    [][]byte{{0x05, 0x00, 0x00, 0x80}},
				expectedStack: [][]byte{{0x85}},
			},
			{
				name:          "128_minimal",
				inputStack:    [][]byte{{0x80, 0x00, 0x00, 0x00}},
				expectedStack: [][]byte{{0x80, 0x00}},
			},
			{
				name:          "empty_stays_zero",
				inputStack:    [][]byte{emptyByteVector()},
				expectedStack: [][]byte{emptyByteVector()},
			},
			{
				name:          "already_minimal",
				inputStack:    [][]byte{{0x85}},
				expectedStack: [][]byte{{0x85}},
			},
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "oversized_input",
				inputStack:    [][]byte{bytes.Repeat([]byte{0x01}, maxBigNumLen+1)},
				expectedError: txscript.ErrNumberTooBig,
			},
		},
	}
}

// reverseBytesSpec verifies OP_REVERSEBYTES pops the top stack item and
// pushes its bytes in reverse order without changing stack depth.
func reverseBytesSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_REVERSEBYTES,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			beforeDepth := len(c.before.GetStack())
			afterDepth := len(c.after.GetStack())
			if c.execErr != nil {
				requireScriptErrorCodeIn(t, c.execErr,
					txscript.ErrInvalidStackOperation,
				)
				require.True(t, afterDepth == beforeDepth || afterDepth == beforeDepth-1)
				return
			}

			require.Equal(t, beforeDepth, afterDepth)
			src := c.before.GetStack()[beforeDepth-1]
			want := slices.Clone(src)
			slices.Reverse(want)
			require.Equal(t, want, c.after.GetStack()[afterDepth-1])
		},
		validVectors: []opcodeVector{
			{
				name:          "empty",
				inputStack:    [][]byte{emptyByteVector()},
				expectedStack: [][]byte{emptyByteVector()},
			},
			{
				name:          "single_byte_unchanged",
				inputStack:    [][]byte{{0x42}},
				expectedStack: [][]byte{{0x42}},
			},
			{
				name:          "three_bytes",
				inputStack:    [][]byte{{0x01, 0x02, 0x03}},
				expectedStack: [][]byte{{0x03, 0x02, 0x01}},
			},
			{
				name: "thirty_two_bytes",
				inputStack: [][]byte{{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
					0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				}},
				expectedStack: [][]byte{{
					0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18,
					0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
					0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
					0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
				}},
			},
			{
				// Models the post-OP_DUP shape: both stack entries alias the
				// same backing []byte. A correct implementation must not
				// mutate the popped buffer in place; otherwise the lower
				// stack entry is silently corrupted.
				name: "shared_backing_buffer_not_mutated",
				inputStack: func() [][]byte {
					shared := []byte{0x01, 0x02, 0x03}
					return [][]byte{shared, shared}
				}(),
				expectedStack: [][]byte{{0x01, 0x02, 0x03}, {0x03, 0x02, 0x01}},
			},
			{
				name:       "max_element_size_520",
				inputStack: [][]byte{seqBytes(txscript.MaxScriptElementSize)},
			},
			{
				name:       "max_element_size_minus_one_519",
				inputStack: [][]byte{seqBytes(txscript.MaxScriptElementSize - 1)},
			},
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

// seqBytes returns a byte slice of length n filled with the values 0,1,2,...
// modulo 256. Used so reversal can be verified by the property checker
// without restating the expected bytes in the test vector.
func seqBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

func txWeightSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_TXWEIGHT,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.NoError(t, c.execErr)
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)
			require.Equal(t, len(c.before.GetStack())+1, len(c.after.GetStack()))
			require.Len(t, c.after.GetStack()[len(c.after.GetStack())-1], 4)
		},
		validVectors: []opcodeVector{
			{name: "push", expectedStack: [][]byte{opcodeWorldTxWeight()}},
		},
	}
}

// sighashTestLeafScript is the witness script we synthesize for OP_SIGHASH
// unit tests. The bytes are inconsequential to the digest the opcode produces
// other than that the same script is also fed into the expected sighash
// computation below, so anything that parses as a tapscript leaf works.
var sighashTestLeafScript = []byte{OP_SIGHASH}

// installSighashTapContext synthesizes the tapscript execution context that
// the engine would normally populate during verifyWitnessProgram. Tests run
// opcodes in isolation, so we wire it up directly here.
func installSighashTapContext(vm *Engine, annex []byte) {
	if vm.hashCache == nil {
		vm.hashCache = txscript.NewTxSigHashes(&vm.tx, vm.prevOutFetcher)
	}
	vm.taprootCtx = newTaprootExecutionCtxForLeaf(
		txscript.NewBaseTapLeaf(sighashTestLeafScript),
	)
	if len(annex) > 0 {
		vm.taprootCtx.annex = append([]byte(nil), annex...)
	}
}

// expectedSighash returns the digest that OP_SIGHASH should push for the
// given flag. Correctness of the digest (round-trip with
// OP_CHECKSIGFROMSTACK, witness-blob masking, domain separation from the
// BIP342 digest) is covered by dedicated tests in engine_test.go; this
// helper is a stability check that the opcode and the helper agree.
func expectedSighash(t *testing.T, vm *Engine, hashType txscript.SigHashType) []byte {
	t.Helper()
	digest, err := computeArkadeSighash(vm, hashType)
	require.NoError(t, err)
	return digest
}

func sighashSpec() *opcodeSpec {
	flagBytes := func(v int64) []byte {
		if v == 0 {
			return emptyByteVector()
		}
		return scriptNum(v).Bytes()
	}

	validFlag := func(name string, hashType txscript.SigHashType) opcodeVector {
		return opcodeVector{
			name:       name,
			inputStack: [][]byte{flagBytes(int64(hashType))},
			setupVM:    func(vm *Engine) { installSighashTapContext(vm, nil) },
		}
	}

	return &opcodeSpec{
		opcode: OP_SIGHASH,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			if c.execErr != nil {
				// PopInt consumes the flag before validation, so on
				// validation failures the data stack is one item
				// shorter; on a clean underflow it is unchanged. We
				// don't assert a specific shape here — the
				// expectedError check on each vector is sufficient.
				return
			}

			require.Equal(t, len(c.before.GetStack()), len(c.after.GetStack()))
			top := c.after.GetStack()[len(c.after.GetStack())-1]
			require.Len(t, top, 32)

			// The popped flag was the only stack input on a successful
			// run; recover it from the before-state to compute the
			// expected digest independently.
			beforeStack := c.before.GetStack()
			flagBytes := beforeStack[len(beforeStack)-1]
			flagNum, err := MakeScriptNum(flagBytes, true, maxScriptNumLen)
			require.NoError(t, err)
			expected := expectedSighash(t, c.before,
				txscript.SigHashType(flagNum.Int32()))
			require.Equal(t, expected, top)
		},
		validVectors: []opcodeVector{
			validFlag("default", txscript.SigHashDefault),
			validFlag("all", txscript.SigHashAll),
			validFlag("none", txscript.SigHashNone),
			validFlag("single", txscript.SigHashSingle),
			validFlag("all_anyonecanpay",
				txscript.SigHashAll|txscript.SigHashAnyOneCanPay),
			validFlag("none_anyonecanpay",
				txscript.SigHashNone|txscript.SigHashAnyOneCanPay),
			validFlag("single_anyonecanpay",
				txscript.SigHashSingle|txscript.SigHashAnyOneCanPay),
			{
				name:       "with_annex",
				inputStack: [][]byte{flagBytes(int64(txscript.SigHashAll))},
				setupVM: func(vm *Engine) {
					installSighashTapContext(vm, []byte{0x50, 0xab, 0xcd})
				},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "no_context",
				inputStack:    [][]byte{flagBytes(int64(txscript.SigHashAll))},
				expectedError: txscript.ErrReservedOpcode,
			},
			{
				name:          "underflow",
				setupVM:       func(vm *Engine) { installSighashTapContext(vm, nil) },
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name:          "unknown_flag",
				inputStack:    [][]byte{scriptNum(0x04).Bytes()},
				setupVM:       func(vm *Engine) { installSighashTapContext(vm, nil) },
				expectedError: txscript.ErrInvalidSigHashType,
			},
			{
				name:          "anyonecanpay_only",
				inputStack:    [][]byte{scriptNum(0x80).Bytes()},
				setupVM:       func(vm *Engine) { installSighashTapContext(vm, nil) },
				expectedError: txscript.ErrInvalidSigHashType,
			},
			{
				name:          "flag_too_large",
				inputStack:    [][]byte{scriptNum(256).Bytes()},
				setupVM:       func(vm *Engine) { installSighashTapContext(vm, nil) },
				expectedError: txscript.ErrNumberTooBig,
			},
			{
				name:          "flag_negative",
				inputStack:    [][]byte{scriptNum(-1).Bytes()},
				setupVM:       func(vm *Engine) { installSighashTapContext(vm, nil) },
				expectedError: txscript.ErrNumberTooBig,
			},
			{
				name:       "single_without_output",
				inputStack: [][]byte{flagBytes(int64(txscript.SigHashSingle))},
				setupWorld: func(w *opcodeWorld) {
					// Drop all outputs so input index >= len(TxOut).
					w.tx.TxOut = nil
				},
				setupVM:       func(vm *Engine) { installSighashTapContext(vm, nil) },
				expectedError: txscript.ErrInvalidSigHashType,
			},
		},
	}
}

func txIDSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_TXID,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.NoError(t, c.execErr)
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)
			require.Equal(t, len(c.before.GetStack())+1, len(c.after.GetStack()))
			top := c.after.GetStack()[len(c.after.GetStack())-1]
			require.Len(t, top, 32)
			h := c.before.tx.TxHash()
			require.Equal(t, h[:], top)
		},
		validVectors: []opcodeVector{{name: "push"}},
	}
}

func le64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

func assetSpec(op byte) *opcodeSpec {
	return &opcodeSpec{
		opcode:          op,
		checkProperties: errorNoMutationChecker(txscript.ErrInvalidStackOperation),
		invalidVectors: []opcodeVector{
			{name: "no_assets", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func checkLockTimeVerifySpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_CHECKLOCKTIMEVERIFY,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetStack(), c.after.GetStack())
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)
			if c.execErr == nil {
				return
			}
			requireScriptErrorCodeIn(t, c.execErr,
				txscript.ErrInvalidStackOperation,
				txscript.ErrNegativeLockTime,
				txscript.ErrUnsatisfiedLockTime,
				txscript.ErrNumberTooBig,
				txscript.ErrMinimalData,
			)
		},
		validVectors: []opcodeVector{
			{
				name:       "satisfied",
				inputStack: [][]byte{scriptNum(100).Bytes()},
				setupWorld: func(w *opcodeWorld) {
					w.tx.LockTime = 200
					w.tx.TxIn[0].Sequence = 0
				},
			},
			{
				name:       "satisfied_5_byte_bignum",
				inputStack: [][]byte{{0x00, 0x5e, 0xd0, 0xb2, 0x00}},
				setupWorld: func(w *opcodeWorld) {
					w.tx.LockTime = 3_000_000_000
					w.tx.TxIn[0].Sequence = 0
				},
			},
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:       "not_satisfied",
				inputStack: [][]byte{scriptNum(300).Bytes()},
				setupWorld: func(w *opcodeWorld) {
					w.tx.LockTime = 200
					w.tx.TxIn[0].Sequence = 0
				},
				expectedError: txscript.ErrUnsatisfiedLockTime,
			},
			{
				name:       "too_large_for_uint32",
				inputStack: [][]byte{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}},
				setupWorld: func(w *opcodeWorld) {
					w.tx.LockTime = 1
					w.tx.TxIn[0].Sequence = 0
				},
				expectedError: txscript.ErrUnsatisfiedLockTime,
			},
			{
				name:       "bignum_above_uint32",
				inputStack: [][]byte{{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}},
				setupWorld: func(w *opcodeWorld) {
					w.tx.LockTime = 1
					w.tx.TxIn[0].Sequence = 0
				},
				expectedError: txscript.ErrUnsatisfiedLockTime,
			},
			{
				name:          "negative",
				inputStack:    [][]byte{scriptNum(-1).Bytes()},
				expectedError: txscript.ErrNegativeLockTime,
			},
			{
				name:       "mismatched_type",
				inputStack: [][]byte{scriptNum(int64(txscript.LockTimeThreshold) + 1).Bytes()},
				setupWorld: func(w *opcodeWorld) {
					w.tx.LockTime = 200
					w.tx.TxIn[0].Sequence = 0
				},
				expectedError: txscript.ErrUnsatisfiedLockTime,
			},
			{
				name:       "finalized_input",
				inputStack: [][]byte{scriptNum(100).Bytes()},
				setupWorld: func(w *opcodeWorld) {
					w.tx.LockTime = 200
					w.tx.TxIn[0].Sequence = wire.MaxTxInSequenceNum
				},
				expectedError: txscript.ErrUnsatisfiedLockTime,
			},
		},
	}
}

func checkSequenceVerifySpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_CHECKSEQUENCEVERIFY,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetStack(), c.after.GetStack())
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)
			if c.execErr == nil {
				return
			}
			requireScriptErrorCodeIn(t, c.execErr,
				txscript.ErrInvalidStackOperation,
				txscript.ErrNegativeLockTime,
				txscript.ErrUnsatisfiedLockTime,
				txscript.ErrNumberTooBig,
				txscript.ErrMinimalData,
			)
		},
		validVectors: []opcodeVector{
			{
				name:       "satisfied",
				inputStack: [][]byte{scriptNum(50).Bytes()},
				setupWorld: func(w *opcodeWorld) {
					w.tx.Version = 2
					w.tx.TxIn[0].Sequence = 100
				},
			},
			{
				name:       "disabled_stack_flag_nop",
				inputStack: [][]byte{scriptNum(int64(wire.SequenceLockTimeDisabled)).Bytes()},
				setupWorld: func(w *opcodeWorld) {
					w.tx.Version = 1
					w.tx.TxIn[0].Sequence = wire.MaxTxInSequenceNum
				},
			},
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:       "not_satisfied",
				inputStack: [][]byte{scriptNum(150).Bytes()},
				setupWorld: func(w *opcodeWorld) {
					w.tx.Version = 2
					w.tx.TxIn[0].Sequence = 100
				},
				expectedError: txscript.ErrUnsatisfiedLockTime,
			},
			{
				name:          "negative",
				inputStack:    [][]byte{scriptNum(-1).Bytes()},
				expectedError: txscript.ErrNegativeLockTime,
			},
			{
				name:       "version_too_low",
				inputStack: [][]byte{scriptNum(50).Bytes()},
				setupWorld: func(w *opcodeWorld) {
					w.tx.Version = 1
					w.tx.TxIn[0].Sequence = 100
				},
				expectedError: txscript.ErrUnsatisfiedLockTime,
			},
			{
				name:       "tx_sequence_disabled",
				inputStack: [][]byte{scriptNum(50).Bytes()},
				setupWorld: func(w *opcodeWorld) {
					w.tx.Version = 2
					w.tx.TxIn[0].Sequence = wire.SequenceLockTimeDisabled
				},
				expectedError: txscript.ErrUnsatisfiedLockTime,
			},
		},
	}
}

func sha256InitializeSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_SHA256INITIALIZE,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			if c.execErr != nil {
				requireScriptErrorCode(t, c.execErr, txscript.ErrInvalidStackOperation)
				return
			}

			beforeStack := c.before.GetStack()
			afterStack := c.after.GetStack()
			require.Equal(t, len(beforeStack), len(afterStack))
			require.Equal(t, beforeStack[:len(beforeStack)-1], afterStack[:len(afterStack)-1])
			require.NotEmpty(t, afterStack[len(afterStack)-1])
			require.NotEqual(t, beforeStack[len(beforeStack)-1], afterStack[len(afterStack)-1])
		},
		validVectors: []opcodeVector{
			{
				name:          "init_golden",
				inputStack:    [][]byte{[]byte("Hello")},
				expectedStack: [][]byte{sha256InitGolden},
			},
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func sha256UpdateSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_SHA256UPDATE,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			if c.execErr != nil {
				requireScriptErrorCode(t, c.execErr, txscript.ErrInvalidStackOperation)
				return
			}

			beforeStack := c.before.GetStack()
			afterStack := c.after.GetStack()
			require.Equal(t, len(beforeStack)-1, len(afterStack))
			require.Equal(t, beforeStack[:len(beforeStack)-2], afterStack[:len(afterStack)-1])
			require.NotEmpty(t, afterStack[len(afterStack)-1])
			require.NotEqual(t, beforeStack[len(beforeStack)-1], afterStack[len(afterStack)-1])
		},
		validVectors: []opcodeVector{
			{
				name:          "valid_update_golden",
				inputStack:    [][]byte{sha256InitGolden, []byte(" World")},
				expectedStack: [][]byte{sha256UpdateGolden},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "invalid_state",
				inputStack:    [][]byte{{0x01, 0x02}, []byte("x")},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{name: "underflow_data", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "underflow_state",
				inputStack:    [][]byte{[]byte("x")},
				expectedError: txscript.ErrInvalidStackOperation,
			},
		},
	}
}

func sha256FinalizeSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_SHA256FINALIZE,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)

			if c.execErr != nil {
				requireScriptErrorCode(t, c.execErr, txscript.ErrInvalidStackOperation)
				return
			}

			beforeStack := c.before.GetStack()
			afterStack := c.after.GetStack()
			require.Equal(t, len(beforeStack)-1, len(afterStack))
			require.Equal(t, beforeStack[:len(beforeStack)-2], afterStack[:len(afterStack)-1])
			require.Len(t, afterStack[len(afterStack)-1], 32)
			require.NotEqual(t, beforeStack[len(beforeStack)-1], afterStack[len(afterStack)-1])
		},
		validVectors: []opcodeVector{
			{
				name:          "valid_finalize_golden",
				inputStack:    [][]byte{sha256UpdateGolden, []byte("!")},
				expectedStack: [][]byte{sha256FinalizeGolden},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "invalid_state",
				inputStack:    [][]byte{{0x01, 0x02}, []byte("x")},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{name: "underflow_data", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "underflow_state",
				inputStack:    [][]byte{[]byte("x")},
				expectedError: txscript.ErrInvalidStackOperation,
			},
		},
	}
}

var sha256InitGolden = mustDecodeHex(
	"097f060102ff8200000070ff80006c736861036a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd1948656c6c6f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005",
)

var sha256UpdateGolden = mustDecodeHex(
	"097f060102ff8200000070ff80006c736861036a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd1948656c6c6f20576f726c640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b",
)

var sha256FinalizeGolden = mustDecodeHex(
	"7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
)

func inspectInputOutpointSpec() *opcodeSpec {
	input0Hash := hashWithSalt([]byte("opcode-vectors"), 0x10)
	return &opcodeSpec{
		opcode:          OP_INSPECTINPUTOUTPOINT,
		checkProperties: inspectInputPropertyChecker(OP_INSPECTINPUTOUTPOINT),
		validVectors: []opcodeVector{
			{
				name:          "input0",
				inputStack:    [][]byte{nil},
				expectedStack: [][]byte{hashBytes(input0Hash), {10}},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "negative",
				inputStack:    [][]byte{scriptNum(-1).Bytes()},
				expectedError: txscript.ErrInvalidIndex,
			},
			{
				name:          "out_of_range",
				inputStack:    [][]byte{scriptNum(9).Bytes()},
				expectedError: txscript.ErrInvalidIndex,
			},
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func inspectInputValueSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_INSPECTINPUTVALUE,
		checkProperties: inspectInputPropertyChecker(OP_INSPECTINPUTVALUE),
		validVectors: []opcodeVector{
			{name: "val0", inputStack: [][]byte{nil}, expectedStack: [][]byte{{0x88, 0x13}}},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "negative",
				inputStack:    [][]byte{scriptNum(-1).Bytes()},
				expectedError: txscript.ErrInvalidIndex,
			},
			{
				name:          "out_of_range",
				inputStack:    [][]byte{scriptNum(9).Bytes()},
				expectedError: txscript.ErrInvalidIndex,
			},
			{
				name:          "no_prev_fetcher",
				inputStack:    [][]byte{nil},
				setupWorld:    func(w *opcodeWorld) { w.prevFetcher = nil },
				expectedError: txscript.ErrInvalidIndex,
			},
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func inspectInputScriptPubkeySpec() *opcodeSpec {
	prevScriptHash := sha256Bytes([]byte{OP_1, 0x20})
	return &opcodeSpec{
		opcode:          OP_INSPECTINPUTSCRIPTPUBKEY,
		checkProperties: inspectInputPropertyChecker(OP_INSPECTINPUTSCRIPTPUBKEY),
		validVectors: []opcodeVector{
			{
				name:       "spk0",
				inputStack: [][]byte{nil},
				setupWorld: func(w *opcodeWorld) {
					prevTx := wire.MsgTx{TxOut: make([]*wire.TxOut, 11)}
					prevTx.TxOut[10] = &wire.TxOut{PkScript: []byte{OP_1, 0x20}}
					attachOpcodePrevArkTx(w, prevTx)
				},
				expectedStack: [][]byte{prevScriptHash, {0x81}},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "negative",
				inputStack:    [][]byte{scriptNum(-1).Bytes()},
				expectedError: txscript.ErrInvalidIndex,
			},
			{
				name:          "out_of_range",
				inputStack:    [][]byte{scriptNum(9).Bytes()},
				expectedError: txscript.ErrInvalidIndex,
			},
			{
				name:          "no_prev_fetcher",
				inputStack:    [][]byte{nil},
				setupWorld:    func(w *opcodeWorld) { w.prevFetcher = nil },
				expectedError: txscript.ErrInvalidIndex,
			},
			{
				name:          "missing_prevout",
				inputStack:    [][]byte{nil},
				setupWorld:    func(w *opcodeWorld) { w.tx.TxIn[0].PreviousOutPoint = wire.OutPoint{} },
				expectedError: txscript.ErrInvalidIndex,
			},
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func inspectInputSequenceSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_INSPECTINPUTSEQUENCE,
		checkProperties: inspectInputPropertyChecker(OP_INSPECTINPUTSEQUENCE),
		validVectors: []opcodeVector{
			{name: "seq0", inputStack: [][]byte{nil}, expectedStack: [][]byte{{100, 0, 0, 0}}},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "negative",
				inputStack:    [][]byte{scriptNum(-1).Bytes()},
				expectedError: txscript.ErrInvalidIndex,
			},
			{
				name:          "out_of_range",
				inputStack:    [][]byte{scriptNum(9).Bytes()},
				expectedError: txscript.ErrInvalidIndex,
			},
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func inspectOutputValueSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_INSPECTOUTPUTVALUE,
		checkProperties: inspectOutputPropertyChecker(OP_INSPECTOUTPUTVALUE),
		validVectors: []opcodeVector{
			{name: "val0", inputStack: [][]byte{nil}, expectedStack: [][]byte{{0x58, 0x1b}}},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "negative",
				inputStack:    [][]byte{scriptNum(-1).Bytes()},
				expectedError: txscript.ErrInvalidIndex,
			},
			{
				name:          "out_of_range",
				inputStack:    [][]byte{scriptNum(9).Bytes()},
				expectedError: txscript.ErrInvalidIndex,
			},
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func inspectOutputScriptPubkeySpec() *opcodeSpec {
	outputScriptHash := sha256Bytes([]byte{OP_TRUE})
	return &opcodeSpec{
		opcode:          OP_INSPECTOUTPUTSCRIPTPUBKEY,
		checkProperties: inspectOutputPropertyChecker(OP_INSPECTOUTPUTSCRIPTPUBKEY),
		validVectors: []opcodeVector{
			{
				name:          "spk0",
				inputStack:    [][]byte{nil},
				expectedStack: [][]byte{outputScriptHash, {0x81}},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "negative",
				inputStack:    [][]byte{scriptNum(-1).Bytes()},
				expectedError: txscript.ErrInvalidIndex,
			},
			{
				name:          "out_of_range",
				inputStack:    [][]byte{scriptNum(9).Bytes()},
				expectedError: txscript.ErrInvalidIndex,
			},
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func pushCurrentInputIndexSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_PUSHCURRENTINPUTINDEX,
		checkProperties: inspectMetaPropertyChecker(OP_PUSHCURRENTINPUTINDEX),
		validVectors:    []opcodeVector{{name: "push", expectedStack: [][]byte{zeroStackItem()}}},
	}
}

func inspectVersionSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_INSPECTVERSION,
		checkProperties: inspectMetaPropertyChecker(OP_INSPECTVERSION),
		validVectors:    []opcodeVector{{name: "push", expectedStack: [][]byte{{2, 0, 0, 0}}}},
	}
}

func inspectLocktimeSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_INSPECTLOCKTIME,
		checkProperties: inspectMetaPropertyChecker(OP_INSPECTLOCKTIME),
		validVectors:    []opcodeVector{{name: "push", expectedStack: [][]byte{{144, 0, 0, 0}}}},
	}
}

func inspectNumInputsSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_INSPECTNUMINPUTS,
		checkProperties: inspectMetaPropertyChecker(OP_INSPECTNUMINPUTS),
		validVectors: []opcodeVector{
			{name: "push", expectedStack: [][]byte{scriptNum(1).Bytes()}},
		},
	}
}

func inspectNumOutputsSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_INSPECTNUMOUTPUTS,
		checkProperties: inspectMetaPropertyChecker(OP_INSPECTNUMOUTPUTS),
		validVectors: []opcodeVector{
			{name: "push", expectedStack: [][]byte{scriptNum(1).Bytes()}},
		},
	}
}

func inspectPacketSpec() *opcodeSpec {
	const packetType = 2
	const maxPacketType = 255
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	maxPayload := []byte{0xff, 0x00, 0xff}
	largePayload := bytes.Repeat([]byte{0xab}, 1000)

	return &opcodeSpec{
		opcode:          OP_INSPECTPACKET,
		checkProperties: inspectPacketPropertyChecker(OP_INSPECTPACKET),
		validVectors: []opcodeVector{
			{
				name:       "found",
				inputStack: [][]byte{scriptNum(packetType).Bytes()},
				setupWorld: func(w *opcodeWorld) {
					w.tx = makeOpcodeTxWithExtension(extension.UnknownPacket{PacketType: packetType, Data: payload})
				},
				expectedStack: [][]byte{payload, {1}},
			},
			{
				name:       "not_found",
				inputStack: [][]byte{scriptNum(9).Bytes()},
				setupWorld: func(w *opcodeWorld) {
					w.tx = makeOpcodeTxWithExtension(extension.UnknownPacket{PacketType: packetType, Data: payload})
				},
				expectedStack: [][]byte{nil, nil},
			},
			{
				name:          "no_extension",
				inputStack:    [][]byte{scriptNum(packetType).Bytes()},
				expectedStack: [][]byte{nil, nil},
			},
			{
				name:       "max_type",
				inputStack: [][]byte{scriptNum(maxPacketType).Bytes()},
				setupWorld: func(w *opcodeWorld) {
					w.tx = makeOpcodeTxWithExtension(extension.UnknownPacket{PacketType: maxPacketType, Data: maxPayload})
				},
				expectedStack: [][]byte{maxPayload, {1}},
			},
		},
		invalidVectors: []opcodeVector{
			{name: "negative_type", inputStack: [][]byte{scriptNum(-1).Bytes()}, expectedError: txscript.ErrInvalidStackOperation},
			{name: "type_out_of_range", inputStack: [][]byte{scriptNum(256).Bytes()}, expectedError: txscript.ErrInvalidStackOperation},
			{
				name:       "malformed_extension",
				inputStack: [][]byte{scriptNum(packetType).Bytes()},
				setupWorld: func(w *opcodeWorld) {
					w.tx = makeOpcodeTxWithMalformedExtension([]byte{'A', 'R', 'K', packetType})
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name:       "large_content",
				inputStack: [][]byte{scriptNum(4).Bytes()},
				setupWorld: func(w *opcodeWorld) {
					w.tx = makeOpcodeTxWithExtension(extension.UnknownPacket{PacketType: 4, Data: largePayload})
				},
				expectedError: txscript.ErrElementTooBig,
			},
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func inspectInputPacketSpec() *opcodeSpec {
	const packetType = 2
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	largePayload := bytes.Repeat([]byte{0xab}, 1000)

	return &opcodeSpec{
		opcode:          OP_INSPECTINPUTPACKET,
		checkProperties: inspectPacketPropertyChecker(OP_INSPECTINPUTPACKET),
		validVectors: []opcodeVector{
			{
				name:       "found",
				inputStack: [][]byte{scriptNum(packetType).Bytes(), nil},
				setupWorld: func(w *opcodeWorld) {
					attachOpcodePrevArkTx(w, makeOpcodeTxWithExtension(extension.UnknownPacket{PacketType: packetType, Data: payload}))
				},
				expectedStack: [][]byte{payload, {1}},
			},
			{
				name:       "not_found",
				inputStack: [][]byte{scriptNum(9).Bytes(), nil},
				setupWorld: func(w *opcodeWorld) {
					attachOpcodePrevArkTx(w, makeOpcodeTxWithExtension(extension.UnknownPacket{PacketType: packetType, Data: payload}))
				},
				expectedStack: [][]byte{nil, nil},
			},
			{
				name:       "prev_tx_no_extension",
				inputStack: [][]byte{scriptNum(packetType).Bytes(), nil},
				setupWorld: func(w *opcodeWorld) {
					attachOpcodePrevArkTx(w, makeOpcodePlainTx())
				},
				expectedStack: [][]byte{nil, nil},
			},
		},
		invalidVectors: []opcodeVector{
			{name: "negative_index", inputStack: [][]byte{scriptNum(packetType).Bytes(), scriptNum(-1).Bytes()}, expectedError: txscript.ErrInvalidIndex},
			{name: "index_out_of_range", inputStack: [][]byte{scriptNum(packetType).Bytes(), scriptNum(9).Bytes()}, expectedError: txscript.ErrInvalidIndex},
			{name: "type_out_of_range", inputStack: [][]byte{scriptNum(256).Bytes(), nil}, expectedError: txscript.ErrInvalidStackOperation},
			{
				name:          "no_prev_fetcher",
				inputStack:    [][]byte{scriptNum(packetType).Bytes(), nil},
				setupWorld:    func(w *opcodeWorld) { w.prevFetcher = nil },
				expectedError: txscript.ErrInvalidIndex,
			},
			{
				name:          "prevout_tx_not_available",
				inputStack:    [][]byte{scriptNum(packetType).Bytes(), nil},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name:       "malformed_prev_tx_extension",
				inputStack: [][]byte{scriptNum(packetType).Bytes(), nil},
				setupWorld: func(w *opcodeWorld) {
					attachOpcodePrevArkTx(w, makeOpcodeTxWithMalformedExtension([]byte{'A', 'R', 'K', packetType}))
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name:       "large_content",
				inputStack: [][]byte{scriptNum(4).Bytes(), nil},
				setupWorld: func(w *opcodeWorld) {
					attachOpcodePrevArkTx(w, makeOpcodeTxWithExtension(extension.UnknownPacket{PacketType: 4, Data: largePayload}))
				},
				expectedError: txscript.ErrElementTooBig,
			},
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{name: "single_stack_element", inputStack: [][]byte{scriptNum(packetType).Bytes()}, expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func inspectInputPropertyChecker(op byte) opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
		require.Equal(t, c.before.condStack, c.after.condStack)

		beforeDepth := len(c.before.GetStack())
		afterDepth := len(c.after.GetStack())
		if c.execErr != nil {
			requireScriptErrorCodeIn(t, c.execErr,
				txscript.ErrInvalidStackOperation,
				txscript.ErrInvalidIndex,
				txscript.ErrNumberTooBig,
				txscript.ErrMinimalData,
			)
			require.True(t, afterDepth == beforeDepth || afterDepth == beforeDepth-1)
			return
		}

		switch op {
		case OP_INSPECTINPUTOUTPOINT, OP_INSPECTINPUTSCRIPTPUBKEY:
			require.Equal(t, beforeDepth+1, afterDepth)
		case OP_INSPECTINPUTVALUE, OP_INSPECTINPUTSEQUENCE:
			require.Equal(t, beforeDepth, afterDepth)
		default:
			t.Fatalf("unsupported inspect input op %s", opcodeArray[op].name)
		}

		top := c.after.GetStack()[afterDepth-1]
		switch op {
		case OP_INSPECTINPUTOUTPOINT:
			require.LessOrEqual(t, len(top), 5)
			require.Len(t, c.after.GetStack()[afterDepth-2], 32)
		case OP_INSPECTINPUTVALUE:
			index, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-1])
			require.NoError(t, err)
			prevOut := c.before.prevOutFetcher.FetchPrevOutput(c.before.tx.TxIn[int(index.BigInt().Int64())].PreviousOutPoint)
			require.NotNil(t, prevOut)
			want, err := BigNumFromUint64(uint64(prevOut.Value)).Bytes()
			require.NoError(t, err)
			require.Equal(t, want, top)
		case OP_INSPECTINPUTSCRIPTPUBKEY:
			require.LessOrEqual(t, len(top), 5)
			programOrHash := c.after.GetStack()[afterDepth-2]
			require.NotEmpty(t, programOrHash)
		case OP_INSPECTINPUTSEQUENCE:
			require.Len(t, top, 4)
		}
	}
}

func inspectOutputPropertyChecker(op byte) opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
		require.Equal(t, c.before.condStack, c.after.condStack)

		beforeDepth := len(c.before.GetStack())
		afterDepth := len(c.after.GetStack())
		if c.execErr != nil {
			requireScriptErrorCodeIn(t, c.execErr,
				txscript.ErrInvalidStackOperation,
				txscript.ErrInvalidIndex,
				txscript.ErrNumberTooBig,
				txscript.ErrMinimalData,
			)
			require.True(t, afterDepth == beforeDepth || afterDepth == beforeDepth-1)
			return
		}

		switch op {
		case OP_INSPECTOUTPUTVALUE:
			require.Equal(t, beforeDepth, afterDepth)
			index, err := BigNumFromBytes(c.before.GetStack()[beforeDepth-1])
			require.NoError(t, err)
			want, err := BigNumFromUint64(uint64(c.before.tx.TxOut[int(index.BigInt().Int64())].Value)).Bytes()
			require.NoError(t, err)
			require.Equal(t, want, c.after.GetStack()[afterDepth-1])
		case OP_INSPECTOUTPUTSCRIPTPUBKEY:
			require.Equal(t, beforeDepth+1, afterDepth)
			require.LessOrEqual(t, len(c.after.GetStack()[afterDepth-1]), 5)
			require.NotEmpty(t, c.after.GetStack()[afterDepth-2])
		default:
			t.Fatalf("unsupported inspect output op %s", opcodeArray[op].name)
		}
	}
}

func inspectMetaPropertyChecker(op byte) opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
		require.Equal(t, c.before.condStack, c.after.condStack)
		require.NoError(t, c.execErr)

		beforeDepth := len(c.before.GetStack())
		afterDepth := len(c.after.GetStack())
		require.Equal(t, beforeDepth+1, afterDepth)

		top := c.after.GetStack()[afterDepth-1]
		switch op {
		case OP_INSPECTVERSION, OP_INSPECTLOCKTIME:
			require.Len(t, top, 4)
		case OP_PUSHCURRENTINPUTINDEX, OP_INSPECTNUMINPUTS, OP_INSPECTNUMOUTPUTS:
			require.LessOrEqual(t, len(top), 5)
		default:
			t.Fatalf("unsupported inspect meta op %s", opcodeArray[op].name)
		}
	}
}

func inspectInputArkadeScriptHashSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_INSPECTINPUTARKADESCRIPTHASH,
		checkProperties: inspectInputArkadePropertyChecker(),
		validVectors: []opcodeVector{
			{
				name:       "valid",
				inputStack: [][]byte{nil},
				setupWorld: func(w *opcodeWorld) {
					w.packet = EmulatorPacket{{Vin: 0, Script: []byte{OP_TRUE}}}
				},
				expectedStack: [][]byte{ArkadeScriptHash([]byte{OP_TRUE})},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "negative",
				inputStack:    [][]byte{scriptNum(-1).Bytes()},
				expectedError: txscript.ErrInvalidIndex,
			},
			{
				name:          "out_of_range",
				inputStack:    [][]byte{scriptNum(9).Bytes()},
				expectedError: txscript.ErrInvalidIndex,
			},
			{
				name:          "missing_entry",
				inputStack:    [][]byte{nil},
				setupWorld:    func(w *opcodeWorld) { w.packet = EmulatorPacket{{Vin: 1, Script: []byte{OP_TRUE}}} },
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name:          "no_packet",
				inputStack:    [][]byte{nil},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func inspectInputArkadeWitnessHashSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode:          OP_INSPECTINPUTARKADEWITNESSHASH,
		checkProperties: inspectInputArkadePropertyChecker(),
		validVectors: []opcodeVector{
			{
				name:       "valid",
				inputStack: [][]byte{nil},
				setupWorld: func(w *opcodeWorld) {
					w.packet = EmulatorPacket{{Vin: 0, Witness: wire.TxWitness{{0x01}}}}
				},
			},
			{
				name:       "empty_witness",
				inputStack: [][]byte{nil},
				setupWorld: func(w *opcodeWorld) {
					w.packet = EmulatorPacket{{Vin: 0, Witness: wire.TxWitness{}}}
				},
				expectedStack: [][]byte{make([]byte, 32)},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "negative",
				inputStack:    [][]byte{scriptNum(-1).Bytes()},
				expectedError: txscript.ErrInvalidIndex,
			},
			{
				name:          "out_of_range",
				inputStack:    [][]byte{scriptNum(9).Bytes()},
				expectedError: txscript.ErrInvalidIndex,
			},
			{
				name:          "missing_entry",
				inputStack:    [][]byte{nil},
				setupWorld:    func(w *opcodeWorld) { w.packet = EmulatorPacket{{Vin: 1, Witness: wire.TxWitness{{0x01}}}} },
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name:          "no_packet",
				inputStack:    [][]byte{nil},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
		},
	}
}

func inspectInputArkadePropertyChecker() opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
		require.Equal(t, c.before.condStack, c.after.condStack)

		beforeDepth := len(c.before.GetStack())
		afterDepth := len(c.after.GetStack())
		if c.execErr != nil {
			requireScriptErrorCodeIn(t, c.execErr,
				txscript.ErrInvalidStackOperation,
				txscript.ErrInvalidIndex,
				txscript.ErrNumberTooBig,
				txscript.ErrMinimalData,
			)
			require.True(t, afterDepth == beforeDepth || afterDepth == beforeDepth-1)
			return
		}

		require.Equal(t, beforeDepth, afterDepth)
		require.Len(t, c.after.GetStack()[afterDepth-1], 32)
	}
}

func inspectPacketPropertyChecker(op byte) opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
		require.Equal(t, c.before.condStack, c.after.condStack)

		beforeDepth := len(c.before.GetStack())
		afterDepth := len(c.after.GetStack())
		if c.execErr != nil {
			requireScriptErrorCodeIn(t, c.execErr,
				txscript.ErrInvalidStackOperation,
				txscript.ErrInvalidIndex,
				txscript.ErrNumberTooBig,
				txscript.ErrMinimalData,
				txscript.ErrElementTooBig,
			)
			switch op {
			case OP_INSPECTPACKET:
				require.True(t, afterDepth == beforeDepth || afterDepth == beforeDepth-1)
			case OP_INSPECTINPUTPACKET:
				require.True(t, afterDepth == beforeDepth || afterDepth == beforeDepth-1 || afterDepth == beforeDepth-2)
			default:
				t.Fatalf("unsupported inspect packet op %s", opcodeArray[op].name)
			}
			return
		}

		switch op {
		case OP_INSPECTPACKET:
			require.Equal(t, beforeDepth+1, afterDepth)
		case OP_INSPECTINPUTPACKET:
			require.Equal(t, beforeDepth, afterDepth)
		default:
			t.Fatalf("unsupported inspect packet op %s", opcodeArray[op].name)
		}

		flag := c.after.GetStack()[afterDepth-1]
		require.True(t, bytes.Equal(flag, zeroStackItem()) || bytes.Equal(flag, []byte{1}))
		require.LessOrEqual(t, len(c.after.GetStack()[afterDepth-2]), txscript.MaxScriptElementSize)
	}
}

func buildOpcodeWorld() *opcodeWorld {
	seed := []byte("opcode-vectors")
	outpoint0 := wire.OutPoint{Hash: hashWithSalt(seed, 0x10), Index: 10}
	tx := wire.MsgTx{
		Version:  2,
		LockTime: 144,
		TxIn:     []*wire.TxIn{{PreviousOutPoint: outpoint0, Sequence: 100}},
		TxOut:    []*wire.TxOut{{Value: 7000, PkScript: []byte{OP_TRUE}}},
	}
	prevouts := map[wire.OutPoint]*wire.TxOut{
		outpoint0: {Value: 5000, PkScript: []byte{OP_1, 0x20}},
	}
	return &opcodeWorld{
		tx:          tx,
		prevouts:    prevouts,
		prevFetcher: newTestArkPrevOutFetcher(txscript.NewMultiPrevOutFetcher(prevouts), nil, nil),
	}
}

func makeOpcodePlainTx() wire.MsgTx {
	return wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0},
		}},
	}
}

func makeOpcodeTxWithExtension(packets ...extension.Packet) wire.MsgTx {
	ext := extension.Extension(packets)
	txOut, err := ext.TxOut()
	if err != nil {
		panic(fmt.Sprintf("Extension.TxOut: %v", err))
	}
	tx := makeOpcodePlainTx()
	tx.TxOut = []*wire.TxOut{txOut}
	return tx
}

func makeOpcodeTxWithMalformedExtension(payload []byte) wire.MsgTx {
	tx := makeOpcodePlainTx()
	tx.TxOut = []*wire.TxOut{{
		Value:    0,
		PkScript: append([]byte{txscript.OP_RETURN, byte(len(payload))}, payload...),
	}}
	return tx
}

func attachOpcodePrevArkTx(w *opcodeWorld, prevTx wire.MsgTx) {
	outpoint := w.tx.TxIn[0].PreviousOutPoint
	w.prevFetcher = newTestArkPrevOutFetcher(
		txscript.NewMultiPrevOutFetcher(w.prevouts),
		map[wire.OutPoint]*wire.MsgTx{outpoint: &prevTx},
		map[wire.OutPoint]uint32{outpoint: outpoint.Index},
	)
}

func newOpcodeEngine(world *opcodeWorld, txIdx int) (*Engine, error) {
	txCopy := world.tx.Copy()
	spk := []byte{OP_TRUE}
	inputAmount := int64(0)

	if txIdx >= 0 && txIdx < len(txCopy.TxIn) {
		if witness := world.witnessByVin[txIdx]; len(witness) > 0 {
			txCopy.TxIn[txIdx].Witness = cloneWitness(witness)
		}
		if script := world.execScriptByVin[txIdx]; len(script) > 0 {
			spk = cloneBytes(script)
		}
		if world.prevFetcher != nil {
			if prevOut := world.prevFetcher.FetchPrevOutput(txCopy.TxIn[txIdx].PreviousOutPoint); prevOut != nil {
				inputAmount = prevOut.Value
			}
		}
	}

	vm, err := NewEngine(spk, txCopy, txIdx, txscript.NewSigCache(32), nil, inputAmount, world.prevFetcher)
	if err != nil {
		return nil, err
	}
	vm.dstack.verifyMinimalData = true
	vm.astack.verifyMinimalData = true
	return vm, nil
}

func invokeOpcodeWithData(opcode byte, data []byte, vm *Engine) error {
	op := &opcodeArray[opcode]
	if op.opfunc == nil {
		return nil
	}
	if data == nil {
		if op.length > 1 {
			data = make([]byte, op.length-1)
		}
	}
	return vm.executeOpcode(op, data)
}

func requireScriptErrorCode(t *testing.T, err error, code txscript.ErrorCode) {
	t.Helper()
	require.Error(t, err)
	scriptErr, ok := err.(txscript.Error)
	require.Truef(t, ok, "expected txscript.Error, got %T: %v", err, err)
	require.Equal(t, code, scriptErr.ErrorCode)
}

func requireScriptErrorCodeIn(t *testing.T, err error, codes ...txscript.ErrorCode) {
	t.Helper()
	require.Error(t, err)
	scriptErr, ok := err.(txscript.Error)
	require.Truef(t, ok, "expected txscript.Error, got %T: %v", err, err)
	if slices.Contains(codes, scriptErr.ErrorCode) {
		return
	}
	t.Fatalf("unexpected txscript error code: got=%v want one of=%v", scriptErr.ErrorCode, codes)
}

func hashWithSalt(seed []byte, salt byte) chainhash.Hash {
	b := make([]byte, len(seed)+1)
	copy(b, seed)
	b[len(seed)] = salt
	sum := sha256.Sum256(b)
	var h chainhash.Hash
	copy(h[:], sum[:])
	return h
}

func mustDecodeHex(hexStr string) []byte {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(fmt.Sprintf("invalid hex string: %v", err))
	}
	return b
}

func zeroStackItem() []byte {
	return scriptNum(0).Bytes()
}

func falseStackItem() []byte {
	return fromBool(false)
}

func emptyByteVector() []byte {
	return []byte{}
}

func opcodeWorldTxWeight() []byte {
	world := buildOpcodeWorld()
	weight := make([]byte, 4)
	binary.LittleEndian.PutUint32(weight, uint32(world.tx.SerializeSizeStripped()*4))
	return weight
}

func hashBytes(h chainhash.Hash) []byte {
	return append([]byte(nil), h[:]...)
}

func sha256Bytes(data []byte) []byte {
	sum := sha256.Sum256(data)
	return append([]byte(nil), sum[:]...)
}

func TestOpcodeModexpSmoke(t *testing.T) {
	t.Parallel()

	require.Equal(t, "OP_MODEXP", opcodeArray[OP_MODEXP].name)
	require.Equal(t, 1, opcodeArray[OP_MODEXP].length)
	require.NotNil(t, opcodeArray[OP_MODEXP].opfunc)
}
