# Introspector

[![test](https://github.com/ArkLabsHQ/introspector/actions/workflows/test.yaml/badge.svg)](https://github.com/ArkLabsHQ/introspector/actions/workflows/test.yaml)
[![quality](https://github.com/ArkLabsHQ/introspector/actions/workflows/quality.yaml/badge.svg)](https://github.com/ArkLabsHQ/introspector/actions/workflows/quality.yaml)
[![Trivy Security Scan](https://github.com/ArkLabsHQ/introspector/actions/workflows/trivy.yaml/badge.svg)](https://github.com/ArkLabsHQ/introspector/actions/workflows/trivy.yaml)

_Introspector is a signing service for the [Arkade](https://docs.arkadeos.com/) protocol, executing [Arkade Script](https://docs.arkadeos.com/experimental/arkade-script)._

This is achieved by signing any Ark transaction (offchain or intent proof) expecting the signature of a [tweaked public key](pkg/arkade/tweak.go). The tweaked key is `introspector_key + hash(arkade_script)`, where the script hash is a [tagged hash](pkg/arkade/tweak.go#L15) (`"ArkScriptHash"`). The Arkade script is revealed via an [Introspector Packet](pkg/arkade/introspector_packet.go) committed in a transaction OP_RETURN output. The packet is a TLV (Type-Length-Value) stream with magic bytes `ARK` (`0x41524b`), containing per-input entries with the script bytecode and optional witness arguments.

## Example: Pay-to-Two-Outputs

This example builds a VTXO that can only be spent if two specific outputs are created with exact amounts. The introspector enforces these conditions via an Arkade script. See the full test in [`test/pay_2_out_test.go`](test/pay_2_out_test.go).

### 1. Build the Arkade script

The script uses introspection opcodes to verify the transaction outputs match the expected addresses and amounts:

```go
arkadeScript, _ := txscript.NewScriptBuilder().
    // output 0 must pay to alice
    AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
    AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY).       // segwit v1
    AddData(alicePkScript[2:]).AddOp(arkade.OP_EQUALVERIFY). // witness program
    // output 0 must have exact amount
    AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTVALUE).
    AddData(uint64LE(aliceAmount)).AddOp(arkade.OP_EQUALVERIFY).
    // output 1 must pay to bob
    AddInt64(1).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
    AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY).
    AddData(bobPkScript[2:]).AddOp(arkade.OP_EQUALVERIFY).
    // output 1 must have exact amount
    AddInt64(1).AddOp(arkade.OP_INSPECTOUTPUTVALUE).
    AddData(uint64LE(bobAmount)).AddOp(arkade.OP_EQUAL).
    Script()
```

### 2. Compute the tweaked key and build the VTXO tapscript

The VTXO uses a `MultisigClosure` with three keys: the ark server, the user and the introspector's tweaked key.

```go
scriptHash := arkade.ArkadeScriptHash(arkadeScript)
tweakedKey := arkade.ComputeArkadeScriptPublicKey(introspectorPubKey, scriptHash)

vtxoScript := script.TapscriptsVtxoScript{
    Closures: []script.Closure{
        &script.MultisigClosure{
            PubKeys: []*btcec.PublicKey{aliceKey, tweakedKey, serverKey},
        },
    },
}
vtxoTapKey, _, _ := vtxoScript.TapTree()
```

### 3. Build the PSBT and attach the Introspector Packet

Build the offchain transaction with outputs matching the script, then commit the Arkade script in an OP_RETURN Introspector Packet:

```go
tx, checkpoints, _ := offchain.BuildTxs(
    []offchain.VtxoInput{vtxoInput},
    []*wire.TxOut{
        {Value: aliceAmount, PkScript: alicePkScript},
        {Value: bobAmount, PkScript: bobPkScript},
    },
    checkpointScript,
)

// build the introspector packet with script for input 0
packet := &arkade.IntrospectorPacket{
    Entries: []arkade.IntrospectorEntry{
        {Vin: 0, Script: arkadeScript},
    },
}
opReturnScript, _ := arkade.BuildOpReturnScript(nil, packet)
tx.UnsignedTx.AddTxOut(&wire.TxOut{Value: 0, PkScript: opReturnScript})
tx.Outputs = append(tx.Outputs, psbt.POutput{})
```

### 4. Submit to the introspector

The introspector [decodes the tapscript](internal/application/utils.go), verifies it is a `MultisigClosure` containing the expected tweaked key, [executes the Arkade script](internal/application/tx.go) against the Ark transaction, and signs both the matching Ark input and checkpoint if it passes. If it is the last required non-`arkd` signer for all owned inputs matched by the introspector packet, it then submits the transaction set to `arkd`, merges `arkd`'s checkpoint signatures, and finalizes the transaction:

```go
signedTx, signedCheckpoints, _ := introspectorClient.SubmitTx(ctx, encodedTx, encodedCheckpoints)
```

## API

### GetInfo

Returns service metadata including the signer's public key. The public key should be tweaked with the Arkade script hash before being used in a VTXO tapscript.

**Endpoint**: `GET /v1/info`

**Response**:
```json
{
  "version": "0.0.1",
  "signer_pubkey": "compressed_public_key"
}
```

### SubmitTx

Validates and signs the Ark transaction inputs owned by this introspector, and signs their matching checkpoint transactions. Arkade scripts are executed only on the Ark transaction, not on checkpoints.

If this introspector is the last required non-`arkd` signer for all owned inputs matched by the introspector packet, each checkpoint PSBT must already include any other required non-`arkd` signatures; otherwise the request fails. In that case, the introspector submits the signed transaction set to `arkd`, merges `arkd`'s checkpoint signatures, finalizes the transaction, and returns the finalized Ark PSBT plus updated checkpoint PSBTs. Otherwise it returns only this introspector's added signatures without calling `arkd`.

**Endpoint**: `POST /v1/tx`

**Request**:
```json
{
  "ark_tx": "base64_encoded_psbt",
  "checkpoint_txs": ["base64_encoded_checkpoint_psbt1", "..."]
}
```

**Response**:
```json
{
  "signed_ark_tx": "base64_encoded_signed_psbt",
  "signed_checkpoint_txs": ["base64_encoded_signed_checkpoint_psbt1", "..."]
}
```

`signed_ark_tx` may be either partially signed or finalized, depending on whether this introspector is the last required non-`arkd` signer for all owned inputs matched by the introspector packet.

### SubmitIntent

Signs an intent proof after validating the register message and executing Arkade scripts on the proof transaction. Must be called before intent registration.

**Endpoint**: `POST /v1/intent`

**Request**:
```json
{
  "intent": {
    "proof": "base64_encoded_psbt",
    "message": "base64_encoded_register_message"
  }
}
```

**Response**:
```json
{
  "signed_proof": "base64_encoded_signed_psbt"
}
```

### SubmitFinalization

Conditionally signs forfeit and/or boarding inputs during batch finalization. Only signs if the signer's signature is found in the intent proof. The connector tree is used to verify the forfeits are part of a real batch session.

**Endpoint**: `POST /v1/finalization`

**Request**:
```json
{
  "signed_intent": {
    "proof": "base64_encoded_signed_psbt",
    "message": "base64_encoded_register_message"
  },
  "forfeits": ["base64_encoded_forfeit_psbt1", "..."],
  "connector_tree": [
    {
      "txid": "transaction_id",
      "tx": "base64_encoded_transaction",
      "children": {
        "0": "child_txid_1",
        "1": "child_txid_2"
      }
    }
  ],
  "commitment_tx": "base64_encoded_psbt"
}
```

**Response**:
```json
{
  "signed_forfeits": ["base64_encoded_signed_forfeit_psbt1", "..."],
  "signed_commitment_tx": "base64_encoded_signed_psbt"
}
```

### SubmitOnchainTx

Validates and signs the inputs of a plain Bitcoin transaction whose tapscripts contain the introspector's tweaked key (e.g. a VTXO unrolled onchain). Each input may carry an optional `PrevoutTxField` PSBT unknown field (key `"prevouttx"`) holding the raw previous transaction, required only by arkade opcodes that introspect it.

Inputs whose tapscript closure also contains the `arkd` signer pubkey are rejected — those must go through [`SubmitTx`](#submittx) so checkpoint and forfeit checks are enforced.

**Endpoint**: `POST /v1/onchain-tx`

**Request**:
```json
{
  "tx": "base64_encoded_psbt"
}
```

**Response**:
```json
{
  "signed_tx": "base64_encoded_signed_psbt"
}
```

## Configuration

The service can be configured using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `INTROSPECTOR_SECRET_KEY` | Private key for signing (hex encoded) | Required |
| `INTROSPECTOR_DATADIR` | Data directory path | OS-specific app data dir |
| `INTROSPECTOR_PORT` | gRPC server port | 7073 |
| `INTROSPECTOR_NO_TLS` | Disable TLS encryption | false |
| `INTROSPECTOR_TLS_EXTRA_IPS` | Additional IPs for TLS cert | [] |
| `INTROSPECTOR_TLS_EXTRA_DOMAINS` | Additional domains for TLS cert | [] |
| `INTROSPECTOR_LOG_LEVEL` | Log level (0-6) | 4 (Debug) |
| `INTROSPECTOR_ARKD_URL` | URL of the `arkd` instance used for attempted finalization in [`SubmitTx`](#submittx) | Required |

## Development

### Prerequisites

- Go 1.25+
- Docker and Docker Compose
- Buf CLI (for protocol buffer generation)
- [Nigiri](https://nigiri.vulpem.com) (for integration testing)

### Building

```bash
# Generate protocol buffer stubs
make proto

# Build the application
make build
```

### Running

```bash
# Run with development configuration
make run
```

### Testing

```bash
# Run unit tests
make test

# Run docker regtest environment
nigiri start
make docker-run

# Run integration tests
make integrationtest
```

### Enclave integration test

Boots the introspector EIF inside a QEMU-emulated Nitro Enclave with mock AWS
services + mock-arkd, then runs the 6-test driver
(`enclave/test/integration-test.sh`: health, HTTP/2 ALPN, native gRPC `GetInfo`
with attestation, wrong-PCR0 reject, `SubmitTx` with a real PSBT, HTTP/1.1
compat). Requires the `enclave` CLI from
[introspector-enclave](https://github.com/ArkLabsHQ/introspector-enclave) on
`$PATH`, plus Docker.

```bash
enclave test build       # auto-picks enclave/enclave_test.yaml
enclave test init        # writes enclave/test/docker-compose.yml
```

Append the mock-arkd block once, below the
`# === user services below this line ===` marker (4-space indent matters):

```yaml
    mock-arkd:
        build:
            context: ../../
            dockerfile: enclave/test/mock-arkd/Dockerfile
        network_mode: host
        environment:
            MOCK_ARKD_ADDR: ":8081"
        healthcheck:
            test: ["CMD-SHELL", "/usr/local/bin/grpcurl -plaintext -max-time 2 localhost:8081 list"]
            interval: 5s
            timeout: 3s
            retries: 5
```

```bash
enclave test start                    # boots the stack, waits for /health 200
./enclave/test/integration-test.sh    # runs the 6-test driver
enclave test down                     # tear down + remove volumes
```

## Supported Opcodes

The following opcodes are supported by the Arkade script engine. They extend Bitcoin Script with additional introspection, data manipulation, and cryptographic operations.

### Transaction Introspection (Inputs)

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTINPUTOUTPOINT | 199 | 0xc7 | index | txid index | Pushes the transaction ID (32 bytes) and output index (scriptNum) of the input at the given index onto the stack. |
| OP_INSPECTINPUTARKADESCRIPTHASH | 200 | 0xc8 | index | script_hash | Pushes the 32-byte Arkade script hash (`tagged_hash("ArkScriptHash", script)`) of the IntrospectorEntry for the input at the given index. This is the same hash used as the tweak scalar in `ComputeArkadeScriptPublicKey`. Fails if no entry exists. |
| OP_INSPECTINPUTVALUE | 201 | 0xc9 | index | value | Pushes the value (8 bytes, little-endian) of the previous output spent by the input at the given index. |
| OP_INSPECTINPUTSCRIPTPUBKEY | 202 | 0xca | index | program version | For witness programs: pushes the witness program (2-40 bytes) and segwit version (scriptNum). For non-native segwit: pushes SHA256 hash of scriptPubKey and -1. |
| OP_INSPECTINPUTSEQUENCE | 203 | 0xcb | index | sequence | Pushes the sequence number (4 bytes, little-endian) of the input at the given index. |
| OP_PUSHCURRENTINPUTINDEX | 205 | 0xcd | Nothing | index | Pushes the current input index (scriptNum) being evaluated onto the stack. |
| OP_INSPECTINPUTARKADEWITNESSHASH | 206 | 0xce | index | witness_hash | Pushes the 32-byte Arkade witness hash (`tagged_hash("ArkWitnessHash", witness)`) of the IntrospectorEntry for the input at the given index. Pushes 32 zero bytes if witness is empty. Fails if no entry exists. |

### Transaction Introspection (Outputs)

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTOUTPUTVALUE | 207 | 0xcf | index | value | Pushes the value (8 bytes, little-endian) of the output at the given index. |
| OP_INSPECTOUTPUTSCRIPTPUBKEY | 209 | 0xd1 | index | program version | For witness programs: pushes the witness program (2-40 bytes) and segwit version (scriptNum). For non-native segwit: pushes SHA256 hash of scriptPubKey and -1. |

### Transaction Introspection (Transaction)

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTVERSION | 210 | 0xd2 | Nothing | version | Pushes the transaction version (4 bytes, little-endian) onto the stack. |
| OP_INSPECTLOCKTIME | 211 | 0xd3 | Nothing | locktime | Pushes the transaction locktime (4 bytes, little-endian) onto the stack. |
| OP_INSPECTNUMINPUTS | 212 | 0xd4 | Nothing | numInputs | Pushes the number of inputs in the transaction (scriptNum) onto the stack. |
| OP_INSPECTNUMOUTPUTS | 213 | 0xd5 | Nothing | numOutputs | Pushes the number of outputs in the transaction (scriptNum) onto the stack. |
| OP_TXWEIGHT | 214 | 0xd6 | Nothing | weight | Pushes the transaction weight (4 bytes, little-endian) onto the stack. Weight is calculated as `SerializeSizeStripped() * 4`. |
| OP_TXID | 243 | 0xf3 | Nothing | txid | Pushes the current transaction hash (32 bytes) onto the stack. |

### Packet Introspection

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTPACKET | 244 | 0xf4 | packet_type | content 1 (or `<empty>` 0) | Looks up the packet with the given type in the current transaction's extension. On hit: pushes the raw packet content and 1. Not found: pushes an empty byte array and 0. |
| OP_INSPECTINPUTPACKET | 245 | 0xf5 | packet_type input_index | content 1 (or `<empty>` 0) | Looks up the packet with the given type in the ark extension of the previous ark transaction spent by the input at `input_index`. On hit: pushes the raw packet content and 1. Not found: pushes an empty byte array and 0. Fails on negative / out-of-range `input_index`. |

### Data Manipulation

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_CAT | 126 | 0x7e | x1 x2 | x1\|x2 | Concatenates two byte arrays. |
| OP_SUBSTR | 127 | 0x7f | x n size | x[n:n+size] | Returns a substring of byte array x starting at position n with length size. |
| OP_LEFT | 128 | 0x80 | x n | x[:n] | Returns the first n bytes of byte array x. |
| OP_RIGHT | 129 | 0x81 | x n | x[len(x)-n:] | Returns the last n bytes of byte array x. |

### Bitwise Logic

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INVERT | 131 | 0x83 | x | ~x | Flips all bits in the input (bitwise NOT). |
| OP_AND | 132 | 0x84 | x1 x2 | x1&x2 | Boolean AND between each bit in the inputs. Operands must be the same length. |
| OP_OR | 133 | 0x85 | x1 x2 | x1\|x2 | Boolean OR between each bit in the inputs. Operands must be the same length. |
| OP_XOR | 134 | 0x86 | x1 x2 | x1^x2 | Boolean exclusive OR between each bit in the inputs. Operands must be the same length. |

### Arithmetic

Arithmetic operands and results use the VM's minimally encoded BigNum format
and can be up to the maximum script element size. `OP_NUM2BIN` and
`OP_BIN2NUM` bridge between BigNum values and fixed-width byte strings.

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_2MUL | 141 | 0x8d | x | x*2 | Multiplies the input by 2. |
| OP_2DIV | 142 | 0x8e | x | x/2 | Divides the input by 2. |
| OP_MUL | 149 | 0x95 | a b | a*b | Multiplies two numbers. |
| OP_DIV | 150 | 0x96 | a b | a/b | Divides a by b. Fails if b is zero. |
| OP_MOD | 151 | 0x97 | a b | a%b | Returns the remainder after dividing a by b. Fails if b is zero. |
| OP_LSHIFT | 152 | 0x98 | x n | x<<n | Logical left shift by n bits. Sign data is discarded. |
| OP_RSHIFT | 153 | 0x99 | x n | x>>n | Logical right shift by n bits. Sign data is discarded. |
| OP_NUM2BIN | 215 | 0xd7 | num size | bytes | Pads a BigNum to exactly size bytes. Fails if the number does not fit or size is negative or greater than the maximum script element size. |
| OP_BIN2NUM | 216 | 0xd8 | bytes | num | Normalizes a byte string into a minimally encoded BigNum. |

### Cryptography

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_CHECKSIGFROMSTACK | 204 | 0xcc | sig pubkey message | True/false | Verifies a Schnorr signature. Pops signature (64 bytes), public key (32 bytes), and message from the stack. Returns 1 if valid, 0 otherwise. If signature is empty, pushes empty vector. |
| OP_MERKLEBRANCHVERIFY | 179 | 0xb3 | leaf_tag branch_tag proof leaf_data | computed_root | Computes a Merkle root using BIP-341 tagged hashes. If leaf_tag is empty, leaf_data (32 bytes) is used as a raw hash; otherwise computes `tagged_hash(leaf_tag, leaf_data)`. Walks the proof path with lexicographic sibling ordering. Pushes the 32-byte computed root. Use with `OP_EQUALVERIFY` to verify against an expected root. |

### Elliptic Curve Operations

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_ECMULSCALARVERIFY | 227 | 0xe3 | k P Q | Nothing/fail | Verifies that Q = k*P where k is a 32-byte scalar, P is a compressed public key, and Q is a compressed public key. Fails if verification fails. |
| OP_TWEAKVERIFY | 228 | 0xe4 | P k Q | Nothing/fail | Verifies that Q = P + k*G where P is a 32-byte X-only internal key, k is a 32-byte big-endian scalar, Q is a 33-byte compressed point, and G is the generator point. Fails if verification fails. |

### SHA256 Streaming Operations

These opcodes allow incremental SHA256 hashing by maintaining hash state on the stack.

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_SHA256INITIALIZE | 196 | 0xc4 | data | state | Initializes a SHA256 context with the given data and pushes the hash state onto the stack. |
| OP_SHA256UPDATE | 197 | 0xc5 | data state | newState | Updates a SHA256 context by adding data to the stream being hashed. Pushes the updated state. |
| OP_SHA256FINALIZE | 198 | 0xc6 | data state | hash | Finalizes a SHA256 hash by adding data and completing padding. Pushes the final 32-byte hash value. |

### Asset Introspection Opcodes

These opcodes provide access to the Arkade Asset V1 packet embedded in the transaction. Asset IDs are represented as two stack items: (txid32, gidx_u16).

#### Packet & Groups

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTNUMASSETGROUPS | 229 | 0xe5 | Nothing | K | Returns the number of asset groups in the packet. |
| OP_INSPECTASSETGROUPASSETID | 230 | 0xe6 | k | txid32 gidx_u16 | Returns the Asset ID of group k. Fresh groups use this transaction's ID. |
| OP_INSPECTASSETGROUPCTRL | 231 | 0xe7 | k | -1 or txid32 gidx_u16 | Returns the control Asset ID if present, else -1. |
| OP_FINDASSETGROUPBYASSETID | 232 | 0xe8 | txid32 gidx_u16 | -1 or k | Finds group index by Asset ID, or -1 if absent. |

#### Metadata

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTASSETGROUPMETADATAHASH | 233 | 0xe9 | k | hash32 | Returns the immutable metadata Merkle root (set at genesis). |

#### Per-Group I/O

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTASSETGROUPNUM | 234 | 0xea | k source_u8 | count_u16 or in_u16 out_u16 | Returns count of inputs/outputs. source: 0=inputs, 1=outputs, 2=both. |
| OP_INSPECTASSETGROUP | 235 | 0xeb | k j source_u8 | type_u8 [data...] amount | Returns j-th input/output of group k. source: 0=input, 1=output. Amounts are pushed as BigNums. |
| OP_INSPECTASSETGROUPSUM | 236 | 0xec | k source_u8 | sum or in_sum out_sum | Returns sum of amounts with overflow safety. source: 0=inputs, 1=outputs, 2=both. Amounts are pushed as BigNums. |

**OP_INSPECTASSETGROUP return values by type:**
- LOCAL input (0x01): `type_u8 input_index_u32 amount`
- INTENT input (0x02): `type_u8 txid_32 output_index_u32 amount`
- LOCAL output (0x01): `type_u8 output_index_u32 amount`

#### Cross-Output (Multi-Asset per UTXO)

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTOUTASSETCOUNT | 237 | 0xed | o | n | Returns number of asset entries assigned to output o. |
| OP_INSPECTOUTASSETAT | 238 | 0xee | o t | txid32 gidx_u16 amount | Returns t-th asset at output o. Amount is pushed as a BigNum. |
| OP_INSPECTOUTASSETLOOKUP | 239 | 0xef | o txid32 gidx_u16 | amount or -1 | Returns amount of asset at output o, or -1 if not found. Amount is pushed as a BigNum. |

#### Cross-Input (Packet-Declared)

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTINASSETCOUNT | 240 | 0xf0 | i | n | Returns number of assets declared for input i. |
| OP_INSPECTINASSETAT | 241 | 0xf1 | i t | txid32 gidx_u16 amount | Returns t-th asset declared for input i. Amount is pushed as a BigNum. |
| OP_INSPECTINASSETLOOKUP | 242 | 0xf2 | i txid32 gidx_u16 | amount or -1 | Returns declared amount for asset at input i, or -1 if not found. Amount is pushed as a BigNum. |
