# Emulator

[![test](https://github.com/arkade-os/emulator/actions/workflows/test.yaml/badge.svg)](https://github.com/arkade-os/emulator/actions/workflows/test.yaml)
[![quality](https://github.com/arkade-os/emulator/actions/workflows/quality.yaml/badge.svg)](https://github.com/arkade-os/emulator/actions/workflows/quality.yaml)
[![Trivy Security Scan](https://github.com/arkade-os/emulator/actions/workflows/trivy.yaml/badge.svg)](https://github.com/arkade-os/emulator/actions/workflows/trivy.yaml)

_Emulator is a signing service for the [Arkade](https://docs.arkadeos.com/) protocol, executing [Arkade Script](https://docs.arkadeos.com/experimental/arkade-script)._

This is achieved by signing any Arkade transaction (offchain or intent proof) expecting the signature of a [tweaked public key](pkg/arkade/tweak.go). The tweaked key is `emulator_key + hash(arkade_script)`, where the script hash is a [tagged hash](pkg/arkade/tweak.go) (`"ArkScriptHash"`). The Arkade script is revealed via an [Emulator Packet](pkg/arkade/emulator_packet.go) committed inside an ARK extension OP_RETURN output. An ARK extension is a TLV stream prefixed with magic bytes `ARK` (`0x41524b`); the Emulator Packet is one of its packet types (`0x01`), containing per-input entries with the script bytecode and optional witness arguments.

## ArkadeScript examples

- [`test/htlc_test.go`](test/htlc_test.go) — **Non-interactive HTLC.** A 2-of-2 (`arkd` + emulator-tweaked) VTXO with a claim path gated by HASH160(preimage) and a refund path gated by absolute timelock. Neither the receiver nor the sender ever signs — an arkade covenant enforcing destination + amount replaces both their signatures.
- [`test/delegate_test.go`](test/delegate_test.go) — **Non-interactive delegate.** A 2-of-2 (`arkd` + emulator-tweaked) VTXO refreshed through batch settlement by any solver, with a CSV exit leaf reserved for the user. The arkade covenant is a self-send (preserves the input's scriptPubKey + value on output 0) gated to intent-proof transactions (`OP_INSPECTVERSION` == 2) so it cannot be drained via off-chain self-send loops.

## API

### GetInfo

Returns service metadata including the signer's public key. The public key should be tweaked with the Arkade script hash before being used in a VTXO tapscript.

**Endpoint**: `GET /v1/info`

**Response**:
```json
{
  "version": "0.0.1",
  "signerPubkey": "compressed_current_public_key",
  "deprecatedSignerPubkeys": ["compressed_deprecated_public_key"]
}
```

### SubmitTx

Validates and signs the Arkade transaction inputs owned by this emulator, and signs their matching checkpoint transactions. Arkade scripts are executed only on the Arkade transaction, not on checkpoints.

If this emulator is the last required non-`arkd` signer for all owned inputs matched by the emulator packet, each checkpoint PSBT must already include any other required non-`arkd` signatures; otherwise the request fails. In that case, the emulator submits the signed transaction set to `arkd`, merges `arkd`'s checkpoint signatures, finalizes the transaction, and returns the finalized Arkade PSBT plus updated checkpoint PSBTs. Otherwise it returns only this emulator's added signatures without calling `arkd`.

**Endpoint**: `POST /v1/tx`

**Request**:
```json
{
  "arkTx": "base64_encoded_psbt",
  "checkpointTxs": ["base64_encoded_checkpoint_psbt1", "..."]
}
```

**Response**:
```json
{
  "signedArkTx": "base64_encoded_signed_psbt",
  "signedCheckpointTxs": ["base64_encoded_signed_checkpoint_psbt1", "..."]
}
```

`signedArkTx` may be either partially signed or finalized, depending on whether this emulator is the last required non-`arkd` signer for all owned inputs matched by the emulator packet.

### SubmitIntent

Signs an intent proof after validating the intent message and executing Arkade scripts on the proof transaction. Accepts any arkd intent message type (`register`, `delete`, `get-pending-tx`, `estimate-intent-fee`, `get-intent`, `get-data`), so contract VTXOs can authenticate every intent-based operation, not just registration.

**Endpoint**: `POST /v1/intent`

**Request**:
```json
{
  "intent": {
    "proof": "base64_encoded_psbt",
    "message": "base64_encoded_intent_message"
  }
}
```

**Response**:
```json
{
  "signedProof": "base64_encoded_signed_psbt"
}
```

### SubmitFinalization

Conditionally signs forfeit and/or boarding inputs during batch finalization. Only signs if the signer's signature is found in the intent proof. The connector tree is used to verify the forfeits are part of a real batch session.

**Endpoint**: `POST /v1/finalization`

**Request**:
```json
{
  "signedIntent": {
    "proof": "base64_encoded_signed_psbt",
    "message": "base64_encoded_intent_message"
  },
  "forfeits": ["base64_encoded_forfeit_psbt1", "..."],
  "connectorTree": [
    {
      "txid": "transaction_id",
      "tx": "base64_encoded_transaction",
      "children": {
        "0": "child_txid_1",
        "1": "child_txid_2"
      }
    }
  ],
  "commitmentTx": "base64_encoded_psbt"
}
```

**Response**:
```json
{
  "signedForfeits": ["base64_encoded_signed_forfeit_psbt1", "..."],
  "signedCommitmentTx": "base64_encoded_signed_psbt"
}
```

### SubmitOnchainTx

Validates and signs the inputs of a plain Bitcoin transaction whose tapscripts contain the emulator's tweaked key (e.g. a VTXO unrolled onchain). Each input may carry an optional `PrevoutTxField` PSBT unknown field (key `"prevouttx"`) holding the raw previous transaction, required only by arkade opcodes that introspect it.

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
  "signedTx": "base64_encoded_signed_psbt"
}
```

## Emulator Packet

The Emulator Packet is the data structure that reveals which inputs of a transaction must be checked by the emulator, the Arkade script bytecode to execute for each, and any witness arguments the script consumes. It lives inside an [ARK extension](https://github.com/arkade-os/arkd/tree/master/pkg/ark-lib/extension) — an OP_RETURN output whose payload starts with the magic prefix `ARK` (`0x41 0x52 0x4b`) followed by a sequence of `(type, length, value)` packets. The emulator packet has type byte `0x01` and shares the envelope with other ARK packets (e.g. the asset packet, type `0x00`); a single OP_RETURN can carry both, and helpers like [`addEmulatorPacket`](test/utils_test.go) merge the emulator packet into an existing extension when one is already present.

The packet content (the value side of the outer TLV) has the following layout — `varint` denotes a Bitcoin-style compact size integer:

| Field | Type | Notes |
|-------|------|-------|
| `entry_count` | varint | Number of entries. Must be `>= 1` and `<= 1000`. |
| `entry[0..entry_count]` | per-entry block (below) | Repeated `entry_count` times. |

Each entry block is:

| Field | Type | Notes |
|-------|------|-------|
| `vin` | u16 LE | Input index this entry applies to. Must be unique across the packet. |
| `script_len` | varint | Length of `script` in bytes. Must be `>= 1` and `<= 10_000`. |
| `script` | bytes | Arkade Script bytecode. |
| `witness_len` | varint | Length of the encoded `witness` blob in bytes. Must be `<= 1_000_000`. |
| `witness` | bytes | Witness blob (see below). May be empty (`witness_len = 0`). |

The `witness` blob is encoded with `psbt.WriteTxWitness` / `txutils.ReadTxWitness`, **not** raw Bitcoin wire-format witness. Concretely, the blob is `varint(num_items)` followed by `varint(item_len) + item_bytes` for each stack item.

The serialized packet is the value of an outer TLV record `(0x01, varint(content_len), content)` written into the ARK extension, which itself is wrapped in an OP_RETURN output. The encoder bypasses `txscript.ScriptBuilder`'s 520-byte data push cap so the OP_RETURN can hold the full extension regardless of size.

### Validation rules

`Validate()` enforces, and any non-Go decoder must enforce:

- `1 <= entry_count <= 1000`
- For every entry: `1 <= len(script) <= 10_000`, `len(witness_blob) <= 1_000_000`
- `vin` is unique across the packet (an entry per vin, never two)
- No trailing bytes after the last entry

### Consensus relevance

The Arkade opcodes `OP_INSPECTPACKET` (`0xf4`) and `OP_INSPECTINPUTPACKET` (`0xf5`) read the raw packet bytes for a given type from the current transaction or a previous Arkade transaction's extension. Any Arkade script that uses these opcodes is sensitive to the exact serialized form of the packet — i.e. the wire format above is part of the consensus surface for those scripts, and changes to it must be treated as a protocol change.

## Configuration

The service can be configured using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `EMULATOR_SECRET_KEY` | Private key for signing (hex encoded) | Required |
| `EMULATOR_DEPRECATED_KEYS` | Comma-separated deprecated private keys (hex encoded) still accepted for signing. Empty means none. CSV is strict: leading commas, trailing commas, empty entries, whitespace, duplicates, and the current key are rejected. | Empty |
| `EMULATOR_DATADIR` | Data directory path | OS-specific app data dir |
| `EMULATOR_PORT` | Server port (gRPC + HTTP REST gateway) | 7073 |
| `EMULATOR_NO_TLS` | Disable TLS encryption | false |
| `EMULATOR_TLS_EXTRA_IPS` | Additional IPs for TLS cert | [] |
| `EMULATOR_TLS_EXTRA_DOMAINS` | Additional domains for TLS cert | [] |
| `EMULATOR_LOG_LEVEL` | Log level (0-6) | 4 (Debug) |
| `EMULATOR_ARKD_URL` | URL of the `arkd` instance used for attempted finalization in [`SubmitTx`](#submittx) | Required |
| `EMULATOR_COMPUTE_LIMITS` | Comma-separated `OPCODE=limit` overrides for per-input opcode execution caps, for example `OP_ECPAIRING=8,OP_MODEXP=128`. Overrides are applied on top of defaults; use an empty value such as `OP_ECADD=` to remove a default cap. | Default compute limits |

## Development

### Prerequisites

- Go 1.26+
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

## Supported Opcodes

The following opcodes are supported by the Arkade script engine. They extend Bitcoin Script with additional introspection, data manipulation, and cryptographic operations.

### Sighash (non-standard)

The arkade VM's `OP_CHECKSIG`, `OP_CHECKSIGVERIFY`, `OP_CHECKSIGADD`, and `OP_SIGHASH` operate on a **non-standard tapscript signature hash**, not BIP342. Two deliberate departures from BIP342:

1. **Witness blobs are masked out of `sha_outputs`.** When `sha_outputs` (or the per-output digest used by `SIGHASH_SINGLE`) is computed, every entry of every Emulator Packet is rewritten with `witness_len = 0` and the witness bytes dropped. Script bytes, `vin`, entry count, co-located ARK packets (e.g. the asset packet), and every non-extension output continue to flow into the digest unchanged. This lets a script be signed before any party has supplied runtime witness arguments, and lets witness arguments be re-supplied per spend attempt without invalidating signatures.
2. **The final BIP-340 tag is `"ArkadeTapSighash"`**, not BIP342's `"TapSighash"`. The two digest domains are therefore disjoint: a signature valid under one CANNOT pass verification under the other, even when the underlying message bytes happen to match.

The Bitcoin-level signatures that the emulator itself produces on PSBT `TaprootScriptSpendSig` entries are unaffected — those remain standard BIP342, computed via `txscript.CalcTapscriptSignaturehash` with the `"TapSighash"` tag. Only signatures verified *inside* the arkade VM use the non-standard digest.
### Transaction Introspection (Inputs)

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTINPUTOUTPOINT | 199 | 0xc7 | index | txid index | Pushes the transaction ID (32 bytes) and output index (scriptNum) of the input at the given index onto the stack. |
| OP_INSPECTINPUTARKADESCRIPTHASH | 200 | 0xc8 | index | script_hash | Pushes the 32-byte Arkade script hash (`tagged_hash("ArkScriptHash", script)`) of the EmulatorEntry for the input at the given index. This is the same hash used as the tweak scalar in `ComputeArkadeScriptPublicKey`. Fails if no entry exists. |
| OP_INSPECTINPUTVALUE | 201 | 0xc9 | index | value | Pushes the satoshi value of the previous output spent by the input at the given index, as a minimally-encoded BigNum. |
| OP_INSPECTINPUTSCRIPTPUBKEY | 202 | 0xca | index | program version | For witness programs: pushes the witness program (2-40 bytes) and segwit version (scriptNum). For non-native segwit: pushes SHA256 hash of scriptPubKey and -1. |
| OP_INSPECTINPUTSEQUENCE | 203 | 0xcb | index | sequence | Pushes the sequence number (4 bytes, little-endian) of the input at the given index. |
| OP_PUSHCURRENTINPUTINDEX | 205 | 0xcd | Nothing | index | Pushes the current input index (scriptNum) being evaluated onto the stack. |
| OP_INSPECTINPUTARKADEWITNESSHASH | 206 | 0xce | index | witness_hash | Pushes the 32-byte Arkade witness hash (`tagged_hash("ArkWitnessHash", witness)`) of the EmulatorEntry for the input at the given index. Pushes 32 zero bytes if witness is empty. Fails if no entry exists. |

### Transaction Introspection (Outputs)

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTOUTPUTVALUE | 207 | 0xcf | index | value | Pushes the satoshi value of the output at the given index, as a minimally-encoded BigNum. |
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
| OP_SIGHASH | 246 | 0xf6 | hashType | sighash | Pops a sighash flag and pushes the 32-byte [arkade tapscript signature hash](#sighash-non-standard) of the currently executing input under that flag. The pushed digest is identical to the message `OP_CHECKSIG` verifies a Schnorr signature against in the same context, but it is **not** the BIP342 digest — see the Sighash section above. The flag must be a minimally encoded scriptNum in `[0,255]` and one of `{0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83}`; `SIGHASH_SINGLE` additionally requires a matching output at the input's index. |

### Packet Introspection

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTPACKET | 244 | 0xf4 | packet_type | content 1 (or `<empty>` 0) | Looks up the packet with the given type in the current transaction's extension. On hit: pushes the raw packet content and 1. Not found: pushes an empty byte array and 0. |
| OP_INSPECTINPUTPACKET | 245 | 0xf5 | packet_type input_index | content 1 (or `<empty>` 0) | Looks up the packet with the given type in the ARK extension of the previous Arkade transaction spent by the input at `input_index`. On hit: pushes the raw packet content and 1. Not found: pushes an empty byte array and 0. Fails on negative / out-of-range `input_index`. |

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
| OP_MODEXP | 218 | 0xda | base exp modulus | result | Pushes `base^exp mod modulus` in the canonical range `[0, modulus)`. Each operand is capped at 64 bytes. Fails if `modulus <= 0`, `exp < 0`, or any operand exceeds 64 bytes. For modular inverse over a prime `p`, pass `exp = p-2` (Fermat's little theorem). |

### Cryptography

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_CHECKSIGFROMSTACK | 204 | 0xcc | sig pubkey message | True/false | Verifies a Schnorr signature. Pops signature (64 bytes), public key (32 bytes), and message from the stack. Returns 1 if valid, 0 otherwise. If signature is empty, pushes empty vector. |
| OP_MERKLEBRANCHVERIFY | 179 | 0xb3 | leaf_tag branch_tag proof leaf_data | computed_root | Computes a Merkle root using BIP-341 tagged hashes. If leaf_tag is empty, leaf_data (32 bytes) is used as a raw hash; otherwise computes `tagged_hash(leaf_tag, leaf_data)`. Walks the proof path with lexicographic sibling ordering. Pushes the 32-byte computed root. Use with `OP_EQUALVERIFY` to verify against an expected root. |

### Elliptic Curve Operations

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_ECADD | 224 | 0xe0 | x1 y1 x2 y2 curve_id | x3 y3 | Adds two affine points on the selected curve. Coordinates are Arkade BigNums; `(0, 0)` represents the point at infinity. Fails on unsupported `curve_id`, non-minimal BigNums, negative or out-of-field coordinates, and off-curve points. |
| OP_ECMUL | 225 | 0xe1 | x y k curve_id | x2 y2 | Multiplies an affine point by a scalar on the selected curve. `k = 0` returns the point at infinity. Fails on scalars `>=` the group order, off-curve points, and the other validation cases listed for OP_ECADD. |
| OP_ECPAIRING | 226 | 0xe2 | [g1_x g1_y g2_x_c1 g2_x_c0 g2_y_c1 g2_y_c0]... pair_count curve_id | bool | Checks whether the product of pairings is the identity in GT. Pushes canonical true (`0x01`) on success, canonical false (empty) on a valid non-identity product. `pair_count = 0` returns true. Pairing only works for `alt_bn128`; any other curve fails execution. Fails on non-minimal BigNums, negative or out-of-field coordinates, off-curve G1, off-curve G2, G2 outside the `alt_bn128` r-subgroup, negative `pair_count`, and `pair_count > 16`. |
| OP_ECMULSCALARVERIFY | 227 | 0xe3 | k P Q | Nothing/fail | Verifies that Q = k*P on secp256k1 where k is a 32-byte scalar, P is a compressed public key, and Q is a compressed public key. Fails if verification fails. |
| OP_TWEAKVERIFY | 228 | 0xe4 | P k Q | Nothing/fail | Verifies that Q = P + k*G where P is a 32-byte X-only internal key, k is a 32-byte big-endian scalar, Q is a 33-byte compressed point, and G is the generator point. Fails if verification fails. |

#### Curve IDs

| Curve ID | Curve | Operations |
|----------|-------|------------|
| 0 | `secp256k1` | addition, scalar multiplication |
| 1 | `secp256r1` (NIST P-256) | addition, scalar multiplication |
| 2 | `alt_bn128` / BN254 | addition, scalar multiplication, pairing |


### SHA256 Streaming Operations

These opcodes allow incremental SHA256 hashing by maintaining hash state on the stack.

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_SHA256INITIALIZE | 196 | 0xc4 | data | state | Initializes a SHA256 context with the given data and pushes the hash state onto the stack. |
| OP_SHA256UPDATE | 197 | 0xc5 | data state | newState | Updates a SHA256 context by adding data to the stream being hashed. Pushes the updated state. |
| OP_SHA256FINALIZE | 198 | 0xc6 | data state | hash | Finalizes a SHA256 hash by adding data and completing padding. Pushes the final 32-byte hash value. |

### Asset Introspection Opcodes

These opcodes provide access to the Arkade Asset V1 packet embedded in the transaction.

An **Asset ID** is the canonical, position-independent identity of an asset. It is represented as two consecutive stack items, `asset_txid asset_gidx`, where `asset_txid` (32 bytes) is the asset's issuance transaction ID and `asset_gidx` is the group index at which the asset was issued (a minimally encoded ScriptNum in `0..65535`). For a fresh issuance the Asset ID is `(this transaction's ID, k)`, where `k` is the group's position in this packet.

`k` is reserved throughout for a **current packet group position** — the index of a group in this transaction's packet. It is distinct from `asset_gidx`: the two coincide only for fresh issuances. Use `OP_FINDASSETGROUPBYASSETID` to convert a canonical Asset ID into the `k` consumed by the structural per-group opcodes.

An intent input's source transaction ID is **not** an Asset ID; it is available through `OP_INSPECTASSETGROUP` and is never emitted or matched by the canonical opcodes.

#### Packet & Groups

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTNUMASSETGROUPS | 229 | 0xe5 | Nothing | K | Returns the number of asset groups in the packet. |
| OP_INSPECTASSETGROUPASSETID | 230 | 0xe6 | k | asset_txid asset_gidx | Returns the canonical Asset ID of packet group k. Fresh groups use this transaction's ID and k. |
| OP_INSPECTASSETGROUPCTRL | 231 | 0xe7 | k | control_asset_txid control_asset_gidx 1, or empty_bytes 0 0 | Returns the canonical Asset ID of the control asset and a success flag, or `empty_bytes 0 0` when absent. References stored by packet group index are resolved to their canonical Asset ID. |
| OP_FINDASSETGROUPBYASSETID | 232 | 0xe8 | asset_txid asset_gidx | k 1, or 0 0 | Converts a canonical Asset ID to its current packet group position k with a success flag, or `0 0` when the Asset ID is not in the packet. |

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
| OP_INSPECTOUTASSETAT | 238 | 0xee | o t | asset_txid asset_gidx amount | Returns the canonical Asset ID and amount of the t-th asset entry at output o. `asset_gidx` is the issuance group index, directly consumable by OP_INSPECTOUTASSETLOOKUP. Amount is pushed as a BigNum. |
| OP_INSPECTOUTASSETLOOKUP | 239 | 0xef | o asset_txid asset_gidx | amount 1, or 0 0 | Returns the amount of the asset with the given canonical Asset ID at output o and a success flag, or `0 0` when absent. Amount is pushed as a BigNum. |

#### Cross-Input (Packet-Declared)

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTINASSETCOUNT | 240 | 0xf0 | i | n | Returns number of assets declared for input i. |
| OP_INSPECTINASSETAT | 241 | 0xf1 | i t | asset_txid asset_gidx amount | Returns the canonical Asset ID and amount of the t-th asset entry declared for input i. `asset_txid` is always the issuance transaction ID, never an intent input's source txid. Amount is pushed as a BigNum. |
| OP_INSPECTINASSETLOOKUP | 242 | 0xf2 | i asset_txid asset_gidx | amount 1, or 0 0 | Returns the declared amount for the asset with the given canonical Asset ID at input i and a success flag, or `0 0` when absent. An intent input's source txid is never accepted as the Asset ID. Amount is pushed as a BigNum. |
