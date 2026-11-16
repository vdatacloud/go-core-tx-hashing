# go-core-tx-hashing

Recompute the hash of a Canton **prepared transaction** in Go, under hashing
schemes V2 and V3, so that a signer signs a hash it computed from what it
read, never one it was handed.

This is a Go port of
[`@canton-network/core-tx-hashing`](https://github.com/canton-network/wallet/tree/main/core/tx-hashing)
(Apache-2.0). It gives the same hash, or refuses with the same error code, on
every one of that package's test vectors.

```go
import txhashing "github.com/vdatacloud/go-core-tx-hashing"

// resp: what /v2/interactive-submission/prepare returned
scheme, err := txhashing.ParseScheme(resp.HashingSchemeVersion)
if err != nil {
    return refuse(err)
}
claimed, _ := base64.StdEncoding.DecodeString(resp.PreparedTransactionHash)
tx, err := txhashing.Verify(resp.PreparedTransaction, scheme, claimed)
if err != nil {
    return refuse(err) // malformed, not fully hashed, or not the hash claimed
}
if err := tx.CheckActAs(myParties...); err != nil {
    return refuse(err)
}
for _, a := range tx.Actions() { // every node the hash covers, in hash order
    // your policy: templates, choices, arguments, amounts, counterparties
}
signature := kms.Sign(tx.Hash()) // the hash computed here
```

## Why institutions need this

Canton lets a party keep its signing key outside the participant node that
hosts it (an *external party*). To submit, an application asks a participant
to **prepare** a transaction, the party signs the transaction's hash, and the
participant **executes** it with that signature. The participant never holds
the key.

For a party whose signature carries real authority (a bank, a custodian, an
escrow agent, any regulated institution), that leaves a gap. If its signer is
handed a hash and signs it, the signer has approved something it never saw.
Whoever prepared the transaction decides what the hash commits to: an
application operator, a service provider, or a compromised host. That is
**blind signing by a middle party**, and it undoes the point of keeping the
key outside the node.

So an institution's signer needs to:

1. **Read what it signs.** It receives the whole prepared transaction, not just a hash.
2. **Compute the hash itself.** It recomputes the hash from the
   transaction, refuses one that differs from what it was told, and signs only
   its own result.
3. **Refuse what it can't vouch for.** It refuses anything the hash would not
   cover, or that it can't read: an unknown scheme, LF version, node version or
   protobuf field, a field the scheme doesn't hash, or a node outside the
   transaction's tree.
4. **Read exactly what the hash covers.** Its policy reads the same nodes, in
   the same tree, that the hash was computed over.
5. **Apply its own policy to the content.** That covers who the transaction acts as, on
   which synchronizer, which templates it creates and which choices it exercises, with
   what arguments.
6. **Run unattended in the institution's own environment,** with the key in
   its HSM or KMS. Routine acts can't wait for a person, and the key and
   the policy belong to the institution, not to the application's operator.

Upstream's package covers points 1 to 4 for wallets in TypeScript. This
module brings the same checks to Go, the language most signing services,
HSM integrations and back-office systems at institutions are written in,
and adds the small layer a policy engine needs for point 5 (`Verify`,
`CheckActAs`, `Actions`). It holds no key and makes no network calls.

## API

| | |
|---|---|
| `HashBase64(b64, scheme, opts...)` | The 32-byte hash of a prepared transaction in base64, as the JSON API returns it. |
| `Hash(bytes, scheme, opts...)` | The same from protobuf bytes. |
| `Decode(bytes, scheme, opts...)` | Decode, check and hash; returns the transaction (`*ledgerapi.PreparedTransaction`) with its `Hash()`. |
| `Verify(b64, scheme, claimedHash, opts...)` | `Decode`, and refuse (`HASH_MISMATCH`) a claimed hash that differs. |
| `(*Decoded).Actions()` | Every node the hash covers, depth first in hash order: kind, template (`package-name:Module:Entity`), interface, choice, consuming, byKey, acting parties, signatories, stakeholders, argument, and whether it sits under a rollback. |
| `(*Decoded).CheckActAs(parties...)` | Refuse a transaction submitted as any other party. |
| `ParseScheme(name)` | `HASHING_SCHEME_VERSION_V2` or `_V3`; anything else is `UNSUPPORTED_SCHEME`. |
| `WithLimits(Limits)` | Override `DefaultLimits` (10,000 nodes, node depth 100, value depth 101; value depth at most 256). |

Every refusal is an `*Error` with a `Code` and, where known, a `Path` into the
transaction, such as `transaction.nodes[2].v1.exercise.children[0]`. Use
`CodeOf(err)` to read the code, or `errors.Is(err, &txhashing.Error{Code: ...})`.

The codes are upstream's, with the same meaning:
- **Decoding:** `DECODE_FAILED`, `UNKNOWN_FIELD`.
- **Versions:** `UNSUPPORTED_SCHEME`, `UNSUPPORTED_NODE_VERSION`, `UNSUPPORTED_LF_VERSION`.
- **Missing or unhashed fields:** `FIELD_NOT_COVERED_BY_SCHEME`, `MISSING_FIELD`, `MISSING_NODE_SEED`, `DUPLICATE_NODE_SEED`.
- **Node structure:** `INVALID_NODE_ID`, `DUPLICATE_NODE_ID`, `DANGLING_NODE_REFERENCE`, `SHARED_CHILD`, `CYCLE`, `ORPHAN_NODE`.
- **Limits:** `NODE_LIMIT_EXCEEDED`, `DEPTH_LIMIT_EXCEEDED`.
- **Values:** `INVALID_HEX`, `INVALID_VALUE`.

Upstream's README describes each. `HASH_MISMATCH` comes from `Verify` and is
this module's own.

`metadata.globalKeyMapping` and `metadata.inputContracts[i].eventBlob` are
accepted, but no scheme hashes them. Don't present their content as signed.

## How the hash is derived

The prepared transaction is encoded deterministically; the protobuf bytes are
never hashed directly. This follows upstream's implementation, which follows
Canton's own hashing examples (`daml_transaction_hashing_v2.py` and `_v3.py`,
Canton v3.5.1, interactive submission).

- **Primitives:**
  - Integers are big-endian: int32 is 4 bytes, int64 is 8 bytes.
  - A boolean is one byte.
  - A string or byte string is an int32 length followed by its bytes, with strings as UTF-8.
  - A contract id is lower-case hex of even length, decoded to bytes and then length-prefixed.
  - A seed and a key hash are written raw, and must be 32 bytes.
- **Optionals and lists:**
  - An optional is `00` when absent, or `01` followed by the value.
  - A list is an int32 count followed by its elements.
- **Identifiers:** the package id, then the module name and the entity name, each split on `.` and encoded as a list of strings.
- **Values:** a tag byte, then the content:

  | Tag | Type |
  |---|---|
  | `00` | unit |
  | `01` | bool |
  | `02` | int64 |
  | `03` | numeric (as its string) |
  | `04` | timestamp (micros, within 0001 to 9999) |
  | `05` | date (days, same range) |
  | `06` | party |
  | `07` | text |
  | `08` | contract id |
  | `09` | optional |
  | `0a` | list |
  | `0b` | text map |
  | `0c` | record |
  | `0d` | variant |
  | `0e` | enum |
  | `0f` | generic map |

  Record, variant and enum type ids are optional. Every record field is `01` followed by its label, an empty label included.
- **Nodes:** each node is hashed as `SHA-256(head ‖ children)`, children first, which makes the transaction a Merkle tree.
  - **Head:** the node's fields in schema order, after its LF version and a kind tag. The tags are create `00`, exercise `01`, fetch `02`, rollback `03`, and query-by-key `04` (V3 only).
  - **Children:** for an exercise or a rollback, a list of the children's hashes.
  - **Seeds:** create and exercise nodes must have a seed; no other node may.
- **Transaction hash:** `SHA-256(purpose ‖ version ‖ roots)`. `purpose` is `00 00 00 30`, and `roots` is the list of the root nodes' hashes.
- **Metadata hash:** `SHA-256(purpose ‖ metadata)`. The metadata is `actAs`, `commandId`, `transactionUuid`, `mediatorGroup`, `synchronizerId`, the optional min and max ledger effective times, `preparationTime`, and the input contracts.
  - Each input contract is `createdAt ‖ SHA-256(its create node, without a seed)`.
- **Prepared transaction hash:** `SHA-256(purpose ‖ scheme version ‖ transactionHash ‖ metadataHash)`.

**V2 and V3 differ in five ways:**

| | V2 | V3 |
|---|---|---|
| Encoding version byte `01` before each node and the metadata | Yes | No |
| LF versions hashed | `2.1` only | `2.1`, and `2` (which contract keys need) |
| Contract keys and `byKey` | Refused (`FIELD_NOT_COVERED_BY_SCHEME`) | Hashed |
| Query-by-key nodes | Refused | Hashed |
| `maxRecordTime` | Refused | Hashed, at the end of the metadata |

## Protobuf definitions

`proto/` holds Canton v3.5.10's definitions of a prepared transaction:
`value.proto`, `interactive_submission_common_data.proto`,
`interactive_submission_data.proto`, and the prepared-transaction messages of
`interactive_submission_service.proto`. Apache-2.0.

- **Message and field numbers are Canton's,** so the wire format is
  identical.
- **Only the proto package differs** (`txhashing.ledgerapi`), so these types
  never clash with other Ledger API bindings linked into the same program.
- **Field 17 of an exercise node is left out,** as upstream leaves it out.
  That's `external_call_results`, LF dev only and hashed from scheme V4. A
  transaction carrying it is therefore refused as `UNKNOWN_FIELD`, as upstream
  refuses it.
- **Generated Go types** are in `ledgerapi/`. Regenerate them with
  `go generate ./...` (buf and protoc-gen-go, version-pinned).

## Testing and keeping up with upstream

- **`testdata/upstream/`** holds upstream's 128 vectors, copied from upstream
  at `UpstreamCommit` (`version.go`). `go test ./...` runs every one:

  | Folder | What the vectors are |
  |---|---|
  | `v2/`, `v3/` | Prepare responses captured from a Canton 3.5.10 participant, with the hash the participant returned |
  | `held-out/` | Captured after upstream's code was written |
  | `mutation/` | One hashed byte changed |
  | `reject/` | Input that must be refused, with its error code |

- **CI on every change:**
  - gofmt, `go vet`, and the tests with the race detector.
  - A minute of fuzzing, so that malformed input never panics.
  - A check that the generated code matches `proto/`.
  - Every vector against exactly `UpstreamVersion` of the TypeScript package.
  - A check that every message's field numbers equal upstream's
    (`TestFieldsMatchUpstream`).
- **Weekly:** CI runs upstream's newest vectors and newest release against
  this port. A vector this port fails fails the job, and a newer release
  raises a warning.

## Releases

Each release follows one upstream version, named in `version.go`
(`UpstreamVersion`):
- **Tags** carry upstream's major and minor version: `v1.2.x` ports
  `@canton-network/core-tx-hashing` 1.2. The patch number is this module's own.
- **CI refuses** a tag that doesn't carry the upstream major and minor version.
- **Release notes** name the upstream version and the Canton version of `proto/`.

## Status and contributing

This is pre-release and has not yet been independently audited. It is
intended for contribution to the Canton ecosystem, under the Canton
Foundation or alongside upstream, once it has been reviewed. Issues and
review are welcome. Please sign off your commits
([DCO](https://developercertificate.org/)).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
