// Copyright 2026 vDataCloud and the go-core-tx-hashing authors.
// SPDX-License-Identifier: Apache-2.0
//
// Ported from @canton-network/core-tx-hashing (hash.ts, decode.ts,
// limits.ts), Copyright (c) 2025-2026 Digital Asset (Switzerland) GmbH and/or
// its affiliates, Apache-2.0; see NOTICE.

// Package txhashing recomputes the hash of a Canton prepared transaction
// under hashing schemes V2 and V3, so that a signer can check the hash rather
// than trust it. It is a Go port of @canton-network/core-tx-hashing and
// gives the same hash, or refuses with the same code, on every one of that
// package's test vectors.
package txhashing

import (
	"github.com/vdatacloud/go-core-tx-hashing/ledgerapi"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Scheme is a hashing scheme, as the participant names it in a prepare
// response (hashingSchemeVersion).
type Scheme int32

const (
	SchemeV2 = Scheme(ledgerapi.HashingSchemeVersion_HASHING_SCHEME_VERSION_V2)
	SchemeV3 = Scheme(ledgerapi.HashingSchemeVersion_HASHING_SCHEME_VERSION_V3)
)

// ParseScheme reads the JSON API name, HASHING_SCHEME_VERSION_V2 or
// HASHING_SCHEME_VERSION_V3; anything else is UNSUPPORTED_SCHEME.
func ParseScheme(name string) (Scheme, error) {
	switch name {
	case "HASHING_SCHEME_VERSION_V2":
		return SchemeV2, nil
	case "HASHING_SCHEME_VERSION_V3":
		return SchemeV3, nil
	}
	return 0, refuse(UnsupportedScheme, "", "hashing scheme %q is not supported: expected HASHING_SCHEME_VERSION_V2 or HASHING_SCHEME_VERSION_V3", name)
}

func (s Scheme) impl() (scheme, error) {
	switch s {
	case SchemeV2:
		return schemeV2{}, nil
	case SchemeV3:
		return schemeV3{}, nil
	}
	return nil, refuse(UnsupportedScheme, "", "hashing scheme %d is not supported: expected V2 or V3", int32(s))
}

// Limits bound the decoded transaction; they don't bound decoding itself,
// so cap the size of the prepare response.
type Limits struct {
	MaxNodes      int // nodes in the transaction
	MaxNodeDepth  int // levels of nodes, a root at level 1
	MaxValueDepth int // levels of a value, the outermost at level 1; at most 256
}

// DefaultLimits are those of @canton-network/core-tx-hashing.
var DefaultLimits = Limits{MaxNodes: 10_000, MaxNodeDepth: 100, MaxValueDepth: 101}

// maxValueDepth is the upper bound for Limits.MaxValueDepth: values are
// encoded recursively.
const maxValueDepth = 256

// Option adjusts a hash computation.
type Option func(*Limits)

// WithLimits overrides DefaultLimits; a zero field keeps its default.
func WithLimits(l Limits) Option {
	return func(d *Limits) {
		if l.MaxNodes != 0 {
			d.MaxNodes = l.MaxNodes
		}
		if l.MaxNodeDepth != 0 {
			d.MaxNodeDepth = l.MaxNodeDepth
		}
		if l.MaxValueDepth != 0 {
			d.MaxValueDepth = l.MaxValueDepth
		}
	}
}

func limitsOf(opts []Option) (Limits, error) {
	l := DefaultLimits
	for _, o := range opts {
		o(&l)
	}
	for name, v := range map[string]int{"maxNodes": l.MaxNodes, "maxNodeDepth": l.MaxNodeDepth, "maxValueDepth": l.MaxValueDepth} {
		if v < 1 {
			return l, refuse(InvalidValue, "options.limits."+name, "options.limits.%s must be an integer of at least 1", name)
		}
	}
	if l.MaxValueDepth > maxValueDepth {
		return l, refuse(InvalidValue, "options.limits.maxValueDepth", "options.limits.maxValueDepth must be at most %d", maxValueDepth)
	}
	return l, nil
}

// HashBase64 recomputes the participant's hash of a prepared transaction
// given in base64, as the JSON API returns it. It returns the 32-byte
// SHA-256 hash, or an *Error.
func HashBase64(preparedTransaction string, s Scheme, opts ...Option) ([]byte, error) {
	if _, err := s.impl(); err != nil {
		return nil, err
	}
	if _, err := limitsOf(opts); err != nil {
		return nil, err
	}
	raw, err := decodeBase64(preparedTransaction)
	if err != nil {
		return nil, err
	}
	return Hash(raw, s, opts...)
}

// Hash recomputes the participant's hash of a prepared transaction given as
// protobuf bytes.
func Hash(preparedTransaction []byte, s Scheme, opts ...Option) ([]byte, error) {
	tx, err := Decode(preparedTransaction, s, opts...)
	if err != nil {
		return nil, err
	}
	return tx.hash, nil
}

// Decoded is a prepared transaction this package decoded, checked and hashed:
// what its hash covers is exactly what Transaction holds, except
// metadata.globalKeyMapping and metadata.inputContracts[i].eventBlob, which
// no scheme hashes; don't show their content as signed.
type Decoded struct {
	Transaction *ledgerapi.PreparedTransaction
	hash        []byte
	forest      *forest
}

// Hash is the transaction's hash, as this package computed it.
func (d *Decoded) Hash() []byte { return append([]byte(nil), d.hash...) }

// Decode decodes, checks and hashes a prepared transaction given as protobuf
// bytes.
func Decode(preparedTransaction []byte, s Scheme, opts ...Option) (*Decoded, error) {
	impl, err := s.impl()
	if err != nil {
		return nil, err
	}
	limits, err := limitsOf(opts)
	if err != nil {
		return nil, err
	}
	prepared, err := readPreparedTransaction(preparedTransaction)
	if err != nil {
		return nil, err
	}
	tx := prepared.GetTransaction()
	if tx == nil {
		return nil, refuse(MissingField, "transaction", "prepared transaction has no transaction")
	}
	if len(tx.GetRoots()) == 0 {
		return nil, refuse(MissingField, "transaction.roots", "transaction has no roots")
	}
	f, err := checkForest(tx, limits)
	if err != nil {
		return nil, err
	}
	h, err := hashPrepared(tx, prepared.GetMetadata(), f, impl, limits.MaxValueDepth)
	if err != nil {
		return nil, err
	}
	return &Decoded{Transaction: prepared, hash: h, forest: f}, nil
}

// readPreparedTransaction decodes the input, refusing unknown fields: the
// hash would not cover them.
func readPreparedTransaction(raw []byte) (*ledgerapi.PreparedTransaction, error) {
	if len(raw) == 0 {
		return nil, refuse(DecodeFailed, "", "input is empty")
	}
	tx := &ledgerapi.PreparedTransaction{}
	if err := proto.Unmarshal(raw, tx); err != nil {
		return nil, refuse(DecodeFailed, "", "input cannot be decoded as a protobuf PreparedTransaction: %v", err)
	}
	if name, num, ok := firstUnknownField(tx.ProtoReflect()); ok {
		return nil, refuse(UnknownField, "", "unknown field %d in %s: the hash would not cover it", num, name)
	}
	return tx, nil
}

// firstUnknownField finds a message in m holding a field number its
// definition doesn't have.
func firstUnknownField(m protoreflect.Message) (protoreflect.FullName, protoreflect.FieldNumber, bool) {
	if u := m.GetUnknown(); len(u) > 0 {
		num, _, _ := protowire.ConsumeTag(u)
		return m.Descriptor().FullName(), num, true
	}
	var (
		name  protoreflect.FullName
		num   protoreflect.FieldNumber
		found bool
	)
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Message() == nil {
			return true
		}
		check := func(child protoreflect.Message) bool {
			name, num, found = firstUnknownField(child)
			return !found
		}
		switch {
		case fd.IsList():
			for i := 0; i < v.List().Len(); i++ {
				if !check(v.List().Get(i).Message()) {
					return false
				}
			}
		case fd.IsMap():
			v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
				if fd.MapValue().Message() == nil {
					return true
				}
				return check(mv.Message())
			})
			return !found
		default:
			return check(v.Message())
		}
		return true
	})
	return name, num, found
}
