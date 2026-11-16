// Copyright 2026 vDataCloud and the go-core-tx-hashing authors.
// SPDX-License-Identifier: Apache-2.0
//
// Ported from @canton-network/core-tx-hashing (Copyright (c) 2025-2026 Digital
// Asset (Switzerland) GmbH and/or its affiliates, Apache-2.0); see NOTICE.

package txhashing

import "fmt"

// Code names why a transaction, a scheme or an option is refused. The codes
// and their meaning are those of @canton-network/core-tx-hashing.
type Code string

const (
	DecodeFailed            Code = "DECODE_FAILED"
	UnknownField            Code = "UNKNOWN_FIELD"
	UnsupportedScheme       Code = "UNSUPPORTED_SCHEME"
	UnsupportedNodeVersion  Code = "UNSUPPORTED_NODE_VERSION"
	UnsupportedLFVersion    Code = "UNSUPPORTED_LF_VERSION"
	FieldNotCoveredByScheme Code = "FIELD_NOT_COVERED_BY_SCHEME"
	MissingField            Code = "MISSING_FIELD"
	MissingNodeSeed         Code = "MISSING_NODE_SEED"
	DuplicateNodeSeed       Code = "DUPLICATE_NODE_SEED"
	InvalidNodeID           Code = "INVALID_NODE_ID"
	DuplicateNodeID         Code = "DUPLICATE_NODE_ID"
	DanglingNodeReference   Code = "DANGLING_NODE_REFERENCE"
	SharedChild             Code = "SHARED_CHILD"
	Cycle                   Code = "CYCLE"
	OrphanNode              Code = "ORPHAN_NODE"
	NodeLimitExceeded       Code = "NODE_LIMIT_EXCEEDED"
	DepthLimitExceeded      Code = "DEPTH_LIMIT_EXCEEDED"
	InvalidHex              Code = "INVALID_HEX"
	InvalidValue            Code = "INVALID_VALUE"
	HashMismatch            Code = "HASH_MISMATCH" // Verify only: not in the upstream package
)

// Error is every refusal. Path, when known, points into the transaction, such
// as transaction.nodes[2].v1.exercise.children[0].
type Error struct {
	Code    Code
	Message string
	Path    string
}

func (e *Error) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("%s: %s (at %s)", e.Code, e.Message, e.Path)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Is matches another *Error by code: errors.Is(err, &txhashing.Error{Code: txhashing.UnknownField}).
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// CodeOf is err's code, or "" when err is not an *Error.
func CodeOf(err error) Code {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}

func refuse(code Code, path, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Path: path}
}
