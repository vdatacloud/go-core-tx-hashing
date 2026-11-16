// Copyright 2026 vDataCloud and the go-core-tx-hashing authors.
// SPDX-License-Identifier: Apache-2.0
//
// Ported from @canton-network/core-tx-hashing (bytes.ts, encoding.ts),
// Copyright (c) 2025-2026 Digital Asset (Switzerland) GmbH and/or its
// affiliates, Apache-2.0; see NOTICE.

package txhashing

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	"github.com/vdatacloud/go-core-tx-hashing/ledgerapi"
)

// Mirrors daml_transaction_hashing_common.py (canton v3.5.1, 08-interactive-submission).

const (
	// 0001-01-01T00:00:00Z and 9999-12-31T23:59:59.999999Z, in microseconds
	timestampMin = -62_135_596_800_000_000
	timestampMax = 253_402_300_799_999_999
	// 0001-01-01 and 9999-12-31, in days since 1970-01-01
	dateMin = -719_162
	dateMax = 2_932_896
)

func sha(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// buf accumulates an encoding.
type buf []byte

func (b *buf) byte(v byte)   { *b = append(*b, v) }
func (b *buf) raw(v []byte)  { *b = append(*b, v...) }
func (b *buf) bool(v bool)   { b.byte(boolByte(v)) }
func (b *buf) int64(v int64) { *b = binary.BigEndian.AppendUint64(*b, uint64(v)) }

func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}

// int32 refuses a value outside int32; path names it.
func (b *buf) int32(v int64, path string) error {
	if v < math.MinInt32 || v > math.MaxInt32 {
		return refuse(InvalidValue, path, "%d is not a valid int32", v)
	}
	*b = binary.BigEndian.AppendUint32(*b, uint32(int32(v)))
	return nil
}

func (b *buf) count(n int) { _ = b.int32(int64(n), "") }

func (b *buf) bytes(v []byte) { b.count(len(v)); b.raw(v) }
func (b *buf) str(s string)   { b.bytes([]byte(s)) }

func (b *buf) strs(ss []string) {
	b.count(len(ss))
	for _, s := range ss {
		b.str(s)
	}
}

// time encodes a metadata time: a uint64 field the participant fills with
// signed microseconds, read as int64 and refused outside Daml's range.
func (b *buf) time(v uint64, path string) error { return b.timestamp(int64(v), path) }

func (b *buf) timestamp(micros int64, path string) error {
	if micros < timestampMin || micros > timestampMax {
		return refuse(InvalidValue, path, "time %d is outside the range of a Daml timestamp, 0001-01-01T00:00:00Z to 9999-12-31T23:59:59.999999Z", micros)
	}
	b.int64(micros)
	return nil
}

func (b *buf) optTime(v *uint64, path string) error {
	if v == nil {
		b.byte(0)
		return nil
	}
	b.byte(1)
	return b.time(*v, path)
}

// hex encodes lower-case hex of even length as length-prefixed bytes.
func (b *buf) hex(s, path string) error {
	if len(s)%2 != 0 {
		return refuse(InvalidHex, path, "hex string has an odd number of characters")
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		hi, lo := nibble(s[2*i]), nibble(s[2*i+1])
		if hi < 0 || lo < 0 {
			return refuse(InvalidHex, path, "hex string has a character other than 0-9 and a-f near index %d", 2*i)
		}
		out[i] = byte(hi<<4 | lo)
	}
	b.bytes(out)
	return nil
}

func nibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return -1
}

func (b *buf) identifier(id *ledgerapi.Identifier, path string) error {
	if id == nil {
		return refuse(MissingField, path, "identifier is missing")
	}
	b.str(id.GetPackageId())
	b.strs(strings.Split(id.GetModuleName(), "."))
	b.strs(strings.Split(id.GetEntityName(), "."))
	return nil
}

func (b *buf) optIdentifier(id *ledgerapi.Identifier, path string) error {
	if id == nil {
		b.byte(0)
		return nil
	}
	b.byte(1)
	return b.identifier(id, path)
}

// value encodes v; depth is its nesting level, the outermost value being 1.
func (b *buf) value(v *ledgerapi.Value, maxDepth int, path string, depth int) error {
	if depth > maxDepth {
		return refuse(DepthLimitExceeded, path, "value is nested deeper than %d levels", maxDepth)
	}
	if v == nil {
		return refuse(MissingField, path, "value is missing")
	}
	inner := func(child *ledgerapi.Value, at string) error { return b.value(child, maxDepth, at, depth+1) }
	switch s := v.GetSum().(type) {
	case *ledgerapi.Value_Unit:
		b.byte(0x00)
	case *ledgerapi.Value_Bool:
		b.byte(0x01)
		b.bool(s.Bool)
	case *ledgerapi.Value_Int64:
		b.byte(0x02)
		b.int64(s.Int64)
	case *ledgerapi.Value_Numeric:
		b.byte(0x03)
		b.str(s.Numeric)
	case *ledgerapi.Value_Timestamp:
		b.byte(0x04)
		return b.timestamp(s.Timestamp, path+".timestamp")
	case *ledgerapi.Value_Date:
		b.byte(0x05)
		if s.Date < dateMin || s.Date > dateMax {
			return refuse(InvalidValue, path+".date", "date %d is outside the range of a Daml date, 0001-01-01 to 9999-12-31", s.Date)
		}
		return b.int32(int64(s.Date), path+".date")
	case *ledgerapi.Value_Party:
		b.byte(0x06)
		b.str(s.Party)
	case *ledgerapi.Value_Text:
		b.byte(0x07)
		b.str(s.Text)
	case *ledgerapi.Value_ContractId:
		b.byte(0x08)
		return b.hex(s.ContractId, path+".contractId")
	case *ledgerapi.Value_Optional:
		b.byte(0x09)
		if s.Optional.GetValue() == nil {
			b.byte(0)
			return nil
		}
		b.byte(1)
		return inner(s.Optional.GetValue(), path+".optional.value")
	case *ledgerapi.Value_List:
		b.byte(0x0a)
		els := s.List.GetElements()
		b.count(len(els))
		for i, e := range els {
			if err := inner(e, fmt.Sprintf("%s.list.elements[%d]", path, i)); err != nil {
				return err
			}
		}
	case *ledgerapi.Value_TextMap:
		b.byte(0x0b)
		entries := s.TextMap.GetEntries()
		b.count(len(entries))
		for i, e := range entries {
			b.str(e.GetKey())
			if err := inner(e.GetValue(), fmt.Sprintf("%s.textMap.entries[%d].value", path, i)); err != nil {
				return err
			}
		}
	case *ledgerapi.Value_Record:
		b.byte(0x0c)
		if err := b.optIdentifier(s.Record.GetRecordId(), path+".record.recordId"); err != nil {
			return err
		}
		fields := s.Record.GetFields()
		b.count(len(fields))
		for i, f := range fields {
			// Always 01 and the label, as in Canton's Python example. Scala
			// writes 00 for an empty label, which the participant never sends.
			b.byte(0x01)
			b.str(f.GetLabel())
			if err := inner(f.GetValue(), fmt.Sprintf("%s.record.fields[%d].value", path, i)); err != nil {
				return err
			}
		}
	case *ledgerapi.Value_Variant:
		b.byte(0x0d)
		if err := b.optIdentifier(s.Variant.GetVariantId(), path+".variant.variantId"); err != nil {
			return err
		}
		b.str(s.Variant.GetConstructor())
		return inner(s.Variant.GetValue(), path+".variant.value")
	case *ledgerapi.Value_Enum:
		b.byte(0x0e)
		if err := b.optIdentifier(s.Enum.GetEnumId(), path+".enum.enumId"); err != nil {
			return err
		}
		b.str(s.Enum.GetConstructor())
	case *ledgerapi.Value_GenMap:
		b.byte(0x0f)
		entries := s.GenMap.GetEntries()
		b.count(len(entries))
		for i, e := range entries {
			at := fmt.Sprintf("%s.genMap.entries[%d]", path, i)
			if err := inner(e.GetKey(), at+".key"); err != nil {
				return err
			}
			if err := inner(e.GetValue(), at+".value"); err != nil {
				return err
			}
		}
	default:
		return refuse(InvalidValue, path, "value has no known kind set")
	}
	return nil
}

// decodeBase64 decodes non-empty canonical standard base64, refusing
// anything else (Go's decoder skips newlines; a signer must not).
func decodeBase64(s string) ([]byte, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	bad := func(reason string) error {
		return refuse(DecodeFailed, "", "input is not canonical standard base64: %s", reason)
	}
	if len(s) == 0 || len(s)%4 != 0 {
		return nil, bad("length is not a positive multiple of 4")
	}
	padding := 0
	if strings.HasSuffix(s, "==") {
		padding = 2
	} else if strings.HasSuffix(s, "=") {
		padding = 1
	}
	out := make([]byte, 0, len(s)/4*3-padding)
	var acc, bits uint
	for i := 0; i < len(s)-padding; i++ {
		v := strings.IndexByte(alphabet, s[i])
		if v < 0 {
			return nil, bad(fmt.Sprintf("invalid character at index %d", i))
		}
		acc = acc<<6 | uint(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
			acc &= 1<<bits - 1
		}
	}
	if acc != 0 {
		return nil, bad("non-zero trailing bits")
	}
	return out, nil
}
