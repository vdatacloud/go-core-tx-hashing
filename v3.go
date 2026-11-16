// Copyright 2026 vDataCloud and the go-core-tx-hashing authors.
// SPDX-License-Identifier: Apache-2.0
//
// Ported from @canton-network/core-tx-hashing (v3.ts), Copyright (c)
// 2025-2026 Digital Asset (Switzerland) GmbH and/or its affiliates,
// Apache-2.0; see NOTICE.

package txhashing

import (
	"fmt"

	"github.com/vdatacloud/go-core-tx-hashing/ledgerapi"
)

// Hashing scheme V3, after daml_transaction_hashing_v3.py (canton v3.5.1,
// 08-interactive-submission). Unlike V2: no encoding version in nodes and
// metadata, a contract key in create, exercise and fetch nodes, byKey in
// exercise and fetch nodes, QueryByKey nodes, and maxRecordTime in metadata.
type schemeV3 struct{}

// lfWithoutKeys is the LF version V3 hashes without keys; "2" is the later
// one that contract keys need.
const lfWithoutKeys = "2.1"

const noKeys = "keys are not supported in nodes with LF serialization version 2.1"

func (schemeV3) version() byte        { return 0x03 }
func (schemeV3) rollbackHead() []byte { return []byte{0x03} }

func (schemeV3) checkLFVersion(lf, path string) error {
	if lf != "2.1" && lf != "2" {
		return refuse(UnsupportedLFVersion, path, "hashing scheme V3 hashes LF versions 2.1 and 2 only")
	}
	return nil
}

// checkKeyUse: the participant's decoder refuses a key or byKey = true in an
// LF 2.1 node, though the Python example hashes both.
func checkKeyUse(lf string, key *ledgerapi.GlobalKeyWithMaintainers, byKey bool, at string) error {
	if lf != lfWithoutKeys {
		return nil
	}
	if key != nil {
		return refuse(UnsupportedLFVersion, at+".key", "%s", noKeys)
	}
	if byKey {
		return refuse(UnsupportedLFVersion, at+".byKey", "byKey is not supported in nodes with LF serialization version 2.1")
	}
	return nil
}

// key encodes a contract key; its hash is written raw, without its length,
// so it must be 32 bytes.
func (b *buf) key(k *ledgerapi.GlobalKeyWithMaintainers, path string, maxValueDepth int) error {
	if k == nil {
		return refuse(MissingField, path, "key is missing")
	}
	at := path + ".key"
	g := k.GetKey()
	if g == nil {
		return refuse(MissingField, at, "key has no global key")
	}
	if len(g.GetHash()) != 32 {
		return refuse(InvalidValue, at+".hash", "key hash has %d bytes, not 32", len(g.GetHash()))
	}
	b.str(g.GetPackageName())
	if err := b.identifier(g.GetTemplateId(), at+".templateId"); err != nil {
		return err
	}
	if err := b.value(g.GetKey(), maxValueDepth, at+".key", 1); err != nil {
		return err
	}
	b.raw(g.GetHash())
	b.strs(k.GetMaintainers())
	return nil
}

func (b *buf) optKey(k *ledgerapi.GlobalKeyWithMaintainers, path string, maxValueDepth int) error {
	if k == nil {
		b.byte(0)
		return nil
	}
	b.byte(1)
	return b.key(k, path, maxValueDepth)
}

func (s schemeV3) encodeCreate(b *buf, c *ledgerapi.Create, at string, seed []byte, maxValueDepth int) error {
	if err := s.checkLFVersion(c.GetLfVersion(), at+".lfVersion"); err != nil {
		return err
	}
	if err := checkKeyUse(c.GetLfVersion(), c.Key, false, at); err != nil {
		return err
	}
	b.str(c.GetLfVersion())
	b.byte(0x00)
	optSeed(b, seed)
	if err := b.hex(c.GetContractId(), at+".contractId"); err != nil {
		return err
	}
	b.str(c.GetPackageName())
	if err := b.identifier(c.GetTemplateId(), at+".templateId"); err != nil {
		return err
	}
	if err := b.value(c.GetArgument(), maxValueDepth, at+".argument", 1); err != nil {
		return err
	}
	b.strs(c.GetSignatories())
	b.strs(c.GetStakeholders())
	return b.optKey(c.Key, at+".key", maxValueDepth)
}

func (s schemeV3) encodeExercise(b *buf, x *ledgerapi.Exercise, at string, seed []byte, maxValueDepth int) error {
	if err := s.checkLFVersion(x.GetLfVersion(), at+".lfVersion"); err != nil {
		return err
	}
	if err := checkKeyUse(x.GetLfVersion(), x.Key, x.GetByKey(), at); err != nil {
		return err
	}
	b.str(x.GetLfVersion())
	b.byte(0x01)
	b.raw(seed)
	if err := b.hex(x.GetContractId(), at+".contractId"); err != nil {
		return err
	}
	b.str(x.GetPackageName())
	if err := b.identifier(x.GetTemplateId(), at+".templateId"); err != nil {
		return err
	}
	b.strs(x.GetSignatories())
	b.strs(x.GetStakeholders())
	b.strs(x.GetActingParties())
	if err := b.optIdentifier(x.GetInterfaceId(), at+".interfaceId"); err != nil {
		return err
	}
	b.str(x.GetChoiceId())
	if err := b.value(x.GetChosenValue(), maxValueDepth, at+".chosenValue", 1); err != nil {
		return err
	}
	b.bool(x.GetConsuming())
	if err := optValue(b, x.GetExerciseResult(), maxValueDepth, at+".exerciseResult"); err != nil {
		return err
	}
	b.strs(x.GetChoiceObservers())
	b.bool(x.GetByKey())
	return b.optKey(x.Key, at+".key", maxValueDepth)
}

func (s schemeV3) encodeFetch(b *buf, f *ledgerapi.Fetch, at string, maxValueDepth int) error {
	if err := s.checkLFVersion(f.GetLfVersion(), at+".lfVersion"); err != nil {
		return err
	}
	if err := checkKeyUse(f.GetLfVersion(), f.Key, f.GetByKey(), at); err != nil {
		return err
	}
	b.str(f.GetLfVersion())
	b.byte(0x02)
	if err := b.hex(f.GetContractId(), at+".contractId"); err != nil {
		return err
	}
	b.str(f.GetPackageName())
	if err := b.identifier(f.GetTemplateId(), at+".templateId"); err != nil {
		return err
	}
	b.strs(f.GetSignatories())
	b.strs(f.GetStakeholders())
	if err := b.optIdentifier(f.GetInterfaceId(), at+".interfaceId"); err != nil {
		return err
	}
	b.strs(f.GetActingParties())
	b.bool(f.GetByKey())
	return b.optKey(f.Key, at+".key", maxValueDepth)
}

func (s schemeV3) encodeQueryByKey(b *buf, q *ledgerapi.QueryByKey, at string, maxValueDepth int) error {
	if err := s.checkLFVersion(q.GetLfVersion(), at+".lfVersion"); err != nil {
		return err
	}
	// Its key is required, and the participant refuses any key in LF 2.1.
	if q.GetLfVersion() == lfWithoutKeys {
		return refuse(UnsupportedLFVersion, at, "%s", noKeys)
	}
	b.str(q.GetLfVersion())
	b.byte(0x04)
	b.str(q.GetPackageName())
	if err := b.identifier(q.GetTemplateId(), at+".templateId"); err != nil {
		return err
	}
	b.bool(q.GetExhaustive())
	// Required here, so without the presence byte of the other nodes' key.
	if err := b.key(q.GetKey(), at+".key", maxValueDepth); err != nil {
		return err
	}
	b.count(len(q.GetResult()))
	for i, cid := range q.GetResult() {
		if err := b.hex(cid, fmt.Sprintf("%s.result[%d]", at, i)); err != nil {
			return err
		}
	}
	return nil
}

func (s schemeV3) encodeMetadata(b *buf, m *ledgerapi.Metadata, maxValueDepth int) error {
	si, err := submitterInfoOf(m)
	if err != nil {
		return err
	}
	if err := metadataCommon(b, m, si, s, maxValueDepth); err != nil {
		return err
	}
	return b.optTime(m.MaxRecordTime, "metadata.maxRecordTime")
}
