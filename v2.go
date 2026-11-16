// Copyright 2026 vDataCloud and the go-core-tx-hashing authors.
// SPDX-License-Identifier: Apache-2.0
//
// Ported from @canton-network/core-tx-hashing (v2.ts), Copyright (c)
// 2025-2026 Digital Asset (Switzerland) GmbH and/or its affiliates,
// Apache-2.0; see NOTICE.

package txhashing

import "github.com/vdatacloud/go-core-tx-hashing/ledgerapi"

// Hashing scheme V2, after daml_transaction_hashing_v2.py (canton v3.5.1,
// 08-interactive-submission). Contract keys, byKey, QueryByKey nodes and
// maxRecordTime are refused, as V2 does not hash them.
type schemeV2 struct{}

const (
	// v2EncodingVersion is the protobuf encoding's version, written first in
	// every node and in the metadata.
	v2EncodingVersion = 0x01
	// v2LFVersion is the only LF version V2 hashes; nodes with contract keys
	// have a later one.
	v2LFVersion = "2.1"
)

func (schemeV2) version() byte        { return 0x02 }
func (schemeV2) rollbackHead() []byte { return []byte{v2EncodingVersion, 0x03} }

func (schemeV2) checkLFVersion(lf, path string) error {
	if lf != v2LFVersion {
		return refuse(UnsupportedLFVersion, path, "hashing scheme V2 hashes LF version %s only", v2LFVersion)
	}
	return nil
}

func notCoveredV2(what, path string) error {
	return refuse(FieldNotCoveredByScheme, path, "%s is not covered by hashing scheme V2", what)
}

func (s schemeV2) encodeCreate(b *buf, c *ledgerapi.Create, at string, seed []byte, maxValueDepth int) error {
	if err := s.checkLFVersion(c.GetLfVersion(), at+".lfVersion"); err != nil {
		return err
	}
	if c.Key != nil {
		return notCoveredV2("a contract key", at+".key")
	}
	b.byte(v2EncodingVersion)
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
	return nil
}

func checkNoKeyV2(key *ledgerapi.GlobalKeyWithMaintainers, byKey bool, at string) error {
	if key != nil {
		return notCoveredV2("a contract key", at+".key")
	}
	if byKey {
		return notCoveredV2("byKey = true", at+".byKey")
	}
	return nil
}

func (s schemeV2) encodeExercise(b *buf, x *ledgerapi.Exercise, at string, seed []byte, maxValueDepth int) error {
	if err := s.checkLFVersion(x.GetLfVersion(), at+".lfVersion"); err != nil {
		return err
	}
	if err := checkNoKeyV2(x.Key, x.GetByKey(), at); err != nil {
		return err
	}
	b.byte(v2EncodingVersion)
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
	return nil
}

func (s schemeV2) encodeFetch(b *buf, f *ledgerapi.Fetch, at string, _ int) error {
	if err := s.checkLFVersion(f.GetLfVersion(), at+".lfVersion"); err != nil {
		return err
	}
	if err := checkNoKeyV2(f.Key, f.GetByKey(), at); err != nil {
		return err
	}
	b.byte(v2EncodingVersion)
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
	return nil
}

func (schemeV2) encodeQueryByKey(_ *buf, _ *ledgerapi.QueryByKey, path string, _ int) error {
	return notCoveredV2("a QueryByKey node", path)
}

func (s schemeV2) encodeMetadata(b *buf, m *ledgerapi.Metadata, maxValueDepth int) error {
	if m.MaxRecordTime != nil {
		return notCoveredV2("maxRecordTime", "metadata.maxRecordTime")
	}
	si, err := submitterInfoOf(m)
	if err != nil {
		return err
	}
	b.byte(v2EncodingVersion)
	return metadataCommon(b, m, si, s, maxValueDepth)
}

// metadataCommon is the metadata both schemes encode alike, after V2's
// encoding version.
func metadataCommon(b *buf, m *ledgerapi.Metadata, si *ledgerapi.Metadata_SubmitterInfo, s scheme, maxValueDepth int) error {
	b.strs(si.GetActAs())
	b.str(si.GetCommandId())
	b.str(m.GetTransactionUuid())
	if err := b.int32(int64(m.GetMediatorGroup()), "metadata.mediatorGroup"); err != nil {
		return err
	}
	b.str(m.GetSynchronizerId())
	if err := b.optTime(m.MinLedgerEffectiveTime, "metadata.minLedgerEffectiveTime"); err != nil {
		return err
	}
	if err := b.optTime(m.MaxLedgerEffectiveTime, "metadata.maxLedgerEffectiveTime"); err != nil {
		return err
	}
	if err := b.time(m.GetPreparationTime(), "metadata.preparationTime"); err != nil {
		return err
	}
	return encodeInputContracts(b, m.GetInputContracts(), s, maxValueDepth)
}

func optValue(b *buf, v *ledgerapi.Value, maxValueDepth int, path string) error {
	if v == nil {
		b.byte(0)
		return nil
	}
	b.byte(1)
	return b.value(v, maxValueDepth, path, 1)
}
