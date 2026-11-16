// Copyright 2026 vDataCloud and the go-core-tx-hashing authors.
// SPDX-License-Identifier: Apache-2.0
//
// Ported from @canton-network/core-tx-hashing (scheme.ts), Copyright (c)
// 2025-2026 Digital Asset (Switzerland) GmbH and/or its affiliates,
// Apache-2.0; see NOTICE.

package txhashing

import (
	"fmt"

	"github.com/vdatacloud/go-core-tx-hashing/ledgerapi"
)

// Code shared by hashing schemes V2 and V3. Neither hashes
// metadata.globalKeyMapping (deprecated, left empty by the participant) or
// metadata.inputContracts[i].eventBlob, so a signature does not cover them.

// purpose is the hash purpose of a prepared transaction.
var purpose = []byte{0x00, 0x00, 0x00, 0x30}

// scheme is how one hashing scheme encodes the metadata, and each kind of
// node up to its children's hashes.
type scheme interface {
	version() byte
	checkLFVersion(lf, path string) error
	// encodeCreate: a create in the transaction has a seed; an input contract has none (nil).
	encodeCreate(b *buf, c *ledgerapi.Create, path string, seed []byte, maxValueDepth int) error
	encodeExercise(b *buf, x *ledgerapi.Exercise, path string, seed []byte, maxValueDepth int) error
	encodeFetch(b *buf, f *ledgerapi.Fetch, path string, maxValueDepth int) error
	rollbackHead() []byte
	encodeQueryByKey(b *buf, q *ledgerapi.QueryByKey, path string, maxValueDepth int) error
	encodeMetadata(b *buf, m *ledgerapi.Metadata, maxValueDepth int) error
}

// hashPrepared is sha256(purpose || scheme || sha256(purpose || transaction) || sha256(purpose || metadata)).
func hashPrepared(tx *ledgerapi.DamlTransaction, md *ledgerapi.Metadata, f *forest, s scheme, maxValueDepth int) ([]byte, error) {
	if md == nil {
		return nil, refuse(MissingField, "metadata", "prepared transaction has no metadata")
	}
	if err := checkSeeds(tx, f); err != nil {
		return nil, err
	}
	txHash, err := hashTransaction(tx, f, s, maxValueDepth)
	if err != nil {
		return nil, err
	}
	// After the nodes: the transaction's LF version is the highest of
	// theirs, so the node at fault is reported first.
	if err := s.checkLFVersion(tx.GetVersion(), "transaction.version"); err != nil {
		return nil, err
	}
	var m buf
	m.raw(purpose)
	if err := s.encodeMetadata(&m, md, maxValueDepth); err != nil {
		return nil, err
	}
	var out buf
	out.raw(purpose)
	out.byte(s.version())
	out.raw(txHash)
	out.raw(sha(m))
	return sha(out), nil
}

func kindOf(n *ledgerapi.DamlTransaction_Node) string {
	switch n.GetV1().GetNodeType().(type) {
	case *ledgerapi.Node_Create:
		return "create"
	case *ledgerapi.Node_Exercise:
		return "exercise"
	case *ledgerapi.Node_Fetch:
		return "fetch"
	case *ledgerapi.Node_Rollback:
		return "rollback"
	case *ledgerapi.Node_QueryByKey:
		return "queryByKey"
	}
	return ""
}

// checkSeeds: a seed is hashed raw, without its length, and only for a
// create or an exercise node, so it must have 32 bytes and other nodes may
// not have one.
func checkSeeds(tx *ledgerapi.DamlTransaction, f *forest) error {
	for j, s := range tx.GetNodeSeeds() {
		if len(s.GetSeed()) != 32 {
			return refuse(InvalidValue, fmt.Sprintf("transaction.nodeSeeds[%d].seed", j), "node seed has %d bytes, not 32", len(s.GetSeed()))
		}
		// checkForest made sure the seed's node exists.
		switch kind := kindOf(f.nodes[fmt.Sprint(s.GetNodeId())]); kind {
		case "fetch", "rollback", "queryByKey":
			return refuse(FieldNotCoveredByScheme, fmt.Sprintf("transaction.nodeSeeds[%d]", j), "%s node %d has a seed, which the hash does not cover", kind, s.GetNodeId())
		}
	}
	for i, n := range tx.GetNodes() {
		kind := kindOf(n)
		if _, ok := f.seeds[n.GetNodeId()]; (kind == "create" || kind == "exercise") && !ok {
			return refuse(MissingNodeSeed, fmt.Sprintf("transaction.nodes[%d]", i), "%s node %s has no seed", kind, n.GetNodeId())
		}
	}
	return nil
}

// encodeNode encodes a node up to its children; hasChildren is false for a
// node that can't have any.
func encodeNode(n *ledgerapi.DamlTransaction_Node, path string, seed []byte, s scheme, maxValueDepth int) (head buf, kids []string, hasChildren bool, err error) {
	v1 := n.GetV1()
	if v1 == nil {
		return nil, nil, false, refuse(UnsupportedNodeVersion, path, "node is not a v1 node")
	}
	at := path + ".v1"
	switch t := v1.GetNodeType().(type) {
	case *ledgerapi.Node_Create:
		err = s.encodeCreate(&head, t.Create, at+".create", seed, maxValueDepth)
		return head, nil, false, err
	case *ledgerapi.Node_Exercise:
		// checkSeeds made sure every exercise has a seed.
		err = s.encodeExercise(&head, t.Exercise, at+".exercise", seed, maxValueDepth)
		return head, t.Exercise.GetChildren(), true, err
	case *ledgerapi.Node_Fetch:
		err = s.encodeFetch(&head, t.Fetch, at+".fetch", maxValueDepth)
		return head, nil, false, err
	case *ledgerapi.Node_Rollback:
		if len(t.Rollback.GetChildren()) == 0 {
			return nil, nil, false, refuse(MissingField, at+".rollback.children", "rollback node has no children")
		}
		return append(buf(nil), s.rollbackHead()...), t.Rollback.GetChildren(), true, nil
	case *ledgerapi.Node_QueryByKey:
		err = s.encodeQueryByKey(&head, t.QueryByKey, at+".queryByKey", maxValueDepth)
		return head, nil, false, err
	default:
		return nil, nil, false, refuse(MissingField, at, "node has no node type")
	}
}

// hashTransaction hashes children before their parent (a Merkle tree); the
// transaction itself is the top: purpose || version || its roots' hashes.
func hashTransaction(tx *ledgerapi.DamlTransaction, f *forest, s scheme, maxValueDepth int) ([]byte, error) {
	var hashChildren func(head buf, ids []string) ([]byte, error)
	hashChildren = func(head buf, ids []string) ([]byte, error) {
		head.count(len(ids))
		for _, id := range ids {
			n := f.nodes[id] // checkForest made sure every id it walked is a node
			nh, kids, has, err := encodeNode(n, fmt.Sprintf("transaction.nodes[%d]", f.position[id]), f.seeds[id], s, maxValueDepth)
			if err != nil {
				return nil, err
			}
			if !has {
				head.raw(sha(nh))
				continue
			}
			h, err := hashChildren(nh, kids)
			if err != nil {
				return nil, err
			}
			head.raw(h)
		}
		return sha(head), nil
	}
	var top buf
	top.raw(purpose)
	top.str(tx.GetVersion())
	return hashChildren(top, f.roots)
}

func submitterInfoOf(m *ledgerapi.Metadata) (*ledgerapi.Metadata_SubmitterInfo, error) {
	if m.GetSubmitterInfo() == nil {
		return nil, refuse(MissingField, "metadata.submitterInfo", "metadata has no submitter info")
	}
	return m.GetSubmitterInfo(), nil
}

// encodeInputContracts is rep(i64(createdAt) || sha256(create)) over the
// input contracts, each encoded as a create without a seed.
func encodeInputContracts(b *buf, contracts []*ledgerapi.Metadata_InputContract, s scheme, maxValueDepth int) error {
	b.count(len(contracts))
	for i, c := range contracts {
		path := fmt.Sprintf("metadata.inputContracts[%d]", i)
		create := c.GetV1()
		if create == nil {
			return refuse(MissingField, path, "input contract has no v1 contract")
		}
		if err := b.time(c.GetCreatedAt(), path+".createdAt"); err != nil {
			return err
		}
		var enc buf
		if err := s.encodeCreate(&enc, create, path+".v1", nil, maxValueDepth); err != nil {
			return err
		}
		b.raw(sha(enc))
	}
	return nil
}

func optSeed(b *buf, seed []byte) {
	if seed == nil {
		b.byte(0)
		return
	}
	b.byte(1)
	b.raw(seed)
}
