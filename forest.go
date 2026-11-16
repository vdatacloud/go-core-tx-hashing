// Copyright 2026 vDataCloud and the go-core-tx-hashing authors.
// SPDX-License-Identifier: Apache-2.0
//
// Ported from @canton-network/core-tx-hashing (forest.ts), Copyright (c)
// 2025-2026 Digital Asset (Switzerland) GmbH and/or its affiliates,
// Apache-2.0; see NOTICE.

package txhashing

import (
	"fmt"
	"strconv"

	"github.com/vdatacloud/go-core-tx-hashing/ledgerapi"
)

// forest is a transaction's nodes checked to form a forest: unique canonical
// ids, each node reached from the roots by exactly one reference.
type forest struct {
	roots    []string
	nodes    map[string]*ledgerapi.DamlTransaction_Node
	seeds    map[string][]byte
	position map[string]int
}

const maxNodeID = 2_147_483_647

func isNodeID(id string) bool {
	if id == "" || len(id) > 10 || (id[0] == '0' && len(id) > 1) {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < '0' || id[i] > '9' {
			return false
		}
	}
	n, err := strconv.ParseInt(id, 10, 64)
	return err == nil && n <= maxNodeID
}

func invalidID(id string) string {
	shown := strconv.Quote(id)
	if len(id) > 20 {
		shown = strconv.Quote(id[:20]) + "..."
	}
	return fmt.Sprintf("%s is not a node id: expected decimal digits without leading zeros, at most %d", shown, maxNodeID)
}

func checkForest(tx *ledgerapi.DamlTransaction, limits Limits) (*forest, error) {
	if len(tx.GetNodes()) > limits.MaxNodes {
		return nil, refuse(NodeLimitExceeded, "transaction.nodes", "transaction has %d nodes, the limit is %d", len(tx.GetNodes()), limits.MaxNodes)
	}
	f := &forest{roots: tx.GetRoots(), nodes: map[string]*ledgerapi.DamlTransaction_Node{}, position: map[string]int{}}
	for i, n := range tx.GetNodes() {
		at := fmt.Sprintf("transaction.nodes[%d].nodeId", i)
		if !isNodeID(n.GetNodeId()) {
			return nil, refuse(InvalidNodeID, at, "%s", invalidID(n.GetNodeId()))
		}
		if _, dup := f.nodes[n.GetNodeId()]; dup {
			return nil, refuse(DuplicateNodeID, at, "node id %s is used by more than one node", n.GetNodeId())
		}
		f.nodes[n.GetNodeId()] = n
		f.position[n.GetNodeId()] = i
	}
	if err := f.checkReferences(tx, limits.MaxNodeDepth); err != nil {
		return nil, err
	}
	seeds, err := f.indexSeeds(tx)
	if err != nil {
		return nil, err
	}
	f.seeds = seeds
	return f, nil
}

// children is a node's child ids, and the kind that has them; ok is false for
// a node that can't have children.
func children(n *ledgerapi.DamlTransaction_Node) (kind string, ids []string, ok bool) {
	switch t := n.GetV1().GetNodeType().(type) {
	case *ledgerapi.Node_Exercise:
		return "exercise", t.Exercise.GetChildren(), true
	case *ledgerapi.Node_Rollback:
		return "rollback", t.Rollback.GetChildren(), true
	}
	return "", nil, false
}

type frame struct {
	kind string // roots, exercise, rollback
	id   string // the node the ids are children of; "" for the roots
	ids  []string
	next int
}

// checkReferences walks depth first with an explicit stack: the forest can be
// as deep as it has nodes.
func (f *forest) checkReferences(tx *ledgerapi.DamlTransaction, maxDepth int) error {
	seen, onPath := map[string]bool{}, map[string]bool{}
	pathOf := func(fr *frame, i int) string {
		if fr.kind == "roots" {
			return fmt.Sprintf("transaction.roots[%d]", i)
		}
		return fmt.Sprintf("transaction.nodes[%d].v1.%s.children[%d]", f.position[fr.id], fr.kind, i)
	}
	// The roots are walked like the children of a node above them all, so
	// len(stack) is the depth of the node being entered.
	stack := []*frame{{kind: "roots", ids: tx.GetRoots()}}
	for len(stack) > 0 {
		fr := stack[len(stack)-1]
		if fr.next >= len(fr.ids) {
			delete(onPath, fr.id)
			stack = stack[:len(stack)-1]
			continue
		}
		i := fr.next
		fr.next++
		id := fr.ids[i]
		if !isNodeID(id) {
			return refuse(InvalidNodeID, pathOf(fr, i), "%s", invalidID(id))
		}
		n, ok := f.nodes[id]
		if !ok {
			return refuse(DanglingNodeReference, pathOf(fr, i), "no node has the id %s", id)
		}
		if onPath[id] {
			return refuse(Cycle, pathOf(fr, i), "node %s is its own ancestor", id)
		}
		if seen[id] {
			return refuse(SharedChild, pathOf(fr, i), "node %s is referenced more than once", id)
		}
		if len(stack) > maxDepth {
			return refuse(DepthLimitExceeded, pathOf(fr, i), "nodes are nested deeper than %d levels", maxDepth)
		}
		seen[id] = true
		if kind, ids, ok := children(n); ok {
			onPath[id] = true
			stack = append(stack, &frame{kind: kind, id: id, ids: ids})
		}
	}
	if len(f.nodes) > len(seen) {
		for i, n := range tx.GetNodes() {
			if !seen[n.GetNodeId()] {
				return refuse(OrphanNode, fmt.Sprintf("transaction.nodes[%d].nodeId", i), "node %s is not reachable from any root", n.GetNodeId())
			}
		}
	}
	return nil
}

func (f *forest) indexSeeds(tx *ledgerapi.DamlTransaction) (map[string][]byte, error) {
	seeds := map[string][]byte{}
	for i, s := range tx.GetNodeSeeds() {
		id := strconv.Itoa(int(s.GetNodeId()))
		at := fmt.Sprintf("transaction.nodeSeeds[%d]", i)
		if !isNodeID(id) {
			return nil, refuse(InvalidNodeID, at+".nodeId", "%s", invalidID(id))
		}
		if _, ok := f.nodes[id]; !ok {
			return nil, refuse(DanglingNodeReference, at+".nodeId", "no node has the id %s", id)
		}
		if _, dup := seeds[id]; dup {
			return nil, refuse(DuplicateNodeSeed, at, "node %s has more than one seed", id)
		}
		seeds[id] = s.GetSeed()
	}
	return seeds, nil
}
