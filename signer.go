// Copyright 2026 vDataCloud and the go-core-tx-hashing authors.
// SPDX-License-Identifier: Apache-2.0

package txhashing

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/vdatacloud/go-core-tx-hashing/ledgerapi"
)

// Helpers for an external signer, beyond the upstream package: check a
// claimed hash, the parties a transaction acts as, and read what it does.

// Verify decodes, checks and hashes a base64 prepared transaction and, when
// claimedHash is not empty, refuses (HASH_MISMATCH) a hash that differs from
// the one computed. Sign Decoded.Hash(), never claimedHash.
func Verify(preparedTransaction string, s Scheme, claimedHash []byte, opts ...Option) (*Decoded, error) {
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
	d, err := Decode(raw, s, opts...)
	if err != nil {
		return nil, err
	}
	if len(claimedHash) > 0 && !bytes.Equal(d.hash, claimedHash) {
		return nil, refuse(HashMismatch, "", "the hash the transaction came with is not its hash")
	}
	return d, nil
}

// ActAs is who the transaction is submitted as.
func (d *Decoded) ActAs() []string {
	return d.Transaction.GetMetadata().GetSubmitterInfo().GetActAs()
}

// Synchronizer is the synchronizer the transaction is for.
func (d *Decoded) Synchronizer() string { return d.Transaction.GetMetadata().GetSynchronizerId() }

// CheckActAs refuses a transaction submitted as no party, or as any party
// not in allowed.
func (d *Decoded) CheckActAs(allowed ...string) error {
	ok := map[string]bool{}
	for _, p := range allowed {
		ok[p] = true
	}
	if len(d.ActAs()) == 0 {
		return fmt.Errorf("the transaction acts as no party")
	}
	for _, p := range d.ActAs() {
		if !ok[p] {
			return fmt.Errorf("the transaction acts as %s, which this signer doesn't sign for", p)
		}
	}
	return nil
}

// Action is one node the hash covers, as a signer's policy reads it.
type Action struct {
	NodeID        string
	Kind          string // create, exercise, fetch, rollback, queryByKey
	Template      string // "<package-name>:<Module>:<Entity>": the package name, stable across upgrades
	Interface     string // "<package-id>:<Module>:<Entity>", for an exercise or fetch through an interface
	Choice        string // exercise only
	Consuming     bool
	ByKey         bool
	ActingParties []string
	Signatories   []string
	Stakeholders  []string
	Argument      *ledgerapi.Value // a create's argument, or an exercise's choice argument
	RolledBack    bool             // under a rollback node: its effects are undone
}

// Actions lists every node the hash covers, depth first from the roots, in
// the order they are hashed.
func (d *Decoded) Actions() []Action {
	var out []Action
	var walk func(ids []string, rolledBack bool)
	walk = func(ids []string, rolledBack bool) {
		for _, id := range ids {
			n := d.forest.nodes[id]
			a := Action{NodeID: id, Kind: kindOf(n), RolledBack: rolledBack}
			switch t := n.GetV1().GetNodeType().(type) {
			case *ledgerapi.Node_Create:
				c := t.Create
				a.Template, a.Signatories, a.Stakeholders, a.Argument = templateName(c.GetPackageName(), c.GetTemplateId()), c.GetSignatories(), c.GetStakeholders(), c.GetArgument()
			case *ledgerapi.Node_Exercise:
				x := t.Exercise
				a.Template, a.Choice, a.Consuming, a.ByKey = templateName(x.GetPackageName(), x.GetTemplateId()), x.GetChoiceId(), x.GetConsuming(), x.GetByKey()
				a.ActingParties, a.Signatories, a.Stakeholders, a.Argument = x.GetActingParties(), x.GetSignatories(), x.GetStakeholders(), x.GetChosenValue()
				a.Interface = qualified(x.GetInterfaceId())
			case *ledgerapi.Node_Fetch:
				f := t.Fetch
				a.Template, a.ByKey, a.ActingParties, a.Signatories, a.Stakeholders = templateName(f.GetPackageName(), f.GetTemplateId()), f.GetByKey(), f.GetActingParties(), f.GetSignatories(), f.GetStakeholders()
				a.Interface = qualified(f.GetInterfaceId())
			case *ledgerapi.Node_QueryByKey:
				a.Template = templateName(t.QueryByKey.GetPackageName(), t.QueryByKey.GetTemplateId())
			}
			out = append(out, a)
			if _, kids, ok := children(n); ok {
				walk(kids, rolledBack || a.Kind == "rollback")
			}
		}
	}
	walk(d.forest.roots, false)
	return out
}

func templateName(pkgName string, id *ledgerapi.Identifier) string {
	return pkgName + ":" + id.GetModuleName() + ":" + id.GetEntityName()
}

func qualified(id *ledgerapi.Identifier) string {
	if id == nil {
		return ""
	}
	return strings.Join([]string{id.GetPackageId(), id.GetModuleName(), id.GetEntityName()}, ":")
}
