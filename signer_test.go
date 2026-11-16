package txhashing

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/vdatacloud/go-core-tx-hashing/ledgerapi"
	"google.golang.org/protobuf/proto"
)

func loadVector(t testing.TB, path string) vector {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyAndActions(t *testing.T) {
	v := loadVector(t, "testdata/upstream/v2/v2-create-and-exercise.json")
	want, _ := hex.DecodeString(v.Expected.Hash)
	d, err := Verify(v.PreparedTransaction, SchemeV2, want)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(d.Hash()) != v.Expected.Hash {
		t.Fatalf("hash %x", d.Hash())
	}
	if _, err := Verify(v.PreparedTransaction, SchemeV2, []byte("another hash")); CodeOf(err) != HashMismatch {
		t.Fatalf("a claimed hash that differs: %v", err)
	}
	acts := d.Actions()
	if len(acts) == 0 || acts[0].Template == "" {
		t.Fatalf("actions: %+v", acts)
	}
	for _, a := range acts {
		if a.Kind == "exercise" && a.Choice == "" {
			t.Fatalf("an exercise without its choice: %+v", a)
		}
	}
	if err := d.CheckActAs(d.ActAs()...); err != nil {
		t.Fatal(err)
	}
	if err := d.CheckActAs("someone-else::1220"); err == nil {
		t.Fatal("acting as a party the signer doesn't sign for must be refused")
	}
}

// Changing what any hashed field says changes the hash (upstream's
// mutation vectors cover one byte each; this covers the decoded fields a
// policy reads).
func TestPolicyFieldsAreHashed(t *testing.T) {
	v := loadVector(t, "testdata/upstream/v2/v2-create-and-exercise.json")
	raw, _ := base64.StdEncoding.DecodeString(v.PreparedTransaction)
	d, err := Decode(raw, SchemeV2)
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(f func(d *Decoded)) []byte {
		c := &Decoded{Transaction: proto.Clone(d.Transaction).(*ledgerapi.PreparedTransaction)}
		f(c)
		b, _ := proto.Marshal(c.Transaction)
		h, err := Hash(b, SchemeV2)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	base := d.Hash()
	cases := map[string]func(*Decoded){
		"actAs":        func(c *Decoded) { c.Transaction.Metadata.SubmitterInfo.ActAs = []string{"mallory::1220"} },
		"synchronizer": func(c *Decoded) { c.Transaction.Metadata.SynchronizerId += "x" },
		"package name": func(c *Decoded) {
			for _, n := range c.Transaction.Transaction.Nodes {
				if x := n.GetV1().GetExercise(); x != nil {
					x.PackageName += "x"
				}
			}
		},
	}
	for name, f := range cases {
		if string(mutate(f)) == string(base) {
			t.Errorf("changing the %s didn't change the hash", name)
		}
	}
}
