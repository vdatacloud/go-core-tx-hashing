package txhashing

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/vdatacloud/go-core-tx-hashing/ledgerapi"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The vendored protobuf definitions have exactly the fields the upstream
// package's have, message by message, so both refuse the same unknown
// fields. UPSTREAM_FIELDS is written by scripts/upstream-check.mjs (CI).
func TestFieldsMatchUpstream(t *testing.T) {
	path := os.Getenv("UPSTREAM_FIELDS")
	if path == "" {
		t.Skip("UPSTREAM_FIELDS not set: run scripts/upstream-check.mjs (CI does)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string][]int
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	got := map[string][]int{}
	var walk func(md protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		name := strings.ReplaceAll(strings.TrimPrefix(string(md.FullName()), "txhashing.ledgerapi."), ".", "_")
		if _, ok := got[name]; ok {
			return
		}
		nos := []int{}
		for i := 0; i < md.Fields().Len(); i++ {
			nos = append(nos, int(md.Fields().Get(i).Number()))
		}
		sort.Ints(nos)
		got[name] = nos
		for i := 0; i < md.Fields().Len(); i++ {
			if m := md.Fields().Get(i).Message(); m != nil {
				walk(m)
			}
		}
	}
	walk((&ledgerapi.PreparedTransaction{}).ProtoReflect().Descriptor())
	if !reflect.DeepEqual(got, want) {
		for name, nos := range want {
			if !reflect.DeepEqual(got[name], nos) {
				t.Errorf("%s: fields %v here, %v upstream", name, got[name], nos)
			}
		}
		for name := range got {
			if _, ok := want[name]; !ok {
				t.Errorf("%s is here but not upstream", name)
			}
		}
	}
}
