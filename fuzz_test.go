package txhashing

import (
	"encoding/base64"
	"path/filepath"
	"testing"
)

// A signer reads transactions it didn't build: whatever it is sent, Hash
// returns a hash or an *Error and never panics.
func FuzzHash(f *testing.F) {
	files, _ := filepath.Glob("testdata/upstream/*/*.json")
	for _, p := range files {
		v := loadVector(f, p)
		if raw, err := base64.StdEncoding.DecodeString(v.PreparedTransaction); err == nil {
			f.Add(raw, true)
		}
	}
	f.Fuzz(func(t *testing.T, raw []byte, v3 bool) {
		s := SchemeV2
		if v3 {
			s = SchemeV3
		}
		d, err := Decode(raw, s)
		if err != nil {
			if CodeOf(err) == "" {
				t.Fatalf("a refusal that is not an *Error: %v", err)
			}
			return
		}
		if len(d.Hash()) != 32 {
			t.Fatalf("hash of %d bytes", len(d.Hash()))
		}
		_ = d.Actions()
	})
}
