package txhashing

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type vector struct {
	ID                  string `json:"id"`
	Kind                string `json:"kind"`
	Scheme              string `json:"scheme"`
	PreparedTransaction string `json:"preparedTransaction"`
	Expected            struct {
		Hash  string `json:"hash"`
		Error string `json:"error"`
	} `json:"expected"`
	Limits *struct {
		MaxNodes      int `json:"maxNodes"`
		MaxNodeDepth  int `json:"maxNodeDepth"`
		MaxValueDepth int `json:"maxValueDepth"`
	} `json:"limits"`
}

// Every vector of @canton-network/core-tx-hashing (testdata/upstream, copied
// from its repository at UpstreamCommit): the same hash, or a refusal with
// the same code.
func TestUpstreamVectors(t *testing.T) {
	files, err := filepath.Glob("testdata/upstream/*/*.json")
	if err != nil || len(files) < 128 {
		t.Fatalf("want the 128 upstream vectors, found %d (%v)", len(files), err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v vector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		t.Run(filepath.Base(filepath.Dir(f))+"/"+v.ID, func(t *testing.T) {
			var opts []Option
			if v.Limits != nil {
				l := DefaultLimits
				if v.Limits.MaxNodes != 0 {
					l.MaxNodes = v.Limits.MaxNodes
				}
				if v.Limits.MaxNodeDepth != 0 {
					l.MaxNodeDepth = v.Limits.MaxNodeDepth
				}
				if v.Limits.MaxValueDepth != 0 {
					l.MaxValueDepth = v.Limits.MaxValueDepth
				}
				opts = append(opts, func(d *Limits) { *d = l })
			}
			h, err := func() ([]byte, error) {
				s, err := ParseScheme(v.Scheme)
				if err != nil {
					return nil, err
				}
				return HashBase64(v.PreparedTransaction, s, opts...)
			}()
			switch {
			case v.Expected.Error != "":
				if got := CodeOf(err); string(got) != v.Expected.Error {
					t.Fatalf("want refusal %s, got %v (hash %x)", v.Expected.Error, err, h)
				}
			case err != nil:
				t.Fatalf("want hash %s, got %v", v.Expected.Hash, err)
			case hex.EncodeToString(h) != v.Expected.Hash:
				t.Fatalf("hash %x, want %s", h, v.Expected.Hash)
			}
		})
	}
}
