// Copyright 2026 vDataCloud and the go-core-tx-hashing authors.
// SPDX-License-Identifier: Apache-2.0

package txhashing

// The upstream implementation this port follows. Release tags carry its
// major and minor version (v1.2.x ports 1.2); the patch number is this
// module's own. CI checks every vector against exactly this version, and
// testdata/upstream holds the vectors of UpstreamCommit.
const (
	UpstreamPackage = "@canton-network/core-tx-hashing"
	UpstreamVersion = "1.2.0"
	UpstreamRepo    = "https://github.com/canton-network/wallet/tree/main/core/tx-hashing"
	UpstreamCommit  = "cf704945fa65c1f0cdbf43a148f63b36e98f590f"
	// CantonVersion is the Canton release the protobuf definitions in
	// proto/ are vendored from.
	CantonVersion = "3.5.10"
)
