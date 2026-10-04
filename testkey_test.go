// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package factors

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// testKey stands for a registered credential's public key. No test here gets
// as far as a signature: the platform side is swapped out before it.
var testKey = func() *ecdsa.PublicKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &k.PublicKey
}()
