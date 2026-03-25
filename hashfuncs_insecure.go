//go:build insecure

package main

import (
	"crypto"
	"maps"

	// Register the hash functions we want to support
	_ "crypto/md5"
	_ "crypto/sha1"

	_ "golang.org/x/crypto/md4"
	_ "golang.org/x/crypto/ripemd160"
)

func init() {
	maps.Insert(hashFuncs, maps.All(map[string]crypto.Hash{

		// The old-school ones.
		"MD4":       crypto.MD4,
		"RIPEMD160": crypto.RIPEMD160,

		// Dead but still used
		"MD5":  crypto.MD5,
		"SHA1": crypto.SHA1,
	}))
}
