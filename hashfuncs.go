package main

import (
	"crypto"
	"maps"

	_ "crypto/sha256"

	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/blake2s"
)

var hashFuncs = map[string]crypto.Hash{}

func init() {

	maps.Insert(hashFuncs, maps.All(map[string]crypto.Hash{

		// "It's not broken yet"
		"SHA224": crypto.SHA224,
		"SHA256": crypto.SHA256,
		"SHA384": crypto.SHA384,
		"SHA512": crypto.SHA512,

		// The new kids on the block.
		"SHA3-224": crypto.SHA3_224,
		"SHA3-256": crypto.SHA3_256,
		"SHA3-384": crypto.SHA3_384,
		"SHA3-512": crypto.SHA3_512,

		// BLAKE2: What SHA3 should have been.
		"BLAKE2B-256": crypto.BLAKE2b_256,
		"BLAKE2B-384": crypto.BLAKE2b_384,
		"BLAKE2B-512": crypto.BLAKE2b_512,
		"BLAKE2S-256": crypto.BLAKE2s_256,
	}))
}
