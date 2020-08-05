package main

// https://github.com/zeebo/blake3
// https://github.com/lukechampine/blake3
import "github.com/zeebo/blake3"

func blake3Sum256(data []byte) []byte {
	h := blake3.New()
	h.Write(data)
	return h.Sum(nil)
}
