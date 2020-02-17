package main

import "github.com/zeebo/blake3"

func blake3Sum256(data []byte) []byte {
	h := blake3.NewSized(32)
	h.Write(data)
	return h.Sum(nil)
}

func blake3Sum384(data []byte) []byte {
	h := blake3.NewSized(48)
	h.Write(data)
	return h.Sum(nil)
}

func blake3Sum512(data []byte) []byte {
	h := blake3.NewSized(64)
	h.Write(data)
	return h.Sum(nil)
}
