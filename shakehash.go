package main

import (
	"golang.org/x/crypto/sha3"
)

// ShakeHash convert to normal golang hases...
type shake2hash32 struct {
	shake sha3.ShakeHash
}
type shake2hash64 struct {
	shake sha3.ShakeHash
}

// Pass through fuctions...
func (s *shake2hash32) Write(p []byte) (n int, err error) {
	return s.shake.Write(p)
}
func (s *shake2hash32) Read(p []byte) (n int, err error) {
	return s.shake.Read(p)
}
func (s *shake2hash32) Reset() {
	s.shake.Reset()
}
func (s *shake2hash32) BlockSize() int {
	return 4096
}
func (s *shake2hash64) Write(p []byte) (n int, err error) {
	return s.shake.Write(p)
}
func (s *shake2hash64) Read(p []byte) (n int, err error) {
	return s.shake.Read(p)
}
func (s *shake2hash64) Reset() {
	s.shake.Reset()
}
func (s *shake2hash64) BlockSize() int {
	return 4096
}

// Different 32/64 functions...
func (s *shake2hash32) Clone() sha3.ShakeHash {
	return &shake2hash32{s.shake.Clone()}
}
func (s *shake2hash32) Size() int {
	return 32
}
func (s *shake2hash32) Sum(b []byte) []byte {
	ns := s.shake.Clone()

	var ret [32]byte
	ns.Write(b)
	ns.Read(ret[:])
	return ret[:]
}

func (s *shake2hash64) Clone() sha3.ShakeHash {
	return &shake2hash64{s.shake.Clone()}
}
func (s *shake2hash64) Size() int {
	return 64
}
func (s *shake2hash64) Sum(b []byte) []byte {
	ns := s.shake.Clone()

	var ret [64]byte
	ns.Write(b)
	ns.Read(ret[:])
	return ret[:]
}

// No Sum32/Sum64 ?

// ShakeSum128_32 is a 32 byte output version of ShakeSum128
func ShakeSum128_32(data []byte) [32]byte {
	var ret [32]byte
	sha3.ShakeSum128(ret[:], data)
	return ret
}

// ShakeSum256_64 is a 64 byte output version of ShakeSum256
func ShakeSum256_64(data []byte) [64]byte {
	var ret [64]byte
	sha3.ShakeSum256(ret[:], data)
	return ret
}
