package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"io"
	"sort"

	"github.com/cespare/xxhash"
	// djb2/djb2a/sdbm
	"github.com/dgryski/dgohash"
	// github.com/spaolacci/murmur3 is more popular, but twmb seemed to have
	// more testing and amd64 asm.
	"github.com/twmb/murmur3"
	"golang.org/x/crypto/sha3"
)

func data2csum(csum string, data []byte) []byte {
	switch csum {
	case "md5":
		val := md5.Sum(data)
		return val[:]
	case "sha1":
		val := sha1.Sum(data)
		return val[:]

	case "sha224":
		val := sha256.Sum224(data)
		return val[:]
	case "sha256":
		val := sha256.Sum256(data)
		return val[:]
	case "sha384":
		val := sha512.Sum384(data)
		return val[:]
	case "sha512":
		val := sha512.Sum512(data)
		return val[:]
	case "sha512-224":
		val := sha512.Sum512_224(data)
		return val[:]
	case "sha512-256":
		val := sha512.Sum512_256(data)
		return val[:]

	case "sha3-224":
		val := sha3.Sum224(data)
		return val[:]
	case "sha3-256":
		val := sha3.Sum256(data)
		return val[:]
	case "sha3-384":
		val := sha3.Sum384(data)
		return val[:]
	case "sha3-512":
		val := sha3.Sum512(data)
		return val[:]

	case "shake-128-32":
		val := ShakeSum128_32(data)
		return val[:]
	case "shake-256-64":
		val := ShakeSum256_64(data)
		return val[:]

	case "djb2":
		h := dgohash.NewDjb32()
		h.Write(data)
		return h.Sum(nil)
	case "djb2a":
		h := dgohash.NewDjb32a()
		h.Write(data)
		return h.Sum(nil)

	case "sdbm":
		h := dgohash.NewSDBM32()
		h.Write(data)
		return h.Sum(nil)

	case "xxh64":
		h := xxhash.New()
		h.Write(data)
		return h.Sum(nil)

	case "murmur3-32":
		h := murmur3.New32()
		h.Write(data)
		return h.Sum(nil)
	case "murmur3-64":
		h := murmur3.New64()
		h.Write(data)
		return h.Sum(nil)
	case "murmur3-128":
		h := murmur3.New128()
		h.Write(data)
		return h.Sum(nil)

	default:
		panic("Bad csum: " + csum)
	}
}

// chkSize is the size in bytes returned by the checksum, double for hex.
func chkSize(csum string) int {
	switch csum {
	case "md5":
		return 16
	case "sha1":
		return 20

	case "sha224":
		return 28
	case "sha256":
		return 32
	case "sha384":
		return 48
	case "sha512":
		return 64
	case "sha512-224":
		return 28
	case "sha512-256":
		return 32

	case "sha3-224":
		return 28
	case "sha3-256":
		return 32
	case "sha3-384":
		return 48
	case "sha3-512":
		return 64

	case "shake-128-32":
		return 32
	case "shake-256-64":
		return 64

	case "djb2":
		return 4
	case "djb2a":
		return 4

	case "sdbm":
		return 4

	case "xxh64":
		return 8

	case "murmur3-32":
		return 4
	case "murmur3-64":
		return 16
	case "murmur3-128":
		return 16

	default:
		panic("Bad csum: " + csum)
	}
}

func chkNew(csum string) hash.Hash {
	switch csum {
	case "md5":
		return md5.New()
	case "sha1":
		return sha1.New()

	case "sha224":
		return sha256.New224()
	case "sha256":
		return sha256.New()
	case "sha384":
		return sha512.New384()
	case "sha512":
		return sha512.New()
	case "sha512-224":
		return sha512.New512_224()
	case "sha512-256":
		return sha512.New512_256()

	case "sha3-224":
		return sha3.New224()
	case "sha3-256":
		return sha3.New256()
	case "sha3-384":
		return sha3.New384()
	case "sha3-512":
		return sha3.New512()

	case "shake-128-32":
		return &shake2hash32{sha3.NewShake128()}
	case "shake-256-64":
		return &shake2hash64{sha3.NewShake256()}

	case "djb2":
		return dgohash.NewDjb32()
	case "djb2a":
		return dgohash.NewDjb32a()

	case "sdbm":
		return dgohash.NewSDBM32()

	case "xxh64":
		return xxhash.New()

	case "murmur3-32":
		return murmur3.New32()
	case "murmur3-64":
		return murmur3.New64()
	case "murmur3-128":
		return murmur3.New128()

	default:
		panic("Bad csum: " + csum)
	}
}

var validChecksumKinds = []string{"md5", "sha1",
	"sha224", "sha256", "sha384", "sha512", "sha512-224", "sha512-256",
	"sha3-224", "sha3-256", "sha3-384", "sha3-512",
	"shake-128-32", "shake-256-64",
	// These are the non-crypto "fast" hashes...
	"djb2", "djb2a", "sdbm", "xxh64",
	"murmur3-32", "murmur3-64", "murmur3-128"}
var validChecksumSorted = false

// validChecksum checks the kind is valid, uses sort.SearchStrings
func validChecksum(kind string) bool {
	if !validChecksumSorted {
		sort.Strings(validChecksumKinds)
		validChecksumSorted = true
	}

	i := sort.SearchStrings(validChecksumKinds, kind)
	if i < len(validChecksumKinds) && validChecksumKinds[i] == kind {
		return true
	}
	return false
}

type autohash struct {
	iow   io.Writer
	csums []string
	hs    []hash.Hash
}

func (a *autohash) Write(p []byte) (n int, err error) {
	return a.iow.Write(p)
}

func (a *autohash) Checksums() []Checksum {
	var csums []Checksum

	for i, csum := range a.csums {
		csums = append(csums, Checksum{csum, a.hs[i].Sum(nil)})
	}

	return csums
}

func autohashNew(csums ...string) *autohash {
	chks := []hash.Hash{}
	chksio := []io.Writer{}
	for _, csum := range csums {
		c := chkNew(csum)
		chks = append(chks, c)
		chksio = append(chksio, c)
	}

	iow := io.MultiWriter(chksio...)

	return &autohash{iow, csums, chks}
}
