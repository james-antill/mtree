package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"io"

	"github.com/cespare/xxhash"
	"github.com/dgryski/dgohash"
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

	case "sdbm":
		h := dgohash.NewSDBM32()
		h.Write(data)
		return h.Sum(nil)

	case "xxh64":
		h := xxhash.New()
		h.Write(data)
		return h.Sum(nil)

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

	case "sdbm":
		return dgohash.NewSDBM32()

	case "xxh64":
		return xxhash.New()

	default:
		panic("Bad csum: " + csum)
	}
}

var validChecksumKinds = [...]string{"md5", "sha1",
	"sha224", "sha256", "sha384", "sha512", "sha512-224", "sha512-256",
	"sha3-224", "sha3-256", "sha3-384", "sha3-512",
	"shake-128-32", "shake-256-64",
	"djb2", "sdbm", "xxh64"}

func validChecksum(kind string) bool {
	csums := validChecksumKinds

	// Check it's an apporved checksum
	for _, csum := range csums {
		if csum == kind {
			return true
		}
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
